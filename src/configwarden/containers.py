"""Lecture de « docker run » / « podman run » / « nerdctl run » et des références d'image.

Sert à la règle CW111 (image non figée). Deux étapes :
1. `run_image` trouve l'image dans la ligne de commande : options globales, sous-commande
   `run` (ou `container run`), options de `run`, puis le premier mot qui n'est pas une
   option. Une option inconnue sans « = » arrête l'analyse : on ne sait pas si elle prend
   une valeur, et deviner ferait prendre cette valeur pour l'image (fausse alerte).
2. `parse_reference` découpe l'image selon la grammaire officielle
   `[registre[:port]/]chemin[:étiquette][@empreinte]` ; une saisie invalide (que Docker
   refuserait de lancer) donne None.

Sources (Éclaireur, 14 octobre 2026) : docs.docker.com et docker/cli (options de
`docker run` et options globales), spf13/pflag (options courtes groupées : `-it`,
`-eKEY=V`), containers/podman et containerd/nerdctl (options en plus, options globales
acceptées aussi après `run`), github.com/distribution/reference (grammaire, image
officielle quand le nom n'a qu'un seul composant), opencontainers/go-digest (sha256,
sha512).

Sert aussi à CW106 (conteneur qui casse son isolation) : `run_option_pairs` lit les
options de `run` comme pflag les lit, formes collées comprises (`-v/:/host`, `-iv/x`,
`-v=/:/host`, `--privileged=1`) ; `loose_option_pairs` relit une ligne illisible mot
par mot, par prudence (revue de l'Auditeur du 20 octobre 2026).

Sécurité : chaque mot est lu une seule fois (temps linéaire). Une image de plus de
512 caractères est ignorée avant toute expression régulière, et ces expressions n'ont
pas d'imbrication ambiguë : pas de lenteur sur une entrée piégée.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# --- Options des moteurs de conteneurs -------------------------------------------------

# docker run : options suivies d'une valeur (forme longue).
_DOCKER_RUN_WITH_VALUE = {
    "--add-host", "--annotation", "--attach", "--blkio-weight", "--blkio-weight-device",
    "--cap-add", "--cap-drop", "--cgroup-parent", "--cgroupns", "--cidfile", "--cpu-count",
    "--cpu-percent", "--cpu-period", "--cpu-quota", "--cpu-rt-period", "--cpu-rt-runtime",
    "--cpu-shares", "--cpus", "--cpuset-cpus", "--cpuset-mems", "--detach-keys", "--device",
    "--device-cgroup-rule", "--device-read-bps", "--device-read-iops", "--device-write-bps",
    "--device-write-iops", "--dns", "--dns-option", "--dns-opt", "--dns-search", "--domainname",
    "--entrypoint", "--env", "--env-file", "--expose", "--gpus", "--group-add", "--health-cmd",
    "--health-interval", "--health-retries", "--health-start-interval", "--health-start-period",
    "--health-timeout", "--hostname", "--io-maxbandwidth", "--io-maxiops", "--ip", "--ip6",
    "--ipc", "--isolation", "--kernel-memory", "--label", "--label-file", "--link",
    "--link-local-ip", "--log-driver", "--log-opt", "--mac-address", "--memory",
    "--memory-reservation", "--memory-swap", "--memory-swappiness", "--mount", "--name",
    "--net", "--net-alias", "--network", "--network-alias", "--oom-score-adj", "--pid",
    "--pids-limit", "--platform", "--publish", "--pull", "--restart", "--runtime",
    "--security-opt", "--shm-size", "--stop-signal", "--stop-timeout", "--storage-opt",
    "--sysctl", "--tmpfs", "--ulimit", "--user", "--userns", "--uts", "--volume",
    "--volume-driver", "--volumes-from", "--workdir",
}  # fmt: skip
_DOCKER_RUN_BOOLEAN = {
    "--detach", "--interactive", "--tty", "--publish-all", "--quiet", "--rm", "--init",
    "--privileged", "--read-only", "--no-healthcheck", "--oom-kill-disable",
    "--use-api-socket", "--sig-proxy", "--disable-content-trust",
}  # fmt: skip
# Attention : dans « run », -h est le nom d'hôte (avec valeur), pas l'aide.
_DOCKER_RUN_SHORT_WITH_VALUE = frozenset("acehlmpuvw")
_DOCKER_RUN_SHORT_BOOLEAN = frozenset("diPqt")

_PODMAN_RUN_WITH_VALUE = {
    "--arch", "--authfile", "--cert-dir", "--cgroup-conf", "--cgroups", "--chrootdirs",
    "--conmon-pidfile", "--creds", "--decryption-key", "--env-merge", "--gidmap",
    "--group-entry", "--health-log-destination", "--health-max-log-count",
    "--health-max-log-size", "--health-on-failure", "--health-startup-cmd",
    "--health-startup-interval", "--health-startup-retries", "--health-startup-success",
    "--health-startup-timeout", "--healthcheck-command", "--healthcheck-interval",
    "--healthcheck-retries", "--healthcheck-start-period", "--healthcheck-timeout",
    "--hostuser", "--hosts-file", "--image-volume", "--init-path", "--os", "--override-arch",
    "--override-os", "--override-variant", "--passwd-entry", "--personality", "--pidfile",
    "--pod", "--pod-id-file", "--preserve-fd", "--preserve-fds", "--rdt-class", "--requires",
    "--retry", "--retry-delay", "--sdnotify", "--seccomp-policy", "--secret",
    "--shm-size-systemd", "--signature-policy", "--subgidname", "--subuidname", "--systemd",
    "--timeout", "--tz", "--uidmap", "--umask", "--unsetenv", "--variant",
}  # fmt: skip
_PODMAN_RUN_BOOLEAN = {
    "--env-host", "--http-proxy", "--no-hosts", "--no-hostname", "--passwd", "--read-only-tmpfs",
    "--replace", "--rmi", "--unsetenv-all", "--tls-verify",
}  # fmt: skip
_NERDCTL_RUN_WITH_VALUE = {
    "--verify", "--cosign-key", "--cosign-certificate-identity",
    "--cosign-certificate-identity-regexp", "--cosign-certificate-oidc-issuer",
    "--cosign-certificate-oidc-issuer-regexp", "--init-binary", "--ipfs-address", "--pidfile",
    "--systemd", "--cgroup-conf", "--rdt-class", "--umask",
}  # fmt: skip

# Options globales, avant la sous-commande (« docker --context x run … »).
_DOCKER_GLOBAL_WITH_VALUE = {
    "--config", "--context", "--host", "--log-level", "--tlscacert", "--tlscert", "--tlskey",
}  # fmt: skip
_DOCKER_GLOBAL_BOOLEAN = {"--debug", "--tls", "--tlsverify"}
_DOCKER_GLOBAL_SHORT_WITH_VALUE = frozenset("cHl")
_DOCKER_GLOBAL_SHORT_BOOLEAN = frozenset("D")

# Podman et nerdctl acceptent aussi leurs options globales APRÈS « run ».
_PODMAN_GLOBAL_WITH_VALUE = {
    "--connection", "--url", "--host", "--identity", "--tls-cert", "--tls-key", "--tls-ca",
    "--tls-details", "--root", "--runroot", "--storage-driver", "--storage-opt", "--log-level",
    "--runtime", "--runtime-flag", "--cgroup-manager", "--events-backend", "--hooks-dir",
    "--module", "--out", "--tmpdir", "--volumepath", "--imagestore", "--pull-option",
    "--conmon", "--network-cmd-path", "--network-config-dir", "--cdi-spec-dir", "--db-backend",
    "--ssh", "--config",
}  # fmt: skip
_PODMAN_GLOBAL_BOOLEAN = {"--remote", "--syslog", "--noout", "--transient-store", "--debug"}
_PODMAN_GLOBAL_SHORT_WITH_VALUE = frozenset("cH")
_PODMAN_GLOBAL_SHORT_BOOLEAN = frozenset("r")

_NERDCTL_GLOBAL_WITH_VALUE = {
    "--address", "--host", "--namespace", "--snapshotter", "--storage-driver", "--cni-path",
    "--cni-netconfpath", "--data-root", "--cgroup-manager", "--hosts-dir", "--host-gateway-ip",
    "--bridge-ip", "--cdi-spec-dirs", "--userns-remap", "--log-file", "--log-level",
}  # fmt: skip
_NERDCTL_GLOBAL_BOOLEAN = {"--debug", "--debug-full", "--insecure-registry", "--experimental"}
_NERDCTL_GLOBAL_SHORT_WITH_VALUE = frozenset("aHn")

# Options qui arrêtent l'analyse : aide, version, ou premier mot qui n'est pas une image.
_GLOBAL_STOP = {"--help", "--version"}
_GLOBAL_SHORT_STOP = frozenset("hv")
_RUN_STOP = {"--help", "--rootfs"}

# Préfixes de Podman et nerdctl : « docker:// » désigne un registre ; les autres
# désignent un fichier ou un stockage local, ou une adresse par contenu (IPFS).
_REGISTRY_TRANSPORT = "docker://"
_LOCAL_TRANSPORTS = (
    "containers-storage:", "dir:", "docker-archive:", "docker-daemon:", "oci:",
    "oci-archive:", "sif:", "ipfs://",
)  # fmt: skip


@dataclass(frozen=True)
class _Options:
    with_value: frozenset[str]
    boolean: frozenset[str]
    short_with_value: frozenset[str]
    short_boolean: frozenset[str]
    stop: frozenset[str]
    short_stop: frozenset[str]


def _options(
    with_value: set[str],
    boolean: set[str],
    short_with_value: frozenset[str],
    short_boolean: frozenset[str],
    stop: set[str],
    short_stop: frozenset[str] = frozenset(),
) -> _Options:
    return _Options(
        frozenset(with_value),
        frozenset(boolean),
        short_with_value,
        short_boolean,
        frozenset(stop),
        short_stop,
    )


_GLOBAL_OPTIONS = {
    "docker": _options(
        _DOCKER_GLOBAL_WITH_VALUE,
        _DOCKER_GLOBAL_BOOLEAN,
        _DOCKER_GLOBAL_SHORT_WITH_VALUE,
        _DOCKER_GLOBAL_SHORT_BOOLEAN,
        _GLOBAL_STOP,
        _GLOBAL_SHORT_STOP,
    ),
    "podman": _options(
        _PODMAN_GLOBAL_WITH_VALUE,
        _PODMAN_GLOBAL_BOOLEAN,
        _PODMAN_GLOBAL_SHORT_WITH_VALUE,
        _PODMAN_GLOBAL_SHORT_BOOLEAN,
        _GLOBAL_STOP,
        _GLOBAL_SHORT_STOP,
    ),
    "nerdctl": _options(
        _NERDCTL_GLOBAL_WITH_VALUE,
        _NERDCTL_GLOBAL_BOOLEAN,
        _NERDCTL_GLOBAL_SHORT_WITH_VALUE,
        frozenset(),
        _GLOBAL_STOP,
        _GLOBAL_SHORT_STOP,
    ),
}
_RUN_OPTIONS = {
    "docker": _options(
        _DOCKER_RUN_WITH_VALUE,
        _DOCKER_RUN_BOOLEAN,
        _DOCKER_RUN_SHORT_WITH_VALUE,
        _DOCKER_RUN_SHORT_BOOLEAN,
        _RUN_STOP,
    ),
    "podman": _options(
        _DOCKER_RUN_WITH_VALUE | _PODMAN_RUN_WITH_VALUE | _PODMAN_GLOBAL_WITH_VALUE,
        _DOCKER_RUN_BOOLEAN | _PODMAN_RUN_BOOLEAN | _PODMAN_GLOBAL_BOOLEAN,
        _DOCKER_RUN_SHORT_WITH_VALUE | {"H"},
        _DOCKER_RUN_SHORT_BOOLEAN | _PODMAN_GLOBAL_SHORT_BOOLEAN,
        _RUN_STOP,
    ),
    "nerdctl": _options(
        _DOCKER_RUN_WITH_VALUE | _NERDCTL_RUN_WITH_VALUE | _NERDCTL_GLOBAL_WITH_VALUE,
        _DOCKER_RUN_BOOLEAN | _NERDCTL_GLOBAL_BOOLEAN,
        _DOCKER_RUN_SHORT_WITH_VALUE | _NERDCTL_GLOBAL_SHORT_WITH_VALUE,
        _DOCKER_RUN_SHORT_BOOLEAN,
        _RUN_STOP,
    ),
}

ENGINES = frozenset(_RUN_OPTIONS)


Pair = tuple[str, str]  # (option telle qu'écrite, valeur) ; un booléen seul vaut « true »


def _read_short(
    word: str, following: str | None, options: _Options
) -> tuple[list[Pair], bool] | None:
    """Lit « -it », « -v/:/h », « -v=/:/h », « -eKEY=V », « -e KEY=V » (règles de spf13/pflag).

    Renvoie les couples (option, valeur) et si le mot suivant a été pris comme valeur de
    la dernière lettre ; None si une lettre est inconnue, demande d'arrêter, ou si la
    valeur manque (le moteur refuserait alors la ligne).
    """
    pairs: list[Pair] = []
    for position in range(1, len(word)):
        letter = word[position]
        rest = word[position + 1 :]
        if letter in options.short_stop or not (
            letter in options.short_with_value or letter in options.short_boolean
        ):
            return None
        name = "-" + letter
        if len(rest) >= 2 and rest[0] == "=":
            pairs.append((name, rest[1:]))  # « -v=/:/host », « -i=false »
            return pairs, False
        if letter in options.short_boolean:
            pairs.append((name, "true"))  # « -it » : -i, puis la lettre suivante
            continue
        if rest:
            pairs.append((name, rest))  # « -v/:/host », « -eKEY=V » : la suite est la valeur
            return pairs, False
        if following is None:
            return None
        pairs.append((name, following))  # « -v /:/host »
        return pairs, True
    return pairs, False


def _first_positional(args: list[str], start: int, options: _Options, *, run: bool) -> int | None:
    """Indice du premier mot qui n'est ni une option ni sa valeur ; None si incertain."""
    index = start
    while index < len(args):
        word = args[index]
        if word == "--":
            # Fin des options : après « run », le mot suivant est l'image.
            return index + 1 if run and index + 1 < len(args) else None
        if word.startswith("--"):
            name, has_value, _ = word.partition("=")
            if name in options.stop:
                return None
            if has_value or name in options.boolean:
                index += 1
            elif name in options.with_value:
                index += 2
            else:
                return None  # option inconnue : prend-elle une valeur ? On ne devine pas.
        elif word.startswith("-") and len(word) > 1:
            following = args[index + 1] if index + 1 < len(args) else None
            read = _read_short(word, following, options)
            if read is None:
                return None
            index += 2 if read[1] else 1
        else:
            return index
    return None


def _locate_run(engine: str, args: list[str]) -> tuple[int, int] | None:
    """(début des options de `run`, position de l'image), ou None si incertain."""
    if engine not in ENGINES:
        return None
    command = _first_positional(args, 0, _GLOBAL_OPTIONS[engine], run=False)
    if command is None:
        return None
    if args[command] == "container" and command + 1 < len(args):
        command += 1
    if args[command] != "run":
        return None
    image_index = _first_positional(args, command + 1, _RUN_OPTIONS[engine], run=True)
    if image_index is None:
        return None
    return command + 1, image_index


def run_options(engine: str, args: list[str]) -> list[str] | None:
    """Les options de `run`, placées avant l'image (ce qui suit est donné au conteneur).

    None si la ligne ne peut pas être lue avec certitude : l'appelant vérifie alors
    toute la ligne, par prudence.
    """
    located = _locate_run(engine, args)
    if located is None:
        return None
    start, image_index = located
    # « -- » qui annonce l'image n'est pas une option.
    end = image_index - 1 if image_index > start and args[image_index - 1] == "--" else image_index
    return args[start:end]


def _pairs(words: list[str], options: _Options, *, strict: bool) -> list[Pair]:
    """Couples (option, valeur) d'une suite d'options, jusqu'à « -- ».

    strict : la ligne a été lue avec certitude, chaque valeur n'est prise qu'une fois.
    Sinon (ligne illisible), chaque mot est AUSSI examiné comme une option possible :
    plus d'alertes peut-être, mais aucune option dangereuse n'est sautée.
    """
    pairs: list[Pair] = []
    index = 0
    while index < len(words):
        word = words[index]
        if word == "--":
            break
        following = words[index + 1] if index + 1 < len(words) else None
        used_following = False
        if word.startswith("--"):
            name, has_value, value = word.partition("=")
            if has_value:
                pairs.append((name, value))  # « --privileged=1 », « --volume=/:/host »
            elif name in options.boolean:
                pairs.append((name, "true"))
            elif following is not None:
                pairs.append((name, following))
                used_following = True
        elif word.startswith("-") and len(word) > 1:
            read = _read_short(word, following, options)
            if read is not None:
                pairs.extend(read[0])
                used_following = read[1]
        index += 2 if strict and used_following else 1
    return pairs


def run_option_pairs(engine: str, args: list[str]) -> list[Pair] | None:
    """Les options de `run` placées avant l'image, en couples (option, valeur).

    « -v/:/host », « -iv/x », « -v=/:/host » et « --privileged=1 » y sont lus comme Docker
    les lit. None si la ligne ne peut pas être lue avec certitude.
    """
    located = _locate_run(engine, args)
    if located is None:
        return None
    start, image_index = located
    return _pairs(args[start:image_index], _RUN_OPTIONS[engine], strict=True)


def loose_option_pairs(engine: str, args: list[str]) -> list[Pair]:
    """Lecture prudente d'une ligne illisible : toutes les options qu'on y reconnaît."""
    return _pairs(args, _RUN_OPTIONS.get(engine, _RUN_OPTIONS["docker"]), strict=False)


def run_image(engine: str, args: list[str]) -> str | None:
    """L'image lancée par « <engine> [options] run|container run [options] IMAGE … ».

    None si ce n'est pas un lancement de conteneur, si l'image vient d'un fichier ou
    d'un stockage local, ou si la ligne ne peut pas être lue avec certitude.
    """
    located = _locate_run(engine, args)
    if located is None:
        return None
    image = args[located[1]]
    if engine == "podman" and image.startswith(_REGISTRY_TRANSPORT):
        image = image[len(_REGISTRY_TRANSPORT) :]
    if image.startswith(_LOCAL_TRANSPORTS):
        return None
    return image


# --- Références d'image -------------------------------------------------------------

_MAX_REFERENCE = 512
_MAX_NAME = 255
# Grammaire de distribution/reference, en ASCII seulement (\w et \d de Python
# accepteraient des chiffres arabes ou des lettres accentuées).
_DOMAIN_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
_DOMAIN = re.compile(rf"(?:{_DOMAIN_LABEL}(?:\.{_DOMAIN_LABEL})*|\[[0-9A-Fa-f:]+\])(?::[0-9]+)?")
_PATH_COMPONENT = re.compile(r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*")
_TAG = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")
# go-digest n'enregistre que sha256 et sha512, en hexadécimal minuscule.
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}|sha512:[0-9a-f]{128}")


@dataclass(frozen=True)
class ImageReference:
    domain: str | None  # None : Docker Hub, implicite
    path: str
    tag: str | None
    digest: str | None


def parse_reference(text: str) -> ImageReference | None:
    """« ghcr.io:443/org/srv:1.2@sha256:… » -> registre, chemin, étiquette, empreinte."""
    if not text or len(text) > _MAX_REFERENCE or not text.isascii():
        return None
    name, has_digest, digest = text.partition("@")
    if has_digest and not _DIGEST.fullmatch(digest):
        return None
    # L'étiquette suit le DERNIER composant : « registre:5000/img » n'en a pas.
    tag = None
    colon = name.rfind(":")
    if colon > name.rfind("/"):
        name, tag = name[:colon], name[colon + 1 :]
        if not _TAG.fullmatch(tag):
            return None
    if not name or len(name) > _MAX_NAME:
        return None
    parts = name.split("/")
    domain = None
    first = parts[0]
    # Le 1er composant est un registre s'il a un point, un port, des majuscules ou
    # vaut « localhost » ; sinon l'image vient de Docker Hub (« mcp/github »).
    looks_like_host = "." in first or ":" in first or first.lower() != first
    if len(parts) > 1 and (looks_like_host or first == "localhost"):
        domain = first
        parts = parts[1:]
        if not _DOMAIN.fullmatch(domain):
            return None
    if not all(_PATH_COMPONENT.fullmatch(part) for part in parts):
        return None
    return ImageReference(domain, "/".join(parts), tag, digest or None)


# --- Image figée ou non ---------------------------------------------------------------

_DOCKER_HUB = {"docker.io", "index.docker.io", "registry-1.docker.io"}
_LOCAL_REGISTRIES = {"localhost", "127.0.0.1", "[::1]"}
# Mots d'une étiquette qui suit les nouvelles publications (« latest », « 20-lts »…).
# Pas « alpha », « beta » ni « rc » : « 1.2.3-beta.1 » est une version précise.
_FLOATING_WORDS = {
    "latest", "stable", "main", "master", "edge", "nightly", "dev", "develop", "development",
    "canary", "lts", "current", "head", "snapshot", "unstable", "trunk", "rolling", "mainline",
}  # fmt: skip
_TAG_WORDS = re.compile(r"[-_.]")
# Version majeure seule : « 20 », « v1 », « 20-alpine » (suit les versions 20.x).
_MAJOR_ONLY = re.compile(r"v?[0-9]{1,3}(?:[-_][a-z][a-z0-9]*)*")


def _is_official_or_local(reference: ImageReference) -> bool:
    """Image officielle de Docker Hub (un seul nom) ou registre local : rien à figer."""
    domain = (reference.domain or "docker.io").lower()
    if domain in _DOCKER_HUB:
        return "/" not in reference.path or reference.path.startswith("library/")
    # Sans le port : « localhost:5000 » -> « localhost », « [::1]:5000 » -> « [::1] ».
    host = domain[: domain.find("]") + 1] if domain.startswith("[") else domain.split(":")[0]
    return host in _LOCAL_REGISTRIES


def is_floating_tag(tag: str) -> bool:
    lowered = tag.lower()
    if not any(character.isdigit() for character in lowered):
        return True  # « latest », « alpine », « bookworm » : aucune version
    if any(word in _FLOATING_WORDS for word in _TAG_WORDS.split(lowered)):
        return True
    return bool(_MAJOR_ONLY.fullmatch(lowered))


def pinning_problem(reference: ImageReference) -> str | None:
    """Pourquoi l'image n'est pas figée (texte pour le message), ou None."""
    if reference.digest or _is_official_or_local(reference):
        return None
    if reference.tag is None:
        return "without a tag or digest (Docker pulls ':latest')"
    if is_floating_tag(reference.tag):
        return f"with a floating tag (':{reference.tag}')"
    return None
