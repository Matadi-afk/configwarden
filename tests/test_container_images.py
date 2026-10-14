"""Tests v0.4.0 : CW111, image de conteneur non figée.

Décisions du 14 octobre 2026 :
- gravité moyenne, comme CW102 (paquet npm / PyPI non figé) ;
- une image est figée si elle a une empreinte (`@sha256:…`) ou une version précise
  (`:1.2.3`, `:1.0`) ; pas d'étiquette (Docker prend `:latest`), `:latest`, `:main`,
  `:stable`, une étiquette sans chiffre ou une version majeure seule (`:20`) sont signalées ;
- les images officielles de Docker Hub (un seul nom : `node`, `python`) et les images
  locales (`localhost/…`) ne sont pas signalées : personne d'autre ne peut y publier.

Sources de la syntaxe (Éclaireur, 14 octobre 2026) : docs.docker.com (docker run,
options globales), github.com/distribution/reference (grammaire d'une image),
spf13/pflag (options courtes groupées), containers/podman, containerd/nerdctl.
"""

import time

import pytest

from configwarden import containers
from configwarden.scanner import scan
from tests.conftest import fake_secret

SHA256 = "sha256:" + "0123456789abcdef" * 4
SHA512 = "sha512:" + "0123456789abcdef" * 8


def ids_for(write_mcp, command: str, args: list[str]) -> list[str]:
    return sorted(
        f.rule.id for f in scan(write_mcp({"s": {"command": command, "args": args}})).findings
    )


def messages_for(write_mcp, command: str, args: list[str]) -> list[str]:
    findings = scan(write_mcp({"s": {"command": command, "args": args}})).findings
    return [f.message for f in findings if f.rule.id == "CW111"]


# --- Images non figées : signalées ------------------------------------------------


@pytest.mark.parametrize(
    "image",
    [
        "mcp/github",
        "ghcr.io/org/server",
        "ghcr.io/org/server:latest",
        "org/server:main",
        "org/server:master",
        "org/server:stable",
        "org/server:edge",
        "org/server:nightly",
        "org/server:LATEST",
        "org/server:alpine",  # pas de chiffre : une étiquette qui suit les nouvelles versions
        "org/server:latest-alpine",
        "org/server:stable-1.2",  # un mot flottant suffit, même avec des chiffres
        "org/server:20",  # version majeure seule
        "org/server:v1",
        "org/server:20-alpine",
        "docker.io/org/server",
        "registry.example.com:5000/org/server",  # « :5000 » est un port, pas une étiquette
        "registry.example.com:5000/server",
        "registry.example.com/server:latest",  # registre explicite : pas une image officielle
        "quay.io/org/team/server",
    ],
)
def test_unpinned_image_is_flagged(write_mcp, image) -> None:
    assert ids_for(write_mcp, "docker", ["run", "-i", "--rm", image]) == ["CW111"]


@pytest.mark.parametrize(
    "image",
    [
        "org/server:1.2.3",
        "org/server:v1.2.3",
        "org/server:1.0",
        "org/server:1.2.3-alpine",
        "org/server:2024.10.01",
        "org/server:20241001",
        "org/server:sha-3f2a9c1",
        "ghcr.io/org/server@" + SHA256,
        "ghcr.io/org/server:latest@" + SHA256,  # l'empreinte l'emporte sur l'étiquette
        "org/server@" + SHA512,
        "registry.example.com:5000/org/server:1.2.3",
    ],
)
def test_pinned_image_is_fine(write_mcp, image) -> None:
    assert ids_for(write_mcp, "docker", ["run", "-i", "--rm", image]) == []


@pytest.mark.parametrize(
    "image",
    [
        "node",  # image officielle de Docker Hub (docker.io/library/node)
        "mcp-redis",  # le plus souvent construite sur place (docker build -t mcp-redis .)
        "mcp-redis:latest",
        "library/node",
        "docker.io/library/node:latest",
        "localhost/server",  # Podman : image locale
        "localhost:5000/org/server",  # registre local
        "127.0.0.1:5000/org/server:latest",
    ],
)
def test_official_and_local_images_are_not_flagged(write_mcp, image) -> None:
    assert ids_for(write_mcp, "docker", ["run", "-i", "--rm", image]) == []


def test_message_names_the_image_and_the_problem(write_mcp) -> None:
    [missing] = messages_for(write_mcp, "docker", ["run", "-i", "--rm", "mcp/github"])
    assert "'mcp/github'" in missing
    assert "without a tag or digest" in missing
    [floating] = messages_for(write_mcp, "docker", ["run", "ghcr.io/org/server:latest"])
    assert "'ghcr.io/org/server:latest'" in floating
    assert "floating tag" in floating


# --- Lecture de la ligne de commande -------------------------------------------------


@pytest.mark.parametrize(
    ("command", "args"),
    [
        ("docker", ["container", "run", "-i", "org/server"]),
        ("docker", ["--context", "remote", "run", "org/server"]),
        ("docker", ["-H", "unix:///var/run/docker.sock", "run", "org/server"]),
        ("docker", ["-l", "debug", "--tls", "run", "org/server"]),
        ("docker", ["run", "-e", "KEY=value", "-v", "data:/data", "-p", "80:80", "org/server"]),
        ("docker", ["run", "--name", "srv", "--env-file", "srv.env", "org/server"]),
        ("docker", ["run", "-it", "org/server"]),
        ("docker", ["run", "-ite", "KEY=value", "org/server"]),
        ("docker", ["run", "-eKEY=value", "org/server"]),
        ("docker", ["run", "-e=KEY=value", "org/server"]),
        ("docker", ["run", "--rm=true", "--name=srv", "org/server"]),
        ("docker", ["run", "--pull", "always", "org/server:latest"]),
        ("docker", ["run", "--", "org/server"]),
        ("docker", ["run", "--mount", "type=bind,src=/a,dst=/b", "org/server"]),
        ("podman", ["run", "--rm", "docker://quay.io/org/server:latest"]),
        ("podman", ["--root", "/srv/r", "run", "--authfile", "auth.json", "org/server"]),
        ("podman", ["run", "--runroot", "/srv/r", "org/server"]),  # option globale après run
        ("nerdctl", ["--namespace", "k8s.io", "run", "org/server"]),
        ("docker.exe", ["run", "org/server"]),
        ("/usr/bin/docker", ["run", "org/server"]),
        ("sudo", ["docker", "run", "org/server"]),
        ("docker run -i --rm org/server", []),  # toute la commande dans « command »
    ],
)
def test_command_line_forms_are_understood(write_mcp, command, args) -> None:
    assert ids_for(write_mcp, command, args) == ["CW111"]


@pytest.mark.parametrize(
    "args",
    [
        # Pièges : la valeur d'une option ressemble à une image non figée.
        ["run", "-h", "org/fake", "org/server:1.2.3"],  # -h = nom d'hôte, pas l'aide
        ["run", "-e", "org/fake", "org/server:1.2.3"],
        ["run", "-ei", "org/server:1.2.3"],  # « -ei » : -e reçoit la valeur « i »
        ["run", "-w", "org/fake", "-u", "org/fake", "org/server:1.2.3"],
        ["-c", "org/fake", "run", "org/server:1.2.3"],  # -c = contexte (option globale)
        ["--config", "org/fake", "run", "org/server:1.2.3"],
        # Les arguments passés au conteneur ne sont pas des images.
        ["run", "org/server:1.2.3", "org/fake"],
        ["run", "org/server:1.2.3", "--image", "org/fake"],
    ],
)
def test_option_values_are_not_taken_for_the_image(write_mcp, args) -> None:
    assert containers.run_image("docker", args) == "org/server:1.2.3"
    assert ids_for(write_mcp, "docker", args) == []


@pytest.mark.parametrize(
    ("command", "args"),
    [
        ("docker", ["exec", "-i", "container", "server"]),
        ("docker", ["compose", "run", "--rm", "service"]),
        ("docker", ["rm", "-f", "server"]),
        ("docker", ["mcp", "gateway", "run"]),
        ("docker", ["build", "-t", "org/server", "."]),
        ("docker", ["run"]),  # pas d'image
        ("docker", ["run", "-i", "--rm"]),
        ("docker", ["run", "-e"]),  # valeur manquante
        ("docker", ["container", "ls"]),
        ("podman", ["run", "--rootfs", "/srv/rootfs", "server"]),  # pas une image
        ("podman", ["run", "oci-archive:/tmp/server.tar"]),
        ("podman", ["run", "containers-storage:org/server"]),
        ("nerdctl", ["run", "ipfs://bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"]),
        ("npx", ["-y", "org/server@1.2.3"]),  # pas un moteur de conteneurs
    ],
)
def test_other_commands_are_ignored(write_mcp, command, args) -> None:
    assert ids_for(write_mcp, command, args) == []


@pytest.mark.parametrize(
    "args",
    [
        # Une option inconnue sans « = » : on ne sait pas si elle prend une valeur.
        # Mieux vaut se taire que deviner (et signaler la valeur comme une image).
        ["run", "--future-option", "org/fake", "org/server:1.2.3"],
        ["run", "-Z", "org/fake", "org/server:1.2.3"],
        ["run", "-iZ", "org/fake", "org/server:1.2.3"],
        ["--future-global", "org/fake", "run", "org/server:1.2.3"],
        ["-Z", "org/fake", "run", "org/server:1.2.3"],
    ],
)
def test_unknown_options_stop_the_analysis(write_mcp, args) -> None:
    assert containers.run_image("docker", args) is None
    assert ids_for(write_mcp, "docker", args) == []


def test_unknown_option_with_inline_value_is_skipped(write_mcp) -> None:
    assert ids_for(write_mcp, "docker", ["run", "--future-option=value", "org/server"]) == ["CW111"]


# --- Valeurs qui ne sont pas des images (modèles, variables, saisies invalides) -------


@pytest.mark.parametrize(
    "image",
    [
        "${IMAGE}",
        "$IMAGE",
        "${env:IMAGE}",
        "<your-image>",
        "[image]",
        "{image}",
        "your/image:<tag>",
        "org/server@sha256:<digest>",
        "org/server@sha256:abc",  # empreinte trop courte : Docker refuse de la lancer
        "org/server@md5:" + "0" * 32,  # algorithme inconnu
        "Org/Server",  # majuscules interdites dans le chemin
        "org//server",
        "org/server:",
        "org/server:" + "a" * 129,  # étiquette trop longue
        "org/server:.hidden",
        "org/server:-dash",
        "org/" + "a" * 300,  # nom trop long
        "/org/server",
        "org/server/",
        ":latest",
        "@" + SHA256,
        "org/server:latest" + chr(0x202E),  # caractère bidirectionnel
        "org/server" + chr(0x0A) + "::error::fake",  # saut de ligne
        "org/server:" + chr(0x0661) + chr(0x0662),  # chiffres arabes : pas ASCII
        "org/sérver",
    ],
)
def test_non_image_values_are_ignored(write_mcp, image) -> None:
    assert ids_for(write_mcp, "docker", ["run", "-i", "--rm", image]) == []


# --- Fonctions du module (contrat) ------------------------------------------------------


def test_run_image_returns_the_image_reference() -> None:
    assert containers.run_image("docker", ["run", "-it", "org/server:1.2.3", "x"]) == (
        "org/server:1.2.3"
    )
    assert containers.run_image("docker", ["exec", "c", "x"]) is None
    assert containers.run_image("unknown", ["run", "org/server"]) is None


def test_parse_reference_splits_registry_tag_and_digest() -> None:
    ref = containers.parse_reference("registry.example.com:5000/org/server:1.2.3@" + SHA256)
    assert ref is not None
    assert (ref.domain, ref.path, ref.tag, ref.digest) == (
        "registry.example.com:5000",
        "org/server",
        "1.2.3",
        SHA256,
    )
    ref = containers.parse_reference("org/server")
    assert ref is not None
    assert (ref.domain, ref.path, ref.tag, ref.digest) == (None, "org/server", None, None)
    assert containers.parse_reference("Org/Server") is None


# --- Entrées piégées : jamais de plantage, jamais de lenteur ------------------------------


def test_many_options_are_read_in_linear_time(write_mcp) -> None:
    # Environ 0,9 Mo : juste sous la taille maximale d'un fichier analysé (1 Mo).
    args = ["run", *(["-e", "K=v"] * 30_000), "org/server"]
    start = time.perf_counter()
    assert ids_for(write_mcp, "docker", args) == ["CW111"]
    assert time.perf_counter() - start < 5
    args = ["run", *(["-e", "K=v"] * 200_000), "org/server"]
    start = time.perf_counter()
    assert containers.run_image("docker", args) == "org/server"
    assert time.perf_counter() - start < 1


@pytest.mark.parametrize(
    "image",
    [
        "a" * 1_000_000,
        "a/" * 200_000 + "b",
        "a-" * 200_000 + "b",
        "a." * 200_000 + "b/c",
        "a" * 100_000 + ":" + "b" * 100_000,
        "a@" * 100_000,
        ":" * 100_000,
    ],
    ids=["long", "slashes", "dashes", "dots", "colon", "ats", "colons"],
)
def test_huge_image_values_are_fast(image) -> None:
    start = time.perf_counter()
    assert containers.parse_reference(image) is None or len(image) <= 512
    containers.run_image("docker", ["run", image])
    assert time.perf_counter() - start < 1


def test_message_never_contains_other_arguments(write_mcp) -> None:
    # Assemblé par un appel de fonction : Python ne le recopie pas en clair dans le .pyc.
    secret_like = "=".join(("API_KEY", fake_secret("Zt", 30)))
    [message] = messages_for(write_mcp, "docker", ["run", "-e", secret_like, "org/server"])
    assert "aB3dE5gH7j" not in message
