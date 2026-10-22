"""Lecture des arguments de `npx` et de `npm exec` comme npm 10 les lit vraiment.

Pourquoi (revue de l'Auditeur, 20 octobre 2026) : configwarden supposait qu'une option
inconnue de npx ne prend pas de valeur. Une option comme `--cafile chemin` décalait donc
la lecture : un `npx -c "commande"` (un shell) ou un paquet venu de GitHub placé après
passait sans alerte. Ce module reproduit fidèlement la lecture de npm 10.9.4 :

1. `bin/npx-cli.js` cherche le premier mot qui n'est pas une option et place « -- »
   devant. Une option qu'il ne sait pas booléenne prend le mot suivant comme valeur,
   sauf si ce mot commence par « - » ;
2. npm lit ensuite les options avec la bibliothèque `nopt` : abréviations sans ambiguïté
   (`--cal`…), lettres groupées (`-yc` = `-y -c`), « --no-… », type de chaque option.
   Une option inconnue y est booléenne : un mot « avalé » à l'étape 1 redevient alors un
   argument, donc la commande lancée.

Les deux étapes ne sont pas toujours d'accord, et c'est le résultat de la seconde qui
compte : c'est elle que npm exécute. `npm exec` (et `npm x`) n'a que la seconde étape :
npm y lit les options PARTOUT sur la ligne, même après le paquet. Ce module a été comparé
à la lecture de npm lui-même sur des milliers de lignes générées au hasard (voir
tests/test_npm_args.py).

`pnpm dlx` et `bunx` sont lus comme npx (leurs options courantes sont les mêmes), avec en
plus l'option `--shell-mode` de pnpm : la commande est alors une ligne pour un shell.

Sources : npm 10.9.4 (bin/npx-cli.js, lib/commands/exec.js, lib/utils/cmd-list.js),
@npmcli/config 9.0.0 (definitions.js : options, types, raccourcis), nopt 8.1.0
(lib/nopt-lib.js), abbrev ; documentation de pnpm dlx (octobre 2026).

Sécurité : lecture en un seul passage (temps linéaire), sans jamais modifier une liste en
place ; les raccourcis ne se développent qu'en options longues (pas de boucle infinie).
"""

from __future__ import annotations

import re
from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass, field

# --- Données de npm 10.9.4 --------------------------------------------------------------

# Type de chaque option (nopt) : jetons séparés par « | » ; « [ » = type tableau.
# « lit:x » = valeur littérale permise ; path, url, semver, Umask = types propres à npm.
_TYPES = {
    "_auth": "[null|String",
    "access": "[null|lit:restricted|lit:public",
    "all": "Boolean",
    "allow-same-version": "Boolean",
    "also": "[null|lit:dev|lit:development",
    "audit": "Boolean",
    "audit-level": "[null|lit:info|lit:low|lit:moderate|lit:high|lit:critical|lit:none",
    "auth-type": "[lit:legacy|lit:web",
    "before": "[null|Date",
    "bin-links": "Boolean",
    "browser": "[null|Boolean|String",
    "ca": "[null|String|Array",
    "cache": "path",
    "cache-max": "Number",
    "cache-min": "Number",
    "cafile": "path",
    "call": "String",
    "cert": "[null|String",
    "cidr": "[null|String|Array",
    "color": "[lit:always|Boolean",
    "commit-hooks": "Boolean",
    "cpu": "[null|String",
    "depth": "[null|Number",
    "description": "Boolean",
    "dev": "Boolean",
    "diff": "[String|Array",
    "diff-dst-prefix": "String",
    "diff-ignore-all-space": "Boolean",
    "diff-name-only": "Boolean",
    "diff-no-prefix": "Boolean",
    "diff-src-prefix": "String",
    "diff-text": "Boolean",
    "diff-unified": "Number",
    "dry-run": "Boolean",
    "editor": "String",
    "engine-strict": "Boolean",
    "expect-result-count": "[null|Number",
    "expect-results": "[null|Boolean",
    "fetch-retries": "Number",
    "fetch-retry-factor": "Number",
    "fetch-retry-maxtimeout": "Number",
    "fetch-retry-mintimeout": "Number",
    "fetch-timeout": "Number",
    "force": "Boolean",
    "foreground-scripts": "Boolean",
    "format-package-lock": "Boolean",
    "fund": "Boolean",
    "git": "String",
    "git-tag-version": "Boolean",
    "global": "Boolean",
    "global-style": "Boolean",
    "globalconfig": "path",
    "heading": "String",
    "https-proxy": "[null|url",
    "if-present": "Boolean",
    "ignore-scripts": "Boolean",
    "include": "[Array|lit:prod|lit:dev|lit:optional|lit:peer",
    "include-staged": "Boolean",
    "include-workspace-root": "Boolean",
    "init-author-email": "String",
    "init-author-name": "String",
    "init-author-url": "[lit:|url",
    "init-license": "String",
    "init-module": "path",
    "init-version": "semver",
    "init.author.email": "String",
    "init.author.name": "String",
    "init.author.url": "[lit:|url",
    "init.license": "String",
    "init.module": "path",
    "init.version": "semver",
    "install-links": "Boolean",
    "install-strategy": "[lit:hoisted|lit:nested|lit:shallow|lit:linked",
    "json": "Boolean",
    "key": "[null|String",
    "legacy-bundling": "Boolean",
    "legacy-peer-deps": "Boolean",
    "libc": "[null|String",
    "link": "Boolean",
    "local-address": "[null|lit:127.0.0.1|lit:192.0.2.2",
    "location": "[lit:global|lit:user|lit:project",
    "lockfile-version": "[null|num:1|num:2|num:3|lit:1|lit:2|lit:3",
    "loglevel": "[lit:silent|lit:error|lit:warn|lit:notice|lit:http|lit:info|lit:verbose|lit:silly",
    "logs-dir": "[null|path",
    "logs-max": "Number",
    "long": "Boolean",
    "maxsockets": "Number",
    "message": "String",
    "node-options": "[null|String",
    "noproxy": "[String|Array",
    "offline": "Boolean",
    "omit": "[Array|lit:dev|lit:optional|lit:peer",
    "omit-lockfile-registry-resolved": "Boolean",
    "only": "[null|lit:prod|lit:production",
    "optional": "[null|Boolean",
    "os": "[null|String",
    "otp": "[null|String",
    "pack-destination": "String",
    "package": "[String|Array",
    "package-lock": "Boolean",
    "package-lock-only": "Boolean",
    "parseable": "Boolean",
    "prefer-dedupe": "Boolean",
    "prefer-offline": "Boolean",
    "prefer-online": "Boolean",
    "prefix": "path",
    "preid": "String",
    "production": "[null|Boolean",
    "progress": "Boolean",
    "provenance": "Boolean",
    "provenance-file": "path",
    "proxy": "[null|false|url",
    "read-only": "Boolean",
    "rebuild-bundle": "Boolean",
    "registry": "url",
    "replace-registry-host": "[lit:npmjs|lit:never|lit:always|String",
    "save": "Boolean",
    "save-bundle": "Boolean",
    "save-dev": "Boolean",
    "save-exact": "Boolean",
    "save-optional": "Boolean",
    "save-peer": "Boolean",
    "save-prefix": "String",
    "save-prod": "Boolean",
    "sbom-format": "[lit:cyclonedx|lit:spdx",
    "sbom-type": "[lit:library|lit:application|lit:framework",
    "scope": "String",
    "script-shell": "[null|String",
    "searchexclude": "String",
    "searchlimit": "Number",
    "searchopts": "String",
    "searchstaleness": "Number",
    "shell": "String",
    "shrinkwrap": "Boolean",
    "sign-git-commit": "Boolean",
    "sign-git-tag": "Boolean",
    "strict-peer-deps": "Boolean",
    "strict-ssl": "Boolean",
    "tag": "String",
    "tag-version-prefix": "String",
    "timing": "Boolean",
    "umask": "Umask",
    "unicode": "Boolean",
    "update-notifier": "Boolean",
    "usage": "Boolean",
    "user-agent": "String",
    "userconfig": "path",
    "version": "Boolean",
    "versions": "Boolean",
    "viewer": "String",
    "which": "[null|Number",
    "workspace": "[String|Array",
    "workspaces": "[null|Boolean",
    "workspaces-update": "Boolean",
    "yes": "[null|Boolean",
}
_SHORTHANDS: dict[str, tuple[str, ...]] = {
    "?": ("--usage",),
    "B": ("--save-bundle",),
    "C": ("--prefix",),
    "D": ("--save-dev",),
    "E": ("--save-exact",),
    "H": ("--usage",),
    "L": ("--location",),
    "O": ("--save-optional",),
    "P": ("--save-prod",),
    "S": ("--save",),
    "a": ("--all",),
    "c": ("--call",),
    "d": ("--loglevel", "info"),
    "dd": ("--loglevel", "verbose"),
    "ddd": ("--loglevel", "silly"),
    "desc": ("--description",),
    "enjoy-by": ("--before",),
    "f": ("--force",),
    "g": ("--global",),
    "h": ("--usage",),
    "help": ("--usage",),
    "iwr": ("--include-workspace-root",),
    "l": ("--long",),
    "local": ("--no-global",),
    "m": ("--message",),
    "n": ("--no-yes",),
    "no": ("--no-yes",),
    "p": ("--parseable",),
    "porcelain": ("--parseable",),
    "q": ("--loglevel", "warn"),
    "quiet": ("--loglevel", "warn"),
    "readonly": ("--read-only",),
    "reg": ("--registry",),
    "s": ("--loglevel", "silent"),
    "silent": ("--loglevel", "silent"),
    "v": ("--version",),
    "verbose": ("--loglevel", "verbose"),
    "w": ("--workspace",),
    "ws": ("--workspaces",),
    "y": ("--yes",),
}

# bin/npx-cli.js
_REMOVED_SWITCHES = frozenset({"always-spawn", "ignore-existing", "shell-auto-fallback"})
_REMOVED_OPTS = frozenset({"npm", "node-arg", "n"})
_REMOVED = _REMOVED_SWITCHES | _REMOVED_OPTS


def _parse_type(spec: str) -> tuple[bool, frozenset[str]]:
    return spec.startswith("["), frozenset(spec.lstrip("[").split("|"))


_PARSED_TYPES = {key: _parse_type(spec) for key, spec in _TYPES.items()}
_BOOLEAN_KEYS = frozenset(key for key, (_, parts) in _PARSED_TYPES.items() if "Boolean" in parts)
_NPX_SWITCHES = (
    _BOOLEAN_KEYS | _REMOVED_SWITCHES | {"no-install", "quiet", "q", "version", "v", "help", "h"}
)
_NPX_OPTS = _REMOVED_OPTS | {
    "package", "p", "cache", "userconfig", "call", "c", "shell", "npm", "node-arg", "n",
}  # fmt: skip
# lib/utils/cmd-list.js : seuls ces mots mènent à `npm exec` (alias « x », abréviation « exe »).
_NPM_EXEC_COMMANDS = frozenset({"exec", "exe", "x"})
_SINGLES = frozenset(key for key in _SHORTHANDS if len(key) == 1)
_URL_START = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:.")
_ONLY_DASHES = re.compile(r"-{2,}")
_SINGLE_DASH_WORD = re.compile(r"-[^-]")
_DASH_WORD = re.compile(r"-{1,2}[^-]+")
_DOUBLE_DASH_WORD = re.compile(r"-{2,}[^-]")
# Ce que `isNaN()` de JavaScript accepte comme nombre (« --no-depth 1 » prend « 1 »).
_JS_NUMBER = re.compile(
    r"[+-]?(?:Infinity|(?:[0-9]+\.?[0-9]*|\.[0-9]+)(?:[eE][+-]?[0-9]+)?)"
    r"|0[xX][0-9a-fA-F]+|0[oO][0-7]+|0[bB][01]+"
)
_JS_SPACES = (  # espaces retirés par trim() et Number() de JavaScript
    "\t\n\x0b\x0c\r \xa0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008"
    "\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"
)


def _abbreviations(words: Iterable[str]) -> dict[str, str]:
    """Préfixes sans ambiguïté, comme le paquet `abbrev` : « cal » -> « call »."""
    unique = sorted(set(words))
    counts: dict[str, int] = {}
    for word in unique:
        for end in range(1, len(word) + 1):
            counts[word[:end]] = counts.get(word[:end], 0) + 1
    result: dict[str, str] = {}
    for word in unique:
        for end in range(1, len(word) + 1):
            if counts[word[:end]] == 1:
                result[word[:end]] = word
        result[word] = word
    return result


_ABBREVIATIONS = _abbreviations(_TYPES)
_SHORT_ABBREVIATIONS = _abbreviations(_SHORTHANDS)


@dataclass
class NpxArguments:
    """Ce que npm fera vraiment d'une ligne `npx …` (ou `npm exec …`)."""

    call: str | None = None  # ligne de commande donnée à un shell (`-c`, `--call`…)
    packages: list[str] = field(default_factory=list)  # valeurs de `--package` / `-p`
    command: list[str] = field(default_factory=list)  # commande lancée et ses arguments
    shell_mode: bool = False  # `pnpm dlx --shell-mode` : la commande est une ligne de shell
    # Registres demandés (`--registry`, `--@scope:registry`) : (option, adresse), pour CW112.
    registries: list[tuple[str, str]] = field(default_factory=list)

    def shell_option(self) -> str | None:
        """L'option qui fait lancer une ligne de commande par un shell, ou None."""
        if self.shell_mode:
            return "--shell-mode"
        # « --no-call » ou « --call » sans valeur : npm reçoit « false », « true » ou rien.
        return "-c" if self.call not in (None, "", "true", "false") else None

    def as_npx_args(self) -> list[str]:
        """La même lecture écrite comme des arguments de npx, sans aucune ambiguïté.

        `parse_npx(lecture.as_npx_args())` redonne exactement `lecture` (vérifié par les
        tests) : c'est la forme sous laquelle `npm exec …` est transmis aux règles.
        """
        words = [f"--package={package}" for package in self.packages]
        if self.call is not None:
            words.append(f"--call={self.call}")
        if self.shell_mode:
            words.append("--shell-mode")
        words += [f"--{key}={address}" for key, address in self.registries]
        return [*words, "--", *self.command]


class _Tokens:
    """Mots à lire, avec des mots insérés en tête (raccourcis développés)."""

    def __init__(self, words: list[str]) -> None:
        self._words = words
        self._index = 0
        self._pending: deque[str] = deque()

    def peek(self) -> str | None:
        if self._pending:
            return self._pending[0]
        return self._words[self._index] if self._index < len(self._words) else None

    def take(self) -> str | None:
        if self._pending:
            return self._pending.popleft()
        if self._index < len(self._words):
            self._index += 1
            return self._words[self._index - 1]
        return None

    def push_front(self, words: Iterable[str]) -> None:
        self._pending.extendleft(reversed(list(words)))

    def rest(self) -> list[str]:
        remaining = [*self._pending, *self._words[self._index :]]
        self._pending.clear()
        self._index = len(self._words)
        return remaining


def _npx_prepass(args: list[str]) -> list[str]:
    """Étape 1 (bin/npx-cli.js) : réécrit les options et insère « -- » devant la commande."""
    tokens = _Tokens(args)
    out: list[str] = []
    while (word := tokens.take()) is not None:
        if word == "--":
            out.append(word)
            out.extend(tokens.rest())
            break
        if not word.startswith("-"):
            out.extend(["--", word, *tokens.rest()])
            break
        key, *value = word.lstrip("-").split("=")
        if key == "p":
            word = "=".join(["--package", *value])
        elif key == "shell":
            word = "=".join(["--script-shell", *value])
        elif key == "no-install":
            word = "--yes=false"
        elif key in _SHORTHANDS and key not in _REMOVED:
            tokens.push_front([*_SHORTHANDS[key], *(["=".join(value)] if value else [])])
            continue
        removed = key in _REMOVED
        if not removed:
            out.append(word)
        following = tokens.peek()
        takes_next = not value and key not in _NPX_SWITCHES
        if takes_next and (key in _NPX_OPTS or following is None or not following.startswith("-")):
            consumed = tokens.take()
            if consumed is not None and not removed:
                out.append(consumed)
    return out


def _is_js_number(text: str) -> bool:
    stripped = text.strip(_JS_SPACES)
    return not stripped or _JS_NUMBER.fullmatch(stripped) is not None


def _resolve_short(word: str) -> tuple[str, ...] | None:
    """`resolveShort` de nopt : raccourci exact, lettres groupées, abréviation."""
    name = word.lstrip("-")
    if _ABBREVIATIONS.get(name) == name:
        return None
    if name in _SHORTHANDS:
        return _SHORTHANDS[name]
    if all(character in _SINGLES for character in name):
        return tuple(part for character in name for part in _SHORTHANDS[character])
    if name in _ABBREVIATIONS:
        return None
    return _SHORTHANDS.get(_SHORT_ABBREVIATIONS.get(name, name))


def _store(data: dict[str, object], name: str, value: object, array: bool) -> None:
    if not array:
        data[name] = value
        return
    stored = data.get(name, [])
    data[name] = [*(stored if isinstance(stored, list) else [stored]), value]


def _nopt(argv: list[str]) -> tuple[dict[str, object], list[str]]:
    """Étape 2 (nopt) : les options que npm retient, et les arguments restants."""
    tokens = _Tokens(argv)
    data: dict[str, object] = {}
    remain: list[str] = []
    while (word := tokens.take()) is not None:
        if _ONLY_DASHES.fullmatch(word):
            remain.extend(tokens.rest())
            break
        if not (word.startswith("-") and len(word) > 1):
            remain.append(word)
            continue
        had_equal = "=" in word
        if had_equal:
            word, inline = word.split("=", 1)
            tokens.push_front([inline])
        expansion = _resolve_short(word)
        if expansion is not None:
            if not expansion or word != expansion[0]:
                tokens.push_front(expansion)
                continue
            tokens.push_front(expansion[1:])
        name = word.lstrip("-")
        negated: bool | None = None
        while name.lower().startswith("no-"):
            negated = not negated
            name = name[3:]
        name = _ABBREVIATIONS.get(name, name)
        known = name in _PARSED_TYPES
        is_array, parts = _PARSED_TYPES.get(name, (False, frozenset()))
        if is_array and len(parts) == 1:
            is_array = False
        lookahead = tokens.peek()
        is_bool = (
            negated is not None
            or (not is_array and parts == {"Boolean"})
            or (is_array and "Boolean" in parts)
            or (not known and not had_equal)
            or (lookahead == "false" and is_array and "null" in parts)
        )
        # nopt : une option inconnue donnée plusieurs fois devient une liste.
        to_array = (is_array and "Array" in parts) or (not known and name in data)
        if is_bool:
            value: object = not negated
            if lookahead in ("true", "false"):
                tokens.take()
                value = (lookahead == "true") != bool(negated)
                lookahead = None
            if (
                is_array
                and lookahead
                and (
                    ("lit:" + lookahead) in parts
                    or (lookahead == "null" and "null" in parts)
                    or (
                        not _DOUBLE_DASH_WORD.match(lookahead)
                        and _is_js_number(lookahead)
                        and "Number" in parts
                    )
                    or (not _SINGLE_DASH_WORD.match(lookahead) and "String" in parts)
                )
            ):
                value = tokens.take()  # « --browser mot » : la valeur est le mot suivant
            _store(data, name, value, to_array)
            continue
        if (
            not is_array
            and parts == {"String"}
            and (lookahead is None or _DASH_WORD.match(lookahead))
        ):
            _store(data, name, "", to_array)  # la valeur manque : le mot suivant reste une option
            continue
        if lookahead is None or _ONLY_DASHES.fullmatch(lookahead):
            _store(data, name, True, to_array)
            continue
        _store(data, name, tokens.take(), to_array)
    return data, remain


def _as_text(value: object) -> str | None:
    """Comme `nopt.clean` pour une option texte : un booléen devient « true » / « false »,
    et les espaces au début et à la fin sont retirés."""
    if isinstance(value, bool):
        return "true" if value else "false"
    return value.strip(_JS_SPACES) if isinstance(value, str) else None


def _as_list(value: object) -> list[object]:
    return value if isinstance(value, list) else [] if value is None else [value]


def _arguments(data: dict[str, object], command: list[str]) -> NpxArguments:
    return NpxArguments(
        call=_as_text(data.get("call")),
        packages=[
            text
            for package in _as_list(data.get("package"))
            if (text := _as_text(package)) is not None
        ],
        command=command,
        # Par prudence, une seule occurrence suffit (`--shell-mode=false --shell-mode`).
        shell_mode=any(_as_text(item) == "true" for item in _as_list(data.get("shell-mode"))),
        registries=[
            (key, text)
            for key, value in data.items()
            if key == "registry" or (key.startswith("@") and key.endswith(":registry"))
            for item in _as_list(value)
            if (text := _as_text(item)) not in (None, "", "true", "false")
            # nopt écarte une valeur de `--registry` qui n'est pas une adresse (« schéma:… »).
            and (key != "registry" or _URL_START.match(text) is not None)
        ],
    )


def parse_npx(args: list[str]) -> NpxArguments:
    """Lit les arguments de `npx` (ce qui suit le mot « npx ») comme npm 10."""
    data, remain = _nopt(_npx_prepass(list(args)))
    return _arguments(data, remain)


def parse_npm_exec(args: list[str]) -> NpxArguments | None:
    """Lit `npm …` (ce qui suit le mot « npm ») ; None si ce n'est pas `npm exec` / `npm x`.

    Sans l'étape 1 de npx : les options sont lues partout, avant comme après la
    sous-commande et le paquet (`npm -c "…" exec`, `npm exec srv -p github:x`).
    """
    data, remain = _nopt(list(args))
    if not remain or remain[0] not in _NPM_EXEC_COMMANDS:
        return None
    return _arguments(data, remain[1:])
