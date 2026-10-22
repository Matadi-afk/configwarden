"""Analyse de la ligne de commande d'un serveur MCP : enveloppes, lanceurs, shells, code en ligne.

Un serveur est souvent lancé à travers une « enveloppe » : `cmd /c npx …` (Windows),
`wsl …`, `env VAR=1 …`, `sudo …`, `uv run …`, `bash -c "…"`. Pour vérifier le programme
qui tourne VRAIMENT (paquet figé ? source fiable ?), on retire ces enveloppes une à une.
Les lanceurs de paquets équivalents à npx / uvx (`pnpm dlx`, `yarn dlx`, `bun x`,
`npm exec`, `uv tool run`, `pipx run`) sont ramenés à leur forme courte.

Au passage, on relève ce qui permet d'exécuter n'importe quoi (règle CW101) :
- un shell qui reçoit un script (`bash -c`, `sh -lc`, `pwsh -Command`…) ;
- `cmd /c` avec une ligne de commande (un seul texte, ou des caractères spéciaux
  & | < > ^ % !) ; `cmd /c` qui lance un programme en morceaux séparés est accepté
  (décision du 8 octobre 2026 : c'est la méthode des guides officiels sous Windows) ;
- `npx -c` / `pnpm dlx -c` (une ligne de commande passée à un shell) ;
- toute une ligne de commande avec des opérateurs shell écrite dans "command" ;
- du code écrit dans la configuration (`node -e`, `python -c`…).

Toutes les commandes d'un script sont suivies (`cd x && npx …`), pas seulement la 1re :
séparateurs ; && || | & ( ) et fin de ligne ; le mot qui suit une redirection (`> f`)
est un fichier ; `VAR=1`, `exec`, `then`, `do`… en tête de commande sont passés.

Sécurité : chaque étape consomme au moins un mot, donc l'analyse se termine
toujours, en temps linéaire, même avec des milliers d'enveloppes. Un script n'est
découpé que sur ses 10 000 premiers caractères, au plus 5 fois (imbrication), et
`env -S` au plus 20 fois : au-delà, l'empilement lui-même est signalé. Au plus 20
commandes sont suivies en plus de la 1re, toutes imbrications confondues.
"""

from __future__ import annotations

import re
import shlex
from collections import deque
from dataclasses import dataclass, field

from configwarden.npm_args import parse_npm_exec, parse_npx

_WINDOWS_SUFFIXES = (".exe", ".cmd", ".bat", ".com")

# Enveloppes et leurs options suivies d'une valeur (env a son propre analyseur).
_WRAPPER_OPTIONS_WITH_VALUE: dict[str, set[str]] = {
    "sudo": {"-u", "--user", "-g", "--group", "-h", "--host", "-p", "--prompt", "-D", "--chdir"},
    "doas": {"-u", "-C"},
    "wsl": {"-d", "--distribution", "-u", "--user", "--cd", "--shell-type"},
    "nice": {"-n", "--adjustment"},
    "timeout": {"-s", "--signal", "-k", "--kill-after"},
    "stdbuf": {"-i", "-o", "-e", "--input", "--output", "--error"},
    "nohup": set(),
    "time": set(),
    "setsid": set(),
    "busybox": set(),  # « busybox sh -c … » : l'applet est le vrai programme
    "exec": {"-a"},  # « cd x && exec npx … » dans un script
}
# WSL sans -e/--exec passe la commande au shell Linux par défaut (revue du 8 octobre 2026).
_WSL_EXEC_FLAGS = {"-e", "--exec"}
_POSIX_METACHARACTERS = frozenset(";&|<>`")
# su / runuser : options suivies d'une valeur, et options qui passent un script au shell.
_SU_OPTIONS_WITH_VALUE = {
    "-s",
    "--shell",
    "-g",
    "--group",
    "-G",
    "--supp-group",
    "-w",
    "--whitelist-environment",
}
_SU_COMMAND_OPTIONS = {"-c", "--command", "--session-command"}
# script -c « commande » : options suivies d'une valeur.
_SCRIPT_OPTIONS_WITH_VALUE = {
    "-E",
    "--echo",
    "-I",
    "--log-in",
    "-O",
    "--log-out",
    "-B",
    "--log-io",
    "-T",
    "--log-timing",
    "-m",
    "--logging-format",
    "-o",
    "--output-limit",
}
# deno run / deno x : options suivies d'une valeur.
_DENO_OPTIONS_WITH_VALUE = {
    "-c",
    "--config",
    "--import-map",
    "--lock",
    "--cert",
    "--location",
    "--seed",
    "--ext",
    "-L",
    "--log-level",
    "--preload",
    "--conditions",
}
_URL_SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.-]{0,31}://")
_DURATION = re.compile(r"\d+(?:\.\d+)?[smhd]?")
# env (GNU et BSD) : lettres d'options suivies d'une valeur, et options longues.
_ENV_SHORT_WITH_VALUE = frozenset("uCSPLUa")
_ENV_LONG_WITH_VALUE = {"--unset", "--chdir", "--split-string", "--argv0"}

_POSIX_SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "ash", "fish"}
_POSIX_OPTIONS_WITH_VALUE = {"-o", "+o", "-O", "+O", "--rcfile", "--init-file"}
_POWERSHELLS = {"powershell", "pwsh"}
_CMD_EXEC_FLAGS = {"/c", "/k", "/r"}
_CMD_METACHARACTERS = frozenset("&|<>^%!")
_SHELL_OPERATORS = frozenset(";&|()<>")
# Opérateurs qui font d'un texte une ligne de commande pour un shell.
_COMMAND_LINE_OPERATORS = frozenset("&|;<>`\n\r")
# Modèle à remplir entre chevrons : lettres, chiffres, espaces et ponctuation simple.
# Ni « ` » ni « $ » : un shell exécuterait ce qu'ils entourent.
_ANGLE_PLACEHOLDER = re.compile(r"<[A-Za-z0-9_ .,:/'-]{1,64}>")

# Lanceurs de paquets : téléchargent un paquet du registre et l'exécutent.
_NPM_RUNNERS = {"npx", "pnpx", "bunx"}
# pnpm (« pnpm exec -c », « pnpm -c dlx », « pnpm dlx --shell-mode ») : ligne pour un shell.
_PNPM_SHELL_OPTIONS = {"-c", "--shell-mode"}
# « npm_config_call=… » : npm exécute cette ligne dans un shell (comme « npx -c »).
_NPM_CONFIG_CALL = re.compile(r"npm_config_call=\S", re.IGNORECASE)

# Gestionnaires de paquets : options globales suivies d'une valeur (avant la sous-commande).
_GLOBAL_OPTIONS_WITH_VALUE: dict[str, set[str]] = {
    "npm": set(),  # npm est lu exactement comme npm le fait : voir npm_args.parse_npm_exec
    "pnpm": {"-C", "--dir", "-F", "--filter", "--reporter", "--loglevel", "--package"},
    "yarn": {"--cwd"},
    "bun": {"--cwd"},
    "uv": {
        "--directory",
        "--project",
        "--cache-dir",
        "--config-file",
        "--color",
        "--allow-insecure-host",
    },
    "pipx": set(),
    "poetry": {"-C", "--directory", "-P", "--project"},
    "pipenv": set(),
    "pdm": {"-p", "--project"},
    "hatch": {"-e", "--env", "-p", "--project", "--data-dir", "--cache-dir"},
    "conda": set(),
    "mamba": set(),
    "micromamba": set(),
}
# Sous-commandes qui téléchargent et lancent un paquet : ramenées au lanceur court.
_PACKAGE_SUBCOMMANDS: dict[tuple[str, str], str] = {
    ("pnpm", "dlx"): "npx",
    ("yarn", "dlx"): "npx",
    ("bun", "x"): "bunx",
    ("pipx", "run"): "pipx run",
}
# « uv run » : options suivies d'une valeur (relevé de la documentation d'uv, oct. 2026).
_UV_RUN_OPTIONS_WITH_VALUE = {
    "--with",
    "-w",
    "--with-editable",
    "--with-requirements",
    "--python",
    "-p",
    "--directory",
    "--project",
    "--package",
    "--extra",
    "--group",
    "--no-group",
    "--only-group",
    "--index",
    "--index-url",
    "-i",
    "--extra-index-url",
    "--default-index",
    "--find-links",
    "-f",
    "--env-file",
    "--cache-dir",
    "--config-file",
    "--exclude-newer",
    "--exclude-newer-package",
    "--index-strategy",
    "--keyring-provider",
    "--python-preference",
    "--python-platform",
    "--resolution",
    "--prerelease",
    "--fork-strategy",
    "--link-mode",
    "--refresh-package",
    "--reinstall-package",
    "--upgrade-package",
    "-P",
    "--no-build-package",
    "--no-binary-package",
    "--only-binary-package",
    "--no-build-isolation-package",
    "--config-setting",
    "-C",
    "--color",
    "--allow-insecure-host",
    "--torch-backend",
}
_CONDA_RUN_OPTIONS_WITH_VALUE = {"-n", "--name", "-p", "--prefix", "--cwd"}
# Sous-commandes qui lancent un AUTRE programme, comme env : on analyse ce programme.
_RUN_SUBCOMMANDS: dict[tuple[str, str], set[str]] = {
    ("uv", "run"): _UV_RUN_OPTIONS_WITH_VALUE,
    ("pnpm", "exec"): {"--resume-from", "-C", "--dir", "-F", "--filter"},
    ("yarn", "exec"): set(),
    ("poetry", "run"): set(),
    ("pipenv", "run"): set(),
    ("pdm", "run"): set(),
    ("hatch", "run"): set(),
    ("conda", "run"): _CONDA_RUN_OPTIONS_WITH_VALUE,
    ("mamba", "run"): _CONDA_RUN_OPTIONS_WITH_VALUE,
    ("micromamba", "run"): _CONDA_RUN_OPTIONS_WITH_VALUE,
}
# Paquets ajoutés par « uv run --with » : leur code s'exécute aussi.
_UV_WITH_OPTIONS = {"--with", "-w", "--with-editable"}

# Code écrit directement dans la configuration : options par interpréteur, et
# options suivies d'une valeur (pour ne pas prendre cette valeur pour un script).
_INLINE_CODE_FLAGS: dict[str, set[str]] = {
    "node": {"-e", "--eval", "-p", "--print"},
    "bun": {"-e", "--eval", "-p", "--print"},
    "python": {"-c"},
    "ruby": {"-e"},
    "perl": {"-e", "-E"},
    "php": {"-r"},
}
_INTERPRETER_OPTIONS_WITH_VALUE: dict[str, set[str]] = {
    "node": {"-r", "--require", "--import", "--loader", "--experimental-loader"},
    "bun": {"-r", "--preload"},
    "python": {"-X", "-W"},
}

# Programmes reconnus au début d'un texte « npx -y paquet » écrit dans "command".
_KNOWN_PROGRAMS = (
    set(_WRAPPER_OPTIONS_WITH_VALUE)
    | {"env", "cmd", "uvx", "deno", "nodejs", "docker", "podman", "nerdctl"}
    | _POSIX_SHELLS
    | _POWERSHELLS
    | _NPM_RUNNERS
    | set(_GLOBAL_OPTIONS_WITH_VALUE)
    | set(_INLINE_CODE_FLAGS)
)

_SCRIPT_LIMIT = 10_000
_MAX_SCRIPTS = 5
_MAX_SPLITS = 20
_MAX_WORDS = 200
# Commandes vérifiées en plus de la 1re (« cd x && npx … ; uvx … »), par serveur.
_MAX_COMMANDS = 20
# Variables d'environnement et index de paquets gardés au plus, par serveur (CW112).
_MAX_ASSIGNMENTS = 200
# En tête d'une commande de script, ces mots ne lancent rien : on passe au suivant.
_SCRIPT_KEYWORDS = {"!", "{", "if", "then", "else", "elif", "do", "while", "until"}
# Commandes qui posent des variables d'environnement pour la suite du script (CW112) :
# « export A=1 » (shells POSIX), « set A=1 » (cmd), « $env:A = 1 » (PowerShell).
_EXPORT_WORDS = {"export", "declare", "typeset", "readonly", "local"}
_POWERSHELL_ENV = re.compile(r"\$env:([A-Za-z_][A-Za-z0-9_]*)(=?)(.*)", re.IGNORECASE | re.DOTALL)
# « uv run » : options qui remplacent l'index des paquets (CW112).
_UV_INDEX_OPTIONS = {
    "--index-url", "-i", "--default-index", "--extra-index-url", "--index", "--find-links", "-f",
}  # fmt: skip
_ASSIGNMENT_WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")
_WINDOWS_WORD = re.compile(r'"[^"]*"|[&|<>]+|[^\s"&|<>]+')
_POWERSHELL_WORD = re.compile(r'"[^"]*"|[&|<>;]+|[^\s"&|<>;]+')
_FALLBACK_WORD = re.compile(r"[;&|()<>]+|[^\s;&|()<>]+")


@dataclass
class Launch:
    """Résultat de l'analyse : la commande vraiment lancée et ce qu'on a relevé en route."""

    tokens: list[str]
    risks: list[str] = field(default_factory=list)
    # Paquets que l'enveloppe installe en plus (« uv run --with paquet »).
    sources: list[str] = field(default_factory=list)
    # Toute la ligne de commande écrite dans la configuration (enveloppes comprises).
    words: list[str] = field(default_factory=list)
    # Commandes suivantes d'un script (« bash -c "cd x && npx …" »), enveloppes retirées.
    others: list[list[str]] = field(default_factory=list)
    # Vrai si une limite (nombre de commandes, imbrication) a empêché de tout lire.
    truncated: bool = False
    # Variables d'environnement posées par la ligne de commande : « env A=1 », « A=1 cmd »,
    # « export A=1 », « set A=1 », « $env:A = 1 » ; et index de paquets de « uv run ».
    assignments: list[tuple[str, str]] = field(default_factory=list)
    indexes: list[str] = field(default_factory=list)

    @property
    def executable(self) -> str:
        return executable_name(self.tokens[0]) if self.tokens else ""

    @property
    def args(self) -> list[str]:
        return self.tokens[1:]

    @property
    def commands(self) -> list[list[str]]:
        """Toutes les commandes lancées : la 1re, puis celles qui la suivent dans un script."""
        return [command for command in (self.tokens, *self.others) if command]


def shorten(text: str, limit: int = 60) -> str:
    """Raccourcit un mot repris dans un message (un nom piégé peut faire 1 Mo)."""
    return text if len(text) <= limit else text[:limit] + "…"


def executable_name(command: str) -> str:
    """'/usr/bin/bash' -> 'bash' ; 'C:\\...\\npx.CMD' -> 'npx' ; '"npx"' -> 'npx'."""
    command = command.strip()
    # cmd.exe retire les guillemets autour du programme : « "npx" » lance npx.
    if len(command) >= 2 and command[0] == command[-1] and command[0] in "\"'":
        command = command[1:-1].strip()
    name = re.split(r"[\\/]", command)[-1].lower()
    for suffix in _WINDOWS_SUFFIXES:
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


# Ce que `program_word` renvoie quand la ligne ne se lit pas sans risque de recopier une valeur.
UNKNOWN_PROGRAM = "a command"
_OPEN_SUBSTITUTIONS = ("`", "$(", "${", "(")
# Un mot : des morceaux entre guillemets (espaces comprises) et des caractères sans blanc, collés.
# « "ssh"x\\p » est UN mot, comme pour un shell, pas « "ssh" » suivi de « x\\p » (revue de
# l'Auditeur, 9e passe). Un guillemet jamais fermé n'est qu'un caractère.
_WINDOWS_PROGRAM_WORD = re.compile(r'(?:"[^"]*"|\S)+')


def starts_with_assignment(command: str) -> bool:
    """La ligne commence-t-elle par « NOM=valeur » (variable posée devant le programme) ?"""
    return _ASSIGNMENT_WORD.match(command.lstrip()) is not None


def program_word(command: str) -> str | None:
    """Le programme d'une commande écrite sur une seule ligne, ou None s'il n'y en a pas.

    Les affectations du début (« API_TOKEN=x ./k.sh ») sont sautées : ce n'est pas le
    programme, et leur valeur peut être un jeton qu'un rapport ne doit jamais recopier.
    Quand on ne sait pas où finit une valeur (guillemet jamais fermé, substitution, syntaxe
    de Windows) ou quand la ligne est trop longue pour être lue en entier, on renvoie
    `UNKNOWN_PROGRAM` : deviner un mot qui serait un bout de la valeur recopierait le secret,
    et répondre « aucun programme » cacherait une commande que le shell exécute bien
    (revue de l'Auditeur, 21 octobre 2026).
    """
    text = command.lstrip()
    truncated = len(text) > _SCRIPT_LIMIT
    text = text[:_SCRIPT_LIMIT]
    unreadable = UNKNOWN_PROGRAM if truncated else None
    if "\\" in text:
        # Chemin ou syntaxe de Windows : les barres obliques inverses ne sont pas des échappements.
        words = _WINDOWS_PROGRAM_WORD.findall(text)[:_MAX_WORDS]
        if words and _ASSIGNMENT_WORD.match(words[0]):
            return UNKNOWN_PROGRAM
        return words[0] if words else unreadable
    try:
        lexer = shlex.shlex(text, posix=True)
        lexer.whitespace_split = True
        lexer.commenters = ""
        start = 0
        for word in lexer:
            # Le mot tel qu'il est écrit (guillemets compris) : « ''a=x/ssh » est décodé en
            # « a=x/ssh », mais un shell n'y voit pas d'affectation, le nom est entre guillemets :
            # c'est le programme « a=x/ssh » (revue de l'Auditeur, 8e passe).
            end = lexer.instream.tell()
            written = text[start:end].lstrip()
            start = end
            if not _ASSIGNMENT_WORD.match(word) or not _ASSIGNMENT_WORD.match(written):
                return word
            if any(marker in word for marker in _OPEN_SUBSTITUTIONS):
                # « T=$(echo a b) prog » : le shell ne coupe pas comme shlex, le mot suivant
                # serait un bout de la valeur. Et la substitution s'exécute, même seule.
                return UNKNOWN_PROGRAM
        return unreadable
    except ValueError:
        # Guillemet jamais fermé : le shell refuserait la ligne, mais l'outil peut la lire
        # autrement. On ne s'appuie que sur les mots qui précèdent le guillemet.
        words = text.split()
        for word in words[:_MAX_WORDS]:
            if "'" in word or '"' in word:
                return UNKNOWN_PROGRAM if _ASSIGNMENT_WORD.match(word) else word
            if any(marker in word for marker in _OPEN_SUBSTITUTIONS):
                return UNKNOWN_PROGRAM
            if not _ASSIGNMENT_WORD.match(word):
                return word
        return UNKNOWN_PROGRAM if truncated or len(words) > _MAX_WORDS else None


def split_words(text: str) -> list[str]:
    """Mots d'un texte, comme les découpe un shell POSIX (guillemets, échappements)."""
    return _split_words(text)


def _interpreter(executable: str) -> str | None:
    if executable in {"node", "nodejs"}:
        return "node"
    if re.fullmatch(r"python[0-9.]*|py", executable):
        return "python"
    return executable if executable in _INLINE_CODE_FLAGS else None


def _is_known_program(executable: str) -> bool:
    return executable in _KNOWN_PROGRAMS or _interpreter(executable) is not None


def _after_wrapper(wrapper: str, tokens: list[str], index: int) -> int:
    """Position du programme lancé par une enveloppe (après ses options)."""
    with_value = _WRAPPER_OPTIONS_WITH_VALUE[wrapper]
    duration_seen = False
    while index < len(tokens):
        arg = tokens[index]
        if arg == "--":
            return index + 1
        if arg in with_value:
            index += 2
        elif arg.startswith("-") and len(arg) > 1:
            index += 1
        elif wrapper == "timeout" and not duration_seen and _DURATION.fullmatch(arg):
            duration_seen = True
            index += 1
        else:
            return index
    return index


def _split_string_option(
    tokens: list[str], index: int, prefix: str, attached: str
) -> tuple[int, int, str, str]:
    """(début, fin, préfixe, texte) d'un -S : texte collé (« -Stexte ») ou mot suivant."""
    if attached:
        return index, index + 1, prefix, attached
    text = tokens[index + 1] if index + 1 < len(tokens) else ""
    return index, index + 2, prefix, text


def _after_env(tokens: list[str], index: int) -> tuple[int, tuple[int, int, str, str] | None]:
    """`env [options] [VAR=valeur…] programme` : position du programme, ou un -S à découper.

    `env -S "bash -c …"` (--split-string) découpe le texte en mots et les exécute : sans
    ce découpage, « bash -c … » passerait pour un nom de programme inconnu. Renvoie
    (position, None), ou (position, (début, fin, préfixe, texte)) : tokens[début:fin]
    doit être remplacé par le préfixe (« -i » de « -iS ») suivi des mots du texte.
    """
    while index < len(tokens):
        arg = tokens[index]
        if arg == "--":
            return index + 1, None
        if arg == "-":
            index += 1  # « env - » : comme -i
            continue
        if arg.startswith("--"):
            name, equals, value = arg.partition("=")
            if name == "--split-string":
                return index, _split_string_option(tokens, index, "", value if equals else "")
            index += 2 if name in _ENV_LONG_WITH_VALUE and not equals else 1
            continue
        if arg.startswith("-") and len(arg) > 1:
            letters = arg[1:]
            for position, letter in enumerate(letters):
                if letter not in _ENV_SHORT_WITH_VALUE:
                    continue
                attached = letters[position + 1 :]
                if letter == "S":
                    prefix = "-" + letters[:position] if position else ""
                    return index, _split_string_option(tokens, index, prefix, attached)
                index += 1 if attached else 2
                break
            else:
                index += 1  # groupe d'options sans valeur (« -iv »)
            continue
        if "=" in arg and not arg.startswith("="):
            index += 1  # VARIABLE=valeur
            continue
        return index, None
    return index, None


def _cmd_command(tokens: list[str], index: int) -> tuple[int, str] | None:
    """`cmd /d /s /c …` : position de la commande lancée, et l'option utilisée."""
    while index < len(tokens):
        arg = tokens[index]
        if arg.lower() in _CMD_EXEC_FLAGS:
            return index + 1, arg
        if not arg.startswith("/"):
            return None
        index += 1  # /d, /s, /q, /e:on…
    return None


def _posix_script(tokens: list[str], index: int) -> tuple[str, str] | None:
    """`bash [options] -c script` : (option, script), ou None (fichier de script)."""
    while index < len(tokens):
        arg = tokens[index]
        if arg in _POSIX_OPTIONS_WITH_VALUE:
            index += 2
        elif arg == "--" or not arg.startswith(("-", "+")) or len(arg) == 1:
            return None  # le 1er argument positionnel est un fichier de script
        elif arg.startswith("-") and not arg.startswith("--") and "c" in arg[1:]:
            script = tokens[index + 1] if index + 1 < len(tokens) else ""
            return arg, script
        else:
            index += 1
    return None


def _powershell_command(tokens: list[str], index: int) -> tuple[str, str, bool] | None:
    """`pwsh -Command …` / `-EncodedCommand …` : (option, script, encodé ?)."""
    while index < len(tokens):
        arg = tokens[index]
        option = "-" + arg[1:].lower() if arg.startswith(("-", "/")) else ""
        if option in {"-file", "-f"}:
            return None  # la suite appartient au script lancé
        if len(option) >= 2:
            # PowerShell accepte tout début non ambigu : -e, -enc, -ec, -c, -com…
            if option == "-ec" or "-encodedcommand".startswith(option):
                return arg, "", True
            if "-command".startswith(option):
                return arg, " ".join(tokens[index + 1 :]), False
        index += 1
    return None


def _inline_code(interpreter: str, executable: str, tokens: list[str], index: int) -> str | None:
    """Option de code en ligne (`node -e`, `python -c`…) avant tout fichier de script."""
    flags = _INLINE_CODE_FLAGS[interpreter]
    with_value = _INTERPRETER_OPTIONS_WITH_VALUE.get(interpreter, set())
    while index < len(tokens):
        arg = tokens[index]
        option = arg.split("=", 1)[0] if arg.startswith("--") else arg
        if option in flags:
            return f"{shorten(executable)} {option}"
        if interpreter == "python":
            if arg == "-m":
                return None  # module : la suite lui appartient
            if re.fullmatch(r"-[A-Za-z]*c[A-Za-z]*", arg):
                return f"{shorten(executable)} {shorten(arg)}"  # options groupées : python -Bc
        if arg in with_value:
            index += 2
            continue
        if not arg.startswith("-"):
            return None  # fichier de script
        index += 1
    return None


def _subcommand(
    program: str, tokens: list[str], index: int
) -> tuple[int, list[str], str | None] | None:
    """Position de la sous-commande d'un gestionnaire, ses options « --package », et
    l'option shell de pnpm placée avant elle (« pnpm -c exec "…" », « pnpm -c dlx "…" »)."""
    with_value = _GLOBAL_OPTIONS_WITH_VALUE[program]
    package_options: list[str] = []
    shell_option: str | None = None
    while index < len(tokens):
        arg = tokens[index]
        if arg == "--package" and index + 1 < len(tokens):
            package_options += [arg, tokens[index + 1]]  # pnpm --package=x dlx …
        elif arg.startswith("--package="):
            package_options.append(arg)
        elif program == "pnpm" and arg in _PNPM_SHELL_OPTIONS:
            shell_option = arg
        if arg in with_value:
            index += 2
        elif arg.startswith("-"):
            index += 1
        else:
            return index, package_options, shell_option
    return None


def _after_run(
    subcommand: tuple[str, str], tokens: list[str], index: int, indexes: list[str] | None = None
) -> tuple[int, list[str], str | None]:
    """`uv run [options] programme` : (position du programme, paquets --with, option shell).

    `indexes` reçoit les index de paquets donnés à `uv run` (« --index-url … », CW112).
    """
    with_value = _RUN_SUBCOMMANDS[subcommand]
    sources: list[str] = []
    while index < len(tokens):
        arg = tokens[index]
        name, equals, value = arg.partition("=")
        if arg == "--":
            return index + 1, sources, None
        if subcommand == ("pnpm", "exec") and name in _PNPM_SHELL_OPTIONS:
            return index, sources, name  # pnpm exec -c : ligne de commande pour un shell
        if subcommand == ("uv", "run") and name in _UV_WITH_OPTIONS:
            if equals:
                sources.append(value)
            elif index + 1 < len(tokens):
                sources.append(tokens[index + 1])
        if subcommand == ("uv", "run") and name in _UV_INDEX_OPTIONS and indexes is not None:
            if equals:
                indexes.append(value)
            elif index + 1 < len(tokens):
                indexes.append(tokens[index + 1])
        if arg in with_value:
            index += 2
        elif arg.startswith("-"):
            index += 1
        else:
            return index, sources, None
    return index, sources, None


def _su_command(program: str, tokens: list[str], index: int) -> tuple[str, int, str] | None:
    """`su - bob -c "…"` ou `runuser -u bob -- programme` : (genre, position, script).

    genre « script » : position de l'option -c, et le script passé au shell ;
    genre « program » : position du programme, lancé directement (sans shell).
    """
    direct = False  # runuser -u : le programme est lancé sans shell
    while index < len(tokens):
        arg = tokens[index]
        name, equals, value = arg.partition("=")
        if arg.startswith("--") and equals and name in _SU_COMMAND_OPTIONS:
            return "script", index, value
        if arg in _SU_COMMAND_OPTIONS:
            return "script", index, tokens[index + 1] if index + 1 < len(tokens) else ""
        if program == "runuser" and arg in {"-u", "--user"}:
            direct = True
            index += 2
        elif arg == "--":
            return ("program", index + 1, "") if direct else None
        elif arg in _SU_OPTIONS_WITH_VALUE:
            index += 2
        elif arg.startswith("-") and len(arg) > 1:
            index += 1
        elif direct:
            return "program", index, ""
        else:
            index += 1  # « su - bob » : le « - » et le nom d'utilisateur
    return None


def _script_command(tokens: list[str], index: int) -> tuple[str, str] | None:
    """`script -qc "commande" /dev/null` : (option, commande), ou None."""
    while index < len(tokens):
        arg = tokens[index]
        following = tokens[index + 1] if index + 1 < len(tokens) else ""
        if arg.startswith("--command="):
            return "--command", arg.partition("=")[2]
        if arg == "--command":
            return arg, following
        if arg.startswith("-") and not arg.startswith("--") and "c" in arg[1:]:
            attached = arg[arg.index("c", 1) + 1 :]
            return arg, attached or following
        if arg in _SCRIPT_OPTIONS_WITH_VALUE:
            index += 2
        elif arg.startswith("-"):
            index += 1
        else:
            return None  # fichier d'enregistrement : pas de commande
    return None


def _after_deno(tokens: list[str], index: int) -> int:
    """`deno run [options] module` : position du module."""
    while index < len(tokens):
        arg = tokens[index]
        if arg in _DENO_OPTIONS_WITH_VALUE:
            index += 2
        elif arg.startswith("-"):
            index += 1  # -A, --allow-net=…
        else:
            return index
    return index


def _shell_metacharacters_from(tokens: list[str]) -> list[bool]:
    """flags[i] : un opérateur de shell POSIX (; & | < > ` ou $( ) apparaît-il dans tokens[i:] ?"""
    flags = [False] * (len(tokens) + 1)
    for index in range(len(tokens) - 1, -1, -1):
        token = tokens[index]
        flags[index] = flags[index + 1] or bool(_POSIX_METACHARACTERS & set(token)) or "$(" in token
    return flags


def _shell_preprocess(script: str) -> tuple[str, list[str]]:
    """Retire les commentaires et sort les substitutions `…` et $(…) d'un script POSIX.

    Comme bash : « # » ne commence un commentaire qu'en début de mot et hors guillemets
    (« build#1 » n'en est pas un) ; une substitution s'exécute même entre guillemets
    doubles. Chaque substitution est remplacée par un mot neutre, et son contenu est
    renvoyé à part pour être analysé comme un script. Un seul passage, temps linéaire.
    """
    out: list[str] = []
    inner: list[str] = []
    quote = ""
    index, length = 0, len(script)
    while index < length:
        char = script[index]
        if quote == "'":
            out.append(char)
            quote = "" if char == "'" else quote
            index += 1
            continue
        if char == "\\" and index + 1 < length:
            out.append(script[index : index + 2])
            index += 2
            continue
        if char == "`" or (char == "$" and script.startswith("$(", index)):
            closing = "`" if char == "`" else ")"
            start = index + (1 if char == "`" else 2)
            depth, end = 1, start
            while end < length and depth:
                if closing == ")" and script[end] == "(":
                    depth += 1
                elif script[end] == closing:
                    depth -= 1
                end += 1
            inner.append(script[start : end - 1 if not depth else end])
            out.append("_")
            index = end
            continue
        if quote == '"':
            out.append(char)
            quote = "" if char == '"' else quote
        elif char in "'\"":
            out.append(char)
            quote = char
        elif char == "#" and (not out or out[-1][-1:].isspace() or out[-1][-1:] in ";&|()<>"):
            newline = script.find("\n", index)
            index = length if newline < 0 else newline
            continue
        else:
            out.append(char)
        index += 1
    return "".join(out), inner


def _split_commands(words: list[str]) -> list[list[str]]:
    """Commandes d'une suite de mots, séparées par ; && || | & ( ) (au plus 1 + 21).

    Une commande de plus que la limite est gardée : l'appelant sait ainsi que le script
    en contenait trop, et le signale.

    Après une redirection (« > fichier », « 2>&1 », « < entrée »), le mot suivant est un
    fichier, pas le début d'une commande.
    """
    found: list[list[str]] = []
    current: list[str] = []
    skip_file = False
    for word in words:
        if skip_file:
            skip_file = False
        elif word and set(word) <= _SHELL_OPERATORS:
            if "<" in word or ">" in word:
                skip_file = True
            elif current:
                found.append(current)
                current = []
                if len(found) > _MAX_COMMANDS + 1:
                    return found
        elif len(current) < _MAX_WORDS:
            current.append(word.strip("'\""))
    if current:
        found.append(current)
    return found


def _split_posix(script: str, depth: int = 0) -> list[list[str]]:
    # Une ligne continuée (barre oblique inverse en fin de ligne) reste une commande ; une
    # fin de ligne sépare deux commandes, comme « ; » (shlex n'y voit qu'un espace).
    script = script[:_SCRIPT_LIMIT].replace("\\\n", " ")
    cleaned, substitutions = _shell_preprocess(script)
    cleaned = cleaned.replace("\n", "\n;")
    try:
        lexer = shlex.shlex(cleaned, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        lexer.commenters = ""  # commentaires déjà retirés, à la manière de bash
        found = _split_commands(list(lexer))
    except ValueError:
        # Guillemet jamais fermé : découpage simple, sans planter.
        found = _split_commands(_FALLBACK_WORD.findall(cleaned))
    if depth < _MAX_SCRIPTS:
        # Les commandes des substitutions s'exécutent aussi : elles suivent la 1re commande.
        for inner in substitutions[: _MAX_COMMANDS + 1]:
            found.extend(_split_posix(inner, depth + 1))
            if len(found) > _MAX_COMMANDS + 1:
                break
    return found


def _split_windows(text: str, *, powershell: bool = False) -> list[list[str]]:
    """Commandes d'une ligne cmd (& && || |) ou PowerShell (et « ; »)."""
    text = text[:_SCRIPT_LIMIT]
    if powershell:
        text = text.replace("\n", ";")  # une instruction par ligne
        return _split_commands(_POWERSHELL_WORD.findall(text))
    return _split_commands(_WINDOWS_WORD.findall(text.replace("\n", " & ")))


def _split_words(text: str) -> list[str]:
    """Mots d'un texte, comme les découpe `env -S` (guillemets, échappements, sans shell)."""
    text = text[:_SCRIPT_LIMIT]
    try:
        lexer = shlex.shlex(text, posix=True)
        lexer.whitespace_split = True
        lexer.commenters = ""
        words: list[str] = []
        for word in lexer:
            words.append(word)
            if len(words) >= _MAX_WORDS:
                break
        return words
    except ValueError:
        return text.split()[:_MAX_WORDS]


def _command_words(command: str) -> tuple[list[str], bool, list[list[str]]]:
    """« npx -y paquet » écrit tout entier dans "command".

    Renvoie (mots de la 1re commande, opérateurs shell ?, commandes suivantes). Un chemin
    avec des espaces (« C:\\Program Files\\…\\npx.cmd ») reste un seul mot : on ne
    découpe que si le premier mot est un programme connu. Les commandes qui suivent un
    opérateur (« cd x && npx … ») sont toujours renvoyées, pour être vérifiées aussi.
    """
    stripped = command.strip()
    if not any(char.isspace() for char in stripped):
        return [command], False, []
    # « <path-to-npx> » ou « ?key=<your-api-key> » : des modèles à remplir, pas des
    # redirections. On les retire avant de chercher les opérateurs.
    without_placeholders = _ANGLE_PLACEHOLDER.sub("", stripped[:_SCRIPT_LIMIT])
    operators = bool(_COMMAND_LINE_OPERATORS & set(without_placeholders)) or (
        "$(" in without_placeholders
    )
    found = _split_windows(stripped) if "\\" in stripped else _split_posix(stripped)
    rest = found[1:] if operators else []
    if found and _is_known_program(executable_name(found[0][0])):
        return found[0], operators, rest
    return [command], operators, rest


def _metacharacters_from(tokens: list[str]) -> list[bool]:
    """flags[i] : un caractère spécial de cmd apparaît-il dans tokens[i:] ?

    Calculé une fois par liste (en partant de la fin) : vérifier la suite à chaque
    `cmd /c` imbriqué coûterait un temps quadratique sur une chaîne piégée.
    """
    flags = [False] * (len(tokens) + 1)
    for index in range(len(tokens) - 1, -1, -1):
        flags[index] = flags[index + 1] or bool(_CMD_METACHARACTERS & set(tokens[index]))
    return flags


@dataclass
class _Work:
    """État partagé par toutes les commandes d'un serveur : constats et limites."""

    risks: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    pending: deque[list[str]] = field(default_factory=deque)
    queued: int = 0
    scripts: int = 0
    splits: int = 0
    # Une limite a été atteinte : certaines commandes n'ont pas été lues (signalé, CW100).
    truncated: bool = False
    assignments: list[tuple[str, str]] = field(default_factory=list)
    indexes: list[str] = field(default_factory=list)

    def first_of(self, found: list[list[str]]) -> list[str]:
        """1re commande d'un script ; les suivantes attendent leur tour (20 au plus)."""
        for command in found[1:]:
            if self.queued >= _MAX_COMMANDS:
                self.truncated = True
                break
            self.queued += 1
            self.pending.append(command)
        return found[0] if found else []


def analyse(command: str, args: list[str]) -> Launch:
    """Retire les enveloppes et relève les risques CW101 d'une ligne de commande.

    Toutes les commandes d'un script sont suivies (« bash -c "cd x && npx …" ») : la
    1re dans `tokens`, les suivantes dans `others`. Les limites sont communes à toutes
    les commandes d'un serveur, imbrication comprise : le travail reste borné.
    """
    words, operators, rest = _command_words(command)
    tokens = [*words, *args]
    work = _Work()
    if operators:
        work.risks.append("passes a command line with shell operators in 'command'")
    work.first_of([[], *rest])  # commandes qui suivent un opérateur dans "command"
    first = _unwrap(tokens, work)
    others: list[list[str]] = []
    while work.pending:
        unwrapped = _unwrap(work.pending.popleft(), work)
        if unwrapped:
            others.append(unwrapped)
    return Launch(
        tokens=first,
        risks=work.risks,
        sources=work.sources,
        words=list(tokens),
        others=others,
        truncated=work.truncated,
        assignments=work.assignments[:_MAX_ASSIGNMENTS],
        indexes=work.indexes[:_MAX_ASSIGNMENTS],
    )


def _unquote(text: str) -> str:
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        return text[1:-1]
    return text


def _record_assignment(work: _Work, word: str) -> None:
    """« NOM=valeur » -> (NOM, valeur), gardé pour CW112 (nombre borné)."""
    name, equals, value = _unquote(word).partition("=")
    if equals and name and len(work.assignments) < _MAX_ASSIGNMENTS:
        work.assignments.append((name, _unquote(value)))


def _powershell_assignment(tokens: list[str], start: int, work: _Work) -> bool:
    """« $env:NOM = "valeur" » (un, deux ou trois mots) ; vrai si c'en est une."""
    found = _POWERSHELL_ENV.fullmatch(tokens[start].strip())
    if found is None:
        return False
    name, equals, rest = found.groups()
    following = tokens[start + 1 : start + 3]
    if equals and not rest and following:
        rest = following[0]  # « $env:A="valeur" » : le découpage sépare les guillemets
    elif not equals and following and following[0] == "=":
        rest = following[1] if len(following) > 1 else ""
    elif not equals and following and following[0].startswith("="):
        rest = following[0][1:]
    elif not equals:
        return False
    _record_assignment(work, f"{name}={_unquote(rest)}")
    return True


def _unwrap(tokens: list[str], work: _Work) -> list[str]:
    """Retire les enveloppes d'UNE commande ; renvoie le programme et ses arguments."""
    risks = work.risks
    sources = work.sources
    start = 0
    label = ""  # nom écrit par l'utilisateur quand un lanceur a été ramené à npx / uvx
    metacharacters: list[bool] | None = None
    # (liste analysée, drapeaux) : la liste est gardée pour savoir si le calcul est à jour.
    shell_meta: tuple[list[str], list[bool]] | None = None
    while start < len(tokens):
        if _ASSIGNMENT_WORD.match(tokens[start]) or tokens[start] in _SCRIPT_KEYWORDS:
            if _NPM_CONFIG_CALL.match(tokens[start]):
                risks.append("executes a command line through 'npm_config_call'")
            if _ASSIGNMENT_WORD.match(tokens[start]):
                _record_assignment(work, tokens[start])
            start += 1  # « FOO=1 npx … », « then npx … » : rien n'est lancé par ce mot
            continue
        if _powershell_assignment(tokens, start, work):
            return []  # « $env:A = 1 » ne lance rien
        executable = executable_name(tokens[start])
        if executable in _EXPORT_WORDS:
            for word in tokens[start + 1 :]:
                if _ASSIGNMENT_WORD.match(word):
                    _record_assignment(work, word)
            return []  # « export A=1 » ne lance rien
        if executable == "set" and start + 1 < len(tokens):
            # cmd : « set NOM=valeur avec espaces » (« set /a » et « set /p » : pas une variable).
            rest = [word for word in tokens[start + 1 :] if not word.startswith("/")]
            if rest:
                _record_assignment(work, " ".join(rest))
            return []
        if executable == "call":
            start += 1  # cmd : « call programme » lance ce programme
            continue
        if executable == "start":
            # cmd : « start "titre" /b programme » ; le titre et les options /x sont passés.
            start += 1
            while start < len(tokens) and (not tokens[start] or tokens[start][:1] == "/"):
                start += 1
            continue
        if executable == "env":
            position, split = _after_env(tokens, start + 1)
            if any(_NPM_CONFIG_CALL.match(word) for word in tokens[start + 1 : position]):
                risks.append("executes a command line through 'npm_config_call'")
            for word in tokens[start + 1 : position]:
                if _ASSIGNMENT_WORD.match(word):
                    _record_assignment(work, word)
            if split is None:
                start = position
                continue
            if work.splits >= _MAX_SPLITS:
                risks.append("executes commands through deeply nested 'env -S'")
                tokens, start = [], 0
                break
            work.splits += 1
            begin, end, prefix, text = split
            tokens = (
                tokens[:begin] + ([prefix] if prefix else []) + _split_words(text) + tokens[end:]
            )
            metacharacters = None
            continue  # on relit les options d'env avec les mots découpés
        if executable in _WRAPPER_OPTIONS_WITH_VALUE:
            position = _after_wrapper(executable, tokens, start + 1)
            if executable == "wsl" and not _WSL_EXEC_FLAGS & set(tokens[start + 1 : position]):
                # Sans -e, WSL passe la commande au shell Linux : « ; », « | »… s'exécutent.
                if shell_meta is None or shell_meta[0] is not tokens:
                    shell_meta = (tokens, _shell_metacharacters_from(tokens))
                if position < len(tokens) and shell_meta[1][position]:
                    risks.append("executes a command line through 'wsl' (default shell)")
            start = position
            continue
        if executable in {"su", "runuser", "script"}:
            if executable == "script":
                found_script_cmd = _script_command(tokens, start + 1)
                kind, flag, script = (
                    ("script", *found_script_cmd) if found_script_cmd else ("", "", "")
                )
            else:
                found_su = _su_command(executable, tokens, start + 1)
                if found_su is not None and found_su[0] == "program":
                    start = found_su[1]
                    continue
                kind = found_su[0] if found_su else ""
                flag = tokens[found_su[1]].partition("=")[0] if found_su else ""
                script = found_su[2] if found_su else ""
            if kind != "script":
                break
            risks.append(f"executes commands through '{shorten(executable)} {shorten(flag)}'")
            if work.scripts >= _MAX_SCRIPTS:
                work.truncated = True
                tokens, start = [], 0
                break
            work.scripts += 1
            tokens, start, metacharacters = work.first_of(_split_posix(script)), 0, None
            continue
        if executable == "deno" and start + 1 < len(tokens) and tokens[start + 1] in {"run", "x"}:
            subcommand = tokens[start + 1]
            position = _after_deno(tokens, start + 2)
            module = tokens[position] if position < len(tokens) else ""
            if _URL_SCHEME.match(module):
                sources.append(module)  # script téléchargé et exécuté tel quel
                tokens, start = [], 0
                break
            if module.lower().startswith(("npm:", "jsr:")):
                # « -- » : le paquet de deno n'est jamais lu comme une option de npx.
                tokens, start, metacharacters = (
                    ["npx", "--", module[4:], *tokens[position + 1 :]],
                    0,
                    None,
                )
                label = f"deno {subcommand}"
                continue
            break
        if executable == "npm":
            # npm lit ses options partout sur la ligne (npm_args.py) : seule `npm exec` (ou
            # `npm x`) lance un paquet. Elle est transmise sous la forme exacte de npx.
            reading = parse_npm_exec(tokens[start + 1 :])
            if reading is None:
                break
            tokens, start, metacharacters = ["npx", *reading.as_npx_args()], 0, None
            label = "npm exec"
            continue
        if executable in _GLOBAL_OPTIONS_WITH_VALUE:
            found_sub = _subcommand(executable, tokens, start + 1)
            if found_sub is not None:
                sub, package_options, shell_option = found_sub
                word = tokens[sub].lower()
                next_word = tokens[sub + 1].lower() if sub + 1 < len(tokens) else ""
                if (executable, word, next_word) == ("uv", "tool", "run"):
                    tokens, start, metacharacters = ["uvx", *tokens[sub + 2 :]], 0, None
                    label = "uv tool run"
                    continue
                runner = _PACKAGE_SUBCOMMANDS.get((executable, word))
                if runner is not None:
                    shell_mode = ["--shell-mode"] if shell_option else []  # pnpm -c dlx …
                    tokens = [runner, *package_options, *shell_mode, *tokens[sub + 1 :]]
                    start, metacharacters = 0, None
                    label = f"{executable} {word}"
                    continue
                if (executable, word) in _RUN_SUBCOMMANDS:
                    position, found_sources, shell_flag = _after_run(
                        (executable, word), tokens, sub + 1, work.indexes
                    )
                    sources.extend(found_sources)
                    if shell_flag is None and (executable, word) == ("pnpm", "exec"):
                        shell_flag = shell_option  # pnpm -c exec "…"
                    if shell_flag is not None:
                        risks.append(
                            f"executes a command line through '{executable} {word} {shell_flag}'"
                        )
                        tokens, start = [], 0
                        break
                    if (
                        (executable, word) == ("uv", "run")
                        and position < len(tokens)
                        and _URL_SCHEME.match(tokens[position])
                    ):
                        sources.append(tokens[position])  # uv run https://… : script distant
                        tokens, start = [], 0
                        break
                    start = position
                    continue
            # Sous-commande inconnue : « bun -e … » reste vérifié plus bas (code en ligne).
        if executable in _NPM_RUNNERS:
            # `npx -c "…"` (lu exactement comme npm 10) ou `pnpm dlx --shell-mode "…"`.
            shell_flag = parse_npx(tokens[start + 1 :]).shell_option()
            if shell_flag is not None:
                runner_name = shorten(label or executable)
                risks.append(f"executes a command line through '{runner_name} {shell_flag}'")
            break
        if executable == "cmd":
            found = _cmd_command(tokens, start + 1)
            if found is None:
                break
            inner_start, flag = found
            single_text = len(tokens) - inner_start == 1 and any(
                c.isspace() for c in tokens[inner_start]
            )
            if metacharacters is None:
                metacharacters = _metacharacters_from(tokens)
            if single_text or metacharacters[inner_start]:
                risks.append(f"executes a command line through 'cmd {shorten(flag)}'")
            if single_text and work.scripts < _MAX_SCRIPTS:
                work.scripts += 1
                tokens = work.first_of(_split_windows(tokens[inner_start]))
                start, metacharacters = 0, None
            else:
                start = inner_start
            continue
        if executable in _POSIX_SHELLS:
            found_script = _posix_script(tokens, start + 1)
            if found_script is None:
                break
            flag, script = found_script
            risks.append(f"executes commands through '{shorten(executable)} {shorten(flag)}'")
            if work.scripts >= _MAX_SCRIPTS:
                work.truncated = True
                tokens, start = [], 0
                break
            work.scripts += 1
            tokens, start, metacharacters = work.first_of(_split_posix(script)), 0, None
            continue
        if executable in _POWERSHELLS:
            found_ps = _powershell_command(tokens, start + 1)
            if found_ps is None:
                break
            flag, script, encoded = found_ps
            if encoded:
                risks.append(
                    f"executes an encoded command through '{shorten(executable)} {shorten(flag)}'"
                )
                tokens, start = [], 0
                break
            risks.append(f"executes commands through '{shorten(executable)} {shorten(flag)}'")
            if work.scripts >= _MAX_SCRIPTS:
                work.truncated = True
                tokens, start = [], 0
                break
            work.scripts += 1
            tokens = work.first_of(_split_windows(script, powershell=True))
            start, metacharacters = 0, None
            continue
        interpreter = _interpreter(executable)
        if interpreter is not None:
            inline = _inline_code(interpreter, executable, tokens, start + 1)
            if inline is not None:
                risks.append(f"executes inline code ('{inline}')")
        elif executable == "deno" and start + 1 < len(tokens) and tokens[start + 1] == "eval":
            risks.append("executes inline code ('deno eval')")
        break
    return tokens[start:]
