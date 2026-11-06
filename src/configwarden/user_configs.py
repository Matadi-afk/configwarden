"""Où les outils IA rangent leur configuration pour l'utilisateur courant (`scan --user`).

Pourquoi (décision du 6 novembre 2026) : pour vérifier SA machine, il ne faut pas parcourir
tout le dossier personnel (lent, et plein de fichiers sans rapport), mais lire seulement les
fichiers où Claude, Cursor, VS Code, Gemini CLI, Windsurf, Zed… rangent leurs serveurs MCP,
leurs réglages et leurs commandes automatiques. Emplacements relevés dans la documentation
officielle de chaque outil (recherche de l'Éclaireur, 6 novembre 2026).

Sécurité :
- liste FERMÉE de fichiers : jamais de parcours du dossier personnel ;
- les fichiers où les outils rangent leurs jetons de connexion ne sont JAMAIS lus
  (`~/.claude/.credentials.json`, `~/.codex/auth.json`, `~/.gemini/mcp-oauth-tokens.json`,
  `~/.copilot/config.json`, `~/.aws/credentials`…) : ils ne figurent pas dans la liste, et
  `NEVER_READ` les refuse même si un chemin calculé y menait ;
- les chemins affichés commencent par `~` : un rapport ne montre pas le nom d'utilisateur.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePath, PurePosixPath, PureWindowsPath

# Noms de fichiers qui contiennent des jetons de connexion : jamais ouverts.
NEVER_READ = frozenset(
    {
        ".credentials.json",
        "auth.json",
        "mcp-oauth-tokens.json",
        "oauth_creds.json",  # Gemini CLI
        "google_accounts.json",  # Gemini CLI
        "credentials",
        "config.json",  # ~/.copilot/config.json : authentification de Copilot CLI
    }
)
# Exception : ces config.json-là sont des configurations MCP (Continue), pas des jetons.
_ALLOWED_CONFIG_JSON = ("/.continue/config.json",)

# Éditeurs de la famille VS Code : leur dossier « User » a la même forme.
_VSCODE_FAMILY = ("Code", "Code - Insiders", "Cursor", "Windsurf")
# Extensions qui rangent des serveurs MCP dans le stockage global de l'éditeur.
_EXTENSION_FILES = (
    "globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json",  # Cline
    "globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json",  # Roo Code
)
_MAX_PROFILES = 200  # profils VS Code, extensions Gemini : bornés (au-delà, on le dit)
_UNSUPPORTED = (
    (".codex/config.toml", "Codex CLI (TOML)"),
    (".continue/config.yaml", "Continue (YAML)"),
)


@dataclass(frozen=True)
class Location:
    """Un fichier à lire : son chemin réel et le chemin affiché (`~/…`)."""

    path: Path
    shown: str
    folder: str  # dossier « logique » (`.claude` pour les réglages de Claude Code)


def _home(env: Mapping[str, str], windows: bool) -> PurePath:
    flavour = PureWindowsPath if windows else PurePosixPath
    if windows:
        return flavour(env.get("USERPROFILE") or str(Path.home()))
    return flavour(env.get("HOME") or str(Path.home()))


def user_home(env: Mapping[str, str] | None = None, platform: str | None = None) -> str:
    """Le dossier personnel, tel que les outils le voient (HOME, ou USERPROFILE sous Windows)."""
    import sys

    env = os.environ if env is None else env
    return str(_home(env, (sys.platform if platform is None else platform) == "win32"))


def candidate_paths(env: Mapping[str, str], platform: str) -> list[tuple[PurePath, str]]:
    """Les emplacements possibles (chemin, dossier logique), pour `platform`
    (`sys.platform`). Fonction pure : aucun accès au disque, testable pour chaque système."""
    windows = platform == "win32"
    mac = platform == "darwin"
    home = _home(env, windows)
    flavour = PureWindowsPath if windows else PurePosixPath
    found: list[tuple[PurePath, str]] = []

    def add(path: PurePath, folder: str = "") -> None:
        found.append((path, folder or path.parent.name))

    if windows:
        appdata = flavour(env.get("APPDATA") or str(home / "AppData" / "Roaming"))
        program_files = flavour(env.get("ProgramFiles") or "C:\\Program Files")
        program_data = flavour(env.get("ProgramData") or "C:\\ProgramData")
        app_support = appdata
    elif mac:
        app_support = home / "Library" / "Application Support"
    else:
        app_support = flavour(env.get("XDG_CONFIG_HOME") or str(home / ".config"))
    xdg = flavour(env.get("XDG_CONFIG_HOME") or str(home / ".config"))

    # Claude Desktop
    add(app_support / "Claude" / "claude_desktop_config.json")
    # Claude Code : ~/.claude.json, ~/.claude/settings*.json, réglages gérés du système
    claude_dir = flavour(env["CLAUDE_CONFIG_DIR"]) if env.get("CLAUDE_CONFIG_DIR") else None
    add(home / ".claude.json")
    for directory in (home / ".claude", claude_dir):
        if directory is None:
            continue
        if directory != home / ".claude":
            add(directory / ".claude.json")
        for name in ("settings.json", "settings.local.json"):
            add(directory / name, ".claude")
    if windows:
        managed = program_files / "ClaudeCode"
    elif mac:
        managed = PurePosixPath("/Library/Application Support/ClaudeCode")
    else:
        managed = PurePosixPath("/etc/claude-code")
    add(managed / "managed-settings.json", ".claude")
    add(managed / "managed-mcp.json")
    # Cursor
    add(home / ".cursor" / "mcp.json")
    add(home / ".cursor" / "hooks.json")
    if windows:
        add(program_data / "Cursor" / "hooks.json")
    elif mac:
        add(PurePosixPath("/Library/Application Support/Cursor/hooks.json"))
    else:
        add(PurePosixPath("/etc/cursor/hooks.json"))
    # VS Code et sa famille : réglages, MCP et tâches de l'utilisateur, puis extensions
    for editor in _VSCODE_FAMILY:
        user = app_support / editor / "User"
        for name in ("settings.json", "mcp.json", "tasks.json"):
            add(user / name)
        for extension_file in _EXTENSION_FILES:
            add(user / extension_file)
    # Windsurf / Devin
    add(home / ".codeium" / "windsurf" / "mcp_config.json")
    add(home / ".codeium" / "windsurf-next" / "mcp_config.json")
    add((appdata if windows else xdg) / "devin" / "mcp_config.json")
    # Gemini CLI (réglages de l'utilisateur et du système)
    add(home / ".gemini" / "settings.json")
    if windows:
        add(program_data / "gemini-cli" / "settings.json")
    elif mac:
        add(PurePosixPath("/Library/Application Support/GeminiCli/settings.json"))
    else:
        add(PurePosixPath("/etc/gemini-cli/settings.json"))
    # Zed
    add((appdata / "Zed" if windows else xdg / "zed") / "settings.json")
    # Cline (version 3), Kiro, Amazon Q, Copilot CLI, Continue
    add(home / ".cline" / "data" / "settings" / "cline_mcp_settings.json")
    add(home / ".kiro" / "settings" / "mcp.json")
    add(home / ".aws" / "amazonq" / "default.json")
    add(home / ".aws" / "amazonq" / "mcp.json")
    copilot = flavour(env["COPILOT_HOME"]) if env.get("COPILOT_HOME") else home / ".copilot"
    add(copilot / "mcp-config.json")
    add(home / ".continue" / "config.json")

    unique: dict[str, tuple[PurePath, str]] = {}
    for path, folder in found:
        unique.setdefault(str(path).lower() if windows else str(path), (path, folder))
    return [entry for entry in unique.values() if not is_secret_store(entry[0])]


def is_secret_store(path: PurePath) -> bool:
    """Le fichier est-il un coffre de jetons, à ne jamais lire ?"""
    if path.name.lower() not in NEVER_READ:
        return False
    text = path.as_posix().lower()
    return not text.endswith(_ALLOWED_CONFIG_JSON)


# Variables qui peuvent placer une configuration hors du dossier personnel : affichées par
# leur nom (`$XDG_CONFIG_HOME/…`), jamais par leur valeur (elle contient souvent le nom
# d'utilisateur : « /srv/alice/cfg »). Revue de l'Auditeur, 6 nov. 2026.
_ROOT_VARIABLES = ("CLAUDE_CONFIG_DIR", "COPILOT_HOME", "XDG_CONFIG_HOME", "APPDATA")


def _normal(path: PurePath) -> str:
    """Le texte du chemin sans le préfixe « \\\\?\\ » des chemins longs de Windows."""
    text = str(path)
    return text[4:] if text.startswith(("\\\\?\\", "//?/")) else text


def _relative(path: PurePath, base: PurePath) -> str | None:
    windows = isinstance(path, PureWindowsPath)
    flavour = PureWindowsPath if windows else PurePosixPath
    a = flavour(_collapse(_normal(path), windows))
    b = flavour(_collapse(_normal(base), windows))
    try:
        return a.relative_to(b).as_posix()
    except ValueError:
        return None


def _collapse(text: str, windows: bool) -> str:
    """Retire « . » et « .. » sans toucher au disque (pour les chemins des deux systèmes)."""
    import ntpath
    import posixpath

    return (ntpath if windows else posixpath).normpath(text)


def shown_path(path: PurePath, home: PurePath, env: Mapping[str, str] | None = None) -> str:
    """`~/…` pour un fichier du dossier personnel (sans le nom d'utilisateur), `$VAR/…` pour un
    dossier choisi par une variable, sinon le chemin du système tel quel (`/etc/…`,
    `C:/Program Files/…`), en barres obliques."""
    relative = _relative(path, home)
    if relative is not None:
        return "~" if relative == "." else "~/" + relative
    windows = isinstance(path, PureWindowsPath)
    for name in _ROOT_VARIABLES:
        value = (env or {}).get(name)
        if value:
            relative = _relative(path, (PureWindowsPath if windows else PurePosixPath)(value))
            if relative is not None:
                label = f"%{name}%" if windows else f"${name}"
                return label if relative == "." else f"{label}/{relative}"
    return path.as_posix()


def _expand_folders(path: Path, notes: list[str], shown: str) -> list[tuple[Path, str]]:
    """Ajoute les fichiers des profils VS Code et des extensions Gemini (un niveau, borné).
    Seuls les fichiers présents comptent dans la limite ; au-delà, on le dit (`notes`)."""
    parent = path.parent
    if parent.name == "User" and path.name in ("settings.json", "mcp.json", "tasks.json"):
        folder, files = parent / "profiles", lambda item: (item / path.name, item.name)
    elif path.name == "settings.json" and parent.name == ".gemini":
        folder = parent / "extensions"
        files = lambda item: (item / "gemini-extension.json", item.name)  # noqa: E731
    elif path.name == "managed-settings.json":
        folder = parent / "managed-settings.d"
        files = lambda item: (item, ".claude")  # noqa: E731
    else:
        return []
    if not folder.is_dir() or folder.is_symlink():
        return []
    extra: list[tuple[Path, str]] = []
    for item in sorted(folder.iterdir()):
        if item.is_symlink() and folder.name == "extensions":
            continue  # une extension dont le dossier est un lien sortirait de son dossier
        candidate = files(item)
        if candidate[0].suffix.lower() != ".json" or not _present(candidate[0]):
            continue
        if len(extra) == _MAX_PROFILES:
            notes.append(
                f"Not checked: more than {_MAX_PROFILES} entries next to {shown} (limit reached)"
            )
            break
        extra.append(candidate)
    return extra


def user_locations(
    env: Mapping[str, str] | None = None, platform: str | None = None
) -> tuple[list[Location], list[str]]:
    """Les fichiers de configuration présents sur cette machine, et des remarques : fichiers
    dans un format que configwarden ne lit pas encore, limites atteintes (pour le dire, pas
    les taire)."""
    import sys

    env = os.environ if env is None else env
    platform = sys.platform if platform is None else platform
    home = _home(env, platform == "win32")
    locations: list[Location] = []
    notes: list[str] = []
    seen: set[str] = set()
    for pure, folder in candidate_paths(env, platform):
        path = Path(pure)
        shown = shown_path(path, home, env)
        for candidate, candidate_folder in [(path, folder), *_safe_expand(path, notes, shown)]:
            key = os.path.normcase(str(candidate))
            if key in seen or is_secret_store(candidate) or not _present(candidate):
                continue
            seen.add(key)
            locations.append(
                Location(candidate, shown_path(candidate, home, env), candidate_folder)
            )
    notes += [
        f"Not checked (format not supported yet): {shown_path(Path(home) / relative, home)} "
        f"({label})"
        for relative, label in _UNSUPPORTED
        if _present(Path(home) / relative)
    ]
    return locations, notes


# Coffres de jetons et d'identifiants connus, comparés par identité de fichier (appareil et
# numéro d'inode) au fichier réellement OUVERT : ni un lien symbolique, ni un lien dur, ni un
# échange de fichier entre la vérification et la lecture ne font lire l'un d'eux
# (contre-vérification de l'Auditeur, 6 nov. 2026).
_SECRET_FILES = (
    ".claude/.credentials.json",
    ".codex/auth.json",
    ".gemini/oauth_creds.json",
    ".gemini/google_accounts.json",
    ".gemini/mcp-oauth-tokens.json",
    ".copilot/config.json",
    ".git-credentials",
    ".netrc",
    "_netrc",
    ".npmrc",
    ".pypirc",
    ".aws/credentials",
    ".docker/config.json",
    ".config/gh/hosts.yml",
    ".config/github-copilot/apps.json",
    ".config/github-copilot/hosts.json",
    ".config/gcloud/application_default_credentials.json",
    ".azure/msal_token_cache.json",
    ".kube/config",
)
_SECRET_FILE_VARIABLES = (
    ("CLAUDE_CONFIG_DIR", ".credentials.json"),
    ("CODEX_HOME", "auth.json"),
    ("COPILOT_HOME", "config.json"),
)
_CONFIG_SUFFIXES = (".json", ".jsonc")


def secret_file_ids(env: Mapping[str, str] | None = None, platform: str | None = None) -> set:
    """(appareil, inode) de chaque coffre connu présent sur la machine, et des clés SSH."""
    env = os.environ if env is None else env
    home = Path(user_home(env, platform))
    paths = [home / relative for relative in _SECRET_FILES]
    paths += [Path(env[name]) / file for name, file in _SECRET_FILE_VARIABLES if env.get(name)]
    try:
        ssh = home / ".ssh"
        if ssh.is_dir():
            paths += [item for item in sorted(ssh.iterdir())[:200] if item.is_file()]
    except OSError:
        pass
    ids = set()
    for path in paths:
        try:
            info = os.stat(path)
        except (OSError, ValueError):
            continue
        if info.st_ino:
            ids.add((info.st_dev, info.st_ino))
    return ids


def real_target(path: Path) -> Path | None:
    """Le fichier à ouvrir, liens suivis, s'il peut l'être ; sinon None.

    Refusé : une cible qui n'est pas un fichier JSON, un coffre par son nom, ou, pour une
    extension Gemini (installée depuis un dépôt inconnu), une cible hors de son dossier.
    Le fichier est ensuite ouvert à CE chemin sans suivre de lien (O_NOFOLLOW) : un lien
    échangé entre-temps fait échouer l'ouverture au lieu de lire autre chose."""
    try:
        real = Path(os.path.realpath(path))
    except (OSError, ValueError):
        return None
    if not real.name.lower().endswith(_CONFIG_SUFFIXES) or is_secret_store(real):
        return None
    if path.parent.parent.name == "extensions" and path.parent.parent.parent.name == ".gemini":
        try:
            real.relative_to(Path(os.path.realpath(path.parent)))
        except ValueError:
            return None
    return real


def may_read(opened: os.stat_result, secret_ids: set) -> bool:
    """Le fichier OUVERT peut-il être lu ? Non s'il est un coffre connu (même atteint par un
    lien dur ou échangé en cours de route)."""
    return (opened.st_dev, opened.st_ino) not in secret_ids


def _safe_expand(path: Path, notes: list[str], shown: str) -> list[tuple[Path, str]]:
    try:
        return _expand_folders(path, notes, shown)
    except OSError:
        return []


def _present(path: Path) -> bool:
    """Quelque chose existe à cet endroit (fichier, lien, dossier, tube…) : il sera lu, ou
    signalé comme illisible (CW100) s'il n'est pas un fichier ordinaire."""
    try:
        return os.path.lexists(path)
    except (OSError, ValueError):
        return False
