"""Le moteur : parcourt les fichiers d'un dossier et applique les règles.

Précautions de sécurité du parcours :
- on ne suit PAS les liens symboliques (un lien piégé pourrait faire lire
  des fichiers hors du projet, ou boucler à l'infini) ;
- on ne lit que les fichiers ordinaires (un « tube » FIFO bloquerait le scan) ;
- on ignore les fichiers trop gros et les fichiers binaires ;
- un fichier ou un dossier illisible est sauté (et compté) sans faire planter le scan.
"""

from __future__ import annotations

import codecs
import fnmatch
import os
import stat
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from configwarden import user_configs
from configwarden.models import Finding, Suppressed
from configwarden.rules import mcp, secrets

MAX_FILE_SIZE = 1_000_000  # 1 Mo
# `scan --user` : ~/.claude.json garde aussi l'historique des conversations et dépasse
# souvent 1 Mo (des dizaines de Mo signalés). Lu jusqu'à 64 Mo (environ 6 s), au-delà il
# est signalé comme illisible plutôt que de ralentir ou d'épuiser la mémoire.
MAX_USER_FILE_SIZE = 64_000_000
_BINARY_SNIFF_SIZE = 8192
# En-têtes (BOM) des fichiers UTF-32 et UTF-16, que VS Code sait ouvrir. Sans eux, leurs
# octets nuls les feraient prendre pour des fichiers binaires, ignorés par toutes les
# règles. UTF-32 d'abord : son en-tête commence comme celui d'UTF-16.
_WIDE_ENCODINGS = (
    (codecs.BOM_UTF32_LE, "utf-32"),
    (codecs.BOM_UTF32_BE, "utf-32"),
    (codecs.BOM_UTF16_LE, "utf-16"),
    (codecs.BOM_UTF16_BE, "utf-16"),
)

DEFAULT_IGNORED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    ".hypothesis",  # cache des tests de propriétés (constantes du code, chemins locaux)
    ".tox",
    "dist",
    "build",
}


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0
    # Dossier de référence des chemins des constats (chemin absolu). Sert au rapport
    # SARIF ; n'apparaît jamais dans un rapport (il peut contenir un nom d'utilisateur).
    root: str = ""
    # Exceptions (`.configwarden-ignore`, voir ignore.py) : alertes acceptées, toujours
    # listées avec leur raison, et remarques sur le fichier (lignes fautives, expirées…).
    suppressed: list[Suppressed] = field(default_factory=list)
    ignore_notes: list[str] = field(default_factory=list)
    ignore_file: str = ""


def _is_excluded(relative: PurePosixPath, patterns: Iterable[str]) -> bool:
    text = relative.as_posix()
    return any(fnmatch.fnmatch(text, p) or fnmatch.fnmatch(relative.name, p) for p in patterns)


def iter_files(
    root: Path,
    excludes: Iterable[str] = (),
    on_error: Callable[[OSError], None] | None = None,
    on_symlink: Callable[[Path], None] | None = None,
) -> Iterator[Path]:
    """Liste les fichiers à analyser, sans suivre les liens symboliques.

    `on_error` est appelé pour chaque dossier illisible : sans lui, os.walk les
    ignorerait en silence et le rapport dirait « No issues found » à tort.
    `on_symlink` est appelé pour chaque lien symbolique ignoré (fichier ou dossier).
    """
    excludes = list(excludes)
    if root.is_file():
        yield root
        return
    for current, dirnames, filenames in os.walk(root, onerror=on_error, followlinks=False):
        current_path = Path(current)
        kept: list[str] = []
        for dirname in sorted(dirnames):
            if dirname in DEFAULT_IGNORED_DIRS:
                continue
            directory = current_path / dirname
            if _is_excluded(PurePosixPath(directory.relative_to(root).as_posix()), excludes):
                continue
            if directory.is_symlink():
                if on_symlink is not None:
                    on_symlink(directory)
                continue
            kept.append(dirname)
        # Modifier `dirnames` sur place empêche os.walk de descendre dans les autres.
        dirnames[:] = kept
        for filename in sorted(filenames):
            path = current_path / filename
            if _is_excluded(PurePosixPath(path.relative_to(root).as_posix()), excludes):
                continue
            if path.is_symlink():
                if on_symlink is not None:
                    on_symlink(path)
                continue
            yield path


class RefusedFile(Exception):
    """Le fichier ouvert ne doit pas être lu (`scan --user` : coffre de jetons)."""


def _read_text(
    path: Path,
    max_size: int = MAX_FILE_SIZE,
    accept: Callable[[os.stat_result], bool] | None = None,
    nofollow: bool = False,
) -> str | None:
    """Lit un fichier texte, ou renvoie None s'il faut l'ignorer. `accept` juge le fichier
    réellement ouvert (avant toute lecture) ; s'il le refuse : RefusedFile."""
    try:
        info = path.stat()
        # Seulement les fichiers ordinaires : un tube (FIFO) ou un périphérique
        # bloquerait la lecture indéfiniment.
        if not stat.S_ISREG(info.st_mode) or info.st_size > max_size:
            return None
        # Ouverture non bloquante, puis nouveau contrôle sur le fichier OUVERT : un fichier
        # remplacé par un tube entre les deux vérifications ne bloque pas la lecture.
        flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
        if nofollow:
            flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as handle:
            opened = os.fstat(handle.fileno())
            if not stat.S_ISREG(opened.st_mode) or opened.st_size > max_size:
                return None
            if accept is not None and not accept(opened):
                raise RefusedFile(str(path))
            raw = handle.read(max_size + 1)  # lecture bornée, même si le fichier grossit
    except OSError:
        return None
    if len(raw) > max_size:
        return None
    for bom, encoding in _WIDE_ENCODINGS:
        if raw.startswith(bom):
            return raw.decode(encoding, errors="replace")
    if b"\0" in raw[:_BINARY_SNIFF_SIZE]:  # octet nul = fichier binaire
        return None
    # « utf-8-sig » retire l'éventuel BOM : sinon json.loads refuserait le fichier et
    # une configuration dangereuse échapperait à l'analyse.
    return raw.decode("utf-8-sig", errors="replace")


def scan(target: str | Path, excludes: Iterable[str] = ()) -> ScanResult:
    """Analyse un fichier ou un dossier et renvoie tous les constats."""
    root = Path(target).resolve()
    if not root.exists():
        raise FileNotFoundError(f"Path not found: {target}")
    base = root.parent if root.is_file() else root

    result = ScanResult(root=str(base))

    def count_unreadable_directory(_error: OSError) -> None:
        result.files_skipped += 1

    def report_symlinked_config(path: Path) -> None:
        # Un outil IA suit les liens ; configwarden non (ils peuvent sortir du projet).
        # Une configuration atteinte par un lien ne doit donc pas passer inaperçue.
        relative = PurePosixPath(path.relative_to(base).as_posix())
        if mcp.is_client_config_path(relative):
            result.findings.append(mcp.symlinked_config_finding(relative.as_posix()))

    for path in iter_files(
        root, excludes, on_error=count_unreadable_directory, on_symlink=report_symlinked_config
    ):
        relative = PurePosixPath(path.relative_to(base).as_posix())
        _check_file(result, path, relative, folder=path.parent.name)

    # Tri : le plus grave d'abord, puis par fichier et ligne.
    result.findings.sort(key=lambda f: (-f.severity.rank, f.path, f.line, f.rule.id))
    return result


def _check_file(
    result: ScanResult,
    path: Path,
    relative: PurePosixPath,
    *,
    folder: str,
    max_size: int = MAX_FILE_SIZE,
    client_config: bool = False,
    accept: Callable[[os.stat_result], bool] | None = None,
    nofollow: bool = False,
) -> None:
    """Lit un fichier et lui applique les règles. `relative` est le chemin affiché."""
    rel_str = relative.as_posix()
    try:
        text = _read_text(path, max_size, accept, nofollow)
    except RefusedFile:
        result.files_skipped += 1
        result.findings.append(mcp.linked_secret_store_finding(rel_str))
        return
    if text is None:
        result.files_skipped += 1
        if client_config or mcp.is_client_config_path(relative):
            result.findings.append(mcp.unreadable_config_finding(rel_str))
        return
    result.files_scanned += 1

    result.findings.extend(secrets.check_text(text, rel_str))
    # Fichiers MCP connus ET tout autre fichier JSON : de nombreux outils IA
    # rangent leurs serveurs dans des fichiers aux noms génériques (settings.json…).
    mcp_named = mcp.is_mcp_config(relative)
    if client_config or mcp_named or mcp.is_json_file(relative):
        result.findings.extend(mcp.check_text(text, rel_str, mcp_named=mcp_named, folder=folder))


def scan_user(locations: Iterable[user_configs.Location], home: str = "") -> ScanResult:
    """`scan --user` : lit seulement les fichiers de configuration des outils IA de
    l'utilisateur (liste fermée, voir user_configs.py), jamais tout le dossier personnel.

    Ici, un lien symbolique est suivi : c'est la machine de l'utilisateur (dossiers de
    configuration partagés par un dépôt « dotfiles »), et la liste des fichiers est fixée
    par configwarden, pas par un dépôt inconnu. Seul un fichier ordinaire est lu.
    """
    # Pas de dossier de référence : les chemins affichés sont déjà `~/…`, et un rapport SARIF
    # ne doit pas les rattacher au dossier courant (il y ajouterait le nom d'utilisateur).
    result = ScanResult(root="")
    secret_ids = user_configs.secret_file_ids()
    token = mcp.HOME_FOR_DISPLAY.set(home)  # projets de ~/.claude.json : « ~/… » à l'écran
    try:
        for location in locations:
            # Liens suivis d'abord, cible jugée par son nom ; puis ouverture de la cible sans
            # suivre de lien, et jugement du fichier OUVERT (lien dur, échange en route).
            real = user_configs.real_target(location.path)
            if real is None and os.path.lexists(location.path):
                result.files_skipped += 1
                result.findings.append(mcp.linked_secret_store_finding(location.shown))
                continue

            def accept(opened: os.stat_result) -> bool:
                return user_configs.may_read(opened, secret_ids)

            _check_file(
                result,
                real or location.path,
                PurePosixPath(location.shown),
                folder=location.folder,
                max_size=MAX_USER_FILE_SIZE,
                client_config=True,
                accept=accept,
                nofollow=True,
            )
    finally:
        mcp.HOME_FOR_DISPLAY.reset(token)
    result.findings.sort(key=lambda f: (-f.severity.rank, f.path, f.line, f.rule.id))
    return result
