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

from configwarden.models import Finding, Suppressed
from configwarden.rules import mcp, secrets

MAX_FILE_SIZE = 1_000_000  # 1 Mo
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


def _read_text(path: Path) -> str | None:
    """Lit un fichier texte, ou renvoie None s'il faut l'ignorer."""
    try:
        info = path.stat()
        # Seulement les fichiers ordinaires : un tube (FIFO) ou un périphérique
        # bloquerait la lecture indéfiniment.
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE_SIZE:
            return None
        with path.open("rb") as handle:
            raw = handle.read(MAX_FILE_SIZE + 1)  # lecture bornée, même si le fichier grossit
    except OSError:
        return None
    if len(raw) > MAX_FILE_SIZE:
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
        rel_str = relative.as_posix()
        text = _read_text(path)
        if text is None:
            result.files_skipped += 1
            if mcp.is_client_config_path(relative):
                result.findings.append(mcp.unreadable_config_finding(rel_str))
            continue
        result.files_scanned += 1

        result.findings.extend(secrets.check_text(text, rel_str))
        # Fichiers MCP connus ET tout autre fichier JSON : de nombreux outils IA
        # rangent leurs serveurs dans des fichiers aux noms génériques (settings.json…).
        mcp_named = mcp.is_mcp_config(relative)
        if mcp_named or mcp.is_json_file(relative):
            result.findings.extend(
                mcp.check_text(text, rel_str, mcp_named=mcp_named, folder=path.parent.name)
            )

    # Tri : le plus grave d'abord, puis par fichier et ligne.
    result.findings.sort(key=lambda f: (-f.severity.rank, f.path, f.line, f.rule.id))
    return result
