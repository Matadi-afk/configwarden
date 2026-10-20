"""Fichier d'exceptions `.configwarden-ignore` : accepter une alerte en connaissance de cause.

Une ligne par exception, toujours avec une raison :

    # règle  fichier ou dossier/        [date de fin]       -- raison
    CW106    examples/demo/mcp.json                         -- démo volontairement vulnérable
    CW111    tests/fixtures/            until=2026-12-31    -- images figées plus tard

Garde-fous (décisions du 20 octobre 2026) :
- une règle précise par ligne (jamais de joker) et un fichier précis ou un dossier
  terminé par « / » : jamais tout le projet ;
- une raison obligatoire (3 caractères au moins) ; une date de fin facultative, après
  laquelle l'exception ne s'applique plus et l'alerte revient ;
- une ligne mal écrite est ignorée et signalée par son NUMÉRO, sans recopier son contenu :
  il pourrait contenir un secret, ou venir d'un fichier atteint par un lien piégé ;
- les lignes sont coupées sur « \n » seulement, comme les lit GitHub. Une ligne qui
  contient un caractère invisible ou de contrôle (sauf la tabulation) est refusée, même
  en commentaire : U+2028, U+0085 ou \x0c y feraient passer une exception pour du texte
  (revue de l'Auditeur du 20 octobre 2026) ;
- un secret écrit par erreur dans une raison est masqué avant tout affichage ;
- le fichier du projet n'est pas lu s'il est un lien symbolique (il pourrait faire lire
  n'importe quel fichier de la machine), ni s'il dépasse 256 Ko ;
- une alerte mise en exception ne compte plus pour le code de sortie mais reste listée
  dans les rapports texte et JSON, avec sa raison : un dépôt piégé ne peut pas cacher
  son propre serveur sans que cela se voie. Elle est retirée du SARIF, car GitHub ignore
  le marquage « suppressions » de la norme et l'afficherait comme une alerte ouverte.

Sécurité : lecture bornée (taille, nombre de lignes), temps linéaire, aucune expression
régulière qui revient en arrière. La correspondance se fait par dictionnaire, et par un
arbre des dossiers : des milliers d'exceptions ou des chemins très profonds ne ralentissent
pas le scan.
"""

from __future__ import annotations

import os
import re
import stat
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from configwarden.models import Suppressed
from configwarden.redact import sanitize
from configwarden.rules.secrets import mask_secrets

IGNORE_FILE_NAME = ".configwarden-ignore"
MAX_IGNORE_SIZE = 256_000
MAX_ENTRIES = 10_000
MIN_REASON = 3
_LISTED_LINES = 10  # numéros de ligne (ou erreurs) cités au plus dans les notes

_SEPARATOR = re.compile(r"(?:^|\s)--(?:\s|$)")
_TOKEN = re.compile(r'"[^"]*"|\S+')
_RULE_ID = re.compile(r"[A-Z]{2}[0-9]{3}")
_DRIVE = re.compile(r"[A-Za-z]:")
_WILDCARDS = frozenset("*?[]")
_FORBIDDEN_CATEGORIES = {"Cc", "Cf", "Cs", "Co", "Zl", "Zp"}
_UNTIL = "until="


@dataclass(frozen=True)
class IgnoreEntry:
    rule: str
    path: str  # « dossier/ » pour un dossier
    folder: bool
    until: date | None
    reason: str
    line: int


@dataclass
class IgnoreFile:
    name: str  # nom affiché (jamais un chemin absolu)
    entries: list[IgnoreEntry] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class _LineError(ValueError):
    """Problème d'une ligne : le message ne contient jamais le texte de la ligne."""


def _has_forbidden_character(text: str, *, allow_tab: bool = False) -> bool:
    return any(
        unicodedata.category(character) in _FORBIDDEN_CATEGORIES
        and not (allow_tab and character == "\t")
        for character in text
    )


def _normalise_path(raw: str) -> tuple[str, bool]:
    path = raw.replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    if _has_forbidden_character(path):
        raise _LineError("invalid character in the path")
    folder = path.endswith("/")
    core = path.rstrip("/")
    if core in {"", ".", "*", "**"}:
        raise _LineError("the path covers the whole project; name a file or a folder")
    if path.startswith("/") or _DRIVE.match(path):
        raise _LineError("the path must be relative to the scanned folder")
    if any(part in {"", ".", ".."} for part in core.split("/")):
        raise _LineError("the path must not contain '..', '.' or empty parts")
    if _WILDCARDS & set(core):
        raise _LineError("wildcards are not allowed in the path; name a file or a folder")
    return core + ("/" if folder else ""), folder


def _parse_line(line: str, number: int, known_rules: set[str]) -> IgnoreEntry:
    separator = _SEPARATOR.search(line)
    if separator is None:
        raise _LineError(f"missing reason: write at least {MIN_REASON} characters after ' -- '")
    reason = line[separator.end() :].strip()
    if len(reason) < MIN_REASON:
        raise _LineError(f"missing reason: write at least {MIN_REASON} characters after ' -- '")
    reason = mask_secrets(reason)  # un jeton collé là par erreur ne sera jamais affiché
    left = line[: separator.start()]
    if left.count('"') % 2:
        raise _LineError("unclosed quote")
    tokens = [token.strip('"') for token in _TOKEN.findall(left)]
    if not tokens:
        raise _LineError("missing rule and path")
    rule = tokens[0].upper()
    if not _RULE_ID.fullmatch(rule) or rule not in known_rules:
        raise _LineError("unknown rule (expected one rule ID such as CW106, no wildcard)")
    if len(tokens) < 2:
        raise _LineError("missing path (a file, or a folder ending with '/')")
    path, folder = _normalise_path(tokens[1])
    until = None
    for option in tokens[2:]:
        if not option.startswith(_UNTIL) or until is not None:
            raise _LineError("unexpected text before ' -- ' (only until=YYYY-MM-DD is allowed)")
        value = option[len(_UNTIL) :]
        try:
            if len(value) != 10:
                raise ValueError
            until = date.fromisoformat(value)
        except ValueError:
            raise _LineError("invalid date in until= (expected YYYY-MM-DD)") from None
    return IgnoreEntry(rule, path, folder, until, reason, number)


def parse(text: str, name: str, known_rules: Iterable[str]) -> IgnoreFile:
    """Lit le texte d'un fichier d'exceptions. Les lignes fautives sont listées à part."""
    known = set(known_rules)
    result = IgnoreFile(name=name)
    # split("\n") et non splitlines() : ce dernier coupe aussi sur \x0c, \x1c, \x85,
    # U+2028… qu'un éditeur ou GitHub n'affichent pas comme des fins de ligne.
    for number, raw in enumerate(text.split("\n"), start=1):
        line = raw.removesuffix("\r")
        if _has_forbidden_character(line, allow_tab=True):
            result.errors.append(
                f"{name} line {number}: invalid character in the line (control or invisible "
                "character); this line is not used."
            )
            continue
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if len(result.entries) >= MAX_ENTRIES:
            result.errors.append(
                f"{name}: too many exceptions; lines from {number} on are not used "
                f"(limit: {MAX_ENTRIES})."
            )
            break
        try:
            result.entries.append(_parse_line(line, number, known))
        except _LineError as error:
            result.errors.append(f"{name} line {number}: {error}; this line is not used.")
    return result


def _too_large(name: str) -> IgnoreFile:
    limit = MAX_IGNORE_SIZE // 1000
    return IgnoreFile(name, errors=[f"{name} is too large (over {limit} KB); no exception used."])


def read(path: Path, name: str, known_rules: Iterable[str], *, trusted: bool) -> IgnoreFile:
    """Lit un fichier d'exceptions sur le disque.

    `trusted=False` (fichier du projet analysé) : un lien symbolique n'est pas suivi.
    Un fichier trop gros, spécial ou illisible n'apporte aucune exception : les alertes
    restent visibles, ce qui est le choix sûr.
    """
    try:
        info = path.stat() if trusted else path.lstat()
        if stat.S_ISLNK(info.st_mode):
            return IgnoreFile(
                name, errors=[f"{name} is a symbolic link; it was not read (no exception used)."]
            )
        if not stat.S_ISREG(info.st_mode):
            return IgnoreFile(name, errors=[f"{name} is not a regular file; no exception used."])
        if info.st_size > MAX_IGNORE_SIZE:
            return _too_large(name)
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        if not trusted:
            flags |= getattr(os, "O_NOFOLLOW", 0)  # le fichier ne doit pas devenir un lien
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as handle:
            raw = handle.read(MAX_IGNORE_SIZE + 1)
    except OSError:
        return IgnoreFile(name, errors=[f"{name} could not be read; no exception used."])
    if len(raw) > MAX_IGNORE_SIZE:
        return _too_large(name)  # le fichier a grossi pendant la lecture
    return parse(raw.decode("utf-8-sig", errors="replace"), name, known_rules)


def _lines(numbers: list[int]) -> str:
    shown = ", ".join(str(number) for number in numbers[:_LISTED_LINES])
    return shown + ("…" if len(numbers) > _LISTED_LINES else "")


@dataclass
class _Folder:
    """Nœud de l'arbre des dossiers en exception : « a/b/ » -> racine["a"]["b"]."""

    children: dict[str, _Folder] = field(default_factory=dict)
    entry: IgnoreEntry | None = None


def _folder_entry(roots: dict[str, _Folder], rule: str, path: str) -> IgnoreEntry | None:
    """Exception du dossier le plus haut qui contient `path` (un seul passage sur le chemin)."""
    node = roots.get(rule)
    if node is None:
        return None
    for part in path.split("/")[:-1]:
        child = node.children.get(part)
        if child is None:
            return None
        if child.entry is not None:
            return child.entry
        node = child
    return None


def apply(result, ignore_file: IgnoreFile, today: date | None = None) -> None:
    """Retire de `result.findings` les alertes couvertes par une exception valide.

    Elles passent dans `result.suppressed` avec leur raison. Les problèmes du fichier
    (lignes fautives, exceptions expirées ou inutiles) vont dans `result.ignore_notes`.
    """
    today = today or date.today()
    exact: dict[tuple[str, str], IgnoreEntry] = {}
    folders: dict[str, _Folder] = {}
    expired: list[IgnoreEntry] = []
    active: list[IgnoreEntry] = []
    for entry in ignore_file.entries:
        if entry.until is not None and today > entry.until:
            expired.append(entry)
            continue
        active.append(entry)
        if not entry.folder:
            exact.setdefault((entry.rule, entry.path), entry)  # un doublon reste inutilisé
            continue
        node = folders.setdefault(entry.rule, _Folder())
        for part in entry.path.rstrip("/").split("/"):
            node = node.children.setdefault(part, _Folder())
        if node.entry is None:
            node.entry = entry

    used: set[int] = set()
    kept = []
    for finding in result.findings:
        entry = exact.get((finding.rule.id, finding.path))
        if entry is None and folders:
            entry = _folder_entry(folders, finding.rule.id, finding.path)
        if entry is None:
            kept.append(finding)
            continue
        used.add(entry.line)
        result.suppressed.append(
            Suppressed(finding=finding, reason=sanitize(entry.reason), line=entry.line)
        )
    result.findings = kept
    result.ignore_file = ignore_file.name

    notes = [f"Warning: {error}" for error in ignore_file.errors[:_LISTED_LINES]]
    if len(ignore_file.errors) > _LISTED_LINES:
        hidden = len(ignore_file.errors) - _LISTED_LINES
        notes.append(f"Warning: {ignore_file.name}: {hidden} more line(s) with errors.")
    for entry in expired[:_LISTED_LINES]:
        notes.append(
            f"Note: {ignore_file.name} line {entry.line} expired on {entry.until}; "
            "its findings are reported again."
        )
    if len(expired) > _LISTED_LINES:
        notes.append(f"Note: {ignore_file.name}: {len(expired)} exceptions have expired.")
    unused = sorted({entry.line for entry in active} - used)
    if unused:
        notes.append(
            f"Note: {ignore_file.name}: {len(unused)} exception(s) matched nothing "
            f"(line {_lines(unused)})."
        )
    result.ignore_notes.extend(sanitize(note) for note in notes)
