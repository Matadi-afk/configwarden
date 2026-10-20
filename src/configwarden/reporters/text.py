"""Rapport lisible dans le terminal, avec couleurs si possible."""

from __future__ import annotations

from configwarden.commands import shorten
from configwarden.models import Severity
from configwarden.scanner import ScanResult

_COLORS = {
    Severity.CRITICAL: "\033[1;35m",
    Severity.HIGH: "\033[1;31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
}
_RESET = "\033[0m"


def _shown_path(path: str) -> str:
    """« ::x/mcp.json » -> « ./::x/mcp.json » : une ligne du rapport ne commence jamais par
    « :: », lu comme une commande par GitHub Actions, même après des espaces (le runner
    les retire avant de lire la ligne)."""
    return "./" + path if path.lstrip().startswith((":", "#")) else path


def render_text(result: ScanResult, *, color: bool = False) -> str:
    def paint(text: str, severity: Severity) -> str:
        return f"{_COLORS[severity]}{text}{_RESET}" if color else text

    lines: list[str] = []
    for f in result.findings:
        label = paint(f"[{f.severity.value.upper()}]", f.severity)
        lines.append(f"{label} {f.rule.id} {f.rule.title}")
        lines.append(f"    {_shown_path(f.path)}:{f.line}  {f.message}")
        lines.append(f"    Fix: {f.rule.remediation}")
        lines.append("")

    if result.suppressed:
        # Toujours affichées : une exception se voit, elle ne peut pas cacher en silence.
        lines.append(f"Suppressed by {result.ignore_file} ({len(result.suppressed)}):")
        for s in result.suppressed:
            f = s.finding
            lines.append(
                f"    [{f.severity.value.upper()}] {f.rule.id} {_shown_path(f.path)}:{f.line}  "
                f"reason: {shorten(s.reason, 120)}"
            )
        lines.append("")

    counts = {s: 0 for s in Severity}
    for f in result.findings:
        counts[f.severity] += 1
    summary = ", ".join(f"{counts[s]} {s.value}" for s in reversed(Severity))
    hidden = f" ({len(result.suppressed)} suppressed)" if result.suppressed else ""
    lines.append(
        f"Scanned {result.files_scanned} file(s), skipped {result.files_skipped}. "
        f"{len(result.findings)} finding(s): {summary}{hidden}."
    )
    if not result.findings:
        lines.append("No issues found.")
    lines.extend(result.ignore_notes)
    if result.files_skipped:
        # Transparence : « aucun problème » ne vaut que pour ce qui a été lu.
        lines.append(
            f"Note: {result.files_skipped} file(s) or folder(s) could not be analysed "
            "(too large, binary, special or unreadable)."
        )
    # « ##[…] » (GitHub) et « ##vso[…] » (Azure Pipelines) sont des commandes où qu'ils
    # soient dans une ligne : « ## » venu d'un nom de fichier ou de serveur est affiché
    # « #\x23 », comme les autres caractères neutralisés par sanitize().
    return "\n".join(lines).replace("##", "#\\x23")
