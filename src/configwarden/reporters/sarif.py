"""Rapport SARIF 2.1.0 : le format standard des outils d'analyse de sécurité.

GitHub, GitLab, DefectDojo, VS Code (extension SARIF Viewer)… savent le lire.
C'est ce qui rend configwarden *complémentaire* des autres outils plutôt
que concurrent : ses résultats s'affichent dans leurs tableaux de bord.
"""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import quote

from configwarden import __version__
from configwarden.models import Severity
from configwarden.redact import json_for_logs
from configwarden.rules import ALL_RULES
from configwarden.scanner import ScanResult

_SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_LEVELS = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}
# Score utilisé par GitHub pour classer les alertes (0 à 10).
_SECURITY_SCORE = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "2.0",
}


def _prefix_from_current_folder(root: str) -> str | None:
    """Chemin du dossier analysé vu depuis le dossier courant (« sub/ »), ou None.

    En CI, la commande est lancée à la racine du dépôt : GitHub attend des chemins
    relatifs à cette racine. Un dossier analysé hors du dossier courant garde des
    chemins relatifs à lui-même : jamais de chemin absolu dans un rapport (il peut
    révéler un nom d'utilisateur ou l'organisation des dossiers de la machine).
    """
    if not root:
        return None
    try:
        relative = Path(root).relative_to(Path.cwd().resolve())
    except (ValueError, OSError):
        return None
    prefix = relative.as_posix()
    return "" if prefix == "." else prefix + "/"


def _artifact_location(path: str, prefix: str | None) -> dict:
    # Une URI SARIF doit être encodée (espace -> %20, # -> %23…).
    if prefix is None:
        return {"uri": quote(path, safe="/")}
    return {"uri": quote(prefix + path, safe="/"), "uriBaseId": "%SRCROOT%"}


def render_sarif(result: ScanResult, **_: object) -> str:
    prefix = _prefix_from_current_folder(result.root)
    rules = [
        {
            "id": rule.id,
            "name": rule.title.replace(" ", ""),
            "shortDescription": {"text": rule.title},
            "help": {"text": rule.remediation},
            "defaultConfiguration": {"level": _LEVELS[rule.severity]},
            "properties": {
                "security-severity": _SECURITY_SCORE[rule.severity],
                "tags": ["security", "ai-agents"],
            },
        }
        for rule in ALL_RULES
    ]
    results = [
        {
            "ruleId": f.rule.id,
            "level": _LEVELS[f.severity],
            "message": {"text": f.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": _artifact_location(f.path, prefix),
                        "region": {"startLine": f.line},
                    }
                }
            ],
        }
        for f in result.findings
    ]
    sarif = {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "configwarden",
                        "version": __version__,
                        "informationUri": "https://github.com/Matadi-afk/configwarden",
                        "rules": rules,
                    }
                },
                "results": results,
                # Les alertes mises en exception sont retirées (décision du 20 octobre
                # 2026) : GitHub ignore le marquage « suppressions » de la norme et les
                # afficherait comme des alertes ouvertes. Leur nombre reste indiqué.
                "properties": {"suppressedResults": len(result.suppressed)},
            }
        ],
    }
    return json_for_logs(json.dumps(sarif, indent=2, ensure_ascii=False))
