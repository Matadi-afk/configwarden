"""Rapport JSON, pratique pour d'autres scripts ou outils."""

from __future__ import annotations

import json

from configwarden import __version__
from configwarden.redact import json_for_logs
from configwarden.scanner import ScanResult


def render_json(result: ScanResult, **_: object) -> str:
    payload = {
        "tool": "configwarden",
        "version": __version__,
        "files_scanned": result.files_scanned,
        "files_skipped": result.files_skipped,
        "findings": [f.to_dict() for f in result.findings],
        # Alertes mises en exception (.configwarden-ignore), avec leur raison.
        "suppressed": [s.to_dict() for s in result.suppressed],
        "ignore": (
            {"file": result.ignore_file, "notes": result.ignore_notes}
            if result.ignore_file or result.ignore_notes
            else None
        ),
    }
    return json_for_logs(json.dumps(payload, indent=2, ensure_ascii=False))
