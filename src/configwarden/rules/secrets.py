"""Règle CW001 : secrets (clés API, tokens) écrits en clair dans un fichier.

Chaque motif (regex) reconnaît le format officiel d'un type de clé.
On reste volontairement strict pour éviter les faux positifs : les valeurs d'exemple
des documentations (« xoxb-your-bot-token », « AKIA…EXAMPLE », un en-tête de clé
privée suivi de « ... ») ne sont pas signalées (grand test du 8 octobre 2026).
"""

from __future__ import annotations

import re

from configwarden import values
from configwarden.models import Finding, Rule, Severity
from configwarden.redact import redact, redact_url

HARDCODED_SECRET = Rule(
    id="CW001",
    title="Hardcoded secret",
    severity=Severity.CRITICAL,
    remediation=(
        "Revoke the key immediately in the provider dashboard (deleting the commit is "
        "NOT enough), then load it from an environment variable or a secret manager."
    ),
)

RULES = [HARDCODED_SECRET]

# (nom lisible, motif). Les motifs sont compilés une seule fois (performance).
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Anthropic API key", re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}")),
    ("OpenAI API key", re.compile(r"sk-(?!ant-)(?:proj-)?[A-Za-z0-9_\-]{32,}")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}")),
    ("GitHub fine-grained token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}")),
    ("AWS access key ID", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}")),
    ("Hugging Face token", re.compile(r"\bhf_[A-Za-z0-9]{30,}")),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("Stripe live key", re.compile(r"\b[rs]k_live_[A-Za-z0-9]{20,}")),
    ("Private key", re.compile(r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----")),
]
# Un vrai jeton Slack contient des numéros (équipe, bot) : « xoxb- » suivi de groupes de chiffres.
_SLACK_DIGITS = re.compile(r"\d{6}")
# Contenu d'une clé privée : une ligne de base64 après l'en-tête (dans les 5 lignes,
# à cause des en-têtes « Proc-Type: … » des anciennes clés chiffrées).
_KEY_MATERIAL = re.compile(r"[A-Za-z0-9+/=]{40}")
_KEY_LOOKAHEAD_LINES = 6
# Bornés : un fichier piégé peut aligner des milliers d'en-têtes sur une seule ligne,
# ou les faire suivre de lignes d'un mégaoctet.
_KEY_LOOKAHEAD_CHARS = 256
_SHORT_LINE = 80
# mask_secrets : un long mot de lettres, chiffres, « _ » ou « - » (un jeton inconnu). Le
# début de mot est obligatoire et rien n'est imbriqué : temps linéaire.
_GENERIC_TOKEN = re.compile(r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{24,}")
_HAS_LETTER = re.compile(r"[A-Za-z]")
_HAS_DIGIT = re.compile(r"[0-9]")


def _has_key_material(lines: list[str], index: int, end: int) -> bool:
    """L'en-tête « BEGIN … PRIVATE KEY » est-il suivi d'une vraie clé (et non de « ... ») ?"""
    # Clé écrite dans une chaîne JSON : tout est sur une ligne, avec des « \\n ».
    rest = lines[index][end : end + _KEY_LOOKAHEAD_CHARS].replace("\\n", "\n")
    nearby = lines[index + 1 : index + 1 + _KEY_LOOKAHEAD_LINES]
    parts: list[str] = []
    for part in rest.split("\n") + [line[:_KEY_LOOKAHEAD_CHARS] for line in nearby]:
        stripped = part.strip()
        if stripped.startswith("-----"):
            break  # fin de la clé (« -----END ») ou en-tête suivant
        parts.append(stripped)
    # Clé tronquée d'une documentation (« MIIEvg… » puis « ... ») : un exemple.
    if any("..." in part or "…" in part for part in parts):
        return False
    for part in parts:
        if _KEY_MATERIAL.match(part):
            return True
        if len(part) <= _SHORT_LINE and values.is_placeholder(part):
            return False  # « <votre clé ici> »
    return False


def _is_real(label: str, secret: str, lines: list[str], index: int, end: int) -> bool:
    if values.is_example_token(secret):
        return False  # « sk-ant-xxxx… », « AKIA…EXAMPLE »
    if label == "Slack token":
        return bool(_SLACK_DIGITS.search(secret))
    if label == "Private key":
        return _has_key_material(lines, index, end)
    return True


def _mask_generic(match: re.Match[str]) -> str:
    word = match.group(0)
    if _HAS_LETTER.search(word) and _HAS_DIGIT.search(word):
        return redact(word)
    return word  # « mcp-server-filesystem-demo » : que des lettres, pas un jeton


def mask_secrets(text: str) -> str:
    """Masque tout ce qui ressemble à un secret dans un texte libre (raison d'une exception).

    Sont masqués : les identifiants d'une URL (« user:motdepasse@ », paramètres), les
    clés et jetons aux formats connus, et tout long mot (24 caractères au moins) qui mêle
    lettres et chiffres. En cas de doute, on masque : ce texte sera affiché dans les
    rapports et les journaux de CI (revue de l'Auditeur du 20 octobre 2026).
    """
    text = redact_url(text)
    for label, pattern in _PATTERNS:
        if label != "Private key":  # l'en-tête seul n'est pas un secret
            text = pattern.sub(lambda match: redact(match.group(0)), text)
    return _GENERIC_TOKEN.sub(_mask_generic, text)


def check_text(text: str, path: str) -> list[Finding]:
    """Cherche des secrets ligne par ligne dans le contenu d'un fichier."""
    findings: list[Finding] = []
    # split("\n") et non splitlines() : ce dernier coupe aussi sur \x0c, \x1c, \u2028…
    # et les numéros de ligne ne correspondraient plus à ceux de l'éditeur ni de GitHub.
    lines = text.split("\n")
    for index, line in enumerate(lines):
        line_number = index + 1
        for label, pattern in _PATTERNS:
            for match in pattern.finditer(line):
                if not _is_real(label, match.group(0), lines, index, match.end()):
                    continue
                findings.append(
                    Finding(
                        rule=HARDCODED_SECRET,
                        path=path,
                        line=line_number,
                        # On n'écrit QUE la version masquée du secret.
                        message=f"{label} found: {redact(match.group(0))}",
                    )
                )
    return findings
