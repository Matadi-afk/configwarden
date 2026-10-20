"""Masquage des secrets et assainissement des textes affichés.

Deux règles d'or d'un outil de sécurité :

1. Un rapport ne doit JAMAIS recopier un secret en entier. Sinon le rapport
   (logs CI, fichier SARIF, capture d'écran) devient lui-même une fuite.
2. Tout texte venant d'un fichier analysé est NON FIABLE. Avant de l'afficher,
   on neutralise les caractères de contrôle : un saut de ligne pourrait créer
   une fausse commande GitHub Actions (« ::error … »), un code ANSI pourrait
   effacer ou maquiller le terminal.
"""

from __future__ import annotations

import re
import unicodedata

_VISIBLE_CHARS = 4
# En dessous de cette longueur, on ne montre RIEN : afficher 4 caractères d'un
# mot de passe de 9 caractères en révélerait presque la moitié.
_MIN_LENGTH_FOR_PREFIX = 16

# Une URL dans un texte : « schéma:// » puis tout jusqu'à un espace ou un guillemet.
# Performance (anti-ReDoS) : le schéma doit commencer en début de mot et fait au
# plus 32 caractères, sinon un long texte sans « :// » coûterait un temps quadratique.
_SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]{0,31}://")
# Raccourcis npm sans « :// » : github:auteur/projet, gitlab:…, bitbucket:…, gist:…
_SHORTHAND = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]{0,31}:(?!//)")
_URL = re.compile(
    r"(?<![A-Za-z0-9+.\-])(?P<scheme>[A-Za-z][A-Za-z0-9+.\-]{0,31}://)(?P<rest>[^\s'\"]*)"
)
# Hôte d'une URL (nom, IPv4 ou [IPv6]) et port facultatif. Longueurs bornées.
_PORT = r"(?::\d{1,5})?"
_HOST = re.compile(r"(?:[A-Za-z0-9._~-]{1,253}|\[[0-9A-Fa-f:.]{2,45}\])" + _PORT)
# Forme d'un VRAI nom d'hôte (« github.com », « localhost ») ou d'une adresse IP.
_NAMED_HOST = re.compile(
    r"(?:(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.){1,126}[A-Za-z]{2,63}"
    r"|localhost|\d{1,3}(?:\.\d{1,3}){3}|\[[0-9A-Fa-f:.]{2,45}\])" + _PORT
)

# Catégories Unicode dangereuses à l'affichage :
#   Cc      contrôles (\n, \x1b, DEL…) : nouvelles lignes, codes ANSI ;
#   Cf      caractères invisibles de mise en forme : contrôles bidirectionnels
#           (attaque « Trojan Source »), espaces de largeur nulle, « tags »…
#   Cs      moitiés de paire UTF-16, invalides : la sortie ne pourrait pas être écrite ;
#   Zl, Zp  séparateurs de ligne et de paragraphe.
_DANGEROUS_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Zl", "Zp"})
# Tous les caractères « ignorables par défaut » d'Unicode (propriété
# Default_Ignorable_Code_Point) : invisibles à l'écran, mais lisibles par une IA
# qui lirait le rapport. Une suite de sélecteurs de variante suffit à y cacher
# un message. La plupart sont déjà de catégorie Cf ; on liste tout par prudence.
_DEFAULT_IGNORABLE_RANGES = (
    (0x00AD, 0x00AD),
    (0x034F, 0x034F),
    (0x061C, 0x061C),
    (0x115F, 0x1160),
    (0x17B4, 0x17B5),
    (0x180B, 0x180F),
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x206F),
    (0x3164, 0x3164),
    (0xFE00, 0xFE0F),
    (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0),
    (0xFFF0, 0xFFF8),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0000, 0xE0FFF),
)
_NAMED_ESCAPES = {"\n": "\\n", "\r": "\\r", "\t": "\\t"}


def redact(secret: str) -> str:
    """Retourne une version masquée d'un secret.

    >>> redact("sk-ant-abcdefghijklmnop")
    'sk-a****…(23 chars)'
    >>> redact("Winter2026!")
    '****'
    """
    if len(secret) < _MIN_LENGTH_FOR_PREFIX:
        return "****"
    return f"{secret[:_VISIBLE_CHARS]}****…({len(secret)} chars)"


def _redact_one_url(match: re.Match[str]) -> str:
    rest = match.group("rest")
    # La requête (?…) et l'ancre (#…) peuvent porter un jeton : on les masque.
    for marker in "?#":
        head, sep, _ = rest.partition(marker)
        if sep:
            rest = f"{head}{sep}****"
            break
    # Identifiants : tout ce qui précède le DERNIER « @ » de la partie avant « ?# ».
    # Choix prudent : un mot de passe mal encodé peut contenir « / » ou « @ ».
    head, at, host_and_path = rest.rpartition("@")
    if at and head:
        rest = f"****@{host_and_path}"
    return match.group("scheme") + rest


def redact_url(value: str) -> str:
    """Masque les identifiants et paramètres sensibles des URL d'un texte.

    >>> redact_url("git+https://alice:token123@github.com/x/y.git")
    'git+https://****@github.com/x/y.git'
    >>> redact_url("https://example.com/pkg.tgz?token=abc")
    'https://example.com/pkg.tgz?****'

    Un texte sans URL est renvoyé tel quel. On utilise une expression régulière
    plutôt qu'un analyseur d'URL : elle ne peut pas lever d'exception sur une
    entrée malformée. En cas de doute, on masque trop plutôt que pas assez.
    """
    return _URL.sub(_redact_one_url, value)


def url_origin(value: str) -> str:
    """Garde seulement « schéma://hôte/… » d'une URL.

    >>> url_origin("https://jane:p4ss w0rd@npm.example/T0KEN/pkg.tgz?x=1")
    'https://npm.example/…'
    >>> url_origin("git+https://github.com/o/r.git@main")
    'git+https://github.com/…'

    Le plus sûr pour un message : ni identifiants, ni chemin (certains registres
    privés y placent un jeton), ni paramètres. Un texte qui n'est pas une URL
    (« github:auteur/projet ») est renvoyé après redact_url().

    L'hôte est celui que lisent git, curl et les navigateurs : ce qui suit le dernier
    « @ » AVANT le premier « / ». Sinon « https://evil.example/x@github.com » afficherait
    github.com, un hôte de confiance, alors que le code vient d'evil.example. En cas de
    doute, on n'affiche pas d'hôte du tout (« https://… ») :
    - « \\ » avant le premier « / » : les outils ne le lisent pas tous pareil ;
    - un « @ » plus loin (référence git « @main », ou mot de passe mal encodé qui
      contient « / ») : l'hôte n'est affiché que s'il a la forme d'un vrai nom
      (« github.com », une adresse IP), jamais celle d'un morceau de mot de passe.
    """
    value = value.strip()
    scheme = _SCHEME.match(value)
    if scheme:
        rest = value[scheme.end() :]
        authority = re.split(r"[/?#]", rest, maxsplit=1)[0]
        after = rest[len(authority) :]
        host = authority.rpartition("@")[2]
        ambiguous = "@" in after
        if "\\" in authority or not _HOST.fullmatch(host):
            return f"{scheme.group(0)}…"
        if ambiguous and not _NAMED_HOST.fullmatch(host):
            return f"{scheme.group(0)}…"
        return f"{scheme.group(0)}{host}/…"
    shorthand = _SHORTHAND.match(value)
    if shorthand:
        # « github:jane:jeton@auteur/projet » -> « github:auteur/projet »
        return shorthand.group(0) + value[shorthand.end() :].rpartition("@")[2]
    return redact_url(value)


def _is_dangerous(char: str) -> bool:
    if char.isprintable() and char.isascii():
        return False  # cas courant, le plus rapide
    if unicodedata.category(char) in _DANGEROUS_CATEGORIES:
        return True
    code = ord(char)
    return any(low <= code <= high for low, high in _DEFAULT_IGNORABLE_RANGES)


def _escape(char: str) -> str:
    if char in _NAMED_ESCAPES:
        return _NAMED_ESCAPES[char]
    code = ord(char)
    if code <= 0xFF:
        return f"\\x{code:02x}"
    if code <= 0xFFFF:
        return f"\\u{code:04x}"
    return f"\\U{code:08x}"


def json_for_logs(json_text: str) -> str:
    """Un JSON sans « ## » littéral, toujours valide et au contenu identique.

    Affiché dans un journal de CI, « ##[…] » (GitHub Actions) ou « ##vso[…] » (Azure
    Pipelines) serait lu comme une commande, où qu'il soit dans la ligne. « \\u0023 »
    est l'écriture JSON de « # » : le texte décodé ne change pas. « ## » n'apparaît que
    dans des chaînes, et aucun échappement JSON ne commence ni ne finit par « # ».
    """
    return json_text.replace("##", "#\\u0023")


def sanitize(text: str) -> str:
    """Rend visibles (et inoffensifs) les caractères de contrôle d'un texte.

    >>> sanitize("evil\\n::error::x")
    'evil\\\\n::error::x'

    Les lettres accentuées et les emojis sont conservés : seuls les caractères
    capables de modifier l'affichage, de créer une nouvelle ligne, de cacher du
    texte ou de rendre la sortie impossible à encoder sont échappés.
    """
    if not any(_is_dangerous(c) for c in text):
        return text  # cas courant : aucun coût
    return "".join(_escape(c) if _is_dangerous(c) else c for c in text)
