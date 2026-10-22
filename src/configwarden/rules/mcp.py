"""Règles CW1xx : configurations de serveurs MCP dangereuses.

MCP (Model Context Protocol) permet à un agent IA (Claude, Cursor, VS Code…)
d'utiliser des outils externes. Une mauvaise config peut donner à l'IA, ou
à quelqu'un qui la manipule par injection de prompt, un accès bien trop large.

Emplacements des serveurs reconnus (documentation officielle, octobre 2026) :
  {"mcpServers": {...}}                       Claude Desktop, Claude Code, Cursor, Gemini CLI,
                                              Cline, Roo Code, Windsurf, Kiro, Amazon Q…
  {"servers": {...}}                          VS Code (.vscode/mcp.json), fichiers « mcp » seulement
  {"mcp": {"servers": {...}}}                 VS Code, ancien format de settings.json
  {"customizations": {"vscode": {"mcp":
      {"servers": {...}}}}}                   conteneur de développement (devcontainer.json)
  {"context_servers": {...}}                  Zed (settings.json)
  {"projects": {"/chemin": {"mcpServers"}}}   Claude Code (~/.claude.json, serveurs par projet)

Tout fichier .json ou .jsonc est lu, commentaires compris (voir jsonc.py) ; il n'est
analysé que s'il contient l'une de ces structures. La détection se fait APRÈS la
lecture : un nom de clé écrit avec des échappements (« mcp\\u0053ervers ») ne
permet pas de cacher un serveur.
"""

from __future__ import annotations

import json
import re
import sys
from collections.abc import Iterable, Iterator
from pathlib import PurePosixPath
from urllib.parse import unquote, urlparse

from configwarden import commands, containers, jsonc, values
from configwarden.models import Finding, Rule, Severity
from configwarden.npm_args import parse_npx
from configwarden.redact import redact, redact_url, url_origin
from configwarden.rules.secrets import mask_secrets

# --- Définition des règles -----------------------------------------------------

# Gravité moyenne (décision du 8 octobre 2026) : certains outils IA tolèrent les
# erreurs de syntaxe et lancent quand même les serveurs qu'ils ont pu lire. Un
# fichier abîmé exprès pourrait donc cacher un serveur à configwarden.
INVALID_CONFIG = Rule(
    id="CW100",
    title="Unreadable MCP configuration",
    severity=Severity.MEDIUM,
    remediation=(
        "Fix the JSON syntax so the configuration can be audited. Some AI clients still "
        "start the servers they can read from a broken file."
    ),
)
SHELL_EXECUTION = Rule(
    id="CW101",
    title="MCP server runs a shell script or inline code",
    severity=Severity.HIGH,
    remediation=(
        "Call the server program directly, with its arguments as separate items (on Windows, "
        "`cmd /c` followed by the program and its arguments is fine). A script given to "
        "`bash -c`, a command-line string or inline code (`node -e`) enables command "
        "injection and hides what really runs."
    ),
)
UNPINNED_PACKAGE = Rule(
    id="CW102",
    title="Unpinned MCP package version",
    severity=Severity.MEDIUM,
    remediation=(
        "Pin an exact version (e.g. `@scope/pkg@1.2.3` or `pkg==1.2.3`). Without it, "
        "a compromised new release would run automatically on your machine."
    ),
)
HARDCODED_ENV_SECRET = Rule(
    id="CW103",
    title="Secret hardcoded in MCP configuration",
    severity=Severity.HIGH,
    remediation=(
        "Reference an environment variable (e.g. `${GITHUB_TOKEN}` or "
        "`${env:GITHUB_TOKEN}`) instead of writing the value in the file."
    ),
)
BROAD_FILESYSTEM = Rule(
    id="CW104",
    title="Overly broad filesystem access",
    severity=Severity.HIGH,
    remediation=(
        "Grant access only to the project folder the agent needs, never the root "
        "or home directory (which contains SSH keys, browser data, .env files…)."
    ),
)
INSECURE_TRANSPORT = Rule(
    id="CW105",
    title="Remote MCP server over plain HTTP",
    severity=Severity.HIGH,
    remediation="Use https:// so tokens and data cannot be intercepted.",
)

DANGEROUS_CONTAINER = Rule(
    id="CW106",
    title="MCP server container escapes isolation",
    severity=Severity.HIGH,
    remediation=(
        "Remove --privileged, host namespaces and mounts of '/', the home directory or the "
        "Docker socket. Mount only the project folder the server needs, read-only if possible."
    ),
)
UNTRUSTED_PACKAGE_SOURCE = Rule(
    id="CW107",
    title="MCP package installed from an unverified source",
    severity=Severity.HIGH,
    remediation=(
        "Install the server from the official registry (npm / PyPI) with a pinned version. "
        "A git repository or URL can change at any time and bypasses registry checks."
    ),
)
AUTO_APPROVED_TOOLS = Rule(
    id="CW108",
    title="MCP tools run without user confirmation",
    severity=Severity.MEDIUM,
    remediation=(
        "Remove `alwaysAllow` / `autoApprove` / `trust: true`, or limit it to read-only tools. "
        "Confirmation is the last barrier against a prompt-injected agent."
    ),
)

# CW109 (décision du 8 octobre 2026) : un réglage de l'outil IA, et non d'un serveur,
# qui supprime toute confirmation. Dans un dépôt, il transforme l'ouverture d'un
# projet piégé en exécution automatique de ses serveurs et de ses outils.
CLIENT_AUTO_APPROVE = Rule(
    id="CW109",
    title="AI client approves actions without confirmation",
    severity=Severity.HIGH,
    remediation=(
        "Turn off the global auto-approve setting and approve servers and tools one by one. "
        "Never commit such a setting to a repository: anyone who opens the project would run "
        "its servers and tools without being asked."
    ),
)

# CW110 : vérification des certificats TLS désactivée (NODE_TLS_REJECT_UNAUTHORIZED=0,
# --insecure…). Relevé par le grand test du 8 octobre 2026, où ce réglage n'était
# signalé que comme un « secret » (CW103), pour une mauvaise raison.
INSECURE_TLS = Rule(
    id="CW110",
    title="TLS certificate checks disabled",
    severity=Severity.HIGH,
    remediation=(
        "Remove the setting that turns off certificate verification. Without it, anyone on "
        "the network path can impersonate the server or the package registry, and read or "
        "change the traffic, tokens included."
    ),
)

# CW111 (décision du 14 octobre 2026) : l'équivalent de CW102 pour les conteneurs. Le
# grand test du 8 octobre a trouvé environ 110 « docker run » dans 3 099 exemples
# publiés, tous sans version ni empreinte.
UNPINNED_CONTAINER_IMAGE = Rule(
    id="CW111",
    title="Unpinned MCP container image",
    severity=Severity.MEDIUM,
    remediation=(
        "Pin the image to a digest (e.g. `ghcr.io/org/server@sha256:…`), or at least to an "
        "exact version tag (e.g. `:1.2.3`). `latest` and other floating tags point to whatever "
        "was pushed last: a new machine, a `docker pull` or `--pull always` would run a "
        "compromised release without warning."
    ),
)

# CW112 (décision du 21 octobre 2026) : une variable d'environnement, ou une option du
# lanceur, qui change ce qui s'exécute vraiment. C'est le même contournement que ceux de
# la revue de la 0.4.0, par un autre chemin : du code chargé en plus, ou des paquets
# pris ailleurs que dans le registre officiel.
UNSAFE_ENVIRONMENT = Rule(
    id="CW112",
    title="MCP server environment changes what really runs",
    severity=Severity.HIGH,
    remediation=(
        "Remove the variable or option. Code loaded through NODE_OPTIONS (--require, --import), "
        "LD_PRELOAD, BASH_ENV or a Java agent runs inside every program the server starts, "
        "and a replaced package registry can serve modified packages. If you really use a "
        "private registry or mirror, accept it explicitly in .configwarden-ignore."
    ),
)

# CW113 (décision du 21 octobre 2026, gravité moyenne) : une commande que l'outil IA ou
# l'éditeur lance tout seul (hooks, tâche à l'ouverture du dossier, initializeCommand).
# C'est ainsi que le ver Shai-Hulud se réinstalle dans les projets de ses victimes.
AUTO_RUN_COMMAND = Rule(
    id="CW113",
    title="Command runs automatically when the project is used",
    severity=Severity.MEDIUM,
    remediation=(
        "Check what the command does and who added it. A repository can make your AI client or "
        "editor run a program as soon as the project is opened or the agent acts (hooks, tasks "
        "run on folder open, dev container initializeCommand): this is how the Shai-Hulud worm "
        "reinstalls itself. Remove it, or accept it in .configwarden-ignore after review."
    ),
)

RULES = [
    INVALID_CONFIG,
    SHELL_EXECUTION,
    UNPINNED_PACKAGE,
    HARDCODED_ENV_SECRET,
    BROAD_FILESYSTEM,
    INSECURE_TRANSPORT,
    DANGEROUS_CONTAINER,
    UNTRUSTED_PACKAGE_SOURCE,
    AUTO_APPROVED_TOOLS,
    CLIENT_AUTO_APPROVE,
    INSECURE_TLS,
    UNPINNED_CONTAINER_IMAGE,
    UNSAFE_ENVIRONMENT,
    AUTO_RUN_COMMAND,
]

# --- Constantes de détection ---------------------------------------------------

# Fichiers propres à MCP : s'ils sont illisibles, on le signale (CW100), et la clé
# « servers » (VS Code) n'y est reconnue que là. Les autres fichiers JSON sont lus
# aussi, mais restent silencieux s'ils sont illisibles ou sans serveur MCP.
MCP_CONFIG_NAMES = {
    "mcp.json",  # VS Code, Cursor, Roo Code, Kiro, Amazon Q
    ".mcp.json",  # Claude Code, VS Code
    "mcp_config.json",  # Windsurf / Devin Desktop
    "claude_desktop_config.json",  # Claude Desktop
    "cline_mcp_settings.json",  # Cline
    "mcp_settings.json",  # Roo Code (global)
    "mcp-config.json",  # GitHub Copilot CLI
}
_JSON_SUFFIXES = (".json", ".jsonc")
# Dossiers de configuration des outils IA : un fichier JSON qu'on n'y peut pas lire
# (trop gros, binaire, lien symbolique…) est signalé, car l'outil, lui, peut le lire.
_CLIENT_FOLDERS = {
    ".amazonq",
    ".claude",
    ".codeium",
    ".codex",
    ".continue",
    ".copilot",
    ".cursor",
    ".devcontainer",
    ".devin",
    ".gemini",
    ".kiro",
    ".roo",
    ".vscode",
    ".windsurf",
    ".zed",
}
# Clés qui annoncent des serveurs MCP. Cherchées dans le texte brut d'un fichier
# JSON abîmé, après décodage des échappements « \\uXXXX ».
_MCP_MARKERS = ('"mcpServers"', '"context_servers"', '"mcp"')
# Clés de commandes automatiques (CW113) : un fichier abîmé qui les contient est signalé,
# car VS Code et d'autres outils lisent leurs fichiers avec tolérance.
_AUTO_RUN_MARKERS = ('"hooks"', '"runOn"', '"initializeCommand"')
_UNICODE_ESCAPE = re.compile(r"\\u([0-9a-fA-F]{4})")
# Clés qui désignent l'adresse d'un serveur distant, selon l'outil.
_URL_KEYS = ("url", "serverUrl", "httpUrl")
# Lanceurs de paquets ; « pnpm dlx », « bun x », « uv tool run »… y sont ramenés par
# commands.analyse(). « pipx run » garde son nom : ses options lui sont propres.
_PACKAGE_RUNNERS = {"npx", "pnpx", "bunx", "uvx", "pipx run"}
_PYTHON_RUNNERS = {"uvx", "pipx run"}
# Options dont la valeur désigne le paquet lancé (« -p » est --python pour uvx). npx,
# pnpm dlx et bunx sont lus exactement comme npm les lit : voir npm_args.py.
_UV_PACKAGE_FLAGS = {"--from"}
_PIPX_PACKAGE_FLAGS = {"--spec"}
_PIPX_OPTIONS_WITH_VALUE = {"--spec", "--python", "--index-url", "-i", "--pip-args", "--backend"}
# Chemin local (« ./serveur », « /opt/srv », « C:\\srv », « file:… ») : rien n'est
# téléchargé depuis un registre, il n'y a donc pas de version à figer.
_LOCAL_PATH = re.compile(r"\.{1,2}(?:[\\/]|$)|~[\\/]|/|[A-Za-z]:[\\/]|file:", re.IGNORECASE)
# uvx : paquets installés EN PLUS du serveur (leur code s'exécute aussi).
_EXTRA_PACKAGE_FLAGS = {"--with", "--with-editable"}
_NPM_LIKE_RUNNERS = {"npx", "pnpx", "bunx"}
# Variable d'environnement lue par npm (npx, npm exec) : une ligne lancée dans un shell.
_NPM_CONFIG_CALL_KEY = re.compile(r"npm_config_call", re.IGNORECASE)
# uv sépare les paquets de « --with a,b » sur les virgules, sauf entre crochets (extras :
# « pkg[a,b] ») et sauf devant un opérateur de version (plage : « pkg>=1,<2 »). Vérifié
# avec uv 0.11 le 20 octobre 2026.
_VERSION_OPERATORS = frozenset("!=<>~")
_NEXT_CHARACTER = re.compile(r"\s*(\S)")
# Python : les « extras » de PEP 508 (« mcp[cli] », « psycopg[binary,pool] ») suivent un
# nom ; un modèle à remplir (« [VOTRE PAQUET] ») commence, lui, par le crochet.
_PYTHON_EXTRAS = re.compile(r"(?<=[A-Za-z0-9])\[[A-Za-z0-9._,\s-]{1,128}\]")
# Options d'uvx suivies d'une valeur (« -f » y est --find-links). Sans cette liste, la
# valeur d'une option (« --index-url https://… ») serait prise pour le paquet, et une
# option sans valeur ferait sauter le vrai paquet. Une option inconnue est supposée SANS
# valeur. npx n'a plus besoin de liste : il est lu comme npm le lit (npm_args.py).
_UV_OPTIONS_WITH_VALUE = {
    "--from",
    "--with",
    "--with-editable",
    "--with-requirements",
    "--python",
    "-p",
    "--index",
    "--index-url",
    "--extra-index-url",
    "--default-index",
    "--find-links",
    "-f",
    "--directory",
    "--project",
    "--cache-dir",
    "--config-file",
    "--constraints",
    "--overrides",
    "--exclude-newer",
    "--index-strategy",
    "--keyring-provider",
    "--python-preference",
    # Relevé complet des options d'uvx (« uv tool run ») suivies d'une valeur, oct. 2026.
    "-c",
    "-b",
    "--build-constraints",
    "-i",
    "-C",
    "--config-setting",
    "--config-settings-package",
    "-P",
    "--upgrade-package",
    "--reinstall-package",
    "--refresh-package",
    "--no-build-package",
    "--no-binary-package",
    "--only-binary-package",
    "--no-build-isolation-package",
    "--resolution",
    "--prerelease",
    "--fork-strategy",
    "--link-mode",
    "--env-file",
    "--color",
    "--allow-insecure-host",
    "--exclude-newer-package",
    "--torch-backend",
    "--python-platform",
}
# Clés qui annoncent un secret. Elles sont d'abord normalisées (« apiKey », « api-key »
# -> « API_KEY »), puis lues mot par mot : KEY, AUTH ou SESSION doivent être des mots
# entiers (KEYCLOAK, TOKENIZER, OAUTH ne sont pas des secrets) ; PASSWORD, SECRET,
# TOKEN… peuvent finir un mot collé (« MYSQLPASSWORD », « GHTOKEN »).
_GLUED_SENSITIVE_WORDS = (
    r"[A-Z0-9]{0,40}(?:PASSWORD|PASSWD|PASSPHRASE|SECRETS?|TOKENS?|APIKEY|ACCESSKEY"
    r"|SECRETKEY|PRIVATEKEY)"
)
_SENSITIVE_KEY = re.compile(
    rf"(?:^|_)(?:{_GLUED_SENSITIVE_WORDS}|KEYS?|PASS|PWD|PAT|AUTH|AUTHORIZATION|CREDENTIALS?|SESSION"
    r"|COOKIES?|BEARER)(?:_|$)"
)
# Sous ces clés, même un mot ou un nombre peut être le secret (« postgres », « 123456 »).
_PASSWORD_KEY = re.compile(
    r"(?:^|_)(?:[A-Z0-9]{0,40}(?:PASSWORD|PASSWD|PASSPHRASE|SECRETS?)|PASS|PWD)(?:_|$)"
)
# Clés qui contiennent un mot sensible sans désigner un secret : un réglage, une
# adresse, un identifiant public… (MAX_TOKENS, TOKEN_URL, CLIENT_ID, SORT_KEY…).
# Mesuré le 8 octobre 2026 sur 3 099 exemples publiés, puis revue de l'Auditeur.
_NON_SECRET_KEY = re.compile(
    r"(?:^|_)(?:MAX|MIN|NUM)_"
    r"|(?:^|_)(?:SORT|PRIMARY|FOREIGN|PARTITION|ROUTING|LOOKUP|INDEX|CACHE)_KEYS?(?:_|$)"
    r"|_(?:PORT|TIMEOUT|TTL|LIMIT|SIZE|COUNT|LENGTH|URL|URI|ENDPOINT|HOST|DOMAIN|PATH|FILE|DIR"
    r"|NAME|USER|USERNAME|EMAIL|REGION|SCOPES?|ISSUER|AUDIENCE|ALGORITHM|TYPE|METHOD|MODE"
    r"|PROVIDER|VERSION|EXPIRY|EXPIRES(?:_IN)?|ENABLED|DISABLED|MINT|ADDRESS|LOCATION"
    r"|COMMAND|CMD|PREFIX|STRATEGY|REALM|MODEL"
    r"|(?:CLIENT|APP|TENANT|PROJECT|ACCOUNT|ORG|USER)_ID)$"
)
# Clés qui annoncent un chemin de fichier (le contenu, lui, n'est pas dans la valeur).
_PATH_KEY = re.compile(r"PATH|FILE|DIR|FOLDER|CREDENTIALS|LOCATION|KEYSTORE|CERT|PEM|P12|PFX")
# Paramètre d'URL signé (Azure SAS « sig= », AWS « X-Amz-Signature= ») : un secret.
_SIGNATURE_KEY = re.compile(r"(?:^|_)SIG(?:NATURE)?$")
_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_KEY_SEPARATORS = re.compile(r"[-.\s]+")
_SCHEME_PREFIX = re.compile(r"[A-Za-z][A-Za-z0-9+.-]{0,31}://")
# Ligne de commande : options qui passent un en-tête HTTP ou une variable d'environnement.
_HEADER_OPTIONS = {"-H", "--header", "--headers"}
_ENV_OPTIONS = {"-e", "--env", "--set-env", "--environment"}
_OPTION = re.compile(r"--?([A-Za-z][A-Za-z0-9_.-]{0,63})(?:=(.*))?", re.DOTALL)
_ASSIGNMENT = re.compile(r"([A-Za-z_][A-Za-z0-9_.-]{0,127})=(.*)", re.DOTALL)
_MAX_QUERY_PARAMETERS = 100
_MAX_EMBEDDED_JSON = 65_536

# CW110 : réglages qui coupent la vérification des certificats TLS.
_TRUE = {"1", "true", "yes", "on", "y"}
_FALSE = {"0", "false", "no", "off", "n"}
# Variables connues dont la valeur « 0 » coupe la vérification.
_TLS_OFF_WHEN_ZERO = {"NODE_TLS_REJECT_UNAUTHORIZED", "PYTHONHTTPSVERIFY"}
# Hôtes acceptés sans vérification (uv, pip) : toute valeur compte.
_TLS_INSECURE_HOSTS = {
    "UV_INSECURE_HOST",
    "PIP_TRUSTED_HOST",
    "ALLOW_INSECURE_HOST",
    "TRUSTED_HOST",
}
# « …_SSL_VERIFY=false », « VERIFY_SSL=false », « --strict-ssl=false »
_TLS_VERIFY_NAME = re.compile(
    r"(?:^|_)(?:(?:SSL|TLS|CERTS?)_?VERIF(?:Y|ICATION)|VERIFY_?(?:SSL|TLS|CERTS?)"
    r"|(?:SSL|TLS)_?(?:CHECK|VALIDATION)|STRICT_?SSL|CHECK_?CERTIFICATES?)$"
)
# « …_INSECURE=true », « GIT_SSL_NO_VERIFY=true », « --insecure-skip-tls-verify »
_TLS_SKIP_NAME = re.compile(
    r"(?:^|_)(?:INSECURE|(?:SKIP|NO|DISABLE|IGNORE)_?(?:SSL|TLS|CERT(?:IFICATE)?S?)"
    r"(?:_?(?:VERIFY|VERIFICATION|CHECKS?|ERRORS))?|(?:SSL|TLS)_?(?:NO|SKIP)_?VERIFY"
    r"|INSECURE_?SKIP_?TLS_?VERIFY|TLS_?INSECURE)$"
)
# CW103 : références à une variable (pas un secret) selon les outils :
# $VAR, ${VAR}, ${env:VAR}, ${input:id}, %VAR% (Windows), $env:VAR (PowerShell),
# ${{ secrets.NOM }} (Continue).
_ENV_REFERENCE = re.compile(
    r"\$\{?[A-Za-z_][A-Za-z0-9_:.]*\}?"
    r"|\$\{(?:env|input):.+\}"
    r"|%[A-Za-z_][A-Za-z0-9_]*%"
    r"|\$env:[A-Za-z_][A-Za-z0-9_]*"
    r"|\$\{\{\s*[A-Za-z0-9_.]+\s*\}\}"
)
# ${VAR:-défaut} : la valeur par défaut, elle, peut être un vrai secret écrit en clair.
_DEFAULTED_REFERENCE = re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*:?[-=](.*)\}", re.DOTALL)
# Les modèles à remplir des documentations (<YOUR_KEY>, sk-..., xxxx…) sont reconnus
# par values.is_placeholder().
# Mot de passe dans une URL (postgres://user:motdepasse@hôte). Quantités bornées et
# début de mot obligatoire : temps linéaire même sur un texte piégé.
_URL_PASSWORD = re.compile(
    r"(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]{0,31}://[^/@\s:]{0,256}:([^@\s/]{1,512})@"
)
# Jeton utilisé comme nom d'utilisateur : https://ghp_…@github.com/… (long, avec un chiffre).
_URL_USER_TOKEN = re.compile(
    r"[A-Za-z][A-Za-z0-9+.-]{0,31}://((?=[A-Za-z0-9_-]{0,255}\d)[A-Za-z0-9_-]{20,256})@"
)
# CW104 / CW106 : dossiers trop larges (racine, lecteur, dossier personnel entier).
_BROAD_PATH = re.compile(
    r"/|/root|[a-z]:|(?:/home|/users|[a-z]:/users)(?:/[^/]+)?"
    r"|~|\$home|\$\{home\}|\$\{userhome\}|%userprofile%|%homepath%"
    r"|\$\{env:(?:userprofile|home)\}|\$env:(?:userprofile|home)",
    re.IGNORECASE,
)
# Dossiers d'identifiants, où qu'ils soient : .ssh, .aws, .gnupg, .kube, .docker…
_CREDENTIAL_FOLDER = re.compile(
    r"(?:^|/)\.(?:ssh|aws|gnupg|kube|docker|azure|config/gcloud)(?:/|$)", re.IGNORECASE
)
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}  # noqa: S104 (liste de comparaison)

# CW106 : moteurs de conteneurs et options qui cassent l'isolation.
_CONTAINER_ENGINES = {"docker", "podman", "nerdctl"}
# Valeurs « vrai » d'un booléen pour Docker, Podman et nerdctl (strconv.ParseBool de Go).
_PFLAG_TRUE = {"1", "t", "T", "TRUE", "true", "True"}
_HOST_NAMESPACE_FLAGS = {"--network", "--net", "--pid", "--ipc", "--uts", "--userns"}
_MOUNT_FLAGS = {"-v", "--volume"}
_DANGEROUS_CAPABILITIES = {"ALL", "SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "NET_ADMIN"}
_SENSITIVE_MOUNT_SOURCES = {"/etc", "/root", "/var/run", "/run"}

# CW107 : préfixes qui désignent un paquet hors registre officiel.
_UNTRUSTED_SOURCE_PREFIXES = (
    "git+",
    "git://",
    "github:",
    "gitlab:",
    "bitbucket:",
    "http://",
    "https://",
    "ssh://",
    "hg+",
    "svn+",
    "bzr+",
)
# npm : « auteur/projet » (sans @ devant) désigne un dépôt GitHub, pas le registre.
_GITHUB_SHORTHAND = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9_.-]+(?:#\S*)?")
# Adresse git au format « scp » : git@github.com:auteur/projet.git
_SCP_GIT = re.compile(r"[A-Za-z0-9._-]+@([A-Za-z0-9.-]+):\S+")
# Python (PEP 508) : « nom @ url » installe depuis cette adresse.
_PEP508_URL = re.compile(r"\s*[A-Za-z0-9._-]+(?:\[[^\]]*\])?\s*@\s*(\S+)\s*")
# Version exacte : npm (semver x.y.z) et Python (== ou @ suivi d'un numéro).
_NPM_EXACT_VERSION = re.compile(r"v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?")
_UV_EXACT_VERSION = re.compile(
    r"\s*[A-Za-z0-9._-]+(?:\[[^\]]*\])?\s*(?:===?|@)\s*v?\d[0-9A-Za-z.+!-]*\s*"
)

# CW112 : variables qui font charger du code en plus (noms comparés en majuscules :
# Windows ne distingue pas la casse).
_PRELOAD_VARIABLES = {
    "LD_PRELOAD": "preloads a library into every program it starts",
    "LD_AUDIT": "loads an audit library into every program it starts",
    "DYLD_INSERT_LIBRARIES": "preloads a library into every program it starts",
    "BASH_ENV": "runs a script every time bash starts",
    "DOTNET_STARTUP_HOOKS": "loads a .NET startup hook",
    "NPM_CONFIG_SCRIPT_SHELL": "replaces the shell that runs npm scripts",
    "YARN_YARN_PATH": "runs another Yarn program instead of Yarn (yarnPath)",
}
_NODE_OPTIONS_VARIABLES = {"NODE_OPTIONS", "NPM_CONFIG_NODE_OPTIONS"}
_NODE_CODE_OPTIONS = {"-r", "--require", "--import", "--loader", "--experimental-loader"}
_NODE_DEBUG_OPTIONS = {"--inspect", "--inspect-brk", "--inspect-wait"}
_JAVA_OPTIONS_VARIABLES = {"JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS"}
_JAVA_AGENT = re.compile(
    r"(?:^|\s)(-javaagent|-agentpath|-agentlib|-XX:OnError|-XX:OnOutOfMemoryError)[:=]"
)
# Git : GIT_SSH_COMMAND est lu par un shell. « ssh -i clé » est normal ; un autre programme
# ou des caractères de shell ne le sont pas.
_SHELL_CHARACTERS = frozenset(";&|`$<>()\n{}*?[")
# Une ligne de plus de 10 000 caractères ou de 100 mots n'est pas lue en entier : on la signale
# plutôt que d'ignorer la fin (revue de l'Auditeur, 4e passe).
_SSH_LINE_LIMIT = 10_000
# Variables que le shell (GIT_SSH_COMMAND, par git) ou bash (BASH_ENV) développent eux-mêmes :
# « $X » y désigne une autre variable, que le bloc « env » a pu remplir. Seule la référence à la
# variable elle-même (« ${GIT_SSH_COMMAND} », le réglage de l'utilisateur transmis tel quel) est
# écartée. GIT_SSH (le programme que git lance à la place de ssh) n'est développé par personne : sa
# valeur est le nom exact du fichier, lue ici sans rien en retirer (revue de l'Auditeur, 10e passe).
_SHELL_READ_VARIABLES = ("GIT_SSH_COMMAND", "GIT_SSH", "BASH_ENV")
# Dossiers des programmes du système (hors du projet). Pas « /usr/src », « /opt/app », « /home »,
# « /tmp » ni « /proc » : un projet peut y être (conteneur, poste) ou s'y atteindre
# (« /proc/self/cwd »). Revue de l'Auditeur, 5e passe.
_SYSTEM_PREFIXES = (
    "/usr/bin/", "/usr/sbin/", "/usr/local/bin/", "/usr/local/sbin/", "/usr/local/opt/",
    "/usr/local/Cellar/", "/bin/", "/sbin/", "/opt/homebrew/", "/opt/local/bin/", "/etc/",
    "/Applications/", "/usr/games/", "/usr/local/games/", "/snap/bin/", "/nix/store/",
    "/nix/var/nix/profiles/", "/run/current-system/sw/bin/", "/usr/local/go/bin/",
    "/opt/X11/bin/", "/System/Cryptexes/App/usr/bin/", "/Library/Apple/usr/bin/",
)  # fmt: skip
# Dossiers d'outils de l'utilisateur (gestionnaires de versions, installations locales) : un
# dossier caché, « bin » ou « go/bin ». Pas « ~/projet » : le projet y est cloné par défaut.
_USER_TOOLS = re.compile(r"(?:/Users/[^/]+|/home/[^/]+|/root)/(?:\.[^/]|bin/|go/bin/)")
_HOME_TOOLS = re.compile(r"(?:~|\$HOME|\$\{HOME\})/(?:\.[^/]|bin/|go/bin/)")
# Windows, seulement quand le scanner y tourne (voir `_on_windows`).
_SYSTEM_WINDOWS = re.compile(
    r"[A-Za-z]:[\\/](?:Windows|Program Files(?: \(x86\))?)(?:[\\/]|$)", re.I
)
_USER_TOOLS_WINDOWS = re.compile(
    r"[A-Za-z]:[\\/]Users[\\/][^\\/]+[\\/]"
    r"(?:\.[^\\/]|AppData[\\/]|scoop[\\/]|bin[\\/]|go[\\/]bin[\\/])",
    re.I,
)
_PATH_SELF = frozenset({"$PATH", "${PATH}", "%PATH%"})
# Références à une variable : « ${X} », « ${env:X} », « $X », « %X% », « $env:X » ; avec valeur par
# défaut (« ${X:-…} ») pour la seconde forme.
_PLAIN_REFERENCE = re.compile(
    r"\$\{(?:(?i:env):)?(?P<a>[A-Za-z_][A-Za-z0-9_]*)\}|\$(?i:env):(?P<d>[A-Za-z_][A-Za-z0-9_]*)"
    r"|%(?P<c>[A-Za-z_][A-Za-z0-9_]*)%|\$(?P<b>[A-Za-z_][A-Za-z0-9_]*)"
)
_DEFAULTED_NAME = re.compile(
    r"\$\{(?P<name>[A-Za-z_][A-Za-z0-9_]*):?[-=](?P<default>.*)\}", re.DOTALL
)
# Toute référence à lire dans un texte. « ${…} » : npm lit son contenu entier comme un nom
# (« ${a-b} », « ${a.b} »), un shell seulement le début (« a », puis une valeur par défaut) ; on
# essaie les deux, quelle que soit la longueur du nom. Ni « { » ni « } » dedans (npm fait de même :
# seule la référence la plus intérieure compte) : chaque « ${ » s'arrête à l'accolade suivante, donc
# « ${A:-${A:-… » répété se relit en temps linéaire (avec « [^}]* », il était quadratique).
_REFERENCE_IN_TEXT = re.compile(
    r"\$\{(?P<g>[^{}]+)\}|\$(?i:env):(?P<d>[A-Za-z_][A-Za-z0-9_]*)"
    r"|%(?P<c>[A-Za-z_][A-Za-z0-9_]*)%|\$(?P<b>[A-Za-z_][A-Za-z0-9_]*)"
)
_BRACED_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
# Une espace que le shell ne coupe pas (il ne coupe que « ' ', tabulation, saut de ligne »).
_UNUSUAL_SPACE = re.compile(r"[^\S \t\n]")
# « ${X:-défaut} », « ${X-défaut} », « ${X:=défaut} », « ${X=défaut} » et « ${X:+valeur} » (X
# définie : sa valeur de remplacement) n'importe où dans un texte.
# Pas d'accolade dans le défaut : seule la référence la plus intérieure se lit à chaque tour, donc
# un texte piégé (« ${A:-${A:-… ») se relit en temps linéaire.
_DEFAULT_IN_TEXT = re.compile(r"\$\{[A-Za-z_]\w*:?[-=+]([^{}]*)\}")
# « ${…} » comme Claude Code le développe : /\$\{([^}]+)\}/g, le contenu coupé au premier « :- » (le
# nom peut être n'importe quoi, le défaut s'arrête à la première « } »). Voir `_client_reading`.
_CLIENT_REFERENCE = re.compile(r"\$\{([^}]+)\}")
_URL_SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]{0,31}://")
# Limites du suivi des références (voir `_known_expansions`).
_MAX_EXPANSIONS = 64
_MAX_EXPANDED_LENGTH = 20_000
_MAX_REFERENCE_DEPTH = 8
_MAX_DEFINITIONS = 8
_MAX_REPEAT = 3  # une variable n'est remplacée que 3 fois le long d'un chemin (A=${B}, B=${A})
_MAX_READING = 400_000  # caractères relus au total pour un même ensemble de variables
# « $HOME » et « ${HOME} » seuls ne lancent rien. Toute autre variable (« $OPTS ») peut contenir
# des options ou des mots, et « $IFS » les couper : elles restent signalées.
_HOME_REFERENCE = re.compile(r"\$(?:HOME(?![A-Za-z0-9_])|\{HOME\})")
# « "~/x" », « ~"/x" », « \~/x », « '$HOME/x' » : le shell ne les développe pas, c'est un chemin
# relatif, donc un dossier du projet (revue de l'Auditeur, 6e passe).
_UNEXPANDED_HOME = re.compile(r"""["'\\]~|~["'\\]|\\\$|'[^']*\$\{?HOME""")
# Options de ssh qui lancent un programme ou chargent une bibliothèque, et la valeur qui les
# désactive.
_SSH_PROGRAM_OPTIONS = {
    "proxycommand": "ProxyCommand",
    "localcommand": "LocalCommand",
    "knownhostscommand": "KnownHostsCommand",
    "pkcs11provider": "PKCS11Provider",
    "securitykeyprovider": "SecurityKeyProvider",
    "xauthlocation": "XAuthLocation",  # lancé quand le transfert X11 est actif
}
_SSH_OFF_VALUES = {
    "ProxyCommand": ("none",),
    "PKCS11Provider": ("none",),
    "SecurityKeyProvider": ("internal",),
}
_SSH_LETTERS_WITH_ARGUMENT = frozenset("BbcDEeFIiJLlmOPpQRSWw")
# Perl : « -M », « -m » (module) et « -d » (débogueur), seuls ou groupés (« -wMx »).
_PERL_MODULE = re.compile(r"(?:^|\s)-[CDITUWtw]*([Mmd])")
# Ruby : « -r » charge une bibliothèque, avec ou sans tiret (« RUBYOPT=rubygems »).
_RUBY_REQUIRE = re.compile(r"(?:^|\s)-?[CEIKTWadlsvwx0-9]*r")
# CW112 : variables qui remplacent la source des paquets.
_REGISTRY_VARIABLES = {
    "PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "PIP_FIND_LINKS", "UV_INDEX_URL", "UV_DEFAULT_INDEX",
    "UV_EXTRA_INDEX_URL", "UV_INDEX", "UV_FIND_LINKS", "NPM_CONFIG_REGISTRY",
    "YARN_NPM_REGISTRY_SERVER", "YARN_REGISTRY", "BUN_CONFIG_REGISTRY",
}  # fmt: skip
_NPM_SCOPED_REGISTRY = re.compile(r"NPM_CONFIG_@[^:\s]{1,214}:REGISTRY")
# Registres officiels : pas d'alerte (test.pypi.org n'en fait pas partie : tout le monde
# peut y publier).
_OFFICIAL_REGISTRIES = {
    "pypi.org", "pypi.python.org", "files.pythonhosted.org", "registry.npmjs.org",
    "registry.yarnpkg.com",
}  # fmt: skip
# Options des lanceurs Python qui remplacent l'index des paquets.
_PYTHON_INDEX_OPTIONS = {
    "--index-url", "-i", "--default-index", "--extra-index-url", "--index", "--find-links", "-f",
}  # fmt: skip
_MAX_INDEX_ENTRIES = 20

# CW108 : clés qui autorisent des outils sans confirmation, selon le client IA.
_AUTO_APPROVE_KEYS = ("alwaysAllow", "autoApprove")


def _normalize_path(arg: str) -> str:
    """'C:\\' -> 'C:' ; '~/' -> '~' ; '/' reste '/'."""
    return arg.strip().rstrip("/\\") or "/"


def is_mcp_config(path: PurePosixPath) -> bool:
    """Le fichier porte-t-il un nom propre aux configurations MCP ?"""
    name = path.name.lower()
    return name in MCP_CONFIG_NAMES or name.endswith((".mcp.json", ".mcp.jsonc"))


def is_json_file(path: PurePosixPath) -> bool:
    """Fichier JSON quelconque, à lire au cas où il contiendrait des serveurs MCP."""
    return path.name.lower().endswith(_JSON_SUFFIXES)


def is_client_config_path(path: PurePosixPath) -> bool:
    """Chemin d'une configuration d'outil IA (fichier MCP, ou JSON d'un dossier connu)."""
    name = path.name.lower()
    if is_mcp_config(path) or name == ".claude.json":
        return True
    in_client_folder = any(part.lower() in _CLIENT_FOLDERS for part in path.parts)
    return in_client_folder and (is_json_file(path) or name in _CLIENT_FOLDERS)


def unreadable_config_finding(path: str) -> Finding:
    """Fichier de configuration que configwarden n'a pas pu lire du tout."""
    return Finding(
        rule=INVALID_CONFIG,
        path=path,
        line=1,
        message=(
            "This AI client configuration could not be read (too large, binary or "
            "unreadable), so it cannot be audited."
        ),
    )


def symlinked_config_finding(path: str) -> Finding:
    """Configuration (ou dossier de configuration) qui est un lien symbolique."""
    return Finding(
        rule=INVALID_CONFIG,
        path=path,
        line=1,
        message=(
            "This AI client configuration is a symbolic link. configwarden does not follow "
            "links (they can point outside the project): check what it points to."
        ),
    )


def _mentions_mcp(text: str) -> bool:
    """Le texte brut annonce-t-il des serveurs MCP ou des commandes automatiques (même avec
    des échappements) ?"""
    decoded = _UNICODE_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), text)
    return any(marker in decoded for marker in (*_MCP_MARKERS, *_AUTO_RUN_MARKERS))


# Une chaîne JSON complète, puis le « : » qui en fait une clé. On parcourt les
# chaînes ENTIÈRES, sans jamais redémarrer au milieu de l'une d'elles : temps
# linéaire, même avec des milliers de « \\" ». Le texte a déjà été accepté par
# json.loads, donc chaque guillemet trouvé ici ouvre bien une chaîne. Une chaîne
# peut contenir un saut de ligne brut (lecture tolérante, strict=False) : le motif
# l'accepte, sinon il se décalerait et redeviendrait quadratique.
_JSON_STRING = re.compile(r'"[^"\\]*(?:\\[\s\S][^"\\]*)*"')
_KEY_SEPARATOR = re.compile(r"\s*:")


def _key_lines(text: str) -> dict[str, int]:
    """Numéro de ligne (approximatif) de la 1re apparition de chaque clé JSON.

    Calculé en UNE seule lecture du fichier. Sécurité : relire tout le fichier pour
    chaque serveur coûtait un temps quadratique ; un fichier piégé de quelques
    centaines de Ko bloquait alors le scan pendant plusieurs minutes.
    Les noms écrits avec des échappements (« \\u0073 ») sont décodés.
    """
    lines: dict[str, int] = {}
    line, position = 1, 0
    for match in _JSON_STRING.finditer(text):
        if not _KEY_SEPARATOR.match(text, match.end()):
            continue  # une valeur, pas une clé
        line += text.count("\n", position, match.start())
        position = match.start()
        try:
            key = json.loads(match.group(0))
        except ValueError:
            continue
        lines.setdefault(key, line)
    return lines


def _dig(data: object, *keys: str) -> object:
    """data[k1][k2]… sans jamais lever d'exception (None si le chemin n'existe pas)."""
    for key in keys:
        if not isinstance(data, dict):
            return None
        data = data.get(key)
    return data


def _server_groups(data: object, mcp_named: bool) -> list[tuple[str, dict[str, dict]]]:
    """Tous les groupes de serveurs d'un fichier : (précision d'affichage, serveurs)."""
    if not isinstance(data, dict):
        return []
    candidates: list[tuple[str, object]] = [
        ("", data.get("mcpServers")),
        ("", _dig(data, "mcp", "servers")),
        ("", _dig(data, "customizations", "vscode", "mcp", "servers")),
        ("", data.get("context_servers")),
    ]
    if mcp_named:
        candidates.append(("", data.get("servers")))
    projects = data.get("projects")
    if isinstance(projects, dict):
        for project_path, project in projects.items():
            candidates.append((f" (project {project_path})", _dig(project, "mcpServers")))
    groups = []
    for label, servers in candidates:
        if isinstance(servers, dict):
            valid = {str(k): v for k, v in servers.items() if isinstance(v, dict)}
            if valid:
                groups.append((label, valid))
    return groups


def _auto_approve_settings(data: object) -> list[tuple[str, str]]:
    """Réglages CW109 trouvés : (clé pour le numéro de ligne, description du réglage).

    Réglages relevés dans la documentation officielle de chaque outil (8 octobre 2026).
    Seules les valeurs exactes comptent (`true` booléen, chaîne précise) : un type
    inattendu est ignoré, jamais une cause de plantage.
    """
    if not isinstance(data, dict):
        return []
    found: list[tuple[str, str]] = []

    def flag(key: str, description: str) -> None:
        found.append((key, description))

    # Claude Code (.claude/settings.json, settings.local.json, ~/.claude/settings.json)
    if data.get("enableAllProjectMcpServers") is True:
        flag(
            "enableAllProjectMcpServers",
            "Claude Code approves every MCP server of the project automatically "
            "(enableAllProjectMcpServers: true)",
        )
    if _dig(data, "permissions", "defaultMode") == "bypassPermissions":
        flag(
            "defaultMode",
            "Claude Code runs every action without asking (permissions.defaultMode: "
            "bypassPermissions)",
        )
    if data.get("skipDangerousModePermissionPrompt") is True:
        flag(
            "skipDangerousModePermissionPrompt",
            "Claude Code skips the confirmation of its dangerous modes "
            "(skipDangerousModePermissionPrompt: true)",
        )
    # VS Code (settings.json : clés « à plat »)
    for key in ("chat.tools.global.autoApprove", "chat.tools.autoApprove"):
        if data.get(key) is True:
            flag(key, f"VS Code approves every tool call without asking ({key}: true)")
    # Zed (settings.json : objets imbriqués)
    if _dig(data, "agent", "always_allow_tool_actions") is True:
        flag(
            "always_allow_tool_actions",
            "Zed runs every tool action without asking (agent.always_allow_tool_actions: true)",
        )
    if _dig(data, "agent", "tool_permissions", "default") == "allow":
        flag(
            "tool_permissions",
            "Zed allows every tool by default (agent.tool_permissions.default: allow)",
        )
    if _dig(data, "session", "trust_all_worktrees") is True:
        flag(
            "trust_all_worktrees",
            "Zed trusts every project folder, so project settings and servers load without a "
            "prompt (session.trust_all_worktrees: true)",
        )
    # Cursor (.cursor/permissions.json et configuration de la ligne de commande)
    allowlist = data.get("mcpAllowlist")
    if isinstance(allowlist, list) and "*:*" in allowlist:
        flag(
            "mcpAllowlist",
            "Cursor lets the agent run every MCP tool without asking (mcpAllowlist: *:*)",
        )
    cli_allow = _dig(data, "permissions", "allow")
    if isinstance(cli_allow, list) and "Mcp(*:*)" in cli_allow:
        flag("allow", "Cursor CLI lets the agent run every MCP tool without asking (Mcp(*:*))")
    # Kiro (réglages de l'éditeur)
    autonomy = data.get("kiroAgent.agentAutonomy")
    if isinstance(autonomy, str) and autonomy.lower() == "autopilot":
        flag(
            "kiroAgent.agentAutonomy",
            "Kiro runs in Autopilot mode: the agent's actions are not confirmed "
            "(kiroAgent.agentAutonomy: Autopilot)",
        )
    return found


_MAX_AUTO_RUNS = 100  # commandes automatiques signalées au plus, par fichier
# Champs qui portent la commande d'un hook : Claude Code, Cursor, Gemini, Windsurf
# (« command »), GitHub Copilot CLI (« bash », « powershell », « exec »).
_HOOK_COMMAND_FIELDS = ("command", "bash", "powershell", "exec")
# Réglages de Claude Code qui lancent un programme, acceptés dans un fichier du projet
# (documentation officielle, 21 octobre 2026).
_CLAUDE_COMMAND_SETTINGS = {
    "statusLine": "to draw its status line",
    "subagentStatusLine": "to draw its status line",
    "fileSuggestion": "to suggest files",
    "apiKeyHelper": "to get its API key",
    "awsAuthRefresh": "to refresh AWS credentials",
    "awsCredentialExport": "to export AWS credentials",
    "gcpAuthRefresh": "to refresh Google Cloud credentials",
    "otelHeadersHelper": "to compute telemetry headers",
}


def _program(command: object) -> str | None:
    """Le programme d'une commande (« curl -s x | sh » -> « curl »), jamais la ligne entière :
    elle peut contenir un jeton. None si ce n'est pas une commande lisible et non vide."""
    if isinstance(command, dict):
        command = command.get("value")  # VS Code : {"value": "…", "quoting": "…"}
    if isinstance(command, list):
        first = next((word for word in command if isinstance(word, str) and word.strip()), None)
    elif isinstance(command, str):
        first = commands.program_word(command)
    else:
        return None
    if not first:
        return None
    # Jamais ce qui suit un « = » (revue de l'Auditeur, 21 octobre) : « NOM=valeur » peut
    # porter un jeton. Retiré avant `executable_name`, qui ne garderait que la fin d'un chemin.
    first = first.partition("=")[0].strip()
    if not first or _secret_like(first):
        return commands.UNKNOWN_PROGRAM  # un jeton collé à la place de la commande
    name = commands.executable_name(first) or first
    # Seuls les noms de forme ordinaire sont montrés (revue de l'Auditeur, 4e passe) : un
    # morceau de secret avec « : », « @ » ou « ! » ne ressemble à aucun jeton connu.
    return name if _PROGRAM_NAME.fullmatch(name) else commands.UNKNOWN_PROGRAM


# Un mot de 20 caractères ou plus, sans point, fait d'une seule suite de lettres, chiffres et
# « _ + - » : un jeton bien plus souvent qu'un nom de programme (les scripts ont une extension).
_TOKEN_LIKE = re.compile(r"[A-Za-z0-9_+-]{20,}")
_PROGRAM_NAME = re.compile(r"[A-Za-z0-9_.-]{1,24}")


def _secret_like(word: str) -> bool:
    """Le mot (ou un des dossiers du chemin) ressemble-t-il à un secret ?"""
    for part in (word, *re.split(r"[\\/]", word)):
        if part and (
            mask_secrets(part) != part or _TOKEN_LIKE.fullmatch(part) or part.startswith("eyJ")
        ):
            return True
    return False


def _is_claude_settings(path: str, folder: str = "") -> bool:
    """Le fichier est-il un réglage de Claude Code (.claude/settings*.json) ?

    Casse ignorée (macOS et Windows ne la distinguent pas). `folder` est le dossier réel du
    fichier : un fichier analysé seul (« scan .claude/settings.json ») perd son dossier dans
    le chemin affiché.
    """
    location = PurePosixPath(path)
    name = location.name.lower()
    if name == "managed-settings.json":
        return True
    parent = (location.parent.name or folder).lower()
    return parent == ".claude" and name.startswith("settings") and name.endswith(".json")


def _auto_run_commands(data: object, *, claude_settings: bool = False) -> list[tuple[str, str]]:
    """CW113 : (clé pour le numéro de ligne, description) de chaque commande automatique.

    Formats relevés dans la documentation officielle (Éclaireur, 21 octobre 2026) :
    - « hooks » de Claude Code (.claude/settings*.json : événement -> [{matcher, hooks:
      [{type: "command", command}]}]) et de Cursor (.cursor/hooks.json : événement ->
      [{command}]) ;
    - tâches de VS Code (.vscode/tasks.json) avec "runOptions": {"runOn": "folderOpen"} ;
    - « initializeCommand » d'un conteneur de développement, lancé sur la machine hôte ;
    - réglages qui lancent un programme (« statusLine », « apiKeyHelper »…), lus seulement
      dans les fichiers de Claude Code (`claude_settings`) : ailleurs, « statusLine » peut être
      un simple texte d'interface (fichier de traduction).
    Un type inattendu est ignoré, jamais une cause de plantage ; le travail est borné.
    """
    if not isinstance(data, dict):
        return []
    found: list[tuple[str, str]] = []
    seen: set[str] = set()

    def flag(key: str, description: str) -> None:
        if description not in seen and len(found) < _MAX_AUTO_RUNS:
            seen.add(description)
            found.append((key, description))

    hooks = data.get("hooks")
    events_by_program: dict[str, list[str]] = {}  # un constat par programme, pas par événement
    budget = _MAX_AUTO_RUNS * 100  # gestionnaires examinés au plus : temps borné
    if isinstance(hooks, dict):
        for event, entries in list(hooks.items())[: _MAX_AUTO_RUNS * 10]:
            if not isinstance(entries, list):
                continue
            for entry in entries[:_MAX_AUTO_RUNS]:
                if not isinstance(entry, dict):
                    continue
                handlers = entry.get("hooks")
                candidates = [entry, *(handlers if isinstance(handlers, list) else [])]
                for handler in candidates[:_MAX_AUTO_RUNS]:
                    budget -= 1
                    if budget < 0:
                        break
                    if not isinstance(handler, dict) or handler.get("type", "command") != "command":
                        continue
                    program = next(
                        (
                            found_program
                            for field_name in _HOOK_COMMAND_FIELDS
                            if (found_program := _program(handler.get(field_name)))
                        ),
                        None,
                    )
                    if program and len(events_by_program) < _MAX_AUTO_RUNS:
                        events = events_by_program.setdefault(program, [])
                        if str(event) not in events and len(events) < _MAX_AUTO_RUNS:
                            events.append(str(event))
    elif isinstance(hooks, list):
        # Kiro (.kiro/hooks/*.json) : [{"trigger": …, "action": {"type": "command", …}}]
        for hook in hooks[: _MAX_AUTO_RUNS * 10]:
            if not isinstance(hook, dict) or not isinstance(hook.get("action"), dict):
                continue
            action = hook["action"]
            program = _program(action.get("command")) if action.get("type") == "command" else None
            if program and len(events_by_program) < _MAX_AUTO_RUNS:
                event = str(hook.get("trigger", "a trigger"))
                events = events_by_program.setdefault(program, [])
                if event not in events and len(events) < _MAX_AUTO_RUNS:
                    events.append(event)
    for program, events in events_by_program.items():
        shown = ", ".join(f"'{commands.shorten(event, 40)}'" for event in events[:3])
        more = f" and {len(events) - 3} more" if len(events) > 3 else ""
        flag(events[0], f"The AI client runs '{program}' automatically on {shown}{more} (hooks)")
    tasks = data.get("tasks")
    if isinstance(tasks, list):
        for task in tasks[: _MAX_AUTO_RUNS * 10]:
            if not isinstance(task, dict):
                continue
            # « windows », « linux », « osx » remplacent les propriétés de la tâche.
            variants = [task] + [
                variant
                for platform in ("windows", "linux", "osx")
                if isinstance(variant := task.get(platform), dict)
            ]
            if not any(
                isinstance(options := variant.get("runOptions"), dict)
                and options.get("runOn") == "folderOpen"
                for variant in variants
            ):
                continue
            program = next(
                (
                    task_program
                    for variant in variants
                    if (task_program := _program(variant.get("command")))
                ),
                "a task",
            )
            label = task.get("label")
            named = f" '{commands.shorten(label, 40)}'" if isinstance(label, str) and label else ""
            flag(
                "runOn",
                f"VS Code runs the task{named} ('{program}') as soon as the folder is opened "
                "(runOn: folderOpen)",
            )
    for key, purpose in _CLAUDE_COMMAND_SETTINGS.items() if claude_settings else ():
        setting = data.get(key)
        command = setting.get("command") if isinstance(setting, dict) else setting
        program = _program(command)
        if program:
            flag(key, f"Claude Code runs '{program}' {purpose} ({key})")
    initialize = data.get("initializeCommand")
    if isinstance(initialize, dict):
        programs = [_program(command) for command in list(initialize.values())[:_MAX_AUTO_RUNS]]
    else:
        programs = [_program(initialize)]
    for program in programs:
        if program:
            flag(
                "initializeCommand",
                f"The dev container runs '{program}' on your machine before it starts "
                "(initializeCommand)",
            )
    return found


def _claude_settings_env(data: object, claude_settings: bool) -> list[tuple[str, str]]:
    """CW112 : bloc « env » des réglages de Claude Code (.claude/settings*.json), appliqué à
    chaque session et à tous ses sous-processus : (clé, ce que la variable change)."""
    if not claude_settings:
        return []
    block = data.get("env") if isinstance(data, dict) else None
    if not isinstance(block, dict):
        return []
    found = []
    variables = _environment_variables(block)
    for key, value in list(block.items())[: _MAX_AUTO_RUNS * 10]:
        if isinstance(value, str):
            issue = _environment_issue(str(key), value, variables)
            if issue:
                found.append((str(key), issue))
    return found[:_MAX_AUTO_RUNS]


def _normalize_server(server: dict) -> dict:
    """Zed (ancien format) : "command": {"path", "args", "env"} -> forme commune."""
    command = server.get("command")
    if not isinstance(command, dict):
        return server
    merged = dict(server)
    merged["command"] = command.get("path")
    for key in ("args", "env"):
        if key in command and key not in server:
            merged[key] = command[key]
    return merged


def _package_is_pinned(runner: str, package: str) -> bool:
    """Version EXACTE ? « ^1.0.0 », « ~1.2 », « 1 », « beta », « >=1 » ne le sont pas."""
    if runner in _PYTHON_RUNNERS:
        return bool(_UV_EXACT_VERSION.fullmatch(package))
    # npm : "@scope/pkg@1.2.3" -> on ignore le "@" initial du scope.
    name_and_version = package[1:] if package.startswith("@") else package
    if "@" not in name_and_version:
        return False
    version = name_and_version.rsplit("@", 1)[1]
    return bool(_NPM_EXACT_VERSION.fullmatch(version))


def _is_broad_path(value: str) -> bool:
    """Racine, lecteur entier ou dossier personnel complet (pas un sous-dossier)."""
    return bool(_BROAD_PATH.fullmatch(_normalize_path(value).replace("\\", "/")))


def _literal_secret(value: str) -> str | None:
    """La partie littérale d'une valeur, ou None si c'est une référence ou un modèle."""
    candidate = value.strip().removeprefix("Bearer ").strip()
    for _ in range(20):  # ${A:-${B:-…}} : on descend, mais jamais indéfiniment
        defaulted = _DEFAULTED_REFERENCE.fullmatch(candidate)
        if defaulted is None:
            break
        candidate = defaulted.group(1).strip()
        if not candidate:
            return None
    if not candidate or _ENV_REFERENCE.fullmatch(candidate) or values.is_placeholder(candidate):
        return None
    return candidate


def _has_url_password(value: str) -> bool:
    match = _URL_PASSWORD.search(value)
    return match is not None and _literal_secret(match.group(1)) is not None


def _normalize_key(key: str) -> str:
    """« apiKey », « api-key », « X-Api-Key » -> « API_KEY », « X_API_KEY »."""
    return _KEY_SEPARATORS.sub("_", _CAMEL_BOUNDARY.sub("_", key.strip())).upper()


def _is_sensitive_name(key: str) -> bool:
    normalized = _normalize_key(key)
    return bool(_SENSITIVE_KEY.search(normalized)) and not _NON_SECRET_KEY.search(normalized)


def _secret_value(key: str, value: str, *, sensitive: bool = False) -> str | None:
    """La valeur littérale si le couple (clé, valeur) a l'air d'un secret écrit en clair.

    Ne sont PAS des secrets : une référence (${TOKEN}), un modèle à remplir, un booléen,
    un nombre court ou un mot (sauf sous une clé de mot de passe : « postgres »), un
    chemin de fichier, une adresse web (ses identifiants sont vérifiés à part).
    `sensitive` : la clé est déjà connue comme sensible (paramètre « sig » d'une URL).
    """
    normalized = _normalize_key(key)
    if not sensitive and (
        not _SENSITIVE_KEY.search(normalized) or _NON_SECRET_KEY.search(normalized)
    ):
        return None
    literal = _literal_secret(value)
    if literal is None or values.is_boolean(literal):
        return None
    password_like = bool(_PASSWORD_KEY.search(normalized))
    if not password_like and (values.is_number(literal) or values.is_word(literal)):
        return None
    if values.is_file_path(literal, path_hint=bool(_PATH_KEY.search(normalized))):
        return None
    if _SCHEME_PREFIX.match(literal):
        return None
    return literal


def _url_secret(url: str) -> str | None:
    """Ce qui rend une URL secrète : « an embedded password », « a secret 'token' parameter »."""
    url = url.strip()
    # Mot de passe : cherché partout (« jdbc:postgresql://user:pass@hôte » compris).
    if _has_url_password(url):
        return "an embedded password"
    if not _SCHEME_PREFIX.match(url):
        return None
    user_token = _URL_USER_TOKEN.match(url)
    if user_token and _secret_value("TOKEN", user_token.group(1)) is not None:
        return "an embedded token"  # https://ghp_…@github.com/…
    _, question_mark, query = url.partition("?")
    if not question_mark:
        return None
    for pair in query.split("#", 1)[0].split("&")[:_MAX_QUERY_PARAMETERS]:
        name, equals, value = pair.partition("=")
        if not equals:
            continue
        name, value = unquote(name), unquote(value)
        signed = bool(_SIGNATURE_KEY.search(_normalize_key(name)))
        if _secret_value(name, value, sensitive=signed) is not None:
            return f"a secret '{commands.shorten(name)}' parameter"
    return None


def _embedded_secrets(value: str) -> list[str]:
    """Clés secrètes d'un objet JSON écrit dans une valeur (« {"Authorization": "Bearer …"} »)."""
    text = value.strip()
    if not (text.startswith("{") and text.endswith("}")) or len(text) > _MAX_EMBEDDED_JSON:
        return []
    try:
        data = json.loads(text)
    except (ValueError, RecursionError):
        return []
    if not isinstance(data, dict):
        return []
    return [
        str(key)
        for key, item in data.items()
        if isinstance(item, str) and _secret_value(str(key), item) is not None
    ]


def _option_secret(flag: str, name: str, value: str) -> str | None:
    """Description (sans la valeur) d'un secret passé par une option, sinon None."""
    if flag in _HEADER_OPTIONS:
        header, colon, header_value = value.partition(":")
        if colon and _secret_value(header.strip(), header_value.strip()) is not None:
            return f"{flag} '{commands.shorten(header.strip())}: ****'"
        return None
    if flag in _ENV_OPTIONS:
        assignment = _ASSIGNMENT.fullmatch(value)
        if assignment and _secret_value(assignment.group(1), assignment.group(2)) is not None:
            return f"{flag} {commands.shorten(assignment.group(1))}=****"
        return None
    if _secret_value(name, value) is not None:
        return f"{commands.shorten(flag)} ****"
    return None


def _is_option_value(word: str) -> bool:
    """Le mot suivant est-il la valeur de l'option ? Un secret peut commencer par « - »
    (environ 3 % des jetons base64url), une option courte (« -v ») ou longue, non."""
    return not word.startswith("-") or (not word.startswith("--") and len(word) >= 16)


def _command_line_secrets(words: list[str]) -> list[str]:
    """Secrets écrits sur la ligne de commande : « --api-key valeur », « -e TOKEN=valeur »…

    Une ligne de commande se lit aussi dans la liste des processus (`ps`) : un secret
    n'y a pas sa place. Seules les options aux noms sensibles sont examinées.
    """
    found: list[str] = []
    index = 0
    while index < len(words):
        word = words[index]
        option = _OPTION.fullmatch(word)
        if option:
            flag = word.split("=", 1)[0]
            name, attached = option.group(1), option.group(2)
            if flag in _HEADER_OPTIONS or flag in _ENV_OPTIONS or _is_sensitive_name(name):
                following = words[index + 1] if index + 1 < len(words) else None
                if attached is not None:
                    value, used = attached, 1
                elif following is not None and _is_option_value(following):
                    value, used = following, 2
                else:
                    index += 1
                    continue
                description = _option_secret(flag, name, value)
                if description:
                    found.append(description)
                index += used
                continue
        else:
            assignment = _ASSIGNMENT.fullmatch(word)
            if assignment and _secret_value(assignment.group(1), assignment.group(2)) is not None:
                found.append(f"{commands.shorten(assignment.group(1))}=****")
        index += 1
    return found


def _command_line_urls(words: list[str]) -> list[tuple[str, str]]:
    """(URL, ce qui la rend secrète) pour chaque URL de la ligne de commande."""
    found: list[tuple[str, str]] = []
    for word in words:
        candidate = word.split("=", 1)[1] if word.startswith("-") and "=" in word else word
        where = _url_secret(candidate)
        if where:
            found.append((candidate, where))
    return found


def _tls_disabled_by_env(key: str, value: str) -> bool:
    """Variable d'environnement qui coupe la vérification des certificats TLS."""
    name = _normalize_key(key)
    setting = value.strip().lower()
    if name in _TLS_OFF_WHEN_ZERO:
        return setting == "0"
    if name in _TLS_INSECURE_HOSTS:
        return bool(setting)
    if _TLS_SKIP_NAME.search(name):
        return setting in _TRUE  # MCP_INSECURE=1, GIT_SSL_NO_VERIFY=true
    if _TLS_VERIFY_NAME.search(name):
        return setting in _FALSE  # SSL_VERIFY=false, NPM_CONFIG_STRICT_SSL=false
    return False


def _tls_disabled_by_options(words: list[str]) -> list[str]:
    """Options qui coupent la vérification TLS : --insecure, --strict-ssl=false…"""
    found: list[str] = []
    for index, word in enumerate(words):
        if not word.startswith("--"):
            continue
        flag, equals, value = word.partition("=")
        name = _normalize_key(flag[2:])
        negated = name.startswith("NO_")
        base = name[3:] if negated else name
        setting = value.strip().lower()
        if base in _TLS_INSECURE_HOSTS:
            if not negated:
                found.append(commands.shorten(flag))  # --allow-insecure-host, --trusted-host
        elif negated and _TLS_SKIP_NAME.search(base):
            continue  # --no-insecure : l'inverse, donc sûr
        elif _TLS_SKIP_NAME.search(name):
            if not equals or setting in _TRUE:
                found.append(commands.shorten(flag))  # --insecure, --skip-tls-verify
        elif _TLS_VERIFY_NAME.search(base):
            # --no-strict-ssl ; --strict-ssl=false ; --verify-ssl false
            following = words[index + 1] if index + 1 < len(words) else ""
            if negated or (setting if equals else following.strip().lower()) in _FALSE:
                found.append(commands.shorten(flag))
    return found


def _option_values(args: list[str], flags: set[str]) -> list[str]:
    """Valeurs d'une option, sous les formes « --flag valeur » et « --flag=valeur »."""
    values: list[str] = []
    for index, arg in enumerate(args):
        flag, sep, value = arg.partition("=")
        if flag not in flags:
            continue
        if sep:
            values.append(value)
        elif index + 1 < len(args):
            values.append(args[index + 1])
    return values


def _mount_source(spec: str) -> str:
    """Partie « source » d'un montage : '/:/host:ro' -> '/' ; 'C:\\data:/d' -> 'C:\\data'.

    Gère aussi la syntaxe --mount : 'type=bind,source=/,target=/host' -> '/'.
    """
    if "=" in spec and "," in spec or spec.startswith(("source=", "src=", "type=")):
        for part in spec.split(","):
            key, _, value = part.partition("=")
            if key.strip() in {"source", "src"}:
                return value.strip()
        return ""
    # Lettre de lecteur Windows (« C: ») : le premier « : » n'est pas un séparateur.
    if len(spec) >= 2 and spec[1] == ":" and spec[0].isalpha():
        return spec[:2] + spec[2:].split(":", 1)[0]
    return spec.split(":", 1)[0]


def _is_sensitive_mount(source: str) -> bool:
    normalized = _normalize_path(source)
    if _is_broad_path(normalized) or _CREDENTIAL_FOLDER.search(normalized.replace("\\", "/")):
        return True
    lowered = normalized.lower()
    if "docker.sock" in lowered or "docker_engine" in lowered:
        return True
    return any(
        normalized == root or normalized.startswith(root + "/") for root in _SENSITIVE_MOUNT_SOURCES
    )


def _container_issues(pairs: list[containers.Pair]) -> list[str]:
    """Liste lisible des options dangereuses d'un « docker run » / « podman run ».

    `pairs` : les options lues par containers.run_option_pairs (ou loose_option_pairs).
    """
    issues: list[str] = []
    if any(name == "--privileged" and value in _PFLAG_TRUE for name, value in pairs):
        issues.append("--privileged")
    if any(name in _HOST_NAMESPACE_FLAGS and value == "host" for name, value in pairs):
        issues.append("a host namespace (=host)")
    for name, value in pairs:
        if name in _MOUNT_FLAGS or name == "--mount":
            source = _mount_source(value)
            if source and _is_sensitive_mount(source):
                issues.append(f"a mount of '{source}'")
    for name, value in pairs:
        if name == "--cap-add" and value.upper().removeprefix("CAP_") in _DANGEROUS_CAPABILITIES:
            issues.append(f"--cap-add {value}")
    for name, value in pairs:
        if name == "--security-opt" and value.endswith(("=unconfined", ":unconfined")):
            issues.append(f"--security-opt {value}")
    return issues


def _package_flags(runner: str) -> set[str]:
    """uvx et pipx run (npx est lu par _npm_reading)."""
    return _PIPX_PACKAGE_FLAGS if runner == "pipx run" else _UV_PACKAGE_FLAGS


def _options_with_value(runner: str) -> set[str]:
    """uvx et pipx run (npx est lu par _npm_reading)."""
    return _PIPX_OPTIONS_WITH_VALUE if runner == "pipx run" else _UV_OPTIONS_WITH_VALUE


def _npm_reading(args: list[str]) -> tuple[list[str], list[str]]:
    """(valeurs de --package, commande lancée) d'un `npx …`, lus exactement comme npm 10.

    `pnpm dlx` et `bunx` sont lus de la même façon (voir npm_args.py). En mode shell
    (`-c "…"`, `--call`, `--shell-mode`), la commande est une ligne de shell, déjà
    signalée par CW101 : elle n'est pas lue comme un nom de paquet.
    """
    reading = parse_npx(args)
    return reading.packages, ([] if reading.shell_option() else reading.command)


def _is_local_path(package: str) -> bool:
    return bool(_LOCAL_PATH.match(package.strip()))


def _first_positional(runner: str, args: list[str]) -> str | None:
    """1er argument qui n'est ni une option, ni la valeur d'une option."""
    with_value = _options_with_value(runner)
    skip_next = False
    for arg in args:
        if skip_next:
            skip_next = False
        elif arg in with_value:
            skip_next = True
        elif not arg.startswith("-"):
            return arg
    return None


def _package_spec(runner: str, args: list[str]) -> str | None:
    """Le paquet lancé : valeur de --from / --package / -p, sinon 1er argument.

    Seules les options placées AVANT le paquet sont celles du lanceur : dans
    « npx srv@1.2.3 -p 3000 », « -p 3000 » est donné au serveur (revue du 20 octobre).
    """
    if runner in _NPM_LIKE_RUNNERS:
        packages, command = _npm_reading(args)
        return packages[0] if packages else (command[0] if command else None)
    explicit = _option_values(_options_before_package(runner, args), _package_flags(runner))
    return explicit[0] if explicit else _first_positional(runner, args)


def _untrusted_source(runner: str, args: list[str]) -> str | None:
    """Renvoie la source d'un paquet si elle est hors registre officiel (git, URL…).

    On ne regarde que les paquets installés, pas les arguments transmis au serveur :
    un serveur « fetch » peut légitimement recevoir une URL. Un registre privé
    (--registry, --index-url) n'est pas un paquet et n'est pas signalé ici.
    """
    if runner in _NPM_LIKE_RUNNERS:
        packages, command = _npm_reading(args)
        candidates = [*packages, *command[:1]]
    else:
        options = _options_before_package(runner, args)
        candidates = _option_values(options, _package_flags(runner) | _EXTRA_PACKAGE_FLAGS)
        first = _first_positional(runner, args)
        if first:
            candidates.append(first)
    for value in candidates:
        source = _source_outside_registry(runner, value)
        if source:
            return source
    return None


def _source_outside_registry(runner: str, value: str) -> str | None:
    """L'adresse d'où vient le paquet s'il ne vient pas du registre officiel."""
    if value.lower().startswith(_UNTRUSTED_SOURCE_PREFIXES):
        return value
    pep508 = _PEP508_URL.fullmatch(value)
    if pep508 and pep508.group(1).lower().startswith(_UNTRUSTED_SOURCE_PREFIXES):
        return pep508.group(1)
    scp = _SCP_GIT.fullmatch(value)
    if scp and scp.group(1).lower() != "npm":  # « alias@npm:paquet » reste le registre
        return value.split("@", 1)[1]  # sans la partie « utilisateur@ »
    is_archive = value.lower().endswith((".tgz", ".tar.gz", ".tar"))
    if runner not in _PYTHON_RUNNERS and _GITHUB_SHORTHAND.fullmatch(value) and not is_archive:
        return value
    return None


def _options_before_package(runner: str, args: list[str]) -> list[str]:
    """Les options du lanceur : ce qui précède le paquet (après, ce sont celles du serveur)."""
    with_value = _options_with_value(runner)
    index = 0
    while index < len(args):
        arg = args[index]
        if arg == "--":
            break
        if arg.split("=", 1)[0] in with_value and "=" not in arg:
            index += 2
        elif arg.startswith("-"):
            index += 1
        else:
            break
    return args[:index]


def _split_requirements(value: str) -> list[str]:
    """Comme uv : « a==1,b » -> ['a==1', 'b'] ; « pkg>=1,<2 » et « pkg[a,b] » restent entiers."""
    parts: list[str] = []
    depth = start = 0
    for index, character in enumerate(value):
        if character == "[":
            depth += 1
        elif character == "]":
            depth = max(0, depth - 1)
        elif character == "," and depth == 0:
            following = _NEXT_CHARACTER.match(value, index + 1)
            if following and following.group(1) in _VERSION_OPERATORS:
                continue  # « >=1,<2 » : une seule plage de versions
            parts.append(value[start:index])
            start = index + 1
    parts.append(value[start:])
    return [part.strip() for part in parts if part.strip()]


def _extra_packages(runner: str, args: list[str]) -> list[str]:
    """Paquets installés en plus du serveur : `uvx --with`, et `npx -p` après le 1er."""
    if runner == "uvx":
        values = _option_values(_options_before_package(runner, args), {"--with"})
    elif runner in _NPM_LIKE_RUNNERS:
        values = _npm_reading(args)[0][1:]
    else:
        return []
    return [package for value in values for package in _split_requirements(value)]


def _is_unpinned_registry_package(runner: str, package: str) -> bool:
    """Paquet du registre sans version exacte (un chemin local ou une URL ne compte pas)."""
    if not package or _is_local_path(package) or package.lower().endswith(".whl"):
        return False
    # « mcp[cli] » est un vrai paquet : ses extras ne doivent pas passer pour un modèle.
    name = _PYTHON_EXTRAS.sub("", package, count=1) if runner in _PYTHON_RUNNERS else package
    if "$" in package or values.is_placeholder(name):
        return False  # variable (« ${DB_DRIVER} ») ou modèle à remplir : rien à figer ici
    if _source_outside_registry(runner, package) is not None:
        return False  # source non vérifiée : déjà signalée par CW107
    return not _package_is_pinned(runner, package)


def _http_host(url: str) -> str | None:
    """Hôte d'une URL en http:// ('' si illisible), ou None si l'URL n'est pas en http://."""
    url = url.strip()
    if not url.lower().startswith("http://"):
        return None
    try:
        return urlparse(url).hostname or ""
    except ValueError:
        # Sécurité : URL malformée (peut-être exprès). On la signale quand même, sans
        # recopier l'URL ni le message d'erreur : ils peuvent contenir un mot de passe.
        return ""


def _configured_value(value: str) -> str | None:
    """La valeur réellement utilisée : None si vide ou simple référence (« ${VAR} »).

    Contrairement aux secrets (CW103), les modèles à remplir ne sont PAS écartés ici : un
    mot comme « example » dans une adresse ou un chemin ne doit pas suffire à cacher un
    registre remplacé ou du code chargé en plus. La valeur par défaut de « ${VAR:-…} »
    est celle qui s'appliquera.
    """
    candidate = value.strip()
    for _ in range(20):  # ${A:-${B:-…}} : on descend, mais jamais indéfiniment
        defaulted = _DEFAULTED_REFERENCE.fullmatch(candidate)
        if defaulted is None:
            break
        candidate = defaulted.group(1).strip()
    if not candidate or _ENV_REFERENCE.fullmatch(candidate):
        return None
    return candidate


def _code_injection(
    name: str, value: str, variables: dict[str, list[str]] | None = None
) -> str | None:
    """Ce que fait la variable `name` si elle fait charger du code en plus, sinon None.

    `variables` : HOME et PATH posés en même temps (bloc « env » et ligne de commande)."""
    if name in _PRELOAD_VARIABLES:
        return _PRELOAD_VARIABLES[name] + f" ({name})"
    if name in _NODE_OPTIONS_VARIABLES:
        # Guillemets retirés : « NODE_OPTIONS='--require x' » écrit dans une ligne de commande.
        options = [
            word.strip("'\"").split("=", 1)[0] for word in value.split()[:_MAX_QUERY_PARAMETERS]
        ]
        for option in options:
            if option in _NODE_CODE_OPTIONS:
                return f"loads extra code ('{option}')"
        for option in options:
            if option in _NODE_DEBUG_OPTIONS:
                return f"opens a debugger port: anyone who reaches it runs code ('{option}')"
        return None
    if name in _JAVA_OPTIONS_VARIABLES:
        agent = _JAVA_AGENT.search(value)
        return f"loads a Java agent ('{agent.group(1)}')" if agent else None
    if name == "PERL5OPT":
        module = _PERL_MODULE.search(value)
        return f"loads a Perl module ('-{module.group(1)}')" if module else None
    if name == "RUBYOPT":
        return "loads a Ruby library ('-r')" if _RUBY_REQUIRE.search(value) else None
    if name == "GIT_SSH_COMMAND":
        return _git_ssh_issue(value, variables or {})
    if name == "GIT_SSH":
        return _git_ssh_program_issue(value, variables or {})
    return None


def _on_windows() -> bool:
    """Le scanner tourne-t-il sous Windows ? Un chemin à lecteur (« C:/Windows/ssh ») n'y est un
    chemin absolu que là : sous Linux et macOS, « C: » est un dossier du projet (revue de
    l'Auditeur, 5e passe). Le résultat dépend donc du système qui lit la configuration."""
    return sys.platform == "win32"


def _pure_reference(text: str) -> str | None:
    """Nom en majuscules de la variable, si `text` n'est qu'une référence à une variable."""
    match = _PLAIN_REFERENCE.fullmatch(text)
    return match.group(match.lastgroup).upper() if match and match.lastgroup else None


class _Variables(dict):
    """Les variables posées ensemble (nom en majuscules -> valeurs) et ce qu'il reste de budget de
    lecture pour ce serveur : un fichier qui multiplie les références ne peut pas ralentir le scan
    (revue de l'Auditeur, 6e passe)."""

    def __init__(self, *args: object) -> None:
        super().__init__(*args)  # type: ignore[arg-type]
        self.reading = _MAX_READING

    def charge(self, size: int) -> bool:
        """Compte `size` caractères relus ; False quand le budget est épuisé."""
        self.reading -= size
        return self.reading >= 0


def _environment_variables(
    env_block: object = None, assignments: Iterable[tuple[str, str]] = ()
) -> _Variables:
    """Les variables posées ensemble : nom en majuscules -> valeurs. Viennent du bloc « env »
    (ignoré s'il n'est pas un dict) et de la ligne de commande. Une variable qui ne fait que se
    transmettre (« HOME=${HOME} ») n'est pas redéfinie."""
    pairs = list(env_block.items()) if isinstance(env_block, dict) else []
    pairs.extend(assignments)
    found = _Variables()
    for key, value in pairs:
        name = str(key).strip().upper()
        if isinstance(value, str) and _pure_reference(value) != name:
            found.setdefault(name, []).append(value)
    return found


def _names_of(match: re.Match[str], whole: bool) -> tuple[str, ...]:
    """Le nom de variable (en majuscules) qu'une référence désigne. « ${a-b} » est la variable
    « a-b » pour npm (`whole`), « a » (valeur par défaut « b ») pour un shell ou Claude Code."""
    group = match.group("g")
    if group is None:
        return (match.group(match.lastgroup).upper(),) if match.lastgroup else ()
    inner = group.strip()
    if inner[:4].lower() == "env:":
        inner = inner[4:].strip()
    if whole:
        return (inner.upper(),)
    head = _BRACED_NAME.match(inner)
    return (head.group(0).upper(),) if head else ()


def _known_expansions(value: str, variables: _Variables, own: str) -> tuple[list[str], bool]:
    """`value` avec ses références à des variables posées ailleurs dans le même environnement
    remplacées par leur valeur (npm développe lui-même « ${X} » dans ses réglages ; un shell,
    « $X »), partout où elles apparaissent. Renvoie les textes obtenus et si tout a pu être lu :
    au-delà des limites (trop de définitions, de références imbriquées ou de texte), on ne sait
    pas, et l'appelant le dit. Les deux lectures de « ${a-b} » (voir `_names_of`) sont suivies,
    chacune pour toutes les références du texte."""
    found: list[str] = []
    complete = True
    if "$" not in value and "%" not in value:
        return found, complete  # aucune référence à suivre
    if len(value) > _MAX_EXPANDED_LENGTH:
        return found, False

    def walk(text: str, chain: tuple[str, ...], whole: bool) -> None:
        nonlocal complete
        if not variables.charge(len(text)):
            complete = False
            return
        for match in _REFERENCE_IN_TEXT.finditer(text):
            names = _names_of(match, whole)
            # Soi-même : le réglage de l'utilisateur. Déjà remplacée plusieurs fois le long de ce
            # chemin : une boucle (A=${B}, B=${A}). Une fois ne suffit pas : « $a${a-b} » remplace
            # « a », puis la définition de « a-b » en cite encore.
            if not names or names[0] == own or names[0] not in variables:
                continue
            if chain.count(names[0]) >= _MAX_REPEAT:
                continue
            name = names[0]
            if len(chain) >= _MAX_REFERENCE_DEPTH or len(variables[name]) > _MAX_DEFINITIONS:
                complete = False
                return
            for definition in variables[name]:
                expanded = _REFERENCE_IN_TEXT.sub(
                    lambda m, d=definition, n=name: (
                        d if _names_of(m, whole) == (n,) else m.group(0)
                    ),
                    text,
                )
                if len(found) >= _MAX_EXPANSIONS or len(expanded) > _MAX_EXPANDED_LENGTH:
                    complete = False
                    return
                found.append(expanded)
                walk(expanded, (*chain, name), whole)  # les références suivantes
            return

    walk(value, (), True)
    walk(value, (), False)
    return found, complete


def _is_system_location(path: str, *, home_known: bool = True) -> bool:
    """Le chemin est-il dans un dossier du système ou dans un dossier d'outils de l'utilisateur
    (caché ou « bin » ; sous « ~ » et « $HOME » seulement si HOME n'est pas redéfini) ? Jamais
    avec « .. » : on peut en sortir. Pas « ~/projet » : le projet y est cloné par défaut.

    `path` est le nom exact, tel que le programme le reçoit : rien n'est « nettoyé ». Le shell ne
    retire ni espace, ni guillemet, ni espace insécable : « " /usr/bin/ssh" » est un dossier « »
    (une espace) du projet (Auditeur, 7e passe). Tous les chemins de confiance commencent par « / »,
    « ~ », « $ » ou une lettre de disque : ce qui précède les écarte déjà ; la fin est vérifiée.

    « .. » se cherche dans le chemin tel qu'il est écrit, puis sans barres obliques inverses ni
    guillemets : une ligne qui contient une barre oblique inverse garde le mot tel quel (chemin
    Windows), mais un shell les retire, et « .\\. » ou « ..'' » y sont « .. » (revue de l'Auditeur,
    10e passe). Retirer plus que le shell ne retire peut signaler à tort, jamais rater un « .. »."""
    if path != path.strip():
        return False
    for written in (path, re.sub(r"""[\\'"]""", "", path)):
        if ".." in re.split(r"[\\/]", written):
            return False
    probe = path.rstrip("/") + "/"
    if probe.startswith(_SYSTEM_PREFIXES) or _USER_TOOLS.match(probe):
        return True
    # Un « : » après la lettre du disque n'existe pas dans un chemin Windows.
    windows_path = _SYSTEM_WINDOWS.match(path) or _USER_TOOLS_WINDOWS.match(path)
    if _on_windows() and ":" not in path[2:] and windows_path:
        return True
    return home_known and _HOME_TOOLS.match(probe) is not None


def _path_is_system(path_value: str) -> bool:
    """Tous les dossiers de ce PATH sont-ils sûrs ? Une entrée vide, c'est le dossier courant.
    « $PATH » (la liste d'origine) est écarté. « ~ » et « $HOME » n'y sont pas développés (ni par
    le client qui transmet l'environnement, ni par la recherche d'un programme) : « ~/bin » est un
    dossier « ~ » du projet (revue de l'Auditeur, 6e passe)."""
    separator = ":"
    # Windows sépare par « ; » (et ses lettres de disque contiennent « : »), les autres par « : ».
    if _on_windows() and (";" in path_value or re.match(r'"?[A-Za-z]:[\\/]', path_value)):
        separator = ";"
    for entry in path_value.split(separator):
        # Sous Windows seulement, un dossier peut être entre guillemets (« "C:\Program Files\x" »).
        # Ailleurs, comme partout, une espace ou un guillemet fait partie du nom du dossier.
        if _on_windows() and len(entry) >= 2 and entry[0] == entry[-1] == '"':
            entry = entry[1:-1]
        if entry in _PATH_SELF:
            continue
        if not _is_system_location(entry, home_known=False):  # entrée vide : dossier courant
            return False
    return True


def _ssh_option_arguments(words: list[str]) -> Iterator[tuple[str, str]]:
    """(lettre, argument) des options -o, -I et -F de ssh, comme getopt les lit : « -o A=b »,
    « -oA=b », « -vo A=b » (lettres groupées), « -I bibliothèque » et « -F fichier »."""
    index = 1
    while index < len(words):
        word = words[index]
        index += 1
        if len(word) < 2 or word[0] != "-" or word[1] == "-":
            continue
        for position, letter in enumerate(word[1:], start=1):
            if letter in "oIF":
                rest = word[position + 1 :]
                if rest:
                    yield letter, rest
                elif index < len(words):
                    yield letter, words[index]
                    index += 1
                break
            if letter in _SSH_LETTERS_WITH_ARGUMENT:
                index += 0 if word[position + 1 :] else 1  # l'argument est le mot suivant
                break


def _ssh_program_option(letter: str, argument: str) -> str | None:
    """Nom de l'option (`-o`, `-I`) qui lance un programme ou charge une bibliothèque."""
    if letter == "I":  # -I : bibliothèque PKCS#11
        key, rest = "pkcs11provider", argument
    else:
        # ssh sépare le nom de la valeur par « = » ou par n'importe quelle espace.
        parts = re.split(r"[\s=]+", argument.strip(), maxsplit=1)
        key, rest = parts[0], (parts[1] if len(parts) > 1 else "")
    option = _SSH_PROGRAM_OPTIONS.get(key.lower())
    if option and rest.strip().lower() not in _SSH_OFF_VALUES.get(option, ()):
        return option
    return None


def _ssh_command_option(value: str, *, home_known: bool = True) -> str | None:
    """Ce que fait une option de ssh qui lance un programme, charge une bibliothèque ou lit un
    fichier de configuration (« -F ») du projet ; None sinon."""
    words = commands.split_words(value)
    for word in words[1:]:
        if word.lower() == "-proxycmd":  # plink (PuTTY)
            return "makes git's ssh run another program ('-proxycmd', GIT_SSH_COMMAND)"
    for letter, argument in _ssh_option_arguments(words):
        if letter == "F":
            # « -F /dev/null » : ssh ne lit aucun fichier de configuration. Le fichier d'un
            # dépôt, lui, peut contenir « ProxyCommand ».
            if argument != "/dev/null" and not _is_system_location(argument, home_known=home_known):
                return (
                    "makes git's ssh read a configuration file that may come from the "
                    "project ('-F', GIT_SSH_COMMAND)"
                )
        else:
            option = _ssh_program_option(letter, argument)
            if option:
                return f"makes git's ssh run another program ('{option}', GIT_SSH_COMMAND)"
    return None


def _is_plain_ssh(
    word: str, variables: dict[str, list[str]], home_known: bool, windows_line: bool
) -> bool:
    """« ssh », « plink » ou leur chemin dans un dossier du système : pas un « ./ssh », un
    « bin/ssh » du projet, ni un faux chemin absolu (« /proc/self/cwd/ssh », « C:/ssh »).

    `word` : le premier mot de `commands.program_word`. Dans une ligne qui contient une barre
    oblique inverse (`windows_line`), ce mot garde ses guillemets, qu'on retire une fois ; sinon ils
    sont déjà retirés, et un guillemet restant fait partie du nom. Le nom n'est jamais « nettoyé » :
    une espace devant ou derrière, une espace insécable ou un guillemet en font un autre fichier."""
    if windows_line and len(word) >= 2 and word[0] == word[-1] and word[0] in "\"'":
        word = word[1:-1]
    if word != word.strip() or word[:1] in ('"', "'"):
        return False
    if commands.executable_name(word) not in {"ssh", "plink"}:
        return False
    if "/" not in word and "\\" not in word:
        # Nom seul : cherché dans le PATH. Un PATH posé avec le serveur peut y mettre le projet.
        return all(_path_is_system(path) for path in variables.get("PATH", ()))
    return _is_system_location(word, home_known=home_known)


def _git_ssh_issue(value: str, variables: dict[str, list[str]]) -> str | None:
    """GIT_SSH_COMMAND : « ssh -i clé » est normal ; une ligne trop longue pour être lue, une
    variable posée devant ssh, un autre programme (ou un « ./ssh » du projet), du shell ou une
    option qui lance un programme ne le sont pas. `variables` : HOME et PATH posés avec elle."""
    if value.lstrip(" \t\n")[:1].isspace():
        # Le shell ne saute que l'espace, la tabulation et le saut de ligne. Toute autre espace
        # (insécable, cadratin, retour chariot…) commence le nom du programme, alors que
        # `commands.program_word` la retire (revue de l'Auditeur, 7e passe).
        return "makes git run a program whose name starts with an unusual space (GIT_SSH_COMMAND)"
    if commands.starts_with_assignment(value):
        # « LD_PRELOAD=./x.so ssh » : la variable s'applique à ssh (revue de l'Auditeur). Même
        # seule, git lui ajoute l'hôte : « A=1 hôte » lance « hôte ».
        return "makes git run ssh with variables set in front of it (GIT_SSH_COMMAND)"
    word = commands.program_word(value)
    if word is None:
        return None
    if len(value) > _SSH_LINE_LIMIT or len(commands.split_words(value)) > _MAX_QUERY_PARAMETERS:
        # Ce qui dépasse la limite n'est pas lu : ne pas répondre « rien à signaler ».
        return "makes git run a command line too long to be read (GIT_SSH_COMMAND)"
    program = _program(value)
    # HOME n'est connu que s'il n'est pas redéfini avec la commande. Toute autre variable
    # (« $OPTS ») peut contenir des options ou des mots, et « $IFS » les couper.
    home_known = "HOME" not in variables and not _UNEXPANDED_HOME.search(value)
    text = _HOME_REFERENCE.sub("", value) if home_known else value
    if _SHELL_CHARACTERS & set(text):
        return f"makes git run '{program}' through a shell (GIT_SSH_COMMAND)"
    if not _is_plain_ssh(word, variables, home_known, windows_line="\\" in value):
        if commands.executable_name(word.strip("\"'")) in {"ssh", "plink"}:
            return (
                f"makes git run '{program}' from the project instead of the system "
                "(GIT_SSH_COMMAND)"
            )
        return f"makes git run '{program}' through a shell (GIT_SSH_COMMAND)"
    option = _ssh_command_option(value, home_known=home_known)
    if option:
        return option
    if _UNUSUAL_SPACE.search(value):
        # Même après le premier mot : « -F\r/etc/ssh/ssh_config » est un seul mot pour le shell
        # (un fichier du projet), deux pour l'analyse (revue de l'Auditeur, 8e passe).
        return (
            "has a space the shell does not split on, so the program git runs may not be "
            "the one read (GIT_SSH_COMMAND)"
        )
    return None


def _git_ssh_program_issue(value: str, variables: dict[str, list[str]]) -> str | None:
    """GIT_SSH : le programme que git lance à la place de ssh, sans shell et sans options. La valeur
    entière est le nom du fichier (« ssh -i clé » en est un autre, introuvable). Seul « ssh » ou
    « plink » du système est sûr ; « ./p/ssh » fait exécuter le fichier du projet, comme
    GIT_SSH_COMMAND. Ni « ~ » ni « $HOME » n'y sont développés (un chemin « ~/bin/ssh » est un
    dossier « ~ » du projet), donc HOME n'est jamais « connu » (revue de l'Auditeur, 10e passe)."""
    if _is_plain_ssh(value, variables, home_known=False, windows_line=False):
        return None
    program = _program(value) or commands.UNKNOWN_PROGRAM
    return f"makes git run '{program}' instead of the system's ssh (GIT_SSH)"


def _foreign_registry(value: str) -> str | None:
    """L'origine (« https://hôte/… ») du 1er index qui n'est ni officiel ni local, sinon None."""
    for entry in value.split()[:_MAX_INDEX_ENTRIES]:
        # « UV_INDEX=nom=https://… » : le nom de l'index précède l'adresse.
        _, equals, address = entry.partition("=")
        candidate = address if equals and "://" not in entry.split("=", 1)[0] else entry
        if not candidate or _configured_value(candidate) is None or _is_local_path(candidate):
            continue
        if "://" not in candidate:
            continue  # ni adresse ni chemin reconnu : pip et uv la refuseraient
        try:
            host = (urlparse(candidate).hostname or "").lower()
        except ValueError:
            return url_origin(candidate)  # une adresse qui ne se lit pas a au moins un schéma
        if host in _OFFICIAL_REGISTRIES or host in _LOCAL_HOSTS:
            continue
        return _registry_origin(candidate)
    return None


def _registry_origin(address: str) -> str:
    """L'origine d'une adresse de registre pour un message. Quand son schéma n'est pas lisible
    (« ${S}://u:mdp@hôte », « 1https:// »), on ne sait pas où sont les identifiants : on n'en
    garde rien (revue de l'Auditeur, 6e passe)."""
    if _URL_SCHEME.match(address):
        return url_origin(address)
    return "…"


def _shell_read_value(name: str, value: str) -> str | None:
    """La valeur d'une variable que le shell développe (GIT_SSH_COMMAND, BASH_ENV) : None si vide
    ou si elle ne fait que transmettre le réglage de l'utilisateur (« ${GIT_SSH_COMMAND} »,
    « ${GIT_SSH_COMMAND:-ssh -i clé} »). « $X », lui, désigne une autre variable.

    Seul le shell de GIT_SSH_COMMAND saute l'espace et la tabulation du début et de la fin. Pour
    BASH_ENV, la valeur est le nom d'un fichier, espaces comprises : « " " » en est un (revue de
    l'Auditeur, 7e passe)."""
    blanks = " \t" if name == "GIT_SSH_COMMAND" else ""
    candidate = value.strip(blanks)
    for _ in range(20):  # ${A:-${A:-…}} : on descend, mais jamais indéfiniment
        defaulted = _DEFAULTED_NAME.fullmatch(candidate)
        if defaulted is None or defaulted.group("name").upper() != name:
            break
        candidate = defaulted.group("default").strip(blanks)
    if not candidate or _pure_reference(candidate) == name:
        return None
    return candidate


def _with_defaults(text: str, variables: _Variables) -> tuple[str, bool]:
    """`text` où chaque « ${X:-défaut} » (et « ${X-…} », « ${X:=…} », « ${X=…} », « ${X:+…} ») est
    remplacé par son défaut : ce que lit un client quand X est absente ou vide (ou, pour « + »,
    définie), à n'importe quelle place du texte. La vraie valeur de X, si le bloc la pose, est
    suivie par `_known_expansions`. Les défauts emboîtés se lisent de l'intérieur ; au-delà de
    `_MAX_REFERENCE_DEPTH` niveaux, ou du budget de lecture, on ne sait pas : le second résultat
    est alors False et l'appelant le dit."""
    for _ in range(_MAX_REFERENCE_DEPTH):
        replaced = _DEFAULT_IN_TEXT.sub(r"\1", text)
        if replaced == text:
            return text, True
        if not variables.charge(len(replaced)):
            return text, False
        text = replaced
    return text, _DEFAULT_IN_TEXT.search(text) is None


def _client_default(match: re.Match[str]) -> str:
    # `contenu.split(":-", 2)` de Claude Code : le défaut est le 2e morceau, pas tout le reste.
    parts = match.group(1).split(":-", 2)
    return parts[1] if len(parts) > 1 else match.group(0)


def _client_reading(text: str, variables: _Variables) -> tuple[str, bool]:
    """`text` comme Claude Code le lit quand ses variables sont absentes : chaque « ${nom:-défaut} »
    devient « défaut », en une seule passe. Contrairement à un shell, le nom n'a pas de forme
    imposée (« ${a.b:-r} », « ${1:-r} », « ${:-r} ») ; le contenu va jusqu'à la première « } »
    (« ${${:-r} » lit « r ») et le défaut s'arrête à un deuxième « :- » (« ${U:-r:-z} » lit « r »).
    Le second résultat est False quand le budget de lecture est épuisé (revue de l'Auditeur,
    8e passe).

    Rien ne peut correspondre après la dernière « } » : ce reste est mis de côté, sinon un texte
    fait de « ${ » sans fin obligerait à le relire depuis chaque « ${ » (temps quadratique)."""
    if ":-" not in text:
        return text, True
    end = text.rfind("}") + 1
    read = _CLIENT_REFERENCE.sub(_client_default, text[:end]) + text[end:]
    if not variables.charge(len(read)):
        return text, False
    return read, True


_MAX_VIEW_DEPTH = 8  # imbrication lue dans un serveur (listes et objets) pour `_client_view`


def _client_view(server: dict) -> dict | None:
    """Le serveur tel que Claude Code le lit quand ses variables sont absentes : « ${A:-bash} » dans
    `command`, `args`, `url`, `headers`, `env`… devient « bash ». Une copie ; None si rien ne
    change. Les noms de champ ne sont pas lus, ni ce qui est plus profond que `_MAX_VIEW_DEPTH`
    (laissé tel quel). Chaque texte a son propre budget de lecture (revue de l'Auditeur, 9e
    passe)."""
    changed = False

    def read(value: object, depth: int) -> object:
        nonlocal changed
        if isinstance(value, str):
            text, _ = _client_reading(value, _Variables())
            changed = changed or text != value
            return text
        if depth >= _MAX_VIEW_DEPTH:
            return value
        if isinstance(value, list):
            return [read(item, depth + 1) for item in value]
        if isinstance(value, dict):
            return {key: read(item, depth + 1) for key, item in value.items()}
        return value

    view = read(server, 0)
    return view if changed and isinstance(view, dict) else None


# Ce qui, dans un message, vient de la valeur lue : un texte entre apostrophes (nom, origine,
# option) et la valeur masquée « (sk-a****…(40 chars)) ».
_VALUE_FRAGMENT = re.compile(r"'[^']*'|\([^()]{0,4}\*{4}(?:…\(\d+ chars\))?\)")


def _same_finding(finding: Finding) -> tuple[str, str]:
    """Deux constats de la même règle qui ne diffèrent que par ce qui vient de la valeur lue sont le
    même : le serveur d'origine et sa lecture par Claude Code disent « 'https://…' » et
    « 'https://hôte/…' » du même registre, ou masquent deux fois le même secret."""
    return finding.rule.id, _VALUE_FRAGMENT.sub("", finding.message)


def _environment_issue(
    key: str, value: str, variables: dict[str, list[str]] | None = None
) -> str | None:
    """CW112 : ce que change la variable `key` (texte du message, sans sa valeur), sinon None.

    `variables` : les variables posées en même temps (voir `_environment_variables`). Une
    référence à l'une d'elles (« ${X} ») est remplacée par sa valeur avant l'analyse."""
    if not isinstance(variables, _Variables):
        variables = _Variables(variables or {})
    name = key.strip().upper()
    if name in _SHELL_READ_VARIABLES:
        return _issue_of_value(name, _shell_read_value(name, value), variables)
    if not _is_checked_variable(name):
        return None  # inutile de développer les références d'une variable que CW112 ignore
    expansions, complete = _known_expansions(value, variables, name)
    # Claude Code lit le texte d'abord ; npm ou le shell développent ensuite ce qui en sort avec les
    # variables du même bloc : « $${a.b:-{}REG} » devient « ${REG} », puis la valeur de REG (revue
    # de l'Auditeur, 9e passe). Les lectures déjà faites ne sont pas comptées deux fois.
    clients = {value: _client_reading(value, variables)}
    first = clients[value][0]
    complete = complete and clients[value][1]
    if first != value:
        further, further_complete = _known_expansions(first, variables, name)
        expansions = [first, *expansions, *further]
        complete = complete and further_complete
    for text in dict.fromkeys((value, *expansions)):
        # Le texte tel quel, puis tel que le lit un client quand ses variables sont absentes :
        # « -${U:-r} » lit « -r » (revue de l'Auditeur, 7e passe).
        defaulted, readable = _with_defaults(text, variables)
        if text not in clients:
            clients[text] = _client_reading(text, variables)
        client, client_readable = clients[text]
        complete = complete and readable and client_readable
        for reading in dict.fromkeys((text, defaulted, client)):
            issue = _issue_of_value(name, _configured_value(reading), variables)
            if issue:
                return issue
            if "$" in reading or "%" in reading:
                # Une référence à une variable inconnue peut être vide : « ${X}--require ./h.js »
                # lit « --require ./h.js » quand X n'existe pas (revue de ma propre simulation
                # de npm).
                issue = _issue_of_value(
                    name, _configured_value(_REFERENCE_IN_TEXT.sub("", reading)), variables
                )
                if issue:
                    return issue
    if not complete:
        return "has references to other variables that are too many or too deep to be read"
    return None


def _is_checked_variable(name: str) -> bool:
    """CW112 regarde-t-elle la valeur de cette variable (en majuscules) ?"""
    return (
        name in _PRELOAD_VARIABLES
        or name in _NODE_OPTIONS_VARIABLES
        or name in _JAVA_OPTIONS_VARIABLES
        or name in _REGISTRY_VARIABLES
        or name in {"PERL5OPT", "RUBYOPT", "NPM_CONFIG_PACKAGE"}
        or _NPM_SCOPED_REGISTRY.fullmatch(name) is not None
    )


def _issue_of_value(name: str, literal: str | None, variables: dict[str, list[str]]) -> str | None:
    if literal is None:
        return None  # vide, ou simple référence (« ${NODE_OPTIONS} »)
    injected = _code_injection(name, literal, variables)
    if injected:
        return injected
    if name in _REGISTRY_VARIABLES or _NPM_SCOPED_REGISTRY.fullmatch(name):
        origin = _foreign_registry(literal)
        if origin:
            return f"takes its packages from '{origin}' instead of the official registry"
        return None
    if name == "NPM_CONFIG_PACKAGE":
        return "installs extra packages through npm_config_package"
    return None


def _launcher_indexes(runner: str, args: list[str]) -> list[str]:
    """Registres ou index donnés au lanceur lui-même (« npx --registry », « uvx -i »)."""
    if runner in _NPM_LIKE_RUNNERS:
        return [address for _, address in parse_npx(args).registries]
    options = _options_before_package(runner, args)
    return _option_values(options, _PYTHON_INDEX_OPTIONS)


def _check_server(name: str, server: dict, line: int, path: str) -> list[Finding]:
    findings: list[Finding] = []
    command = server.get("command")
    raw_args = server.get("args")
    args = [a for a in raw_args if isinstance(a, str)] if isinstance(raw_args, list) else []

    reported: set[tuple[str, str]] = set()
    env_block = server.get("env")
    # HOME et PATH posés avec le serveur changent le sens de « ssh » et de « ~ » (CW112).
    variables = _environment_variables(env_block)
    # « npm_config_call » : npm (npx, npm exec, et tout npm lancé par le serveur) exécute
    # cette ligne dans un shell, comme « npx -c ». Une valeur vide est ignorée par npm.
    npm_call_key = (
        next(
            (
                str(key)
                for key, value in env_block.items()
                if _NPM_CONFIG_CALL_KEY.fullmatch(str(key))
                and isinstance(value, str)
                and value.strip()
            ),
            None,
        )
        if isinstance(env_block, dict)
        else None
    )

    def add(rule: Rule, message: str) -> None:
        # Une seule fois par message : 70 000 « --insecure » ne font pas 70 000 alertes.
        if (rule.id, message) in reported:
            return
        reported.add((rule.id, message))
        findings.append(Finding(rule=rule, path=path, line=line, message=message))

    if isinstance(command, str) and command.strip():
        # Les enveloppes (cmd /c, wsl, env, sudo, uv run, bash -c…) sont retirées : on
        # vérifie le programme vraiment lancé, et on relève au passage les risques CW101.
        launch = commands.analyse(command, args)
        variables = _environment_variables(env_block, launch.assignments)

        # CW101 : shell, ligne de commande ou code en ligne (une seule alerte par serveur)
        risks = launch.risks or (
            [f"executes a command line through 'npm_config_call' (env.{npm_call_key})"]
            if npm_call_key
            else []
        )
        if risks:
            add(SHELL_EXECUTION, f"Server '{name}' {risks[0]}.")

        # CW112 : variables posées sur la ligne de commande (« env A=1 », « export A=1 »…)
        # et index de paquets de « uv run ».
        for key, value in launch.assignments:
            issue = _environment_issue(key, value, variables)
            if issue:
                add(UNSAFE_ENVIRONMENT, f"Server '{name}' {issue} (on its command line).")
        for index in launch.indexes:
            origin = _foreign_registry(index)
            if origin:
                add(
                    UNSAFE_ENVIRONMENT,
                    f"Server '{name}' takes its packages from '{origin}' instead of the "
                    "official registry (on its command line).",
                )

        # CW100 : script trop long ou trop imbriqué ; ce qui suit n'a pas été lu.
        if launch.truncated:
            add(
                INVALID_CONFIG,
                f"Server '{name}' chains too many commands or nested scripts: they could not "
                "all be checked.",
            )

        # CW107 : paquets ajoutés par l'enveloppe (« uv run --with git+https://… »)
        for extra in launch.sources:
            extra_source = _source_outside_registry("uvx", extra)
            if extra_source:
                add(
                    UNTRUSTED_PACKAGE_SOURCE,
                    f"Server '{name}' installs its code from '{url_origin(extra_source)}' "
                    "instead of a registry.",
                )
                break
        # CW102 : paquets du registre ajoutés par l'enveloppe, sans version exacte
        for extra in launch.sources:
            for package in _split_requirements(extra):
                if _is_unpinned_registry_package("uvx", package):
                    add(
                        UNPINNED_PACKAGE,
                        f"Server '{name}' also installs '{redact_url(package)}' "
                        "without a pinned version.",
                    )

        # Chaque commande lancée : la 1re, puis celles qui la suivent dans un script
        # (« bash -c "cd x && npx …" »), enveloppes retirées.
        for launched in launch.commands:
            exe, args = commands.executable_name(launched[0]), launched[1:]
            if exe in _PACKAGE_RUNNERS:
                # CW107 : paquet hors registre (git, URL…). Plus grave qu'CW102, qu'on ne
                # signale pas en plus pour éviter deux alertes sur la même ligne.
                source = _untrusted_source(exe, args)
                if source:
                    # Seulement « schéma://hôte/… » : le chemin ou les paramètres d'une URL
                    # peuvent contenir un jeton, même sans « user:token@ ».
                    add(
                        UNTRUSTED_PACKAGE_SOURCE,
                        f"Server '{name}' installs its code from '{url_origin(source)}' "
                        "instead of a registry.",
                    )
                else:
                    # CW102 : paquet non figé (un chemin local n'a pas de version à figer)
                    package = _package_spec(exe, args)
                    if (
                        package
                        and not _is_local_path(package)
                        and not _package_is_pinned(exe, package)
                    ):
                        add(
                            UNPINNED_PACKAGE,
                            f"Server '{name}' runs '{redact_url(package)}' "
                            "without a pinned version.",
                        )
                # CW112 : registre ou index donné au lanceur (« npx --registry … »)
                for index in _launcher_indexes(exe, args):
                    origin = _foreign_registry(index)
                    if origin:
                        add(
                            UNSAFE_ENVIRONMENT,
                            f"Server '{name}' takes its packages from '{origin}' instead of "
                            "the official registry (on its command line).",
                        )
                # CW102 : paquets installés en plus du serveur (--with, 2e « -p »)
                for extra in _extra_packages(exe, args):
                    if _is_unpinned_registry_package(exe, extra):
                        add(
                            UNPINNED_PACKAGE,
                            f"Server '{name}' also installs '{redact_url(extra)}' "
                            "without a pinned version.",
                        )

            # CW106 : conteneur qui casse son isolation. Seules les options placées avant
            # l'image comptent (après, ce sont les arguments du programme du conteneur) ;
            # si la ligne est illisible, toute la ligne est vérifiée, par prudence.
            if exe in _CONTAINER_ENGINES:
                pairs = containers.run_option_pairs(exe, args)
                if pairs is None:
                    pairs = containers.loose_option_pairs(exe, args) if "run" in args else []
                for issue in _container_issues(pairs):
                    add(DANGEROUS_CONTAINER, f"Server '{name}' runs a container with {issue}.")

                # CW111 : image sans empreinte ni version précise (« :latest », pas d'étiquette)
                image = containers.run_image(exe, args)
                reference = containers.parse_reference(image) if image else None
                problem = containers.pinning_problem(reference) if reference else None
                if image and problem:
                    # L'image a passé la grammaire officielle : ASCII, sans espace ni contrôle.
                    add(
                        UNPINNED_CONTAINER_IMAGE,
                        f"Server '{name}' runs the container image "
                        f"'{commands.shorten(image, 100)}' {problem}.",
                    )

            # CW104 : accès disque trop large (serveur "filesystem")
            if any("filesystem" in a.lower() for a in args):
                for arg in args:
                    if _is_broad_path(arg):
                        add(BROAD_FILESYSTEM, f"Server '{name}' exposes '{arg}' to the AI agent.")

        # CW103 : secrets passés sur la ligne de commande (visibles aussi dans `ps`)
        for description in _command_line_secrets(launch.words):
            add(
                HARDCODED_ENV_SECRET,
                f"Server '{name}' passes a secret on its command line ({description}).",
            )
        for url, where in _command_line_urls(launch.words):
            add(
                HARDCODED_ENV_SECRET,
                f"Server '{name}' passes a URL with {where} on its command line "
                f"({url_origin(url)}).",
            )

        # CW110 : vérification TLS coupée par une option (--insecure, --strict-ssl=false…)
        for flag in _tls_disabled_by_options(launch.words):
            add(INSECURE_TLS, f"Server '{name}' turns off TLS certificate checks ({flag}).")

    # CW103 : secrets en dur dans env / headers ; CW110 : vérification TLS coupée (env)
    for block_name in ("env", "headers"):
        block = server.get(block_name)
        if not isinstance(block, dict):
            continue
        for raw_key, value in block.items():
            if not isinstance(value, str):
                continue
            key = str(raw_key)
            # CW112 : code chargé en plus ou registre remplacé (le message ne recopie pas la
            # valeur, seulement l'option en cause ou l'origine de l'adresse). Même une valeur
            # d'espaces : « BASH_ENV=" " » exécute le fichier nommé « » (une espace).
            issue = _environment_issue(key, value, variables) if block_name == "env" else None
            if issue:
                add(
                    UNSAFE_ENVIRONMENT,
                    f"Server '{name}' {issue} (env.{commands.shorten(key)}).",
                )
            if block_name == "env" and _tls_disabled_by_env(key, value):
                add(
                    INSECURE_TLS,
                    f"Server '{name}' turns off TLS certificate checks (env.{key}).",
                )
                continue
            # Mot de passe ou paramètre secret dans une URL (DATABASE_URL…), quel que
            # soit le nom de la clé.
            where = _url_secret(value)
            if where:
                add(
                    HARDCODED_ENV_SECRET,
                    f"Server '{name}' sets {block_name}.{key} to a URL with {where} "
                    f"({url_origin(value)}).",
                )
                continue
            # En-têtes HTTP écrits en JSON dans une seule variable (« MCP_HEADERS »).
            embedded = _embedded_secrets(value)
            if embedded:
                add(
                    HARDCODED_ENV_SECRET,
                    f"Server '{name}' sets {block_name}.{key} to JSON with a literal "
                    f"'{commands.shorten(embedded[0])}' value.",
                )
                continue
            # Références (${TOKEN}), modèles (<YOUR_KEY>), réglages (MAX_TOKENS=4096),
            # chemins de fichiers : pas des secrets.
            if _secret_value(key, value) is None:
                continue
            add(
                HARDCODED_ENV_SECRET,
                f"Server '{name}' sets {block_name}.{key} to a literal value ({redact(value)}).",
            )

    # CW105 : serveur distant en HTTP non chiffré (« url », « serverUrl » ou « httpUrl »)
    # CW103 : identifiants ou paramètre secret écrits dans cette adresse
    reported_hosts: set[str] = set()
    for url_key in _URL_KEYS:
        url = server.get(url_key)
        if not isinstance(url, str):
            continue
        where = _url_secret(url)
        if where:
            add(
                HARDCODED_ENV_SECRET,
                f"Server '{name}' connects to a URL with {where} ({url_origin(url)}).",
            )
        host = _http_host(url)
        if host is not None and host not in _LOCAL_HOSTS and host not in reported_hosts:
            reported_hosts.add(host)
            shown = host or "an unreadable address"
            add(INSECURE_TRANSPORT, f"Server '{name}' connects to {shown} over HTTP.")

    # CW108 : outils exécutés sans confirmation de l'utilisateur
    for key in _AUTO_APPROVE_KEYS:
        tools = server.get(key)
        if isinstance(tools, list) and tools:
            listed = ", ".join(str(t) for t in tools[:3]) + ("…" if len(tools) > 3 else "")
            add(
                AUTO_APPROVED_TOOLS,
                f"Server '{name}' lets the agent run {len(tools)} tool(s) "
                f"without asking ({key}: {listed}).",
            )
    if server.get("trust") is True:
        add(AUTO_APPROVED_TOOLS, f"Server '{name}' is fully trusted (trust: true).")

    # CW113 : programme lancé pour calculer les en-têtes d'un serveur distant (Claude Code)
    helper = _program(server.get("headersHelper"))
    if helper:
        add(
            AUTO_RUN_COMMAND,
            f"Server '{name}' makes the AI client run '{helper}' to compute its headers "
            "(headersHelper).",
        )

    return findings


def check_text(
    text: str, path: str, *, mcp_named: bool | None = None, folder: str = ""
) -> list[Finding]:
    """Analyse un fichier JSON (ou JSONC) qui peut contenir des serveurs MCP.

    `mcp_named` : le fichier porte-t-il un nom propre à MCP ? Par défaut, déduit du
    chemin. Un fichier MCP illisible est signalé ; un autre fichier JSON illisible
    reste silencieux (ce n'est probablement pas une configuration MCP). `folder` : dossier
    réel du fichier, pour reconnaître `.claude/settings.json` analysé seul.
    """
    if mcp_named is None:
        mcp_named = is_mcp_config(PurePosixPath(path))
    try:
        data, parsed_text = jsonc.loads(text)
    except json.JSONDecodeError as error:
        # Un fichier JSON ordinaire illisible reste silencieux… sauf s'il annonce des
        # serveurs MCP : un outil tolérant aux erreurs pourrait quand même les lancer.
        if not mcp_named and not _mentions_mcp(text):
            return []
        hint = "" if mcp_named else " The file seems to declare MCP servers or automatic commands."
        return [
            Finding(
                rule=INVALID_CONFIG,
                path=path,
                line=error.lineno,
                message=f"Invalid JSON: {error.msg}.{hint}",
            )
        ]
    except (RecursionError, ValueError):
        # Sécurité : un JSON imbriqué à l'extrême (« [[[[…]]]] ») épuise la pile
        # de Python. Sans ce garde-fou, un seul fichier piégé ferait planter
        # tout le scan (déni de service en CI). On le signale comme illisible.
        if not mcp_named and not _mentions_mcp(text):
            return []
        return [
            Finding(
                rule=INVALID_CONFIG,
                path=path,
                line=1,
                message="Invalid JSON: nesting too deep or unreadable content.",
            )
        ]

    groups = _server_groups(data, mcp_named)
    settings = _auto_approve_settings(data)
    claude_settings = _is_claude_settings(path, folder)
    auto_runs = _auto_run_commands(data, claude_settings=claude_settings)
    claude_env = _claude_settings_env(data, claude_settings)
    if not groups and not settings and not auto_runs and not claude_env:
        return []
    # Numéros de ligne calculés sur le texte effectivement lu (commentaires
    # remplacés par des espaces, positions identiques).
    key_lines = _key_lines(parsed_text)
    findings: list[Finding] = [
        Finding(
            rule=CLIENT_AUTO_APPROVE,
            path=path,
            line=key_lines.get(key, 1),
            message=f"{description}.",
        )
        for key, description in settings
    ]
    findings += [
        Finding(
            rule=UNSAFE_ENVIRONMENT,
            path=path,
            line=key_lines.get(key, 1),
            message=f"Claude Code {issue} in every session (env.{commands.shorten(key)}).",
        )
        for key, issue in claude_env
    ]
    findings += [
        Finding(
            rule=AUTO_RUN_COMMAND,
            path=path,
            line=key_lines.get(key, 1),
            message=f"{description}.",
        )
        for key, description in auto_runs
    ]
    for label, servers in groups:
        for raw_name, server in servers.items():
            name = raw_name + label
            line = key_lines.get(raw_name, 1)
            try:
                checked = _normalize_server(server)
                found = _check_server(name, checked, line, path)
                # Claude Code remplace « ${A:-défaut} » par son défaut quand A est absente : on lit
                # aussi le serveur ainsi (revue de l'Auditeur, 9e passe).
                view = _client_view(checked)
                if view is not None:
                    seen = {_same_finding(finding) for finding in found}
                    found += [
                        finding
                        for finding in _check_server(name, view, line, path)
                        if _same_finding(finding) not in seen
                    ]
                findings.extend(found)
            except Exception:
                # Défense en profondeur : un contenu imprévu dans UN serveur ne doit ni
                # faire planter le scan, ni masquer les problèmes des autres serveurs.
                findings.append(
                    Finding(
                        rule=INVALID_CONFIG,
                        path=path,
                        line=line,
                        message=f"Server '{name}' could not be analysed (unexpected content).",
                    )
                )
    return findings
