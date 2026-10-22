"""Tests de propriétés (« fuzzing ») avec Hypothesis : des milliers d'entrées tordues.

Pourquoi (décision du 20 octobre 2026) : configwarden lit des fichiers qui peuvent être
piégés. Les tests classiques vérifient les cas auxquels on a pensé ; Hypothesis génère
lui-même des lignes de commande, des images, des JSON et des fichiers d'exceptions
absurdes, et vérifie des propriétés qui doivent TOUJOURS être vraies :
- l'analyse ne plante jamais et reste bornée ;
- un secret n'apparaît jamais en entier dans un rapport (texte, JSON, SARIF) ;
- aucun caractère de contrôle ou invisible ne sort dans un message ;
- les lectures fidèles (npx, npm exec, docker run, exceptions) restent cohérentes avec
  un modèle simple, et rapides même sur de très longues entrées (revue de l'Auditeur
  du 20 octobre 2026 : les premières propriétés n'en vérifiaient pas assez).

Deux profils :
- « ci » (par défaut) : 150 exemples par propriété, tirage reproductible, aucun fichier
  écrit sur le disque (pas de dossier .hypothesis) ;
- « fuzz » : 5 000 exemples au hasard, pour une recherche plus longue en local :
  $env:CONFIGWARDEN_HYPOTHESIS = "fuzz" ; python -m pytest tests/test_fuzz.py
Hypothesis est un outil de développement seulement : il n'est jamais installé chez les
utilisateurs. Sans lui, ces tests sont simplement sautés.
"""

import json
import os
import string
from datetime import date, timedelta

import pytest

hypothesis = pytest.importorskip("hypothesis")

from hypothesis import HealthCheck, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from configwarden import commands, containers, ignore, values  # noqa: E402
from configwarden.models import Finding  # noqa: E402
from configwarden.npm_args import parse_npm_exec, parse_npx  # noqa: E402
from configwarden.redact import _is_dangerous, redact_url, sanitize, url_origin  # noqa: E402
from configwarden.reporters import RENDERERS  # noqa: E402
from configwarden.rules import ALL_RULES, mcp, secrets  # noqa: E402
from configwarden.scanner import ScanResult  # noqa: E402

settings.register_profile(
    "ci",
    max_examples=150,
    derandomize=True,
    database=None,
    deadline=2000,
    suppress_health_check=[HealthCheck.too_slow],
)
settings.register_profile(
    "fuzz",
    max_examples=5000,
    database=None,
    deadline=2000,
    suppress_health_check=[HealthCheck.too_slow],
)
settings.load_profile(os.environ.get("CONFIGWARDEN_HYPOTHESIS", "ci"))

RULES = [rule.id for rule in ALL_RULES]
RULE_BY_ID = {rule.id: rule for rule in ALL_RULES}
# Les longues entrées coûtent plus cher : moins d'exemples, mais la même limite de temps.
_FEW = max(10, settings.default.max_examples // 10)

# --- Générateurs ------------------------------------------------------------------------

# Caractères qui comptent pour un shell, une URL ou une image Docker.
_SPECIAL = " \t\n\r;&|<>()$`\"'\\=-/:.@#*?[]{}~,!%^+"
_TRICKY = "".join(chr(code) for code in (0x00, 0x1B, 0x7F, 0x85, 0x200B, 0x202E, 0x2028, 0xFEFF))
_ALPHABET = string.ascii_letters + string.digits + _SPECIAL + _TRICKY + "éß中"

# Mots qui déclenchent les chemins de code intéressants (enveloppes, lanceurs, moteurs).
_WORDS = [
    "bash", "sh", "-c", "-lc", "cmd", "/c", "pwsh", "-Command", "-EncodedCommand", "env",
    "-S", "sudo", "-u", "wsl", "-e", "su", "script", "exec", "then", "do", "if", "FOO=1",
    "npx", "-y", "-p", "--package", "uvx", "--with", "--from", "uv", "run", "tool", "pnpm",
    "dlx", "bun", "x", "pipx", "deno", "npm:", "node", "python", "docker", "podman",
    "nerdctl", "container", "--privileged", "-v", "/:/host", "--rm", "-it", "--", "&&",
    ";", "|", ">", "2>&1", "(", ")", "'", '"', "img:1.0", "org/server", "git+https://x/y",
    "https://user:pw@host.example/x?token=abc", "${TOKEN}", "<your-key>",
]  # fmt: skip

# Options de npm qui changent la lecture de la ligne (valeurs, raccourcis, abréviations).
_NPM_WORDS = [
    "-c", "--call", "--call=x", "--cal", "-yc", "--no-call", "-p", "--package",
    "--package=github:a/b", "--shell-mode", "--shell-mode=false", "--cafile", "--registry",
    "--browser", "--no-registry", "--future-flag", "--yes", "--no-install", "exec", "x",
    "exe", "true", "false", "null", "--", "---", "-", "srv@1.0.0", "github:a/b",
]  # fmt: skip

text = st.text(alphabet=_ALPHABET, max_size=80)
word = st.one_of(st.sampled_from(_WORDS), text)
arg_list = st.lists(word, max_size=25)
command_line = st.lists(word, min_size=1, max_size=12).map(" ".join)
npm_args = st.lists(
    st.one_of(st.sampled_from(_NPM_WORDS), st.sampled_from(_WORDS), text), max_size=14
)
# Un motif répété : des entrées de plusieurs dizaines de milliers de caractères, sans
# dépasser ce que Hypothesis sait générer.
long_text = st.builds(lambda unit, count: unit * count, text, st.integers(1, 2_000))
long_args = st.builds(lambda unit, count: unit * count, arg_list, st.integers(1, 400))

# Un faux secret aléatoire, assez long pour être unique dans un rapport.
secret_body = st.text(alphabet=string.ascii_letters + string.digits, min_size=24, max_size=40)
secret_prefix = st.sampled_from(["", "ghp_", "sk-ant-api03-", "sk-proj-", "xoxb-", "hf_"])


def _assert_clean(message: str) -> None:
    assert not any(_is_dangerous(character) for character in message), repr(message)


# --- Lignes de commande -------------------------------------------------------------------


@given(command=st.one_of(command_line, word), args=arg_list)
def test_command_analysis_never_crashes_and_stays_bounded(command, args) -> None:
    launch = commands.analyse(command, args)
    assert len(launch.commands) <= 1 + commands._MAX_COMMANDS
    assert all(command and all(isinstance(w, str) for w in command) for command in launch.commands)
    assert all(isinstance(risk, str) for risk in launch.risks)


# --- Conteneurs ---------------------------------------------------------------------------


image_text = st.text(alphabet=string.ascii_letters + string.digits + "./:@-_" + _TRICKY)


@given(engine=st.sampled_from(sorted(containers.ENGINES)), args=arg_list)
def test_container_lines_never_crash(engine, args) -> None:
    image = containers.run_image(engine, args)
    options = containers.run_options(engine, args)
    if image is not None:
        assert image in args or "docker://" + image in args
    if options is not None:
        assert all(option in args for option in options)
    pairs = containers.run_option_pairs(engine, args)
    assert (pairs is None) == (options is None)
    loose = containers.loose_option_pairs(engine, args)
    for name, value in [*(pairs or []), *loose]:
        assert name.startswith("-") and isinstance(value, str)
    # La lecture prudente voit au moins tout ce que voit la lecture exacte.
    assert all(pair in loose for pair in pairs or [])


# --- npx et npm exec -----------------------------------------------------------------------


@given(args=npm_args)
def test_npm_readings_never_crash_and_round_trip(args) -> None:
    reading = parse_npx(args)
    # La forme canonique (transmise aux règles pour « npm exec ») se relit à l'identique.
    assert parse_npx(reading.as_npx_args()) == reading
    exec_reading = parse_npm_exec(args)
    if exec_reading is not None:
        assert parse_npx(exec_reading.as_npx_args()) == exec_reading


@given(reference=st.one_of(image_text, text))
def test_image_references_round_trip(reference) -> None:
    parsed = containers.parse_reference(reference)
    if parsed is None:
        return
    assert reference.isascii() and len(reference) <= 512
    rebuilt = (parsed.domain + "/" if parsed.domain else "") + parsed.path
    rebuilt += (":" + parsed.tag if parsed.tag else "") + (
        "@" + parsed.digest if parsed.digest else ""
    )
    assert rebuilt == reference
    containers.pinning_problem(parsed)  # ne plante jamais


# --- Configurations MCP complètes ------------------------------------------------------------

json_leaf = st.one_of(st.none(), st.booleans(), st.integers(), text, st.sampled_from(_WORDS))
json_value = st.recursive(
    json_leaf,
    lambda children: st.one_of(
        st.lists(children, max_size=5),
        st.dictionaries(st.one_of(text, st.sampled_from(_WORDS)), children, max_size=5),
    ),
    max_leaves=30,
)
server = st.fixed_dictionaries(
    {},
    optional={
        "command": st.one_of(command_line, word, json_leaf),
        "args": st.one_of(arg_list, json_value),
        "env": st.one_of(st.dictionaries(text, st.one_of(text, json_leaf), max_size=4), json_value),
        "headers": st.dictionaries(text, text, max_size=3),
        "url": st.one_of(text, st.sampled_from(_WORDS)),
        "alwaysAllow": st.lists(text, max_size=4),
        "trust": st.booleans(),
    },
)


@given(servers=st.dictionaries(text, st.one_of(server, json_value), max_size=4))
def test_any_mcp_configuration_is_analysed_safely(servers) -> None:
    for key in ("mcpServers", "servers", "context_servers"):
        document = json.dumps({key: servers})
        for finding in mcp.check_text(document, "mcp.json", mcp_named=True):
            _assert_clean(finding.message)
            _assert_clean(finding.path)
            # Ce message vient du filet de sécurité (exception interceptée) : c'est un bug.
            assert "could not be analysed" not in finding.message, finding.message


# Serveurs qui lancent un programme connu : les règles de paquets et de conteneurs sont
# alors toujours exercées (une configuration tirée au hasard les atteint rarement).
_LAUNCHERS = [
    "npx", "npm", "pnpm", "pnpx", "bunx", "bun", "uvx", "uv", "pipx", "docker", "podman",
    "nerdctl", "bash", "cmd", "deno", "env",
]  # fmt: skip
_CONTAINER_WORDS = [
    "run", "container", "-v", "-v/:/host", "-iv/var/run/docker.sock:/s", "--volume=/:/h",
    "--privileged", "--privileged=1", "--privileged=false", "--network=host", "--pid", "host",
    "--cap-add", "ALL", "--security-opt", "seccomp=unconfined", "--mount",
    "type=bind,source=/,target=/h", "-e", "A=1", "--rm", "-it", "img:1.0", "--future", "dlx",
]  # fmt: skip
_ENV_VALUES = [
    "--require x.js", "-r", "--inspect", "https://pypi.example/simple", "a=https://x b=http://[",
    "http://[broken", "${X:-${Y:---require z}}", "-javaagent:a.jar", "rubygems", "-MFoo",
    "https://user:pw@host.example/simple", "",
]  # fmt: skip
# Une sous-commande en tête (« run », « exec »…) la moitié du temps, puis des mots tordus.
launched_args = st.tuples(
    st.sampled_from([[], ["run"], ["container", "run"], ["exec"], ["dlx"], ["-c"]]),
    st.lists(st.one_of(st.sampled_from(_CONTAINER_WORDS + _NPM_WORDS), word), max_size=14),
).map(lambda parts: parts[0] + parts[1])
launched_server = st.fixed_dictionaries(
    {"command": st.sampled_from(_LAUNCHERS), "args": launched_args},
    optional={
        "env": st.dictionaries(
            st.sampled_from(
                [
                    "npm_config_call",
                    "API_KEY",
                    "NODE_OPTIONS",
                    "LD_PRELOAD",
                    "PIP_INDEX_URL",
                    "UV_INDEX",
                    "npm_config_@x:registry",
                    "JAVA_TOOL_OPTIONS",
                    "RUBYOPT",
                    "PERL5OPT",
                    "BASH_ENV",
                ]
            ),  # fmt: skip
            st.one_of(text, st.sampled_from(_ENV_VALUES)),
        )
    },
)


@given(servers=st.dictionaries(text, launched_server, min_size=1, max_size=3))
def test_launched_servers_have_no_internal_error(servers) -> None:
    document = json.dumps({"mcpServers": servers})
    for finding in mcp.check_text(document, "mcp.json", mcp_named=True):
        assert "could not be analysed" not in finding.message, finding.message
        _assert_clean(finding.message)


@given(content=text)
def test_any_text_is_analysed_safely(content) -> None:
    for finding in mcp.check_text(content, "mcp.json", mcp_named=True):
        _assert_clean(finding.message)
    for finding in secrets.check_text(content, "notes.txt"):
        _assert_clean(finding.message)


# --- Un secret n'apparaît jamais en entier ------------------------------------------------------

_PLACEMENTS = {
    "env": lambda s: {"command": "srv", "env": {"API_KEY": s}},
    "env-url": lambda s: {"command": "srv", "env": {"DATABASE_URL": f"postgres://app:{s}@db/x"}},
    "env-json": lambda s: {"command": "srv", "env": {"HEADERS": json.dumps({"Authorization": s})}},
    "header": lambda s: {"url": "https://mcp.example.com/sse", "headers": {"Authorization": s}},
    "url-password": lambda s: {"url": f"https://user:{s}@mcp.example.com/sse"},
    "url-query": lambda s: {"url": f"https://mcp.example.com/sse?token={s}"},
    "arg-option": lambda s: {"command": "npx", "args": ["-y", "srv@1.0.0", "--api-key", s]},
    "arg-equals": lambda s: {"command": "npx", "args": ["-y", "srv@1.0.0", f"--token={s}"]},
    "docker-env": lambda s: {"command": "docker", "args": ["run", "-e", f"API_KEY={s}", "img"]},
    "command-line": lambda s: {"command": f"npx -y srv@1.0.0 --api-key {s}"},
    "git-source": lambda s: {"command": "npx", "args": ["-y", f"git+https://u:{s}@github.com/a/b"]},
    "script": lambda s: {"command": "bash", "args": ["-c", f"API_KEY={s} npx -y srv"]},
}


@given(
    placement=st.sampled_from(sorted(_PLACEMENTS)),
    prefix=secret_prefix,
    body=secret_body,
    renderer=st.sampled_from(sorted(RENDERERS)),
)
def test_secrets_never_appear_in_any_report(placement, prefix, body, renderer) -> None:
    secret = prefix + body
    document = json.dumps({"mcpServers": {"srv": _PLACEMENTS[placement](secret)}})
    result = ScanResult(
        findings=[
            *mcp.check_text(document, "mcp.json", mcp_named=True),
            *secrets.check_text(document, "mcp.json"),
        ]
    )
    report = RENDERERS[renderer](result, color=False)
    assert body not in report
    assert body[4:20] not in report  # pas même un long morceau


# Fichiers qui ne sont pas des listes de serveurs : hooks, tâches, réglages (CW112, CW113).
_FILE_PLACEMENTS = {
    "claude-helper": (".claude/settings.json", lambda s: {"apiKeyHelper": f"T={s} ./k.sh"}),
    "claude-helper-token": (".claude/settings.json", lambda s: {"apiKeyHelper": s}),
    "claude-helper-token-args": (".claude/settings.json", lambda s: {"apiKeyHelper": f"{s} -x"}),
    "claude-helper-substitution": (
        ".claude/settings.json",
        lambda s: {"apiKeyHelper": f"T=$(echo {s}) run"},
    ),
    "claude-helper-quoted": (
        ".claude/settings.json",
        lambda s: {"apiKeyHelper": f"T='{s} {s}' ./k.sh"},
    ),
    "claude-helper-unclosed": (".claude/settings.json", lambda s: {"apiKeyHelper": f"T='{s} k"}),
    "claude-hook": (
        ".claude/settings.json",
        lambda s: {"hooks": {"Stop": [{"hooks": [{"command": f"T={s} run"}]}]}},
    ),
    "claude-status": (
        ".claude/settings.json",
        lambda s: {"statusLine": {"type": "command", "command": f"T={s} run"}},
    ),
    "claude-env": (
        ".claude/settings.json",
        lambda s: {"env": {"NODE_OPTIONS": f"--require ./h.js --token={s}"}},
    ),
    "claude-env-url": (
        ".claude/settings.json",
        lambda s: {"env": {"PIP_INDEX_URL": f"https://u:{s}@pypi.evil.example/simple"}},
    ),
    "cursor-hook": (".cursor/hooks.json", lambda s: {"hooks": {"stop": [{"command": f"T={s} h"}]}}),
    "copilot-hook": (
        ".github/hooks/h.json",
        lambda s: {"hooks": {"sessionStart": [{"powershell": f"T={s} h"}]}},
    ),
    "task": (
        ".vscode/tasks.json",
        lambda s: {"tasks": [{"command": f"T={s} x", "runOptions": {"runOn": "folderOpen"}}]},
    ),
    "devcontainer": (
        ".devcontainer/devcontainer.json",
        lambda s: {"initializeCommand": f"T={s} x"},
    ),
    "devcontainer-list": (
        ".devcontainer/devcontainer.json",
        lambda s: {"initializeCommand": [f"T={s}/x", "bash"]},
    ),
    "headers-helper": (
        "mcp.json",
        lambda s: {
            "mcpServers": {"s": {"url": "https://m.example.com/x", "headersHelper": f"T={s} h"}}
        },
    ),
    "git-ssh-shell": (
        "mcp.json",
        lambda s: {"mcpServers": {"s": {"command": "x", "env": {"GIT_SSH_COMMAND": f"T={s} sh"}}}},
    ),
    "git-ssh-option": (
        "mcp.json",
        lambda s: {
            "mcpServers": {
                "s": {
                    "command": "x",
                    "env": {"GIT_SSH_COMMAND": f"ssh -o ProxyCommand=./h -o SendEnv={s}"},
                }
            }
        },
    ),
}


@given(
    placement=st.sampled_from(sorted(_FILE_PLACEMENTS)),
    prefix=secret_prefix,
    body=secret_body,
    renderer=st.sampled_from(sorted(RENDERERS)),
)
def test_secrets_never_appear_for_hooks_tasks_and_settings(
    placement, prefix, body, renderer
) -> None:
    path, build = _FILE_PLACEMENTS[placement]
    document = json.dumps(build(prefix + body))
    result = ScanResult(
        findings=[*mcp.check_text(document, path), *secrets.check_text(document, path)]
    )
    report = RENDERERS[renderer](result, color=False).lower()
    # Même en minuscules : le nom d'un programme s'affiche en minuscules.
    assert body.lower() not in report
    assert body[4:20].lower() not in report  # pas même un long morceau


@given(password=secret_body, user=st.text(alphabet=string.ascii_letters, max_size=8))
def test_url_helpers_never_keep_the_password(password, user) -> None:
    for url in (
        f"https://{user}:{password}@host.example/path",
        f"https://host.example/path?token={password}",
        f"git+https://{password}@github.com/a/b.git",
    ):
        assert password not in url_origin(url)
        assert password not in redact_url(url)


@given(content=st.text(max_size=200))
def test_sanitize_leaves_no_dangerous_character(content) -> None:
    _assert_clean(sanitize(content))


@given(value=st.one_of(text, st.text(max_size=300)))
def test_value_helpers_never_crash(value) -> None:
    values.is_placeholder(value)
    values.is_example_token(value)
    values.is_boolean(value)
    values.is_number(value)
    values.is_word(value)
    values.is_file_path(value)


# --- Fichier d'exceptions ----------------------------------------------------------------------

ignore_line = st.one_of(
    text,
    st.builds(
        lambda rule, path, until, reason: f"{rule} {path} {until} -- {reason}",
        st.one_of(st.sampled_from(RULES), text),
        st.one_of(text, st.sampled_from(["mcp.json", "a/", ".", "..", "*", "/x", "C:/x"])),
        st.one_of(st.just(""), st.dates().map(lambda d: f"until={d.isoformat()}"), text),
        text,
    ),
)


# --- Longues entrées : la limite de temps de Hypothesis (2 s) s'applique à chaque exemple ---


@settings(max_examples=_FEW)
@given(command=st.one_of(word, long_text), args=long_args)
def test_long_command_lines_stay_fast(command, args) -> None:
    launch = commands.analyse(command, args)
    assert len(launch.commands) <= 2 + commands._MAX_COMMANDS


@settings(max_examples=_FEW)
@given(engine=st.sampled_from(sorted(containers.ENGINES)), args=long_args)
def test_long_container_lines_stay_fast(engine, args) -> None:
    containers.run_option_pairs(engine, args)
    containers.loose_option_pairs(engine, args)
    containers.run_image(engine, args)


@settings(max_examples=_FEW)
@given(args=st.builds(lambda unit, count: unit * count, npm_args, st.integers(1, 400)))
def test_long_npm_lines_stay_fast(args) -> None:
    parse_npx(args)
    parse_npm_exec(args)


@settings(max_examples=_FEW)
@given(content=long_text)
def test_long_texts_stay_fast(content) -> None:
    mcp.check_text(content, "mcp.json", mcp_named=True)
    secrets.check_text(content, "notes.txt")
    ignore.parse(content, ".configwarden-ignore", RULES)
    secrets.mask_secrets(content)


@given(lines=st.lists(ignore_line, max_size=20), marker=secret_body)
def test_ignore_files_never_crash_nor_echo_their_content(lines, marker) -> None:
    content = "\n".join(line.replace("\n", " ") + " " + marker for line in lines)
    parsed = ignore.parse(content, ".configwarden-ignore", RULES)
    for error in parsed.errors:
        assert marker not in error
        _assert_clean(sanitize(error))
    for entry in parsed.entries:
        assert entry.rule in RULES
        assert not entry.path.startswith("/") and ".." not in entry.path.split("/")
        assert len(entry.reason) >= ignore.MIN_REASON
    result = ScanResult()
    ignore.apply(result, parsed, today=date(2026, 10, 20))
    for note in result.ignore_notes:
        assert marker not in note


# --- Exceptions : comparaison avec un modèle naïf, mais évident -----------------------------

_PARTS = ["a", "b", "c", "mcp.json"]
finding_path = st.lists(st.sampled_from(_PARTS), min_size=1, max_size=5).map("/".join)
finding_rule = st.sampled_from(["CW106", "CW111", "CW001"])
exception_line = st.builds(
    lambda rule, parts, folder, days: (
        f"{rule} {'/'.join(parts)}{'/' if folder else ''}"
        + (f" until={(date(2026, 10, 20) + timedelta(days=days)).isoformat()}" if days else "")
        + " -- reviewed"
    ),
    finding_rule,
    st.lists(st.sampled_from(_PARTS), min_size=1, max_size=4),
    st.booleans(),
    st.one_of(st.none(), st.integers(-3, 3).filter(bool)),
)


def _naive(findings, entries, today):
    """Modèle : exception exacte d'abord, sinon le dossier le plus haut ; 1re ligne gagnante."""
    active = [e for e in entries if e.until is None or today <= e.until]
    kept, suppressed = [], []
    for finding in findings:
        matching = [
            e
            for e in active
            if not e.folder and (e.rule, e.path) == (finding.rule.id, finding.path)
        ]
        if not matching:
            parts = finding.path.split("/")[:-1]
            for depth in range(1, len(parts) + 1):
                prefix = "/".join(parts[:depth]) + "/"
                matching = [
                    e for e in active if e.folder and (e.rule, e.path) == (finding.rule.id, prefix)
                ]
                if matching:
                    break
        if matching:
            suppressed.append((finding, matching[0].line))
        else:
            kept.append(finding)
    return kept, suppressed


@given(
    found=st.lists(st.tuples(finding_rule, finding_path), max_size=25),
    lines=st.lists(exception_line, max_size=12),
)
def test_ignore_apply_matches_a_naive_model(found, lines) -> None:
    findings = [
        Finding(rule=RULE_BY_ID[rule], path=path, line=1, message="m") for rule, path in found
    ]
    parsed = ignore.parse("\n".join(lines), ".configwarden-ignore", RULES)
    assert parsed.errors == []  # toutes les lignes générées sont valides
    today = date(2026, 10, 20)
    expected_kept, expected_suppressed = _naive(findings, parsed.entries, today)
    result = ScanResult(findings=list(findings))
    ignore.apply(result, parsed, today=today)
    assert result.findings == expected_kept
    assert [(s.finding, s.line) for s in result.suppressed] == expected_suppressed


# --- Commandes automatiques (CW113) ------------------------------------------------------

_HOOK_KEYS = ["hooks", "tasks", "runOptions", "runOn", "folderOpen", "command", "type",
              "initializeCommand", "label", "matcher"]  # fmt: skip
hook_value = st.recursive(
    st.one_of(json_leaf, st.sampled_from(_HOOK_KEYS)),
    lambda children: st.one_of(
        st.lists(children, max_size=4),
        st.dictionaries(st.one_of(st.sampled_from(_HOOK_KEYS), text), children, max_size=4),
    ),
    max_leaves=25,
)


@given(document=st.dictionaries(st.sampled_from(_HOOK_KEYS), hook_value, max_size=4))
def test_automatic_command_files_are_analysed_safely(document) -> None:
    for name in (".claude/settings.json", ".vscode/tasks.json", "devcontainer.json"):
        for finding in mcp.check_text(json.dumps(document), name):
            _assert_clean(finding.message)
            assert "could not be analysed" not in finding.message
