"""Tests des défauts trouvés par la revue indépendante finale de la 0.5.0 (5 novembre 2026).

Pourquoi : avant de publier, l'Auditeur a montré avec un vrai Node 22 que CW112 se taisait
alors que du code était bien chargé, et que CW113 ratait des tâches VS Code lancées toutes
seules. Chaque cas ci-dessous a été démontré (ou vérifié dans le code source de VS Code).

1. `NODE_OPTIONS` est lu comme Node le lit (`ParseNodeOptionsEnvVar`) : seul `"` ouvre et
   ferme une chaîne, n'importe où dans un mot ; `\\` échappe le caractère suivant dans une
   chaîne ; seule l'espace sépare les mots. Dans le nom d'une option, `_` vaut `-`.
   `--openssl-config` fait charger une bibliothèque native (moteur OpenSSL).
2. VS Code compare `runOn` sans tenir compte de la casse (`value.toLowerCase()`), et
   `worktreeCreated` lance aussi la tâche toute seule (création d'un worktree de session
   d'agent).
3. Un nom d'événement de hook ou un nom de tâche qui ressemble à un secret n'est pas recopié.
"""

import json

import pytest

from configwarden.rules import mcp
from configwarden.scanner import scan
from tests.conftest import fake_secret


def env_findings(write_mcp, value: str, key: str = "NODE_OPTIONS"):
    server = {"command": "node", "args": ["server.js"], "env": {key: value}}
    return [f for f in scan(write_mcp({"s": server})).findings if f.rule.id == "CW112"]


# --- 1. NODE_OPTIONS lu comme Node --------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "option"),
    [
        ('--req"uire" ./h.js', "--require"),  # guillemets au milieu du mot : retirés par Node
        ('"--require" ./h.js', "--require"),
        ('--im""port=./l.mjs', "--import"),
        ("--experimental_loader=./l.mjs", "--experimental-loader"),  # « _ » vaut « - »
        ("--experimental_loader ./l.mjs", "--experimental-loader"),
        ('--exp"erimental_lo"ader=./l.mjs', "--experimental-loader"),
        ('"--req\\uire" ./h.js', "--require"),  # « \\ » échappe « u » dans une chaîne
        ('--max_old_space_size=4096 --re"quire" ./h.js', "--require"),
    ],
)
def test_node_options_read_like_node(write_mcp, value: str, option: str) -> None:
    [finding] = env_findings(write_mcp, value)
    assert f"'{option}'" in finding.message
    assert "h.js" not in finding.message and "l.mjs" not in finding.message


@pytest.mark.parametrize("value", ["--inspect_brk=0", '--insp"ect"', "--inspect_wait"])
def test_node_debugger_options_read_like_node(write_mcp, value: str) -> None:
    [finding] = env_findings(write_mcp, value)
    assert "debugger" in finding.message


@pytest.mark.parametrize("value", ["--openssl-config=./o.cnf", "--openssl_config ./o.cnf"])
def test_node_openssl_config_loads_native_code(write_mcp, value: str) -> None:
    [finding] = env_findings(write_mcp, value)
    assert "--openssl-config" in finding.message and "o.cnf" not in finding.message


def test_node_options_on_command_line(write_mcp) -> None:
    server = {"command": "env", "args": ["NODE_OPTIONS=--experimental_loader=./l.mjs", "node"]}
    ids = [f.rule.id for f in scan(write_mcp({"s": server})).findings]
    assert "CW112" in ids


@pytest.mark.parametrize(
    "value",
    [
        "--max_old_space_size=4096",
        '--enable-source-maps "--no-warnings"',
        "--dns_result_order=ipv4first",
        '"unterminated',
        "\\",
        '""',
    ],
)
def test_ordinary_node_options_stay_quiet(write_mcp, value: str) -> None:
    assert env_findings(write_mcp, value) == []


def test_node_option_words_follow_node() -> None:
    assert mcp._node_option_words('--req"uire" ./h.js') == ["--require", "./h.js"]
    assert mcp._node_option_words('"a b" c') == ["a b", "c"]
    assert mcp._node_option_words('"x\\"y"') == ['x"y']
    assert mcp._node_option_words("a\tb") == ["a\tb"]  # Node ne coupe que sur l'espace


def test_very_long_node_options_is_fast(write_mcp) -> None:
    # Juste sous la limite de taille d'un fichier (1 Mo) : un seul mot entre guillemets très
    # long, puis beaucoup de mots. Rien ne plante, la lecture reste linéaire, le début est lu.
    import time

    start = time.monotonic()
    env_findings(write_mcp, '"' + "a" * 900_000 + '" --require ./h.js')
    value = ('"' + "a" * 50 + '" ') * 15_000 + "--require ./h.js"
    env_findings(write_mcp, value)
    assert env_findings(write_mcp, "--require ./h.js " + value)
    assert time.monotonic() - start < 10


# --- 2. runOn de VS Code ------------------------------------------------------------------


def task_findings(tmp_path, run_on: object, **extra):
    task = {"label": "setup", "type": "shell", "command": "node x.js"}
    task.update(extra)
    if run_on is not None:
        task["runOptions"] = {"runOn": run_on}
    path = tmp_path / ".vscode" / "tasks.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"version": "2.0.0", "tasks": [task]}), encoding="utf-8")
    return [f for f in scan(tmp_path).findings if f.rule.id == "CW113"]


@pytest.mark.parametrize("run_on", ["folderOpen", "FolderOpen", "folderopen", "FOLDEROPEN"])
def test_run_on_folder_open_any_case(tmp_path, run_on: str) -> None:
    [finding] = task_findings(tmp_path, run_on)
    assert "folder is opened" in finding.message and "runOn: folderOpen" in finding.message


@pytest.mark.parametrize("run_on", ["worktreeCreated", "WorktreeCreated", "worktreecreated"])
def test_run_on_worktree_created(tmp_path, run_on: str) -> None:
    [finding] = task_findings(tmp_path, run_on)
    assert "worktree" in finding.message and "runOn: worktreeCreated" in finding.message


@pytest.mark.parametrize(
    "run_on", [None, "default", "Default", "", 1, ["folderOpen"], " folderOpen"]
)
def test_run_on_default_stays_quiet(tmp_path, run_on: object) -> None:
    assert task_findings(tmp_path, run_on) == []


def test_run_on_platform_variant_any_case(tmp_path) -> None:
    [finding] = task_findings(tmp_path, None, windows={"runOptions": {"runOn": "FOLDEROPEN"}})
    assert "folder is opened" in finding.message


# --- 3. Pas de secret dans les noms affichés ----------------------------------------------


def test_secret_like_task_label_is_not_shown(tmp_path) -> None:
    token = fake_secret("ghp_", 36)
    [finding] = task_findings(tmp_path, "folderOpen", label=token)
    assert token not in finding.message and token[:8] not in finding.message


def test_secret_like_hook_event_is_not_shown(tmp_path) -> None:
    token = fake_secret("ghp_", 36)
    hooks = {"hooks": {token: [{"hooks": [{"type": "command", "command": "curl x"}]}]}}
    path = tmp_path / ".claude" / "settings.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(hooks), encoding="utf-8")
    [finding] = [f for f in scan(tmp_path).findings if f.rule.id == "CW113"]
    assert token not in finding.message and token[:8] not in finding.message
    assert "'curl'" in finding.message


def test_ordinary_names_are_still_shown(tmp_path) -> None:
    [finding] = task_findings(tmp_path, "folderOpen")
    assert "'setup'" in finding.message


@pytest.mark.parametrize("filler", ["--no-warnings ", '"" ', "--max-old-space-size=4096 "])
def test_require_after_many_options_is_read(write_mcp, filler: str) -> None:
    # Contre-vérification de l'Auditeur : 100 mots avant « --require » le cachaient.
    [finding] = env_findings(write_mcp, filler * 300 + "--require ./h.js")
    assert "'--require'" in finding.message
