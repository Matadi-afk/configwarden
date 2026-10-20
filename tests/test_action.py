"""Tests de l'Action GitHub (action.yml) et du hook pre-commit (.pre-commit-hooks.yaml).

Le script de l'Action est extrait de action.yml et lancé comme sur GitHub (« bash
--noprofile --norc -eo pipefail ») : les entrées arrivent par des variables
d'environnement. On vérifie le comportement
(codes de sortie, SARIF) et surtout la sécurité :
- une entrée piégée n'est jamais exécutée comme une commande ;
- le dépôt analysé ne peut pas remplacer un module de configwarden ou de Python
  (Python est lancé en mode isolé, avec le code de l'action seulement).
Ces tests demandent bash : ils sont sautés sous Windows.
"""

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
ACTION = ROOT / "action.yml"
HOOKS = ROOT / ".pre-commit-hooks.yaml"

pytestmark = pytest.mark.skipif(
    sys.platform == "win32" or shutil.which("bash") is None, reason="needs bash (Linux, macOS)"
)


def action_script() -> str:
    """Le bloc « run: | » de l'étape de l'Action (indentation de 8 espaces retirée)."""
    lines = ACTION.read_text(encoding="utf-8").splitlines()
    start = lines.index("      run: |") + 1
    script = []
    for line in lines[start:]:
        if line and not line.startswith("        "):
            break
        script.append(line[8:])
    return "\n".join(script) + "\n"


def run_action(workdir: Path, **inputs: str) -> subprocess.CompletedProcess:
    env = {
        "PATH": os.environ["PATH"],
        "HOME": os.environ.get("HOME", str(workdir)),
        "CW_PATH": inputs.get("path", "."),
        "CW_FAIL_ON": inputs.get("fail_on", "low"),
        "CW_EXCLUDE": inputs.get("exclude", ""),
        "CW_SARIF": inputs.get("sarif_file", ""),
        "CW_NO_IGNORE": inputs.get("no_ignore", "false"),
        "CW_SOURCE": str(ROOT / "src"),
    }
    if "github" in inputs:
        env["GITHUB_ACTIONS"] = inputs["github"]
    # Options exactes de GitHub pour « shell: bash » : -e arrête l'étape à la 1re erreur.
    return subprocess.run(  # noqa: S603 (bash et script du dépôt, entrées de test)
        ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", action_script()],  # noqa: S607
        cwd=workdir,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


def vulnerable(directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    server = {"command": "docker", "args": ["run", "--privileged", "org/server:1.2.3"]}
    (directory / "mcp.json").write_text(json.dumps({"mcpServers": {"box": server}}))
    return directory


def test_clean_project_passes(tmp_path) -> None:
    (tmp_path / "README.md").write_text("Nothing here\n")
    result = run_action(tmp_path)
    assert result.returncode == 0, result.stderr
    assert "No issues found." in result.stdout


def test_findings_fail_the_step(tmp_path) -> None:
    result = run_action(vulnerable(tmp_path))
    assert result.returncode == 1
    assert "CW106" in result.stdout


def test_fail_on_threshold(tmp_path) -> None:
    assert run_action(vulnerable(tmp_path), fail_on="critical").returncode == 0


def test_exclude_lines_and_odd_paths(tmp_path) -> None:
    # Un chemin qui commence par « - » ne doit pas être pris pour une option.
    vulnerable(tmp_path / "-odd")
    vulnerable(tmp_path / "-odd" / "skip me")
    result = run_action(tmp_path, path="-odd", exclude="skip me/*\r\n\nnothing/*\n")
    assert result.returncode == 1, result.stdout + result.stderr
    assert result.stdout.count("CW106") == 1, result.stdout


def test_sarif_report_is_written(tmp_path) -> None:
    result = run_action(vulnerable(tmp_path), sarif_file="configwarden.sarif")
    assert result.returncode == 1
    report = json.loads((tmp_path / "configwarden.sarif").read_text())
    assert [r["ruleId"] for r in report["runs"][0]["results"]] == ["CW106"]
    # Revue de l'Auditeur (20 octobre 2026) : avec -e, les alertes du SARIF (code 1)
    # arrêtaient l'étape avant le rapport texte, qui n'apparaissait jamais.
    assert "CW106" in result.stdout
    assert "Report written to configwarden.sarif" in result.stdout


def test_report_is_shielded_on_github(tmp_path) -> None:
    project = vulnerable(tmp_path / "::warning::fake")
    result = run_action(tmp_path, github="true")
    assert result.returncode == 1
    lines = result.stdout.splitlines()
    start = next(index for index, line in enumerate(lines) if "::stop-commands::" in line)
    token = lines[start].removeprefix("::stop-commands::")
    assert f"::{token}::" in lines[start + 1 :]
    assert "CW106" in result.stdout and project.name in result.stdout


def test_no_ignore_input(tmp_path) -> None:
    project = vulnerable(tmp_path)
    (project / ".configwarden-ignore").write_text("CW106 mcp.json -- sandbox on purpose\n")
    assert run_action(project).returncode == 0
    assert run_action(project, no_ignore="true").returncode == 1


@pytest.mark.parametrize(
    "inputs",
    [
        {"fail_on": "low; touch pwned"},
        {"fail_on": "$(touch pwned)"},
        {"no_ignore": "true; touch pwned"},
        {"path": ""},
    ],
)
def test_invalid_inputs_are_refused(tmp_path, inputs) -> None:
    result = run_action(tmp_path, **inputs)
    assert result.returncode == 2
    assert "::error title=configwarden::" in result.stdout
    assert not (tmp_path / "pwned").exists()


@pytest.mark.parametrize(
    "inputs",
    [
        {"exclude": "$(touch pwned)\n`touch pwned`"},
        {"path": "$(touch pwned)"},
        {"sarif_file": "$(touch pwned).sarif"},
    ],
)
def test_inputs_are_never_executed(tmp_path, inputs) -> None:
    run_action(tmp_path, **inputs)
    assert not (tmp_path / "pwned").exists()


def test_scanned_repository_cannot_replace_modules(tmp_path) -> None:
    # Un dépôt piégé place de faux modules dans le dossier courant : s'ils étaient
    # importés, ils créeraient le fichier « pwned ».
    trap = "open('pwned', 'w').close()\n"
    (tmp_path / "configwarden").mkdir()
    (tmp_path / "configwarden" / "__init__.py").write_text(trap)
    for name in ("json.py", "re.py", "runpy.py", "argparse.py"):
        (tmp_path / name).write_text(trap)
    result = run_action(tmp_path)
    assert result.returncode in (0, 1), result.stderr
    assert not (tmp_path / "pwned").exists()


def test_sarif_output_refuses_symlinks(tmp_path) -> None:
    project = vulnerable(tmp_path / "repo")
    victim = tmp_path / "victim.txt"
    victim.write_text("keep me")
    try:
        (project / "out.sarif").symlink_to(victim)
    except OSError:
        pytest.skip("cannot create symlink on this system")
    result = run_action(project, sarif_file="out.sarif")
    assert result.returncode == 2
    assert victim.read_text() == "keep me"


# --- Hook pre-commit -----------------------------------------------------------------------


def test_pre_commit_hook_definition() -> None:
    text = HOOKS.read_text(encoding="utf-8")
    assert re.search(r"^- id: configwarden$", text, re.MULTILINE)
    assert re.search(r"^  entry: configwarden scan$", text, re.MULTILINE)
    assert re.search(r"^  language: python$", text, re.MULTILINE)
    assert re.search(r"^  pass_filenames: false$", text, re.MULTILINE)
