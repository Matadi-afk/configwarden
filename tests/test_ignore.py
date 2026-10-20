"""Tests v0.4.0 : le fichier d'exceptions `.configwarden-ignore`.

Décisions du 20 octobre 2026 :
- une ligne = une règle (jamais de joker) + un fichier précis ou un dossier terminé par
  « / » (jamais tout le projet) + une raison obligatoire après « -- » ;
- date de fin facultative (`until=AAAA-MM-JJ`) : une exception expirée ne s'applique plus ;
- une alerte mise en exception ne compte plus pour le code de sortie, mais elle reste
  TOUJOURS listée (texte et JSON) avec sa raison : un dépôt piégé ne peut pas cacher son
  propre serveur sans que cela se voie. Elle est retirée du SARIF (GitHub ignore le
  marquage « suppressions » de la norme et l'afficherait comme une alerte ouverte) ;
- une ligne mal écrite est signalée par son numéro, sans recopier son contenu (elle
  pourrait contenir un secret, ou venir d'un fichier lu à travers un lien piégé).
"""

import json
import os
import time
from datetime import date

import pytest

from configwarden import ignore
from configwarden.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, main
from configwarden.rules import ALL_RULES
from configwarden.scanner import scan
from tests.conftest import fake_secret

RULES = {rule.id for rule in ALL_RULES}
TODAY = date(2026, 10, 20)
# Serveur qui déclenche CW106 (conteneur privilégié) et CW111 (image non figée).
DOCKER_SERVER = {"command": "docker", "args": ["run", "--privileged", "org/server"]}


def parse(text: str) -> ignore.IgnoreFile:
    return ignore.parse(text, ".configwarden-ignore", RULES)


def project(tmp_path, ignore_text: str | None = None, name: str = "mcp.json"):
    """Projet avec un fichier MCP (CW106 + CW111) et, si demandé, un fichier d'exceptions."""
    config = tmp_path / name
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text(json.dumps({"mcpServers": {"box": DOCKER_SERVER}}), encoding="utf-8")
    if ignore_text is not None:
        (tmp_path / ".configwarden-ignore").write_text(ignore_text, encoding="utf-8")
    return tmp_path


def ids(findings) -> list[str]:
    return sorted(f.rule.id for f in findings)


# --- Lecture des lignes ---------------------------------------------------------------


def test_valid_lines_are_read() -> None:
    parsed = parse(
        "# exceptions du projet\n"
        "\n"
        "CW106  examples/demo/mcp.json  -- demo file, intentionally vulnerable\n"
        "cw111  tests/fixtures/  until=2026-12-31  -- fixtures pinned later\n"
    )
    assert parsed.errors == []
    first, second = parsed.entries
    assert (first.rule, first.path, first.folder, first.until, first.line) == (
        "CW106",
        "examples/demo/mcp.json",
        False,
        None,
        3,
    )
    assert first.reason == "demo file, intentionally vulnerable"
    assert (second.rule, second.path, second.folder, second.until, second.line) == (
        "CW111",
        "tests/fixtures/",
        True,
        date(2026, 12, 31),
        4,
    )


@pytest.mark.parametrize(
    ("written", "expected"),
    [
        ("./a/mcp.json", "a/mcp.json"),
        (".\\a\\mcp.json", "a/mcp.json"),  # chemin écrit sous Windows
        ('"my folder/mcp.json"', "my folder/mcp.json"),  # espace : entre guillemets
        ("a--b/mcp.json", "a--b/mcp.json"),  # « -- » dans un nom n'est pas le séparateur
    ],
)
def test_paths_are_normalised(written, expected) -> None:
    parsed = parse(f"CW106 {written} -- reason here")
    assert parsed.errors == []
    assert parsed.entries[0].path == expected


@pytest.mark.parametrize(
    ("line", "problem"),
    [
        ("CW106 a/mcp.json", "reason"),
        ("CW106 a/mcp.json --", "reason"),
        ("CW106 a/mcp.json -- ok", "reason"),  # raison trop courte
        ("CW106 -- some reason", "path"),
        ("CW999 a/mcp.json -- some reason", "rule"),
        ("* a/mcp.json -- some reason", "rule"),
        ("CW1* a/mcp.json -- some reason", "rule"),
        ("CW106 . -- some reason", "whole project"),
        ("CW106 ./ -- some reason", "whole project"),
        ("CW106 / -- some reason", "whole project"),
        ("CW106 * -- some reason", "whole project"),
        ("CW106 ** -- some reason", "whole project"),
        ("CW106 a/*.json -- some reason", "wildcard"),
        ("CW106 a/mcp.jso? -- some reason", "wildcard"),
        ("CW106 /etc/mcp.json -- some reason", "relative"),
        ("CW106 C:/x/mcp.json -- some reason", "relative"),
        ("CW106 ../mcp.json -- some reason", ".."),
        ("CW106 a/../mcp.json -- some reason", ".."),
        ("CW106 a//mcp.json -- some reason", ".."),
        ("CW106 a/mcp.json until=2026-13-01 -- some reason", "date"),
        ("CW106 a/mcp.json until=tomorrow -- some reason", "date"),
        ("CW106 a/mcp.json extra -- some reason", "unexpected"),
        ('CW106 "a/mcp.json -- some reason', "quote"),
        ("CW106 a/mcp" + chr(0x1B) + ".json -- some reason", "character"),
        ("CW106 a/mcp" + chr(0x202E) + ".json -- some reason", "character"),
    ],
)
def test_bad_lines_are_reported_with_their_number(line, problem) -> None:
    parsed = parse("# header\n" + line + "\n")
    assert parsed.entries == []
    [error] = parsed.errors
    assert "line 2" in error
    assert problem in error


def test_errors_never_repeat_the_line_content() -> None:
    secret = fake_secret("ghp_", 36)
    parsed = parse(f"CW106 a/mcp.json {secret}\nCW106 {secret} b.json -- reason here\n")
    assert len(parsed.errors) == 2
    assert all(secret not in error and "aB3dE5" not in error for error in parsed.errors)


def test_too_many_lines_are_bounded() -> None:
    text = "".join(f"CW106 dir{index}/mcp.json -- reason here\n" for index in range(20_000))
    parsed = parse(text)
    assert len(parsed.entries) == ignore.MAX_ENTRIES
    assert any("too many" in error for error in parsed.errors)


@pytest.mark.parametrize(
    "text",
    [
        "CW106 " + "a/" * 100_000 + "x -- reason here\n",
        "CW106 a.json -- " + "r" * 200_000 + "\n",
        '"' * 200_000,
        "-- " * 100_000,
        "CW106 a.json until=" + "9" * 100_000 + " -- reason here\n",
        "\n" * 200_000,
    ],
    ids=["deep", "long-reason", "quotes", "dashes", "long-date", "empty-lines"],
)
def test_hostile_files_are_fast(text) -> None:
    start = time.perf_counter()
    parse(text)
    assert time.perf_counter() - start < 1


# --- Application aux constats -----------------------------------------------------------


def apply(tmp_path, ignore_text: str, today: date = TODAY):
    result = scan(project(tmp_path))
    ignore.apply(result, parse(ignore_text), today=today)
    return result


def test_exception_hides_only_its_rule_and_file(tmp_path) -> None:
    result = apply(tmp_path, "CW106 mcp.json -- sandbox needs it\n")
    assert ids(result.findings) == ["CW111"]
    [suppressed] = result.suppressed
    assert suppressed.finding.rule.id == "CW106"
    assert suppressed.reason == "sandbox needs it"
    assert suppressed.line == 1


def test_folder_exception_covers_files_below_it(tmp_path) -> None:
    project(tmp_path / "configs" / "team", name="mcp.json")
    result = scan(tmp_path)
    ignore.apply(result, parse("CW111 configs/ -- images pinned by the platform\n"), today=TODAY)
    assert ids(result.findings) == ["CW106"]
    assert [s.finding.path for s in result.suppressed] == ["configs/team/mcp.json"]


@pytest.mark.parametrize(
    "line",
    [
        "CW106 other.json -- not this file",
        "CW106 mcp.json/ -- a folder of the same name",
        "CW106 mcp -- a prefix is not a folder",
        "CW101 mcp.json -- another rule",
    ],
)
def test_exception_must_match_exactly(tmp_path, line) -> None:
    result = apply(tmp_path, line + "\n")
    assert ids(result.findings) == ["CW106", "CW111"]
    assert result.suppressed == []


def test_expired_exception_no_longer_applies(tmp_path) -> None:
    result = apply(tmp_path, "CW106 mcp.json until=2026-10-19 -- temporary\n")
    assert ids(result.findings) == ["CW106", "CW111"]
    assert any("line 1" in note and "expired" in note for note in result.ignore_notes)


def test_exception_is_valid_on_its_last_day(tmp_path) -> None:
    result = apply(tmp_path, "CW106 mcp.json until=2026-10-20 -- temporary\n")
    assert ids(result.findings) == ["CW111"]


def test_unused_exceptions_are_reported(tmp_path) -> None:
    result = apply(tmp_path, "CW106 mcp.json -- used\nCW105 gone.json -- stale entry\n")
    assert any("matched nothing" in note and "2" in note for note in result.ignore_notes)


# --- Ligne de commande ---------------------------------------------------------------------


def test_cli_uses_the_project_file_and_lists_what_it_hides(tmp_path, capsys) -> None:
    project(tmp_path, "CW106 mcp.json -- sandbox\nCW111 mcp.json -- pinned in prod\n")
    assert main(["scan", str(tmp_path)]) == EXIT_OK
    out = capsys.readouterr().out
    assert "No issues found." in out
    # Toujours visible : un dépôt ne peut pas se cacher en silence.
    assert "Suppressed by .configwarden-ignore (2)" in out
    assert "CW106 mcp.json:1" in out and "sandbox" in out
    assert "2 suppressed" in out


def test_cli_no_ignore_shows_everything(tmp_path, capsys) -> None:
    project(tmp_path, "CW106 mcp.json -- sandbox\nCW111 mcp.json -- pinned in prod\n")
    assert main(["scan", str(tmp_path), "--no-ignore"]) == EXIT_FINDINGS
    out = capsys.readouterr().out
    assert "CW106" in out and "Suppressed" not in out


def test_cli_explicit_ignore_file(tmp_path, capsys) -> None:
    project(tmp_path)
    trusted = tmp_path.parent / (tmp_path.name + "-exceptions.txt")
    trusted.write_text("CW106 mcp.json -- sandbox\nCW111 mcp.json -- pinned\n", encoding="utf-8")
    assert main(["scan", str(tmp_path), "--ignore-file", str(trusted)]) == EXIT_OK
    assert main(["scan", str(tmp_path), "--ignore-file", str(tmp_path / "missing")]) == EXIT_ERROR
    err = capsys.readouterr().err
    assert "ignore file not found" in err


def test_cli_rejects_both_options(tmp_path, capsys) -> None:
    project(tmp_path)
    with pytest.raises(SystemExit) as raised:
        main(["scan", str(tmp_path), "--no-ignore", "--ignore-file", "x"])
    assert raised.value.code == EXIT_ERROR


def test_cli_reports_bad_lines_and_keeps_the_findings(tmp_path, capsys) -> None:
    project(tmp_path, "CW106 mcp.json\n")
    assert main(["scan", str(tmp_path)]) == EXIT_FINDINGS
    out = capsys.readouterr().out
    assert "Warning: .configwarden-ignore line 1" in out


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks unsupported")
def test_symlinked_project_file_is_not_read(tmp_path, capsys) -> None:
    outside = tmp_path / "outside.txt"
    outside.write_text("CW106 mcp.json -- hidden\nCW111 mcp.json -- hidden\n", encoding="utf-8")
    repo = project(tmp_path / "repo")
    try:
        os.symlink(outside, repo / ".configwarden-ignore")
    except OSError:
        pytest.skip("cannot create symlink on this system")
    assert main(["scan", str(repo)]) == EXIT_FINDINGS
    out = capsys.readouterr().out
    assert "symbolic link" in out
    assert "hidden" not in out


def test_json_lists_suppressed_findings_with_their_reason(tmp_path, capsys) -> None:
    project(tmp_path, "CW106 mcp.json -- sandbox needs it\n")
    main(["scan", str(tmp_path), "--format", "json"])
    report = json.loads(capsys.readouterr().out)
    assert [f["rule"]["id"] for f in report["findings"]] == ["CW111"]
    [suppressed] = report["suppressed"]
    assert suppressed["rule"]["id"] == "CW106"
    assert suppressed["reason"] == "sandbox needs it"
    assert suppressed["ignore_line"] == 1
    assert report["ignore"]["file"] == ".configwarden-ignore"


def test_sarif_leaves_suppressed_findings_out(tmp_path, capsys) -> None:
    project(tmp_path, "CW106 mcp.json -- sandbox needs it\n")
    main(["scan", str(tmp_path), "--format", "sarif"])
    run = json.loads(capsys.readouterr().out)["runs"][0]
    assert [r["ruleId"] for r in run["results"]] == ["CW111"]
    assert run["properties"]["suppressedResults"] == 1


def test_large_or_special_ignore_files_are_refused(tmp_path, capsys) -> None:
    project(tmp_path)
    (tmp_path / ".configwarden-ignore").write_text(
        "CW106 mcp.json -- sandbox\n" * 20_000, encoding="utf-8"
    )
    assert main(["scan", str(tmp_path)]) == EXIT_FINDINGS
    assert "too large" in capsys.readouterr().out
