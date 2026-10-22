"""Tests de durcissement : configwarden face à des fichiers MALVEILLANTS.

Un outil de sécurité lit des fichiers écrits par n'importe qui. Ces tests
reproduisent trois attaques trouvées lors de la revue de sécurité du
7 octobre 2026, corrigées en version 0.2.1 :

- V1 : fuite d'identifiants (« user:token@ ») recopiés dans les rapports ;
- V2 : injection de caractères de contrôle dans la sortie (sauts de ligne,
  codes ANSI, commandes de workflow GitHub Actions « ::… ») ;
- V3 : plantage du scan sur un JSON imbriqué à l'extrême (déni de service).
"""

import json
import os
import threading
import time

import pytest

from configwarden import scanner as scanner_module
from configwarden.cli import main
from configwarden.models import Finding
from configwarden.redact import redact, redact_url, sanitize
from configwarden.reporters.text import render_text
from configwarden.rules import mcp
from configwarden.rules.mcp import INSECURE_TRANSPORT
from configwarden.scanner import ScanResult, scan
from tests.conftest import fake_secret

# Faux identifiant assemblé à l'exécution (jamais écrit en clair dans le dépôt).
FAKE_TOKEN = fake_secret("tok", 24)

# Caractères invisibles construits avec chr() : jamais écrits tels quels dans
# le code source (un formateur pourrait les « dé-échapper »).
RLO = chr(0x202E)  # inverse le sens d'affichage (attaque « Trojan Source »)
LINE_SEP = chr(0x2028)  # séparateur de ligne Unicode


# --- V1 : identifiants dans les URL ---------------------------------------------


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("git+https://alice:SECRET@github.com/x/y.git", "git+https://****@github.com/x/y.git"),
        ("https://SECRET@example.com/pkg.tgz", "https://****@example.com/pkg.tgz"),
        ("https://example.com/pkg.tgz", "https://example.com/pkg.tgz"),
        ("github:someone/repo", "github:someone/repo"),
        ("git@github.com:someone/repo.git", "git@github.com:someone/repo.git"),
        ("@scope/pkg@1.2.3", "@scope/pkg@1.2.3"),
    ],
)
def test_redact_url(url, expected) -> None:
    assert redact_url(url) == expected


@pytest.mark.parametrize(
    "args",
    [
        ["-y", f"git+https://alice:{FAKE_TOKEN}@github.com/x/y.git"],
        ["-y", f"https://{FAKE_TOKEN}@example.com/server-1.0.0.tgz"],
    ],
)
def test_credentials_in_package_url_never_reach_any_report(write_mcp, tmp_path, capsys, args):
    path = write_mcp({"s": {"command": "npx", "args": args}})
    for fmt in ("text", "json", "sarif"):
        main(["scan", str(path), "--format", fmt])
        out = capsys.readouterr().out
        assert FAKE_TOKEN not in out, f"token leaked in {fmt} output"
        assert "://" in out and "/…" in out  # seule l'origine de l'URL est affichée


def test_credentials_in_uvx_from_are_redacted(write_mcp) -> None:
    # v0.3.0 : le jeton écrit dans l'URL est aussi un secret en clair (CW103).
    args = ["--from", f"git+https://bob:{FAKE_TOKEN}@gitlab.com/x/y", "server"]
    findings = scan(write_mcp({"s": {"command": "uvx", "args": args}})).findings
    assert sorted(f.rule.id for f in findings) == ["CW103", "CW107"]
    assert all(FAKE_TOKEN not in f.message for f in findings)


# --- V2 : caractères de contrôle dans la sortie ---------------------------------

HOSTILE_NAME = "evil\n::error title=PWNED::fake\r\x1b[2J\x1b]52;c;ZXZpbA==\x07" + RLO


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("normal text", "normal text"),
        ("a\nb", "a\\nb"),
        ("a\rb\tc", "a\\rb\\tc"),
        ("\x1b[31m", "\\x1b[31m"),
        ("\x7f", "\\x7f"),
        ("\x9b", "\\x9b"),
        (f"abc{RLO}def", "abc\\u202edef"),
        (f"line{LINE_SEP}sep", "line\\u2028sep"),
        ("accents éàü 🔒", "accents éàü 🔒"),
    ],
)
def test_sanitize(raw, expected) -> None:
    assert sanitize(raw) == expected


def test_finding_message_and_path_are_sanitized_at_creation() -> None:
    finding = Finding(rule=INSECURE_TRANSPORT, path="a\nb.json", line=1, message="x\x1by")
    assert finding.path == "a\\nb.json"
    assert finding.message == "x\\x1by"


def test_hostile_server_name_cannot_inject_lines_or_escape_codes(write_mcp) -> None:
    path = write_mcp({HOSTILE_NAME: {"url": "http://evil.example"}})
    result = scan(path)
    assert [f.rule.id for f in result.findings] == ["CW105"]
    for color in (False, True):
        out = render_text(result, color=color)
        # Aucune ligne ne peut commencer par une commande de workflow GitHub Actions.
        assert not any(line.lstrip().startswith("::") for line in out.splitlines())
        # Aucun code d'échappement injecté (les seuls autorisés sont nos couleurs).
        assert "\x1b[2J" not in out and "\x1b]52" not in out and RLO not in out


def test_hostile_file_path_is_sanitized_in_text_report() -> None:
    finding = Finding(rule=INSECURE_TRANSPORT, path="x\n::warning::y.json", line=1, message="m")
    out = render_text(ScanResult(findings=[finding], files_scanned=1))
    assert not any(line.lstrip().startswith("::") for line in out.splitlines())


# --- V3 : déni de service par JSON trop imbriqué --------------------------------


def test_deeply_nested_json_does_not_crash_the_scan(tmp_path) -> None:
    depth = 200_000
    (tmp_path / "mcp.json").write_text("[" * depth + "]" * depth, encoding="utf-8")
    (tmp_path / "app.py").write_text("token = '" + fake_secret("ghp_", 36) + "'\n")
    ids = sorted(f.rule.id for f in scan(tmp_path).findings)
    # Le fichier piégé est signalé comme illisible ET le reste du projet est analysé.
    assert ids == ["CW001", "CW100"]


@pytest.mark.parametrize(
    "text",
    [
        "[]",
        "null",
        '"just a string"',
        '{"mcpServers": null}',
        '{"mcpServers": {"a": 5}}',
        '{"mcp": 3}',
        '{"servers": {"a": {"args": "notalist", "env": [1, 2]}}}',
        '{"mcpServers": {"a": {"command": 7, "url": 9, "alwaysAllow": "x", "trust": "yes"}}}',
        '{"mcpServers": {"a": {"command": "docker", "args": ["run", "-v"]}}}',
        '{"mcpServers": {"a": {"command": "npx", "args": ["--from"]}}}',
    ],
)
def test_malformed_but_valid_json_never_crashes(text) -> None:
    mcp.check_text(text, "mcp.json")  # ne doit lever aucune exception


def test_sarif_output_stays_valid_json_with_hostile_input(write_mcp, capsys) -> None:
    path = write_mcp({HOSTILE_NAME: {"url": "http://evil.example"}})
    main(["scan", str(path), "--format", "sarif"])
    sarif = json.loads(capsys.readouterr().out)
    assert sarif["runs"][0]["results"][0]["ruleId"] == "CW105"


# --- Garde-fou permanent : pas de caractères invisibles dans notre propre code ---


def test_no_invisible_or_bidi_characters_in_source() -> None:
    """Empêche une attaque « Trojan Source » contre configwarden lui-même."""
    from pathlib import Path

    from configwarden.redact import sanitize as _sanitize

    root = Path(__file__).resolve().parent.parent
    offenders = []
    for path in [*root.glob("src/**/*.py"), *root.glob("tests/**/*.py")]:
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if _sanitize(line.replace("\t", " ")) != line.replace("\t", " "):
                offenders.append(f"{path.name}:{number}")
    assert offenders == []


# =============================================================================
# Revue de sécurité indépendante du 7 octobre 2026 (corrigée en 0.2.2)
# =============================================================================

# --- V4 : identifiants qui échappaient encore à redact_url ------------------------


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://jane@corp.com:SECRET@host/p.tgz", "https://****@host/p.tgz"),
        ("git+https://jane:ab/SECRET@github.com/x/y.git", "git+https://****@github.com/x/y.git"),
        ("https://h.example/x.whl?private_token=SECRET", "https://h.example/x.whl?****"),
        ("https://h.example/p.tgz#SECRET", "https://h.example/p.tgz#****"),
        ("srv @ git+https://u:SECRET@h.example/x", "srv @ git+https://****@h.example/x"),
    ],
    ids=["two-at", "slash-in-password", "query", "fragment", "pep508"],
)
def test_redact_url_hard_cases(url, expected) -> None:
    assert redact_url(url) == expected


@pytest.mark.parametrize(
    "server",
    [
        {"command": "npx", "args": ["-y", f"https://jane@corp.com:{FAKE_TOKEN}@h.example/p.tgz"]},
        {"command": "npx", "args": ["-y", f"git+https://jane:ab/{FAKE_TOKEN}@github.com/x/y"]},
        {"command": "npx", "args": ["-y", f"https://h.example/p.tgz?token={FAKE_TOKEN}"]},
        {
            "command": "uvx",
            "args": ["--from", f"https://h.example/x.whl?private_token={FAKE_TOKEN}", "srv"],
        },
    ],
    ids=["two-at", "slash-in-password", "npx-query", "uvx-query"],
)
def test_token_in_unusual_url_never_reaches_any_report(write_mcp, capsys, server) -> None:
    path = write_mcp({"s": server})
    for fmt in ("text", "json", "sarif"):
        main(["scan", str(path), "--format", fmt])
        assert FAKE_TOKEN not in capsys.readouterr().out, f"token leaked in {fmt} output"


# --- V5 : une URL malformée faisait planter tout le scan ------------------------


def test_malformed_url_does_not_crash_the_scan(tmp_path) -> None:
    (tmp_path / "mcp.json").write_text('{"mcpServers": {"bad": {"url": "http://[broken"}}}')
    (tmp_path / "app.py").write_text("token = '" + fake_secret("ghp_", 36) + "'\n")
    ids = sorted(f.rule.id for f in scan(tmp_path).findings)
    # Le serveur reste signalé (http://) ET le reste du projet est analysé.
    assert ids == ["CW001", "CW105"]


def test_malformed_url_never_echoes_its_credentials(write_mcp, capsys) -> None:
    # Le message d'erreur de urlparse recopiait l'URL entière, mot de passe compris.
    url = f"http://admin:{FAKE_TOKEN}@host" + chr(0x1B) + "c" + chr(0xFF03) + "x/"
    path = write_mcp({"s": {"url": url}})
    main(["scan", str(path)])
    captured = capsys.readouterr()
    assert FAKE_TOKEN not in captured.out + captured.err


def test_one_broken_server_does_not_hide_the_others(write_mcp, monkeypatch) -> None:
    real_check = mcp._check_server

    def flaky(name, server, *args):
        if name == "boom":
            raise RuntimeError("unexpected")
        return real_check(name, server, *args)

    monkeypatch.setattr(mcp, "_check_server", flaky)
    path = write_mcp({"boom": {"url": "http://a.example"}, "ok": {"url": "http://b.example"}})
    assert sorted(f.rule.id for f in scan(path).findings) == ["CW100", "CW105"]


# --- V6 : caractères Unicode invalides ou invisibles dans la sortie -------------


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        (0xD800, "\\ud800"),  # moitié de paire (surrogate) : rendait le rapport impossible
        (0x200B, "\\u200b"),  # espace de largeur nulle
        (0xFEFF, "\\ufeff"),  # BOM invisible
        (0x00AD, "\\xad"),  # trait d'union conditionnel
        (0xE0041, "\\U000e0041"),  # caractère « tag » : texte caché lisible par une IA
    ],
)
def test_sanitize_escapes_invisible_and_invalid_characters(code, expected) -> None:
    assert sanitize("a" + chr(code) + "b") == "a" + expected + "b"


@pytest.mark.parametrize("fmt", ["text", "json", "sarif"])
def test_surrogate_in_server_name_still_produces_a_report(tmp_path, fmt) -> None:
    # « \ud800 » est écrit avec un antislash : le fichier lui-même reste du JSON valide.
    (tmp_path / "mcp.json").write_text('{"mcpServers": {"\\ud800": {"url": "http://e.example"}}}')
    report = tmp_path / "out.txt"
    assert main(["scan", str(tmp_path), "--format", fmt, "--output", str(report)]) == 1
    content = report.read_text(encoding="utf-8")
    assert "CW105" in content
    if fmt != "text":
        json.loads(content)


# --- V7 : --output ne doit jamais écrire à travers un lien symbolique -----------


def test_output_refuses_to_follow_a_symlink(tmp_path, capsys) -> None:
    victim = tmp_path / "victim.txt"
    victim.write_text("precious")
    project = tmp_path / "repo"
    project.mkdir()
    link = project / "configwarden.sarif"
    try:
        os.symlink(victim, link)
    except (OSError, NotImplementedError):
        pytest.skip("symbolic links not available on this system")
    code = main(["scan", str(project), "--format", "sarif", "--output", str(link)])
    assert code == 2
    assert victim.read_text() == "precious"
    assert "symbolic link" in capsys.readouterr().err


# --- V8 : lenteur provoquée (calcul des numéros de ligne en temps quadratique) --


def test_many_servers_are_scanned_quickly(tmp_path) -> None:
    # 20 000 serveurs aux noms échappés : 35 s avant la correction, < 1 s après.
    servers = ",".join(f'"\\u0073{i}": {{"command": "srv"}}' for i in range(20_000))
    (tmp_path / "mcp.json").write_text('{"mcpServers": {' + servers + "}}")
    start = time.perf_counter()
    scan(tmp_path)
    assert time.perf_counter() - start < 10


def test_line_numbers_follow_real_lines_only(tmp_path) -> None:
    # \x0c (saut de page) n'est pas une fin de ligne pour un éditeur ni pour GitHub.
    text = "a = 1\x0c2\nkey = '" + fake_secret("ghp_", 36) + "'\n"
    (tmp_path / "app.py").write_text(text)
    assert [f.line for f in scan(tmp_path).findings] == [2]


def test_escaped_server_name_gets_the_right_line(tmp_path) -> None:
    text = (
        '{\n  "mcpServers": {\n    "a": {"command": "srv"},\n'
        '    "\\u0062": {"url": "http://x.example"}\n  }\n}'
    )
    (tmp_path / "mcp.json").write_text(text)
    assert [(f.rule.id, f.line) for f in scan(tmp_path).findings] == [("CW105", 4)]


# --- V9 : fichiers spéciaux et dossiers illisibles ------------------------------


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO not available on this system")
def test_fifo_does_not_hang_the_scan(tmp_path) -> None:
    os.mkfifo(tmp_path / "pipe.json")
    (tmp_path / "app.py").write_text("token = '" + fake_secret("ghp_", 36) + "'\n")
    outcome: list = []
    worker = threading.Thread(target=lambda: outcome.append(scan(tmp_path)), daemon=True)
    worker.start()
    worker.join(timeout=10)
    assert not worker.is_alive(), "scan blocked on a FIFO"
    assert [f.rule.id for f in outcome[0].findings] == ["CW001"]
    assert outcome[0].files_skipped == 1


def test_unreadable_directory_is_counted_as_skipped(tmp_path, monkeypatch) -> None:
    real_walk = os.walk

    def walk_with_error(top, *args, onerror=None, **kwargs):
        assert onerror is not None, "os.walk errors must be reported, not silently ignored"
        onerror(PermissionError(13, "Permission denied", str(top)))
        return real_walk(top, *args, onerror=onerror, **kwargs)

    monkeypatch.setattr(scanner_module.os, "walk", walk_with_error)
    assert scan(tmp_path).files_skipped == 1


# --- V10 : masquage des secrets courts et faux positif « PATH » -----------------


def test_short_secret_reveals_nothing() -> None:
    assert redact("Winter2026!") == "****"
    assert redact(fake_secret("sk-ant-", 30)).startswith("sk-a****")


@pytest.mark.parametrize(
    ("key", "expected"),
    [("PATH", []), ("GITHUB_PAT", ["CW103"]), ("DB_PASS", ["CW103"]), ("DB_PASSWORD", ["CW103"])],
)
def test_sensitive_env_key_detection(write_mcp, key, expected) -> None:
    path = write_mcp({"s": {"command": "srv", "env": {key: "literal-value-0123456789"}}})
    assert [f.rule.id for f in scan(path).findings] == expected


# --- V11 : emplacements SARIF valides -------------------------------------------


def test_sarif_uri_is_percent_encoded(tmp_path, capsys) -> None:
    (tmp_path / "a #b.mcp.json").write_text('{"mcpServers": {"s": {"url": "http://x.example"}}}')
    main(["scan", str(tmp_path), "--format", "sarif"])
    sarif = json.loads(capsys.readouterr().out)
    location = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "a%20%23b.mcp.json"


# --- Contre-vérification de la revue (N1 à N4) ----------------------------------


@pytest.mark.parametrize(
    "args",
    [
        ["-y", f"https://jane:Rock'n'{FAKE_TOKEN}@npm.corp.example/pkg-1.0.0.tgz"],
        ["-y", f"https://jane:my {FAKE_TOKEN}@npm.corp.example/pkg-1.0.0.tgz"],
        ["-y", f"https://jane:my\t{FAKE_TOKEN}@npm.corp.example/pkg-1.0.0.tgz"],
        ["-y", f"https://npm.corp.example/{FAKE_TOKEN}/pkg-1.0.0.tgz"],
    ],
    ids=["quote", "space", "tab", "token-in-path"],
)
def test_ag107_shows_only_the_origin_of_the_url(write_mcp, capsys, args) -> None:
    path = write_mcp({"s": {"command": "npx", "args": args}})
    for fmt in ("text", "json", "sarif"):
        main(["scan", str(path), "--format", fmt])
        out = capsys.readouterr().out
        assert FAKE_TOKEN not in out, f"token leaked in {fmt} output"
        assert "https://npm.corp.example/" in out


@pytest.mark.parametrize(
    ("command", "args"),
    [
        ("npx", ["--registry", f"https://npm-proxy.example/{FAKE_TOKEN}/", "@acme/mcp@1.0.0"]),
        ("uvx", ["--index-url", f"https://pypi.example/{FAKE_TOKEN}/", "acme-mcp==1.0"]),
        ("uvx", ["-p", "3.12", "acme-mcp==1.0"]),
        ("uvx", ["--from", "acme-mcp==1.0", "acme-server"]),
    ],
    ids=["npx-registry", "uvx-index-url", "uvx-python", "uvx-from-pinned"],
)
def test_option_values_are_not_taken_for_the_package(write_mcp, command, args) -> None:
    findings = scan(write_mcp({"s": {"command": command, "args": args}})).findings
    # Depuis le 21 octobre 2026, un registre non officiel est signalé (CW112), sans que
    # le jeton de son adresse apparaisse ; la valeur de l'option n'est jamais lue comme
    # un paquet (pas de CW102 ni de CW107).
    assert {f.rule.id for f in findings} <= {"CW112"}
    assert not any(FAKE_TOKEN in f.message for f in findings)


def test_uvx_with_git_dependency_is_flagged(write_mcp) -> None:
    args = ["--with", "git+https://github.com/someone/helper", "acme-mcp==1.0"]
    assert [
        f.rule.id for f in scan(write_mcp({"s": {"command": "uvx", "args": args}})).findings
    ] == ["CW107"]


def test_escaped_quotes_cannot_slow_down_line_numbers(tmp_path) -> None:
    # Avant : 80 Ko de « \" » = 42 s (temps quadratique). Après : quelques ms.
    note = '\\"' * 40_000
    text = '{"mcpServers": {"s": {"url": "http://x.example"}}, "note": "' + note + '"}'
    (tmp_path / "mcp.json").write_text(text)
    start = time.perf_counter()
    findings = scan(tmp_path).findings
    assert time.perf_counter() - start < 5
    assert [f.rule.id for f in findings] == ["CW105"]


def test_output_refuses_a_symlinked_parent_directory(tmp_path, capsys, monkeypatch) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "configwarden.sarif").write_text("precious")
    project = tmp_path / "repo"
    project.mkdir()
    try:
        os.symlink(outside, project / "reports", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symbolic links not available on this system")
    monkeypatch.chdir(project)
    code = main(["scan", ".", "--format", "sarif", "--output", "reports/configwarden.sarif"])
    assert code == 2
    assert (outside / "configwarden.sarif").read_text() == "precious"


@pytest.mark.parametrize("code", [0xFE00, 0xFE0F, 0xE0100, 0xE01EF, 0x115F, 0x3164, 0xFFA0])
def test_sanitize_escapes_variation_selectors_and_fillers(code) -> None:
    # Des sélecteurs de variante à la suite peuvent cacher un message à un humain
    # tout en restant lisibles par une IA qui lirait le rapport.
    assert chr(code) not in sanitize("ok" + chr(code))


def test_text_report_warns_when_files_were_not_analysed(tmp_path) -> None:
    (tmp_path / "big.json").write_bytes(b"x" * 1_000_001)
    out = render_text(scan(tmp_path))
    assert "No issues found" in out
    assert "could not be analysed" in out


# --- Troisième passe de la revue (R1 à R4) --------------------------------------


@pytest.mark.parametrize(
    ("command", "args"),
    [
        ("npx", ["-f", "git+https://github.com/someone/srv.git"]),
        ("npx", ["--loglevel", "silent", "git+https://github.com/someone/srv.git"]),
        ("uvx", ["--directory", "/srv", "git+https://github.com/someone/srv"]),
        ("uvx", ["--python", "3.12", "--from", "git+https://github.com/someone/srv", "srv"]),
    ],
    ids=["npx-force", "npx-loglevel", "uvx-directory", "uvx-python-from"],
)
def test_options_never_hide_a_git_source(write_mcp, command, args) -> None:
    findings = scan(write_mcp({"s": {"command": command, "args": args}})).findings
    assert [f.rule.id for f in findings] == ["CW107"]


@pytest.mark.parametrize(
    "source",
    [
        f"https://jane:{FAKE_TOKEN}?x@npm.corp.example/p.tgz",
        f"https://jane:{FAKE_TOKEN}#x@npm.corp.example/p.tgz",
        f"github:jane:{FAKE_TOKEN}@someone/srv",
    ],
    ids=["question-mark", "hash", "shorthand"],
)
def test_url_origin_edge_cases_never_leak(write_mcp, capsys, source) -> None:
    path = write_mcp({"s": {"command": "npx", "args": ["-y", source]}})
    main(["scan", str(path)])
    out = capsys.readouterr().out
    assert "CW107" in out
    assert FAKE_TOKEN not in out


def test_output_refuses_parent_directory_components(tmp_path, capsys, monkeypatch) -> None:
    (tmp_path / "reports").mkdir()
    monkeypatch.chdir(tmp_path)
    assert main(["scan", ".", "--output", "reports/../configwarden.sarif"]) == 2
    assert ".." in capsys.readouterr().err
    assert not (tmp_path / "configwarden.sarif").exists()


@pytest.mark.parametrize("code", [0x034F, 0x17B4, 0x17B5, 0xFFF0, 0xE0080, 0xE01F0, 0x1BCA0])
def test_sanitize_escapes_all_default_ignorable_characters(code) -> None:
    assert chr(code) not in sanitize("ok" + chr(code))
