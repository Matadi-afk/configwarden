from pathlib import Path, PurePosixPath

import pytest

from configwarden.rules import mcp
from configwarden.scanner import scan

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def rule_ids(path: Path) -> list[str]:
    return sorted(f.rule.id for f in scan(path).findings)


# --- CW101 : shell --------------------------------------------------------------


@pytest.mark.parametrize(
    ("command", "args"),
    [
        ("bash", ["-c", "echo hi"]),
        ("/bin/sh", ["-c", "x"]),
        # cmd /c avec un caractère spécial (décision du 8 octobre 2026 : sans caractère
        # spécial, cmd /c n'est plus signalé et la commande lancée est analysée).
        ("C:\\Windows\\cmd.exe", ["/c", "x & y"]),
    ],
)
def test_shell_execution_is_flagged(write_mcp, command, args) -> None:
    assert rule_ids(write_mcp({"s": {"command": command, "args": args}})) == ["CW101"]


def test_direct_binary_is_fine(write_mcp) -> None:
    assert rule_ids(write_mcp({"s": {"command": "/usr/local/bin/my-server", "args": []}})) == []


# --- CW102 : versions non figées ------------------------------------------------


@pytest.mark.parametrize(
    "package",
    ["@modelcontextprotocol/server-github", "some-server", "@scope/pkg@latest", "pkg@next"],
)
def test_unpinned_npx_package_is_flagged(write_mcp, package) -> None:
    assert rule_ids(write_mcp({"s": {"command": "npx", "args": ["-y", package]}})) == ["CW102"]


@pytest.mark.parametrize("package", ["@scope/pkg@1.2.3", "some-server@0.4.0"])
def test_pinned_npx_package_is_fine(write_mcp, package) -> None:
    assert rule_ids(write_mcp({"s": {"command": "npx", "args": ["-y", package]}})) == []


@pytest.mark.parametrize(
    ("package", "expected"), [("mcp-server==1.0", []), ("mcp-server", ["CW102"])]
)
def test_uvx_pinning(write_mcp, package, expected) -> None:
    assert rule_ids(write_mcp({"s": {"command": "uvx", "args": [package]}})) == expected


# --- CW103 : secrets dans env / headers -----------------------------------------


def test_literal_token_in_env_is_flagged_and_redacted(write_mcp) -> None:
    path = write_mcp({"s": {"command": "srv", "env": {"API_TOKEN": "my-literal-value-123"}}})
    findings = scan(path).findings
    assert [f.rule.id for f in findings] == ["CW103"]
    assert "my-literal-value-123" not in findings[0].message


@pytest.mark.parametrize(
    "value", ["${API_TOKEN}", "${env:API_TOKEN}", "$API_TOKEN", "${input:token}", "Bearer ${TOKEN}"]
)
def test_env_references_are_fine(write_mcp, value) -> None:
    path = write_mcp({"s": {"command": "srv", "env": {"API_TOKEN": value}}})
    assert rule_ids(path) == []


def test_non_sensitive_env_is_ignored(write_mcp) -> None:
    path = write_mcp({"s": {"command": "srv", "env": {"LOG_LEVEL": "debug"}}})
    assert rule_ids(path) == []


# --- CW104 : accès disque trop large --------------------------------------------


@pytest.mark.parametrize("folder", ["/", "~", "~/", "C:\\", "${userHome}"])
def test_broad_filesystem_access_is_flagged(write_mcp, folder) -> None:
    args = ["-y", "@modelcontextprotocol/server-filesystem@1.0.0", folder]
    assert rule_ids(write_mcp({"fs": {"command": "npx", "args": args}})) == ["CW104"]


def test_project_folder_access_is_fine(write_mcp) -> None:
    args = ["-y", "@modelcontextprotocol/server-filesystem@1.0.0", "./data"]
    assert rule_ids(write_mcp({"fs": {"command": "npx", "args": args}})) == []


# --- CW105 : HTTP non chiffré ---------------------------------------------------


def test_plain_http_remote_is_flagged(write_mcp) -> None:
    assert rule_ids(write_mcp({"r": {"url": "http://mcp.example.com/sse"}})) == ["CW105"]


@pytest.mark.parametrize("url", ["https://mcp.example.com", "http://localhost:3000/mcp"])
def test_https_and_localhost_are_fine(write_mcp, url) -> None:
    assert rule_ids(write_mcp({"r": {"url": url}})) == []


# --- CW106 : conteneur qui casse son isolation ----------------------------------


@pytest.mark.parametrize(
    "dangerous",
    [
        ["--privileged"],
        ["--network", "host"],
        ["--net=host"],
        ["--pid=host"],
        ["-v", "/:/host"],
        ["-v", "/var/run/docker.sock:/var/run/docker.sock"],
        ["--volume=${HOME}:/home"],
        ["-v", "C:\\:/c"],
        ["--mount", "type=bind,source=/,target=/host"],
        ["--cap-add", "SYS_ADMIN"],
        ["--security-opt", "seccomp=unconfined"],
    ],
    ids=lambda flags: " ".join(flags),
)
def test_dangerous_container_is_flagged(write_mcp, dangerous) -> None:
    args = ["run", "-i", "--rm", *dangerous, "mcp/server:1.0"]
    assert rule_ids(write_mcp({"c": {"command": "docker", "args": args}})) == ["CW106"]


def test_each_dangerous_option_is_reported(write_mcp) -> None:
    args = ["run", "--privileged", "-v", "/:/host", "mcp/server:1.0"]
    assert rule_ids(write_mcp({"c": {"command": "podman", "args": args}})) == ["CW106", "CW106"]


def test_nerdctl_is_checked(write_mcp) -> None:
    args = ["run", "--privileged", "mcp/server:1.0"]
    assert rule_ids(write_mcp({"c": {"command": "nerdctl", "args": args}})) == ["CW106"]


@pytest.mark.parametrize(
    "safe",
    [
        ["-v", "./data:/data:ro"],
        ["-v", "C:\\projets\\data:/data"],
        ["--network", "bridge"],
        ["--cap-add", "NET_BIND_SERVICE"],
        ["-e", "GITHUB_TOKEN"],
    ],
    ids=lambda flags: " ".join(flags),
)
def test_safe_container_is_fine(write_mcp, safe) -> None:
    args = ["run", "-i", "--rm", *safe, "mcp/server:1.0"]
    assert rule_ids(write_mcp({"c": {"command": "docker", "args": args}})) == []


def test_docker_without_run_is_ignored(write_mcp) -> None:
    args = ["exec", "--privileged", "my-container", "server"]
    assert rule_ids(write_mcp({"c": {"command": "docker", "args": args}})) == []


# --- CW107 : paquet de source non vérifiée --------------------------------------


@pytest.mark.parametrize(
    ("command", "args"),
    [
        ("npx", ["-y", "github:someone/mcp-server"]),
        ("npx", ["-y", "git+https://github.com/someone/mcp-server.git"]),
        ("npx", ["-y", "https://example.com/mcp-server-1.0.0.tgz"]),
        ("uvx", ["--from", "git+https://github.com/someone/mcp-server", "mcp-server"]),
        ("uvx", ["--from=git+https://github.com/someone/mcp-server", "mcp-server"]),
    ],
)
def test_untrusted_package_source_is_flagged(write_mcp, command, args) -> None:
    # CW107 remplace CW102 : une seule alerte pour un seul problème.
    assert rule_ids(write_mcp({"s": {"command": command, "args": args}})) == ["CW107"]


def test_url_given_to_the_server_is_not_a_package_source(write_mcp) -> None:
    args = ["-y", "@modelcontextprotocol/server-fetch@1.0.0", "https://example.com"]
    assert rule_ids(write_mcp({"s": {"command": "npx", "args": args}})) == []


# --- CW108 : outils approuvés automatiquement -----------------------------------


@pytest.mark.parametrize("key", ["alwaysAllow", "autoApprove"])
def test_auto_approved_tools_are_flagged(write_mcp, key) -> None:
    path = write_mcp({"s": {"command": "srv", key: ["write_file", "run_command"]}})
    findings = scan(path).findings
    assert [f.rule.id for f in findings] == ["CW108"]
    assert "2 tool(s)" in findings[0].message


def test_trusted_server_is_flagged(write_mcp) -> None:
    assert rule_ids(write_mcp({"s": {"command": "srv", "trust": True}})) == ["CW108"]


@pytest.mark.parametrize("server", [{"alwaysAllow": []}, {"trust": False}, {}])
def test_confirmation_kept_is_fine(write_mcp, server) -> None:
    assert rule_ids(write_mcp({"s": {"command": "srv", **server}})) == []


# --- Formats et fichiers --------------------------------------------------------


def test_vscode_servers_format_is_supported(write_mcp) -> None:
    path = write_mcp({"r": {"url": "http://evil.example"}}, name=".vscode/mcp.json", key="servers")
    assert rule_ids(path) == ["CW105"]


def test_invalid_json_is_reported(tmp_path) -> None:
    (tmp_path / "mcp.json").write_text("{ not json", encoding="utf-8")
    assert rule_ids(tmp_path) == ["CW100"]


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("mcp.json", True),
        (".mcp.json", True),
        ("claude_desktop_config.json", True),
        ("team.mcp.json", True),
        ("package.json", False),
    ],
)
def test_mcp_file_detection(name, expected) -> None:
    assert mcp.is_mcp_config(PurePosixPath(name)) is expected


# --- Exemples fournis avec le projet --------------------------------------------


def test_vulnerable_example_triggers_every_mcp_rule() -> None:
    ids = set(rule_ids(EXAMPLES / "vulnerable-mcp"))
    expected = {f"CW{number}" for number in range(101, 114)}  # CW101 à CW113
    assert expected <= ids


def test_safe_example_is_clean() -> None:
    assert rule_ids(EXAMPLES / "safe-mcp") == []
