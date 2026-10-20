"""Tests v0.4.0 (20 octobre 2026) : corrections mesurées sur le corpus de 3 099 exemples.

- CW102 : les paquets installés EN PLUS du serveur (`uvx --with`, `uv run --with`,
  2e `npx -p`) sont vérifiés aussi. Le corpus en contient 13, aucun n'est figé.
- CW106 : seules les options de `docker run` placées AVANT l'image comptent ; après
  l'image, ce sont les arguments du programme lancé dans le conteneur. Si la ligne ne
  peut pas être lue avec certitude, toute la ligne est vérifiée, comme avant.
"""

import pytest

from configwarden import containers
from configwarden.rules import mcp
from configwarden.scanner import scan
from tests.conftest import fake_secret


def findings_for(write_mcp, command: str, args: list[str]):
    return scan(write_mcp({"s": {"command": command, "args": args}})).findings


def ids_for(write_mcp, command: str, args: list[str]) -> list[str]:
    return sorted(f.rule.id for f in findings_for(write_mcp, command, args))


# --- CW102 : paquets ajoutés à côté du serveur --------------------------------------------


@pytest.mark.parametrize(
    ("command", "args", "unpinned"),
    [
        ("uvx", ["--with", "psycopg2-binary", "mcp-alchemy==1.0"], ["psycopg2-binary"]),
        ("uvx", ["--with=pymysql", "mcp-alchemy==1.0"], ["pymysql"]),
        ("uvx", ["--with", "a==1.0,b", "srv==1.0"], ["b"]),
        ("uvx", ["--with", "pkg>=1,<2", "srv==1.0"], ["pkg>=1,<2"]),
        ("uv", ["tool", "run", "--with", "oracledb", "srv==1.0"], ["oracledb"]),
        ("uv", ["run", "--with", "psycopg2-binary", "server.py"], ["psycopg2-binary"]),
        ("uv", ["run", "--with", "mcp", "mcp", "run", "server.py"], ["mcp"]),
        # Configuration écrite par « mcp install » (SDK Python officiel). Les extras de
        # PEP 508 sont un vrai paquet, pas un modèle « [À REMPLIR] » (vu au corpus).
        ("uv", ["run", "--with", "mcp[cli]", "mcp", "run", "server.py"], ["mcp[cli]"]),
        ("uvx", ["--with", "psycopg[binary,pool]", "srv==1.0"], ["psycopg[binary,pool]"]),
        ("npx", ["-y", "-p", "@scope/srv@1.2.3", "-p", "helper", "srv"], ["helper"]),
        ("bash", ["-c", "cd x && uvx --with pymssql srv==1.0"], ["pymssql"]),
    ],
)
def test_extra_packages_must_be_pinned(write_mcp, command, args, unpinned) -> None:
    findings = [f for f in findings_for(write_mcp, command, args) if f.rule.id == "CW102"]
    assert len(findings) == len(unpinned)
    for finding, package in zip(findings, unpinned, strict=True):
        assert f"also installs '{package}' without a pinned version" in finding.message


@pytest.mark.parametrize(
    ("command", "args"),
    [
        ("uvx", ["--with", "psycopg2-binary==2.9.10", "mcp-alchemy==1.0"]),
        ("uvx", ["--with", "a==1.0,b==2.0", "srv==1.0"]),
        ("uvx", ["--with-editable", "./plugins/local", "srv==1.0"]),
        ("uvx", ["--with", "./wheels/helper.whl", "srv==1.0"]),
        # Après le paquet, ce sont les arguments du serveur, pas des options d'uvx.
        ("uvx", ["srv==1.0", "--with", "anything"]),
        ("npx", ["-y", "-p", "@scope/srv@1.2.3", "-p", "helper@2.0.0", "srv"]),
        ("npx", ["-y", "@scope/srv@1.2.3", "-p", "not-an-npx-option"]),
        ("uv", ["run", "--with", "psycopg2-binary==2.9.10", "server.py"]),
        ("uvx", ["--with", "${DB_DRIVER}", "srv==1.0"]),  # variable : rien à figer ici
        ("uv", ["run", "--with", "$PACKAGE", "server.py"]),
        ("uvx", ["--with", "<your-driver>", "srv==1.0"]),
        ("uvx", ["--with", "[YOUR DRIVER]", "srv==1.0"]),
        ("uvx", ["--with", "psycopg[binary]==3.2.1", "srv==1.0"]),
        # Après le paquet, « -p 3000 » est une option du serveur (son port), pas de npx.
        ("npx", ["-y", "some-server@1.2.3", "-p", "3000"]),
        ("uvx", ["srv==1.0", "--from", "git+https://github.com/x/y"]),
    ],
)
def test_pinned_or_local_extras_are_fine(write_mcp, command, args) -> None:
    assert ids_for(write_mcp, command, args) == []


@pytest.mark.parametrize(
    ("value", "parts"),
    [
        ("a==1,b", ["a==1", "b"]),
        ("pkg>=1,<2", ["pkg>=1,<2"]),
        ("pkg>=1, <2", ["pkg>=1, <2"]),
        ("pkg==1.4,~=1.4.2", ["pkg==1.4,~=1.4.2"]),
        ("psycopg[binary,pool],b", ["psycopg[binary,pool]", "b"]),
        ("a,./local", ["a", "./local"]),
        ("a, ,b,", ["a", "b"]),
    ],
)
def test_requirements_are_split_like_uv(value, parts) -> None:
    # Comportement relevé avec uv 0.11 (« uv run --offline --with … ») le 20 octobre 2026.
    assert mcp._split_requirements(value) == parts


def test_extra_from_git_is_reported_once_as_untrusted(write_mcp) -> None:
    args = ["--with", "git+https://github.com/evil/helper", "srv==1.0"]
    assert ids_for(write_mcp, "uvx", args) == ["CW107"]


def test_main_and_extra_packages_are_both_reported(write_mcp) -> None:
    assert ids_for(write_mcp, "uvx", ["--with", "helper", "srv"]) == ["CW102", "CW102"]


# --- CW106 : options de docker run seulement ---------------------------------------------


@pytest.mark.parametrize(
    "args",
    [
        ["run", "-i", "--rm", "org/server:1.2.3", "--privileged"],
        ["run", "-i", "--rm", "org/server:1.2.3", "-v", "/:/host"],
        ["run", "-i", "--rm", "org/server:1.2.3", "--network", "host"],
        ["run", "-i", "--rm", "org/server:1.2.3", "--cap-add", "SYS_ADMIN"],
    ],
)
def test_arguments_after_the_image_are_not_docker_options(write_mcp, args) -> None:
    assert ids_for(write_mcp, "docker", args) == []


@pytest.mark.parametrize(
    "args",
    [
        ["run", "--privileged", "org/server:1.2.3"],
        ["run", "-i", "-v", "/:/host", "org/server:1.2.3", "serve"],
        ["run", "--privileged"],  # pas d'image : toute la ligne est vérifiée
        ["run", "--future-option", "x", "--privileged", "org/server:1.2.3"],  # ligne illisible
        ["--context", "prod", "run", "--pid=host", "org/server:1.2.3"],
    ],
)
def test_options_before_the_image_are_still_checked(write_mcp, args) -> None:
    assert ids_for(write_mcp, "docker", args) == ["CW106"]


def test_podman_rootfs_falls_back_to_the_whole_line(write_mcp) -> None:
    args = ["run", "--privileged", "--rootfs", "/srv/rootfs", "server"]
    assert ids_for(write_mcp, "podman", args) == ["CW106"]


def test_run_options_contract() -> None:
    assert containers.run_options("docker", ["run", "-i", "--rm", "img:1.0", "--x"]) == [
        "-i",
        "--rm",
    ]
    assert containers.run_options("docker", ["--context", "c", "container", "run", "img"]) == []
    assert containers.run_options("docker", ["run", "-i", "--", "img:1.0"]) == ["-i"]
    assert containers.run_options("docker", ["run", "--future", "x", "img"]) is None
    assert containers.run_options("docker", ["exec", "c"]) is None


def test_hypothesis_cache_is_not_scanned(tmp_path) -> None:
    # Hypothesis range des constantes du code (et des chemins locaux) dans .hypothesis/.
    (tmp_path / ".hypothesis" / "constants").mkdir(parents=True)
    (tmp_path / ".hypothesis" / "constants" / "x").write_text(fake_secret("ghp_", 36))
    assert scan(tmp_path).findings == []
