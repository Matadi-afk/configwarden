"""Tests v0.4.0 : toutes les commandes d'un script sont vérifiées, pas seulement la 1re.

Constat du grand test (8 octobre 2026) : dans `bash -c "cd x && npx paquet"`, seule la
1re commande (`cd x`) était lue. CW101 signalait bien le script, mais le paquet non figé
(CW102), la source non vérifiée (CW107), le conteneur dangereux (CW106) ou l'image non
figée (CW111) cachés plus loin passaient inaperçus. Le corpus en contenait 4 exemples.

Limites (sécurité) : au plus 20 commandes en plus par serveur, scripts imbriqués au plus
5 fois, chaque script découpé sur ses 10 000 premiers caractères.
"""

import shlex
import time

import pytest

from configwarden import commands
from configwarden.scanner import scan


def ids_for_server(write_mcp, server: dict) -> list[str]:
    return sorted(f.rule.id for f in scan(write_mcp({"s": server})).findings)


def ids_for(write_mcp, command: str, args: list[str]) -> list[str]:
    return ids_for_server(write_mcp, {"command": command, "args": args})


# --- Ce qui suit la 1re commande est vérifié --------------------------------------------


@pytest.mark.parametrize(
    ("command", "args", "expected"),
    [
        ("bash", ["-c", "cd /srv && npx -y some-server"], ["CW101", "CW102"]),
        (
            "bash",
            ["-c", "source ~/.nvm/nvm.sh 2>/dev/null; exec npx -y some-server@latest"],
            ["CW101", "CW102"],
        ),
        (
            "bash",
            ["-lc", "export NVM_DIR=x && nvm use 20 >/dev/null && npx -y some-server@latest"],
            ["CW101", "CW102"],
        ),
        (
            "bash",
            ["-c", "docker rm -f x >/dev/null 2>&1 || true; docker run -i --rm org/server"],
            ["CW101", "CW111"],
        ),
        (
            "sh",
            ["-c", "cd x && uvx --from git+https://github.com/evil/srv srv"],
            ["CW101", "CW107"],
        ),
        ("bash", ["-c", "cd x; docker run --privileged org/server:1.2.3"], ["CW101", "CW106"]),
        ("bash", ["-c", "cd x | npx -y fs-server filesystem /"], ["CW101", "CW102", "CW104"]),
        ("bash", ["-c", "FOO=1 BAR=2 npx -y some-server"], ["CW101", "CW102"]),
        ("bash", ["-c", "if true; then npx -y some-server; fi"], ["CW101", "CW102"]),
        ("bash", ["-c", "(cd x && npx -y some-server)"], ["CW101", "CW102"]),
        ("bash", ["-c", "{ cd x; npx -y some-server; }"], ["CW101", "CW102"]),
        ("bash", ["-c", "cd x && exec -a srv npx -y some-server"], ["CW101", "CW102"]),
        ("bash", ["-c", "cd x & npx -y some-server"], ["CW101", "CW102"]),
        ("bash", ["-c", "cd x && bash -c 'cd y && npx -y some-server'"], ["CW101", "CW102"]),
        ("su", ["-c", "cd /x && npx -y some-server", "root"], ["CW101", "CW102"]),
        ("cmd", ["/c", "cd C:\\srv && npx -y some-server"], ["CW101", "CW102"]),
        ("pwsh", ["-Command", "Set-Location C:\\srv; npx -y some-server"], ["CW101", "CW102"]),
        ("wsl", ["bash", "-c", "cd ~ && npx -y some-server"], ["CW101", "CW102"]),
        # Une fin de ligne sépare aussi deux commandes (après un commentaire aussi).
        ("bash", ["-c", "cd /srv\nnpx -y some-server"], ["CW101", "CW102"]),
        ("bash", ["-c", "cd /srv\r\nnpx -y some-server"], ["CW101", "CW102"]),
        ("bash", ["-c", "# start the server\nnpx -y some-server"], ["CW101", "CW102"]),
        ("bash", ["-c", "npx -y \\\nsome-server"], ["CW101", "CW102"]),  # ligne continuée
        ("pwsh", ["-Command", "Set-Location C:\\srv\nnpx -y some-server"], ["CW101", "CW102"]),
    ],
)
def test_later_commands_are_checked(write_mcp, command, args, expected) -> None:
    assert ids_for(write_mcp, command, args) == expected


def test_each_later_command_is_checked(write_mcp) -> None:
    script = "npx -y first-server; npx -y second-server; uvx third-server"
    findings = scan(write_mcp({"s": {"command": "bash", "args": ["-c", script]}})).findings
    messages = sorted(f.message for f in findings if f.rule.id == "CW102")
    assert len(messages) == 3
    assert "'second-server'" in messages[1] and "'third-server'" in messages[2]


def test_command_line_with_operators_in_command_is_checked(write_mcp) -> None:
    server = {"command": "cd /srv && npx -y some-server"}
    assert ids_for_server(write_mcp, server) == ["CW101", "CW102"]


@pytest.mark.parametrize(
    ("command", "args"),
    [
        ("bash", ["-c", "cd /srv && npx -y some-server@1.2.3"]),
        ("bash", ["-c", "cd x && docker run -i --rm org/server:1.2.3"]),
        # Après une redirection, le mot suivant est un fichier, pas une commande.
        ("bash", ["-c", "echo > npx some-server"]),
        ("bash", ["-c", "npx -y some-server@1.2.3 2> uvx"]),
        ("bash", ["-c", "cat < uvx some-server"]),
        ("cmd", ["/c", "cd C:\\srv && npx -y some-server@1.2.3 > npx"]),
        # Texte entre guillemets : un seul argument, pas une commande.
        ("bash", ["-c", "echo 'npx -y some-server; uvx other'"]),
        ("bash", ["-c", "# npx -y some-server"]),
        ("bash", ["-c", "echo 'first line\nnpx -y some-server'"]),  # texte sur deux lignes
    ],
)
def test_pinned_or_non_commands_stay_quiet(write_mcp, command, args) -> None:
    assert ids_for(write_mcp, command, args) == ["CW101"]


# --- Contrat de commands.analyse ---------------------------------------------------------


def test_analyse_lists_the_other_commands() -> None:
    launch = commands.analyse("bash", ["-c", "cd x && npx a; FOO=1 uvx b > log.txt"])
    assert launch.tokens == ["cd", "x"]
    assert launch.others == [["npx", "a"], ["uvx", "b"]]
    assert launch.commands == [["cd", "x"], ["npx", "a"], ["uvx", "b"]]


def test_simple_command_has_no_other_command() -> None:
    launch = commands.analyse("npx", ["-y", "some-server"])
    assert launch.others == []
    assert launch.commands == [["npx", "-y", "some-server"]]


def test_wrappers_are_removed_from_later_commands_too() -> None:
    launch = commands.analyse("bash", ["-c", "cd x; sudo -u app env A=1 npx -y srv"])
    assert launch.others == [["npx", "-y", "srv"]]


# --- Entrées piégées : nombre de commandes et temps bornés -------------------------------


def test_number_of_commands_is_bounded() -> None:
    script = "; ".join(f"npx -y server-{index}" for index in range(5_000))
    start = time.perf_counter()
    launch = commands.analyse("bash", ["-c", script])
    assert time.perf_counter() - start < 1
    assert len(launch.commands) <= 21


def test_commands_from_several_scripts_share_one_limit() -> None:
    # 20 commandes par script, 5 scripts : sans limite commune, 100 commandes.
    inner = shlex.quote("; ".join(f"npx -y server-{index}" for index in range(20)))
    script = "; ".join([f"bash -c {inner}"] * 6)
    launch = commands.analyse("bash", ["-c", script])
    assert len(launch.commands) <= 21


def test_script_split_and_words_are_bounded() -> None:
    assert len(commands._split_posix("a;" * 5_000)) <= 21
    assert len(commands._split_windows("a&" * 5_000)) <= 21
    launch = commands.analyse("bash", ["-c", "npx " + "x " * 5_000])
    assert all(len(command) <= 200 for command in launch.commands)


def test_nested_scripts_are_bounded() -> None:
    # Chaque commande relance un shell avec des commandes : l'arbre grandirait vite.
    script = "npx -y a"
    for _ in range(6):
        script = "; ".join([f"bash -c {shlex.quote(script)}"] * 4)
    start = time.perf_counter()
    launch = commands.analyse("bash", ["-c", script])
    assert time.perf_counter() - start < 2
    assert len(launch.commands) <= 21


@pytest.mark.parametrize(
    "script",
    [
        "a;" * 500_000,
        "npx " + "x " * 500_000,
        "'" * 100_001,
        "> " * 500_000,
        "( " * 500_000,
        "A=1 " * 500_000 + "npx -y srv",
        "if " * 500_000,
    ],
    ids=["separators", "words", "quotes", "redirections", "parens", "assignments", "keywords"],
)
def test_huge_scripts_are_fast(script) -> None:
    start = time.perf_counter()
    commands.analyse("bash", ["-c", script])
    assert time.perf_counter() - start < 1


def test_huge_script_in_a_file_does_not_crash(write_mcp) -> None:
    script = "; ".join(["cd x && npx -y some-server"] * 30_000)[:900_000]
    start = time.perf_counter()
    assert ids_for(write_mcp, "bash", ["-c", script]) == ["CW101", "CW102"]
    assert time.perf_counter() - start < 5
