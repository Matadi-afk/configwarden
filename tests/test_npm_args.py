"""Tests de npm_args.py : la lecture de `npx` et de `npm exec` est celle de npm lui-même.

Chaque cas ci-dessous a été donné à npm 10.9.4 (bin/npx-cli.js, puis nopt 8.1.0) les
20 et 21 octobre 2026, et sa réponse est figée ici. Avant d'être figée, la lecture Python a
été comparée à celle de npm sur plus de 180 000 lignes tirées au hasard : aucune
différence (le 21 octobre, cette comparaison élargie a trouvé et fait corriger deux écarts :
« --no-depth 1 » avale le nombre, et nopt retire les espaces autour d'une valeur).

Quelques surprises de npm, toutes vérifiées :
- `--cal x` n'est pas l'abréviation de `--call` : c, a et l sont trois raccourcis d'une
  lettre, donc `--cal` vaut `--call --all --long` (et `--call` n'a plus de valeur) ;
- `npx --browser srv -c "…"` : `--browser` avale le « -- » placé par npx, et `-c`
  redevient une option ;
- pour `npm` (sans x), `-p` est `--parseable`, pas `--package` ;
- `npx --no-depth 1 paquet` : « 1 » est la valeur de `--no-depth`, et c'est `paquet` qui
  est lancé.
"""

from dataclasses import replace

import pytest

from configwarden.npm_args import NpxArguments, parse_npm_exec, parse_npx
from configwarden.scanner import scan

# (arguments de npx, call, paquets, commande, mode shell de pnpm)
NPX_CASES = [
    (["-y", "srv@1.2.3"], None, [], ["srv@1.2.3"], False),
    (["-y", "srv@1.2.3", "-c", "config.json"], None, [], ["srv@1.2.3", "-c", "config.json"], False),
    (["-y", "srv@1.2.3", "-p", "3000"], None, [], ["srv@1.2.3", "-p", "3000"], False),
    (["--cafile", "/etc/ssl/certs/ca.pem", "-y", "evil-mcp"], None, [], ["evil-mcp"], False),
    (["--cafile", "/etc/ssl/certs/ca.pem", "-c", "touch PWNED"], "touch PWNED", [], [], False),
    (["-yc", "touch PWNED"], "touch PWNED", [], [], False),
    (["-cy", "touch PWNED"], "", [], ["touch PWNED"], False),
    (["--call=touch PWNED"], "touch PWNED", [], [], False),
    (["--cal", "touch PWNED"], "", [], ["touch PWNED"], False),
    (["--no-call", "srv"], "false", [], ["srv"], False),
    (["--call"], "", [], [], False),
    (["--browser", "srv@1.0.0", "-c", "touch PWNED"], "touch PWNED", [], ["srv@1.0.0"], False),
    (["--future-flag", "github:attacker/evil"], None, [], ["github:attacker/evil"], False),
    (
        ["--no-registry", "github:attacker/evil", "srv@1.0.0"],
        None,
        [],
        ["github:attacker/evil", "srv@1.0.0"],
        False,
    ),
    (
        ["-y", "-p", "srv@1.0.0", "--cafile", "/x.pem", "-p", "github:attacker/evil", "srv"],
        None,
        ["srv@1.0.0", "github:attacker/evil"],
        ["srv"],
        False,
    ),
    (
        ["-p", "a@1.0.0", "-p=b", "--package", "c", "--package=d", "run-it"],
        None,
        ["a@1.0.0", "b", "c", "d"],
        ["run-it"],
        False,
    ),
    (["--registry", "https://registry.example.com", "srv@1.2.3"], None, [], ["srv@1.2.3"], False),
    (["-y", "--", "srv@1.2.3", "--call", "x"], None, [], ["srv@1.2.3", "--call", "x"], False),
    (["---", "-c"], None, [], ["--call"], False),
    (["--shell", "/bin/sh", "srv"], None, [], ["srv"], False),
    (["--yes=false", "srv"], None, [], ["srv"], False),
    (["--yes", "true", "srv"], None, [], ["true", "srv"], False),
    (["-q", "srv", "--quiet"], None, [], ["srv", "--quiet"], False),
    (["--shell-mode", "echo hi | cowsay"], None, [], ["echo hi | cowsay"], True),
    (["--package", "cowsay", "--shell-mode", "echo hi"], None, ["cowsay"], ["echo hi"], True),
    (["-n", "--inspect", "srv"], None, [], ["srv"], False),
    (["--node-arg=--inspect", "srv"], None, [], ["srv"], False),
    # Option inconnue répétée : nopt en fait une liste (« true,false ») ; une seule
    # occurrence active suffit pour signaler le mode shell.
    (["--shell-mode", "--shell-mode=false", "echo hi"], None, [], ["echo hi"], True),
    (["--shell-mode=false", "echo hi"], None, [], ["echo hi"], False),
    # Un nombre après une option numérique niée est sa valeur : c'est github:… qui est lancé.
    (["--no-depth", "1", "github:attacker/evil"], None, [], ["github:attacker/evil"], False),
    (["-c", " "], "", [], [], False),  # nopt retire les espaces : pas de ligne de commande
    (["--call", " touch x "], "touch x", [], [], False),
]

# (arguments de npx, registres retenus par npm : (option, adresse))
REGISTRY_CASES = [
    (
        ["--registry", "https://registry.example.com", "srv@1.2.3"],
        [("registry", "https://registry.example.com")],
    ),
    (["--@myorg:registry=https://r.example", "srv"], [("@myorg:registry", "https://r.example")]),
    (["--reg", "--registry=https://r.example", "srv"], []),  # « --registry=… » avalé, rejeté
    (["-y", "srv", "--registry", "https://r.example"], []),  # option du serveur
]

# (arguments de npm, lecture de `npm exec` : (call, paquets, commande), ou None)
NPM_CASES = [
    (["exec", "srv@1.2.3"], (None, [], ["srv@1.2.3"])),
    (["x", "-y", "srv@1.2.3"], (None, [], ["srv@1.2.3"])),
    (["exe", "srv"], (None, [], ["srv"])),
    (["-c", "touch PWNED", "exec"], ("touch PWNED", [], [])),
    (["--call=touch PWNED", "x"], ("touch PWNED", [], [])),
    (["exec", "srv@1.0.0", "-c", "touch PWNED"], ("touch PWNED", [], ["srv@1.0.0"])),
    (["exec", "srv", "--package=github:attacker/evil"], (None, ["github:attacker/evil"], ["srv"])),
    (
        ["--package", "github:attacker/evil", "exec", "srv"],
        (None, ["github:attacker/evil"], ["srv"]),
    ),
    (["exec", "srv", "-p", "github:attacker/evil"], (None, [], ["srv", "github:attacker/evil"])),
    (["-p", "github:attacker/evil", "exec", "srv"], None),
    (["exec", "--", "srv", "-c", "x"], (None, [], ["srv", "-c", "x"])),
    (["--cafile", "/x.pem", "exec", "srv"], (None, [], ["srv"])),
    (["--prefix", "exec", "x", "srv"], (None, [], ["srv"])),
    (
        ["exec", "--yes", "--package", "a@1.0.0", "--package", "helper", "a"],
        (None, ["a@1.0.0", "helper"], ["a"]),
    ),
    (["install", "srv"], None),
    (["run", "start"], None),
    (["EXEC", "srv"], None),
    (["ex", "srv"], None),
]


@pytest.mark.parametrize(("args", "call", "packages", "command", "shell_mode"), NPX_CASES)
def test_npx_is_read_like_npm(args, call, packages, command, shell_mode) -> None:
    reading = parse_npx(args)
    assert replace(reading, registries=[]) == NpxArguments(call, packages, command, shell_mode)
    assert parse_npx(reading.as_npx_args()) == reading


@pytest.mark.parametrize(("args", "registries"), REGISTRY_CASES)
def test_registries_are_read_like_npm(args, registries) -> None:
    # npm écrit l'adresse sous sa forme normalisée (« …com/ ») : seul l'hôte compte ici.
    reading = parse_npx(args)
    assert [(key, address.rstrip("/")) for key, address in reading.registries] == registries
    assert parse_npx(reading.as_npx_args()) == reading


@pytest.mark.parametrize(("args", "expected"), NPM_CASES)
def test_npm_exec_is_read_like_npm(args, expected) -> None:
    reading = parse_npm_exec(args)
    if expected is None:
        assert reading is None
        return
    assert reading == NpxArguments(*expected)
    assert parse_npx(reading.as_npx_args()) == reading


@pytest.mark.parametrize(
    ("call", "shell_mode", "expected"),
    [
        ("touch x", False, "-c"),
        ("", False, None),  # « --call » sans valeur
        ("true", False, None),
        ("false", False, None),  # « --no-call »
        (None, True, "--shell-mode"),
        (None, False, None),
    ],
)
def test_shell_option(call, shell_mode, expected) -> None:
    assert NpxArguments(call=call, shell_mode=shell_mode).shell_option() == expected


def test_parsing_does_not_change_the_arguments() -> None:
    args = ["-yc", "touch x", "--", "srv"]
    parse_npx(args)
    parse_npm_exec(args)
    assert args == ["-yc", "touch x", "--", "srv"]


# --- De bout en bout : ce que configwarden signale ------------------------------------------


def ids_for(write_mcp, command: str, args: list[str]) -> list[str]:
    return sorted(
        f.rule.id for f in scan(write_mcp({"s": {"command": command, "args": args}})).findings
    )


@pytest.mark.parametrize(
    ("command", "args", "expected"),
    [
        # npm lit ses options partout : « -c » avant « exec » lance un shell.
        ("npm", ["-c", "touch PWNED", "exec"], ["CW101"]),
        ("npm", ["--cafile", "/x.pem", "exec", "-c", "touch PWNED"], ["CW101"]),
        # « --package » après le paquet : npm installe AUSSI le paquet venu de GitHub.
        ("npm", ["exec", "-y", "srv@1.0.0", "--package=github:attacker/evil"], ["CW107"]),
        ("npm", ["exec", "-y", "srv@1.2.3"], []),
        ("npm", ["x", "-y", "srv"], ["CW102"]),
        ("npm", ["exe", "-y", "srv"], ["CW102"]),
        # Pour npm, « -p » est --parseable : github:… est un argument du serveur.
        ("npm", ["exec", "-y", "srv@1.2.3", "-p", "github:a/b"], []),
        ("npm", ["install", "srv"], []),
        # pnpm : l'option shell peut se placer AVANT dlx ou exec.
        ("pnpm", ["-c", "dlx", "echo hi | cowsay"], ["CW101"]),
        ("pnpm", ["--package", "cowsay", "-c", "dlx", "echo hi | cowsay"], ["CW101", "CW102"]),
        ("pnpm", ["-c", "exec", "echo hi"], ["CW101"]),
        ("pnpm", ["dlx", "srv@1.2.3", "--shell-mode"], []),  # option du serveur
        # deno : « npm:… » est un paquet, jamais une option de npx.
        ("deno", ["run", "npm:@scope/srv@1.2.3"], []),
        ("deno", ["run", "npm:-c"], ["CW102"]),
    ],
)
def test_package_runners_end_to_end(write_mcp, command, args, expected) -> None:
    assert ids_for(write_mcp, command, args) == expected
