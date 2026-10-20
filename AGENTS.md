# AGENTS.md : guide du projet pour les assistants IA

Ce fichier résume le projet pour qu'un assistant IA (Claude, Copilot, Cursor…) puisse travailler **sans relire tout le code**. Il doit rester court et à jour : quand la structure, une commande ou une règle change, on met ce fichier à jour dans le même commit.

> ⚠️ Ce fichier est public. Il ne doit **jamais** contenir de secret, de chemin personnel ni d'information privée.

## Le projet en une phrase

**configwarden** aide les développeurs qui branchent des agents IA à leurs outils à ne pas fuiter leurs secrets ni ouvrir leur machine.

Anciennement **agentguard** : renommé le 8 octobre 2026, car ce nom était trop proche de projets existants (PyPI le refusait, et un autre outil MCP installe déjà une commande `agentguard`). Les règles gardent leurs numéros avec le préfixe `CW` (`AG103` → `CW103`).

Il s'agit d'un scanner en ligne de commande, open source (Apache‑2.0), écrit en Python ≥ 3.10, **sans aucune dépendance à l'exécution**. Il produit des rapports en texte, JSON ou SARIF.

Toute idée qui ne sert pas cette phrase va dans `IDEES.md`, pas dans le code.

## Carte du code

```
src/configwarden/
  cli.py            Commandes `scan` et `rules`, codes de sortie 0/1/2 ; --output refuse d'écrire à travers un lien symbolique ; sous GitHub Actions, rapport texte entre « ::stop-commands:: » et un jeton aléatoire
  scanner.py        Parcours des fichiers (sans suivre les symlinks ; fichiers ordinaires seulement ; ignore binaires et > 1 Mo ; lit l'UTF-16/32 avec BOM) + appel des règles
  models.py         Severity (LOW < MEDIUM < HIGH < CRITICAL), Rule, Finding (chemin et message assainis à la création)
  commands.py       analyse() : retire les enveloppes (cmd /c, wsl, env -S, sudo, uv run, bash -c, su -c…), ramène pnpm dlx / bun x / uv tool run / npm exec… à npx / uvx et relève les risques CW101 ; suit TOUTES les commandes d'un script (Launch.commands : 1 + 20 au plus, limite commune aux scripts imbriqués ; Launch.truncated si dépassée -> CW100)
  npm_args.py       parse_npx() / parse_npm_exec() : lecture EXACTE de npx et de npm exec (port de npx-cli.js et de nopt, données de npm 10.9.4) ; comparée à npm réel sur plus de 50 000 lignes (cas figés : tests/test_npm_args.py)
  containers.py     run_image() : image lancée par « docker/podman/nerdctl run » (options globales, options courtes groupées, option inconnue = analyse arrêtée) ; run_option_pairs() : options avant l'image lues comme pflag (-v/:/h, -iv/x, --privileged=1) ; loose_option_pairs() : relecture prudente d'une ligne illisible ; parse_reference() : grammaire officielle d'une image ; pinning_problem() pour CW111
  ignore.py         Fichier d'exceptions .configwarden-ignore : parse() (lignes coupées sur \n seulement, caractère de contrôle ou invisible refusé ; règle + fichier/dossier + until= facultatif + raison obligatoire, masquée par mask_secrets()), read() (pas de lien symbolique, 256 Ko max), apply() (arbre des dossiers ; exceptions toujours listées ; retirées du SARIF)
  values.py         Forme d'une valeur : modèle à remplir, booléen, nombre, mot, chemin (filtre les fausses alertes de CW001 et CW103)
  jsonc.py          loads() : JSON strict, sinon JSON avec commentaires et virgules finales (temps linéaire, positions conservées)
  redact.py         redact() masque un secret ; redact_url() masque identifiants et paramètres d'URL ; url_origin() ne garde que « schéma://hôte/… » ; sanitize() neutralise les caractères de contrôle et invisibles ; json_for_logs() écrit « ## » en « #\u0023 » (commandes des journaux de CI)
  config.py         Secret + get_secret() : lecture sécurisée des variables d'environnement (étape 8)
  rules/
    __init__.py     ALL_RULES = liste de toutes les règles
    secrets.py      CW001 : secrets en clair (regex par fournisseur) ; mask_secrets() pour un texte libre
    mcp.py          CW100-CW111 : configurations MCP dangereuses et réglages « tout approuver » ; lit tout fichier .json/.jsonc (voir « Formats reconnus »)
  reporters/        text.py, json_reporter.py, sarif.py (+ RENDERERS dans __init__)
tests/              pytest ; conftest.py fournit fake_secret() et write_mcp ; test_hardening.py rejoue les attaques connues ; test_real_configs.py couvre le format de chaque outil IA ; test_review_fixes.py rejoue les constats de l'Auditeur et du grand test ; test_container_images.py couvre CW111 ; test_script_commands.py les commandes suivantes d'un script ; test_ignore.py le fichier d'exceptions ; test_v040_fixes.py CW102 --with et CW106 ; test_fuzz.py les propriétés (Hypothesis) ; test_action.py l'Action GitHub (lancée comme GitHub : bash -eo pipefail) et le hook pre-commit ; test_audit_v040.py rejoue les preuves de la revue de la 0.4.0 ; test_npm_args.py fige les réponses de npm réel
examples/           vulnerable-mcp/ (doit déclencher CW101-CW111) et safe-mcp/ (doit rester propre). Fichiers nommés pour qu'aucun outil IA ne les charge (jamais `.vscode/mcp.json`, `.mcp.json`, `.claude/settings.json`…)
docs/GUIDE-FR.md    Guide d'installation pas à pas pour débutant (Windows/macOS)
action.yml          Action GitHub (composite) : lance configwarden depuis son propre code, Python en mode isolé, entrées par variables d'environnement
.pre-commit-hooks.yaml  Hook pre-commit pour les autres projets (id: configwarden)
```

## Règles existantes

| ID | Gravité | Fichier | Détecte |
|----|---------|---------|---------|
| CW001 | critical | rules/secrets.py | Clé API ou token en clair (exemples de documentation ignorés : `…EXAMPLE`, `xxxx`, clé tronquée) |
| CW100 | medium | rules/mcp.py | Config MCP illisible (certains outils lancent quand même une partie d'un fichier abîmé), ou script trop long pour être vérifié en entier |
| CW101 | high | rules/mcp.py | Shell qui reçoit un script (`bash -c`, `pwsh -Command`, `su -c`), `cmd /c` ou WSL avec une ligne de commande ou des caractères spéciaux, `npx -c` et `npm exec -c` (lus exactement comme npm), `pnpm -c dlx`, `npm_config_call`, opérateurs shell dans `command`, code en ligne (`node -e`, `python -c`) |
| CW102 | medium | rules/mcp.py | Paquet du registre sans version **exacte** (`^1.0`, `@beta`, `>=1` ne comptent pas), quel que soit le lanceur (npx, uvx, pnpm dlx, bun x, uv tool run, pipx run, deno run npm:…) ; chemin local ignoré |
| CW103 | high | rules/mcp.py | Secret littéral dans `env`, `headers`, la ligne de commande (`--api-key`, `-e TOKEN=`) ou une URL (mot de passe, `?token=`), valeur par défaut de `${VAR:-…}` ; références, modèles, réglages et chemins ignorés (values.py) |
| CW104 | high | rules/mcp.py | Serveur filesystem ouvert sur `/`, un lecteur entier ou un dossier personnel complet |
| CW105 | high | rules/mcp.py | Serveur distant en `http://` |
| CW106 | high | rules/mcp.py + containers.py | Conteneur Docker/Podman qui casse l'isolation (`--privileged`, `=host`, montage de `/`, du dossier personnel, de `.ssh`/`.aws`… ou du socket Docker), formes collées comprises (`-v/:/host`, `--privileged=1`) |
| CW107 | high | rules/mcp.py | Paquet ou script installé depuis git, une URL, un raccourci GitHub `auteur/projet` ou `nom @ url`, y compris `uv run --with` et `deno run https://…` (remplace CW102 pour ce paquet) |
| CW108 | medium | rules/mcp.py | Outils approuvés sans confirmation (`alwaysAllow`, `autoApprove`, `trust: true`) |
| CW109 | high | rules/mcp.py | Réglage de l'outil IA qui approuve tout : Claude Code (`enableAllProjectMcpServers`, `bypassPermissions`, `skipDangerousModePermissionPrompt`), VS Code (`chat.tools.global.autoApprove`), Zed, Cursor (`*:*`), Kiro (Autopilot) |
| CW110 | high | rules/mcp.py | Vérification TLS coupée : `NODE_TLS_REJECT_UNAUTHORIZED=0`, `*_SSL_VERIFY=false`, `--insecure`, `--strict-ssl=false`, `--allow-insecure-host` |
| CW111 | medium | rules/mcp.py + containers.py | Image de conteneur sans empreinte ni version précise : pas d'étiquette, `:latest`, `:main`, `:stable`, étiquette sans chiffre, version majeure seule (`:20`) ; images officielles de Docker Hub (un seul nom) et registres locaux ignorés |

Prochain ID libre : **CW002** (secrets) ou **CW112** (MCP).

## Formats reconnus

configwarden lit **tout fichier `.json` ou `.jsonc`** (commentaires et virgules finales acceptés, voir `jsonc.py`) et cherche les serveurs MCP à ces emplacements. La recherche se fait après la lecture du fichier : un nom de clé écrit avec des échappements ne cache rien.

| Emplacement | Outils |
|---|---|
| `mcpServers` | Claude Desktop, Claude Code (`.mcp.json`), Cursor, Gemini CLI, Cline, Roo Code, Windsurf/Devin, Kiro, Amazon Q, Copilot CLI |
| `servers` (fichiers « nommés MCP » seulement) | VS Code (`.vscode/mcp.json`) |
| `mcp.servers` | VS Code, ancien `settings.json` |
| `customizations.vscode.mcp.servers` | `devcontainer.json` |
| `context_servers` | Zed (`command` texte, ou objet `{path, args, env}` dans l'ancien format) |
| `projects.<chemin>.mcpServers` | Claude Code (`~/.claude.json`, serveurs par projet) |

- Fichiers « nommés MCP » (illisibles → CW100) : `mcp.json`, `.mcp.json`, `*.mcp.json`, `*.mcp.jsonc`, `mcp_config.json`, `claude_desktop_config.json`, `cline_mcp_settings.json`, `mcp_settings.json`, `mcp-config.json`. Les autres fichiers JSON illisibles restent silencieux.
- Adresses distantes : `url`, `serverUrl` (Windsurf), `httpUrl` (Gemini CLI).
- **Jamais de silence sur une configuration non auditable** (CW100) : fichier MCP ou JSON d'un dossier d'outil IA (`.vscode/`, `.cursor/`, `.gemini/`, `.claude/`…) trop gros, d'apparence binaire ou lien symbolique ; fichier JSON abîmé qui annonce des serveurs. Un outil tolérant pourrait lancer ce que configwarden n'a pas lu.
- Pas encore pris en charge (voir `IDEES.md`) : YAML (Continue), TOML (Codex CLI).
- Source : documentation officielle de chaque outil, relevée le 8 octobre 2026. À revérifier quand un outil change de format.

## Commandes

Elles se lancent depuis la racine du projet, avec l'environnement `.venv` activé (Windows PowerShell : `.venv\Scripts\Activate.ps1`).

```bash
pip install -e ".[dev]"                     # installation (une fois)
pytest                                      # tests (dont 150 exemples par propriété Hypothesis)
$env:CONFIGWARDEN_HYPOTHESIS = "fuzz" ; pytest tests/test_fuzz.py   # fuzzing long (5 000 exemples)
ruff check . ; ruff format .                # qualité + sécurité (règles Bandit "S")
pre-commit run --all-files                  # tous les contrôles, dont gitleaks
configwarden scan examples/vulnerable-mcp     # démo : 15 constats attendus
configwarden scan . --exclude "examples/*"    # auto-scan : 0 constat attendu
```

## Ajouter une règle (procédure)

1. Déclarer un `Rule(id=..., title=..., severity=..., remediation=...)` dans le bon fichier de `rules/`, puis l'ajouter à la liste `RULES` de ce fichier.
2. Écrire la détection. Elle doit produire des `Finding` dont le `message` n'expose **jamais** une valeur sensible : passer par `redact()` (valeur) ou `url_origin()` (URL).
3. Ajouter des tests : au moins un cas détecté et un cas propre (faux positif évité).
4. Si la règle concerne MCP, l'ajouter dans `examples/vulnerable-mcp/mcp.json` et vérifier que `examples/safe-mcp` reste propre.
5. Mettre à jour le tableau des règles ici **et** dans `README.md`.
6. `pytest` et `pre-commit run --all-files` doivent passer.

## Règles de sécurité (non négociables)

- **Aucun secret dans le dépôt**, même faux. Dans les tests, les faux secrets sont **assemblés à l'exécution** avec `fake_secret("ghp_", 36)` : jamais de chaîne littérale au format d'une vraie clé. Les paramètres de test utilisent `ids=` pour qu'aucune valeur n'apparaisse dans les noms de tests.
- **Un rapport n'affiche jamais un secret en entier** (texte, JSON comme SARIF).
- **Zéro dépendance à l'exécution** : `dependencies = []` dans `pyproject.toml`. Toute nouvelle dépendance doit être justifiée et validée par le mainteneur.
- Les secrets de l'application se lisent via `config.get_secret()` et restent enveloppés dans `Secret` jusqu'à `.reveal()`.
- Pas d'`eval`, d'`exec`, de `pickle`, ni de `subprocess` avec `shell=True`.
- Le scanner lit, il n'exécute jamais rien de ce qu'il analyse.
- **Action GitHub** (`action.yml`) : les entrées passent par `env:` et sont vérifiées, jamais `${{ inputs.* }}` dans un script ; Python lancé avec `-I` (le dépôt analysé ne peut pas remplacer un module) ; rien n'est installé.
- **Exceptions** : une alerte mise en exception reste toujours visible (texte, JSON) ; un message sur le fichier d'exceptions cite un numéro de ligne, jamais son contenu.
- **Lire comme le vrai programme** : npx et npm exec passent par `npm_args.py` (fidèle à npm, jamais une liste d'options devinée) ; docker run par les règles de pflag ; `--with` est découpé comme uv. Une ligne qu'on ne sait pas lire avec certitude est relue prudemment, jamais ignorée. Quand npm change, refaire la comparaison avec npm réel.
- **Journaux de CI** : aucune ligne d'un rapport ne commence par « :: », « ## » est neutralisé dans tous les formats, et le rapport texte est encadré par « ::stop-commands:: » sous GitHub Actions.
- Ne pas désactiver un contrôle (`--no-verify`, `# noqa` non justifié) pour faire passer un commit.

## Checklist sécurité (obligatoire pour TOUTE modification)

Fil rouge du projet : configwarden est un outil de sécurité, il doit être lui-même irréprochable. Avant de proposer un changement, vérifier chaque point :

1. **Entrées non fiables** : tout ce qui vient d'un fichier analysé (JSON, texte, noms de fichiers) peut être piégé. Vérifier les types (`isinstance`), ne jamais supposer une structure, et ne jamais laisser une exception arrêter le scan (penser aux fichiers énormes, très imbriqués ou malformés, aux URL invalides, aux fichiers spéciaux).
2. **Temps de calcul** : jamais de traitement quadratique sur une entrée (une boucle qui relit tout le fichier pour chaque élément, une regex qui peut revenir en arrière). Tester avec une entrée de ~1 Mo construite pour être lente.
3. **Sorties assainies** : les textes affichés passent par `Finding`, qui applique `sanitize()`. Ne jamais afficher une donnée lue sans passer par là.
4. **Secrets masqués** : valeur sensible → `redact()` ; URL → `url_origin()` dans un message (un jeton peut se cacher dans les identifiants, le chemin ou les paramètres). Ne jamais recopier un message d'erreur Python qui contient l'entrée.
5. **Écritures sûres** : ne jamais écrire à travers un lien symbolique (le dossier analysé n'est pas fiable).
6. **Aucune nouvelle dépendance** à l'exécution, et pas d'action CI non figée par empreinte SHA.
7. **Un test « malveillant »** pour chaque nouvelle règle ou entrée : il doit échouer sans la protection et passer avec (« test du test »).
8. **Pas de caractère invisible** dans le code : un caractère spécial s'écrit avec `chr(0x…)`. Le test `test_no_invisible_or_bidi_characters_in_source` le vérifie.
9. **Exposition** : rien de personnel ni de privé dans les fichiers publics (vrai nom, chemins locaux, noms de projets privés, inventaire de clés).
10. **Contre-vérification** : pour un changement de sécurité, faire relire le correctif par une revue indépendante qui tente de le contourner. Un correctif peut introduire une nouvelle faille (vécu en 0.2.2).

## Conventions

- Code, messages du CLI et README **en anglais** (public international). Commentaires, docstrings et documentation `docs/` **en français**.
- Lignes de 100 caractères maximum ; format et imports gérés par ruff.
- Chemins des constats relatifs et avec des `/`, quel que soit le système d'exploitation.

## Fichiers à ne pas modifier sans accord explicite du mainteneur

`.github/workflows/`, `.pre-commit-config.yaml`, `.gitignore`, `LICENSE`, `pyproject.toml` (section `dependencies`), `action.yml` et `.pre-commit-hooks.yaml` (interfaces utilisées par d'autres projets).

## État du projet

- Version 0.3.0 (12 règles) : vrais fichiers de configuration, commandes enveloppées, CW109 et SARIF, puis corrections de la revue de l'Auditeur et du grand test sur 3 099 exemples publiés (règle CW110). 572 tests. Notes de version dans `CHANGELOG.md` : à compléter à chaque nouvelle version.
- Version 0.4.0 (13 règles) : CW111 (image de conteneur non figée), toutes les commandes d'un script, fichier d'exceptions `.configwarden-ignore`, Action GitHub et hook pre-commit, CW102 pour `--with`, CW106 limité aux options avant l'image, tests de propriétés (Hypothesis) ; puis corrections de la revue de l'Auditeur (lecture exacte de npx et npm exec, options collées de Docker, journaux de CI protégés), contre-vérifiées sans défaut moyen ou plus. 1 012 tests.
- Cap fixé jusqu'au 4 novembre 2026 : publier sur GitHub, ajouter 3 règles, faire un premier post. Voir `IDEES.md` pour ce qui est volontairement mis de côté.
