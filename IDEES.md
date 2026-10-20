# Idées en attente

Le parking à idées. Une idée qui ne sert pas la phrase du projet atterrit ici,
**pas dans le code**. On relit ce fichier au jour 30 (4 novembre 2026), pas avant.

> configwarden aide les développeurs qui branchent des agents IA à leurs outils
> à ne pas fuiter leurs secrets ni ouvrir leur machine.

## Depuis des prototypes antérieurs
- Analyse AST du code des serveurs MCP (subprocess, eval, réseau caché)
- Base de menaces des paquets MCP alimentée par NVD/OTX (offre Pro)
- Réputation VirusTotal des paquets et URL MCP
- `configwarden fix` : propose une config corrigée, n'exécute jamais seul
- Rapport HTML (ex-dashboard Streamlit) pour la version Pro
- Au placard : forensique d'images, EDR + quarantaine

## Retours du premier test réel (6 octobre 2026)
- **CW002 – secret générique** : repérer `NOM_API_KEY=valeur`, `*_TOKEN=`, `*_SECRET=` quand la
  valeur est littérale, même sans préfixe connu (clés au format UUID ou hexadécimal, qui n'ont
  pas de préfixe reconnaissable).
- **Préfixes à ajouter** : Groq (`gsk_`), puis vérifier les formats d'autres fournisseurs IA.
- **`.env` protégé ou non** : alerte critique si le `.env` n'est PAS couvert par `.gitignore`,
  simple information s'il l'est (évite un faux positif observé).
- **Serveur de modèles exposé** : signaler `OLLAMA_HOST=0.0.0.0` (API Ollama ouverte au réseau,
  sans authentification). Même idée pour d'autres serveurs d'IA locaux.
- **Ignorer une alerte** : le JSON n'accepte pas de commentaires, donc pas de `# ignore` dans
  `mcp.json`. Piste retenue : un fichier `.configwarden-ignore` (ID de règle + chemin + raison
  obligatoire), constats ignorés toujours comptés, option `--no-ignore`, `suppressions` en SARIF.
- **Socket Docker légitime** : certains serveurs MCP gèrent des conteneurs et en ont besoin ;
  prévoir une façon documentée d'accepter ce risque en connaissance de cause.

## Retours de la revue de sécurité (7 octobre 2026)
- **Règle « Trojan Source »** : signaler les caractères invisibles ou bidirectionnels dans les
  fichiers de configuration et le code analysés (déjà vérifié pour notre propre code).
- **Identifiants dans les URL** : détecter `https://user:motdepasse@…` partout, pas seulement
  dans les paquets MCP.

## Angles morts relevés par la revue indépendante (7 octobre 2026)
- **PowerShell encodé** : décoder `-EncodedCommand` (base64 UTF-16) pour analyser la commande
  cachée, au lieu de seulement la signaler.

## Recherche des Éclaireurs (8 octobre 2026)
- **TOML et YAML** (décision du 8 octobre : plus tard) : Codex CLI (`config.toml`,
  `[mcp_servers.nom]`, lisible avec `tomllib` à partir de Python 3.11) ; Continue
  (`config.yaml`, `.continue/mcpServers/*.yaml`, qui demanderait une dépendance).
- **Commandes cachées hors de `command`** : Claude Code `headersHelper` (commande qui produit
  les en-têtes HTTP) ; Gemini CLI `mcp.serverCommand`.
- **Contenu de fichier injecté** : Windsurf/Devin `${file:/chemin}` insère un fichier dans une
  URL ou un en-tête : alerte s'il vise des identifiants (`~/.ssh`, `.env`…).
- **Extensions de bureau** : manifeste `manifest.json` des paquets `.mcpb` / `.dxt`
  (`server.mcp_config`).
- **Agents** : serveurs déclarés dans l'en-tête YAML des agents Claude Code
  (`.claude/agents/*.md`) et Kiro (`.kiro/agents/*.md`).

## Grand test sur 3 099 exemples publiés et contre-vérification (8 octobre 2026)
- ~~**Image Docker non figée**~~ : fait le 14 octobre 2026 (règle CW111, 85 lignes `docker run`
  sur 110 ; les 25 autres lancent une image officielle ou construite sur place).
- ~~**Toutes les commandes d'un script**~~ : fait le 14 octobre 2026 (3 `npx` non figés et
  1 `docker run` trouvés plus loin dans un script).
- ~~**CW102 pour `--with`**~~ : fait le 20 octobre 2026 (17 alertes de plus sur le corpus).
- **CW108 et outils en lecture seule** : 9 listes `alwaysAllow` sur 12 ne contiennent que des
  outils de lecture, que la règle tolère ; distinguer lecture et écriture (gravité basse ?).
- **CW105 dans les arguments** : `npx mcp-remote http://hôte-distant/sse` n'est pas signalé
  (seules les clés `url` le sont). Mesuré le 20 octobre : 1 seul cas sur 3 099 exemples.
- **Fichiers `.code-workspace`** (VS Code) : réglages sous `"settings"` ; vérifier si VS Code
  y lit des serveurs MCP et `chat.tools.autoApprove`.
- **Valeurs de CW109 sans tenir compte de la casse** (`BypassPermissions`) : seulement si
  l'outil concerné les accepte ainsi.
- **`npm init` / `pnpm create`** : téléchargent et lancent un paquet, rares pour MCP.
- **Restes « bas » de l'Auditeur** : `--session dev01` encore pris pour un secret ;
  `${env:A}littéral${env:B}` lu comme une référence (motif `.+` trop gourmand, antérieur à 0.3.0).

## Règle CW111 (14 octobre 2026)
- ~~**CW106 sur toute la ligne**~~ : fait le 20 octobre 2026 (`containers.run_options`).
- **Images officielles de Docker Hub** (`node`, `python`) non signalées : seul Docker peut y
  publier. À revoir si des utilisateurs le demandent.
- **`docker compose run`** : l'image est dans `docker-compose.yml` (YAML, hors périmètre sans
  dépendance).
- **`major.minor`** (`:1.0`) accepté comme version précise : il suit pourtant les correctifs
  dans beaucoup d'images. Une gravité basse pour ce cas ?
- **CW103 et CW110 dans un script** : les mots d'un `bash -c "…"` ne sont pas encore
  examinés pour les secrets (`--api-key …`) ni pour `--insecure`, seulement les programmes.
- **Fin de ligne dans `command`** : `"cd x\nnpx …"` écrit dans `command` n'est pas découpé
  (sans shell, le client chercherait un programme de ce nom).

## Version 0.4.0 (20 octobre 2026)
- **Auto-test de l'Action en CI** : remplacer, dans le job « dogfooding » de `ci.yml`, l'installation
  et le scan par `uses: ./` (fichier protégé : modification par le mainteneur).
- **GitHub Marketplace** : publier l'Action (case à cocher à la création d'une release ; il faut
  accepter les conditions de la Marketplace : décision du mainteneur).
- **Exceptions par serveur** : cibler un serveur précis d'un fichier (`server=nom`), pas tout le
  fichier ; il faudrait un champ « serveur » dans les constats.
- **Hook pre-commit plus ciblé** : analyser seulement les fichiers modifiés (le CLI n'accepte
  qu'un chemin aujourd'hui). Depuis la revue de l'Auditeur, le hook tourne à chaque commit :
  un filtre sur les fichiers JSON laissait passer un secret ajouté ailleurs.
- **Variables d'environnement qui changent ce qui s'exécute** (règle CW112 possible, à valider) :
  `NODE_OPTIONS=--require …`, `LD_PRELOAD`, `BASH_ENV`, `PYTHONPATH`, mais aussi
  `npm_config_package` (installe un paquet de plus), `npm_config_registry`, `UV_INDEX_URL`,
  `PIP_INDEX_URL` (registre remplacé). Seul `npm_config_call` est signalé en 0.4.0 (CW101).
- **CW106, isolation** : `--cgroupns=host`, `--security-opt label=disable` (SELinux coupé) et
  `--device` sur un disque ne sont pas encore signalés.
- **Ligne donnée à `npx -c "…"`** : signalée (CW101) mais pas analysée comme un script
  (`bash -c`) ; un paquet non figé ou venu de GitHub à l'intérieur passerait sans alerte de plus.
- **Azure Pipelines et autres CI** : `##vso[…]` est neutralisé dans les rapports ; un journal
  produit par un autre outil reste à vérifier au cas par cas.
- **Lanceurs pnpm dlx et bunx** : lus comme npx (options courantes identiques). Une lecture
  exacte de leurs propres règles éviterait de rares fausses alertes.

## Nouvelles idées
-
