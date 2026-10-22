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
- ~~**Variables d'environnement qui changent ce qui s'exécute**~~ : fait le 21 octobre (CW112).

## CW112 et CW113 (21 octobre 2026)
- **CW112, formes PowerShell restantes** : `[Environment]::SetEnvironmentVariable("A", "…")`
  et `Set-Item Env:A …` ne sont pas lus (seul `$env:A = …` l'est). Rares dans une
  configuration MCP (revue de l'Auditeur).
- **CW112, variables écartées exprès** : `PYTHONPATH` (très courant, souvent vers le projet),
  `docker run -e …` (s'applique dans le conteneur). À revoir si un cas
  réel d'abus apparaît.
- **CW112, `GIT_SSH_COMMAND` : fait et limites** (revue de l'Auditeur, 2e à 5e passes) :
  `-F fichier` (fichier de configuration du dépôt, qui peut contenir un `ProxyCommand`) est
  signalé sauf `-F /dev/null` et un fichier d'un dossier du système ou des outils de
  l'utilisateur ; `-o Include=…` est refusé par ssh sur la ligne de commande (code source
  d'OpenSSH, non vérifié avec un ssh réel). Un programme n'est « le vrai ssh » que par son nom
  seul ou dans un dossier du système (`/usr/bin`, `/usr/local/bin`, `/bin`, `/opt/homebrew`,
  `/Applications`, `/usr/local/go/bin`, `/opt/X11/bin`, les dossiers système de macOS…, mais pas
  `/usr/src`, `/opt/app`, `/home`, `/tmp` ni `/proc`, où un projet peut se trouver) ou dans un
  dossier caché, `bin` ou `go/bin` de l'utilisateur (`~/.local/bin`, `~/bin`, `~/go/bin`).
  Les chemins Windows (`C:\Windows`, `C:\Program Files`, `C:\Users\…\scoop`) ne sont de confiance
  que **si le scanner tourne lui-même sous Windows** : ailleurs, `C:` est un dossier du projet.
  Conséquence : la même configuration peut être signalée par une CI Linux et pas sur le poste
  Windows de son auteur ; l'exception se déclare alors dans `.configwarden-ignore`. Faux
  positifs connus, jugés rares : un chemin entre guillemets avec une parenthèse
  (`"C:\Program Files (x86)\PuTTY\plink.exe"`, les parenthèses comptent comme du shell même
  entre guillemets), `//usr/bin/ssh` (double barre), un `HOME` redéfini avec `$HOME` dans la
  même commande, un `PATH` avec des dossiers de l'utilisateur à côté d'un `ssh` seul. Faux
  négatif connu : un dossier caché d'un projet cloné dans le dossier de l'utilisateur
  (`/home/dev/.cache/projet/ssh`) est jugé de confiance.
- **CW112, noms lus tels quels** (7ᵉ passe) : le nom du programme (et celui du fichier de `-F`,
  ou d'un dossier de `PATH`) n'est jamais « nettoyé ». Une espace, une espace insécable ou un
  guillemet devant le nom en font un autre fichier : `" /usr/bin/ssh"` est un dossier « » (une
  espace) du projet. Seuls l'espace, la tabulation et le saut de ligne du début d'une ligne de
  commande sont sautés, comme le fait le shell. Sous Windows seulement, un dossier de `PATH`
  peut être entouré de `"`. `BASH_ENV` est un nom de fichier : `" "` (une espace) en est un.
  Dossiers ajoutés : `/usr/local/go/bin`, `/opt/X11/bin`, `/System/Cryptexes/App/usr/bin`,
  `/Library/Apple/usr/bin`, `~/go/bin`.
- **CW112, valeurs par défaut dans un texte** (7ᵉ passe) : `-${U:-r} ./h.js` est lu comme
  `-r ./h.js` quand `U` est absente (ou vide). Formes lues : `:-`, `-`, `:=`, `=` et `:+` ; les
  défauts emboîtés se lisent de l'intérieur (8 niveaux, puis « too many or too deep »). Non lu :
  `${U:?r}` (erreur, jamais `r`). Si `U` est aussi posée dans le bloc, sa valeur est lue en plus.
  Faux positif possible, rare : un défaut qui complète un mot dangereux alors que la vraie variable
  est posée ailleurs (`-${U:-r}` avec `U=max-old…`).
- **CW112, la syntaxe de Claude Code** (8ᵉ passe) : Claude Code développe `${…}` avec
  `/\$\{([^}]+)\}/g` et coupe le contenu au premier `:-` (`split(":-", 2)`). Le nom n'a donc aucune
  forme imposée et le défaut s'arrête à la première `}` : `${a.b:-r}`, `${1:-r}`, `${:-r}`,
  `${U:-r:-z}` (lit `r`) et `${${:-r}` (lit `r`) sont lus comme `r`. `_client_reading` en fait une
  troisième lecture, en une seule passe comme le client, en temps linéaire (le reste après la
  dernière `}` est mis de côté). Limite : on ne sait pas si le client a la variable ; on suppose
  qu'elle est absente, comme pour un shell.
- **CW112, espaces que le shell ne coupe pas** (8ᵉ passe) : `sh` coupe les mots sur l'espace, la
  tabulation et le saut de ligne seulement. `ssh\r.x/ssh` (retour chariot) ou `ssh\u00a0.x/ssh`
  (espace insécable) est UN programme du projet, alors que l'analyse y lit `ssh` puis `.x/ssh`.
  Toute autre espace dans un `GIT_SSH_COMMAND` est donc signalée, où qu'elle soit (`-F\r/etc/…`
  aussi). Faux positif accepté : un retour chariot en fin de valeur (`ssh -i k\r\n`), très rare.
- **CW112, ce que lit Claude Code puis ce que développent npm et le shell** (9ᵉ passe) :
  `$${a.b:-{}REG}` devient `${REG}` après le client ; npm lit alors `REG` dans le bloc `env` du même
  serveur. Les variables du bloc sont donc suivies aussi à partir du texte lu par le client. Limite
  connue : on ne suit qu'un aller-retour (client, puis références, puis client sur le résultat).
- **Le serveur entier relu avec ses défauts** (9ᵉ passe) : `${A:-bash}` dans `command`, `args`,
  `url`, `headers` ou `env` est ce qui s'exécute quand `A` est absente. `_client_view` en fait une
  copie du serveur (champs lus jusqu'à 8 niveaux), vérifiée en plus de l'original ; un constat qui
  ne diffère que par la valeur montrée (`'https://…'` ou `'https://hôte/…'`, un secret masqué
  différemment) n'est compté qu'une fois. Reste signalé, par prudence : `npx -y ${A:-pkg@1.2.3}`
  (CW102), car `A` peut valoir autre chose. Hors champ : les commandes de hooks et de tâches
  (`_program`), lues par un vrai shell, qui ne comprend que les noms de variables ordinaires.
- **Mot entre guillemets collé à du texte** (9ᵉ passe) : sur une ligne avec `\` (lue sans échappements,
  comme un chemin Windows), `"ssh"x\p` est UN mot pour le shell. Les guillemets doubles ne coupent
  plus le mot. Les apostrophes n'ont pas besoin du même traitement : leur mot s'étend jusqu'au
  prochain blanc, donc un mot lu plus court que le vrai garde une apostrophe et n'est jamais « ssh ».
- **`..` caché dans un chemin de confiance** (10ᵉ passe) : sur une ligne avec `\`, le programme garde
  sa forme écrite (chemin Windows), mais un shell retire `\` et les guillemets : `.\.` et `..''`
  sont `..`. `_is_system_location` cherche `..` dans le chemin écrit puis dans le chemin sans `\ ' "`
  (retirer plus que le shell ne retire peut signaler à tort, jamais rater un `..`). Faux positif
  accepté : un chemin avec `\\` ou des guillemets droits qui ne forment pas `..` pour le shell
  (`/usr/bin/.\\./x`) est signalé aussi. Le même contrôle sert au fichier `-F` et aux entrées de `PATH`.
- **`GIT_SSH`** (10ᵉ passe) : git lance ce fichier à la place de `ssh`, sans shell ni options ; `ssh -i k`
  y est donc le nom d'un fichier. `_git_ssh_program_issue` ne laisse passer que `ssh` / `plink` du
  système (nom seul avec un `PATH` sûr, ou chemin dans un dossier du système). `~` et `$HOME` n'y
  sont jamais développés (`${HOME}/.local/bin/ssh` est signalé : faux positif accepté, comme dans un
  `PATH`). Un fichier `ssh` dans `/home/<utilisateur>/bin` est de confiance (limite déjà acceptée).
- **Programme entre guillemets devant `=`** (8ᵉ passe) : `''a=x/ssh` n'est pas une affectation pour
  un shell, c'est le programme `a=x/ssh` du projet. `commands.program_word` ne saute un mot que si
  sa forme décodée ET sa forme écrite (guillemets compris) sont des affectations. Limite connue :
  `commands.analyse` (scripts `bash -c`) décode les mots avant de reconnaître une affectation,
  donc `bash -c "''a=x/prog -i k"` y est lu comme l'affectation `a=x/prog` suivie d'un programme
  `-i`. Aucun faux négatif (CW101 signale déjà `bash -c`, et le programme réel est un fichier du
  projet, pas un programme connu) ; au pire une alerte CW112 en trop sur un `NOM=valeur` entre
  guillemets, et le programme réel n'est pas nommé. À corriger si un jour la découpe des scripts
  garde le texte écrit de chaque mot.
- **CW112, `~` et `$HOME`** (6ᵉ passe) : ils ne comptent que là où le shell les développe. Entre
  guillemets (`"~/.x/ssh"`, `'$HOME/x'`), après un `\` ou dans un `PATH` du bloc `env` (ni le client
  ni la recherche d'un programme ne les développent), `~/bin` est un dossier `~` du projet. Faux
  positif accepté : un guillemet près d'un `~` ailleurs sur la ligne (`ssh -i "~/.ssh/id" -F ~/c`)
  fait traiter tous les `~` de la ligne comme non développés. Dossiers du système ajoutés :
  `/usr/games`, `/snap/bin`, `/nix/store`, `/run/current-system/sw/bin`.
- **CW112, références entre variables** (5ᵉ passe) : `NODE_OPTIONS=${X}` avec `X` posé dans le
  même bloc `env` ou sur la ligne de commande est lu avec la valeur de `X` (npm développe `${X}`
  lui-même dans ses réglages, un shell `$X`). Bornes : 8 niveaux, 8 définitions par variable, 64
  combinaisons, 20 000 caractères par texte et 400 000 caractères relus par serveur ; au-delà, CW112
  le dit (« too many or too deep ») au lieu de
  deviner. Seules les variables que CW112 regarde sont développées (sinon 3 000 variables
  inutiles coûteraient des secondes). Non lus : le fichier `envFile` de VS Code et les `.env`
  (leur contenu n'est pas dans la configuration).
- **CW112, autres variables qui changent ce qui s'exécute (non signalées seules)** : `HOME`
  et `USERPROFILE` relatifs (git y lit `.gitconfig`, `~/.npmrc`…), `PATH` relatif,
  `GIT_PROXY_COMMAND`, `GIT_ASKPASS`, `SSH_ASKPASS`, `GIT_CONFIG_COUNT`/`GIT_CONFIG_KEY_n`
  (`core.sshCommand`, `core.fsmonitor`), `GIT_EXTERNAL_DIFF`, `PAGER`/`EDITOR`, `SHELL`. Elles ne
  comptent aujourd'hui que pour juger `GIT_SSH_COMMAND` et `GIT_SSH` (HOME et PATH). Décision à
  prendre avec le chef : étendre CW112 à tous les programmes que git lance (`GIT_ASKPASS`,
  `SSH_ASKPASS`, `GIT_PROXY_COMMAND`, `core.sshCommand` par `GIT_CONFIG_*`) ? Même question
  pour `git -c core.sshCommand=…` dans les arguments d'un serveur et pour `PYTHONPATH` /
  `NODE_PATH`. L'Auditeur (10ᵉ passe) a prouvé avec un vrai git que `GIT_SSH=./p/ssh` lance le
  fichier du projet : `GIT_SSH` seul est donc traité (il fonctionne comme `GIT_SSH_COMMAND`) ;
  les autres restent à décider (risque de fausses alertes : `GIT_ASKPASS=/usr/bin/…` est courant).
- **CW113, nom de programme** : le message ne montre jamais ce qui suit un `=` ni un mot qui
  ressemble à un jeton (20 caractères ou plus sans point, ou format connu), et seulement un nom
  fait de lettres, chiffres, `_`, `.` et `-` (24 caractères au plus) ; sinon « a command ».
  Un mot de passe court de cette forme, collé comme premier mot de la commande, ne peut pas
  être reconnu : il est alors affiché. Cas jugé rare (un `apiKeyHelper` doit être un
  programme). Contrepartie : un nom long ou à rallonge (`mon-serveur-de-production-v2`) est
  aussi remplacé par « a command » ; l'alerte reste la même, seul le nom est perdu.
- **CW113, `hooks` dans un JSON quelconque** : la forme `{"hooks": {"événement": [{"command": …}]}}`
  est reconnue dans tout fichier JSON, pas seulement dans les dossiers des outils IA. Aucune
  fausse alerte observée sur 3 099 exemples ; à restreindre aux dossiers connus si un cas réel
  apparaît. Les réglages `statusLine`, `apiKeyHelper`… ne sont lus que dans
  `.claude/settings*.json` (une fausse alerte avait été trouvée dans un fichier de traduction).
- **CW113, commandes du conteneur** : `postCreateCommand`, `postStartCommand`… s'exécutent
  dans le conteneur, pas sur la machine : non signalés (seul `initializeCommand` l'est).
- **CW113, analyser la commande elle-même** : appliquer à la commande d'un hook les règles
  des serveurs (CW102, CW107…) : un hook `npx github:…` mériterait aussi CW107.
- **CW106, isolation** : `--cgroupns=host`, `--security-opt label=disable` (SELinux coupé) et
  `--device` sur un disque ne sont pas encore signalés.
- **Ligne donnée à `npx -c "…"`** : signalée (CW101) mais pas analysée comme un script
  (`bash -c`) ; un paquet non figé ou venu de GitHub à l'intérieur passerait sans alerte de plus.
- **Azure Pipelines et autres CI** : `##vso[…]` est neutralisé dans les rapports ; un journal
  produit par un autre outil reste à vérifier au cas par cas.
- **Lanceurs pnpm dlx et bunx** : lus comme npx (options courantes identiques). Une lecture
  exacte de leurs propres règles éviterait de rares fausses alertes.

## Nouvelles idées
- **Jeton collé comme nom de paquet (CW101/CW102)** : `npx -y <jeton>` recopie le nom du paquet dans
  le message. Cas artificiel et ancien (relevé par l'Auditeur, 6ᵉ passe), jamais vu dans le
  corpus ; à traiter comme `_program` si un cas réel apparaît.
