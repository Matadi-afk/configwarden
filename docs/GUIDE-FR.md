# Guide pas à pas (débutant) : de zéro au premier push sécurisé

Suis les étapes dans l'ordre. À chaque étape, la ligne **✅ Vérification** te dit à quoi doit ressembler le résultat. Si ce n'est pas le cas, arrête-toi et copie le message d'erreur exact.

Les commandes sont à taper dans le **terminal intégré de VS Code** (menu *Terminal → Nouveau terminal*). Quand une commande diffère selon le système, les deux versions sont données.

---

## Étape 1 : Installer Python et Git

**Windows** (dans PowerShell) :
```powershell
winget install --id Python.Python.3.13 -e
winget install --id Git.Git -e
```
Sinon, télécharge-les sur python.org et git-scm.com. Pour Python, **coche « Add python.exe to PATH »**.

**macOS** :
```bash
xcode-select --install          # installe Git
# Python : télécharge l'installeur sur python.org (version 3.13)
```

Ferme puis rouvre VS Code, puis vérifie :
```bash
python --version     # macOS : python3 --version
git --version
```
✅ **Vérification :** tu vois `Python 3.1x.x` et `git version 2.x`.

## Étape 2 : Configurer ton identité Git (en protégeant ton e-mail)

Chaque commit publié contient un nom et un e-mail, visibles par tous. Utilise **l'adresse masquée fournie par GitHub** : GitHub → *Settings → Emails* → coche **« Keep my email addresses private »** et copie l'adresse `…@users.noreply.github.com`. Coche aussi **« Block command line pushes that expose my email »**.

```bash
git config --global user.name "Matadi-afk"        # ton pseudo GitHub, pas ton vrai nom
git config --global user.email "12345678+Matadi-afk@users.noreply.github.com"   # 12345678 = ton numéro (Settings → Emails)
git config --global init.defaultBranch main
```
✅ **Vérification :** `git config --global user.email` affiche l'adresse noreply.

## Étape 3 : Ouvrir le projet dans VS Code

1. Récupère le projet dans un dossier de travail (par exemple `Documents/projets/`) :
   `git clone https://github.com/Matadi-afk/configwarden`
2. VS Code → *Fichier → Ouvrir le dossier…* → choisis `configwarden`.
3. Si VS Code demande **« Faire confiance aux auteurs ? »**, réponds *Oui* uniquement parce que tu connais la provenance du dossier. Garde ce réflexe pour tout projet téléchargé.
4. Une notification propose les **extensions recommandées** : clique *Installer*.

## Étape 4 : Créer l'environnement virtuel et installer le projet

Un environnement virtuel (`.venv`) isole les paquets du projet du reste de ton ordinateur.

**Windows (PowerShell) :**
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```
> Si PowerShell refuse avec « l'exécution de scripts est désactivée », lance une seule fois
> `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`, puis réessaie.

**macOS / Linux :**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

Puis, sur tous les systèmes :
```bash
python -m pip install --upgrade pip
pip install -e ".[dev]"
```
✅ **Vérification :** le début de ta ligne de terminal affiche `(.venv)`. Dans VS Code, en bas à droite, l'interpréteur Python indique `.venv`. Sinon : `Ctrl+Shift+P` → *Python: Select Interpreter* → `.venv`.

## Étape 5 : Lancer les tests et l'outil

```bash
pytest
configwarden scan examples/vulnerable-mcp
configwarden scan examples/safe-mcp
```
✅ **Vérification :** une ligne `… passed` sans aucun `failed` (1 012 tests en version 0.4.0 ; sous Windows, quelques-uns sont sautés, `skipped` : c'est normal) ; 18 problèmes sur l'exemple vulnérable ; `No issues found.` sur l'exemple sécurisé.

**Astuce VS Code :** l'onglet *Testing* (icône en forme de fiole) liste et lance les tests. Avec `F5`, tu lances l'outil en mode débogage et tu peux poser des points d'arrêt.

## Étape 6 : Créer le dépôt Git et activer les protections

```bash
git init
pre-commit install
pre-commit run --all-files
```
Le premier lancement télécharge les outils (dont gitleaks), ce qui prend 1 à 3 minutes.

✅ **Vérification :** toutes les lignes affichent `Passed`. Si l'installation de gitleaks échoue, installe Go (go.dev/dl) puis relance.

> **Mettre à jour les outils de contrôle** (une fois par mois) : sous Windows, active d'abord
> l'UTF-8, sinon l'erreur `'charmap' codec can't decode` apparaît :
> ```powershell
> $env:PYTHONUTF8 = "1"
> pre-commit autoupdate --freeze
> ```
> `--freeze` fige chaque outil par son empreinte (immuable) plutôt que par un nom de version
> modifiable. Vérifie ensuite que la version notée en commentaire n'a pas reculé.

## Étape 7 : Tester le filet de sécurité (important)

On va volontairement essayer de committer un **faux** token pour voir le blocage :

```bash
python -c "open('fuite_test.txt','w').write('token=ghp_' + 'aB3dE5gH7j'*4)"
git add fuite_test.txt
git commit -m "test fuite"
```
✅ **Vérification :** le commit est **refusé** avec `Detect hardcoded secrets ... Failed`. C'est exactement ce qu'on veut.

Nettoie ensuite :
```bash
git rm --cached fuite_test.txt
# Windows : del fuite_test.txt     macOS/Linux : rm fuite_test.txt
```

## Étape 8 : Personnaliser le projet

✅ Fait : les liens du projet (README, `pyproject.toml`, rapport SARIF) pointent vers `github.com/Matadi-afk/configwarden`.

## Étape 9 : Premier commit

```bash
git add .
git status          # relis la liste : AUCUN .env, AUCUNE clé
git commit -m "Initial commit: configwarden scanner MVP"
```

## Étape 10 : Publier sur GitHub

1. Sur GitHub : **+ → New repository**, nom `configwarden`, **Public**. Ne coche rien (ni README ni licence : on les a déjà).
2. Dans le terminal :
   ```bash
   git remote add origin https://github.com/Matadi-afk/configwarden.git
   git push -u origin main
   ```
3. Une fenêtre de connexion GitHub s'ouvre (Git Credential Manager) : connecte-toi via le navigateur.
   > ⚠️ Ne colle **jamais** un token dans l'URL du dépôt (`https://TOKEN@github.com/…`) : il serait enregistré en clair dans `.git/config`.

## Étape 11 : Activer les protections GitHub

Dans le dépôt, onglet **Settings** :

- **Advanced Security** : active *Secret scanning* + **Push protection**, *Dependabot alerts*, *Dependabot security updates*, *Private vulnerability reporting* et *Code scanning → CodeQL (Default setup)*.
- **Rules → Rulesets → New branch ruleset** sur `main` (cible : *Include default branch*) : *Restrict deletions* et *Block force pushes*. N'active *Require status checks to pass* que le jour où tu passes par des pull requests : tant que tu pousses directement sur `main`, cette option bloquerait tes push.
- **Actions → General → Workflow permissions** : *Read repository contents permission*.

✅ **Vérification :** l'onglet **Actions** montre la CI en vert. L'onglet **Security → Code scanning** affiche les résultats de configwarden (vides, c'est bon signe).

---

## 🚨 Que faire si un vrai secret fuit un jour

1. **Révoque-le immédiatement** chez le fournisseur (GitHub, OpenAI, AWS…). C'est la seule action qui compte vraiment.
2. Crée-en un nouveau, stocké dans `.env` (jamais dans le code).
3. Seulement ensuite, nettoie l'historique si besoin (outil `git filter-repo`). Ce nettoyage n'annule pas la fuite : des robots copient GitHub en quelques secondes.
4. Vérifie dans les journaux du fournisseur si la clé a été utilisée.

## Règles d'or à garder en tête

- Un secret ne va **que** dans `.env`, et `.env` ne quitte **jamais** ton ordinateur.
- Avant chaque commit, `git status` : relis ce que tu envoies.
- Ne désactive jamais un contrôle pre-commit pour « passer en force » (`--no-verify`) : s'il bloque, il y a une raison.
- Donne à chaque token le minimum de droits et une date d'expiration.
