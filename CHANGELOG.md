# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- **CW112 (high)**: an environment that changes what really runs. Code loaded into every program the server starts (`NODE_OPTIONS` with `--require`, `--import` or `--loader`, `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`, `BASH_ENV` (also when it points to another variable, which bash expands, or when it is only spaces: bash runs the file with that name), Java agents and `-XX:OnError`, `DOTNET_STARTUP_HOOKS`, Perl and Ruby modules, `npm_config_script_shell`, `YARN_YARN_PATH`, a `GIT_SSH_COMMAND` that is too long to be read in full, that is not a plain `ssh` (the system's `ssh` or `plink`, by name or by a path in a system folder such as `/usr/bin` or `/opt/homebrew`, or in a hidden, `bin` or `go/bin` folder of the user's own, where `~` and `$HOME` count only if the shell expands them (not between quotes, not in a `PATH` value): `./ssh`, `"~/.x/ssh"`, `/proc/self/cwd/ssh`, `/usr/src/app/ssh` and `~/project/ssh` are not; `C:\Windows` and `Program Files` paths count as system folders only when the scanner itself runs on Windows, since elsewhere `C:` is a folder of the project; the name is read exactly as the shell reads it, so a space, a no-break space or a quote before it is part of the name: `" /usr/bin/ssh"` is a folder of the project), that sets a variable in front of `ssh`, that uses `$OPTS`-style variables (even a lone `$X`, which git's shell expands from the server's environment) or shell wildcards, that relies on a `HOME` or `PATH` set to something else in the same block or command line (`~`, `$HOME` and a bare `ssh` no longer point to the user's), or that makes `ssh` run a program, load a library or read a configuration file from the project with `-o ProxyCommand=…`, `LocalCommand`, `KnownHostsCommand`, `PKCS11Provider`, `SecurityKeyProvider`, `XAuthLocation`, `-I` or `-F`), a debugger port opened with `--inspect`, and a package registry replaced by a non-official one (`PIP_INDEX_URL`, `UV_DEFAULT_INDEX`, `npm_config_registry`, `npx --registry`, `uvx --index-url`…). Checked in a server's `env` block, in the `env` block of Claude Code settings (applied to every session), and on the command line (`env VAR=…`, `VAR=… cmd`, `export`, cmd `set`, PowerShell `$env:`). A reference to a variable set elsewhere in the same `env` block or command line (`NODE_OPTIONS=${X}` with `X=--require ./h.js`) is replaced by its value before reading, as npm and shells do (every occurrence, names such as `${a-b}` included); a default in the middle of a text is read as a client reads it when the variable is unset (`-${U:-r}` reads `-r`, nested defaults included, and Claude Code's own syntax too: any name, such as `${a.b:-r}` or `${1:-r}`, cut at the first `:-`); in `GIT_SSH_COMMAND`, a space the shell does not split on (carriage return, no-break space…) and a quoted name before `=` (`''a=x/ssh` is a program, not an assignment) are reported; when there are too many or too deeply nested references to read, or the file makes the analysis too long, CW112 says so instead of guessing. Ordinary settings (`NODE_OPTIONS=--max-old-space-size=4096`, the official registries, local test registries, a reference to the user's own setting such as `${NODE_OPTIONS}`) are not reported, and the message never copies the value.
- **CW113 (medium)**: a command that the AI client or the editor runs on its own: hooks of Claude Code, Gemini CLI, Cursor, GitHub Copilot CLI, Windsurf and Kiro; Claude Code settings that run a program (`statusLine`, `apiKeyHelper`, `awsAuthRefresh`, `otelHeadersHelper`…, read only in Claude Code's own `.claude/settings*.json` so that a translation file with a `statusLine` text is left alone) and an MCP server's `headersHelper`; VS Code tasks run when the folder is opened (`"runOn": "folderOpen"`, platform variants included); and dev container `initializeCommand`, which runs on your machine. This is how the Shai-Hulud worm reinstalls itself in its victims' projects. One finding per program; the message names the program, never the command line: a `NAME=value` placed before the program is skipped and its value is never shown, and a name is shown only when it looks like a program name (letters, digits, `_`, `.`, `-`, at most 24 characters), otherwise the message says "a command". A broken file that declares such commands is reported as unreadable (CW100), since editors read these files leniently. Folder trust prompts do not always protect you: they are skipped by `claude -p`, and off by default in Cursor and Gemini CLI.

### Fixed
- `npx` reading: a number after a negated numeric option (`--no-depth 1`) is that option's value, and option values are trimmed, as npm does. Found by comparing with npm itself on 80,000 more command lines.

- A default in the Claude Code syntax is now read everywhere in a server, not only in `env`: with the variable unset, `"command": "${A:-bash}"`, an argument `${A:--c}`, a `url` of `${A:-http://…}` or `--registry ${A:-https://…}` are what runs or what is contacted, so they get the same findings as their plain form (CW101, CW102, CW103, CW105, CW110, CW112…). This also reports `NODE_TLS_REJECT_UNAUTHORIZED=${A:-0}`, which went unnoticed. A finding that only differs by the value it shows is reported once.
- `GIT_SSH_COMMAND`: a quoted word glued to more text on a line with a backslash (`"ssh"x\./p/ssh`) is one word, as for a shell, not a trusted `ssh` followed by something else. What Claude Code reads (`$${a.b:-{}REG}` becomes `${REG}`) is expanded with the variables of the same block, as npm and shells then do.
- `GIT_SSH_COMMAND`: a parent folder hidden by a backslash or a quote on a line that contains a backslash (`/usr/bin/.\./.\./proc/self/cwd/p/ssh`, `/usr/bin/..''\/x/ssh`) is a parent folder, as a shell reads it, so the path is not a system folder. The same check covers the `-F` configuration file.
- `GIT_SSH`, the program git runs in place of `ssh` (no shell, no options), is read too: only the system's `ssh` or `plink` (by name, with a `PATH` of the same block that is itself safe, or by a path in a system folder) is left alone; `./p/ssh`, `~/bin/ssh` (git does not expand `~`) or `ssh -i k` (a file of that name) are reported by CW112, and the message names the program, never the value.

### Changed
- A non-official package registry given to a launcher (`npx --registry`, `uvx --index-url`) is now reported by CW112. It was deliberately ignored before.

## [0.4.0] - 2026-10-20

### Security
Found by an independent review of this release before publication, then re-checked by a second pass. Some of these gaps also affect 0.3.0. They all require a configuration or a repository crafted by an attacker. No user report, no known exploitation.
- **`npx` options were misread**: an option configwarden did not know was assumed to take no value, so `npx --cafile ca.pem -c "…"` (a shell) or a package from GitHub placed after such an option went unreported. `npx` is now read exactly as npm 10 reads it (`npx-cli.js`, then `nopt`: abbreviations, grouped letters, `--no-` options, value types), compared with npm itself on more than 50,000 generated command lines. `npm exec` / `npm x` are read the way npm reads them, with options anywhere on the line (`npm -c "…" exec`, `npm exec server --package=github:…`), `pnpm -c dlx` and `pnpm -c exec` are recognised, and the `npm_config_call` environment variable, which makes npm run a command line in a shell, is reported (CW101).
- **Glued container options were missed** (CW106): `-v/:/host`, `-iv/var/run/docker.sock:/s`, `-v=/:/host` and `--privileged=1` (or `t`, `True`…). Options are now read the way Docker, Podman and nerdctl read them, and a line that cannot be read with certainty is re-read word by word.
- **A new line in `command`** started a second command that was not analysed.
- **CI log commands**: reports print file and server names taken from the scanned repository. A name such as `::error::…` at the start of a line, or `##[…]` (GitHub Actions) and `##vso[…]` (Azure Pipelines) anywhere in a line, could be run as a command by the CI runner (fake annotations, hidden log output, step outputs). Under GitHub Actions the text report is now printed between `::stop-commands::` markers with a random token, report lines never start with `::`, and `##` is neutralised in every format (`#\x23` in text; `#\u0023` in JSON and SARIF, which decodes to the same text).
- Found in the new features of this release before publication: `#` inside a word was taken for a comment in shell scripts, commands after `call` / `start` (cmd), in backquotes or in `$(…)` were skipped, and a script longer than the analysis limit was cut silently (now reported as CW100). In `.configwarden-ignore`, lines were also split on characters that editors and GitHub do not show as line breaks (U+2028, U+0085, `\x0c`…), so an exception could hide in what looks like a comment; a line with a control or invisible character is now refused, a secret written in a reason is masked, and folder exceptions are matched in linear time on very deep paths. The GitHub Action stopped before printing the text report when findings were written to SARIF (GitHub runs steps with `bash -e`), and the pre-commit hook did not run when only non-JSON files were committed.

### Added
- **Exceptions file `.configwarden-ignore`**: accept a finding on purpose, one line per exception: a rule ID, a file or a folder ending with `/`, an optional end date (`until=YYYY-MM-DD`) and a mandatory reason after ` -- `. No wildcard and never the whole project. Suppressed findings no longer fail the scan but are always listed at the end of the text report and in the JSON report (`suppressed`, with the reason), so a repository cannot hide its own dangerous configuration without it showing. They are left out of SARIF reports, since GitHub Code Scanning ignores SARIF suppressions (their number is kept in `runs[0].properties.suppressedResults`). Malformed, expired and unused lines are reported by line number, never by content. The project's file is not read through a symbolic link nor above 256 KB. New options: `--no-ignore` and `--ignore-file FILE` (a file you trust, for example outside a repository under review).
- **GitHub Action** (`uses: Matadi-afk/configwarden@<commit-sha>`): inputs `path`, `fail-on`, `exclude`, `sarif-file` and `no-ignore`. Nothing is installed or downloaded: configwarden runs from the action's own code, at the commit you pin, in Python's isolated mode, so the scanned repository cannot replace its modules. Inputs go through environment variables and are validated, never pasted into the script. No token or permission needed.
- **pre-commit hook** (`id: configwarden`): runs on every commit and scans the whole repository, so a dangerous MCP configuration or a secret in any file blocks the commit.
- **CW111 (medium)**: container image run by `docker run`, `podman run` or `nerdctl run` without a digest or an exact version. Reported: no tag (Docker pulls `:latest`), `:latest`, `:main`, `:stable` and other floating tags, a tag without any digit (`:alpine`) and a major version only (`:20`, `:v1`). A digest (`@sha256:…`) is recommended; an exact version (`:1.2.3`) is accepted. Docker Hub official images (`node`, `python`) and local registries (`localhost:5000/…`) are not reported, since no one else can publish there. Global options, grouped short options (`-it`, `-eKEY=V`) and `docker container run` are understood; an unknown option stops the analysis instead of guessing. Measured on 3,099 published configuration examples: 85 of the 110 `docker run` lines are affected.

### Changed
- **CW102 also checks extra packages**: `uvx --with pkg`, `uv run --with pkg` and a second `npx -p pkg` install more code from the registry, and must be pinned too (19 unpinned extra packages in 3,099 published examples). This includes `uv run --with "mcp[cli]" mcp run server.py`, the configuration written by `mcp install`: use `--with "mcp[cli]==<version>"`. A `--with a,b` list is split the way uv splits it (not inside `pkg[extra1,extra2]`, nor in a version range such as `pkg>=1,<2`).
- **CW106 only reads the options placed before the image**: in `docker run image --privileged`, `--privileged` is an argument of the program inside the container, not a Docker option. If the command line cannot be read with certainty, the whole line is still checked.
- **Every command of a shell script is now checked**, not only the first one. In `bash -c "cd /srv && npx -y server"`, only `cd /srv` was read: CW101 reported the script, but an unpinned package (CW102), an unverified source (CW107), a dangerous container (CW106) or an unpinned image (CW111) further down went unnoticed. Commands separated by `;`, `&&`, `||`, `|`, `&`, parentheses or a new line are read, in `bash -c`, `sh -c`, `su -c`, `cmd /c`, `pwsh -Command` and in a command line written in `command`; leading `VAR=value`, `exec`, `then`, `do`… are skipped, and the word after a redirection (`> file`) is not taken for a command. Limits: 20 extra commands per server, shared by nested scripts. On 3,099 published examples, 4 servers hid such a problem.

### Fixed
- Options written after the package belong to the server, not to the launcher: `npx -y server@1.2.3 -p 3000` reported `3000` as an unpinned package (CW102), and `uvx server==1.0 --from git+https://…` as an untrusted source (CW107).

### Development
- Property-based tests with Hypothesis (development dependency only, never installed for users): thousands of generated command lines, image names, JSON configurations and exception files check that the scan never crashes, never hits its internal error guard, stays fast on very long inputs, and that no secret or control character ever reaches a report. Exceptions are compared with a simple reference model.
- `tests/test_npm_args.py` freezes npm's own answers for tricky `npx` and `npm exec` command lines.
- The `.hypothesis` cache folder is skipped during a scan, like other cache folders.

## [0.3.0] - 2026-10-08

### Security
Detection gaps found by an independent review of this release before publication, then re-checked by a second pass. A configuration crafted to evade configwarden could start a shell or an unverified package without any finding. No user report, no known exploitation.
- **Other package launchers were not checked**: `pnpm dlx`, `yarn dlx`, `bun x`, `npm exec`, `uv tool run` and `pipx run` download and run a package exactly like `npx` or `uvx`, but CW101, CW102 and CW107 skipped them. `uv run`, `pnpm exec`, `yarn exec`, `poetry run`, `pipenv run`, `pdm run`, `hatch run` and `conda run` are now unwrapped, and packages added with `uv run --with` are checked by CW107.
- **`env -S "…"` hid the real command** (`env -S "bash -c …"` reported nothing). The string is now split and analysed.
- **Other ways into a shell**: `su -c`, `runuser`, `script -c`, `setsid`, `busybox sh`, `npx -c` / `pnpm dlx -c`, WSL without `-e` followed by `;` or `|`, and shell operators (`&&`, `;`, `$(…)`, backquotes) in a command line written in `command`.
- **Remote scripts**: `uv run https://…`, `deno run https://…` (CW107) and `deno run npm:…` / `jsr:…` without an exact version (CW102).
- **Quoted program names** (`cmd /c "npx" …`) were not recognised.
- **Misleading host in CW107 messages**: for `git+https://github.com/owner/repo.git@main` the message showed `main` as the host, and a crafted `https://evil.example/x@github.com/…` displayed `github.com` instead of the server that really serves the code. The host is now the one git and curl connect to, and it is hidden when the URL is ambiguous.

### Changed
- **Renamed from `agentguard` to `configwarden`.** The old name is too close to existing projects on PyPI and in the MCP ecosystem (one of them, an MCP proxy, also installs an `agentguard` command). The command and the Python package are now `configwarden`, and rule IDs keep their numbers with a new prefix: `AG103` becomes `CW103`. Entries for earlier releases below keep the old names.
- CW101 is now titled "MCP server runs a shell script or inline code".
- Examples no longer point to a GitHub account that may exist (`not--a--real--user` cannot be a valid account name).
- CW101: `cmd /c` that starts a program given as separate words, without special characters (`& | < > ^ % !`), is no longer reported, since it is the documented way to start `npx` on Windows; the program it starts is analysed instead. A single command-line string or special characters are still reported.
- CW102 only accepts **exact** versions: `pkg@^1.0.0`, `pkg@~1.2`, `pkg@1`, `pkg@beta`, `pkg>=1.0` or `pkg==1.*` are now reported as unpinned.
- CW104 and CW106 also cover whole home directories (`/home/name`, `/Users/name`, `C:\Users\name`, `%USERPROFILE%`, `$env:USERPROFILE`), any drive root, `/root`, and credential folders (`.ssh`, `.aws`, `.gnupg`, `.kube`, `.docker`, `.azure`).
- CW103 no longer reports documentation placeholders (`<YOUR_API_KEY>`, `your-api-key-here`, `xxxx`) or references written as `%VAR%`, `$env:VAR` or `${{ secrets.NAME }}`.
- CW100 (unreadable MCP configuration) is now **medium**: some AI clients still start the servers they can read from a broken file, so an unreadable file may hide a server.
- **Far fewer false alarms**, measured on 3,099 MCP configuration examples published in npm and PyPI package documentation (CW103: 428 → 64 findings, CW001: 5 → 0):
  - CW103 ignores more documentation placeholders (`sk-...`, `ghp_xxxx`, `{API_KEY}`, `your_key`, phrases in other languages, variable names written as values), settings whose name only contains a sensitive word (`MAX_TOKENS`, `OAUTH_PORT`, `TOKEN_URL`, `CLIENT_ID`, `SORT_KEY`, `TOKENIZER_MODEL`…), booleans, short numbers and words (except for passwords), and file paths (`GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json`).
  - CW001 ignores documentation values: AWS `…EXAMPLE` keys, `sk-ant-xxxx…`, Slack tokens without digits (`xoxb-your-bot-token`) and private-key headers followed by `...` or by nothing.
  - CW102 no longer reports a local path (`npx /path/to/server`, `uvx --from ./pkg`).
- `NODE_TLS_REJECT_UNAUTHORIZED=0` is no longer reported as a hardcoded secret (CW103) but as disabled TLS checks (CW110).
- The same finding is reported only once per server.

### Added
- **CW109 (high)**: AI client settings that approve everything without asking: Claude Code (`enableAllProjectMcpServers`, `permissions.defaultMode: bypassPermissions`, `skipDangerousModePermissionPrompt`), VS Code (`chat.tools.global.autoApprove` and its former name `chat.tools.autoApprove`), Zed (`agent.always_allow_tool_actions`, `agent.tool_permissions.default: allow`, `session.trust_all_worktrees`), Cursor (`mcpAllowlist` or CLI `permissions.allow` granting `*:*`) and Kiro (Autopilot). Committed to a repository, such a setting turns opening a booby-trapped project into automatic execution.
- **SARIF paths relative to the current folder** (the repository root in CI), marked with `uriBaseId: %SRCROOT%`, so GitHub links alerts to the right file when a sub-folder is scanned. No absolute path is ever written to a report.
- Demo files in `examples/` for CW109 and for a `cmd /c` command (JSON with comments), named so that no AI client loads them.
- **Real-world configuration files**: configwarden now reads every `.json` / `.jsonc` file and finds MCP servers wherever the main AI clients keep them: VS Code (`.vscode/mcp.json`, legacy `mcp.servers` in settings, `devcontainer.json`), Claude Code (`~/.claude.json`, user and per-project servers), Gemini CLI (`.gemini/settings.json`, extensions), Zed (`context_servers`, both command formats), Cline, Roo Code, Kiro, Amazon Q and GitHub Copilot CLI files. Other JSON files are only reported when they contain MCP servers.
- **JSON with comments and trailing commas** (JSONC), as written by VS Code, Zed or Cursor. It is read in linear time, positions and line numbers are preserved, and a comment can never hide a syntax error. Raw control characters inside strings are tolerated, as lenient client parsers do.
- **Configurations that cannot be audited are reported** (CW100) instead of being silently skipped, so a tolerant AI client cannot run a server configwarden never saw: oversized, binary-looking or symbolic-link configuration files and folders of AI clients (`.vscode/`, `.cursor/`, `.gemini/`, `.claude/`…), and broken JSON files that declare MCP servers.
- Files encoded in **UTF-16 or UTF-32** (with a byte-order mark), which VS Code opens, are now read by every rule, including secret detection, instead of being skipped as binary.
- CW105 also checks Gemini CLI's `httpUrl` key.
- **Wrapped commands are analysed**: `cmd /c`, `wsl`, `env`, `sudo`, `timeout`, `nice` and the script given to `bash -c` / `pwsh -Command` are unwrapped, so CW102, CW104, CW106 and CW107 check the program that really runs. Windows launchers such as `npx.cmd` are recognised.
- CW101 also detects `bash -lc` and grouped options, `env sh -c`, `wsl bash -c`, abbreviated PowerShell options (`-e`, `-ec`, `-Com`…) and **inline code** (`node -e`, `python -c`, `ruby -e`, `perl -e`, `php -r`, `deno eval`).
- CW107 also detects GitHub shorthands (`npx owner/repo`), scp-style git addresses (`git@host:owner/repo`), Python direct references (`name @ git+https://…`) and Mercurial/Subversion/Bazaar sources.
- CW103 also detects passwords inside URLs (`postgres://user:password@host`) whatever the variable name, and literal default values in `${VAR:-default}`.
- **CW110 (high)**: TLS certificate checks turned off (`NODE_TLS_REJECT_UNAUTHORIZED=0`, `PYTHONHTTPSVERIFY=0`, `*_SSL_VERIFY=false`, `*_INSECURE=true`, `GIT_SSL_NO_VERIFY`, `UV_INSECURE_HOST`, `--insecure`, `--strict-ssl=false`, `--allow-insecure-host`, `--insecure-skip-tls-verify`…): anyone on the network path could read or change the traffic, tokens included.
- CW103 also detects secrets **on the command line** (`--api-key …`, `--token=…`, `-e API_KEY=…`, `--header "Authorization: Bearer …"`), which other local users can also read in the process list, secrets **in URLs** (token as user name, `?api_key=…`, signed `sig=` parameters) in `url`, `env` and arguments, JSON-encoded headers in an environment variable, and `*_SESSION` / `*_COOKIE` keys.
- A whole command line written in `command` (`"npx -y pkg"`) is now analysed.

## [0.2.2] - 2026-10-07

### Security
Found by an independent review of 0.2.1, then re-checked by two further bypass attempts on the fixes. All issues require a scanned file or repository crafted by an attacker. No user report, no known exploitation.
- **Credentials still leaked in reports**: URLs with several `@`, a `/`, `?`, `#`, quote or space in the password, a token in the query string (`?token=…`) or in the path of a private registry, and npm shorthands such as `github:user:token@…` were not fully masked. AG107 now shows only the origin of the URL (`https://host/…`).
- **Crash on a malformed URL**: an invalid `url` (e.g. `http://[broken`) stopped the whole scan, and Python's error message could echo the password and raw escape codes. It is now reported as AG105 without echoing the URL, and an unexpected error in one server no longer hides the findings of the others.
- **Report crash on invalid Unicode**: a lone surrogate in a server name or file name made every output format fail and left an empty SARIF file. Surrogates and every Unicode default-ignorable character (zero-width, BOM, tag characters, variation selectors…), which can hide text from humans while an AI reading the report still sees it, are now escaped.
- **Report written through a symbolic link**: `--output` followed a symlink planted in the scanned repository (`agentguard.sarif -> ../file`, or a symlinked folder), which could overwrite another file in CI. agentguard now refuses to write through a symlink or to an output path containing `..`.
- **Denial of service**: line numbers were computed in quadratic time; a crafted file of a few hundred KB blocked the scan for minutes. A FIFO in the scanned tree blocked it forever. Both are fixed (single pass, regular files only).

### Changed
- Short secrets (under 16 characters) are fully masked (`****`) instead of showing their first 4 characters.
- AG103 no longer treats `PATH` as a secret (`PAT` must be a whole word) and now detects `*_PASS` keys.
- AG102/AG107 know which `npx` and `uvx` options take a value (`--registry`, `--index-url`, `uvx -p 3.12`…), which were mistaken for the package; `uvx --with git+…` is now flagged.
- Files starting with a UTF-8 BOM are now analysed instead of being reported as invalid JSON.
- Line numbers count only real line breaks (`\n`), as editors and GitHub do; SARIF URIs are percent-encoded.
- Unreadable folders are counted as skipped, and the text report says when some files could not be analysed.

## [0.2.1] - 2026-10-07

### Security
Three issues found during an internal security review of agentguard itself. They could only be triggered by a scanned file crafted by an attacker. No user report, no known exploitation.
- **Credentials leaked in reports**: AG107 and AG102 copied package URLs verbatim, so `git+https://user:token@host/…` printed the token in clear in text, JSON and SARIF output. Credentials embedded in URLs are now masked (`https://****@host/…`).
- **Output injection**: server names and file paths were printed as-is. Newlines could forge GitHub Actions workflow commands (lines starting with `::`) and ANSI or bidirectional control characters could hide or rewrite terminal output. All control, line-separator and bidi characters in findings are now escaped (`\n`, `\x1b`, `\u202e`…), whatever the output format.
- **Denial of service**: a deeply nested JSON file (`[[[[…]]]]`) crashed the whole scan with a `RecursionError`. It is now reported as AG100 (unreadable configuration) and the rest of the project is still scanned.

### Added
- `tests/test_hardening.py`: regression tests that replay each attack, plus a permanent check that no invisible or bidirectional characters exist in the project's own source code.

### Changed
- Development: pre-commit hooks are pinned to commit SHAs instead of tags.

## [0.2.0] - 2026-10-06

### Added
- **AG106** (high): container-based MCP servers (`docker`, `podman`, `nerdctl` `run`) that break isolation: `--privileged`, host namespaces (`--network host`, `--pid host`…), mounts of `/`, the home directory, `C:\`, `/etc`, `/root`, `/var/run` or the Docker socket, dangerous `--cap-add`, `--security-opt …=unconfined`.
- **AG107** (high): MCP packages installed from git or a URL (`github:`, `git+https://`, `https://…tgz`, `uvx --from git+…`) instead of the npm / PyPI registry.
- **AG108** (medium): tools that run without user confirmation (`alwaysAllow`, `autoApprove`, `trust: true`).
- Demo entries for the new rules in `examples/vulnerable-mcp` and their fixed versions in `examples/safe-mcp`.

### Changed
- AG102 (unpinned package) is no longer reported when AG107 already flags the same package, to avoid duplicate alerts.

## [0.1.0] - 2026-10-05

### Added
- First release: AG001 (hardcoded secrets) and AG100–AG105 (MCP configuration checks).
- Text, JSON and SARIF 2.1.0 reports; exit codes for CI.
- Zero runtime dependencies; secrets are always redacted in reports.

[Unreleased]: https://github.com/Matadi-afk/configwarden/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/Matadi-afk/configwarden/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/Matadi-afk/configwarden/compare/v0.2.2...v0.3.0
[0.2.2]: https://github.com/Matadi-afk/configwarden/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/Matadi-afk/configwarden/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/Matadi-afk/configwarden/releases/tag/v0.2.0
