# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- **CW111 (medium)**: container image run by `docker run`, `podman run` or `nerdctl run` without a digest or an exact version. Reported: no tag (Docker pulls `:latest`), `:latest`, `:main`, `:stable` and other floating tags, a tag without any digit (`:alpine`) and a major version only (`:20`, `:v1`). A digest (`@sha256:…`) is recommended; an exact version (`:1.2.3`) is accepted. Docker Hub official images (`node`, `python`) and local registries (`localhost:5000/…`) are not reported, since no one else can publish there. Global options, grouped short options (`-it`, `-eKEY=V`) and `docker container run` are understood; an unknown option stops the analysis instead of guessing. Measured on 3,099 published configuration examples: 85 of the 110 `docker run` lines are affected.

### Changed
- **Every command of a shell script is now checked**, not only the first one. In `bash -c "cd /srv && npx -y server"`, only `cd /srv` was read: CW101 reported the script, but an unpinned package (CW102), an unverified source (CW107), a dangerous container (CW106) or an unpinned image (CW111) further down went unnoticed. Commands separated by `;`, `&&`, `||`, `|`, `&`, parentheses or a new line are read, in `bash -c`, `sh -c`, `su -c`, `cmd /c`, `pwsh -Command` and in a command line written in `command`; leading `VAR=value`, `exec`, `then`, `do`… are skipped, and the word after a redirection (`> file`) is not taken for a command. Limits: 20 extra commands per server, shared by nested scripts. On 3,099 published examples, 4 servers hid such a problem.

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

[Unreleased]: https://github.com/Matadi-afk/configwarden/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/Matadi-afk/configwarden/compare/v0.2.2...v0.3.0
[0.2.2]: https://github.com/Matadi-afk/configwarden/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/Matadi-afk/configwarden/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/Matadi-afk/configwarden/releases/tag/v0.2.0
