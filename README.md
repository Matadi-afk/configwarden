# configwarden

**Security scanner for AI agent configurations.** Finds hardcoded secrets, dangerous MCP server setups and supply-chain risks before they reach production.

[![CI](https://github.com/Matadi-afk/configwarden/actions/workflows/ci.yml/badge.svg)](https://github.com/Matadi-afk/configwarden/actions/workflows/ci.yml)
![License](https://img.shields.io/badge/license-Apache--2.0-blue)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)

AI agents (Claude, Cursor, VS Code Copilot…) are increasingly wired to tools through the **Model Context Protocol (MCP)**. One bad config line can hand an agent, or anyone who hijacks it through prompt injection, a shell on your machine or your whole home directory. `configwarden` catches these mistakes in seconds.

- **Zero runtime dependencies**: nothing extra to trust.
- **Never prints a secret in full**: reports are safe to share in CI logs.
- **SARIF output**: results show up natively in GitHub Code Scanning and other security dashboards.

*Formerly named `agentguard`: renamed in October 2026 because that name was too close to other projects. Releases up to v0.2.2 use the old name.*

## Quick start

Requires Python 3.10+.

```bash
pip install configwarden==0.4.0
configwarden scan .
```

### Try it on the bundled example

```bash
git clone https://github.com/Matadi-afk/configwarden
cd configwarden
pip install .
configwarden scan examples/vulnerable-mcp   # 18 findings
configwarden scan examples/safe-mcp         # the fixed version: no issues
```

```text
[HIGH] CW101 MCP server runs a shell script or inline code
    mcp.json:16  Server 'helper' executes commands through 'bash -c'.
    Fix: Call the server program directly, with its arguments as separate items ...

[HIGH] CW106 MCP server container escapes isolation
    mcp.json:26  Server 'sandbox' runs a container with a mount of '/var/run/docker.sock'.
    Fix: Remove --privileged, host namespaces and mounts of '/', the home directory or the Docker socket. ...

Scanned 4 file(s), skipped 0. 18 finding(s): 0 critical, 13 high, 5 medium, 0 low.
```

Every value in `examples/` is a fake placeholder, and the example files are named so that no AI client loads them.

## Rules

| ID | Severity | What it detects |
|----|----------|-----------------|
| CW001 | critical | API keys and tokens written in clear (Anthropic, OpenAI, GitHub, AWS, Google, Hugging Face, Slack, Stripe, private keys); documentation examples (`…EXAMPLE`, `sk-xxxx`, truncated keys) are ignored |
| CW100 | medium | MCP config that cannot be parsed (some clients still run the servers they can read from a broken file), or a script too long to be checked entirely |
| CW101 | high | Shell running a script (`bash -c`, `pwsh -Command`, `su -c`), `cmd /c` or WSL with a command line or special characters, `npx -c` and `npm exec -c` (read exactly as npm reads them), `pnpm -c dlx`, `npm_config_call`, a command line with shell operators in `command`, inline code (`node -e`, `python -c`) |
| CW102 | medium | Registry package without an exact version (`^1.0`, `@beta`, `>=1` are not pinned), whatever the launcher: `npx`, `uvx`, `pnpm dlx`, `yarn dlx`, `bun x`, `npm exec`, `uv tool run`, `pipx run`, `deno run npm:`; extra packages too (`uvx --with`, `uv run --with`) |
| CW103 | high | Secret written literally in an MCP server's `env`, `headers`, command line (`--api-key …`, `-e TOKEN=…`) or URL (password, `?token=…`); placeholders, references and plain settings are ignored |
| CW104 | high | Filesystem server exposed to `/`, a whole drive or a whole home directory |
| CW105 | high | Remote MCP server reached over plain `http://` |
| CW106 | high | Docker/Podman server started with `--privileged`, host namespaces, or mounts of `/`, the home directory, `.ssh`/`.aws`… or the Docker socket (options placed before the image, glued forms such as `-v/:/host` or `--privileged=1` included) |
| CW107 | high | Package or script installed from git, a URL or a GitHub shorthand instead of the npm / PyPI registry (`uv run --with git+…`, `deno run https://…`…) |
| CW108 | medium | Tools auto-approved (`alwaysAllow`, `autoApprove`, `trust: true`): no human confirmation |
| CW109 | high | AI client set to approve everything: Claude Code `enableAllProjectMcpServers` or `bypassPermissions`, VS Code `chat.tools.global.autoApprove`, Zed, Cursor `*:*`, Kiro Autopilot |
| CW110 | high | TLS certificate checks turned off: `NODE_TLS_REJECT_UNAUTHORIZED=0`, `*_SSL_VERIFY=false`, `--insecure`, `--strict-ssl=false`, `--allow-insecure-host` |
| CW111 | medium | Container image run by `docker run`, `podman run` or `nerdctl run` without a digest or an exact version: no tag, `:latest`, `:main`, `:stable`, a major version only (`:20`); Docker Hub official images (`node`) and local registries are ignored |
| CW112 | high | Environment that changes what really runs: code loaded through `NODE_OPTIONS=--require`, `LD_PRELOAD`, `BASH_ENV`, a Java agent…, a debugger port (`--inspect`), or a non-official package registry (`PIP_INDEX_URL`, `npm_config_registry`, `npx --registry`, `uvx --index-url`), in a server's `env`, in Claude Code settings or on the command line |
| CW113 | medium | Command run automatically by the AI client or the editor: hooks (Claude Code, Gemini CLI, Cursor, Copilot CLI, Windsurf, Kiro), Claude Code `statusLine` / `apiKeyHelper`…, MCP `headersHelper`, VS Code tasks with `"runOn": "folderOpen"`, dev container `initializeCommand` (the way the Shai-Hulud worm reinstalls itself) |

Commands hidden later in a shell script (`bash -c "cd /srv && npx -y server"`) are checked too.

Run `configwarden rules` to list them from the CLI.

## Supported configuration files

configwarden reads every `.json` / `.jsonc` file (comments and trailing commas allowed) and looks for MCP servers wherever each AI client keeps them:

| Client | Where the servers live |
|---|---|
| Claude Desktop, Cursor, Windsurf, Cline, Roo Code, Kiro, Amazon Q, GitHub Copilot CLI | `mcpServers` |
| Claude Code | `.mcp.json`, and `~/.claude.json` (user and per-project servers) |
| Gemini CLI | `mcpServers` in `.gemini/settings.json` and extensions (`url`, `httpUrl`) |
| VS Code | `servers` in `.vscode/mcp.json`, `mcp.servers` in settings, `devcontainer.json` customizations |
| Zed | `context_servers` in `settings.json` |

Commands that run automatically (CW113) are found in hooks files (`.claude/settings.json`, `.cursor/hooks.json`, `.gemini/settings.json`, `.github/hooks/*.json`, `.windsurf/hooks.json`, `.kiro/hooks/*.json`), in `.vscode/tasks.json` and in `devcontainer.json`.

Other JSON files are only reported when they contain MCP servers or such commands. YAML (Continue) and TOML (Codex CLI) configurations are not supported yet.

Wrapped commands are unwrapped before being checked: `cmd /c npx …`, `wsl …`, `env VAR=1 …` (and `env -S`), `sudo …`, `uv run …`, `pnpm exec …` and `bash -c "…"` are all analysed for the program they really start.

## Usage

```bash
configwarden scan PATH [--format text|json|sarif] [--output FILE]
                     [--fail-on low|medium|high|critical] [--exclude GLOB]...
                     [--no-ignore | --ignore-file FILE]
```

Exit codes: `0` nothing at or above `--fail-on`, `1` findings, `2` usage error.

### Accepting a finding: `.configwarden-ignore`

Put a `.configwarden-ignore` file at the root of the scanned folder, one exception per line, always with a reason:

```text
# rule  file, or folder ending with /   [optional end date]   -- reason (required)
CW106   examples/demo/mcp.json                                -- demo file, intentionally vulnerable
CW111   .vscode/mcp.json               until=2026-12-31       -- vendor has no versioned image yet
```

- One rule per line and one file or folder: no wildcard, never the whole project.
- After `until=`, the exception stops applying and the finding comes back.
- A malformed line is reported (by its number, without copying its content) and ignored. So is a line containing a control or invisible character, even in a comment.
- A secret pasted in a reason by mistake is masked in every report.
- Suppressed findings no longer fail the scan, but they are **always listed** at the end of the text report and in the JSON report, with their reason: a repository cannot hide its own dangerous configuration without it showing. They are left out of SARIF reports, because GitHub Code Scanning ignores SARIF suppressions and would show them as open alerts.
- `--no-ignore` reports everything. `--ignore-file FILE` reads exceptions from a file you trust instead (for example outside a repository you are reviewing). The project's own file is never read through a symbolic link.

### GitHub Action

```yaml
jobs:
  configwarden:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # only needed to upload SARIF results
    steps:
      - uses: actions/checkout@<commit-sha>   # v7
        with:
          persist-credentials: false
      - uses: Matadi-afk/configwarden@<commit-sha>   # v0.4.0
        with:
          fail-on: high                  # low (default), medium, high or critical
          sarif-file: configwarden.sarif # optional
          # exclude: |                   # optional, one glob per line
          #   examples/*
      - uses: github/codeql-action/upload-sarif@<commit-sha>   # v4
        if: always()
        with:
          sarif_file: configwarden.sarif
```

Pin every action to a full commit SHA (`git ls-remote https://github.com/Matadi-afk/configwarden refs/tags/v0.4.0` prints the one for v0.4.0). The action needs no token and no permission, installs nothing, and runs configwarden in isolated mode with the Python already installed on the runner (3.10 or later; add `actions/setup-python` before it otherwise), so the scanned repository cannot replace its code. Results then appear in the repository's **Security → Code scanning** tab.

File and server names from the scanned repository cannot drive the runner either: under GitHub Actions the text report is printed with workflow commands stopped (`::stop-commands::` and a random token), and `##` sequences (`##[…]`, Azure's `##vso[…]`) are neutralised in every report format.

### pre-commit

```yaml
repos:
  - repo: https://github.com/Matadi-afk/configwarden
    rev: <commit-sha>  # frozen: v0.4.0
    hooks:
      - id: configwarden
```

The hook runs on every commit and scans the whole repository: a dangerous MCP configuration or a secret, in any file, blocks the commit.

## Development

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pre-commit install
pytest
```

See [CHANGELOG.md](CHANGELOG.md) for release notes and [SECURITY.md](SECURITY.md) to report a vulnerability.

## License

Apache-2.0
