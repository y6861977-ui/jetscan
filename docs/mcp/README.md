# jetscan as an MCP server

`jetscan mcp` lets AI coding tools such as Claude Code, Cursor, VS Code (Copilot) and
Devin Desktop (formerly Windsurf) call jetscan's checks as tools while they write code.
It uses the Model Context Protocol over stdio: the AI tool starts `jetscan mcp` as a
child process and talks JSON-RPC to it over stdin/stdout.

The idea is that the AI writes code, and jetscan reports the facts: whether a key
was committed, whether a locked package version has a published advisory, whether a
workflow expands untrusted text into a script. The checks are deterministic, so the
same files give the same answer every time.

## What the AI gets

| Tool | What it does | Network | Plan |
| --- | --- | --- | --- |
| `scan_secrets` | Leaked keys, tokens, private keys and `.env` passwords in files and (by default) git history | none | Free |
| `scan_dependencies` | Lockfile versions with known advisories or malicious-package reports (OSV.dev) | **off by default**; `offline: false` sends package names + versions to api.osv.dev | Free |
| `scan_github_actions` | Script injection, `pull_request_target` checking out PR code, unpinned actions, `write-all` permissions | none | Free |
| `resolve_plan` | A fix plan and diff preview for workflow findings. **Never changes files** | none | Free |
| `audit_web_source` | Next.js / Vite React source audit | none | Pro |
| `audit_apk` | Android APK static audit (nothing is installed or run) | none | Pro |

Every tool is read-only, and none of them applies a fix. `resolve_plan` returns a diff,
and the AI is told to show it to you. Applying it is your call. You can run it yourself:

```
jetscan resolve plan . --out jetscan-plan.json
jetscan resolve preview jetscan-plan.json
jetscan resolve apply jetscan-plan.json --confirm
jetscan resolve verify jetscan-plan.json
```

Or you can tell the AI to make the edit.

Each tool result has two text parts:

1. A short summary: counts by severity, the top findings with `file:line`, what was
   *not* checked and why, the limitations, and whether anything went over the network.
2. The same result as strict, redacted Findings V2 JSON (`schema_version: 2`), capped at
   the 50 most severe findings so the AI's context is not flooded. The full report is
   one terminal command away, and the summary names that command.

Secret values never appear in tool results, not even partly masked. This matters
because the AI tool usually sends tool results to a cloud model. Findings carry the
rule, the location and jetscan's 16-hex fingerprint, which is the same value that
`.jetscanignore` and baselines use. A fingerprint of a short or dictionary password can
be brute-forced, so treat reports as sensitive.

## Which files it may read

The tools only read inside the **workspace**:

- the folders given with `jetscan mcp --root <folder>` (repeatable), if any; otherwise
- the folders the AI tool reports as MCP *roots* (see the limits below); otherwise
- the folder the AI tool started `jetscan mcp` in.

A `path` argument outside the workspace is refused, and so is a symbolic link that
points outside it. Scanning a whole home folder or a whole drive is also refused, even
when that is the workspace. Pass a project folder instead.

## Install jetscan first

Put `jetscan` (or `jetscan.exe`) on your `PATH`, or use its full path as the `command`
in the configs below. Check it with `jetscan mcp --help`. `jetscan menu`, item 8, prints
the Claude Code command and the Cursor / VS Code configs with the full path of that
jetscan filled in.

## Claude Code

Verified on 2026-11-13 with Claude Code 2.1.323 on Windows 11. A real session called
`scan_secrets` and `resolve_plan` and relayed the results; the setup used a temporary
`--mcp-config` file, as described below.

```
claude mcp add jetscan -- jetscan mcp
```

Everything after `--` is the server command. The default scope is `local` (only you,
only this project). Use `--scope project` to write a `.mcp.json` for the team, or
`--scope user` to enable it in every project. Check it with `claude mcp list`, or with
`/mcp` inside Claude Code.

As a project file (`.mcp.json` in the project root). An entry without `type` is read as
a stdio server:

```json
{
  "mcpServers": {
    "jetscan": {
      "command": "jetscan",
      "args": ["mcp"]
    }
  }
}
```

Claude Code starts the server in the project folder, so the workspace is that folder.
It also offers MCP roots. jetscan uses roots only from clients on the older handshake
protocol (see "Protocol" below), and Claude Code 2.1 is not one of them.

Source: <https://code.claude.com/docs/en/mcp> (read 2026-11-13).

## Cursor

Project file `.cursor/mcp.json` (or `~/.cursor/mcp.json` for every project). Cursor's
docs say `type` is required for stdio servers. They document `${workspaceFolder}`,
which is the folder that contains `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "jetscan": {
      "type": "stdio",
      "command": "jetscan",
      "args": ["mcp", "--root", "${workspaceFolder}"]
    }
  }
}
```

The docs do not say which folder Cursor starts stdio servers in, so `--root` pins the
workspace explicitly. **Not verified:** this was not tested against a real Cursor. It is
also not known what `${workspaceFolder}` means in the global `~/.cursor/mcp.json`, or
which MCP protocol version Cursor sends. Cursor lists roots support, and without
`--root` jetscan would use roots from Cursor if it uses the handshake protocol.

Source: <https://cursor.com/docs/context/mcp> (read 2026-11-13).

## VS Code (GitHub Copilot)

VS Code's current docs recommend the Copilot "native" files for new setups:
`~/.copilot/mcp-config.json` (or `$COPILOT_HOME/mcp-config.json`), or `.mcp.json` at
the workspace root when the experimental setting `chat.mcp.workspaceRootConfig.enabled`
is on. Both use a top-level `mcpServers` object:

```json
{
  "mcpServers": {
    "jetscan": {
      "type": "stdio",
      "command": "jetscan",
      "args": ["mcp"]
    }
  }
}
```

The older `.vscode/mcp.json` uses a top-level `servers` object. VS Code calls it the
deprecated "Local harness" and says it will be removed in February 2027:

```json
{
  "servers": {
    "jetscan": {
      "type": "stdio",
      "command": "jetscan",
      "args": ["mcp", "--root", "${workspaceFolder}"]
    }
  }
}
```

In that format `cwd` defaults to the workspace folder, and `${workspaceFolder}` is a
documented variable. **Not verified:** this was not tested against a real VS Code. It is
also not verified whether the native `mcpServers` files expand `${workspaceFolder}` or
which folder they start the server in, so the native example above has no `--root`.

Source: <https://code.visualstudio.com/docs/agents/reference/mcp-configuration>
(read 2026-11-13).

## Devin Desktop (formerly Windsurf)

The Windsurf MCP docs URL now redirects to Devin Desktop's docs. The current config
files are:

- user: `~/.config/devin/mcp_config.json` (Windows: `%APPDATA%\devin\mcp_config.json`)
- project: `.devin/mcp_config.json`, plus `.devin/mcp_config.local.json` for a
  gitignored personal override

A stdio entry has no `type`, because the transport is inferred from `command`:

```json
{
  "mcpServers": {
    "jetscan": {
      "command": "jetscan",
      "args": ["mcp"]
    }
  }
}
```

**Not verified:** this was not tested against a real Devin Desktop or Windsurf. The
current docs do not say which folder stdio servers start in, so if scans land in the
wrong folder, add `"--root", "<absolute project path>"` to `args`. The older Windsurf
path `~/.codeium/windsurf/mcp_config.json` (same `mcpServers` shape) comes from earlier
Windsurf docs and was not confirmed against the current docs.

Sources: <https://docs.devin.ai/desktop/cascade/mcp> and
<https://docs.devin.ai/cli/extensibility/mcp/configuration.md> (read 2026-11-13).

## Pro tools and the license key

`audit_web_source` and `audit_apk` are part of jetscan Pro. For now a valid jetscan Teams
key also unlocks them, including in its 14-day grace period after the expiry date (the same
rule as the CLI's Teams flags). In the CLI, `jetscan web source` and `jetscan apk` are free
while they are alpha. Without a key they do **not** scan. They return a
short, normal message for the AI to relay: what the check does, where to get a key
(<https://jetscan.jet.kim>) and how to install it.

- Save the key as one line in `~/.jetscan/license`. It is read on every call, so no
  restart is needed.
- Or set `JETSCAN_LICENSE` in the environment of the AI tool that starts
  `jetscan mcp`, then restart the server. For example, Claude Code takes
  `claude mcp add -e JETSCAN_LICENSE=... jetscan -- jetscan mcp`.

The key is checked on your machine and is never printed or sent.

## Troubleshooting

- The server writes logs to **stderr**, starting with a line like
  `jetscan mcp 0.2.0: serving on stdio, workspace <folder>`. Most AI tools show stderr
  in their MCP logs.
- `refused: ... is outside the workspace`: start the server in the project, or add
  `--root <project>`.
- `refused: ... is your home folder or a whole drive`: the AI tool started jetscan in
  your home folder. Add `--root <project>`.
- `deps.osv: partial ... offline`: `scan_dependencies` only used the local cache. Ask
  the AI to call it with `offline: false`. That sends package names and versions to
  api.osv.dev.

## Protocol

- JSON-RPC 2.0, one message per line on stdin/stdout. Nothing but protocol messages is
  written to stdout. End of input means exit 0.
- **2026-07-28** (current): stateless. Every request carries
  `_meta["io.modelcontextprotocol/protocolVersion"]`, and the server supports
  `server/discover`. Results carry `resultType`, and an unsupported version gets error
  `-32022` with the supported list. Claude Code 2.1.323 uses this.
- **2025-11-25, 2025-06-18, 2025-03-26, 2024-11-05**: the `initialize` handshake. If the
  client offers roots, the server asks `roots/list` after
  `notifications/initialized` and again on `notifications/roots/list_changed`.
- Tools only: `tools/list`, `tools/call`, `ping`. There are no resources, prompts or
  sampling. Calls run one at a time. Tool results have no `structuredContent`, on
  purpose: Claude Code passes `structuredContent` to the model instead of the text, and
  the model would lose the summary.
- Limits: messages up to 4 MiB and JSON nesting up to 64 levels. Batches are refused,
  because MCP has not allowed them since 2025-06-18.

Spec: <https://modelcontextprotocol.io/specification/versioning> and
<https://modelcontextprotocol.io/specification/2026-07-28> (read 2026-11-13).
