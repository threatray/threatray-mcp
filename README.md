# threatray-mcp

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

MCP server for the [Threatray](https://www.threatray.com) malware analysis and threat intelligence platform. Lets MCP-aware clients (Claude Code, Claude Desktop, Cursor, Cline, Windsurf, …) query samples, run code-similarity retrohunts, fetch CAPA capabilities, pull AI analyses, and aggregate IOCs through a single uniform tool surface.

## Quick start

Requires a Threatray API key and Python 3.11+. Install from a local checkout (PyPI release is pending — once it lands the same commands work via `uvx threatray-mcp`):

```bash
git clone https://github.com/threatray/threatray-mcp
cd threatray-mcp
pip install .
```

### Claude Code

```bash
claude mcp add threatray -s user \
  -e THREATRAY_API_KEY=YOUR_API_KEY \
  -e THREATRAY_API_URL=https://api-<your-realm>.analysis.threatray.com \
  -- uvx threatray-mcp

claude mcp list   # should show "threatray: ... connected"
```

Both env vars are required — no default URL. Replace `<your-realm>` with the realm your API key belongs to (provided by your Threatray account team).

### Generic MCP client config

Most MCP-aware editors accept the same JSON shape. Drop this block into the relevant config file (paths below):

```json
{
  "mcpServers": {
    "threatray": {
      "command": "uvx",
      "args": ["threatray-mcp"],
      "env": {
        "THREATRAY_API_KEY": "YOUR_API_KEY",
        "THREATRAY_API_URL": "https://api-<your-realm>.analysis.threatray.com"
      }
    }
  }
}
```

A copy of this snippet is in [`examples/mcp-config.json`](examples/mcp-config.json).

| Client | Config file |
|---|---|
| Claude Code | `~/.claude.json` (managed via `claude mcp add ...`) |
| Claude Desktop | macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`. Windows: `%APPDATA%\Claude\claude_desktop_config.json` |
| Cursor | `~/.cursor/mcp.json` (global) or `<project>/.cursor/mcp.json` (per-project) |
| Cline (VS Code) | Cline UI → "MCP Servers" → edit JSON, or `~/.cline/mcp_settings.json` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` |

After editing, restart the client.

## Configuration

All settings via env vars (prefix `THREATRAY_`):

| Variable | Default | Description |
|---|---|---|
| `THREATRAY_API_KEY` | (required) | API key from your Threatray realm |
| `THREATRAY_API_URL` | (required) | API endpoint for the realm your key belongs to (form: `https://api-<your-realm>.analysis.threatray.com`). Pick a wrong realm and you'll just get auth errors — no default. Provided by your Threatray account team. |
| `THREATRAY_LOG_LEVEL` | `WARNING` | `DEBUG` / `INFO` / `WARNING` / `ERROR` (stderr only, never stdout — stdout carries the JSON-RPC stream) |
| `THREATRAY_TRANSPORT` | `stdio` | `stdio` (default, server runs as subprocess of an MCP client) or `http` (standalone server, see Deployment below) |
| `THREATRAY_HOST` | `0.0.0.0` | Bind address, used only when `THREATRAY_TRANSPORT=http` |
| `THREATRAY_PORT` | `8000` | TCP port, used only when `THREATRAY_TRANSPORT=http` |

Markdown output wraps hashes in clickable links to the Threatray UI; the UI URL is derived automatically from `THREATRAY_API_URL`.

### Deployment

Two transports are supported:
- **`stdio`** (default) — the MCP client spawns `threatray-mcp` as a subprocess. This is what `uvx threatray-mcp` and `claude mcp add` give you.
- **`http`** — long-lived standalone server on `THREATRAY_HOST:THREATRAY_PORT/mcp` (streamable HTTP). Use when the consuming client can't spawn the server (containerized clients, network-segmented deployments). Example: `docker compose --profile http up`. **No app-level auth** — restrict ingress at the network layer.

## Tools

Grouped by [Threatray public API taxonomy](https://docs.threatray.com/reference/overview-api). All 28 tools below; see [`src/threatray_mcp/README.md`](src/threatray_mcp/README.md) for per-tool descriptions.

| Section | Tools |
|---|---|
| Search | `threatray_search`, `threatray_retrohunt_sample` |
| Samples | `threatray_get_sample` |
| Submissions (read) | `threatray_list_submissions`, `threatray_get_task`, `threatray_get_task_by_analysis`, `threatray_list_tasks` |
| Submissions (write) | `threatray_submit_sample`, `threatray_submit_url`, `threatray_submit_endpoint_scan_archive`, `threatray_submit_minidump`, `threatray_submit_mans_file` |
| Analyses | `threatray_get_analysis`, `threatray_get_osint`, `threatray_list_analyses`, `threatray_list_endpoint_scan_analyses` |
| Files | `threatray_get_file_metadata`, `threatray_get_strings`, `threatray_download_file` |
| Functions | `threatray_list_functions`, `threatray_get_code_detections`, `threatray_retrohunt_functions`, `threatray_diff_functions` |
| CAPA Analysis | `threatray_get_capa` |
| AI Analysis | `threatray_get_ai_analysis`, `threatray_get_ai_analysis_by_id`, `threatray_list_ai_analyses`, `threatray_get_latest_ai_job` |

All tools accept `response_format=markdown` (default) or `response_format=json`.

Features not enabled for your account (e.g. AI analysis on some realms) surface as a clean `ThreatrayFeatureUnavailable` tool error rather than an empty result, so the agent gets an actionable signal instead of looping.

## Security

The MCP server runs as a subprocess of your editor under your local user — it inherits read access to every file you can read. The `threatray_submit_*` tools accept a `file_path` argument and upload the file's contents to your configured Threatray realm. Combined with prompt injection (a sample's strings, an OSINT report, a web page rendered in the editor), an attacker could attempt to convince the agent to call e.g. `threatray_submit_sample(file_path="~/.ssh/id_rsa")`.

Mitigations to consider when integrating in a shared or unattended environment:

1. **Don't run the server as a user with read access to secrets** — run it under a least-privilege account or in a sandbox/container without access to your `~`/credentials/git working trees.
2. **Watch for surprising `threatray_submit_*` tool calls** — Claude Code surfaces every tool call before sending it; pay attention to the `file_path` argument before approving.

The same least-privilege account that protects the read side also bounds where `threatray_download_file` can write — the tool relies on OS file-system permissions, not an application-level directory allowlist.

## Troubleshooting

**MCP server not connecting** — verify with `claude mcp list` (or your client's equivalent). If not connected:
1. Confirm Python 3.11+ is on `PATH`.
2. Test the entrypoint directly: `THREATRAY_API_KEY=xxx uvx threatray-mcp` (it'll hang waiting for stdio input — Ctrl-C to exit; absence of an error means startup succeeded).
3. Set `THREATRAY_LOG_LEVEL=DEBUG` and re-launch via the client; check stderr.

**`ThreatrayAuthError`** — API key missing/invalid, OR your key belongs to a different realm than `THREATRAY_API_URL` points at. The error message includes the URL the server tried — confirm it matches your realm.

**`ThreatrayForbiddenError`** — authenticated but the key lacks the required scope.

**`ThreatrayFeatureUnavailable`** — the feature (AI analysis, function diffing, …) isn't enabled for your account. Contact your Threatray account team.

**Connection errors** — `ThreatrayConnectionError` includes the URL it tried; confirm `THREATRAY_API_URL` is reachable from where the MCP server runs.

## Development

```bash
git clone https://github.com/threatray/threatray-mcp
cd threatray-mcp
pip install -e ".[dev]"

# Run all tests (unit + integration)
make test
make unit-tests       # respx-mocked client + formatters + models
make int-tests        # in-process fastmcp.Client end-to-end

# Lint and type check
make lint
make type-check

# Without Docker
python -m unittest discover tests
```

For contributor-facing architecture and the per-section package layout, see [`src/threatray_mcp/README.md`](src/threatray_mcp/README.md). Release notes live in [CHANGELOG.md](CHANGELOG.md).

## License

MIT — see [LICENSE](LICENSE).
