# Changelog

All notable changes to `threatray-mcp` are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.3] — 2026-06-09

### Added
- `Dockerfile` `EXPOSE 8000` — the default port for the optional HTTP transport.

### Changed
- `Development Status` classifier → `5 - Production/Stable` (matches the 1.0 line).

### Fixed
- README links are now absolute so they resolve on the PyPI project page
  (relative links don't resolve there).

## [1.0.2] — 2026-06-09

### Overview

`threatray-mcp` is a Model Context Protocol server for the Threatray malware
analysis and threat intelligence platform. It runs over stdio so MCP-aware
clients (Claude Code, Claude Desktop, Cursor, Cline, Windsurf, …) can query
samples, run code-similarity retrohunts, fetch CAPA capabilities and AI
analyses, aggregate IOCs, and submit files for analysis.

### Tools

28 tools, aligned with the public
[Threatray API taxonomy](https://docs.threatray.com/reference/overview-api):

- **Search:** `threatray_search`, `threatray_retrohunt_sample`
- **Samples:** `threatray_get_sample`
- **Submissions (read):** `threatray_list_submissions`, `threatray_get_task`, `threatray_get_task_by_analysis`, `threatray_list_tasks`
- **Submissions (write):** `threatray_submit_sample`, `threatray_submit_url`, `threatray_submit_endpoint_scan_archive`, `threatray_submit_minidump`, `threatray_submit_mans_file`
- **Analyses:** `threatray_get_analysis`, `threatray_get_osint`, `threatray_list_analyses`, `threatray_list_endpoint_scan_analyses`
- **Files:** `threatray_get_file_metadata`, `threatray_get_strings`, `threatray_download_file`
- **Functions:** `threatray_list_functions`, `threatray_get_code_detections`, `threatray_retrohunt_functions`, `threatray_diff_functions`
- **CAPA:** `threatray_get_capa`
- **AI Analysis:** `threatray_get_ai_analysis`, `threatray_get_ai_analysis_by_id`, `threatray_list_ai_analyses`, `threatray_get_latest_ai_job`

All tools accept `response_format=markdown` (default) or `response_format=json`.

### Configuration

Settings via environment variables (prefix `THREATRAY_`):

| Env var | Default | Purpose |
|---|---|---|
| `THREATRAY_API_KEY` | (required) | API key for the realm |
| `THREATRAY_API_URL` | (required) | API endpoint for the realm your key belongs to |
| `THREATRAY_LOG_LEVEL` | `WARNING` | `DEBUG` / `INFO` / `WARNING` / `ERROR` |
| `THREATRAY_TRANSPORT` | `stdio` | `stdio` (default) or `http` (standalone server) |
| `THREATRAY_HOST` | `0.0.0.0` | Bind address when `THREATRAY_TRANSPORT=http` |
| `THREATRAY_PORT` | `8000` | TCP port when `THREATRAY_TRANSPORT=http` |

### Notable

- **Transports:** stdio (default — JSON-RPC over stdin/stdout, stdout reserved
  for the protocol, logs to stderr) and streamable HTTP (standalone server on
  `THREATRAY_HOST:THREATRAY_PORT/mcp`, for containerized deployments where the
  consuming client cannot spawn the server as a subprocess). No app-level auth
  on HTTP — restrict ingress at the network layer.
- **Errors:** typed exception hierarchy surfaced as MCP `tool_error` results so
  agents see structured failures rather than success-shaped strings.
- **AI analysis flow:** `threatray_get_ai_analysis` supports a
  `trigger_only=True` fire-and-forget mode for slow files; the agent can poll
  later via `threatray_get_latest_ai_job`. Sync wait is configurable
  (`max_wait_seconds`, default 600s, upper bound 3600s).
- **Python support:** 3.11, 3.12, 3.13.

### Acknowledgments

- **TiQ Labs** — contributed the streamable HTTP transport (server-side
  config + dispatch, compose service, integration test) plus a fix for a
  test-runner bug where Compose-passed empty env vars (`${VAR:-}`) silenced
  `os.environ.setdefault` defaults.
