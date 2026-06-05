# Threatray MCP Server (package internals)

Technical reference for contributors. For installation and usage, see the [project README](../../README.md).

## Package layout

```
threatray_mcp/
├── server.py              FastMCP server + lifespan + create_server() factory
├── config.py              Settings via pydantic-settings (THREATRAY_* env vars)
├── log.py                 Stderr-only logging configuration
├── errors.py              ThreatrayError hierarchy
├── __main__.py            Stdio entrypoint (configure_logging + mcp.run)
├── client/                Per-section async HTTP clients + shared HttpClient + JobPoller
├── tools/                 Per-section @mcp.tool registrations + cache/format/context helpers
├── formatters/            Per-section markdown formatters + shared platform-link helper
└── models/                Per-section Pydantic input models + cross-section enums
```

Each section module aligns with the public-API taxonomy ([docs.threatray.com/reference](https://docs.threatray.com/reference/overview-api)): `search`, `samples`, `analyses`, `submissions`, `files`, `functions`, `capa`, `ai_analysis`.

## Concepts

| Term | Meaning |
|------|---------|
| **Sample** | A file the platform has ingested. Identified by hash (md5 / sha1 / sha256). Has one or more **Analyses**. |
| **Analysis** | A single run of the analysis pipeline on a Sample (static, dynamic, minidump, mans). Carries a Verdict + Threats + (for dynamic) processes / memory regions / IOCs. |
| **Verdict** | The analysis-level summary classification: `malicious` / `suspicious` / `unknown`. The fourth value `benign` appears only on per-function code-detection sub-records, never as a sample-level filter input. |
| **Threat** | A labeled risk attached to an Analysis: `{label, confidence}`. Multiple Threats can attach to one Analysis. A Threat usually names a Family. |
| **Family** | A specific malware project (e.g. `Emotet`, `CobaltStrike`, `Lumma`), a generic malware category (`Packer`, `Dropper`), a runtime (`MSVC`, `Lua`, `MFC`), or a specific library (`boost`, `curl`, `poco`). |
| **Code detection** | One Threatray code-signature match on a single function inside the analysed code. A function carries zero or more code detections; each detection ties to a Family and contributes to the parent Analysis's Verdict. |
| **YARA / AV match** | File-level matches from 3rd-party YARA rules and the AV engine. Attached to the Analysis as a whole (in `verdict_details`), not to individual functions. |
| **Classification** | The overall pipeline that runs the detection engines and produces the Verdict + Family assignment. |

## Tools

| Tool | Section | Description |
|------|---------|-------------|
| `threatray_search` | search | Search threats, samples, IOCs with operator syntax |
| `threatray_retrohunt_sample` | search | Find similar samples by code similarity |
| `threatray_get_sample` | samples | Sample metadata by hash |
| `threatray_list_analyses` | analyses | Paginated platform-wide list of sample analyses (filter by verdict / date range) |
| `threatray_list_submissions` | submissions | Recent submissions (a file becomes a sample once it has been analysed) |
| `threatray_submit_sample` | submissions | Submit a file for static or dynamic analysis |
| `threatray_submit_url` | submissions | Download the file referenced by a URL and submit it for analysis (does not analyze the URL itself) |
| `threatray_submit_endpoint_scan_archive` | submissions | Submit an endpoint-scan archive |
| `threatray_submit_minidump` | submissions | Submit a Windows minidump |
| `threatray_submit_mans_file` | submissions | Submit a Mandiant `.mans` memory-triage file |
| `threatray_get_task` | submissions | Get one task by task-id |
| `threatray_get_task_by_analysis` | submissions | Get the task that produced an analysis |
| `threatray_list_tasks` | submissions | List tasks (optionally filtered by file hash or submission ID — defaults to all recent) |
| `threatray_get_analysis` | analyses | Full analysis details (verdict, IOCs) |
| `threatray_get_osint` | analyses | OSINT for a hash (md5/sha1/sha256) |
| `threatray_list_endpoint_scan_analyses` | analyses | Endpoint-scan analyses with cursor-based pagination |
| `threatray_get_file_metadata` | files | PE headers, sections, imports, exports, resources, version info — strings excluded by design (paired with `threatray_get_strings`) |
| `threatray_get_strings` | files | Extracted strings list (markdown caps at 200; `response_format='json'` returns every string) |
| `threatray_download_file` | files | File download (password-protected ZIP) |
| `threatray_list_functions` | functions | Function list extracted from a sample, with per-function disassembly metadata (size, address, API call counts, constant counts) |
| `threatray_get_code_detections` | functions | Per-function code-signature + family matches |
| `threatray_retrohunt_functions` | functions | Function-level retrohunt |
| `threatray_diff_functions` | functions | 1-source-to-N-targets function diff (per-match score/confidence/similarity, via `POST /v1/functions/diff`) |
| `threatray_get_capa` | capa | CAPA capability analysis (per-function capability matches with rule names) |
| `threatray_get_ai_analysis` | ai_analysis | AI analysis of a file's functions (with optional `trigger_only` mode that enqueues the job and returns immediately, for slow files) |
| `threatray_get_ai_analysis_by_id` | ai_analysis | Fetch an AI analysis by its ID |
| `threatray_list_ai_analyses` | ai_analysis | All AI analyses for a file |
| `threatray_get_latest_ai_job` | ai_analysis | Latest AI analysis job state for a file |

## Response formats

All tools accept `response_format` (`markdown` default, or `json`). JSON returns the raw upstream payload.

## Error model

Tools propagate typed exceptions from `errors.py` (`ThreatrayError` and subclasses: `ThreatrayAuthError`, `ThreatrayForbiddenError`, `ThreatrayNotFound`, `ThreatrayFeatureUnavailable`, `ThreatrayRateLimitError`, `ThreatrayServerError`, `ThreatrayTimeoutError`, `ThreatrayConnectionError`, `ThreatrayBadRequest`, `ThreatrayJobFailed`, `ThreatrayJobTimeout`). FastMCP surfaces these as MCP `tool_error` results — the client sees a structured failure rather than a string masquerading as success.

`ThreatrayFeatureUnavailable` specifically signals that the upstream feature (AI analysis, function diffing) isn't enabled for the caller's account.

## Joining function-level data

A code region (a memory dump or sample) carries N functions, each independently analysed by the platform's engines. The agent can join the per-function outputs on two keys:

- **By `uid`** — `threatray_list_functions` produces function records with a stable `uid` (e.g. `CFF.6490927083070388341`). The same `uid` keys into `threatray_get_code_detections` (code-signature + family matches per function) and `threatray_retrohunt_functions` (cross-corpus matches for that function's bytes).
- **By `address`** — `threatray_get_capa` (per-function CAPA capabilities) and `threatray_get_ai_analysis` (per-function AI-generated function summaries + an overall verdict / sample-level summary) key results by the function's virtual address inside the analysed code region.

The Threatray UI assembles all four (`list_functions`, `get_code_detections`, `get_capa`, `get_ai_analysis`) into a single per-function row. Agents can replicate that by calling the four tools for the same `hash` and joining on `uid` (signature/family/retrohunt) and `address` (CAPA/AI).

### Worked example

For a sample with sha256 `<HASH>`, an agent that wants a unified per-function view does:

1. `threatray_get_file_metadata({file_hash: HASH, response_format: "json"})` → confirm the file exists and capture its PE structure / base address.
2. `threatray_list_functions({file_hash: HASH, response_format: "json"})` → get the function list. Each entry has `uid` (e.g. `CFF.6490927083070388341`) and `address` (e.g. `0x401200`).
3. `threatray_get_code_detections({hash_sha256: HASH, response_format: "json"})` → match by `function.uid` to attach signature / family hits.
4. `threatray_get_capa({file_hash: HASH, response_format: "json"})` → match each capability rule's matched addresses against `function.address` to attach capabilities.
5. `threatray_get_ai_analysis({file_hash: HASH, response_format: "json"})` → match `functions[].address` against `function.address` to attach the AI summary + verdict.

Steps (1) and (2) are always available. Steps (3) and (5) may surface `ThreatrayFeatureUnavailable` for realms that don't have code signatures or AI analysis enabled — treat each as optional rather than failing the whole join. Step (4) CAPA is not feature-gated: a 404 there means no CAPA result has been computed for the file yet (`ThreatrayNotFound`), not that the feature is off — call `threatray_get_capa` with `trigger_if_missing=true` to compute one.

There is intentionally no single "joined" tool today: each of the four sources has independent latency (CAPA and AI may trigger async jobs), independent enablement (per-realm feature gates), and independent payload sizes. A fan-out at the MCP layer would hide all three from the agent. The right place to add a server-side join is the backend, not the MCP — and that's a separate ticket.

## Progress reporting

`threatray_get_capa` and `threatray_get_ai_analysis` may trigger long-running async jobs. They report progress via the FastMCP `Context.report_progress` API while polling.

## Pagination

| Tool | Mechanism |
|------|-----------|
| `threatray_search` | `max_results` server-side |
| `threatray_list_submissions` | `limit` + `status_filter` server-side |
| `threatray_retrohunt_sample` | `max_results` server-side |

`list_functions`, `get_code_detections`, `diff_functions` have no pagination; results may be large for complex binaries.

## Extension seam for downstream packages

`threatray_mcp.server.create_server() -> FastMCP` returns a fresh server with all public tools registered. A downstream package can extend it:

```python
from threatray_mcp.log import configure_logging
from threatray_mcp.server import create_server
from my_extra_tools import register_extras

def main():
    configure_logging()
    mcp = create_server()
    register_extras(mcp)
    mcp.run("stdio")
```

The `register(mcp)` pattern used by `threatray_mcp.tools.*` is the idiomatic shape — see any of those modules for a one-page example.

## Adding a new tool (this package)

1. Add an input model to `models/<section>.py` and re-export from `models/__init__.py`.
2. Add a method to `client/<section>.py`; if the section is new, add a fresh section client and wire it onto `ThreatrayClient` in `client/__init__.py`.
3. Add a formatter to `formatters/<section>.py` and re-export from `formatters/__init__.py` (if markdown output is needed).
4. Add the `@mcp.tool` decoration inside the `register(mcp)` function of `tools/<section>.py`.
5. Add tests under `tests/unit/client/` (respx-mocked) and `tests/integration/` (in-process `fastmcp.Client`).

## Configuration

| Env var | Default | Purpose |
|---|---|---|
| `THREATRAY_API_KEY` | (required) | API key for the realm |
| `THREATRAY_API_URL` | (required) | API base — point at the endpoint of the realm your key belongs to (e.g. `https://api-<realm>.analysis.threatray.com`). No default. Mis-pointing at the wrong realm is a common mistake and produces only an auth error, so be deliberate. |
| `THREATRAY_LOG_LEVEL` | `WARNING` | `DEBUG`/`INFO`/`WARNING`/`ERROR` |

Markdown output wraps hashes in clickable links to the Threatray UI; the UI URL is derived from `THREATRAY_API_URL`.

Stdio transport requires stdout to be JSON-RPC-only; logs go to stderr via `log.configure_logging()`.

## Testing

```bash
make unit-tests   # respx-mocked client + formatters + models
make int-tests    # fastmcp.Client in-process tool tests
make test         # both
make lint         # ruff + vulture
```

Without Docker, in a venv with the dev extras installed:

```bash
python -m unittest discover tests
```
