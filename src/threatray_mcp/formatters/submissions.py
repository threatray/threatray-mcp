"""Submissions section formatters."""

from typing import Any

from ._helpers import escape_cell, format_timestamp


def format_submissions_list(data: dict[str, Any], limit: int = 50) -> str:
    submissions: list[dict[str, Any]] = data.get("submissions", [])
    lines = [f"## Submissions: {len(submissions)} found\n"]

    lines.append(
        "| Task ID | Submission ID | Analysis ID | Status | Scope | Verdict | Threats "
        "| Sample / URL | Submitter | Submitted |"
    )
    lines.append(
        "|---------|---------------|-------------|--------|-------|---------|---------"
        "|--------------|-----------|-----------|"
    )
    for s in submissions:
        task_id = s.get("task_id", "?")
        submission_id = s.get("submission_id", "-")
        analysis = s.get("analysis") or {}
        analysis_id = analysis.get("id", "-")
        status = s.get("status", "-")
        # Verdict / threats live on the analysis once analysis has completed;
        # earlier states (queued, analyzing) leave both fields empty.
        verdict = _verdict_str(analysis.get("verdict") or s.get("verdict"))
        threats = _threats_str(analysis.get("threats") or s.get("threats"))
        sample = s.get("sample") or {}
        url_block = s.get("url") or {}
        sha256 = sample.get("hash_sha256", "")
        scope = analysis.get("scope") or sample.get("scope") or "-"
        target = escape_cell(sample.get("file_name") or url_block.get("url") or (sha256 if sha256 else "-"))
        sample_link = f"`{sha256}`" if sha256 else target
        submitter = s.get("username") or "-"
        created = format_timestamp(s.get("created_at"))
        lines.append(
            f"| `{task_id}` | `{submission_id}` | `{analysis_id}` | {status} | {scope} "
            f"| {verdict} | {threats} | {sample_link if sha256 else target} "
            f"| {submitter} | {created} |"
        )

    if len(submissions) >= limit:
        lines.append(f"\n*Returned the page limit ({limit}). Increase `limit` or filter by `status_filter`.*")

    return "\n".join(lines)


def format_submission_response(data: dict[str, Any]) -> str:
    """Render the POST /v1/submissions/* response.

    Each submission record includes `task_id`, `submission_id`, `status`,
    `sample` (with hashes when the backend has classified the file), and an
    `analysis` block (with the analysis UUID). We surface all four IDs the
    agent might need to follow up: task_id, submission_id, analysis.id,
    sample.hash_sha256.
    """
    lines = ["## Submission accepted"]
    err = data.get("error")
    if err:
        msg = err if isinstance(err, str) else err.get("message") or err.get("code") or str(err)
        lines.append(f"\n⚠ Server reported an error: `{msg}`")

    items = data.get("submissions", [])
    if not items:
        if not err:
            lines.append("\n*Server returned no submission records.*")
        return "\n".join(lines)

    lines.append(f"\n{len(items)} submission(s) created:\n")
    lines.append("| Task ID | Submission ID | Analysis ID | Status | Sample SHA256 | File / URL |")
    lines.append("|---------|---------------|-------------|--------|---------------|------------|")
    for s in items:
        task_id = s.get("task_id", "-")
        submission_id = s.get("submission_id", "-")
        analysis = s.get("analysis") or {}
        analysis_id = analysis.get("id", "-")
        status = s.get("status", "-")
        sample = s.get("sample") or {}
        url_block = s.get("url") or {}
        sha256 = sample.get("hash_sha256", "")
        target = escape_cell(sample.get("file_name") or url_block.get("url") or "-")
        lines.append(
            f"| `{task_id}` | `{submission_id}` | `{analysis_id}` | {status} "
            f"| {f'`{sha256}`' if sha256 else '-'} | {target} |"
        )

    return "\n".join(lines)


def _verdict_str(v: Any) -> str:
    if isinstance(v, dict):
        return str(v.get("label") or v.get("value") or "-")
    return str(v) if v is not None else "-"


def _threats_str(threats: Any) -> str:
    if not isinstance(threats, list):
        return str(threats) if threats else "-"
    labels = [t.get("label", str(t)) if isinstance(t, dict) else str(t) for t in threats]
    return ", ".join(labels) or "-"


def format_task(data: dict[str, Any] | list[dict[str, Any]]) -> str:
    """Render a task object.

    `/v1/tasks/{task_id}` returns a single dict. `/v1/tasks/by-analysis/{id}`
    returns a *list* of tasks (one analysis can produce multiple tasks — e.g.
    static + dynamic from the same submission). We render the first task and
    note the count when there are siblings, so the markdown view stays focused
    but the JSON response (when chosen) still carries the full list."""
    if isinstance(data, list):
        if not data:
            return "## Task\n\n_No task found for this analysis._"
        tasks = data
        data = tasks[0]
        sibling_note = (
            f"\n\n*Analysis produced {len(tasks)} tasks; showing the first. "
            "Re-call with `response_format='json'` for the full list.*"
            if len(tasks) > 1
            else ""
        )
    else:
        sibling_note = ""
    sample = data.get("sample") or {}
    analysis = data.get("analysis") or {}
    sha256 = sample.get("hash_sha256", "")
    aid = analysis.get("id", "")
    task_id = data.get("task_id", "?")

    lines = [f"## Task `{task_id}`\n"]
    lines.append("### Submission")
    lines.append(f"- **Status**: {data.get('status', 'unknown')}")
    lines.append(f"- **Submission ID**: `{data.get('submission_id', '?')}`")
    if (priority := data.get("priority_tier")) is not None:
        lines.append(f"- **Priority**: {priority}")
    if user := data.get("username"):
        lines.append(f"- **Submitted by**: {user}")
    lines.append(f"- **Created**: {format_timestamp(data.get('created_at'))}")
    if mod := data.get("modified_at"):
        lines.append(f"- **Updated**: {format_timestamp(mod)}")

    if sample:
        lines.append("\n### Sample")
        if sha256:
            lines.append(f"- **SHA256**: `{sha256}`")
        if file_name := sample.get("file_name"):
            lines.append(f"- **File**: `{file_name}`")
        if file_type := sample.get("file_type"):
            lines.append(f"- **Type**: {file_type}")

    if analysis:
        lines.append("\n### Analysis")
        if aid:
            lines.append(f"- **ID**: `{aid}`")
        lines.append(f"- **Mode**: {analysis.get('analysis_mode', '-')}")
        lines.append(f"- **Environment**: {analysis.get('environment', '-')}")
        lines.append(f"- **Verdict**: {_verdict_str(analysis.get('verdict'))}")
        lines.append(f"- **Threats**: {_threats_str(analysis.get('threats'))}")

    return "\n".join(lines) + sibling_note


def format_tasks_list(data: dict[str, Any], limit: int | None = None) -> str:
    """Render `/v1/tasks` response (list of task objects).

    Render-side safety cap: the table is bounded to the requested `limit`
    (or 200 if none was supplied) so an over-broad backend response can't
    blow the MCP response budget. The cap is reported in the header when it
    fires so the caller knows the view was clipped.
    """
    tasks = data.get("tasks") if isinstance(data, dict) else None
    tasks = tasks or []
    total_received = len(tasks)
    render_cap = limit if limit and limit > 0 else 200
    shown = tasks[:render_cap]
    truncated = total_received > render_cap

    header = (
        f"## Tasks: {len(shown)} shown (of {total_received} returned)\n"
        if truncated
        else f"## Tasks: {len(shown)} found\n"
    )
    lines = [header]
    if not shown:
        return "\n".join(lines)

    lines.append("| Task ID | Analysis ID | Status | Scope | Verdict | Threats | Sample / URL | Submitter | Created |")
    lines.append("|---------|-------------|--------|-------|---------|---------|--------------|-----------|---------|")
    for t in shown:
        tid = t.get("task_id", "?")
        status = t.get("status", "unknown")
        sample = t.get("sample") or {}
        analysis = t.get("analysis") or {}
        url_block = t.get("url") or {}
        analysis_id = analysis.get("id") or "-"
        scope = analysis.get("scope") or sample.get("scope") or "-"
        verdict = _verdict_str(analysis.get("verdict") or sample.get("verdict"))
        threats = _threats_str(analysis.get("threats") or sample.get("threats"))
        target = escape_cell(sample.get("file_name") or url_block.get("url") or sample.get("hash_sha256") or "-")
        submitter = t.get("username") or "-"
        created = format_timestamp(t.get("created_at"))
        lines.append(
            f"| `{tid}` | `{analysis_id}` | {status} | {scope} | {verdict} | {threats} "
            f"| {target} | {submitter} | {created} |"
        )

    if truncated:
        lines.append(
            f"\n*Render cap: {render_cap}. Backend returned {total_received}. "
            "Raise `limit` to see more.*"
        )
    elif limit and len(shown) >= limit:
        lines.append(f"\n*Returned the page limit ({limit}). Increase `limit` to widen the window.*")
    return "\n".join(lines)
