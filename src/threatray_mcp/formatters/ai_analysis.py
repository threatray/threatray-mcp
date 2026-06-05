"""AI Analysis section formatters."""

from typing import Any

from ._helpers import format_timestamp


def _fmt_addr(addr: Any) -> str:
    return f"0x{addr:x}" if isinstance(addr, int) else str(addr or "-")


def format_ai_analysis(data: dict[str, Any]) -> str:
    """Render the AI analysis result returned by `/v1/ai-analysis/results/{id}` (full
    detail) or the trigger-only ack from `/v1/ai-analysis/jobs`.

    The full-detail shape carries `id`, `file_hash`, `verdict`, `assessment`,
    `capabilities[{category,title,description}]`, `functions[{address,verdict,
    explanation}]`, plus `functions_analyzed` / `functions_decompiled` /
    `created_at`. The list-shape entry (from `/v1/ai-analysis/results`) only has
    `id`/`file_hash`/`functions_analyzed`/`created_at` and is rendered as a
    summary card.

    Per-function explanations are rendered inline in full; the formatter
    never silently drops entries.

    Trigger-only ack: `{"job": {job_id, file_hash, job_status}, "pending": true}`.
    Latest-job shape: `{job_id, file_hash, job_status}` directly.
    """
    # Trigger-only / pending ack first — has no detail to render.
    if data.get("pending") and isinstance(data.get("job"), dict):
        job = data["job"]
        return (
            "## AI Analysis Job — queued\n\n"
            f"- **Job ID**: `{job.get('job_id', '?')}`\n"
            f"- **File hash**: `{job.get('file_hash', '?')}`\n"
            f"- **Status**: {job.get('job_status', 'unknown')}\n\n"
            "*Re-call `threatray_get_latest_ai_job` to poll, or "
            "`threatray_get_ai_analysis_by_id` once the job is `DONE`.*"
        )

    # Bare job-status payload (from /v1/ai-analysis/jobs/latest).
    if "job_status" in data and "verdict" not in data:
        return (
            "## AI Analysis Job\n\n"
            f"- **Job ID**: `{data.get('job_id', '?')}`\n"
            f"- **File hash**: `{data.get('file_hash', '?')}`\n"
            f"- **Status**: {data.get('job_status', 'unknown')}\n"
        )

    # Listing-shape entry (no `assessment`, no `functions`).
    if "verdict" not in data and "functions" not in data and "assessment" not in data:
        if "id" in data and "file_hash" in data:
            return (
                "## AI Analysis (summary)\n\n"
                f"- **ID**: `{data.get('id')}`\n"
                f"- **File hash**: `{data.get('file_hash')}`\n"
                f"- **Functions analysed**: {data.get('functions_analyzed', '?')}\n"
                f"- **Created**: {format_timestamp(data.get('created_at'))}\n\n"
                "*Use `threatray_get_ai_analysis_by_id` with the ID above for the full "
                "per-function detail.*"
            )

    # Full detail.
    lines = ["## AI Analysis"]
    lines.append("")
    lines.append(f"- **ID**: `{data.get('id', '?')}`")
    lines.append(f"- **File hash**: `{data.get('file_hash', '?')}`")
    lines.append(f"- **Verdict**: {data.get('verdict', 'unknown')}")
    if created := data.get("created_at"):
        lines.append(f"- **Created**: {format_timestamp(created)}")
    analyzed = data.get("functions_analyzed")
    decompiled = data.get("functions_decompiled")
    if analyzed is not None or decompiled is not None:
        lines.append(
            f"- **Functions**: {analyzed or '?'} analysed / {decompiled or '?'} decompiled"
        )

    if assessment := data.get("assessment"):
        lines.append("\n### Summary (LLM-generated)")
        lines.append(assessment)

    capabilities = data.get("capabilities") or []
    if capabilities:
        lines.append(f"\n### Capabilities ({len(capabilities)})")
        for cap in capabilities:
            category = cap.get("category", "-")
            title = cap.get("title", "?")
            description = cap.get("description", "")
            lines.append(f"- **{title}** [{category}]")
            if description:
                lines.append(f"  - {description}")

    functions = data.get("functions") or []
    if functions:
        lines.append(f"\n### Per-function explanations ({len(functions)})")
        for f in functions:
            verdict = f.get("verdict", "-")
            addr = _fmt_addr(f.get("address"))
            explanation = f.get("explanation", "")
            lines.append(f"- `{addr}` — {verdict}: {explanation}")

    return "\n".join(lines) + "\n"


def format_ai_analysis_list(data: dict[str, Any]) -> str:
    """Render `/v1/ai-analysis/results?file_hash=...` — the list of AI runs for a file."""
    results = data.get("results") or []
    lines = [f"## AI Analyses: {len(results)} found\n"]
    if not results:
        return "\n".join(lines) + "\n*No AI analysis has been run for this file yet.*\n"

    lines.append("| Analysis ID | Verdict | Functions analysed | Created |")
    lines.append("|-------------|---------|-------------------:|---------|")
    for r in results:
        verdict = r.get("verdict") or "-"
        if isinstance(verdict, dict):
            verdict = verdict.get("label") or verdict.get("value") or "-"
        lines.append(
            f"| `{r.get('id', '?')}` | {verdict} | {r.get('functions_analyzed', '?')} "
            f"| {format_timestamp(r.get('created_at'))} |"
        )
    return "\n".join(lines) + "\n"
