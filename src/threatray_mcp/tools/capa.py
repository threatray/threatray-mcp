"""CAPA Analysis section tools."""

from fastmcp import Context, FastMCP

from .. import formatters
from ..client._types import CapaJobId, FileHashSha256
from ..formatters.capa import capa_addresses_overflow
from ..models import CapaInput, CapaJobInput, ResponseFormat
from ._cache import format_with_cache
from ._context import get_client
from ._format import format_json


def register(mcp: FastMCP) -> None:
    @mcp.tool(
        name="threatray_get_capa",
        annotations={  # type: ignore[arg-type]
            "title": "Get CAPA Analysis",
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    async def threatray_get_capa(ctx: Context, params: CapaInput) -> str:
        """Get CAPA capability analysis for a file.

        CAPA identifies capabilities and behaviors in executable files by matching
        against a comprehensive rule set. Each matched rule may carry an ATT&CK
        technique mapping (surfaced verbatim from the upstream CAPA payload).

        Behaviour:
        - Default: returns the latest existing CAPA result if any. If
          `trigger_if_missing=True` (default) and no result exists, creates a
          CAPA job and waits for it to complete (the wait can be long).
        - `trigger_only=True`: creates the job and returns the job-id
          immediately without polling. Useful for slow files. Poll that id with
          `threatray_get_capa_job`, then fetch the result by re-calling
          `threatray_get_capa(file_hash, trigger_if_missing=False)`.

        Keep the job-id: CAPA exposes no "job status by file hash" endpoint, so
        the id is the only handle on a running job. Note that this tool returns
        an existing result — at whatever CAPA rules version produced it —
        without creating a job at all, so `trigger_only=True` yields a job-id
        only when the file has no CAPA result yet.
        """
        client = get_client(ctx)

        async def progress_callback(progress: float, message: str) -> None:
            await ctx.report_progress(int(progress * 100), 100, message)

        result = await client.capa.get(
            FileHashSha256(params.file_hash),
            trigger_if_missing=params.trigger_if_missing,
            trigger_only=params.trigger_only,
            progress_callback=progress_callback,
        )
        if params.response_format == ResponseFormat.JSON:
            return format_json(result)
        if params.trigger_only and result.get("pending"):
            # Trigger-only ack carries a job dict, not a CAPA result, so the
            # results formatter can't render it.
            return formatters.format_capa_job_ack(result.get("job") or {})
        # Spill long-tail address lists. `contain loop` on EddieStealer fires
        # at 421 addresses; without spill a single rule used to fill the
        # response. Summary keeps the per-rule cap; spill file lifts it.
        summary = formatters.format_capa_results(result)
        full_markdown = formatters.format_capa_results(result, max_addresses_per_rule=None)
        rule_count = len((result.get("capabilities") or {}).get("rules") or {})
        return format_with_cache(
            summary=summary,
            full_markdown=full_markdown,
            prefix="capa",
            item_count=rule_count,
            force_spill=capa_addresses_overflow(result),
        )

    @mcp.tool(
        name="threatray_get_capa_job",
        annotations={  # type: ignore[arg-type]
            "title": "Get CAPA Analysis Job",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    async def threatray_get_capa_job(ctx: Context, params: CapaJobInput) -> str:
        """Get the status of one CAPA analysis job by its job-id.

        Use after `threatray_get_capa(file_hash, trigger_only=True)`, which returns
        the job-id: this polls that job for `CREATED`, `QUEUED`, `PROCESSING`,
        `DONE` or `FAILED` instead of guessing from a 404. Once it reports `DONE`,
        fetch the result with `threatray_get_capa(file_hash, trigger_if_missing=False)`.

        The payload carries only the job-id, file hash and status — CAPA jobs expose
        no stage, progress or ETA, so there is nothing to report but the status.
        `FAILED` means this job did not produce a result and will not progress on
        its own — not that the id is spent. Re-running is a `threatray_get_capa`
        call, not something this tool does.

        You own the polling loop: this tool has no timeout of its own and will keep
        reporting `PROCESSING` for as long as the job holds that status. The waiting
        form, `threatray_get_capa(file_hash)`, gives up after about twelve minutes —
        treat that as the ceiling here too, and report back rather than polling past
        it.
        """
        client = get_client(ctx)
        result = await client.capa.get_job(CapaJobId(str(params.job_id)))
        if params.response_format == ResponseFormat.JSON:
            return format_json(result)
        return formatters.format_capa_job(result)
