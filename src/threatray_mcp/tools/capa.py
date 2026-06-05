"""CAPA Analysis section tools."""

from fastmcp import Context, FastMCP

from .. import formatters
from ..formatters.capa import capa_addresses_overflow
from ..models import CapaInput, ResponseFormat
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
          immediately without polling. Useful for slow files; the caller
          fetches the completed result later by re-calling
          `threatray_get_capa(file_hash, trigger_if_missing=False)` — once
          the job has completed, the latest result is returned. (Unlike AI
          analysis, CAPA does not yet expose a "latest job status by hash"
          endpoint, so there is no separate poll-the-job tool.)
        """
        client = get_client(ctx)

        async def progress_callback(progress: float, message: str) -> None:
            await ctx.report_progress(int(progress * 100), 100, message)

        result = await client.capa.get(
            params.file_hash,
            trigger_if_missing=params.trigger_if_missing,
            trigger_only=params.trigger_only,
            progress_callback=progress_callback,
        )
        if params.response_format == ResponseFormat.JSON:
            return format_json(result)
        if params.trigger_only and result.get("pending"):
            # Trigger-only path returns the job dict; render as JSON since the
            # capa-results formatter expects the full payload.
            return format_json(result)
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
