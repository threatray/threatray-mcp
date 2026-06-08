"""AI Analysis section tools."""

from fastmcp import Context, FastMCP

from .. import formatters
from ..client._types import AiAnalysisId, FileHashSha256
from ..models import (
    AiAnalysisByIdInput,
    AiAnalysisInput,
    AiAnalysisResultsInput,
    AiLatestJobInput,
    ResponseFormat,
)
from ._context import get_client
from ._format import format_json

_READONLY = {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}


def register(mcp: FastMCP) -> None:
    @mcp.tool(
        name="threatray_get_ai_analysis",
        annotations={  # type: ignore[arg-type]
            "title": "Get AI Analysis",
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    async def threatray_get_ai_analysis(ctx: Context, params: AiAnalysisInput) -> str:
        """Get AI analysis for a file.

        Analyses the file's disassembled functions with an AI model and returns:
        per-function natural-language summaries describing what each function does,
        the capabilities the model extracted from those functions, and an overall
        sample-level summary plus verdict.

        Behavior modes (set via `trigger_only`):
          - `trigger_only=False` (default): block until the job finishes, up to
            `max_wait_seconds` (default 600s, max 3600s).
          - `trigger_only=True`: enqueue the job and return immediately with the job-id;
            check completion later with `threatray_get_latest_ai_job` (or list_ai_analyses).
        """
        client = get_client(ctx)

        async def progress_callback(progress: float, message: str) -> None:
            await ctx.report_progress(int(progress * 100), 100, message)

        result = await client.ai_analysis.get(
            FileHashSha256(params.file_hash),
            trigger_if_missing=params.trigger_if_missing,
            trigger_only=params.trigger_only,
            max_wait_seconds=params.max_wait_seconds,
            progress_callback=progress_callback,
        )
        # When the cached-results path returns a listing entry (no full detail),
        # follow up with /results/{id} so the caller doesn't need to chain
        # `get_ai_analysis_by_id` manually for the common "what did the AI say
        # about this file?" workflow. The trigger-only ack (carries a `job`
        # block) is excluded — the caller explicitly opted out of waiting.
        if (
            isinstance(result, dict)
            and not result.get("pending")
            and "assessment" not in result
            and "functions" not in result
            and (rid := result.get("id"))
        ):
            result = await client.ai_analysis.get_result_by_id(AiAnalysisId(str(rid)))

        if params.response_format == ResponseFormat.JSON:
            return format_json(result)
        return formatters.format_ai_analysis(result)

    @mcp.tool(
        name="threatray_list_ai_analyses",
        annotations={  # type: ignore[arg-type]
            "title": "List AI Analyses for File",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    async def threatray_list_ai_analyses(ctx: Context, params: AiAnalysisResultsInput) -> str:
        """List all AI analysis runs for a sample.

        Returns one summary row per AI analysis run for the sample identified by
        the given hash (status, creation timestamp, AI analysis ID). Use
        `threatray_get_ai_analysis_by_id` to fetch the full result of a specific
        run.
        """
        client = get_client(ctx)
        result = await client.ai_analysis.list_results(FileHashSha256(params.file_hash))
        if params.response_format == ResponseFormat.JSON:
            return format_json(result)
        return formatters.format_ai_analysis_list(result)

    @mcp.tool(
        name="threatray_get_ai_analysis_by_id",
        annotations={"title": "Get AI Analysis by ID", **_READONLY},  # type: ignore[arg-type]
    )
    async def threatray_get_ai_analysis_by_id(ctx: Context, params: AiAnalysisByIdInput) -> str:
        """Get a specific AI analysis result by its ID.

        Use this when you already have the AI analysis ID — e.g. from a previous
        `threatray_list_ai_analyses` call — and want the full AI analysis result
        (per-function summaries, extracted capabilities, sample-level summary and
        verdict) without re-listing.
        """
        client = get_client(ctx)
        result = await client.ai_analysis.get_result_by_id(AiAnalysisId(str(params.analysis_id)))
        if params.response_format == ResponseFormat.JSON:
            return format_json(result)
        return formatters.format_ai_analysis(result)

    @mcp.tool(
        name="threatray_get_latest_ai_job",
        annotations={"title": "Get Latest AI Analysis Job", **_READONLY},  # type: ignore[arg-type]
    )
    async def threatray_get_latest_ai_job(ctx: Context, params: AiLatestJobInput) -> str:
        """Get the most recent AI analysis job for a file (status + progress).

        Useful when `threatray_get_ai_analysis` was previously called with
        `trigger_only=True`: the kickoff returned just the job id, and this tool lets
        you poll later for completion (`job_status` of `DONE`, `FAILED`, `UNSUPPORTED`,
        or `SKIPPED`).
        """
        client = get_client(ctx)
        result = await client.ai_analysis.get_latest_job(FileHashSha256(params.file_hash))
        if params.response_format == ResponseFormat.JSON:
            return format_json(result)
        return formatters.format_ai_analysis(result)
