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
            # NOT idempotent: AI-analysis job creation is not deduplicated, so
            # calling this twice on a file with no result yields two distinct
            # jobs and two analyses. Advertising idempotency here tells a client
            # that retrying is free, which is exactly what it must not do.
            # (CAPA differs — it reuses an existing job for the same file and
            # rule set — so `threatray_get_capa` keeps the hint.)
            "idempotentHint": False,
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
            await ctx.report_progress(progress, message=message)

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
        """Read the latest AI analysis job for a file. **Not an existence check.**

        Use this after `threatray_get_ai_analysis(trigger_only=True)` hands back a
        job id: it reports `job_status` (`DONE`, `FAILED`, `UNSUPPORTED`, `SKIPPED`),
        and a processing job carries its stage, start time and a nullable
        server-calculated remaining-time range.

        It looks up the *latest* job for the file, not one job by id, and job creation
        is not deduplicated — so where a file has several jobs this need not be the
        one you started.

        A not-found here is ambiguous and stays that way: it reports that no job was
        found, which on a deployment without AI analysis is indistinguishable from the
        feature being absent. To ask whether a file *has* an analysis, call
        `threatray_list_ai_analyses` — where AI analysis is enabled for your account
        it answers with an empty list rather than an error. To confirm the file itself
        exists, use `threatray_get_file_metadata`.
        """
        client = get_client(ctx)
        result = await client.ai_analysis.get_latest_job(FileHashSha256(params.file_hash))
        if params.response_format == ResponseFormat.JSON:
            return format_json(result)
        return formatters.format_ai_analysis(result)
