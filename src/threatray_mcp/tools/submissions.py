"""Submissions section tools — list, get, the submit-* family, and task lookups."""

from fastmcp import Context, FastMCP

from .. import formatters
from ..models import (
    ResponseFormat,
    SubmissionsInput,
    SubmitEndpointScanArchiveInput,
    SubmitMansFileInput,
    SubmitMinidumpInput,
    SubmitSampleInput,
    SubmitUrlInput,
    TaskByAnalysisInput,
    TaskIdInput,
    TasksListInput,
)
from ._context import get_client
from ._format import format_json

_READONLY = {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}
_WRITE = {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True}


def register(mcp: FastMCP) -> None:
    @mcp.tool(
        name="threatray_list_submissions",
        annotations={"title": "List Sample Submissions", **_READONLY},  # type: ignore[arg-type]
    )
    async def threatray_list_submissions(ctx: Context, params: SubmissionsInput) -> str:
        """Get recent sample submissions to the Threatray platform."""
        client = get_client(ctx)
        result = await client.submissions.list_submissions(
            limit=params.limit,
            status_filter=params.status_filter,
            user_submissions_only=params.user_submissions_only,
        )
        if params.response_format == ResponseFormat.JSON:
            return format_json(result)
        return formatters.format_submissions_list(result, params.limit)

    @mcp.tool(
        name="threatray_get_task",
        annotations={"title": "Get Task by ID", **_READONLY},  # type: ignore[arg-type]
    )
    async def threatray_get_task(ctx: Context, params: TaskIdInput) -> str:
        """Get a single task by its numeric ID.

        Returns the task's submission, sample, and analysis metadata (verdict, threats,
        environment, timing). Useful for tracking an in-flight submission.
        """
        client = get_client(ctx)
        result = await client.submissions.get_task(params.task_id)
        if params.response_format == ResponseFormat.JSON:
            return format_json(result)
        return formatters.format_task(result)

    @mcp.tool(
        name="threatray_get_task_by_analysis",
        annotations={"title": "Get Task by Analysis ID", **_READONLY},  # type: ignore[arg-type]
    )
    async def threatray_get_task_by_analysis(ctx: Context, params: TaskByAnalysisInput) -> str:
        """Get the task that produced a given analysis ID."""
        client = get_client(ctx)
        result = await client.submissions.get_task_by_analysis(str(params.analysis_id))
        if params.response_format == ResponseFormat.JSON:
            return format_json(result)
        return formatters.format_task(result)

    @mcp.tool(
        name="threatray_list_tasks",
        annotations={"title": "List Tasks", **_READONLY},  # type: ignore[arg-type]
    )
    async def threatray_list_tasks(ctx: Context, params: TasksListInput) -> str:
        """List tasks, optionally filtered by file hash or submission ID.

        Tasks correspond 1:1 to analyses created by submissions (samples, urls, archives,
        minidumps, mans-files). Useful for finding all tasks for a sample, or all tasks
        belonging to a single bulk submission.
        """
        client = get_client(ctx)
        result = await client.submissions.list_tasks(
            file_hash=params.file_hash,
            submission_id=str(params.submission_id) if params.submission_id else None,
            limit=params.limit,
        )
        if params.response_format == ResponseFormat.JSON:
            return format_json(result)
        return formatters.format_tasks_list(result, params.limit)

    @mcp.tool(
        name="threatray_submit_sample",
        annotations={"title": "Submit Sample for Analysis", **_WRITE},  # type: ignore[arg-type]
    )
    async def threatray_submit_sample(ctx: Context, params: SubmitSampleInput) -> str:
        """Submit a file for static or dynamic (sandbox) analysis.

        Mode selection:
        - `analysis_mode='static'` extracts code features without execution.
          Fast; works for any supported file type.
        - `analysis_mode='dynamic'` (default) executes the sample in a sandbox
          VM and records runtime behaviour (processes, IOCs, memory regions).
          The optional sandbox-tuning fields (`environments`, `timeout_seconds`,
          `enable_network`, `entry_point`, `cmd_line_arguments`, `dll_exports`,
          `dll_arguments`) only apply in dynamic mode.

        For raw binaries (shellcode, payloads without a PE/ELF header), pass
        the `raw_binary_*` fields so the platform knows how to disassemble them.

        Set `is_compound_sample=True` for archives that bundle multiple samples
        (e.g. installer packages); each contained sample becomes its own analysis.

        Returns the submission ID(s).
        """
        client = get_client(ctx)
        result = await client.submissions.submit_sample(
            params.file_path,
            label=params.label,
            analysis_mode=params.analysis_mode,
            first_seen=params.first_seen,
            environments=params.environments,
            priority=params.priority,
            timeout_seconds=params.timeout_seconds,
            enable_network=params.enable_network,
            is_compound_sample=params.is_compound_sample,
            entry_point=params.entry_point,
            cmd_line_arguments=params.cmd_line_arguments,
            dll_exports=params.dll_exports,
            dll_arguments=params.dll_arguments,
            raw_binary_file_format=params.raw_binary_file_format,
            raw_binary_cpu_architecture=params.raw_binary_cpu_architecture,
            raw_binary_function_entry_point_detection_needed=(
                params.raw_binary_function_entry_point_detection_needed
            ),
            raw_binary_function_file_offset=params.raw_binary_function_file_offset,
            raw_binary_image_base_address=params.raw_binary_image_base_address,
        )
        if params.response_format == ResponseFormat.JSON:
            return format_json(result)
        return formatters.format_submission_response(result)

    @mcp.tool(
        name="threatray_submit_url",
        annotations={"title": "Submit URL for Analysis", **_WRITE},  # type: ignore[arg-type]
    )
    async def threatray_submit_url(ctx: Context, params: SubmitUrlInput) -> str:
        """Download the file referenced by a URL and submit it for analysis.

        The platform fetches the URL, retrieves the file it points at, and analyses
        that file — the URL itself is not the subject of analysis. Returns the
        submission ID(s).
        """
        client = get_client(ctx)
        result = await client.submissions.submit_url(
            params.url,
            label=params.label,
            first_seen=params.first_seen,
            environments=params.environments,
            priority=params.priority,
            timeout_seconds=params.timeout_seconds,
            enable_network=params.enable_network,
        )
        if params.response_format == ResponseFormat.JSON:
            return format_json(result)
        return formatters.format_submission_response(result)

    @mcp.tool(
        name="threatray_submit_endpoint_scan_archive",
        annotations={"title": "Submit Endpoint Scan Archive", **_WRITE},  # type: ignore[arg-type]
    )
    async def threatray_submit_endpoint_scan_archive(
        ctx: Context, params: SubmitEndpointScanArchiveInput
    ) -> str:
        """Submit an endpoint-scan archive (.zip) for analysis.

        The archive contains the files + memory dumps collected by a single
        endpoint scan. Each file (and each memory dump) is extracted and
        analysed individually using the same static-analysis pipeline as
        regular sample submissions.
        """
        client = get_client(ctx)
        result = await client.submissions.submit_endpoint_scan_archive(
            params.file_path,
            label=params.label,
            priority=params.priority,
        )
        if params.response_format == ResponseFormat.JSON:
            return format_json(result)
        return formatters.format_submission_response(result)

    @mcp.tool(
        name="threatray_submit_minidump",
        annotations={"title": "Submit Windows Minidump", **_WRITE},  # type: ignore[arg-type]
    )
    async def threatray_submit_minidump(ctx: Context, params: SubmitMinidumpInput) -> str:
        """Submit a Windows minidump (.dmp) file for memory analysis."""
        client = get_client(ctx)
        result = await client.submissions.submit_minidump(
            params.file_path,
            label=params.label,
            priority=params.priority,
        )
        if params.response_format == ResponseFormat.JSON:
            return format_json(result)
        return formatters.format_submission_response(result)

    @mcp.tool(
        name="threatray_submit_mans_file",
        annotations={"title": "Submit Mandiant .mans File", **_WRITE},  # type: ignore[arg-type]
    )
    async def threatray_submit_mans_file(ctx: Context, params: SubmitMansFileInput) -> str:
        """Submit a Mandiant `.mans` memory-triage file for analysis."""
        client = get_client(ctx)
        result = await client.submissions.submit_mans_file(
            params.file_path,
            label=params.label,
            priority=params.priority,
        )
        if params.response_format == ResponseFormat.JSON:
            return format_json(result)
        return formatters.format_submission_response(result)
