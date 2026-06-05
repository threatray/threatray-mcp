"""Analyses section tools."""

from fastmcp import Context, FastMCP

from .. import formatters
from ..formatters.analyses import osint_reports_overflow
from ..models import (
    AnalysesListInput,
    AnalysisIdInput,
    EndpointScanAnalysesListInput,
    OsintInput,
    ResponseFormat,
)
from ._cache import format_with_cache
from ._context import get_client
from ._format import format_json

_READONLY = {
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": True,
    "openWorldHint": True,
}


def register(mcp: FastMCP) -> None:
    @mcp.tool(
        name="threatray_get_analysis",
        annotations={"title": "Get Analysis Details", **_READONLY},  # type: ignore[arg-type]
    )
    async def threatray_get_analysis(ctx: Context, params: AnalysisIdInput) -> str:
        """Get full analysis details, keyed by analysis_id.

        Returns: verdict, detected threats, analysis environment (the sandbox /
        VM image the sample was run in), creation timestamp, per-process
        behavior (command lines, parent process, memory regions with code
        detections), and IOCs (domains, IPs, URLs, files, mutexes, registry
        keys).

        Use this when you already have a specific `analysis_id` — typically
        from `threatray_search` results or a previous tool call that surfaced
        analysis UUIDs. If you only have a sample hash and want the canonical
        analysis view, use `threatray_get_sample` (sample-keyed; the server
        picks which analysis to return).
        """
        client = get_client(ctx)
        result = await client.analyses.get(str(params.analysis_id))
        if params.response_format == ResponseFormat.JSON:
            return format_json(result)
        return formatters.format_analysis_details(result)

    @mcp.tool(
        name="threatray_get_osint",
        annotations={"title": "Get OSINT Report", **_READONLY},  # type: ignore[arg-type]
    )
    async def threatray_get_osint(ctx: Context, params: OsintInput) -> str:
        """Get the OSINT Hunt report for a sample or code region.

        OSINT Hunt is the Threatray feature that surfaces open-source intelligence
        (cybersecurity blog posts, tweets, public reports, curated repositories)
        mentioning samples that share code with the queried hash. It limits its
        search scope to samples Threatray has ingested from those OSINT sources —
        for a broader cross-corpus code search, use `threatray_retrohunt_sample`.

        Accepts md5, sha1, or sha256.
        """
        client = get_client(ctx)
        result = await client.analyses.osint(params.hash)
        if params.response_format == ResponseFormat.JSON:
            return format_json(result)
        summary = formatters.format_osint_report(result)
        full_markdown = formatters.format_osint_report(result, max_reports_per_sample=None)
        return format_with_cache(
            summary=summary,
            full_markdown=full_markdown,
            prefix="osint",
            item_count=len(result.get("osint") or []),
            force_spill=osint_reports_overflow(result),
        )

    @mcp.tool(
        name="threatray_list_analyses",
        annotations={"title": "List Sample Analyses (paginated)", **_READONLY},  # type: ignore[arg-type]
    )
    async def threatray_list_analyses(ctx: Context, params: AnalysesListInput) -> str:
        """List sample analyses with cursor-based pagination.

        Platform-wide enumeration of analyses produced from file submissions
        (`/v1/analyses/samples`). Filter by `verdicts`
        (`unknown`/`suspicious`/`malicious`) and a finished-at date range. Pass
        the response's `cursor` field back as `cursor` to fetch the next page;
        a null `cursor` in the response means no more results.

        For endpoint-scan analyses use `threatray_list_endpoint_scan_analyses`;
        for query-driven slices (operators like `signature:`, `yara:`,
        `file-hash:`), use `threatray_search`.
        """
        client = get_client(ctx)
        result = await client.analyses.list_samples(
            verdicts=params.verdicts,
            from_finished_at=params.from_finished_at,
            to_finished_at=params.to_finished_at,
            limit=params.limit,
            cursor=params.cursor,
        )
        if params.response_format == ResponseFormat.JSON:
            return format_json(result)
        return formatters.format_analyses_list(result)

    @mcp.tool(
        name="threatray_list_endpoint_scan_analyses",
        annotations={"title": "List Endpoint-Scan Analyses (paginated)", **_READONLY},  # type: ignore[arg-type]
    )
    async def threatray_list_endpoint_scan_analyses(
        ctx: Context, params: EndpointScanAnalysesListInput
    ) -> str:
        """List endpoint-scan analyses with cursor-based pagination.

        Paginated list of analyses produced from endpoint-scan submissions
        (`/v1/submissions/endpoint-scan-archive`). Each entry includes the
        endpoint host_name when available. For sample analyses (file
        submissions) use `threatray_list_analyses`.
        """
        client = get_client(ctx)
        result = await client.analyses.list_endpoint_scans(
            verdicts=params.verdicts,
            from_finished_at=params.from_finished_at,
            to_finished_at=params.to_finished_at,
            limit=params.limit,
            cursor=params.cursor,
        )
        if params.response_format == ResponseFormat.JSON:
            return format_json(result)
        return formatters.format_endpoint_scan_analyses(result)
