"""Samples section tools."""

from fastmcp import Context, FastMCP

from .. import formatters
from ..client._types import FileHashAny
from ..models import ResponseFormat, SampleHashInput
from ._context import get_client
from ._format import format_json

_READONLY = {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": True}


def register(mcp: FastMCP) -> None:
    @mcp.tool(
        name="threatray_get_sample",
        annotations={"title": "Get Sample Details", **_READONLY},  # type: ignore[arg-type]
    )
    async def threatray_get_sample(ctx: Context, params: SampleHashInput) -> str:
        """Deep-dive on a sample, keyed by hash.

        Returns the sample's metadata (hashes, file type/size/name, first-seen,
        verdict, threats) PLUS a full drill-down of the platform's canonical
        Analysis for the sample: per-engine verdict breakdown (code-signatures,
        YARA, AV), static analysis function counts, top code detections,
        per-process behaviour and memory regions, IOCs.

        Use this when you have a sample hash and want the canonical analysis
        view in one call — the server picks which analysis to return. If you
        already have a specific `analysis_id` (e.g. from `threatray_search`
        results when a sample carries multiple analyses) and want THAT
        analysis rather than the canonical one, use `threatray_get_analysis`.
        """
        client = get_client(ctx)
        result = await client.samples.get(FileHashAny(params.sample_hash))
        if params.response_format == ResponseFormat.JSON:
            return format_json(result)
        return formatters.format_sample_details(result)
