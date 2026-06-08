"""Search section tools."""

from typing import cast

from fastmcp import Context, FastMCP

from .. import formatters
from ..client._types import DateRange, FileHashAny
from ..formatters.search import aggregations_overflow
from ..models import ResponseFormat, RetrohuntSampleInput, SearchInput
from ._cache import format_with_cache
from ._context import get_client
from ._format import format_json

# Search-specific inline cap. Higher than the generic LARGE_RESULT_THRESHOLD
# because the analyses table is the analyst's primary index and 50 rows is
# still readable; above 50 the spill-to-disk path takes over.
_SEARCH_INLINE_ANALYSES = 50


def register(mcp: FastMCP) -> None:
    @mcp.tool(
        name="threatray_search",
        annotations={  # type: ignore[arg-type]
            "title": "Search Threats and Samples",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    async def threatray_search(ctx: Context, params: SearchInput) -> str:
        """Search for threats, samples, and IOCs in the Threatray database.

        Query syntax: [operator:] "search term"
        - Multiple terms use AND logic
        - Use quotes for values with spaces/special characters
        - Wildcards: * (multiple chars), ? (single char)

        Supported operators (with concrete examples that return results):
            ip:          IP address or CIDR range (e.g., ip:181.141.3.126)
            domain:      Domain name (e.g., domain:geo.netsupportsoftware.com)
            url:         URL (e.g., url:http://malware.com/payload)
            file:        File path modified (e.g., file:*\\system32\\*.dll)
            mutex:       Mutex name (e.g., mutex:xtremeupdate)
            registry:    Registry key (e.g., registry:HKEY_CURRENT_USER\\SOFTWARE\\Remcos*)
            process:     Process name/cmdline (e.g., process:*powershell*)
            signature:   Malware family (e.g., signature:Cobaltstrike)
            yara:        YARA rule match (e.g., yara:CAPE_Lumma_1)
            verdict:     Sample verdict (e.g., verdict:malicious — also unknown, suspicious)
            label:       Submission label (e.g., label:campaign-2024)
            sample-name: Submitted filename (e.g., sample-name:jfilyg7.exe)
            file-hash:   File hash MD5/SHA1/SHA256 (e.g., file-hash:0123456789abcdef0123456789abcdef)
            memory-hash: Memory region hash MD5/SHA1/SHA256

        Returns search results with samples and aggregations. Markdown output
        includes the aggregation buckets the API returned (verdict, threats,
        family, code_signature, yara, av, domain, ip, url, file, mutex,
        registry, process) plus a sample table. JSON output includes the full
        API response.
        """
        client = get_client(ctx)
        result = await client.search.run(
            params.query, params.max_results, params.scope, cast("DateRange | None", params.date)
        )
        analyses = result.get("analyses", [])
        item_count = len(analyses)

        if params.response_format == ResponseFormat.JSON:
            return format_json(result)

        summary = formatters.format_search_results(result, max_samples=_SEARCH_INLINE_ANALYSES)
        full_markdown = formatters.format_search_results(
            result, max_samples=None, max_aggregation_items=None
        )
        return format_with_cache(
            summary=summary,
            full_markdown=full_markdown,
            prefix="search",
            item_count=item_count,
            threshold=_SEARCH_INLINE_ANALYSES,
            force_spill=aggregations_overflow(result),
        )

    @mcp.tool(
        name="threatray_retrohunt_sample",
        annotations={  # type: ignore[arg-type]
            "title": "Find Similar Samples",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    async def threatray_retrohunt_sample(ctx: Context, params: RetrohuntSampleInput) -> str:
        """Find similar samples based on code similarity (retrohunt).

        Performs code similarity search to find samples sharing code with the input.
        Useful for finding related malware variants and families, tracking threat actor
        tooling across campaigns, and discovering samples that reuse code components.

        Returns similar samples with similarity scores, matching code regions, threat
        aggregations, and IOC aggregations.
        """
        client = get_client(ctx)
        result = await client.search.retrohunt_sample(
            FileHashAny(params.sample_hash),
            params.max_results,
            params.scope,
            cast("DateRange | None", params.date),
        )

        if params.response_format == ResponseFormat.JSON:
            return format_json(result)

        analyses = result.get("analyses", [])
        item_count = len(analyses)
        summary = formatters.format_retrohunt_results(result, max_samples=_SEARCH_INLINE_ANALYSES)
        full_markdown = formatters.format_retrohunt_results(
            result, max_samples=None, max_aggregation_items=None
        )

        return format_with_cache(
            summary=summary,
            full_markdown=full_markdown,
            prefix="retrohunt",
            item_count=item_count,
            threshold=_SEARCH_INLINE_ANALYSES,
            force_spill=aggregations_overflow(result),
        )
