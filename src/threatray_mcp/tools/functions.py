"""Functions section tools."""

from typing import cast

from fastmcp import Context, FastMCP

from .. import formatters
from ..client._types import FileHashAny, FunctionUid, SampleAnalysisId
from ..models import (
    CodeDetectionsInput,
    DiffFunctionsInput,
    FunctionsInput,
    ResponseFormat,
    RetrohuntFunctionsInput,
)
from ._cache import LARGE_RESULT_THRESHOLD, format_with_cache
from ._context import get_client
from ._format import format_json


def register(mcp: FastMCP) -> None:
    @mcp.tool(
        name="threatray_list_functions",
        annotations={  # type: ignore[arg-type]
            "title": "List Binary Functions",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    async def threatray_list_functions(ctx: Context, params: FunctionsInput) -> str:
        """Get the list of functions extracted from a sample.

        Returns each function's address, size, UID, and disassembly metadata
        (API call counts, constant counts). Use the UID with
        `threatray_retrohunt_functions`. The endpoint does not support
        pagination; results may be large for complex samples.
        """
        client = get_client(ctx)
        analysis_id = (
            SampleAnalysisId(str(params.analysis_id)) if params.analysis_id else None
        )
        result = await client.functions.list_functions(
            FileHashAny(params.file_hash), analysis_id, params.pid, params.base
        )

        if params.response_format == ResponseFormat.JSON:
            return format_json(result)

        functions = result.get("functions", [])
        item_count = len(functions)
        summary = formatters.format_functions_list(result, max_functions=LARGE_RESULT_THRESHOLD)
        full_markdown = formatters.format_functions_list(result, max_functions=None)
        return format_with_cache(
            summary=summary,
            full_markdown=full_markdown,
            prefix="functions",
            item_count=item_count,
        )

    @mcp.tool(
        name="threatray_get_code_detections",
        annotations={  # type: ignore[arg-type]
            "title": "Get Code Detections",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    async def threatray_get_code_detections(ctx: Context, params: CodeDetectionsInput) -> str:
        """Get per-function code-signature and family matches.

        Returns each function's code-signature matches plus the family the
        signature belongs to. Families span the full classification space
        (malware, runtime, library, application, installer, packer, ...).
        """
        client = get_client(ctx)
        analysis_id_typed = (
            SampleAnalysisId(str(params.analysis_id)) if params.analysis_id else None
        )
        result = await client.functions.get_code_detections(
            FileHashAny(params.hash_sha256), analysis_id_typed, params.pid, params.base
        )

        if params.response_format == ResponseFormat.JSON:
            return format_json(result)

        functions = result.get("functions", [])
        item_count = len(functions)
        summary = formatters.format_code_detections(result, max_detections=LARGE_RESULT_THRESHOLD)
        full_markdown = formatters.format_code_detections(result, max_detections=None)
        return format_with_cache(
            summary=summary,
            full_markdown=full_markdown,
            prefix="code_detections",
            item_count=item_count,
        )

    @mcp.tool(
        name="threatray_retrohunt_functions",
        annotations={  # type: ignore[arg-type]
            "title": "Find Samples by Functions",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    async def threatray_retrohunt_functions(ctx: Context, params: RetrohuntFunctionsInput) -> str:
        """Find samples containing similar functions (function-level retrohunt).

        Searches for samples containing functions similar to the specified UIDs.
        Useful for tracking specific malware capabilities across samples, finding variants
        sharing specific functionality, and identifying code reuse patterns.
        """
        client = get_client(ctx)
        result = await client.functions.run_retrohunt(
            cast("list[FunctionUid]", params.function_uids), params.threshold, params.scope
        )

        if params.response_format == ResponseFormat.JSON:
            return format_json(result)

        # Per-function retrohunt has a different response shape than sample
        # retrohunt — uses `format_function_retrohunt` which groups matches
        # under each reference function (uid + matched-uid + N/M function
        # counts per code region). The sample-style `format_retrohunt_results`
        # was being called by mistake; the function-style formatter exists,
        # has tests, but wasn't wired up.
        functions = result.get("functions", [])
        total_matches = sum(len(f.get("matches") or []) for f in functions)
        summary = formatters.format_function_retrohunt(result, max_matches=LARGE_RESULT_THRESHOLD)
        full_markdown = formatters.format_function_retrohunt(result, max_matches=None)
        return format_with_cache(
            summary=summary,
            full_markdown=full_markdown,
            prefix="retrohunt_functions",
            item_count=total_matches,
        )

    @mcp.tool(
        name="threatray_diff_functions",
        annotations={  # type: ignore[arg-type]
            "title": "Diff Functions: Source vs Targets",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    async def threatray_diff_functions(ctx: Context, params: DiffFunctionsInput) -> str:
        """1-source-to-N-targets function diff (`POST /v1/functions/diff`).

        Compares every function in `source_hash` against the functions in each
        sample listed in `target_hashes`. Each match carries `score`,
        `confidence`, and `similarity` — useful when you want to know not just
        whether code is shared, but how well it matches.

        This is the engine the IDA plugin's "Find Function Clusters" feature
        sits on top of. Use it when:
          - You have a specific source sample and want to see which of its
            functions appear in a known set of comparison samples.
          - You need per-match score/confidence/similarity (not just "this
            function exists in cluster X").

        For "what OTHER samples share this code" without nominating specific
        targets, use `threatray_retrohunt_sample` (whole-sample similarity
        across the corpus) or `threatray_retrohunt_functions` (per-uid
        similarity).
        """
        client = get_client(ctx)
        result = await client.functions.diff(
            source_hash=FileHashAny(params.source_hash),
            target_hashes=cast("list[FileHashAny]", params.target_hashes),
            with_benign_code=params.with_benign_code,
            threshold=params.threshold,
        )

        if params.response_format == ResponseFormat.JSON:
            return format_json(result)

        functions = result.get("functions", []) or []
        # Spill triggers on the total match count across all source functions,
        # so a sample with many matched-functions x many-targets spills even
        # when no single source-function dominates.
        item_count = sum(len(f.get("matches") or []) for f in functions)
        summary = formatters.format_function_diff(result, max_matches=LARGE_RESULT_THRESHOLD)
        full_markdown = formatters.format_function_diff(result, max_matches=None)
        return format_with_cache(
            summary=summary,
            full_markdown=full_markdown,
            prefix="diff_functions",
            item_count=item_count,
        )
