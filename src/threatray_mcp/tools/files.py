"""Files section tools."""

from fastmcp import Context, FastMCP

from .. import formatters
from ..models import FileDownloadInput, FileMetadataInput, ResponseFormat, StringsInput
from ._cache import format_with_cache
from ._context import get_client
from ._format import format_json

_MARKDOWN_STRINGS_LIMIT = 200
# Ask for one extra string so the formatter can tell "exactly 200 extracted"
# (render all, no truncation note) from ">200 extracted" (render 200 + hint).
_MARKDOWN_STRINGS_PROBE = _MARKDOWN_STRINGS_LIMIT + 1


def register(mcp: FastMCP) -> None:
    @mcp.tool(
        name="threatray_get_file_metadata",
        annotations={  # type: ignore[arg-type]
            "title": "Get File Metadata",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    async def threatray_get_file_metadata(ctx: Context, params: FileMetadataInput) -> str:
        """Get file metadata.

        For PE files: returns headers, sections, imports, exports, resources,
        version info, and the rich-header checksum. For non-PE files only the
        DB-level fields (hashes, magic, size, first_seen, scope) come back.

        Strings are intentionally not returned here — call `threatray_get_strings`
        when you need them. Splitting the two avoids the extra full-buffer scan
        on the metadata path when the caller only wants PE structure.
        """
        client = get_client(ctx)
        result = await client.files.get_metadata(params.file_hash)
        if params.response_format == ResponseFormat.JSON:
            return format_json(result)
        return formatters.format_file_metadata(result)

    @mcp.tool(
        name="threatray_get_strings",
        annotations={  # type: ignore[arg-type]
            "title": "Get File Strings",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    async def threatray_get_strings(ctx: Context, params: StringsInput) -> str:
        """Get the extracted strings list for a file (URLs, registry paths,
        C2 strings, mutex names, hardcoded credentials, …).

        Returns strings in byte-offset order. Markdown view shows the first
        200 strings inline; when the file has more, the full list spills to
        a markdown cache file so the long tail remains reachable via
        Read/offset. JSON output always returns every string in one shot.
        """
        client = get_client(ctx)
        if params.response_format == ResponseFormat.JSON:
            result = await client.files.get_strings(params.file_hash)
            return format_json(result)
        # Fast path: probe with limit=201 so we can tell ≤200 (render all,
        # no spill) from >200 (one extra unbounded fetch, then spill).
        probe = await client.files.get_strings(params.file_hash, limit=_MARKDOWN_STRINGS_PROBE)
        received = len(probe.get("strings") or [])
        if received <= _MARKDOWN_STRINGS_LIMIT:
            return formatters.format_strings_list(probe)
        # Long tail exists — refetch the full list, build both summary and
        # uncapped markdown, spill.
        full = await client.files.get_strings(params.file_hash)
        summary = formatters.format_strings_list(probe)
        full_markdown = formatters.format_strings_list(full, max_strings=None)
        return format_with_cache(
            summary=summary,
            full_markdown=full_markdown,
            prefix="strings",
            item_count=len(full.get("strings") or []),
            force_spill=True,
        )

    @mcp.tool(
        name="threatray_download_file",
        annotations={  # type: ignore[arg-type]
            "title": "Download Malware Sample",
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
    )
    async def threatray_download_file(ctx: Context, params: FileDownloadInput) -> str:
        """Download a malware sample file by its hash.

        Downloads the file as a password-protected ZIP archive (password: 'infected').
        Returns a confirmation message with download path and file size in bytes.
        """
        client = get_client(ctx)
        data = await client.files.download(params.file_hash, zipped=True)
        with open(params.output_path, "wb") as f:
            f.write(data)
        return f"Downloaded {len(data)} bytes to {params.output_path}"
