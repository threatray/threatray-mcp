"""Files section formatters."""

from typing import Any

from ._helpers import escape_cell, format_timestamp

_MAX_RESOURCES_SHOWN = 15
_MAX_STRINGS_MARKDOWN = 200


def _fmt_hex(value: Any) -> str:
    return f"0x{value:08x}" if isinstance(value, int) else str(value or "-")


def format_file_metadata(data: dict[str, Any]) -> str:  # noqa: PLR0912, PLR0915 — single-shot PE-metadata renderer
    """Render `/v1/files/{hash}/metadata?include_strings=false`.

    Real shape (per docs.threatray.com/reference):
      {
        hash_md5, hash_sha1, hash_sha256, first_seen, magic, size, scope,
        header: {
          FileHeader: {Machine, NumberOfSections, TimeDateStamp,
                       PointerToSymbolTable, NumberOfSymbols,
                       SizeOfOptionalHeader, Characteristics, Flags[]},
          OptionalHeader: {Magic, ImageBase, AddressOfEntryPoint,
                           SizeOfCode, SizeOfImage, Subsystem,
                           DllCharacteristics[], MajorLinkerVersion, ...},
        },
        sections: [{Name, VirtualAddress, VirtualSize, SizeOfRawData}],
        imports: [{DLL, functions?}],
        exports: [{name?}],
        resources: [{name, magic}],
        rich_header: {checksum, checksum_valid},
        version_info: [[{CompanyName, LangID}]],
      }

    Strings are intentionally not rendered here — they live on the dedicated
    `/v1/files/{hash}/strings` endpoint (rendered by `format_strings_list`)."""
    lines = ["## File Metadata\n"]

    # ── identification ──────────────────────────────────────────────────────
    lines.append("### Identification")
    if sha := data.get("hash_sha256"):
        lines.append(f"- **SHA256**: `{sha}`")
    if sha1 := data.get("hash_sha1"):
        lines.append(f"- **SHA1**: `{sha1}`")
    if md5 := data.get("hash_md5"):
        lines.append(f"- **MD5**: `{md5}`")
    if magic := data.get("magic"):
        lines.append(f"- **Magic**: {magic}")
    if (size := data.get("size")) is not None:
        lines.append(f"- **Size**: {size} bytes")
    if first_seen := data.get("first_seen"):
        lines.append(f"- **First seen**: {format_timestamp(first_seen)}")
    if scope := data.get("scope"):
        lines.append(f"- **Scope**: {scope}")
    lines.append("")

    header = data.get("header") or {}
    file_header = header.get("FileHeader") or {}
    optional_header = header.get("OptionalHeader") or {}

    # ── file header ─────────────────────────────────────────────────────────
    if file_header:
        lines.append("### FileHeader")
        for key in (
            "Machine", "NumberOfSections", "TimeDateStamp",
            "PointerToSymbolTable", "NumberOfSymbols",
            "SizeOfOptionalHeader", "Characteristics",
        ):
            if (val := file_header.get(key)) is not None:
                lines.append(f"- **{key}**: {val}")
        if flags := file_header.get("Flags"):
            lines.append(f"- **Flags**: {', '.join(flags)}")
        lines.append("")

    # ── optional header ─────────────────────────────────────────────────────
    if optional_header:
        lines.append("### OptionalHeader")
        # The integer fields we hex-format because they're addresses.
        hex_keys = (
            "Magic", "ImageBase", "AddressOfEntryPoint",
            "BaseOfCode", "BaseOfData",
        )
        for key in hex_keys:
            if (val := optional_header.get(key)) is not None:
                lines.append(f"- **{key}**: {_fmt_hex(val)}")
        # The size/version fields render as plain integers.
        plain_keys = (
            "SizeOfCode", "SizeOfImage", "SizeOfHeaders",
            "SizeOfInitializedData", "SizeOfUninitializedData",
            "Subsystem", "CheckSum",
            "MajorLinkerVersion", "MinorLinkerVersion",
            "MajorOperatingSystemVersion", "MinorOperatingSystemVersion",
            "MajorSubsystemVersion", "MinorSubsystemVersion",
            "MajorImageVersion", "MinorImageVersion",
            "FileAlignment", "SectionAlignment",
            "NumberOfRvaAndSizes",
        )
        for key in plain_keys:
            if (val := optional_header.get(key)) is not None:
                lines.append(f"- **{key}**: {val}")
        if dllchars := optional_header.get("DllCharacteristics"):
            lines.append(f"- **DllCharacteristics**: {', '.join(dllchars)}")
        lines.append("")

    # ── sections ────────────────────────────────────────────────────────────
    if sections := data.get("sections", []):
        lines.append(f"### Sections ({len(sections)})")
        lines.append("| Name | VirtualAddress | VirtualSize | SizeOfRawData |")
        lines.append("|------|----------------|-------------|---------------|")
        for s in sections:
            lines.append(
                f"| {escape_cell(s.get('Name', '-'))} | {_fmt_hex(s.get('VirtualAddress'))} "
                f"| {s.get('VirtualSize', '-')} | {s.get('SizeOfRawData', '-')} |"
            )
        lines.append("")

    # ── imports ─────────────────────────────────────────────────────────────
    if imports := data.get("imports", []):
        lines.append(f"### Imports ({len(imports)} DLLs)")
        for imp in imports:
            dll = imp.get("DLL") or imp.get("dll") or "?"
            functions = imp.get("functions") or []
            lines.append(f"- **{dll}**" + (f" ({len(functions)} functions)" if functions else ""))
            for fn in functions[:5]:
                fn_name = fn.get("name") if isinstance(fn, dict) else fn
                lines.append(f"  - `{fn_name}`")
            if len(functions) > 5:
                lines.append(f"  *… and {len(functions) - 5} more*")
        lines.append("")

    # ── exports ─────────────────────────────────────────────────────────────
    if exports := data.get("exports", []):
        lines.append(f"### Exports ({len(exports)})")
        for e in exports[:10]:
            name = e.get("name") if isinstance(e, dict) else e
            lines.append(f"- `{name}`")
        if len(exports) > 10:
            lines.append(f"  *… and {len(exports) - 10} more*")
        lines.append("")

    # ── resources ───────────────────────────────────────────────────────────
    if resources := data.get("resources", []):
        lines.append(f"### Resources ({len(resources)})")
        for r in resources[:_MAX_RESOURCES_SHOWN]:
            name = r.get("name", "?")
            mag = r.get("magic", "")
            lines.append(f"- `{name}`" + (f" — {mag}" if mag else ""))
        if len(resources) > _MAX_RESOURCES_SHOWN:
            lines.append(f"  *… and {len(resources) - _MAX_RESOURCES_SHOWN} more*")
        lines.append("")

    # ── rich header ─────────────────────────────────────────────────────────
    if rich_header := data.get("rich_header"):
        lines.append("### Rich header")
        checksum = rich_header.get("checksum")
        valid = rich_header.get("checksum_valid")
        if checksum is not None:
            lines.append(f"- **Checksum**: {_fmt_hex(checksum)} ({'valid' if valid else 'invalid'})")
        lines.append("")

    # ── version info ────────────────────────────────────────────────────────
    if version_info := data.get("version_info"):
        # The OpenAPI shape is array-of-arrays — flatten for display.
        flat = []
        for entry in version_info:
            if isinstance(entry, list):
                flat.extend(entry)
            elif isinstance(entry, dict):
                flat.append(entry)
        if flat:
            lines.append("### Version info")
            for vi in flat:
                pairs = [f"{k}={v}" for k, v in vi.items() if v is not None]
                lines.append(f"- {'; '.join(pairs)}")
            lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def format_strings_list(
    data: dict[str, Any],
    max_strings: int | None = _MAX_STRINGS_MARKDOWN,
) -> str:
    """Render `/v1/files/{hash}/strings`.

    Real shape: `{"strings": ["...", ...]}`. When `max_strings` is set
    (default 200), the caller is expected to have asked the upstream
    endpoint for at most `max_strings + 1` strings — that way we can tell
    "exactly N ≤ max_strings extracted" (render all) from ">max_strings
    extracted" (render first max_strings + truncation note) without an
    extra round-trip.

    `max_strings=None` renders every string with no truncation footer —
    used by the spill-to-disk path so the cached markdown is exhaustive.
    The caller is responsible for fetching the full strings list upstream
    in that case.
    """
    strings = data.get("strings") or []
    received = len(strings)
    if max_strings is not None and received > max_strings:
        capped = strings[:max_strings]
        lines = [
            f"## Strings (more than {max_strings}, "
            f"showing first {max_strings})\n"
        ]
    else:
        capped = strings
        lines = [f"## Strings ({received})\n"]
    for s in capped:
        # Collapse newlines so a multi-line extracted string can't break the
        # list item (and everything below it). Rendered inside a code span,
        # so `|` is already literal — only newlines are a corruption vector.
        one_line = str(s).replace("\r\n", " ").replace("\n", " ").replace("\r", " ")
        lines.append(f"- `{one_line}`")
    if max_strings is not None and received > max_strings:
        lines.append(
            "\n*Full markdown saved to disk (see pointer below) — or re-call "
            "with `response_format='json'` for the raw array.*"
        )
    return "\n".join(lines).rstrip() + "\n"
