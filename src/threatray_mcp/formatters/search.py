"""Search section formatters (incl. retrohunt-by-sample)."""

from typing import Any

from ._helpers import format_threats, format_timestamp

# Cap per aggregation bucket. 25 keeps the long tail of buckets like YARA
# (which can carry 80+ rules) bounded while still surfacing the dominant
# entries; the full list is always available in JSON mode.
_MAX_AGGREGATION_ITEMS = 25

_AGGREGATION_SECTIONS = [
    ("verdict", "Verdict distribution"),
    ("threats", "Threats"),
    ("family", "Families"),
    ("code_signature", "Code signatures"),
    ("yara", "YARA"),
    ("av", "AV detections"),
    ("domain", "Domains"),
    ("ip", "IPs"),
    ("url", "URLs"),
    ("file", "Files"),
    ("mutex", "Mutexes"),
    ("registry", "Registry"),
    ("process", "Processes"),
]


def aggregations_overflow(data: dict[str, Any]) -> bool:
    """True iff any aggregation bucket would be truncated by the default cap.
    Tools use this to decide whether to spill the full markdown to disk so the
    long-tail entries remain reachable via the spill file."""
    aggregations = data.get("aggregations") or {}
    return any(len(items or []) > _MAX_AGGREGATION_ITEMS for items in aggregations.values())


def _render_aggregations(
    aggregations: dict[str, Any],
    max_items: int | None = _MAX_AGGREGATION_ITEMS,
) -> list[str]:
    """Render the aggregation buckets under a single `## Statistics` heading.
    Mirrors what the UI calls "statistics gathered from the matching analyses"
    (see docs.threatray.com/docs/search). The API field name stays
    `aggregations` in JSON output. `max_items=None` renders every entry (used
    by the spill-to-disk path so the cached markdown isn't truncated)."""
    out: list[str] = []
    has_any = any(aggregations.get(key) for key, _ in _AGGREGATION_SECTIONS)
    if not has_any:
        return out
    out.append("## Statistics")
    out.append("")
    for key, label in _AGGREGATION_SECTIONS:
        items = aggregations.get(key)
        if not items:
            continue
        out.append(f"### {label}")
        rendered = items if max_items is None else items[:max_items]
        for it in rendered:
            count = it.get("count", 0)
            private = it.get("private", 0)
            public = it.get("public", 0)
            scope_str = ""
            if private or public:
                scope_str = f" ({private} private + {public} public)"
            out.append(f"- `{it.get('key', '?')}`: {count}{scope_str}")
        if max_items is not None and len(items) > max_items:
            out.append(f"  *… and {len(items) - max_items} more*")
        out.append("")
    return out


def _yara_match_count(verdict_details: dict[str, Any]) -> int:
    """Count the 3rd-party YARA rules that fired on this analysis."""
    if not isinstance(verdict_details, dict):
        return 0
    yara = verdict_details.get("yara") or []
    return len(yara) if isinstance(yara, list) else 0


def _analysis_link(sha256: str, analysis_id: str) -> str:
    """Render the analysis ID as a plain backtick-wrapped code span."""
    return f"`{analysis_id}`" if analysis_id else "`?`"


def _scope_cell(analysis: dict[str, Any]) -> str:
    """Scope lives on the analysis (search, retrohunt) and on the sample
    (some list endpoints). Prefer the analysis-level value."""
    scope = analysis.get("scope") or (analysis.get("sample") or {}).get("scope")
    return str(scope) if scope else "-"


def _osint_cell(analysis: dict[str, Any]) -> str:
    """`sample.osint` is a boolean indicating whether the sample is mentioned
    in an OSINT report indexed by Threatray. Surfacing it makes it cheap for
    the agent to decide whether `threatray_get_osint` is worth calling."""
    osint = (analysis.get("sample") or {}).get("osint")
    if osint is True:
        return "yes"
    if osint is False:
        return "no"
    return "-"


def _analyses_table(display: list[dict[str, Any]], heading: str) -> list[str]:
    """Render the per-analysis result table for /v1/search.

    Columns mirror the UI search-results table: Analysis ID (linked to the
    analysis page), Sample hash, First seen, Verdict, Threats, Scope
    (public/private), OSINT availability, and the count of 3rd-party YARA
    rules that fired on this analysis."""
    if not display:
        return []
    lines = [
        f"### {heading}",
        "| Analysis ID | Sample hash | First seen | Scope | OSINT | Verdict | Threats | YARA matches |",
        "|-------------|-------------|------------|-------|-------|---------|---------|-------------:|",
    ]
    for a in display:
        sample = a.get("sample", {})
        sha256 = sample.get("hash_sha256", "")
        analysis_id = str(a.get("id") or "")
        first_seen = format_timestamp(sample.get("first_seen"), date_only=True)
        verdict = a.get("verdict", "-")
        threats = format_threats(a.get("threats", []))
        yara_count = _yara_match_count(a.get("verdict_details", {}))
        lines.append(
            f"| {_analysis_link(sha256, analysis_id)} | "
            f"{f'`{sha256}`' if sha256 else '`?`'} | "
            f"{first_seen} | {_scope_cell(a)} | {_osint_cell(a)} | "
            f"{verdict} | {threats} | {yara_count} |"
        )
    return lines


def _format_code_match(analysis: dict[str, Any], region: dict[str, Any] | None) -> str:
    """Render the per-analysis 'Code matches' cell for retrohunt.

    Two labelled fragments separated by `·`:
      `<region_hash> · <P>% sim`

    Function counts are intentionally omitted — the wire shape mixes three
    different denominators (total disassembler functions, unique Threatray
    functions, signature-eligible functions) and the source/matched/region
    figures don't share a single denominator, so any ratio rendered in
    markdown is ambiguous. The full counts remain in the JSON response.

    Wire shape per /v1/search (with the `retrohunt:<hash>` query operator):
    - `analyses[].cr_hash_sha256` → matched code-region hash
    - `analyses[].similarity` → 0..1, rendered as `<P>% sim`"""
    cr_hash = analysis.get("cr_hash_sha256") or (region or {}).get("hash_sha256") or ""
    if not cr_hash:
        return "-"
    similarity = analysis.get("similarity")
    parts = [f"`{cr_hash}`"]
    if isinstance(similarity, (int, float)):
        # One decimal place so a retrohunt's many ~99.7% rows don't all
        # collapse to "100% sim". 100% is reserved for exact-equal
        # (similarity == 1.0) — anything else, even 0.9999, renders as
        # "99.99% sim" so the analyst sees the distinction.
        if similarity == 1.0:
            parts.append("100% sim")
        else:
            parts.append(f"{similarity * 100:.2f}% sim")
    return " · ".join(parts)


def _retrohunt_table(display: list[dict[str, Any]], code_regions: list[dict[str, Any]]) -> list[str]:
    """Retrohunt-specific result table with the Code matches column (per UI).
    Same as `_analyses_table` plus a per-row code-region hash + N/M function
    match count + similarity percentage — sourced from `analyses[].cr_hash_sha256`
    + the matching `code_regions[]` entry."""
    if not display:
        return []
    regions_by_aid: dict[str, dict[str, Any]] = {}
    for cr in code_regions or []:
        aid = cr.get("analysis_id")
        if aid:
            regions_by_aid[str(aid)] = cr
    code_matches_header = "Code matches (region · similarity)"
    lines = [
        "### Similar samples",
        f"| Analysis ID | Sample hash | First seen | Scope | OSINT | Verdict "
        f"| Threats | YARA | {code_matches_header} |",
        "|-------------|-------------|------------|-------|-------|---------|---------|-----:|----------------------------------|",
    ]
    for a in display:
        sample = a.get("sample", {})
        sha256 = sample.get("hash_sha256", "")
        analysis_id = str(a.get("id") or "")
        first_seen = format_timestamp(sample.get("first_seen"), date_only=True)
        verdict = a.get("verdict", "-")
        threats = format_threats(a.get("threats", []))
        yara_count = _yara_match_count(a.get("verdict_details", {}))
        code_match = _format_code_match(a, regions_by_aid.get(analysis_id))
        lines.append(
            f"| {_analysis_link(sha256, analysis_id)} | "
            f"{f'`{sha256}`' if sha256 else '`?`'} | "
            f"{first_seen} | {_scope_cell(a)} | {_osint_cell(a)} | "
            f"{verdict} | {threats} | {yara_count} | {code_match} |"
        )
    return lines


def format_search_results(
    data: dict[str, Any],
    max_samples: int | None = None,
    max_aggregation_items: int | None = _MAX_AGGREGATION_ITEMS,
) -> str:
    """Render `/v1/search` response. Analyses table renders before the
    Statistics block — the table is the analyst's primary index; the
    aggregations are scaffolding to drill into specific dimensions afterwards.
    `max_aggregation_items=None` renders every entry in every bucket (used by
    the spill-to-disk path).

    Shape:
      {"analyses": [{id, sample{}, verdict, threats, environment, scope,
                     verdict_details: {code_signatures, families, av, yara}}],
       "samples":  [{...flattened sample + analysis_id...}],
       "aggregations": {verdict, threats, family, code_signature, yara, av,
                        domain, ip, url, mutex, registry, file, process}}
    """
    analyses = data.get("analyses", [])
    aggregations = data.get("aggregations", {})
    total_count = len(analyses)
    lines = []

    if max_samples and total_count > max_samples:
        lines.append(f"## Search Results: {total_count} analyses found (showing {max_samples})\n")
        display = analyses[:max_samples]
    else:
        lines.append(f"## Search Results: {total_count} analyses found\n")
        display = analyses

    lines.extend(_analyses_table(display, "Analyses"))
    lines.extend(_render_aggregations(aggregations, max_items=max_aggregation_items))

    if max_samples and total_count > max_samples:
        lines.append(f"\n*Showing first {max_samples} of {total_count} analyses.*")

    return "\n".join(lines)


def format_retrohunt_results(
    data: dict[str, Any],
    max_samples: int | None = None,
    max_aggregation_items: int | None = _MAX_AGGREGATION_ITEMS,
) -> str:
    """Render the retrohunt-by-sample response. Same `/v1/search` shape as
    `format_search_results`, but framed as "similar samples found"."""
    analyses = data.get("analyses", [])
    aggregations = data.get("aggregations", {})
    code_regions = data.get("code_regions", [])
    total_count = len(analyses)
    lines = []

    if max_samples and total_count > max_samples:
        lines.append(f"## Similar Samples: {total_count} found (showing {max_samples})\n")
        display = analyses[:max_samples]
    else:
        lines.append(f"## Similar Samples: {total_count} found\n")
        display = analyses

    lines.extend(_retrohunt_table(display, code_regions))
    lines.extend(_render_aggregations(aggregations, max_items=max_aggregation_items))

    if max_samples and total_count > max_samples:
        lines.append(f"\n*Showing first {max_samples} of {total_count} similar samples.*")

    return "\n".join(lines)
