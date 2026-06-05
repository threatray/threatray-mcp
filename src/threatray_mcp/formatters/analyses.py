"""Analyses section formatters."""

from typing import Any
from urllib.parse import urlparse

from ._helpers import format_timestamp

_MAX_MEMORY_REGIONS_PER_PROCESS = 5


# Sort tiers used for Top code detections, mirroring the UI's grouping:
#   1. Malware-category families first (regardless of overlap) — a stealer
#      with overlap 6 is more interesting than a runtime with overlap 322.
#   2. Then other categories (runtime / library / application / …) with
#      non-benign verdict, sorted by overlap desc.
#   3. Benign last, sorted by overlap desc.
_MALWARE_TIER = 0
_OTHER_NON_BENIGN_TIER = 1
_BENIGN_TIER = 2


def _is_benign_row(d: dict[str, Any]) -> bool:
    """A row is benign if the verdict says so. `_render_verdict_details`
    surfaces the verdict consistently across analysis/sample/memory-region
    entries — that's enough to drive the split."""
    return str(d.get("verdict") or "").lower() == "benign"


def _category_of(d: dict[str, Any]) -> str:
    fam = d.get("family") or {}
    if isinstance(fam, dict):
        return str(fam.get("category") or "").lower()
    return ""


def _sort_tier(d: dict[str, Any]) -> int:
    if _is_benign_row(d):
        return _BENIGN_TIER
    return _MALWARE_TIER if _category_of(d) == "malware" else _OTHER_NON_BENIGN_TIER


def _format_overlap(overlap: Any, total_function_count: int) -> str:
    """Render the overlap cell as `<absolute> (<relative>%)` when a total is
    available, falling back to the absolute count otherwise."""
    try:
        abs_value = int(overlap)
    except (TypeError, ValueError):
        return str(overlap) if overlap not in (None, "") else "-"
    if total_function_count > 0:
        pct = abs_value / total_function_count * 100
        # Round to one decimal place; tiny non-zero overlaps render as <0.1%.
        pct_str = "<0.1%" if 0 < pct < 0.1 else f"{pct:.1f}%"
        return f"{abs_value} ({pct_str})"
    return str(abs_value)


def _threats(items: list[Any]) -> str:
    """Render a threat list as a comma-separated string of labels only.

    The wire shape includes a per-threat `confidence` (`high`/`medium`/`low`)
    that the formatter used to surface as `<label> (<confidence>)`. The
    confidence value isn't analyst-actionable as a display element — the
    threat itself is the headline. Stripped here so every threats column
    across every tool renders consistently (search / retrohunt /
    submissions / analyses / functions / OSINT all converge on
    `label, label, ...`)."""
    if not items:
        return "-"
    parts = []
    for t in items:
        if isinstance(t, dict):
            parts.append(t.get("label", "?"))
        else:
            parts.append(str(t))
    return ", ".join(parts)


def _verdict(value: Any) -> str:
    if isinstance(value, dict):
        return str(value.get("label") or value.get("value") or "-")
    return str(value) if value is not None else "-"


def _aggregate_by_family(detections: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Aggregate detections by family.name, mirroring the UI's rule
    (ui/.../code-detections.component.ts): same-family entries are summed
    by `overlap` and reduced to `max(score)`. Detections without a family
    pass through unchanged.

    Useful for collapsing the long tail of versioned runtime signatures —
    e.g. `Rust-1.78.0`, `Rust-1.83.0`, `Rust-1.64.0` all carry
    `family.name == 'Rust'` and become a single `Rust` row."""
    groups: dict[str, dict[str, Any]] = {}
    passthrough: list[dict[str, Any]] = []
    for d in detections:
        fam = d.get("family") or {}
        fam_name = fam.get("name") if isinstance(fam, dict) else None
        if not fam_name:
            passthrough.append(d)
            continue
        entry = groups.get(fam_name)
        if entry is None:
            groups[fam_name] = {
                "family": fam,
                "code_signature": d.get("code_signature") or {},
                "verdict": d.get("verdict", "-"),
                "score": _coerce_score(d.get("score")),
                "overlap": d.get("overlap", 0) or 0,
                "member_count": 1,
            }
            continue
        entry["score"] = max(entry["score"], _coerce_score(d.get("score")))
        try:
            entry["overlap"] = int(entry["overlap"]) + int(d.get("overlap", 0) or 0)
        except (TypeError, ValueError):
            pass
        entry["member_count"] += 1
        if d.get("verdict") in ("malicious", "suspicious") and entry["verdict"] not in ("malicious", "suspicious"):
            entry["verdict"] = d["verdict"]
    return list(groups.values()) + passthrough


def _rank_aggregated(detections: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Aggregate by family and apply the UI's tiered sort:
      1. Malware-category families first (regardless of overlap), then
      2. Other categories with non-benign verdict, then
      3. Benign rows.
    Within each tier, sort by overlap descending. A stealer detected with
    overlap 6 (malware tier) renders before MSVC with overlap 322 (other
    tier) — matches the UI's Code Detections panel and the get_code_detections
    Summary table."""
    aggregated = _aggregate_by_family(detections)
    aggregated.sort(key=lambda x: (
        _sort_tier(x),
        -(_coerce_score(x.get("overlap")) or 0),
    ))
    return aggregated


def _detection_label(d: dict[str, Any]) -> tuple[str, str]:
    """Return (label, category) for one aggregated detection. Label uses
    family.name when present (UI rule), falls back to code-signature name,
    then to 'Generic benign' for unattributed entries."""
    sig = d.get("code_signature") or {}
    fam = d.get("family") or {}
    sig_name = sig.get("name") if isinstance(sig, dict) else None
    fam_name = fam.get("name") if isinstance(fam, dict) else None
    category = fam.get("category") if isinstance(fam, dict) else None
    label = fam_name or sig_name or "Generic benign"
    return label, str(category or "")


def _render_code_detections_table(
    detections: list[dict[str, Any]],
    total_function_count: int = 0,
) -> list[str]:
    """Top-level Top-code-detections renderer as a markdown table.

    Three columns: Label · Category · Overlap (`<absolute> (<percent>)`).
    Mirrors the UI's Code Intelligence tab: non-benign rows first (sorted
    by overlap desc), then benign rows. Every aggregated detection is
    rendered — no per-section cap. Verdict and score columns are dropped:
    the non-benign / benign split is encoded in row order, and a row's
    family category (`malware`, `runtime`, `library`, `application`, …)
    already carries the signal a verdict column would add.

    `total_function_count` is the denominator for the relative-overlap
    percentage — the UI uses the analysis-level function count for this."""
    if not detections:
        return []
    aggregated = _rank_aggregated(detections)
    lines = [
        "| Label | Category | Overlap |",
        "|-------|----------|--------:|",
    ]
    for d in aggregated:
        label, category = _detection_label(d)
        overlap_cell = _format_overlap(d.get("overlap"), total_function_count)
        lines.append(
            f"| `{label}` | {category or '-'} | {overlap_cell} |"
        )
    return lines


def _render_code_detections(
    detections: list[dict[str, Any]],
    indent: str = "",
    total_function_count: int = 0,
) -> list[str]:
    """Render `code_detections` as bullets — used for memory-region listings.

    Same UI-style sort as the top-level table: non-benign rows first (sorted
    by overlap desc), benign rows last. Every aggregated detection is
    rendered. Score column dropped (same rule as the top-level table)."""
    if not detections:
        return []
    aggregated = _rank_aggregated(detections)
    out = []
    for d in aggregated:
        sig = d.get("code_signature") or {}
        fam = d.get("family") or {}
        sig_name = sig.get("name") if isinstance(sig, dict) else None
        fam_name = fam.get("name") if isinstance(fam, dict) else None
        category = fam.get("category") if isinstance(fam, dict) else None
        overlap_cell = _format_overlap(d.get("overlap"), total_function_count)
        verdict = d.get("verdict", "-")
        # Lead label: family.name when present (matches the UI's aggregated
        # rows like `Rust` instead of `Rust-1.78.0`); fall back to signature
        # name. When both are absent the row is a benign-generic detection
        # (the UI calls these `Generic benign`).
        label = fam_name or sig_name or "Generic benign"
        bits = [f"`{label}`"]
        if category:
            bits.append(f"({category})")
        bits.append(f"— {verdict}, overlap {overlap_cell}")
        out.append(f"{indent}- {' '.join(bits)}")
    return out


def _coerce_score(value: Any) -> float:
    if isinstance(value, dict) and "parsedValue" in value:
        return float(value["parsedValue"])
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _render_verdict_details(verdict_details: dict[str, Any]) -> list[str]:
    """Pull `code`, `av`, `yara`, `behavioral_signatures` from the verdict_details block."""
    if not verdict_details:
        return []
    out = []
    code_matches = verdict_details.get("code") or []
    if code_matches:
        labels = [m.get("name", "?") for m in code_matches if isinstance(m, dict)]
        out.append(f"  - code: {', '.join(labels)}")
    av_matches = [m for m in (verdict_details.get("av") or []) if isinstance(m, dict) and m.get("threat")]
    if av_matches:
        out.append(f"  - av: {', '.join(m['threat'] for m in av_matches)}")
    yara_matches = verdict_details.get("yara") or []
    if yara_matches:
        names = []
        for m in yara_matches:
            if isinstance(m, dict):
                # YARA match rows use `rule` for the rule name.
                names.append(m.get("rule") or m.get("name") or "?")
            else:
                names.append(str(m))
        out.append(f"  - yara: {', '.join(names)}")
    behavioral = verdict_details.get("behavioral_signatures") or []
    if behavioral:
        out.append(f"  - behavioral: {len(behavioral)} signatures")
    return out


def _render_process(proc: dict[str, Any]) -> list[str]:
    pid = proc.get("pid", "?")
    ppid = proc.get("ppid", "?")
    name = proc.get("name", "?")
    status = proc.get("status", "?")
    verdict = proc.get("verdict", "-")
    cmdline = proc.get("command_line", "")
    out = [f"#### PID {pid} (parent {ppid}): `{name}` — {status}, {verdict}"]
    if cmdline:
        out.append(f"- **Command line**: `{cmdline}`")
    threats = proc.get("threats") or []
    if threats:
        out.append(f"- **Threats**: {_threats(threats)}")
    regions = proc.get("memory_regions") or []
    if regions:
        out.append(f"- **Memory regions** ({len(regions)}):")
        for r in regions[:_MAX_MEMORY_REGIONS_PER_PROCESS]:
            base = r.get("base")
            size = r.get("size")
            rtype = r.get("type", "?")
            image = r.get("image", "")
            sha = r.get("hash_sha256", "")
            r_verdict = r.get("verdict", "-")
            base_str = f"0x{base:x}" if isinstance(base, int) else "?"
            out.append(
                f"  - {rtype} @ {base_str} size={size} — {r_verdict}"
                f"{(' `' + sha + '`') if sha else ''}"
                f"{(' (' + image + ')') if image else ''}"
            )
            region_detections = r.get("code_detections") or []
            if region_detections:
                region_total = r.get("function_count") or 0
                out.append(f"    code_detections ({len(region_detections)}):")
                # Per-region denominator for the relative overlap.
                out.extend(_render_code_detections(
                    region_detections, indent="    ", total_function_count=region_total
                ))
        if len(regions) > _MAX_MEMORY_REGIONS_PER_PROCESS:
            out.append(f"  *… and {len(regions) - _MAX_MEMORY_REGIONS_PER_PROCESS} more memory regions*")
    return out


def _extract_ioc_value(ioc: Any) -> str:
    """The IOC payload is a list of dicts; the key naming varies per IOC type:
    domains/ips/urls use the type name as the key, files use `filename`,
    mutexes use `mutex`, registry uses `registry_key`."""
    if not isinstance(ioc, dict):
        return str(ioc)
    for key in ("filename", "registry_key", "domain", "ip", "url", "mutex", "name", "value", "path", "key"):
        if key in ioc:
            return str(ioc[key])
    return str(ioc)


def format_analysis_details(data: dict[str, Any]) -> str:  # noqa: PLR0912, PLR0915
    """Render the full analysis payload from `/v1/analyses/{id}` or `/v1/samples/{hash}`.

    The endpoints return the same `Analysis` schema: top-level `sample`,
    `analysis`, `processes[]`, and `ioc{}`. We surface the high-signal parts
    (sample classification, code_detections, per-process behaviour + IOCs);
    the full structure is always available via `response_format=json`.

    Memory-region code-detection bullets carry a `verdict` word. When a row
    reads `malware / unknown`, it means the family's signature has some
    overlap with this code region but the signal was too low for the
    classifier to commit to a malicious verdict — `unknown` is not "haven't
    looked at it"; it's "looked, found some overlap, not confident enough
    to call malware".
    """
    lines: list[str] = []
    analysis = data.get("analysis") or {}
    sample = data.get("sample") or {}
    static_analysis = sample.get("static_analysis") or {}
    iocs = data.get("ioc") or {}

    analysis_id = analysis.get("id", "?")
    sha256 = sample.get("hash_sha256", "")

    lines.append(f"## Analysis: `{analysis_id}`\n")

    # ── overview ────────────────────────────────────────────────────────────
    lines.append("### Overview")
    if analysis_id and analysis_id != "?":
        lines.append(f"- **Analysis ID**: `{analysis_id}`")
    if sha256:
        file_name = sample.get("file_name") or ""
        # Skip the (`file_name`) parenthetical when the file name is just the
        # SHA256 — common for analyst-submitted samples named after their
        # hash, and the duplication adds nothing.
        if file_name and file_name != sha256:
            lines.append(f"- **Sample**: `{sha256}` (`{file_name}`)")
        else:
            lines.append(f"- **Sample**: `{sha256}`")
    if sha1 := sample.get("hash_sha1"):
        lines.append(f"- **SHA-1**: `{sha1}`")
    if md5 := sample.get("hash_md5"):
        lines.append(f"- **MD5**: `{md5}`")
    if file_type := sample.get("file_type"):
        lines.append(f"- **File type**: {file_type}, {sample.get('file_size', '?')} bytes")
    if magic := sample.get("magic"):
        lines.append(f"- **Magic**: {magic}")
    if first_seen := sample.get("first_seen"):
        lines.append(f"- **First seen**: {format_timestamp(first_seen)}")
    lines.append(f"- **Verdict**: {_verdict(analysis.get('verdict') or sample.get('verdict'))}")
    if threats := analysis.get("threats") or sample.get("threats") or []:
        lines.append(f"- **Threats**: {_threats(threats)}")
    if env := analysis.get("environment"):
        lines.append(f"- **Environment**: {env}")
    if atype := analysis.get("type"):
        lines.append(f"- **Analysis type**: {atype}")
    if creation_time := analysis.get("creation_time"):
        lines.append(f"- **Created**: {format_timestamp(creation_time)}")
    if scope := analysis.get("scope") or sample.get("scope"):
        lines.append(f"- **Scope**: {scope}")
    if (analysis_time := analysis.get("analysis_time")) is not None:
        lines.append(f"- **Analysis time**: {analysis_time}s / timeout {analysis.get('analysis_timeout', '?')}s")
    lines.append("")

    # ── verdict-details breakdown (engine-level) ────────────────────────────
    vd = analysis.get("verdict_details") or sample.get("verdict_details") or {}
    vd_lines = _render_verdict_details(vd)
    if vd_lines:
        lines.append("### Verdict breakdown")
        lines.extend(vd_lines)
        lines.append("")

    # ── static-analysis function counts + top code detections ───────────────
    if static_analysis:
        counts = static_analysis.get("function_counts") or {}
        if counts:
            total = static_analysis.get("function_count", "?")
            # UI flattens benign + generic_benign into one "benign" bucket
            # (see ui/.../code-detections.component.ts).
            benign_total = (
                counts.get("benign_function_count", 0)
                + counts.get("generic_benign_function_count", 0)
            )
            lines.append(f"### Static analysis ({total} functions)")
            lines.append(
                "- **Function counts**: "
                f"{counts.get('malicious_function_count', 0)} malicious, "
                f"{counts.get('unknown_function_count', 0)} unknown, "
                f"{benign_total} benign"
            )
        static_detections = static_analysis.get("code_detections") or []
        if static_detections:
            total_function_count = static_analysis.get("function_count") or 0
            lines.append(f"#### Code detections ({len(static_detections)} total)")
            lines.extend(_render_code_detections_table(
                static_detections,
                total_function_count=total_function_count,
            ))
        lines.append("")

    # ── per-process behaviour ───────────────────────────────────────────────
    processes = data.get("processes") or []
    if processes:
        lines.append(f"### Processes ({len(processes)})")
        for proc in processes:
            lines.extend(_render_process(proc))
        lines.append("")

    # ── IOCs ────────────────────────────────────────────────────────────────
    sections = [
        ("Domains", iocs.get("domains") or []),
        ("IPs", iocs.get("ips") or []),
        ("URLs", iocs.get("urls") or []),
        ("Files", iocs.get("files") or []),
        ("Mutexes", iocs.get("mutexes") or []),
        ("Registry", iocs.get("registry") or []),
    ]
    for title, items in sections:
        if not items:
            continue
        lines.append(f"### {title} ({len(items)})")
        for ioc in items:
            value = _extract_ioc_value(ioc)
            ops = ioc.get("operations") if isinstance(ioc, dict) else None
            if ops:
                lines.append(f"- `{value}` — {', '.join(ops)}")
            else:
                lines.append(f"- `{value}`")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


_MAX_REPORTS_PER_SAMPLE = 5

# Domains the UI deprioritises in OSINT report listings (mirrors
# ui/app/src/app/modules/sample/components/osint-hunt/samples-reports/
# samples-reports.component.ts → LOW_GRADE_DOMAINS). Reports from these
# hosts sort to the bottom of every sample's report list regardless of
# publication date; ordering within the low-grade group preserves the
# constant's order so the renderer stays predictable.
_LOW_GRADE_DOMAINS = (
    "alienvault.com",
    "vx-underground.org",
    "medium.com",
    "github.com",
    "github.io",
    "r2.dev",
    "twitter.com",
    "1275.ru",
)


def _root_domain(url: str) -> str:
    """Extract the root domain of a URL, mirroring the UI's getRootDomain
    so the LOW_GRADE_DOMAINS membership check matches. Returns "" when the
    URL is empty or unparseable so it's safe to use in dict/set keys.

    Two-level TLDs like `.co.uk` get three labels back (`foo.co.uk`);
    plain subdomains collapse to `domain.tld`."""
    if not url:
        return ""
    try:
        host = urlparse(url).hostname or ""
    except (ValueError, TypeError):
        return ""
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    # Heuristic identical to the UI: if the second-to-last label is ≤3 chars
    # we assume it's a two-level TLD (`co.uk`, `com.au`, …) and keep three
    # labels; otherwise drop everything before the last two.
    if len(parts[-2]) <= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _report_sort_key(rep: dict[str, Any]) -> tuple[int, int, str, str]:
    """UI sort: (low-grade-domain rank, has-undated-date flag, -pub_date, title).

    Mirrors `sortReports` in samples-reports.component.ts:
      1. Reports from non-low-grade domains first (tier 0); among low-grade
         domains, ordering preserves the LOW_GRADE_DOMAINS constant order.
      2. Then dated reports before undated.
      3. Then publication date desc (newest first).
      4. Then title asc as a tiebreaker.
    """
    domain = _root_domain(rep.get("url", ""))
    low_grade_idx = _LOW_GRADE_DOMAINS.index(domain) if domain in _LOW_GRADE_DOMAINS else -1
    low_grade_tier = (1, low_grade_idx) if low_grade_idx >= 0 else (0, 0)
    date = str(rep.get("date") or "")
    # Dated reports come before undated; within dated, newer first (negate by
    # inverting per-char compare via a `~` reversed string isn't trivial here;
    # use a (dated_first, neg_date) pair).
    return (low_grade_tier[0], low_grade_tier[1], 0 if date else 1, _negate_date(date), rep.get("title") or "")


def _negate_date(date: str) -> str:
    """Return a string that sorts in REVERSE date order — `2025-06-09` sorts
    before `2025-05-30`. Implemented by per-char digit subtraction; non-digits
    pass through. Lets us use `_report_sort_key` as a stable `sorted()` key
    without needing reverse-flag gymnastics."""
    out = []
    for ch in date:
        if ch.isdigit():
            out.append(str(9 - int(ch)))
        else:
            out.append(ch)
    return "".join(out)


def osint_reports_overflow(data: dict[str, Any]) -> bool:
    """True iff any matched sample has more *distinct reports* than the
    inline per-sample cap. Tools use this to decide whether to spill the
    full markdown to disk so the long-tail reports remain reachable."""
    reports = data.get("osint", []) if isinstance(data, dict) else []
    # Per-sample distinct reports — mirrors UI's `entries.includes(entry)`
    # dedupe so the same report appearing in multiple code-regions only
    # counts once.
    per_sample: dict[str, set[int]] = {}
    for r in reports:
        report_id = id(r)
        for cr in r.get("code_regions") or []:
            sha = cr.get("sample_hash_sha256")
            if sha:
                per_sample.setdefault(sha, set()).add(report_id)
    return any(len(ids) > _MAX_REPORTS_PER_SAMPLE for ids in per_sample.values())


def format_osint_report(  # noqa: PLR0912, PLR0915
    data: dict[str, Any],
    max_reports_per_sample: int | None = _MAX_REPORTS_PER_SAMPLE,
) -> str:
    """Render the OSINT Hunt response, mirroring the UI's
    `SampleOsintHuntSamplesReportsComponent` layout.

    Wire shape: `{"osint": [{extracted_data, url, code_regions: [...]}]}`.
    Each `code_region` carries the sample it correlates with plus a
    similarity score against the queried sample.

    Per-sample rendering (one section per unique `sample_hash_sha256`):
      - **Code match**: `This sample (hash-equal)` when any of the sample's
        code_regions is hash-equal to the query; otherwise the highest-
        scoring `(code_region_hash, score)` pair. Score renders as integer
        percent — matches the UI's `(score * 100) | number:'1.0-0'`.
      - **Threat reports (N)**: deduplicated by report identity (a report
        with multiple matching code-regions appears once, not once per
        region). Sort: low-grade domains last (preserving UI's
        LOW_GRADE_DOMAINS order), then dated > undated, then pub_date desc,
        then title.

    Sample sort: hash-equal first (the queried sample), then by best score
    desc — matches UI's `sample_is_hash_equal ? 101 : score` ordering.

    `max_reports_per_sample=None` renders every report (used by the
    spill-to-disk path). Samples themselves are not capped."""
    reports = data.get("osint", []) if isinstance(data, dict) else []

    samples: dict[str, dict[str, Any]] = {}
    # Track which reports are already in each sample's list so dedupe is
    # O(1) on the second-and-later code_region of the same report.
    seen_reports_per_sample: dict[str, set[int]] = {}

    for r in reports:
        extracted = r.get("extracted_data") or {}
        report_meta = {
            "title": extracted.get("title") or "Untitled",
            "url": extracted.get("url") or r.get("url") or "",
            "date": extracted.get("publication_date"),
        }
        report_id = id(r)

        for cr in r.get("code_regions") or []:
            sha = cr.get("sample_hash_sha256", "")
            if not sha:
                continue
            cr_score = _coerce_score(cr.get("score"))
            cr_hash_equal = bool(cr.get("sample_is_hash_equal", False))

            entry = samples.setdefault(
                sha,
                {
                    "sha": sha,
                    "sha1": cr.get("sample_hash_sha1") or "",
                    "md5": cr.get("sample_hash_md5") or "",
                    "first_seen": cr.get("sample_first_seen"),
                    "verdict": cr.get("verdict") or "-",
                    "threats": cr.get("threats") or [],
                    "best_score": cr_score,
                    "best_region_hash": cr.get("code_region_hash") or "",
                    "is_hash_equal": cr_hash_equal,
                    "reports": [],
                },
            )
            # Update the sample's "best" code-region with this one if it
            # outranks. `sample_is_hash_equal` is a one-way upgrade — once
            # set it can't be cleared.
            if cr_score > entry["best_score"]:
                entry["best_score"] = cr_score
                entry["best_region_hash"] = cr.get("code_region_hash") or ""
            if cr_hash_equal:
                entry["is_hash_equal"] = True

            # Dedupe-by-report: append the report to this sample's list
            # only the first time we see it.
            seen = seen_reports_per_sample.setdefault(sha, set())
            if report_id not in seen:
                seen.add(report_id)
                entry["reports"].append(report_meta)

    # Sample sort: hash-equal first (queried sample tops the list), then
    # best score desc.
    sorted_samples = sorted(
        samples.values(),
        key=lambda s: (0 if s["is_hash_equal"] else 1, -s["best_score"]),
    )
    n_samples = len(sorted_samples)
    n_reports = len(reports)

    if n_samples == 0:
        return (
            f"## OSINT Hunt: 0 similar samples from {n_reports} threat report(s)\n\n"
            "*No OSINT reports correlate samples with the queried hash.*\n"
        )

    lines = [
        f"## OSINT Hunt: {n_samples} similar samples from {n_reports} threat report(s)\n"
    ]
    for s in sorted_samples:
        sample_link = f"`{s['sha']}`" if s["sha"] else "`?`"
        threats = _threats(s["threats"])
        lines.append(f"### {sample_link} — {s['verdict']}, threats: {threats}")
        if s["sha1"]:
            lines.append(f"- **SHA-1**: `{s['sha1']}`")
        if s["md5"]:
            lines.append(f"- **MD5**: `{s['md5']}`")
        if s["first_seen"]:
            lines.append(f"- **First seen**: {format_timestamp(s['first_seen'], date_only=True)}")

        # Code match — UI rule: literal "This sample (hash-equal)" for the
        # queried sample, otherwise `<region_hash> · <P>%` (integer percent).
        if s["is_hash_equal"]:
            lines.append("- **Code match**: This sample (hash-equal)")
        else:
            score_pct = round(s["best_score"] * 100)
            if s["best_region_hash"]:
                lines.append(
                    f"- **Code match**: `{s['best_region_hash']}` · {score_pct}%"
                )
            else:
                lines.append(f"- **Code match**: {score_pct}%")

        reports_sorted = sorted(s["reports"], key=_report_sort_key)
        total = len(reports_sorted)
        rendered = reports_sorted if max_reports_per_sample is None else reports_sorted[:max_reports_per_sample]
        lines.append(f"- **Threat reports ({total})**:")
        for rep in rendered:
            date_str = format_timestamp(rep["date"], date_only=True) if rep["date"] else None
            date_part = f" ({date_str})" if date_str else ""
            url_part = f" — {rep['url']}" if rep["url"] else ""
            lines.append(f"  - **{rep['title']}**{date_part}{url_part}")
        if max_reports_per_sample is not None and total > max_reports_per_sample:
            extra = total - max_reports_per_sample
            lines.append(f"  *… and {extra} more report(s)*")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


# Column keys whose values must be passed through `format_timestamp` before
# rendering. Lets `_format_analysis_table` keep its generic key-walking logic
# while still producing human-readable timestamps in the right columns.
_TIMESTAMP_COLUMN_KEYS = {
    "analysis_finished",
    "endpoint.scan_started_at",
}

# Column keys that must not be truncated at 40 chars — full SHA256 is 64.
_NO_TRUNCATE_COLUMN_KEYS = {
    "sample_sha256",
    "id",  # leftmost analysis-id, rendered as a markdown link below
}


def _format_analysis_table(
    analyses: list[dict[str, Any]],
    columns: list[tuple[str, str]],
) -> list[str]:
    headers = " | ".join(c[0] for c in columns)
    sep = "|".join(["---"] * len(columns))
    lines = [f"| {headers} |", f"|{sep}|"]
    for a in analyses:
        cells = []
        for _, key in columns:
            value = a
            for part in key.split("."):
                if not isinstance(value, dict):
                    value = None
                    break
                value = value.get(part)
            if isinstance(value, list):
                value = _threats(value)
            elif isinstance(value, dict):
                value = _verdict(value)
            elif key in _TIMESTAMP_COLUMN_KEYS:
                value = format_timestamp(value)
            cell = str(value) if value not in (None, "") else "-"
            if key == "id" and cell != "-":
                cell = f"`{cell}`"
            if key not in _NO_TRUNCATE_COLUMN_KEYS:
                cell = cell[:40]
            cells.append(cell)
        lines.append(f"| {' | '.join(cells)} |")
    return lines


def format_analyses_list(data: dict[str, Any]) -> str:
    """Render `/v1/analyses/samples` response (paginated, cursor-based).

    Per-sample analysis listing: each entry covers one sample. The Sample
    column carries the SHA-256. For the `/v1/analyses/endpoint-scans`
    response (no per-sample identification), use
    `format_endpoint_scan_analyses`."""
    analyses = data.get("analyses", []) if isinstance(data, dict) else []
    cursor = data.get("cursor") if isinstance(data, dict) else None
    lines = [f"## Sample Analyses: {len(analyses)} entries\n"]
    if not analyses:
        if cursor is None:
            lines.append("*No more results.*")
        return "\n".join(lines)

    columns = [
        ("Analysis ID", "id"),
        ("Sample", "sample_sha256"),
        ("Analysis type", "analysis_type"),
        ("Finished", "analysis_finished"),
        ("Scope", "scope"),
        ("Verdict", "verdict"),
        ("Threats", "threats"),
        ("Label", "label"),
    ]
    lines.extend(_format_analysis_table(analyses, columns))

    if cursor:
        lines.append(f"\n*Next page cursor*: `{cursor}`")
    else:
        lines.append("\n*No more results.*")
    return "\n".join(lines)


def format_endpoint_scan_analyses(data: dict[str, Any]) -> str:
    """Render `/v1/analyses/endpoint-scans` response (paginated, cursor-based).

    Endpoint identification (`host_name` and `scan_started_at`) replaces
    the Sample column from per-sample analysis listings — endpoint-scans
    aren't per-sample by definition (a scan covers one host's binaries)
    and the response has no `sample_sha256` field. For per-sample
    listings (`/v1/analyses/samples`) use `format_analyses_list`."""
    analyses = data.get("analyses", []) if isinstance(data, dict) else []
    cursor = data.get("cursor") if isinstance(data, dict) else None
    lines = [f"## Endpoint-Scan Analyses: {len(analyses)} entries\n"]
    if not analyses:
        if cursor is None:
            lines.append("*No more results.*")
        return "\n".join(lines)

    # No Sample column here: endpoint scans aren't per-sample by definition
    # — an endpoint-scan analysis represents a scan of one host's binaries,
    # and the response has no `sample_sha256` field. Endpoint identification
    # (host_name) is the equivalent locator instead.
    columns = [
        ("Analysis ID", "id"),
        ("Endpoint", "endpoint.host_name"),
        ("Scan started", "endpoint.scan_started_at"),
        ("Analysis type", "analysis_type"),
        ("Finished", "analysis_finished"),
        ("Scope", "scope"),
        ("Verdict", "verdict"),
        ("Threats", "threats"),
        ("Label", "label"),
    ]
    lines.extend(_format_analysis_table(analyses, columns))

    if cursor:
        lines.append(f"\n*Next page cursor*: `{cursor}`")
    else:
        lines.append("\n*No more results.*")
    return "\n".join(lines)
