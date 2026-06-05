"""Functions section formatters."""

from typing import Any

from ._helpers import format_timestamp

_MAX_MATCHES_PER_FN = 15
_MAX_RETROHUNT_FUNCTIONS_TO_SHOW = 20
_MAX_DETECTIONS_PER_FAMILY = 30

_CONFIDENCE_RANK = {"high": 0, "medium": 1, "low": 2}


def _ida_match_sort_key(m: dict[str, Any]) -> tuple:
    """Mirror the IDA plugin's match sort priority — used by both
    `_get_unique_matches` in cluster_analysis_result_controller (for the
    diff/cluster view) and `_get_best_match` in
    function_retrohunt_result_controller (for the retrohunt view).

    Priority:
      1. confidence rank (HIGH=0 first, then MEDIUM, LOW, unknown last)
      2. -score (score desc, tiebreak within same confidence)
      3. hash_sha256 asc (stable tiebreak — also drives the dedupe-by-target
         pass in the diff renderer)
      4. address asc (final tiebreak)

    A high-confidence match at score 0.95 ranks ABOVE a low-confidence
    match at score 0.99 — the IDA plugin treats confidence as the
    headline signal because it's the classifier's commitment, not the
    raw similarity number.
    """
    score = m.get("score")
    try:
        score_v = float(score) if score is not None else 0.0
    except (TypeError, ValueError):
        score_v = 0.0
    return (
        _CONFIDENCE_RANK.get(str(m.get("confidence") or "").lower(), 99),
        -score_v,
        str(m.get("hash_sha256") or ""),
        int(m.get("address") or 0) if isinstance(m.get("address"), (int, float)) else 0,
    )


def _join_strings(items: list[Any], limit: int = 3) -> str:
    if not items:
        return ""
    strs = [str(i) for i in items if i is not None]
    if not strs:
        return ""
    if len(strs) <= limit:
        return ", ".join(strs)
    return ", ".join(strs[:limit]) + f", … (+{len(strs) - limit})"


def _fmt_addr(addr: Any) -> str:
    return f"0x{addr:08x}" if isinstance(addr, int) else str(addr or "-")


def _verdict_short(value: Any) -> str:
    if isinstance(value, dict):
        return str(value.get("label") or value.get("value") or "-")
    return str(value) if value not in (None, "") else "-"


def _threats_str(threats: Any) -> str:
    if not isinstance(threats, list):
        return str(threats) if threats else "-"
    labels = [t.get("label", str(t)) if isinstance(t, dict) else str(t) for t in threats]
    return ", ".join(labels) or "-"


def format_functions_list(data: dict[str, Any], max_functions: int | None = None) -> str:
    """Render `/v1/functions/{hash}` (FunctionsByHashGetResponse).

    Per-function fields exposed: address (formatted hex), size, uid, api_calls,
    constants. The disassembly fields (`size`, `api_calls`, `constants`) live
    inside the nested `disassembly_info` object — the function uid is the join
    key for `get_code_detections` and `run_retrohunt`.
    """
    functions = data.get("functions", [])
    total_count = len(functions)
    lines = []

    if max_functions and total_count > max_functions:
        lines.append(f"## Functions: {total_count} extracted (showing {max_functions})\n")
        display_functions = functions[:max_functions]
    else:
        lines.append(f"## Functions: {total_count} extracted\n")
        display_functions = functions

    lines.append("| Address | Size | UID | API Calls | Constants |")
    lines.append("|---------|------|-----|-----------|-----------|")
    for f in display_functions:
        di = f.get("disassembly_info") or {}
        api_calls = _join_strings(di.get("api_calls") or f.get("api_calls") or []) or "-"
        constants = _join_strings(di.get("constants") or f.get("constants") or []) or "-"
        size = di.get("size") if di.get("size") is not None else f.get("size", "-")
        lines.append(
            f"| `{_fmt_addr(f.get('address'))}` | {size} | `{f.get('uid', '-')}` "
            f"| {api_calls} | {constants} |"
        )

    if max_functions and total_count > max_functions:
        lines.append(f"\n*Showing first {max_functions} of {total_count} functions.*")

    return "\n".join(lines)


def format_code_detections(data: dict[str, Any], max_detections: int | None = None) -> str:  # noqa: PLR0915
    """Render `/v1/functions/code-detections` (FunctionsCodeDetectionsResponse).

    Groups detections by `family.name` and renders:
    1. a `### Summary` table at the top with one row per family (Family /
       Category / Functions), sorted UI-style (non-benign first, then benign,
       by function count desc within each group), and
    2. one per-family table per family with the per-function detections
       (Function · UID · Verdict · Sig · Score · Conf · Sim). Every numeric
       score renders, regardless of verdict — mirrors the UI's per-function
       Code Detections table.

    A row whose verdict reads `malware / unknown` means the family's
    signature has some overlap with the function but the signal was too
    low for the classifier to commit to a malicious verdict — `unknown` is
    not "haven't looked at it"; it's "looked, found some overlap, not
    confident enough to call malware".

    Per-family cap is `_MAX_DETECTIONS_PER_FAMILY = 30` when
    `max_detections` is set; `None` disables both the global and per-family
    caps so the spill markdown is complete.
    """
    functions = data.get("functions", [])
    by_family: dict[str, list[dict[str, Any]]] = {}
    total = 0
    for func in functions:
        for det in func.get("code_detections") or []:
            family = det.get("family") or {}
            family_name = family.get("name") if isinstance(family, dict) else None
            sig = det.get("code_signature") or {}
            sig_name = sig.get("name") if isinstance(sig, dict) else None
            # Wire shape note: a detection where BOTH family.name AND
            # code_signature.name are null is the UI's `Generic benign`
            # bucket — usually a benign-verdict function with score=1.0 and
            # overlap=1.0 that doesn't match any named runtime / library
            # signature. The analyses formatter already labels these
            # `Generic benign`; matching here keeps the two views in sync.
            key = family_name or sig_name or "Generic benign"
            by_family.setdefault(key, []).append({
                "function_address": func.get("address"),
                "function_uid": func.get("uid"),
                "verdict": det.get("verdict"),
                "score": det.get("score"),
                "confidence": det.get("confidence"),
                "similarity": det.get("similarity"),
                "family": family,
                "code_signature_name": sig_name or "Generic benign",
            })
            total += 1

    capped = max_detections and total > max_detections
    lines = [f"## Code Detections: {total} matches" + (f" (showing {max_detections})\n" if capped else "\n")]

    def _family_sort_key(k: str) -> tuple[int, int]:
        rows = by_family[k]
        has_non_benign = any(
            str(r.get("verdict") or "").lower() != "benign" for r in rows
        )
        return (0 if has_non_benign else 1, -len(rows))

    sorted_families = sorted(by_family, key=_family_sort_key)

    # Summary table: one row per family, UI-style sort (families with any
    # non-benign detection first, by function count desc; benign-only
    # families last by count desc).
    if sorted_families:
        lines.append("### Summary")
        lines.append("| Family | Category | Functions |")
        lines.append("|--------|----------|----------:|")
        for key in sorted_families:
            rows = by_family[key]
            family = rows[0]["family"]
            category = family.get("category") if isinstance(family, dict) else ""
            lines.append(f"| `{key}` | {category or '-'} | {len(rows)} |")
        lines.append("")

    # When max_detections is None, also disable the per-family cap so the
    # spill file is truly complete.
    per_family_cap = _MAX_DETECTIONS_PER_FAMILY if max_detections is not None else None
    shown = 0
    # Per-family detail tables — same UI-style sort as the summary.
    for key in sorted_families:
        if max_detections and shown >= max_detections:
            break
        rows = by_family[key]
        family = rows[0]["family"]
        category = family.get("category") if isinstance(family, dict) else ""
        header = f"### `{key}` family ({len(rows)} functions)"
        if category:
            header += f" — {category}"
        lines.append(header)
        lines.append("| Function | UID | Verdict | Sig | Score | Conf | Sim |")
        lines.append("|----------|-----|---------|-----|------:|-----:|----:|")
        family_rows = rows[:per_family_cap] if per_family_cap is not None else rows
        for r in family_rows:
            if max_detections and shown >= max_detections:
                break
            verdict = str(r["verdict"] or "-")
            confidence = r["confidence"] or "-"
            similarity = r["similarity"] or "-"
            score = r["score"]
            score_str = f"{float(score):.3f}" if isinstance(score, (int, float)) else "-"
            sig_cell = f"`{r['code_signature_name']}`" if r["code_signature_name"] else "-"
            lines.append(
                f"| `{_fmt_addr(r['function_address'])}` "
                f"| `{r['function_uid']}` | {verdict} | {sig_cell} "
                f"| {score_str} | {confidence} | {similarity} |"
            )
            shown += 1
        if per_family_cap is not None and len(rows) > per_family_cap:
            lines.append(f"\n*… and {len(rows) - per_family_cap} more in `{key}`.*")
        lines.append("")

    if total == 0:
        lines.append("*No code detections.*")

    return "\n".join(lines).rstrip() + "\n"


def _format_match_pair(ref_uid: str, m: dict[str, Any]) -> str:
    """Render one `<ref_uid> → <matched_uid> @ <addr> · score · conf · sim` pair."""
    matched_uid = m.get("uid") or "?"
    addr = _fmt_addr(m.get("address"))
    score = m.get("score")
    score_str = f"{float(score):.2f}" if isinstance(score, (int, float)) else "-"
    confidence = m.get("confidence") or "-"
    similarity = m.get("similarity") or "-"
    return f"`{ref_uid}` → `{matched_uid}` @ `{addr}` · {score_str} · {confidence} · {similarity}"


def format_function_retrohunt(data: dict[str, Any], max_matches: int | None = None) -> str:  # noqa: PLR0915
    """Render `/v1/retrohunt/functions` (FunctionRetrohunt output).

    Pivots matches by `(analysis_id, code_region)` — one table row per matched
    memory snapshot, mirroring the UI's grouping. A region can absorb hits
    from multiple input UIDs; the Matching-functions cell lists all
    `<ref_uid> → <matched_uid> @ <addr> · score · conf · sim` pairs for that
    region, separated by `<br>` for renderers that support inline-table HTML.

    Sort: by `nr_of_function_matches` desc (regions where more inputs hit are
    densest signal), then by best score desc.
    """
    functions = data.get("functions", [])
    samples_by_analysis = {s.get("analysis_id"): s for s in data.get("samples") or []}
    code_regions_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for cr in data.get("code_regions") or []:
        key = (cr.get("analysis_id") or "", cr.get("hash_sha256") or "")
        code_regions_by_key[key] = cr

    input_uids = [f.get("uid", "?") for f in functions]
    total_input_fns = len(functions)
    total_matches = sum(len(f.get("matches") or []) for f in functions)
    n_samples = len(data.get("samples") or [])

    # Build region → list[(ref_uid, match)] pivot.
    matches_by_region: dict[tuple[str, str], list[tuple[str, dict[str, Any]]]] = {}
    for fn in functions:
        ref_uid = fn.get("uid") or "?"
        for m in fn.get("matches") or []:
            key = (m.get("analysis_id") or "", m.get("code_region") or "")
            matches_by_region.setdefault(key, []).append((ref_uid, m))

    # Build per-region summary rows.
    region_rows: list[dict[str, Any]] = []
    for key, pairs in matches_by_region.items():
        aid, region_hash = key
        cr = code_regions_by_key.get(key, {})
        sample = samples_by_analysis.get(aid, {})
        pairs.sort(key=lambda p: _ida_match_sort_key(p[1]))
        # nr_of_function_matches is the API's count of input UIDs that hit
        # this region; fall back to the unique-uid count from our pairs.
        nr_matches = cr.get("nr_of_function_matches")
        if nr_matches is None:
            nr_matches = len({p[0] for p in pairs})
        best_score = 0.0
        try:
            best_score = max(float(p[1].get("score") or 0) for p in pairs)
        except (TypeError, ValueError):
            pass
        region_rows.append({
            "analysis_id": aid,
            "region_hash": region_hash,
            "region": cr,
            "sample": sample,
            "pairs": pairs,
            "nr_matches": nr_matches,
            "best_score": best_score,
        })
    region_rows.sort(key=lambda r: (-(r["nr_matches"] or 0), -r["best_score"]))

    lines = [
        f"## Function Retrohunt: {total_input_fns} reference function(s), "
        f"{total_matches} total matches across {n_samples} samples\n"
    ]
    if input_uids:
        lines.append(f"**Input UIDs ({total_input_fns}):** " + ", ".join(f"`{u}`" for u in input_uids))
        lines.append("")

    if not region_rows:
        lines.append("*No matches found.*")
        return "\n".join(lines).rstrip() + "\n"

    lines.append(
        "| Analysis ID | Sample hash | First seen | Verdict / Threats "
        "| Code region (refs matched) "
        "| Matching functions (ref → matched @ addr · score · conf · sim) |"
    )
    lines.append("|---|---|---|---|---|---|")

    # When max_matches is None, also disable per-region cap on regions and
    # per-region match-pair cap so the spill file is truly complete.
    region_cap = _MAX_RETROHUNT_FUNCTIONS_TO_SHOW if max_matches is not None else None
    pair_cap = _MAX_MATCHES_PER_FN if max_matches is not None else None

    shown = 0
    displayed_regions = region_rows[:region_cap] if region_cap is not None else region_rows
    for row in displayed_regions:
        if max_matches and shown >= max_matches:
            break
        sample = row["sample"]
        sample_sha = sample.get("hash_sha256") or ""
        analysis_id = row["analysis_id"]
        analysis_link = f"`{analysis_id}`" if analysis_id else "`?`"
        sample_hash_cell = f"`{sample_sha}`" if sample_sha else "`?`"
        first_seen = format_timestamp(sample.get("first_seen"), date_only=True)
        verdict = sample.get("verdict") or row["region"].get("verdict") or "-"
        threats = _threats_str(sample.get("threats") or row["region"].get("threats"))
        region_hash = row["region_hash"]
        region_cell_bits = [f"`{region_hash}`" if region_hash else "`?`"]
        region_cell_bits.append(f"{row['nr_matches']}/{total_input_fns} ref UIDs")
        region_cell = " · ".join(region_cell_bits)
        pairs_to_show = row["pairs"][:pair_cap] if pair_cap is not None else row["pairs"]
        pair_strs = [_format_match_pair(ref_uid, m) for ref_uid, m in pairs_to_show]
        if pair_cap is not None and len(row["pairs"]) > pair_cap:
            pair_strs.append(f"… and {len(row['pairs']) - pair_cap} more")
        matching_cell = "<br>".join(pair_strs)
        lines.append(
            f"| {analysis_link} | {sample_hash_cell} | {first_seen} | "
            f"{verdict} / {threats} | {region_cell} | {matching_cell} |"
        )
        shown += 1

    if region_cap is not None and len(region_rows) > region_cap:
        lines.append(
            f"\n*Showing first {region_cap} of {len(region_rows)} matched regions.*"
        )

    return "\n".join(lines).rstrip() + "\n"


def _diff_file_meta(f: dict[str, Any]) -> tuple[str, str, str]:
    """Pluck (hash, verdict, threats) from a diff `files[]` / `source_file`
    block. function_count intentionally omitted — the wire shape doesn't
    label which denominator it carries (total disassembler / unique
    Threatray / signature-eligible), so surfacing the raw number invites
    misreading."""
    return (
        f.get("hash_sha256") or "?",
        _verdict_short(f.get("verdict")),
        _threats_str(f.get("threats") or []),
    )


def format_function_diff(data: dict[str, Any], max_matches: int | None = None) -> str:  # noqa: PLR0912, PLR0915
    """Render `/v1/functions/diff` response — 1-source-to-N-targets function diff.

    Shape: `{source_file: {meta}, files: [{target meta} …], functions: [{address,
    cc, size, uid, prevalence, matches: [{address, analysis_id, base, cc,
    hash_sha256 (target sample), pid, size, uid, score, confidence, similarity}
    …]} …]}`.

    Layout mirrors the IDA plugin's Cluster Analysis result view
    (`cluster_analysis_result_controller.py`):

    - Per source function: matches are sorted by `_ida_match_sort_key`
      (confidence → -score → hash → address) and **deduplicated by target
      `hash_sha256`** — one row per target sample, keeping the highest-
      ranked match. A source function matching three regions of the same
      target collapses to one row.
    - Source functions are sorted by **prevalence desc** (number of distinct
      samples the function appears in, including the source itself — matches
      the UI's `-f.prevalence` default sort), then by source `address` asc
      as a stable tiebreak.
    - Output: source metadata block + targets table (`Source fns matched
      here` — count of source functions that found at least one match in
      each target) + flat match table (Source UID · Source addr · Target
      sample · Matched UID · Matched addr · Score · Conf · Sim).

    `response_format='json'` preserves the un-deduplicated per-region match
    list for the rare case the analyst needs every region's score.
    """
    source_file = data.get("source_file") or {}
    all_files = data.get("files") or []
    functions = data.get("functions") or []

    lines: list[str] = []

    source_hash, source_verdict, source_threats = _diff_file_meta(source_file)
    # `files[]` includes the source sample itself in the wire shape; filter
    # it out so the Targets table reflects what the caller actually asked
    # for. Self-matches inside `functions[].matches` are filtered the same
    # way before we count or render them.
    target_files = [t for t in all_files if t.get("hash_sha256") != source_hash]

    fns_with_matches = []
    for fn in functions:
        external_matches = [
            m for m in (fn.get("matches") or [])
            if m.get("hash_sha256") and m.get("hash_sha256") != source_hash
        ]
        if not external_matches:
            continue
        # IDA-style per-source-function processing: sort matches by the IDA
        # priority key, then dedupe by target hash — one match row per
        # target sample, the highest-ranked one wins. Mirrors
        # `_get_unique_matches` in cluster_analysis_result_controller.
        sorted_matches = sorted(external_matches, key=_ida_match_sort_key)
        seen_targets: set[str] = set()
        unique_matches: list[dict[str, Any]] = []
        for m in sorted_matches:
            target = m.get("hash_sha256") or ""
            if target and target not in seen_targets:
                seen_targets.add(target)
                unique_matches.append(m)
        fns_with_matches.append({**fn, "matches": unique_matches})
    total_matches = sum(len(f.get("matches") or []) for f in fns_with_matches)

    # Per-target count: how many of the source's functions matched HERE.
    # Distinct source-function count, not match-row count — a source
    # function with 3 matches in the same target counts once.
    source_fns_per_target: dict[str, int] = {}
    for fn in fns_with_matches:
        seen_here: set[str] = set()
        for m in fn.get("matches") or []:
            target_hash = m.get("hash_sha256") or ""
            if target_hash and target_hash not in seen_here:
                seen_here.add(target_hash)
                source_fns_per_target[target_hash] = source_fns_per_target.get(target_hash, 0) + 1

    lines.append(
        f"## Function Diff: source `{source_hash}` vs {len(target_files)} target(s) — "
        f"{len(fns_with_matches)} source function(s) matched, {total_matches} total matches\n"
    )

    # ── source metadata ────────────────────────────────────────────────────
    lines.append("### Source")
    lines.append(f"- **SHA256**: `{source_hash}`")
    lines.append(f"- **Verdict**: {source_verdict}")
    lines.append(f"- **Threats**: {source_threats}")
    lines.append(f"- **Functions with matches**: {len(fns_with_matches)}")
    lines.append("")

    # ── targets table ──────────────────────────────────────────────────────
    if target_files:
        lines.append(f"### Targets ({len(target_files)})")
        lines.append("| Sample hash | Verdict | Threats | Source fns matched here |")
        lines.append("|-------------|---------|---------|------------------------:|")
        for t in target_files:
            t_hash, t_verdict, t_threats = _diff_file_meta(t)
            matched_here = source_fns_per_target.get(t_hash, 0)
            lines.append(f"| `{t_hash}` | {t_verdict} | {t_threats} | {matched_here} |")
        lines.append("")

    if not fns_with_matches:
        lines.append("*No source functions had matches in the targets above the threshold.*")
        return "\n".join(lines).rstrip() + "\n"

    # ── flat match table ───────────────────────────────────────────────────
    # Outer sort: mirror the IDA plugin's default — by prevalence desc, then
    # source address asc. Prevalence = number of distinct samples this
    # function appears in (distinct target hashes already deduplicated above,
    # plus the source itself), matching the UI's `-f.prevalence` key. Source
    # functions that appear in many samples float to the top of the table.
    # Inner matches are already sorted + deduped by the per-function pass.
    def _prevalence(fn: dict[str, Any]) -> int:
        # Distinct target hashes (post-dedupe matches[] already carries one
        # per target) + 1 for the source sample.
        return len(fn.get("matches") or []) + 1

    def _src_addr(fn: dict[str, Any]) -> int:
        addr = fn.get("address")
        return int(addr) if isinstance(addr, (int, float)) else 0

    fns_with_matches.sort(key=lambda f: (-_prevalence(f), _src_addr(f)))
    flat_rows: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for fn in fns_with_matches:
        # Matches are already sorted+deduped above; just flatten.
        for m in fn.get("matches") or []:
            flat_rows.append((fn, m))

    if max_matches is not None and len(flat_rows) > max_matches:
        displayed = flat_rows[:max_matches]
        truncation_note = f"\n*Showing first {max_matches} of {len(flat_rows)} matches.*"
    else:
        displayed = flat_rows
        truncation_note = ""

    lines.append(f"### Matches ({total_matches})")
    lines.append(
        "| Source UID | Source addr | Target sample | Matched UID | Matched addr "
        "| Score | Conf | Sim |"
    )
    lines.append("|---|---|---|---|---|------:|------|------|")
    for fn, m in displayed:
        src_uid = fn.get("uid") or "?"
        src_addr = _fmt_addr(fn.get("address"))
        target_sample = m.get("hash_sha256") or "?"
        matched_uid = m.get("uid") or "?"
        matched_addr = _fmt_addr(m.get("address"))
        score = m.get("score")
        score_str = f"{float(score):.2f}" if isinstance(score, (int, float)) else "-"
        confidence = m.get("confidence") or "-"
        similarity = m.get("similarity") or "-"
        lines.append(
            f"| `{src_uid}` | `{src_addr}` | `{target_sample}` "
            f"| `{matched_uid}` | `{matched_addr}` "
            f"| {score_str} | {confidence} | {similarity} |"
        )

    if truncation_note:
        lines.append(truncation_note)

    return "\n".join(lines).rstrip() + "\n"
