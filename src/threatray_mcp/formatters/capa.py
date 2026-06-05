"""CAPA section formatters."""

from typing import Any

# Mirror the UI's noise filter — internal / library / hosts namespaces don't
# represent malicious capabilities, just engine plumbing and library code.
_NOISY_NAMESPACE_PREFIXES = ("internal/", "library/", "host-interaction/internal")

# Per-rule address cap for the inline summary. The noisiest rules
# (`contain loop`, `parse PE header`) can fire hundreds of times on a
# single binary — surfacing all of them inline is what made CAPA the only
# large-output tool not routed through the spill cache. 30 matches the
# `_MAX_DETECTIONS_PER_FAMILY` cap used by `format_code_detections` so
# the two long-tail formatters use the same threshold.
_MAX_ADDRESSES_PER_RULE = 30


def _address_value(addr: Any) -> str:
    """CAPA addresses come as `{"type": "absolute", "value": <int>}` for normal
    matches and as `{"type": "no address"}` for rules whose matches aren't
    tied to a code offset (e.g. file-level features like 'contain an embedded
    PE file'). Surface those as `n/a` instead of dumping the raw dict."""
    if isinstance(addr, dict):
        if (addr_type := addr.get("type")) == "no address":
            return "n/a"
        if "value" in addr:
            value = addr["value"]
            return f"0x{value:x}" if isinstance(value, int) else str(value)
        return str(addr_type or addr)
    if isinstance(addr, int):
        return f"0x{addr:x}"
    return str(addr) if addr else "-"


def _format_attack(attack_entries: list[dict[str, Any]]) -> str:
    if not attack_entries:
        return ""
    parts = []
    for a in attack_entries:
        tech_id = a.get("id", "")
        technique = a.get("technique", "")
        tactic = a.get("tactic", "")
        sub = a.get("subtechnique", "")
        label = technique
        if sub:
            label = f"{technique}: {sub}"
        if tech_id and tactic:
            parts.append(f"{tactic} / {label} [{tech_id}]")
        elif tech_id:
            parts.append(f"{label} [{tech_id}]")
        else:
            parts.append(label or tactic)
    return ", ".join(parts)


def _format_mbc(mbc_entries: list[dict[str, Any]]) -> str:
    if not mbc_entries:
        return ""
    parts = []
    for m in mbc_entries:
        objective = m.get("objective", "")
        behavior = m.get("behavior", "")
        mbc_id = m.get("id", "")
        label = f"{objective}::{behavior}" if objective and behavior else (behavior or objective)
        if mbc_id:
            parts.append(f"{label} [{mbc_id}]")
        else:
            parts.append(label)
    return ", ".join(parts)


def _is_noisy_namespace(namespace: str) -> bool:
    """The UI suppresses capabilities under `internal/` and `library/`
    namespaces because they describe engine plumbing or runtime code rather
    than malicious behaviour. Mirror that filter here."""
    if not namespace:
        return False
    return any(namespace.startswith(prefix) for prefix in _NOISY_NAMESPACE_PREFIXES)


def capa_addresses_overflow(
    data: dict[str, Any],
    max_addresses_per_rule: int = _MAX_ADDRESSES_PER_RULE,
) -> bool:
    """True iff any non-noise rule has more match addresses than the inline
    cap. Tools use this to decide whether to spill the full markdown to
    disk so the long-tail addresses remain reachable."""
    capabilities = data.get("capabilities") or {}
    rules = capabilities.get("rules") or {}
    for rule_meta in rules.values():
        rmeta = rule_meta.get("meta") or {}
        if _is_noisy_namespace(rmeta.get("namespace", "")):
            continue
        matches = rule_meta.get("matches") or []
        if len(matches) > max_addresses_per_rule:
            return True
    return False


def format_capa_results(  # noqa: PLR0912 — single-shot rendering, splitting hurts readability
    data: dict[str, Any],
    max_addresses_per_rule: int | None = _MAX_ADDRESSES_PER_RULE,
) -> str:
    """Render a curated subset of the CAPA result.

    The full CAPA result is **large** — rules can include nested feature trees,
    every basic-block match with sub-features, and source rule bodies (often
    100+ KB per sample). We surface the high-signal subset and leave the full
    payload available via `response_format=json`:

    - meta: sample hash + target (format/arch/os) + base_address + CAPA version.
    - One flat list of matched rules — namespace, ATT&CK (per rule), MBC, match
      count and every match address. Noise namespaces (`internal/`,
      `library/`, …) are filtered out to mirror the UI.

    `max_addresses_per_rule` caps the per-rule address list at N (default 30)
    with a `*(… and M more)*` footer when the rule fires more often. The
    EddieStealer sample's `contain loop` fires at 421 addresses; without the
    cap a single rule used to drown out every other rule in the response.
    `max_addresses_per_rule=None` disables the cap (used by the spill-to-disk
    path so the cached markdown is complete).
    """
    lines = ["## CAPA Capability Analysis\n"]

    capabilities = data.get("capabilities") or {}
    meta = capabilities.get("meta") or {}
    analysis_meta = meta.get("analysis") or {}
    sample_meta = meta.get("sample") or {}
    rules = capabilities.get("rules") or {}

    # ── meta ────────────────────────────────────────────────────────────────
    if sample_meta or analysis_meta:
        lines.append("### Meta")
        if sample_sha := sample_meta.get("sha256"):
            lines.append(f"- **Sample**: `{sample_sha}`")
        if fmt := analysis_meta.get("format"):
            arch = analysis_meta.get("arch", "?")
            os_name = analysis_meta.get("os", "?")
            lines.append(f"- **Target**: {fmt} / {arch} / {os_name}")
        if base := analysis_meta.get("base_address"):
            lines.append(f"- **Base address**: {_address_value(base)}")
        if version := meta.get("version"):
            lines.append(f"- **CAPA version**: {version}")
        lines.append("")

    # ── rules (flat, namespace-sorted, noise-filtered) ──────────────────────
    records: list[dict[str, Any]] = []
    filtered_out = 0
    for rule_meta in rules.values():
        rmeta = rule_meta.get("meta") or {}
        namespace = rmeta.get("namespace", "")
        if _is_noisy_namespace(namespace):
            filtered_out += 1
            continue
        matches = rule_meta.get("matches") or []
        match_addrs = []
        for entry in matches:
            # Each "match" is `[address, match-tree]`; we take only the address.
            if isinstance(entry, list) and entry:
                match_addrs.append(_address_value(entry[0]))
        records.append({
            "name": rmeta.get("name", "?"),
            "namespace": namespace,
            "attack": rmeta.get("attack") or [],
            "mbc": rmeta.get("mbc") or [],
            "match_count": len(matches),
            "match_addrs": match_addrs,
        })

    records.sort(key=lambda r: (r["namespace"] or "~", r["name"]))

    if records:
        header = f"### Capabilities ({len(records)} rules)"
        if filtered_out:
            header += f" — {filtered_out} internal/library rules hidden"
        lines.append(header)
        for r in records:
            lines.extend(_render_rule(r, max_addresses_per_rule=max_addresses_per_rule))
        lines.append("")
    elif filtered_out:
        lines.append(f"*All {filtered_out} matched rules are in internal/library namespaces (hidden).*")
    else:
        lines.append("*No capabilities matched.*")

    return "\n".join(lines).rstrip() + "\n"


def _render_rule(
    record: dict[str, Any],
    max_addresses_per_rule: int | None = _MAX_ADDRESSES_PER_RULE,
) -> list[str]:
    name = record["name"]
    namespace = record["namespace"]
    attack_str = _format_attack(record["attack"])
    mbc_str = _format_mbc(record["mbc"])
    match_count = record["match_count"]
    match_addrs = record["match_addrs"]

    head = f"- **{name}**"
    if namespace:
        head += f" `{namespace}`"
    head += f" — {match_count} match(es)"
    out = [head]
    if attack_str:
        out.append(f"  - ATT&CK: {attack_str}")
    if mbc_str:
        out.append(f"  - MBC: {mbc_str}")
    if match_addrs:
        if max_addresses_per_rule is not None and len(match_addrs) > max_addresses_per_rule:
            shown = match_addrs[:max_addresses_per_rule]
            extra = len(match_addrs) - max_addresses_per_rule
            out.append(f"  - Addresses: {', '.join(shown)} *(… and {extra} more)*")
        else:
            out.append(f"  - Addresses: {', '.join(match_addrs)}")
    return out
