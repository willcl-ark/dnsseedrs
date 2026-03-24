#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""Analyze bitcoin DNS seeder data and produce JSON for the web dashboard."""

import argparse
import gzip
import json
import os
import re
import urllib.request
from collections import Counter
from datetime import datetime, timezone

SEEDS_URL = "https://bitcoin.fish.foo/seeds.txt.gz"
SEEDS_GZ = "seeds.txt.gz"
SEEDS_TXT = "seeds.txt"


def fetch_seeds(force: bool = False) -> None:
    if not force and os.path.exists(SEEDS_GZ):
        print(f"Using cached {SEEDS_GZ} (use --force to re-download)")
        return
    print(f"Downloading {SEEDS_URL} ...")
    urllib.request.urlretrieve(SEEDS_URL, SEEDS_GZ)
    print("Done.")


def decompress(force: bool = False) -> None:
    if not force and os.path.exists(SEEDS_TXT):
        return
    with gzip.open(SEEDS_GZ, "rb") as f_in, open(SEEDS_TXT, "wb") as f_out:
        f_out.write(f_in.read())


def parse_seeds(path: str) -> list[dict]:
    rows = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = re.search(r'"([^"]*)"', line)
            user_agent = m.group(1) if m else ""
            rest = line[: m.start()].strip() if m else line
            parts = rest.split()
            if len(parts) < 11:
                continue
            rows.append(
                {
                    "address": parts[0],
                    "good": int(parts[1]),
                    "user_agent": user_agent,
                }
            )
    return rows


def extract_prefix16(addr: str) -> str | None:
    if ".onion:" in addr or addr.startswith("["):
        return None
    parts = addr.split(".")
    if len(parts) >= 2:
        return f"{parts[0]}.{parts[1]}"
    return None


def classify_network(addr: str) -> str:
    if ".onion:" in addr:
        return "tor"
    if addr.startswith("["):
        return "ipv6"
    return "ipv4"


def classify_agent(ua: str) -> str:
    if not ua:
        return "unknown"
    ua_lower = ua.lower()
    if "bip110" in ua_lower:
        return "bip110"
    if "knots" in ua_lower:
        return "knots"
    cleaned = re.sub(r"\([^)]*\)", "", ua).strip("/")
    parts = [p for p in cleaned.split("/") if p]
    if len(parts) == 1 and parts[0].startswith("Satoshi:"):
        return "core"
    return "other"


def extract_version(ua: str) -> str:
    ua = ua.strip("/")
    parts = ua.split("/")
    clean = [p.split("(")[0].strip() for p in parts if p]
    if not clean:
        return ua or "unknown"
    bip110 = [p for p in clean if "bip110" in p.lower()]
    knots = [p for p in clean if "Knots" in p and "bip110" not in p.lower()]
    if bip110:
        return "/".join(knots + bip110)
    if knots:
        return knots[0]
    return clean[0]



def build_data(rows: list[dict]) -> dict:
    classes = ["core", "knots", "bip110", "other"]
    labels = ["Core", "Knots (no BIP110)", "BIP110", "Other"]

    all_by_class = Counter()
    good_by_class = Counter()
    for r in rows:
        cls = classify_agent(r["user_agent"])
        all_by_class[cls] += 1
        if r["good"]:
            good_by_class[cls] += 1

    unknown_known = all_by_class.pop("unknown", 0)
    good_by_class.pop("unknown", 0)

    known_vals = [all_by_class[c] for c in classes]
    good_vals = [good_by_class[c] for c in classes]
    good_rates = [
        round(good_by_class[c] / all_by_class[c] * 100, 1) if all_by_class[c] else 0
        for c in classes
    ]

    total_known = sum(known_vals)
    total_good = sum(good_vals)

    print(f"\nTotal nodes in DB: {total_known + unknown_known:,} ({unknown_known:,} never contacted)")
    print(f"Known: {total_known:,}, Good: {total_good:,}")

    # Top user agents (good nodes)
    good_rows = [r for r in rows if r["good"]]
    ua_counter = Counter()
    for r in good_rows:
        ua = r["user_agent"].strip("/")
        parts = ua.split("/")
        simplified = "/".join(p.split("(")[0].strip() for p in parts if p)
        ua_counter[simplified] += 1

    top_agents = ua_counter.most_common(25)
    top_agent_labels = [a for a, _ in top_agents]
    top_agent_counts = [c for _, c in top_agents]

    # Knots & BIP110 versions
    knots_bip_agents = Counter()
    for r in good_rows:
        cls = classify_agent(r["user_agent"])
        if cls in ("knots", "bip110"):
            knots_bip_agents[extract_version(r["user_agent"])] += 1

    top_kb = knots_bip_agents.most_common(15)
    kb_labels = [a for a, _ in top_kb]
    kb_counts = [c for _, c in top_kb]

    # Network stats
    networks = ["ipv4", "ipv6", "tor"]
    net_labels = ["IPv4", "IPv6", "Tor"]
    known_by_net = Counter()
    good_by_net = Counter()
    cross_good = {n: Counter() for n in networks}
    for r in rows:
        if not r["user_agent"]:
            continue
        net = classify_network(r["address"])
        cls = classify_agent(r["user_agent"])
        known_by_net[net] += 1
        if r["good"]:
            good_by_net[net] += 1
            cross_good[net][cls] += 1

    net_known_vals = [known_by_net[n] for n in networks]
    net_good_vals = [good_by_net[n] for n in networks]
    net_good_rates = [
        round(good_by_net[n] / known_by_net[n] * 100, 1) if known_by_net[n] else 0
        for n in networks
    ]

    # Network x Classification (good nodes)
    net_class_series = []
    for cls, lbl in zip(classes, labels):
        net_class_series.append({
            "name": lbl,
            "key": cls,
            "values": [cross_good[n][cls] for n in networks],
        })

    # IPv4 /16 prefix clustering
    prefix_by_class = {}
    for r in good_rows:
        prefix = extract_prefix16(r["address"])
        if prefix is None:
            continue
        cls = classify_agent(r["user_agent"])
        if prefix not in prefix_by_class:
            prefix_by_class[prefix] = Counter()
        prefix_by_class[prefix][cls] += 1

    prefix_totals = {p: sum(c.values()) for p, c in prefix_by_class.items()}

    # Sybil detection
    counts = list(prefix_totals.values())
    mean = sum(counts) / len(counts)
    variance = sum((c - mean) ** 2 for c in counts) / len(counts)
    stddev = variance ** 0.5
    sybil_threshold = mean + 5 * stddev
    sybil_prefixes = sorted(p for p, total in prefix_totals.items() if total > sybil_threshold)

    def is_sybil(addr: str) -> bool:
        prefix = extract_prefix16(addr)
        return prefix is not None and prefix in sybil_prefixes

    sybil_count = sum(1 for r in good_rows if is_sybil(r["address"]))
    sybil_by_cls = Counter()
    for r in good_rows:
        if is_sybil(r["address"]):
            sybil_by_cls[classify_agent(r["user_agent"])] += 1

    print(f"\nSybil: mean={mean:.1f}, σ={stddev:.1f}, threshold={sybil_threshold:.0f}")
    print(f"  Flagged {len(sybil_prefixes)} prefixes, {sybil_count:,} nodes")

    # Sybil breakdown (IPv4 only — sybil detection is IPv4-specific)
    ipv4_good_by_cls = Counter()
    for counts_by_cls in prefix_by_class.values():
        for cls, n in counts_by_cls.items():
            ipv4_good_by_cls[cls] += n

    sybil_bars = []
    for cls, lbl in zip(classes, labels):
        organic = ipv4_good_by_cls.get(cls, 0) - sybil_by_cls.get(cls, 0)
        sybil_n = sybil_by_cls.get(cls, 0)
        sybil_bars.append({"label": lbl, "key": cls, "value": organic})
        if sybil_n > 0:
            sybil_bars.append({"label": f"{lbl} (sybil)", "key": f"{cls}_sybil", "value": sybil_n})

    # Network x Classification with sybil
    net_class_sybil_series = []
    for cls, lbl in zip(classes, labels):
        sybil_in_cls = Counter()
        for r in good_rows:
            if classify_agent(r["user_agent"]) == cls and is_sybil(r["address"]):
                sybil_in_cls[classify_network(r["address"])] += 1
        organic_vals = [cross_good[n].get(cls, 0) - sybil_in_cls.get(n, 0) for n in networks]
        sybil_vals_net = [sybil_in_cls.get(n, 0) for n in networks]
        net_class_sybil_series.append({
            "name": lbl, "key": cls, "values": organic_vals,
        })
        if any(v > 0 for v in sybil_vals_net):
            net_class_sybil_series.append({
                "name": f"{lbl} (sybil)", "key": f"{cls}_sybil", "values": sybil_vals_net,
            })

    # Top /16 prefixes
    top_prefixes = sorted(prefix_totals, key=prefix_totals.get, reverse=True)[:20]
    top_prefix_series = []
    for cls, lbl in zip(classes, labels):
        top_prefix_series.append({
            "name": lbl,
            "key": cls,
            "values": [prefix_by_class[p].get(cls, 0) for p in top_prefixes],
        })

    # Prefix table
    prefix_table = []
    for p in top_prefixes:
        prefix_table.append({
            "prefix": f"{p}.0.0/16",
            "total": prefix_totals[p],
            "core": prefix_by_class[p].get("core", 0),
            "knots": prefix_by_class[p].get("knots", 0),
            "bip110": prefix_by_class[p].get("bip110", 0),
            "other": prefix_by_class[p].get("other", 0),
        })

    # Per-class sybil concentration stats
    sybil_by_class_pct = {}
    for cls in classes:
        total = sum(c.get(cls, 0) for c in prefix_by_class.values())
        in_sybil = sum(prefix_by_class[p].get(cls, 0) for p in sybil_prefixes)
        sybil_by_class_pct[cls] = {
            "total": total,
            "sybil": in_sybil,
            "pct": round(in_sybil / total * 100, 1) if total else 0,
        }

    # Overview pie
    overview_labels = ["No user agent", *labels]
    overview_values = [unknown_known, *known_vals]
    overview_keys = ["unknown", *classes]

    # Custom user agents
    custom_ua = Counter()
    for r in rows:
        cls = classify_agent(r["user_agent"])
        if cls == "other":
            custom_ua[r["user_agent"]] += 1
    custom_filtered = [{"ua": ua, "count": c} for ua, c in custom_ua.most_common() if c > 1]

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "totals": {
            "total_db": total_known + unknown_known,
            "unknown": unknown_known,
            "known": total_known,
            "good": total_good,
        },
        "classification": {
            "labels": labels,
            "keys": classes,
            "known": known_vals,
            "good": good_vals,
            "good_rates": good_rates,
        },
        "top_user_agents": {
            "labels": top_agent_labels,
            "counts": top_agent_counts,
        },
        "knots_bip110_versions": {
            "labels": kb_labels,
            "counts": kb_counts,
        },
        "networks": {
            "labels": net_labels,
            "keys": ["ipv4", "ipv6", "tor"],
            "known": net_known_vals,
            "good": net_good_vals,
            "good_rates": net_good_rates,
        },
        "network_classification": {
            "net_labels": net_labels,
            "series": net_class_series,
        },
        "sybil": {
            "mean": round(mean, 1),
            "stddev": round(stddev, 1),
            "threshold": round(sybil_threshold),
            "prefixes": [f"{p}.0.0/16" for p in sybil_prefixes],
            "count": sybil_count,
            "bars": sybil_bars,
        },
        "network_classification_sybil": {
            "net_labels": net_labels,
            "series": net_class_sybil_series,
        },
        "top_prefixes": {
            "labels": [f"{p}.x.x" for p in top_prefixes],
            "series": top_prefix_series,
        },
        "prefix_table": {
            "rows": prefix_table,
            "stats": {
                "distinct_prefixes": len(prefix_by_class),
                "total_good_ipv4": sum(prefix_totals.values()),
                "sybil_prefix_count": len(sybil_prefixes),
                "sybil_by_class": sybil_by_class_pct,
            },
        },
        "overview_pie": {
            "labels": overview_labels,
            "values": overview_values,
            "keys": overview_keys,
        },
        "custom_user_agents": {
            "items": custom_filtered,
            "total": sum(custom_ua.values()),
            "distinct": len(custom_ua),
        },
    }


def main():
    parser = argparse.ArgumentParser(description="Analyze bitcoin DNS seeder data")
    parser.add_argument("--force", action="store_true", help="Force re-download")
    parser.add_argument("--output", default="web/data.json", help="Output JSON file")
    args = parser.parse_args()

    fetch_seeds(args.force)
    decompress(args.force)

    print("Parsing seeds data...")
    rows = parse_seeds(SEEDS_TXT)

    data = build_data(rows)

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(data, f)
    print(f"\nJSON saved to {args.output} ({os.path.getsize(args.output):,} bytes)")


if __name__ == "__main__":
    main()
