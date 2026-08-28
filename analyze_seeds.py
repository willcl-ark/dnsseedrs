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
import ipaddress
import re
import subprocess
import sys
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from statistics import median

SCRIPT_DIR = Path(__file__).resolve().parent
SEEDS_URL = "https://bitcoin.fish.foo/seeds.txt.gz"
SEEDS_GZ = SCRIPT_DIR / "seeds.txt.gz"
SEEDS_TXT = SCRIPT_DIR / "seeds.txt"
ASMAP_URL = (
    "https://github.com/bitcoin-core/asmap-data/raw/refs/heads/main/latest_asmap.dat"
)
ASMAP_DAT = SCRIPT_DIR / "latest_asmap.dat"
ASMAP_DECODED = SCRIPT_DIR / "latest_asmap.decoded"
ASMAP_TOOL = SCRIPT_DIR / "asmap" / "asmap-tool.py"
ASN_JSON_URL = "https://github.com/quantcdn/asn-info/raw/refs/heads/master/as.json"
ASN_JSON = SCRIPT_DIR / "as.json"
RELIABILITY_WINDOWS = ["2h", "8h", "1d", "1w", "1m"]
SERVICE_FLAGS = [
    ("P2P v2", "p2p_v2", 1 << 11),
    ("Witness", "witness", 1 << 3),
    ("Compact filters", "compact_filters", 1 << 6),
    ("Bloom filters", "bloom", 1 << 2),
]
ACTIVITY_WINDOWS = [
    ("1 hour", 60 * 60),
    ("2 hours", 2 * 60 * 60),
    ("24 hours", 24 * 60 * 60),
    ("7 days", 7 * 24 * 60 * 60),
]


def fetch_seeds(force: bool = False) -> None:
    if not force and SEEDS_GZ.exists():
        print(f"Using cached {SEEDS_GZ.name} (use --force to re-download)")
        return
    print(f"Downloading {SEEDS_URL} ...")
    urllib.request.urlretrieve(SEEDS_URL, SEEDS_GZ)
    print("Done.")


def decompress(force: bool = False) -> None:
    if not force and SEEDS_TXT.exists():
        return
    with gzip.open(SEEDS_GZ, "rb") as f_in, open(SEEDS_TXT, "wb") as f_out:
        f_out.write(f_in.read())


def fetch_asmap(force: bool = False) -> None:
    if not force and ASMAP_DAT.exists():
        print(f"Using cached {ASMAP_DAT.name} (use --force to re-download)")
        return
    print(f"Downloading {ASMAP_URL} ...")
    urllib.request.urlretrieve(ASMAP_URL, ASMAP_DAT)
    print("Done.")


def decode_asmap(force: bool = False) -> None:
    if not force and ASMAP_DECODED.exists():
        print(f"Using cached {ASMAP_DECODED.name} (use --force to re-decode)")
        return
    print(f"Decoding {ASMAP_DAT.name} with {ASMAP_TOOL} ...")
    subprocess.run(
        [sys.executable, str(ASMAP_TOOL), "decode", str(ASMAP_DAT), str(ASMAP_DECODED)],
        check=True,
    )
    print("Done.")


def fetch_asn_json(force: bool = False) -> None:
    if not force and ASN_JSON.exists():
        print(f"Using cached {ASN_JSON.name} (use --force to re-download)")
        return
    print(f"Downloading {ASN_JSON_URL} ...")
    urllib.request.urlretrieve(ASN_JSON_URL, ASN_JSON)
    print("Done.")


def parse_seeds(path: str) -> list[dict]:
    rows = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = re.search(r'"([^"]*)"', line)
            if not m:
                continue
            user_agent = m.group(1) if m else ""
            rest = line[: m.start()].strip()
            parts = rest.split()
            metadata = line[m.end() :].split()
            if len(parts) < 11 or len(metadata) < 2:
                continue
            rows.append(
                {
                    "address": parts[0],
                    "good": int(parts[1]),
                    "last_seen": int(parts[2]),
                    "reliability": {
                        window: float(value.rstrip("%")) / 100
                        for window, value in zip(RELIABILITY_WINDOWS, parts[3:8])
                    },
                    "blocks": int(parts[8]),
                    "services": int(parts[9], 16),
                    "protocol_version": int(parts[10]),
                    "user_agent": user_agent,
                    "last_tried": int(metadata[0]),
                    "try_count": int(metadata[1]),
                }
            )
    return rows


def extract_host(addr: str) -> str | None:
    if ".onion:" in addr or ".b32.i2p:" in addr:
        return None
    if addr.startswith("["):
        return addr.split("]")[0][1:]
    return addr.split(":")[0]


def extract_prefix(addr: str) -> str | None:
    host = extract_host(addr)
    if host is None:
        return None
    if ":" in host:
        try:
            return str(ipaddress.ip_network(host + "/48", strict=False))
        except ValueError:
            return None
    try:
        return str(ipaddress.ip_network(host + "/24", strict=False))
    except ValueError:
        return None


def classify_network(addr: str) -> str:
    if ".onion:" in addr:
        return "tor"
    if ".b32.i2p:" in addr:
        return "i2p"
    if addr.startswith("["):
        return "ipv6"
    return "ipv4"


def classify_agent(ua: str) -> str:
    if any(part.startswith("Satoshi:") for part in ua.strip("/").split("/")):
        return "core"
    return "other"


def load_asmap(path: Path) -> dict:
    tables = {4: {}, 6: {}}
    masks = {4: {}, 6: {}}
    counts = Counter()

    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            prefix, asn = line.split()
            network = ipaddress.ip_network(prefix, strict=False)
            version_tables = tables[network.version]
            if network.prefixlen not in version_tables:
                version_tables[network.prefixlen] = {}
                max_bits = network.max_prefixlen
                if network.prefixlen == 0:
                    masks[network.version][network.prefixlen] = 0
                else:
                    masks[network.version][network.prefixlen] = (
                        (1 << max_bits) - 1
                    ) ^ ((1 << (max_bits - network.prefixlen)) - 1)
            version_tables[network.prefixlen][int(network.network_address)] = asn
            counts[network.version] += 1

    lengths = {
        version: sorted(version_tables, reverse=True)
        for version, version_tables in tables.items()
    }
    print(
        f"\nLoaded ASN map: {counts[4]:,} IPv4 prefixes, {counts[6]:,} IPv6 prefixes from {path}"
    )
    return {"tables": tables, "lengths": lengths, "masks": masks, "path": path}


def load_asn_metadata(path: Path) -> dict[str, dict]:
    metadata = {}
    with open(path) as f:
        for row in json.load(f):
            asn = row.get("asn")
            if asn is None:
                continue
            row_metadata = row.get("metadata") or {}
            description = row_metadata.get("description")
            handle = row_metadata.get("handle")
            category = row_metadata.get("category")
            country = row_metadata.get("country")
            network_role = row_metadata.get("networkRole")
            metadata[f"AS{asn}"] = {
                "name": description or handle or f"AS{asn}",
                "category": category,
                "country": country,
                "network_role": network_role,
            }

    print(f"Loaded ASN metadata: {len(metadata):,} entries from {path}")
    return metadata


def lookup_asn(addr: str, asmap: dict) -> str | None:
    host = extract_host(addr)
    if host is None:
        return None

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return None

    return lookup_asn_for_ip(ip, asmap)


def lookup_asn_for_ip(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address, asmap: dict
) -> str | None:
    version = ip.version
    ip_int = int(ip)
    for prefixlen in asmap["lengths"][version]:
        network_int = ip_int & asmap["masks"][version][prefixlen]
        asn = asmap["tables"][version][prefixlen].get(network_int)
        if asn is not None:
            return asn
    return None


def lookup_asn_for_prefix(prefix: str, asmap: dict) -> str | None:
    try:
        network = ipaddress.ip_network(prefix, strict=False)
    except ValueError:
        return None
    return lookup_asn_for_ip(network.network_address, asmap)


def build_data(rows: list[dict], asmap: dict, asn_metadata: dict[str, dict]) -> dict:
    classes = ["core", "other"]
    labels = ["Bitcoin Core", "Other"]

    def asn_info(asn: str | None) -> dict:
        if asn is None:
            return {
                "name": None,
                "category": None,
                "country": None,
                "network_role": None,
                "tooltip": "ASN unknown",
            }
        metadata = asn_metadata.get(asn, {})
        name = metadata.get("name") or asn
        category = metadata.get("category")
        country = metadata.get("country")
        network_role = metadata.get("network_role")
        parts = [f"{asn} - {name}"]
        if category:
            parts.append(f"Category: {category}")
        if country:
            parts.append(f"Country: {country}")
        if network_role:
            parts.append(f"Network role: {network_role}")
        return {
            "name": name,
            "category": category,
            "country": country,
            "network_role": network_role,
            "tooltip": "\n".join(parts),
        }

    def percentage(part: int, whole: int) -> float:
        return round(part / whole * 100, 1) if whole else 0.0

    def activity_stats(timestamp_key: str) -> dict:
        reference_time = max((r[timestamp_key] for r in rows), default=0)
        counts = [
            sum(
                0 < r[timestamp_key] and reference_time - r[timestamp_key] <= age
                for r in rows
            )
            for _, age in ACTIVITY_WINDOWS
        ]
        return {
            "reference_time": reference_time,
            "labels": [label for label, _ in ACTIVITY_WINDOWS],
            "counts": counts,
            "overall": sum(r[timestamp_key] > 0 for r in rows),
        }

    contacted_rows = [r for r in rows if r["last_seen"] > 0]
    good_rows = [r for r in rows if r["good"]]
    no_handshake = len(rows) - len(contacted_rows)

    contacted_by_class = Counter(classify_agent(r["user_agent"]) for r in contacted_rows)
    good_by_class = Counter(classify_agent(r["user_agent"]) for r in good_rows)
    contacted_vals = [contacted_by_class[c] for c in classes]
    good_vals = [good_by_class[c] for c in classes]
    good_rates = [
        percentage(good_by_class[c], contacted_by_class[c]) for c in classes
    ]

    print(
        f"\nAttempted addresses: {len(rows):,} "
        f"({no_handshake:,} without a successful handshake)"
    )
    print(f"Contacted: {len(contacted_rows):,}, Good: {len(good_rows):,}")

    ua_counter = Counter()
    for r in good_rows:
        parts = r["user_agent"].strip("/").split("/")
        simplified = "/".join(p.split("(")[0].strip() for p in parts if p)
        ua_counter[simplified or "(empty)"] += 1
    top_agents = ua_counter.most_common(20)

    networks = ["ipv4", "ipv6", "tor", "i2p"]
    net_labels = ["IPv4", "IPv6", "Tor", "I2P"]
    attempted_by_net = Counter(classify_network(r["address"]) for r in rows)
    contacted_by_net = Counter(
        classify_network(r["address"]) for r in contacted_rows
    )
    good_by_net = Counter(classify_network(r["address"]) for r in good_rows)
    net_attempted_vals = [attempted_by_net[n] for n in networks]
    net_contacted_vals = [contacted_by_net[n] for n in networks]
    net_good_vals = [good_by_net[n] for n in networks]

    reference_time = max((r["last_seen"] for r in contacted_rows), default=0)
    freshness_labels = ["≤ 2 hours", "2–8 hours", "8–24 hours", "1–7 days", "> 7 days"]
    freshness_counts = [0] * len(freshness_labels)
    for r in contacted_rows:
        age = max(0, reference_time - r["last_seen"])
        if age <= 2 * 60 * 60:
            bucket = 0
        elif age <= 8 * 60 * 60:
            bucket = 1
        elif age <= 24 * 60 * 60:
            bucket = 2
        elif age <= 7 * 24 * 60 * 60:
            bucket = 3
        else:
            bucket = 4
        freshness_counts[bucket] += 1

    reliability_items = []
    reliability_labels = {
        "2h": "2 hours",
        "8h": "8 hours",
        "1d": "1 day",
        "1w": "1 week",
        "1m": "1 month",
    }
    for window in RELIABILITY_WINDOWS:
        values = [r["reliability"][window] for r in contacted_rows]
        reliable = sum(value >= 0.9 for value in values)
        reliability_items.append(
            {
                "label": reliability_labels[window],
                "key": window,
                "median": round(median(values) * 100, 1) if values else 0.0,
                "high_availability_pct": percentage(reliable, len(values)),
            }
        )

    recent_rows = [
        r
        for r in contacted_rows
        if r["blocks"] > 0 and reference_time - r["last_seen"] <= 24 * 60 * 60
    ]
    heights_by_hour = {}
    for r in recent_rows:
        heights_by_hour.setdefault(r["last_seen"] // (60 * 60), []).append(r["blocks"])
    reference_by_hour = {}
    for hour, heights in heights_by_hour.items():
        heights.sort()
        if len(heights) < 20:
            reference_by_hour[hour] = max(heights)
        else:
            reference_by_hour[hour] = heights[int((len(heights) - 1) * 0.95)]
    latest_hour = max(reference_by_hour, default=0)
    reference_height = reference_by_hour.get(latest_hour, 0)
    chain_labels = [
        "Within 2 blocks",
        "3–6 blocks behind",
        "7–144 blocks behind",
        "> 144 blocks behind",
        "> 2 blocks ahead",
    ]
    chain_counts = [0] * len(chain_labels)
    for r in recent_rows:
        lag = reference_by_hour[r["last_seen"] // (60 * 60)] - r["blocks"]
        if lag < -2:
            bucket = 4
        elif lag <= 2:
            bucket = 0
        elif lag <= 6:
            bucket = 1
        elif lag <= 144:
            bucket = 2
        else:
            bucket = 3
        chain_counts[bucket] += 1

    service_items = []
    for label, key, flag in SERVICE_FLAGS:
        count = sum(bool(r["services"] & flag) for r in good_rows)
        service_items.append(
            {
                "label": label,
                "key": key,
                "count": count,
                "pct": percentage(count, len(good_rows)),
            }
        )

    prefix_by_class = {}
    prefix_fingerprints = {}
    for r in good_rows:
        prefix = extract_prefix(r["address"])
        if prefix is None:
            continue
        prefix_by_class.setdefault(prefix, Counter())[classify_agent(r["user_agent"])] += 1
        fingerprint = (
            r["user_agent"],
            r["services"],
            r["protocol_version"],
        )
        prefix_fingerprints.setdefault(prefix, Counter())[fingerprint] += 1
    prefix_totals = {
        prefix: sum(counts.values()) for prefix, counts in prefix_by_class.items()
    }
    top_prefixes = sorted(prefix_totals, key=prefix_totals.get, reverse=True)[:20]

    prefix_table = []
    for prefix in top_prefixes:
        asn = lookup_asn_for_prefix(prefix, asmap)
        info = asn_info(asn)
        fingerprints = prefix_fingerprints[prefix]
        prefix_table.append(
            {
                "prefix": prefix,
                "asn": asn,
                "asn_name": info["name"],
                "asn_category": info["category"],
                "asn_tooltip": info["tooltip"],
                "total": prefix_totals[prefix],
                "core": prefix_by_class[prefix].get("core", 0),
                "other": prefix_by_class[prefix].get("other", 0),
                "distinct_fingerprints": len(fingerprints),
                "dominant_fingerprint_share": percentage(
                    max(fingerprints.values()), prefix_totals[prefix]
                ),
            }
        )

    asn_by_class = {}
    asn_prefixes = {}
    asn_fingerprints = {}
    for r in good_rows:
        asn = lookup_asn(r["address"], asmap)
        prefix = extract_prefix(r["address"])
        if asn is None or prefix is None:
            continue
        asn_by_class.setdefault(asn, Counter())[classify_agent(r["user_agent"])] += 1
        asn_prefixes.setdefault(asn, Counter())[prefix] += 1
        fingerprint = (
            r["user_agent"],
            r["services"],
            r["protocol_version"],
        )
        asn_fingerprints.setdefault(asn, Counter())[fingerprint] += 1
    asn_totals = {
        asn: sum(counts.values()) for asn, counts in asn_by_class.items()
    }
    top_asns = sorted(asn_totals, key=asn_totals.get, reverse=True)[:20]

    asn_table = []
    for asn in top_asns:
        info = asn_info(asn)
        prefix_counts = asn_prefixes[asn]
        fingerprints = asn_fingerprints[asn]
        asn_table.append(
            {
                "asn": asn,
                "name": info["name"],
                "category": info["category"],
                "tooltip": info["tooltip"],
                "total": asn_totals[asn],
                "core": asn_by_class[asn].get("core", 0),
                "other": asn_by_class[asn].get("other", 0),
                "distinct_prefixes": len(prefix_counts),
                "largest_prefix_share": percentage(
                    max(prefix_counts.values()), asn_totals[asn]
                ),
                "distinct_fingerprints": len(fingerprints),
                "dominant_fingerprint_share": percentage(
                    max(fingerprints.values()), asn_totals[asn]
                ),
            }
        )

    category_labels = {
        "business": "Business",
        "education_research": "Education/research",
        "government_admin": "Government/admin",
        "hosting": "Hosting",
        "isp": "ISP",
        "unknown": "Unknown",
    }
    asn_by_category = Counter()
    for asn, total in asn_totals.items():
        asn_by_category[asn_info(asn)["category"] or "unknown"] += total
    asn_category_items = sorted(
        asn_by_category.items(), key=lambda item: item[1], reverse=True
    )

    mapped_good = sum(asn_totals.values())
    hosting_good = asn_by_category.get("hosting", 0)
    top_five_good = sum(sorted(asn_totals.values(), reverse=True)[:5])

    custom_ua = Counter()
    for r in contacted_rows:
        if r["user_agent"] and classify_agent(r["user_agent"]) == "other":
            custom_ua[r["user_agent"]] += 1
    custom_filtered = [
        {"ua": ua, "count": count}
        for ua, count in custom_ua.most_common()
        if count > 1
    ]

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "attempted": len(rows),
            "contacted": len(contacted_rows),
            "good": len(good_rows),
            "no_handshake": no_handshake,
        },
        "classification": {
            "labels": labels,
            "keys": classes,
            "contacted": contacted_vals,
            "good": good_vals,
            "good_rates": good_rates,
        },
        "top_user_agents": {
            "labels": [agent for agent, _ in top_agents],
            "counts": [count for _, count in top_agents],
        },
        "networks": {
            "labels": net_labels,
            "keys": networks,
            "attempted": net_attempted_vals,
            "contacted": net_contacted_vals,
            "good": net_good_vals,
            "contact_rates": [
                percentage(contacted_by_net[n], attempted_by_net[n]) for n in networks
            ],
            "good_rates": [
                percentage(good_by_net[n], contacted_by_net[n]) for n in networks
            ],
        },
        "freshness": {
            "reference_time": reference_time,
            "scope_count": len(contacted_rows),
            "labels": freshness_labels,
            "counts": freshness_counts,
        },
        "activity": {
            "attempts": activity_stats("last_tried"),
            "handshakes": activity_stats("last_seen"),
        },
        "reliability": {
            "scope_count": len(contacted_rows),
            "items": reliability_items,
        },
        "chain_health": {
            "reference_height": reference_height,
            "scope_count": len(recent_rows),
            "labels": chain_labels,
            "counts": chain_counts,
        },
        "service_flags": {
            "scope_count": len(good_rows),
            "items": service_items,
        },
        "infrastructure": {
            "routable_good": sum(prefix_totals.values()),
            "mapped_good": mapped_good,
            "distinct_prefixes": len(prefix_totals),
            "distinct_asns": len(asn_totals),
            "top_five_asn_pct": percentage(top_five_good, mapped_good),
            "hosting_pct": percentage(hosting_good, mapped_good),
        },
        "prefix_table": {
            "rows": prefix_table,
            "stats": {
                "distinct_prefixes": len(prefix_totals),
                "total_good_routable": sum(prefix_totals.values()),
            },
        },
        "asn_categories": {
            "labels": [
                category_labels.get(category, category.replace("_", " ").title())
                for category, _ in asn_category_items
            ],
            "keys": [category for category, _ in asn_category_items],
            "values": [count for _, count in asn_category_items],
        },
        "asn_table": {
            "rows": asn_table,
            "stats": {
                "mapped_asns": len(asn_totals),
                "total_good_routable_mapped": mapped_good,
            },
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
    fetch_asmap(args.force)
    decode_asmap(args.force)
    fetch_asn_json(args.force)

    print("Parsing seeds data...")
    rows = parse_seeds(SEEDS_TXT)
    asmap = load_asmap(ASMAP_DECODED)
    asn_metadata = load_asn_metadata(ASN_JSON)

    data = build_data(rows, asmap, asn_metadata)

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(data, f)
    print(f"\nJSON saved to {args.output} ({os.path.getsize(args.output):,} bytes)")


if __name__ == "__main__":
    main()
