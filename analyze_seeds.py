#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""Analyze bitcoin DNS seeder data and produce JSON for the web dashboard."""

import argparse
import csv
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
ASN_CSV_URL = "https://github.com/quantcdn/asn-info/raw/refs/heads/master/as.csv"
ASN_CSV = SCRIPT_DIR / "as.csv"


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


def fetch_asn_csv(force: bool = False) -> None:
    if not force and ASN_CSV.exists():
        print(f"Using cached {ASN_CSV.name} (use --force to re-download)")
        return
    print(f"Downloading {ASN_CSV_URL} ...")
    urllib.request.urlretrieve(ASN_CSV_URL, ASN_CSV)
    print("Done.")


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


def extract_host(addr: str) -> str | None:
    if ".onion:" in addr:
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


def load_asn_names(path: Path) -> dict[str, str]:
    names = {}
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            asn = row.get("asn")
            description = row.get("description")
            handle = row.get("handle")
            if not asn:
                continue
            names[f"AS{asn}"] = description or handle or f"AS{asn}"

    print(f"Loaded ASN names: {len(names):,} entries from {path}")
    return names


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


def concentration_stats(
    cluster_by_class: dict[str, Counter],
) -> tuple[dict[str, int], float, float, float]:
    cluster_totals = {
        key: sum(counts.values()) for key, counts in cluster_by_class.items()
    }
    counts = list(cluster_totals.values())
    if not counts:
        return cluster_totals, 0.0, 0.0, 0.0
    mean = sum(counts) / len(counts)
    variance = sum((count - mean) ** 2 for count in counts) / len(counts)
    stddev = variance**0.5
    return cluster_totals, mean, stddev, mean + 5 * stddev


def build_data(rows: list[dict], asmap: dict, asn_names: dict[str, str]) -> dict:
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

    print(
        f"\nTotal nodes in DB: {total_known + unknown_known:,} ({unknown_known:,} never contacted)"
    )
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
        net_class_series.append(
            {
                "name": lbl,
                "key": cls,
                "values": [cross_good[n][cls] for n in networks],
            }
        )

    # IP prefix clustering (IPv4 /24, IPv6 /48)
    prefix_by_class = {}
    for r in good_rows:
        prefix = extract_prefix(r["address"])
        if prefix is None:
            continue
        cls = classify_agent(r["user_agent"])
        if prefix not in prefix_by_class:
            prefix_by_class[prefix] = Counter()
        prefix_by_class[prefix][cls] += 1

    prefix_totals, mean, stddev, sybil_threshold = concentration_stats(prefix_by_class)
    sybil_prefixes = sorted(
        p for p, total in prefix_totals.items() if total > sybil_threshold
    )

    def is_sybil(addr: str) -> bool:
        prefix = extract_prefix(addr)
        return prefix is not None and prefix in sybil_prefixes

    sybil_count = sum(1 for r in good_rows if is_sybil(r["address"]))
    sybil_by_cls = Counter()
    for r in good_rows:
        if is_sybil(r["address"]):
            sybil_by_cls[classify_agent(r["user_agent"])] += 1

    print(f"\nSybil: mean={mean:.1f}, σ={stddev:.1f}, threshold={sybil_threshold:.0f}")
    print(f"  Flagged {len(sybil_prefixes)} prefixes, {sybil_count:,} nodes")

    # Sybil breakdown (IPv4 + IPv6, excludes Tor)
    routable_good_by_cls = Counter()
    for counts_by_cls in prefix_by_class.values():
        for cls, n in counts_by_cls.items():
            routable_good_by_cls[cls] += n

    sybil_bars = []
    for cls, lbl in zip(classes, labels):
        organic = routable_good_by_cls.get(cls, 0) - sybil_by_cls.get(cls, 0)
        sybil_n = sybil_by_cls.get(cls, 0)
        sybil_bars.append({"label": lbl, "key": cls, "value": organic})
        if sybil_n > 0:
            sybil_bars.append(
                {"label": f"{lbl} (sybil)", "key": f"{cls}_sybil", "value": sybil_n}
            )

    # Network x Classification with sybil
    net_class_sybil_series = []
    for cls, lbl in zip(classes, labels):
        sybil_in_cls = Counter()
        for r in good_rows:
            if classify_agent(r["user_agent"]) == cls and is_sybil(r["address"]):
                sybil_in_cls[classify_network(r["address"])] += 1
        organic_vals = [
            cross_good[n].get(cls, 0) - sybil_in_cls.get(n, 0) for n in networks
        ]
        sybil_vals_net = [sybil_in_cls.get(n, 0) for n in networks]
        net_class_sybil_series.append(
            {
                "name": lbl,
                "key": cls,
                "values": organic_vals,
            }
        )
        if any(v > 0 for v in sybil_vals_net):
            net_class_sybil_series.append(
                {
                    "name": f"{lbl} (sybil)",
                    "key": f"{cls}_sybil",
                    "values": sybil_vals_net,
                }
            )

    # Top /16 prefixes
    top_prefixes = sorted(prefix_totals, key=prefix_totals.get, reverse=True)[:20]
    top_prefix_owner_items = []
    for prefix in top_prefixes:
        asn = lookup_asn_for_prefix(prefix, asmap)
        top_prefix_owner_items.append(
            {
                "asn": asn,
                "name": asn_names.get(asn, asn) if asn else None,
            }
        )
    top_prefix_series = []
    for cls, lbl in zip(classes, labels):
        top_prefix_series.append(
            {
                "name": lbl,
                "key": cls,
                "values": [prefix_by_class[p].get(cls, 0) for p in top_prefixes],
            }
        )

    # Prefix table
    prefix_table = []
    for idx, p in enumerate(top_prefixes):
        prefix_table.append(
            {
                "prefix": p,
                "asn": top_prefix_owner_items[idx]["asn"],
                "asn_name": top_prefix_owner_items[idx]["name"],
                "total": prefix_totals[p],
                "core": prefix_by_class[p].get("core", 0),
                "knots": prefix_by_class[p].get("knots", 0),
                "bip110": prefix_by_class[p].get("bip110", 0),
                "other": prefix_by_class[p].get("other", 0),
            }
        )

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

    # ASN clustering
    asn_by_class = {}
    for r in good_rows:
        asn = lookup_asn(r["address"], asmap)
        if asn is None:
            continue
        cls = classify_agent(r["user_agent"])
        if asn not in asn_by_class:
            asn_by_class[asn] = Counter()
        asn_by_class[asn][cls] += 1

    asn_totals, asn_mean, asn_stddev, asn_threshold = concentration_stats(asn_by_class)
    sybil_asns = sorted(
        asn for asn, total in asn_totals.items() if total > asn_threshold
    )
    sybil_asn_items = [
        {"asn": asn, "name": asn_names.get(asn, asn)} for asn in sybil_asns
    ]

    asn_sybil_count = 0
    asn_sybil_by_cls = Counter()
    for r in good_rows:
        asn = lookup_asn(r["address"], asmap)
        if asn in sybil_asns:
            asn_sybil_count += 1
            asn_sybil_by_cls[classify_agent(r["user_agent"])] += 1

    print(
        f"\nASN concentration: mean={asn_mean:.1f}, σ={asn_stddev:.1f}, threshold={asn_threshold:.0f}"
    )
    print(f"  Flagged {len(sybil_asns)} ASNs, {asn_sybil_count:,} nodes")

    asn_bars = []
    asn_good_by_cls = Counter()
    for counts_by_cls in asn_by_class.values():
        for cls, n in counts_by_cls.items():
            asn_good_by_cls[cls] += n

    for cls, lbl in zip(classes, labels):
        organic = asn_good_by_cls.get(cls, 0) - asn_sybil_by_cls.get(cls, 0)
        sybil_n = asn_sybil_by_cls.get(cls, 0)
        asn_bars.append({"label": lbl, "key": cls, "value": organic})
        if sybil_n > 0:
            asn_bars.append(
                {
                    "label": f"{lbl} (high concentration AS)",
                    "key": f"{cls}_sybil",
                    "value": sybil_n,
                }
            )

    top_asns = sorted(asn_totals, key=asn_totals.get, reverse=True)[:20]
    top_asn_series = []
    for cls, lbl in zip(classes, labels):
        top_asn_series.append(
            {
                "name": lbl,
                "key": cls,
                "values": [asn_by_class[asn].get(cls, 0) for asn in top_asns],
            }
        )
    top_asn_names = [asn_names.get(asn, asn) for asn in top_asns]

    asn_table = []
    for asn in top_asns:
        asn_table.append(
            {
                "asn": asn,
                "name": asn_names.get(asn, asn),
                "total": asn_totals[asn],
                "core": asn_by_class[asn].get("core", 0),
                "knots": asn_by_class[asn].get("knots", 0),
                "bip110": asn_by_class[asn].get("bip110", 0),
                "other": asn_by_class[asn].get("other", 0),
            }
        )

    asn_sybil_by_class_pct = {}
    for cls in classes:
        total = sum(c.get(cls, 0) for c in asn_by_class.values())
        in_sybil = sum(asn_by_class[asn].get(cls, 0) for asn in sybil_asns)
        asn_sybil_by_class_pct[cls] = {
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
    custom_filtered = [
        {"ua": ua, "count": c} for ua, c in custom_ua.most_common() if c > 1
    ]

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
            "prefixes": sybil_prefixes,
            "count": sybil_count,
            "bars": sybil_bars,
        },
        "asn_sybil": {
            "mean": round(asn_mean, 1),
            "stddev": round(asn_stddev, 1),
            "threshold": round(asn_threshold),
            "asns": sybil_asns,
            "items": sybil_asn_items,
            "count": asn_sybil_count,
            "bars": asn_bars,
        },
        "network_classification_sybil": {
            "net_labels": net_labels,
            "series": net_class_sybil_series,
        },
        "top_prefixes": {
            "labels": top_prefixes,
            "owners": top_prefix_owner_items,
            "series": top_prefix_series,
        },
        "prefix_table": {
            "rows": prefix_table,
            "stats": {
                "distinct_prefixes": len(prefix_by_class),
                "total_good_routable": sum(prefix_totals.values()),
                "sybil_prefix_count": len(sybil_prefixes),
                "sybil_by_class": sybil_by_class_pct,
            },
        },
        "top_asns": {
            "labels": top_asns,
            "names": top_asn_names,
            "series": top_asn_series,
        },
        "asn_table": {
            "rows": asn_table,
            "stats": {
                "mapped_asns": len(asn_by_class),
                "total_good_routable_mapped": sum(asn_totals.values()),
                "sybil_asn_count": len(sybil_asns),
                "sybil_by_class": asn_sybil_by_class_pct,
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
    fetch_asmap(args.force)
    decode_asmap(args.force)
    fetch_asn_csv(args.force)

    print("Parsing seeds data...")
    rows = parse_seeds(SEEDS_TXT)
    asmap = load_asmap(ASMAP_DECODED)
    asn_names = load_asn_names(ASN_CSV)

    data = build_data(rows, asmap, asn_names)

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(data, f)
    print(f"\nJSON saved to {args.output} ({os.path.getsize(args.output):,} bytes)")


if __name__ == "__main__":
    main()
