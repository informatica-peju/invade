#!/usr/bin/env python3
"""Extract public source IPs from MikroTik logs and enrich them with geo/ASN data."""

import argparse
import csv
import ipaddress
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path


CONNECTION_RE = re.compile(
    r"\b(?P<src>(?:\d{1,3}\.){3}\d{1,3}):(?P<src_port>\d+)"
    r"->(?P<dst>(?:\d{1,3}\.){3}\d{1,3}):(?P<dst_port>\d+)\b"
)


def is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip.version == 4 and ip.is_global


def parse_csv_list(value: str) -> set[str]:
    return {item.strip() for item in value.split(",") if item.strip()}


def extract_flows(text: str, dst_ports: set[str], dst_ips: set[str]) -> list[dict]:
    flows = []
    for match in CONNECTION_RE.finditer(text):
        flow = match.groupdict()
        if dst_ports and flow["dst_port"] not in dst_ports:
            continue
        if dst_ips and flow["dst"] not in dst_ips:
            continue
        if not is_public_ip(flow["src"]):
            continue
        flows.append(flow)
    return flows


def fetch_ipwhois(ip: str, timeout: int) -> dict:
    fields = ",".join(
        [
            "success",
            "message",
            "ip",
            "type",
            "continent",
            "country",
            "region",
            "city",
            "latitude",
            "longitude",
            "connection",
            "security",
        ]
    )
    url = f"https://ipwho.is/{urllib.parse.quote(ip)}?fields={fields}"
    req = urllib.request.Request(url, headers={"User-Agent": "invade-network-diagnostics/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        return {"success": False, "ip": ip, "message": str(exc)}


def summarize(flows: list[dict], timeout: int, sleep_seconds: float, no_geo: bool) -> list[dict]:
    source_counts = Counter(flow["src"] for flow in flows)
    by_destination: dict[str, Counter] = defaultdict(Counter)
    for flow in flows:
        by_destination[flow["src"]][f'{flow["dst"]}:{flow["dst_port"]}'] += 1

    rows = []
    for ip, count in source_counts.most_common():
        geo = {} if no_geo else fetch_ipwhois(ip, timeout)
        if not no_geo and sleep_seconds > 0:
            time.sleep(sleep_seconds)

        connection = geo.get("connection") or {}
        security = geo.get("security") or {}
        rows.append(
            {
                "ip": ip,
                "hits": count,
                "destinations": dict(by_destination[ip].most_common()),
                "country": geo.get("country", ""),
                "region": geo.get("region", ""),
                "city": geo.get("city", ""),
                "asn": connection.get("asn", ""),
                "org": connection.get("org", ""),
                "isp": connection.get("isp", ""),
                "vpn": security.get("vpn", ""),
                "proxy": security.get("proxy", ""),
                "tor": security.get("tor", ""),
                "hosting": security.get("hosting", ""),
                "geo_status": "skipped" if no_geo else ("ok" if geo.get("success") else geo.get("message", "failed")),
            }
        )
    return rows


def write_csv(path: Path, rows: list[dict]) -> None:
    fieldnames = [
        "ip",
        "hits",
        "country",
        "region",
        "city",
        "asn",
        "org",
        "isp",
        "vpn",
        "proxy",
        "tor",
        "hosting",
        "geo_status",
        "destinations",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            csv_row = row.copy()
            csv_row["destinations"] = json.dumps(row["destinations"], sort_keys=True)
            writer.writerow(csv_row)


def main() -> None:
    parser = argparse.ArgumentParser(description="Geolocate public source IPs found in MikroTik log files")
    parser.add_argument("--log-file", required=True, help="Path to a saved MikroTik log text file")
    parser.add_argument("--dst-port", default="5060", help="Comma-separated destination ports to include")
    parser.add_argument("--dst-ip", default="", help="Optional comma-separated destination public IPs to include")
    parser.add_argument("--output-dir", default="", help="Optional output directory under reports/")
    parser.add_argument("--timeout", type=int, default=8, help="HTTP timeout for geolocation lookups")
    parser.add_argument("--sleep", type=float, default=0.2, help="Delay between geolocation lookups")
    parser.add_argument("--no-geo", action="store_true", help="Only extract/count IPs; skip external geolocation")
    args = parser.parse_args()

    log_path = Path(args.log_file)
    text = log_path.read_text(encoding="utf-8", errors="replace")
    dst_ports = parse_csv_list(args.dst_port)
    dst_ips = parse_csv_list(args.dst_ip)
    flows = extract_flows(text, dst_ports, dst_ips)
    rows = summarize(flows, args.timeout, args.sleep, args.no_geo)

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = Path(args.output_dir) if args.output_dir else Path("reports") / f"ip_geolocation_{stamp}"
    outdir.mkdir(parents=True, exist_ok=True)

    summary = {
        "source_log_file": str(log_path),
        "dst_ports": sorted(dst_ports),
        "dst_ips": sorted(dst_ips),
        "total_matching_flows": len(flows),
        "unique_public_sources": len(rows),
        "geolocation_provider": "ipwho.is",
        "rows": rows,
    }
    (outdir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    write_csv(outdir / "summary.csv", rows)

    print(json.dumps({"output_dir": str(outdir), **summary}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
