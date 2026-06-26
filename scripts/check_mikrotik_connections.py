#!/usr/bin/env python3
"""Check MikroTik connection tracking for evidence that selected IPs got replies."""

import argparse
import csv
import json
import re
from datetime import datetime
from pathlib import Path

from lib_router import load_inventory, run_commands, runtime_defaults


def get_target(host: str):
    defaults = runtime_defaults()
    inventory = load_inventory(defaults["inventory_file"])
    for target in inventory:
        if target.get("host", "").strip() == host:
            return target, defaults
    raise ValueError(f"Host {host} not found in inventory")


def load_ips(args) -> list[str]:
    ips = []
    if args.ips:
        ips.extend(item.strip() for item in args.ips.split(",") if item.strip())
    if args.ip_csv:
        with Path(args.ip_csv).open(encoding="utf-8") as handle:
            for row in csv.DictReader(handle):
                if row.get("ip"):
                    ips.append(row["ip"].strip())
    return sorted(set(ips))


def parse_connection_blocks(text: str) -> list[dict]:
    records = []
    current = {}
    current_id = None
    token_re = re.compile(r"([A-Za-z0-9_-]+)=([^\\s]+)")

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("$") or line.startswith("[ERRO]"):
            continue
        first = line.split(maxsplit=1)[0]
        if first.isdigit() or first.startswith("*"):
            if current:
                records.append(current)
            current = {}
            current_id = first
            line = line[len(first) :].strip()
            current["id"] = current_id
        for key, value in token_re.findall(line):
            current[key] = value.strip('"')

    if current:
        records.append(current)
    return records


def record_mentions_ip(record: dict, ip: str) -> bool:
    needle = f"{ip}:"
    return any(value == ip or str(value).startswith(needle) for value in record.values())


def has_reply_evidence(record: dict) -> bool:
    if record.get("seen-reply", "").lower() == "yes":
        return True
    if record.get("assured", "").lower() == "yes":
        return True
    for key in ("repl-packets", "reply-packets", "repl-bytes", "reply-bytes"):
        value = record.get(key)
        if value and value.isdigit() and int(value) > 0:
            return True
    return False


def build_commands(ips: list[str], protocol: str) -> list[str]:
    commands = []
    for ip in ips:
        commands.extend(
            [
                f'/ip firewall connection print detail without-paging where protocol={protocol} and src-address~"{ip}"',
                f'/ip firewall connection print detail without-paging where protocol={protocol} and reply-dst-address~"{ip}"',
            ]
        )
    return commands


def main() -> None:
    parser = argparse.ArgumentParser(description="Check active MikroTik conntrack entries for selected IPs")
    parser.add_argument("--host", required=True, help="MikroTik host from inventory")
    parser.add_argument("--ips", default="", help="Comma-separated IP list")
    parser.add_argument("--ip-csv", default="", help="CSV containing an 'ip' column")
    parser.add_argument("--protocol", default="udp", help="Connection protocol to query")
    parser.add_argument("--port", default="5060", help="Destination/source port to highlight")
    args = parser.parse_args()

    ips = load_ips(args)
    target, defaults = get_target(args.host)
    commands = build_commands(ips, args.protocol)
    results = run_commands(target, commands, defaults)
    raw = "\n\n".join(f"$ {cmd}\n{output}" for cmd, output in results.items())
    records = parse_connection_blocks(raw)

    summary_rows = []
    for ip in ips:
        matches = [record for record in records if record_mentions_ip(record, ip)]
        port_matches = [
            record
            for record in matches
            if f":{args.port}" in record.get("src-address", "")
            or f":{args.port}" in record.get("dst-address", "")
            or f":{args.port}" in record.get("reply-src-address", "")
            or f":{args.port}" in record.get("reply-dst-address", "")
        ]
        reply_matches = [record for record in port_matches if has_reply_evidence(record)]
        summary_rows.append(
            {
                "ip": ip,
                "active_matches": len(matches),
                "active_port_matches": len(port_matches),
                "reply_evidence_matches": len(reply_matches),
                "reply_evidence": bool(reply_matches),
                "records": port_matches,
            }
        )

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = Path("reports") / f"conntrack_{args.host}_{stamp}".replace(".", "_")
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "raw_connection_tracking.txt").write_text(raw, encoding="utf-8")
    (outdir / "summary.json").write_text(
        json.dumps(
            {
                "host": args.host,
                "protocol": args.protocol,
                "port": args.port,
                "checked_ips": ips,
                "rows": summary_rows,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    print(json.dumps({"output_dir": str(outdir), "rows": summary_rows}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
