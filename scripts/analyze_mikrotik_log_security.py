#!/usr/bin/env python3
"""Collect MikroTik warnings/errors and identify external SIP/5060 log sources."""

import argparse
import json
import re
from collections import Counter
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


def extract_source_ips(text: str):
    # RouterOS log lines commonly include src-address:port or src-address->dst-address.
    ip_re = re.compile(r"\b(?!(?:10|127|172\.(?:1[6-9]|2\d|3[0-1])|192\.168)\.)((?:\d{1,3}\.){3}\d{1,3})(?::\d+)?\b")
    candidates = []
    for match in ip_re.finditer(text):
        ip = match.group(1)
        octets = [int(part) for part in ip.split(".")]
        if all(0 <= part <= 255 for part in octets):
            candidates.append(ip)
    return candidates


def main():
    parser = argparse.ArgumentParser(description="Analyze MikroTik logs for errors/warnings and external SIP scans")
    parser.add_argument("--host", required=True, help="MikroTik host from inventory")
    parser.add_argument("--sip-filter", default="5060|t-central|sip|SIP", help="Regex for SIP/5060-related log lines")
    args = parser.parse_args()

    target, defaults = get_target(args.host)
    cmds = [
        "/system clock print",
        '/log print without-paging where topics~"warning|error|critical"',
        f'/log print without-paging where message~"{args.sip_filter}"',
        "/ip firewall nat print stats detail",
        "/ip firewall filter print stats detail",
    ]
    out = run_commands(target, cmds, defaults)

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = Path("reports") / f"log_security_{args.host}_{stamp}".replace(".", "_")
    outdir.mkdir(parents=True, exist_ok=True)

    for idx, cmd in enumerate(cmds, start=1):
        safe = cmd.replace("/", "").replace(" ", "_").replace('"', "")[:120]
        (outdir / f"{idx:02d}_{safe}.txt").write_text(f"$ {cmd}\n\n{out[cmd]}\n", encoding="utf-8")

    warnings = out['/log print without-paging where topics~"warning|error|critical"']
    sip_logs = out[f'/log print without-paging where message~"{args.sip_filter}"']
    external_ips = Counter(extract_source_ips(sip_logs))

    summary = {
        "host": args.host,
        "warning_error_line_count": len([line for line in warnings.splitlines() if line.strip()]),
        "sip_log_line_count": len([line for line in sip_logs.splitlines() if line.strip()]),
        "external_sip_source_ips": external_ips.most_common(),
        "output_dir": str(outdir),
    }
    (outdir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
