#!/usr/bin/env python3
"""Collect MikroTik warnings/errors and summarize firewall/security log events."""

import argparse
import json
import re
from collections import Counter, defaultdict
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


FLOW_RE = re.compile(
    r"(?P<prefix>[\w-]+)?\s*(?P<action>dstnat|srcnat|drop|forward|input)?:?.*?"
    r"connection-state:(?P<state>[\w,-]+).*?"
    r"proto (?P<proto>\w+), (?P<src>(?:\d{1,3}\.){3}\d{1,3}):(?P<src_port>\d+)"
    r"->(?P<dst>(?:\d{1,3}\.){3}\d{1,3}):(?P<dst_port>\d+)",
    re.IGNORECASE,
)


def parse_firewall_events(text: str):
    events = []
    for line in text.splitlines():
        if "firewall" not in line:
            continue
        match = FLOW_RE.search(line)
        if not match:
            continue
        event = match.groupdict()
        event["line"] = line.strip()
        events.append(event)
    return events


def summarize_firewall_events(events):
    by_source = Counter(event["src"] for event in events)
    by_destination = Counter(f'{event["dst"]}:{event["dst_port"]}' for event in events)
    by_action = Counter((event.get("action") or "unknown").lower() for event in events)
    by_state = Counter(event["state"] for event in events)
    by_prefix = Counter((event.get("prefix") or "unknown").strip() for event in events)

    inbound_5060 = Counter()
    internal_to_external = defaultdict(Counter)
    for event in events:
        if event["dst_port"] == "5060" and event["dst"].startswith("186.232.145."):
            inbound_5060[event["src"]] += 1
        if event["src"].startswith("192.168.199.") or event["src"].startswith("10."):
            internal_to_external[event["dst"]][event["src"]] += 1

    correlated = []
    for external_ip, count in inbound_5060.items():
        if external_ip in internal_to_external:
            correlated.append(
                {
                    "external_ip": external_ip,
                    "inbound_5060_hits": count,
                    "internal_sources": dict(internal_to_external[external_ip]),
                }
            )

    return {
        "top_sources": by_source.most_common(25),
        "top_destinations": by_destination.most_common(25),
        "by_action": by_action.most_common(),
        "by_state": by_state.most_common(),
        "by_prefix": by_prefix.most_common(25),
        "inbound_5060_sources": inbound_5060.most_common(25),
        "external_ips_with_internal_traffic": correlated,
    }


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
        '/log print without-paging where message~"drop-sip-wan|drop|denied|invalid|5060"',
        "/ip firewall nat print stats detail",
        "/ip firewall filter print stats detail",
        "/ip firewall filter print detail",
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
    security_logs = out['/log print without-paging where message~"drop-sip-wan|drop|denied|invalid|5060"']
    firewall_events = parse_firewall_events("\n".join([sip_logs, security_logs]))
    external_ips = Counter(extract_source_ips(sip_logs))

    summary = {
        "host": args.host,
        "warning_error_line_count": len([line for line in warnings.splitlines() if line.strip()]),
        "sip_log_line_count": len([line for line in sip_logs.splitlines() if line.strip()]),
        "security_log_line_count": len([line for line in security_logs.splitlines() if line.strip()]),
        "external_sip_source_ips": external_ips.most_common(),
        "firewall_event_summary": summarize_firewall_events(firewall_events),
        "output_dir": str(outdir),
    }
    (outdir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
