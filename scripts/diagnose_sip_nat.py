#!/usr/bin/env python3
"""Diagnose MikroTik SIP/5060 NAT and firewall configuration."""

import argparse
import json
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


def build_commands():
    return [
        "/system identity print",
        "/ip address print detail",
        "/interface list print detail",
        "/interface list member print detail",
        "/ip firewall nat print detail",
        "/ip firewall nat print stats detail",
        "/ip firewall nat print detail where dst-port=5060",
        "/ip firewall filter print detail",
        "/ip firewall filter print stats detail",
        "/ip firewall mangle print detail",
        "/ip firewall service-port print detail",
        "/ip firewall connection print count-only",
    ]


def has_enabled_5060_dstnat(nat_detail: str):
    blocks = []
    current = []
    for line in nat_detail.splitlines():
        if line.strip()[:1].isdigit():
            if current:
                blocks.append(" ".join(current))
            current = [line.strip()]
        elif current:
            current.append(line.strip())
    if current:
        blocks.append(" ".join(current))

    matches = []
    for block in blocks:
        if " X " in f" {block} ":
            continue
        if "chain=dstnat" in block and "dst-port=5060" in block:
            matches.append(block)
    return matches


def main():
    parser = argparse.ArgumentParser(description="Diagnose SIP/5060 NAT rules on MikroTik")
    parser.add_argument("--host", required=True, help="MikroTik host from inventory")
    args = parser.parse_args()

    target, defaults = get_target(args.host)
    cmds = build_commands()
    out = run_commands(target, cmds, defaults)

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = Path("reports") / f"sip_nat_{args.host}_{stamp}".replace(".", "_")
    outdir.mkdir(parents=True, exist_ok=True)

    for idx, cmd in enumerate(cmds, start=1):
        safe = cmd.replace("/", "").replace(" ", "_").replace('"', "")[:120]
        (outdir / f"{idx:02d}_{safe}.txt").write_text(f"$ {cmd}\n\n{out[cmd]}\n", encoding="utf-8")

    nat_detail = out["/ip firewall nat print detail"]
    enabled_dstnat_5060 = has_enabled_5060_dstnat(nat_detail)
    service_ports = out["/ip firewall service-port print detail"]

    summary = {
        "host": args.host,
        "enabled_dstnat_5060_count": len(enabled_dstnat_5060),
        "enabled_dstnat_5060_rules": enabled_dstnat_5060,
        "sip_service_port_mentions": [line.strip() for line in service_ports.splitlines() if "sip" in line.lower()],
        "output_dir": str(outdir),
    }
    (outdir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
