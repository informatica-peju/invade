#!/usr/bin/env python3
"""Apply conservative MikroTik SIP NAT hardening with backup."""

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


def sip_helper_enabled(service_port_detail: str):
    for line in service_port_detail.splitlines():
        if 'name="sip"' in line:
            return " X " not in f" {line} "
    return False


def main():
    parser = argparse.ArgumentParser(description="Disable MikroTik SIP helper after backing up service-port state")
    parser.add_argument("--host", required=True, help="MikroTik host from inventory")
    args = parser.parse_args()

    target, defaults = get_target(args.host)
    before = run_commands(target, ["/ip firewall service-port print detail"], defaults)[
        "/ip firewall service-port print detail"
    ]

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = Path("backups") / f"sip_nat_hardening_{args.host}_{stamp}".replace(".", "_")
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "before_service_port_detail.txt").write_text(before + "\n", encoding="utf-8")

    was_enabled = sip_helper_enabled(before)
    applied = False
    if was_enabled:
        run_commands(target, ["/ip firewall service-port set sip disabled=yes"], defaults)
        applied = True

    after = run_commands(target, ["/ip firewall service-port print detail"], defaults)[
        "/ip firewall service-port print detail"
    ]
    (outdir / "after_service_port_detail.txt").write_text(after + "\n", encoding="utf-8")
    (outdir / "applied_command.rsc").write_text("/ip firewall service-port set sip disabled=yes\n", encoding="utf-8")

    summary = {
        "host": args.host,
        "sip_helper_was_enabled": was_enabled,
        "applied": applied,
        "sip_helper_enabled_after": sip_helper_enabled(after),
        "output_dir": str(outdir),
    }
    (outdir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
