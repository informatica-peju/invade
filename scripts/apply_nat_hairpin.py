#!/usr/bin/env python3
"""Apply a MikroTik srcnat hairpin rule with backup and idempotency checks."""

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


def rule_exists(nat_detail: str, internal_ip: str, ports: str, interface_list: str):
    blocks = []
    current = []
    for line in nat_detail.splitlines():
        if line.strip()[:1].isdigit():
            if current:
                blocks.append(" ".join(current))
            current = [line]
        elif current:
            current.append(line)
    if current:
        blocks.append(" ".join(current))

    for block in blocks:
        if " X " in f" {block} ":
            continue
        if (
            "chain=srcnat" in block
            and "action=masquerade" in block
            and f"dst-address={internal_ip}" in block
            and f"in-interface-list={interface_list}" in block
            and f"dst-port={ports}" in block
        ):
            return True
    return False


def main():
    parser = argparse.ArgumentParser(description="Apply a MikroTik hairpin srcnat rule")
    parser.add_argument("--host", required=True, help="MikroTik host from inventory")
    parser.add_argument("--internal-ip", required=True, help="Internal service IP")
    parser.add_argument("--ports", default="80,443", help="TCP destination ports")
    parser.add_argument("--interface-list", default="LAN", help="Internal interface list")
    parser.add_argument("--comment", default="hairpin-esus-todas-lans", help="NAT rule comment")
    args = parser.parse_args()

    target, defaults = get_target(args.host)
    before = run_commands(target, ["/ip firewall nat print detail"], defaults)["/ip firewall nat print detail"]

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = Path("backups") / f"nat_hairpin_apply_{args.host}_{stamp}".replace(".", "_")
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "before_nat_detail.txt").write_text(before + "\n", encoding="utf-8")

    command = (
        f'/ip firewall nat add chain=srcnat action=masquerade protocol=tcp '
        f'dst-address={args.internal_ip} in-interface-list={args.interface_list} '
        f'dst-port={args.ports} comment="{args.comment}"'
    )

    already_exists = rule_exists(before, args.internal_ip, args.ports, args.interface_list)
    applied = False
    if not already_exists:
        run_commands(target, [command], defaults)
        applied = True

    after = run_commands(
        target,
        [
            "/ip firewall nat print detail",
            "/ip firewall nat print stats detail",
        ],
        defaults,
    )
    (outdir / "after_nat_detail.txt").write_text(after["/ip firewall nat print detail"] + "\n", encoding="utf-8")
    (outdir / "after_nat_stats.txt").write_text(after["/ip firewall nat print stats detail"] + "\n", encoding="utf-8")
    (outdir / "applied_command.rsc").write_text(command + "\n", encoding="utf-8")

    summary = {
        "host": args.host,
        "internal_ip": args.internal_ip,
        "ports": args.ports,
        "interface_list": args.interface_list,
        "comment": args.comment,
        "already_exists": already_exists,
        "applied": applied,
        "verified_after": rule_exists(after["/ip firewall nat print detail"], args.internal_ip, args.ports, args.interface_list),
        "output_dir": str(outdir),
    }
    (outdir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
