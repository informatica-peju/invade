#!/usr/bin/env python3
"""Diagnose MikroTik dstnat/hairpin NAT paths for an internal service."""

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


def commands(public_ip: str, internal_ip: str, ports: str):
    nat_filter = f'{public_ip}|{internal_ip}|esus|hairpin'
    return [
        "/system identity print",
        "/ip address print detail",
        "/interface list print detail",
        "/interface list member print detail",
        "/ip firewall nat print detail",
        "/ip firewall nat print stats detail",
        f'/ip firewall nat print detail where dst-address="{public_ip}"',
        f'/ip firewall nat print detail where to-addresses="{internal_ip}"',
        f'/ip firewall nat print detail where comment~"{nat_filter}"',
        "/ip firewall filter print detail",
        "/ip route print detail",
        f"/ping {internal_ip} count=5",
        f"/tool fetch url=http://{public_ip}/ keep-result=no",
        f"/tool fetch url=https://{public_ip}/ keep-result=no check-certificate=no",
    ]


def main():
    parser = argparse.ArgumentParser(description="Diagnose MikroTik hairpin NAT for an internal service")
    parser.add_argument("--host", required=True, help="MikroTik host from inventory")
    parser.add_argument("--public-ip", required=True, help="Public IP used by dstnat")
    parser.add_argument("--internal-ip", required=True, help="Internal service IP")
    parser.add_argument("--ports", default="80,443", help="Service ports, for documentation in output")
    args = parser.parse_args()

    target, defaults = get_target(args.host)
    cmd_list = commands(args.public_ip, args.internal_ip, args.ports)
    out = run_commands(target, cmd_list, defaults)

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = Path("reports") / f"nat_hairpin_{args.host}_{stamp}".replace(".", "_")
    outdir.mkdir(parents=True, exist_ok=True)

    for idx, cmd in enumerate(cmd_list, start=1):
        safe = cmd.replace("/", "").replace(" ", "_").replace('"', "")[:120]
        (outdir / f"{idx:02d}_{safe}.txt").write_text(f"$ {cmd}\n\n{out[cmd]}\n", encoding="utf-8")

    nat_detail = out["/ip firewall nat print detail"]
    summary = {
        "host": args.host,
        "public_ip": args.public_ip,
        "internal_ip": args.internal_ip,
        "ports": args.ports,
        "has_dstnat_to_internal": f"to-addresses={args.internal_ip}" in nat_detail,
        "has_hairpin_to_internal": f"chain=srcnat action=masquerade" in nat_detail
        and f"dst-address={args.internal_ip}" in nat_detail,
        "output_dir": str(outdir),
    }
    (outdir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
