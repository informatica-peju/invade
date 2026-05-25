#!/usr/bin/env python3
"""Analyze active PPPoE and OVPN clients on a MikroTik host from inventory."""

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


def parse_ppp_active_records(text: str):
    records = []
    current = []
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line or line.startswith("Flags:"):
            continue
        if line.lstrip().startswith(tuple(str(i) for i in range(10))):
            if current:
                records.append(" ".join(current))
            current = [line.strip()]
        else:
            if current:
                current.append(line.strip())
    if current:
        records.append(" ".join(current))
    return records


def main():
    parser = argparse.ArgumentParser(description="Analyze PPPoE and OVPN clients on MikroTik")
    parser.add_argument("--host", required=True, help="Target host from inventory")
    args = parser.parse_args()

    target, defaults = get_target(args.host)

    cmds = [
        "/system identity print",
        "/interface print detail where type~\"pppoe-in|ovpn-in\"",
        "/ppp active print detail",
        "/ppp secret print detail",
        "/ip pool used print detail",
    ]

    out = run_commands(target, cmds, defaults)

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = Path("reports") / f"access_clients_{args.host}_{stamp}".replace(".", "_")
    outdir.mkdir(parents=True, exist_ok=True)

    for idx, cmd in enumerate(cmds, start=1):
        safe = cmd.replace("/", "").replace(" ", "_").replace('"', "")[:100]
        (outdir / f"{idx:02d}_{safe}.txt").write_text(f"$ {cmd}\n\n{out[cmd]}\n", encoding="utf-8")

    iface_text = out['/interface print detail where type~"pppoe-in|ovpn-in"']
    ppp_active_text = out['/ppp active print detail']

    pppoe_ifaces = [ln for ln in iface_text.splitlines() if "type=pppoe-in" in ln]
    ovpn_ifaces = [ln for ln in iface_text.splitlines() if "type=ovpn-in" in ln]

    ppp_active_records = parse_ppp_active_records(ppp_active_text)
    active_ovpn = [ln for ln in ppp_active_records if "service=ovpn" in ln]
    active_pppoe = [ln for ln in ppp_active_records if "service=pppoe" in ln]

    def extract_name(record: str):
        marker = "name=\""
        if marker in record:
            s = record.split(marker, 1)[1]
            return s.split("\"", 1)[0]
        marker2 = "name="
        if marker2 in record:
            s = record.split(marker2, 1)[1]
            return s.split(" ", 1)[0]
        return ""

    active_pppoe_names = sorted([n for n in (extract_name(r) for r in active_pppoe) if n])
    active_ovpn_names = sorted([n for n in (extract_name(r) for r in active_ovpn) if n])

    summary = {
        "host": args.host,
        "pppoe_interfaces_detected": len(pppoe_ifaces),
        "ovpn_interfaces_detected": len(ovpn_ifaces),
        "ppp_active_total_rows": len(ppp_active_records),
        "ppp_active_pppoe_rows": len(active_pppoe),
        "ppp_active_ovpn_rows": len(active_ovpn),
        "ppp_active_pppoe_names": active_pppoe_names,
        "ppp_active_ovpn_names": active_ovpn_names,
        "output_dir": str(outdir),
    }

    (outdir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
