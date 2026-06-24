#!/usr/bin/env python3
"""Collect filtered MikroTik logs without changing device state."""

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


def main():
    parser = argparse.ArgumentParser(description="Collect filtered MikroTik logs")
    parser.add_argument("--host", required=True, help="MikroTik host from inventory")
    parser.add_argument("--filter", default="doh|dns|certificate|cert|resolve|timeout|error|warning")
    args = parser.parse_args()

    target, defaults = get_target(args.host)
    cmds = [
        "/system clock print",
        "/ip dns print",
        "/log print without-paging",
        f'/log print without-paging where message~"{args.filter}"',
    ]
    out = run_commands(target, cmds, defaults)

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = Path("reports") / f"mikrotik_logs_{args.host}_{stamp}".replace(".", "_")
    outdir.mkdir(parents=True, exist_ok=True)

    for idx, cmd in enumerate(cmds, start=1):
        safe = cmd.replace("/", "").replace(" ", "_").replace('"', "")[:120]
        (outdir / f"{idx:02d}_{safe}.txt").write_text(f"$ {cmd}\n\n{out[cmd]}\n", encoding="utf-8")

    filtered = out[f'/log print without-paging where message~"{args.filter}"']
    lines = [line for line in filtered.splitlines() if line.strip()]
    summary = {
        "host": args.host,
        "filter": args.filter,
        "filtered_line_count": len(lines),
        "output_dir": str(outdir),
    }
    (outdir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
