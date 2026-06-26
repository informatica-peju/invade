#!/usr/bin/env python3
"""Apply a MikroTik WAN SIP/5060 source allowlist with backup and rollback file."""

import argparse
import json
from datetime import datetime
from pathlib import Path

from lib_router import load_inventory, run_commands, runtime_defaults


ALLOW_COMMENT = "invade: allow SIP 5060 from trusted WAN source"
DROP_COMMENT = "invade: drop SIP 5060 from untrusted WAN sources"
DEFAULT_WAN_DROP_COMMENT = "defconf: drop all from WAN not DSTNATed"


def get_target(host: str):
    defaults = runtime_defaults()
    inventory = load_inventory(defaults["inventory_file"])
    for target in inventory:
        if target.get("host", "").strip() == host:
            return target, defaults
    raise ValueError(f"Host {host} not found in inventory")


def build_apply_commands(allowed_source: str, port: str, log_prefix: str) -> list[str]:
    return [
        f'/ip firewall filter remove [find comment="{ALLOW_COMMENT}"]',
        f'/ip firewall filter remove [find comment="{DROP_COMMENT}"]',
        (
            "/ip firewall filter add "
            "chain=forward action=accept connection-state=new connection-nat-state=dstnat "
            f'protocol=udp in-interface-list=WAN dst-port={port} src-address={allowed_source} '
            f'comment="{ALLOW_COMMENT}" '
            f'place-before=[find comment="{DEFAULT_WAN_DROP_COMMENT}"]'
        ),
        (
            "/ip firewall filter add "
            "chain=forward action=drop connection-state=new connection-nat-state=dstnat "
            f'protocol=udp in-interface-list=WAN dst-port={port} src-address=!{allowed_source} '
            f'log=yes log-prefix="{log_prefix}" comment="{DROP_COMMENT}" '
            f'place-before=[find comment="{DEFAULT_WAN_DROP_COMMENT}"]'
        ),
    ]


def build_rollback_commands() -> list[str]:
    return [
        f'/ip firewall filter remove [find comment="{ALLOW_COMMENT}"]',
        f'/ip firewall filter remove [find comment="{DROP_COMMENT}"]',
    ]


def main() -> None:
    parser = argparse.ArgumentParser(description="Restrict MikroTik WAN SIP/5060 dstnat to an allowed source CIDR")
    parser.add_argument("--host", required=True, help="MikroTik host from inventory")
    parser.add_argument("--allowed-source", required=True, help="Allowed source CIDR, for example 177.22.80.0/22")
    parser.add_argument("--port", default="5060", help="UDP destination port to restrict")
    parser.add_argument("--log-prefix", default="drop-sip-wan", help="Drop rule log prefix")
    parser.add_argument("--apply", action="store_true", help="Actually apply changes; omit for dry-run")
    args = parser.parse_args()

    target, defaults = get_target(args.host)
    backup_commands = [
        "/system clock print",
        "/ip firewall nat print detail",
        "/ip firewall filter print detail",
        "/ip firewall filter print stats detail",
    ]
    before = run_commands(target, backup_commands, defaults)

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = Path("backups") / f"sip_wan_allowlist_{args.host}_{stamp}".replace(".", "_")
    outdir.mkdir(parents=True, exist_ok=True)
    for idx, command in enumerate(backup_commands, start=1):
        safe = command.replace("/", "").replace(" ", "_").replace('"', "")[:120]
        (outdir / f"{idx:02d}_before_{safe}.txt").write_text(
            f"$ {command}\n\n{before[command]}\n",
            encoding="utf-8",
        )

    apply_commands = build_apply_commands(args.allowed_source, args.port, args.log_prefix)
    rollback_commands = build_rollback_commands()
    (outdir / "apply.rsc").write_text("\n".join(apply_commands) + "\n", encoding="utf-8")
    (outdir / "rollback.rsc").write_text("\n".join(rollback_commands) + "\n", encoding="utf-8")

    apply_results = {}
    after = {}
    if args.apply:
        apply_results = run_commands(target, apply_commands, defaults)
        after = run_commands(target, backup_commands, defaults)
        for idx, command in enumerate(backup_commands, start=1):
            safe = command.replace("/", "").replace(" ", "_").replace('"', "")[:120]
            (outdir / f"{idx:02d}_after_{safe}.txt").write_text(
                f"$ {command}\n\n{after[command]}\n",
                encoding="utf-8",
            )

    summary = {
        "host": args.host,
        "allowed_source": args.allowed_source,
        "port": args.port,
        "applied": args.apply,
        "apply_commands": apply_commands,
        "rollback_commands": rollback_commands,
        "apply_results": apply_results,
        "output_dir": str(outdir),
    }
    (outdir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
