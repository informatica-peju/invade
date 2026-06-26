#!/usr/bin/env python3
"""Apply a MikroTik WAN SIP/5060 source allowlist with backup and rollback file."""

import argparse
import json
from datetime import datetime
from pathlib import Path

from lib_router import load_inventory, run_commands, runtime_defaults


FORWARD_ALLOW_COMMENT = "invade: allow SIP dstnat from trusted WAN source"
FORWARD_DROP_COMMENT = "invade: drop SIP dstnat from untrusted WAN sources"
INPUT_TCP_ALLOW_COMMENT = "invade: allow router SIP TCP from trusted WAN source"
INPUT_TCP_DROP_COMMENT = "invade: drop router SIP TCP from untrusted WAN sources"
INPUT_UDP_ALLOW_COMMENT = "invade: allow router SIP UDP from trusted WAN source"
INPUT_UDP_DROP_COMMENT = "invade: drop router SIP UDP from untrusted WAN sources"
DEFAULT_WAN_DROP_COMMENT = "defconf: drop all from WAN not DSTNATed"
INPUT_INSERT_COMMENT = "ACEITA-SIP-TCP"
LEGACY_COMMENTS = [
    "invade: allow SIP 5060 from trusted WAN source",
    "invade: drop SIP 5060 from untrusted WAN sources",
]


def get_target(host: str):
    defaults = runtime_defaults()
    inventory = load_inventory(defaults["inventory_file"])
    for target in inventory:
        if target.get("host", "").strip() == host:
            return target, defaults
    raise ValueError(f"Host {host} not found in inventory")


def managed_comments() -> list[str]:
    return [
        *LEGACY_COMMENTS,
        FORWARD_ALLOW_COMMENT,
        FORWARD_DROP_COMMENT,
        INPUT_TCP_ALLOW_COMMENT,
        INPUT_TCP_DROP_COMMENT,
        INPUT_UDP_ALLOW_COMMENT,
        INPUT_UDP_DROP_COMMENT,
    ]


def build_apply_commands(allowed_source: str, forward_port: str, input_ports: str, log_prefix: str) -> list[str]:
    cleanup = [f'/ip firewall filter remove [find comment="{comment}"]' for comment in managed_comments()]
    return [
        *cleanup,
        (
            "/ip firewall filter add "
            "chain=input action=accept connection-state=new "
            f'protocol=tcp in-interface-list=WAN dst-port={input_ports} src-address={allowed_source} '
            f'comment="{INPUT_TCP_ALLOW_COMMENT}" '
            f'place-before=[find comment="{INPUT_INSERT_COMMENT}"]'
        ),
        (
            "/ip firewall filter add "
            "chain=input action=drop connection-state=new "
            f'protocol=tcp in-interface-list=WAN dst-port={input_ports} src-address=!{allowed_source} '
            f'log=yes log-prefix="{log_prefix}-input-tcp" comment="{INPUT_TCP_DROP_COMMENT}" '
            f'place-before=[find comment="{INPUT_INSERT_COMMENT}"]'
        ),
        (
            "/ip firewall filter add "
            "chain=input action=accept connection-state=new "
            f'protocol=udp in-interface-list=WAN dst-port={input_ports} src-address={allowed_source} '
            f'comment="{INPUT_UDP_ALLOW_COMMENT}" '
            f'place-before=[find comment="{INPUT_INSERT_COMMENT}"]'
        ),
        (
            "/ip firewall filter add "
            "chain=input action=drop connection-state=new "
            f'protocol=udp in-interface-list=WAN dst-port={input_ports} src-address=!{allowed_source} '
            f'log=yes log-prefix="{log_prefix}-input-udp" comment="{INPUT_UDP_DROP_COMMENT}" '
            f'place-before=[find comment="{INPUT_INSERT_COMMENT}"]'
        ),
        (
            "/ip firewall filter add "
            "chain=forward action=accept connection-state=new connection-nat-state=dstnat "
            f'protocol=udp in-interface-list=WAN dst-port={forward_port} src-address={allowed_source} '
            f'comment="{FORWARD_ALLOW_COMMENT}" '
            f'place-before=[find comment="{DEFAULT_WAN_DROP_COMMENT}"]'
        ),
        (
            "/ip firewall filter add "
            "chain=forward action=drop connection-state=new connection-nat-state=dstnat "
            f'protocol=udp in-interface-list=WAN dst-port={forward_port} src-address=!{allowed_source} '
            f'log=yes log-prefix="{log_prefix}-forward" comment="{FORWARD_DROP_COMMENT}" '
            f'place-before=[find comment="{DEFAULT_WAN_DROP_COMMENT}"]'
        ),
    ]


def build_rollback_commands() -> list[str]:
    return [f'/ip firewall filter remove [find comment="{comment}"]' for comment in managed_comments()]


def main() -> None:
    parser = argparse.ArgumentParser(description="Restrict MikroTik WAN SIP access to an allowed source CIDR")
    parser.add_argument("--host", required=True, help="MikroTik host from inventory")
    parser.add_argument("--allowed-source", required=True, help="Allowed source CIDR, for example 177.22.80.0/22")
    parser.add_argument("--port", default="5060", help="Forwarded UDP destination port to restrict")
    parser.add_argument("--input-ports", default="5060,5061", help="Router input TCP/UDP ports to restrict")
    parser.add_argument("--log-prefix", default="drop-sip-wan", help="Drop rule log prefix base")
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

    apply_commands = build_apply_commands(args.allowed_source, args.port, args.input_ports, args.log_prefix)
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
        "forward_port": args.port,
        "input_ports": args.input_ports,
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
