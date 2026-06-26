#!/usr/bin/env python3
"""Apply managed MikroTik WAN security logging rules with backup and rollback."""

import argparse
import json
from datetime import datetime
from pathlib import Path

from lib_router import load_inventory, run_commands, runtime_defaults


COMMENTS = {
    "input_invalid": "invade: log/drop invalid input from WAN",
    "forward_invalid": "invade: log/drop invalid forward from WAN",
    "input_tcp_probe": "invade: log/drop WAN TCP probes to router",
    "input_udp_probe": "invade: log/drop WAN UDP probes to router",
    "input_other": "invade: log/drop other WAN input to router",
    "forward_not_dstnat": "invade: log/drop WAN forward not dstnat",
}


def get_target(host: str):
    defaults = runtime_defaults()
    inventory = load_inventory(defaults["inventory_file"])
    for target in inventory:
        if target.get("host", "").strip() == host:
            return target, defaults
    raise ValueError(f"Host {host} not found in inventory")


def cleanup_commands() -> list[str]:
    return [f'/ip firewall filter remove [find comment="{comment}"]' for comment in COMMENTS.values()]


def build_apply_commands(tcp_ports: str, udp_ports: str) -> list[str]:
    return [
        *cleanup_commands(),
        (
            '/ip firewall filter add chain=input action=drop connection-state=invalid '
            'in-interface-list=WAN log=yes log-prefix="drop-wan-invalid-in" '
            f'comment="{COMMENTS["input_invalid"]}" '
            'place-before=[find chain=input comment="defconf: drop invalid"]'
        ),
        (
            '/ip firewall filter add chain=forward action=drop connection-state=invalid '
            'in-interface-list=WAN log=yes log-prefix="drop-wan-invalid-fwd" '
            f'comment="{COMMENTS["forward_invalid"]}" '
            'place-before=[find chain=forward comment="defconf: drop invalid"]'
        ),
        (
            '/ip firewall filter add chain=input action=drop connection-state=new protocol=tcp '
            f'in-interface-list=WAN dst-port={tcp_ports} log=yes log-prefix="drop-wan-tcp-probe" '
            f'comment="{COMMENTS["input_tcp_probe"]}" '
            'place-before=[find chain=input comment="defconf: drop all not coming from LAN"]'
        ),
        (
            '/ip firewall filter add chain=input action=drop connection-state=new protocol=udp '
            f'in-interface-list=WAN dst-port={udp_ports} log=yes log-prefix="drop-wan-udp-probe" '
            f'comment="{COMMENTS["input_udp_probe"]}" '
            'place-before=[find chain=input comment="defconf: drop all not coming from LAN"]'
        ),
        (
            '/ip firewall filter add chain=input action=drop connection-state=new '
            'in-interface-list=WAN log=yes log-prefix="drop-wan-input-other" '
            f'comment="{COMMENTS["input_other"]}" '
            'place-before=[find chain=input comment="defconf: drop all not coming from LAN"]'
        ),
        (
            '/ip firewall filter add chain=forward action=drop connection-state=new '
            'connection-nat-state=!dstnat in-interface-list=WAN log=yes '
            'log-prefix="drop-wan-fwd-notdstnat" '
            f'comment="{COMMENTS["forward_not_dstnat"]}" '
            'place-before=[find chain=forward comment="defconf: drop all from WAN not DSTNATed"]'
        ),
    ]


def backup_commands() -> list[str]:
    return [
        "/system clock print",
        "/ip firewall filter print detail",
        "/ip firewall filter print stats detail",
        "/ip firewall nat print detail",
        "/log print without-paging where message~\"drop-wan|drop-sip-wan|invalid|denied\"",
    ]


def write_outputs(outdir: Path, prefix: str, results: dict[str, str]) -> None:
    for idx, (command, output) in enumerate(results.items(), start=1):
        safe = command.replace("/", "").replace(" ", "_").replace('"', "")[:120]
        (outdir / f"{idx:02d}_{prefix}_{safe}.txt").write_text(
            f"$ {command}\n\n{output}\n",
            encoding="utf-8",
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Add managed logging drops for WAN security visibility")
    parser.add_argument("--host", required=True, help="MikroTik host from inventory")
    parser.add_argument(
        "--tcp-ports",
        default="22,23,53,80,443,445,3389,5900,7547,8080,8291,8728,8729",
        help="WAN TCP ports to classify as router probes",
    )
    parser.add_argument(
        "--udp-ports",
        default="53,123,137,138,161,1900,5060,5061,5353,11211",
        help="WAN UDP ports to classify as router probes",
    )
    parser.add_argument("--apply", action="store_true", help="Actually apply changes; omit for dry-run")
    args = parser.parse_args()

    target, defaults = get_target(args.host)
    commands = backup_commands()
    before = run_commands(target, commands, defaults)

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = Path("backups") / f"wan_security_logging_{args.host}_{stamp}".replace(".", "_")
    outdir.mkdir(parents=True, exist_ok=True)
    write_outputs(outdir, "before", before)

    apply_commands = build_apply_commands(args.tcp_ports, args.udp_ports)
    rollback_commands = cleanup_commands()
    (outdir / "apply.rsc").write_text("\n".join(apply_commands) + "\n", encoding="utf-8")
    (outdir / "rollback.rsc").write_text("\n".join(rollback_commands) + "\n", encoding="utf-8")

    apply_results = {}
    after = {}
    if args.apply:
        apply_results = run_commands(target, apply_commands, defaults)
        after = run_commands(target, commands, defaults)
        write_outputs(outdir, "after", after)

    summary = {
        "host": args.host,
        "tcp_ports": args.tcp_ports,
        "udp_ports": args.udp_ports,
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
