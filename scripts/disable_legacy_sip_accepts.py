#!/usr/bin/env python3
"""Disable legacy MikroTik SIP accept rules after managed allowlist rules are in place."""

import argparse
import json
from datetime import datetime
from pathlib import Path

from lib_router import load_inventory, run_commands, runtime_defaults


LEGACY_COMMENTS = ["ACEITA-SIP-TCP", "ACEITA-SIP-UDP"]


def get_target(host: str):
    defaults = runtime_defaults()
    inventory = load_inventory(defaults["inventory_file"])
    for target in inventory:
        if target.get("host", "").strip() == host:
            return target, defaults
    raise ValueError(f"Host {host} not found in inventory")


def backup_commands() -> list[str]:
    return [
        "/system clock print",
        "/ip firewall filter print detail",
        "/ip firewall filter print stats detail",
    ]


def build_apply_commands() -> list[str]:
    return [f'/ip firewall filter disable [find comment="{comment}"]' for comment in LEGACY_COMMENTS]


def build_rollback_commands() -> list[str]:
    return [f'/ip firewall filter enable [find comment="{comment}"]' for comment in LEGACY_COMMENTS]


def write_outputs(outdir: Path, prefix: str, results: dict[str, str]) -> None:
    for idx, (command, output) in enumerate(results.items(), start=1):
        safe = command.replace("/", "").replace(" ", "_").replace('"', "")[:120]
        (outdir / f"{idx:02d}_{prefix}_{safe}.txt").write_text(
            f"$ {command}\n\n{output}\n",
            encoding="utf-8",
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Disable legacy SIP accept rules that are superseded by allowlist rules")
    parser.add_argument("--host", required=True, help="MikroTik host from inventory")
    parser.add_argument("--apply", action="store_true", help="Actually apply changes; omit for dry-run")
    args = parser.parse_args()

    target, defaults = get_target(args.host)
    commands = backup_commands()
    before = run_commands(target, commands, defaults)

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = Path("backups") / f"legacy_sip_accept_cleanup_{args.host}_{stamp}".replace(".", "_")
    outdir.mkdir(parents=True, exist_ok=True)
    write_outputs(outdir, "before", before)

    apply_commands = build_apply_commands()
    rollback_commands = build_rollback_commands()
    (outdir / "apply.rsc").write_text("\n".join(apply_commands) + "\n", encoding="utf-8")
    (outdir / "rollback.rsc").write_text("\n".join(rollback_commands) + "\n", encoding="utf-8")

    apply_results = {}
    if args.apply:
        apply_results = run_commands(target, apply_commands, defaults)
        after = run_commands(target, commands, defaults)
        write_outputs(outdir, "after", after)

    summary = {
        "host": args.host,
        "legacy_comments": LEGACY_COMMENTS,
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
