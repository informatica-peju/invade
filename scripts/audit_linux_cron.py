#!/usr/bin/env python3
"""Read-only audit for cron schedules on Debian/Ubuntu-based Linux servers."""

from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path

from lib_router import load_inventory, run_commands, runtime_defaults, write_command_outputs


SUPPORTED_TYPES = {"debian", "ubuntu", "ubuntu-server", "linux"}


def log(level: str, message: str) -> None:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"{ts} [{level}] {message}")


def get_target(host: str):
    defaults = runtime_defaults()
    inventory = load_inventory(defaults["inventory_file"])
    for target in inventory:
        if target.get("host", "").strip() == host:
            return target, defaults
    raise ValueError(f"Host {host} não encontrado no inventário")


def cron_commands() -> list[str]:
    return [
        "crontab -l 2>/dev/null || echo 'NO_USER_CRONTAB'",
        "sudo -n crontab -l -u root 2>/dev/null || echo 'NO_ROOT_CRONTAB_OR_NO_SUDO'",
        "cat /etc/crontab 2>/dev/null || echo 'NO_ETC_CRONTAB'",
        "find /etc/cron.d -maxdepth 1 \\( -type f -o -type l \\) 2>/dev/null | sort | xargs -r -I{} sh -c 'echo \"### {}\"; cat \"{}\" 2>/dev/null; echo'",
        "for d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do echo \"### $d\"; ls -la \"$d\" 2>/dev/null || echo 'MISSING'; echo; done",
        "command -v systemctl >/dev/null 2>&1 && systemctl list-timers --all --no-pager || echo 'SYSTEMD_TIMERS_UNAVAILABLE'",
        "command -v anacron >/dev/null 2>&1 && cat /etc/anacrontab 2>/dev/null || echo 'NO_ANACRON'",
        "grep -R -n -E '(^|\\s)(cron|crontab|timer)' /etc/systemd/system /lib/systemd/system 2>/dev/null || true",
    ]


def summarize(outputs: dict[str, str]) -> str:
    user_crontab = outputs.get("crontab -l 2>/dev/null || echo 'NO_USER_CRONTAB'", "")
    root_crontab = outputs.get("sudo -n crontab -l -u root 2>/dev/null || echo 'NO_ROOT_CRONTAB_OR_NO_SUDO'", "")
    etc_crontab = outputs.get("cat /etc/crontab 2>/dev/null || echo 'NO_ETC_CRONTAB'", "")
    timers = outputs.get("command -v systemctl >/dev/null 2>&1 && systemctl list-timers --all --no-pager || echo 'SYSTEMD_TIMERS_UNAVAILABLE'", "")
    anacron = outputs.get("command -v anacron >/dev/null 2>&1 && cat /etc/anacrontab 2>/dev/null || echo 'NO_ANACRON'", "")

    lines = [
        "# Resumo Cron / Timers",
        "",
        "## Crontab do usuário",
        "```",
        user_crontab.strip() or "Sem saída",
        "```",
        "",
        "## Crontab do root",
        "```",
        root_crontab.strip() or "Sem saída",
        "```",
        "",
        "## /etc/crontab",
        "```",
        etc_crontab.strip() or "Sem saída",
        "```",
        "",
        "## Systemd timers",
        "```",
        timers.strip() or "Sem saída",
        "```",
        "",
        "## Anacron",
        "```",
        anacron.strip() or "Sem saída",
        "```",
    ]
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Read-only cron audit for Debian/Ubuntu Linux servers")
    parser.add_argument("--host", required=True, help="Host address in inventory")
    args = parser.parse_args()

    target, defaults = get_target(args.host)
    dtype = target.get("type", "").strip().lower()
    if dtype not in SUPPORTED_TYPES:
        raise ValueError(f"Tipo de dispositivo não suportado para este script: {dtype}")

    log("INFO", f"Buscando agendamentos cron em {args.host} ({dtype})")
    cmd_list = cron_commands()
    outputs = run_commands(target, cmd_list, defaults)

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_base = Path("reports") / f"linux_cron_audit_{stamp}"
    out_base.mkdir(parents=True, exist_ok=True)
    host_dir = out_base / args.host.replace(".", "_")
    write_command_outputs(host_dir, outputs)

    (host_dir / "SUMMARY.md").write_text(summarize(outputs), encoding="utf-8")
    (host_dir / "summary.json").write_text(
        json.dumps(
            {
                "host": args.host,
                "type": dtype,
                "commands": cmd_list,
                "output_dir": str(host_dir),
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    log("INFO", f"Auditoria de cron concluída em {host_dir}")


if __name__ == "__main__":
    main()
