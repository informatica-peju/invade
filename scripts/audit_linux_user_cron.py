#!/usr/bin/env python3
"""Read-only audit for per-user cron schedules on Debian/Ubuntu Linux servers."""

from __future__ import annotations

import argparse
import json
import re
import shlex
from datetime import datetime
from pathlib import Path

from lib_router import load_inventory, run_commands, runtime_defaults


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


def valid_login_users(passwd_text: str) -> list[str]:
    users: list[str] = []
    seen = set()
    for line in passwd_text.splitlines():
        parts = line.split(":")
        if len(parts) < 7:
            continue
        user, uid_s, shell = parts[0], parts[2], parts[6]
        try:
            uid = int(uid_s)
        except ValueError:
            continue
        if uid < 0:
            continue
        if user in seen:
            continue
        if user == "root" or uid >= 1000:
            if shell.endswith(("nologin", "false")):
                continue
            users.append(user)
            seen.add(user)
    if "root" not in seen:
        users.insert(0, "root")
    return users


def escape_user(user: str) -> str:
    return shlex.quote(user)


def build_user_cron_specs(users: list[str], sudo_password: str | None) -> list[tuple[str, str]]:
    specs: list[tuple[str, str]] = [
        ("cat /etc/passwd", "cat /etc/passwd"),
        ("whoami", "whoami"),
        ("id", "id"),
    ]
    for user in users:
        u = escape_user(user)
        if sudo_password:
            pw = shlex.quote(sudo_password)
            display = f"crontab -l -u {user}"
            cmd = f"printf '%s\\n' {pw} | sudo -S -p '' crontab -l -u {u} 2>/dev/null || echo 'NO_CRONTAB'"
        else:
            display = f"sudo -n crontab -l -u {user}"
            cmd = f"sudo -n crontab -l -u {u} 2>/dev/null || echo 'NO_CRONTAB_OR_NO_SUDO'"
        specs.append((display, cmd))
    return specs


def summarize(outputs: dict[str, str], users: list[str], specs: list[tuple[str, str]]) -> str:
    lines = [
        "# Resumo Crontab por Usuário",
        "",
        f"Usuários verificados: {', '.join(users)}",
        "",
    ]
    for user in users:
        spec = next((item for item in specs if item[0].endswith(f"-u {user}")), None)
        if not spec:
            continue
        out = outputs.get(spec[1], "").strip()
        lines.append(f"## {user}")
        lines.append("```")
        lines.append(out or "Sem saída")
        lines.append("```")
        lines.append("")
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Read-only audit of per-user cron on Debian/Ubuntu Linux servers")
    parser.add_argument("--host", required=True, help="Host address in inventory")
    args = parser.parse_args()

    target, defaults = get_target(args.host)
    dtype = target.get("type", "").strip().lower()
    if dtype not in SUPPORTED_TYPES:
        raise ValueError(f"Tipo de dispositivo não suportado para este script: {dtype}")

    log("INFO", f"Buscando crontabs por usuário em {args.host} ({dtype})")

    passwd_text = run_commands(target, ["cat /etc/passwd"], defaults)["cat /etc/passwd"]
    users = valid_login_users(passwd_text)

    sudo_password = target.get("password", "").strip() or None
    specs = build_user_cron_specs(users, sudo_password)
    cmd_list = [cmd for _, cmd in specs]
    outputs = run_commands(target, cmd_list, defaults)

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_base = Path("reports") / f"linux_user_cron_audit_{stamp}"
    out_base.mkdir(parents=True, exist_ok=True)
    host_dir = out_base / args.host.replace(".", "_")
    host_dir.mkdir(parents=True, exist_ok=True)

    for idx, (display, cmd) in enumerate(specs, start=1):
        safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", display)[:120]
        (host_dir / f"{idx:02d}_{safe}.txt").write_text(f"$ {display}\n\n{outputs[cmd]}\n", encoding="utf-8")

    summary = {
        "host": args.host,
        "type": dtype,
        "users": users,
        "used_sudo_password": bool(sudo_password),
        "commands": [display for display, _ in specs],
        "output_dir": str(host_dir),
    }
    (host_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    (host_dir / "SUMMARY.md").write_text(summarize(outputs, users, specs), encoding="utf-8")

    log("INFO", f"Crontabs por usuário auditados em {host_dir}")


if __name__ == "__main__":
    main()
