#!/usr/bin/env python3
"""Read-only audit for Debian/Ubuntu-based Linux servers."""

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


def commands_for_linux() -> list[str]:
    return [
        "hostnamectl",
        "cat /etc/os-release",
        "uname -a",
        "uptime",
        "who -a",
        "ip -brief address",
        "ip route show",
        "ip rule show",
        "ss -tulpn",
        "systemctl --failed --no-pager",
        "systemctl list-units --type=service --state=running --no-pager",
        "df -hT",
        "free -h",
        "lsblk -o NAME,FSTYPE,SIZE,MOUNTPOINT,MODEL",
        "dpkg-query -W -f='${binary:Package}\t${Version}\t${db:Status-Abbrev}\n' | sort | head -n 200",
        r"grep -h -E '^(Port|PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|AllowUsers|AllowGroups)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null || true",
        "command -v ufw >/dev/null 2>&1 && ufw status verbose || echo 'ufw not installed'",
        "command -v fail2ban-client >/dev/null 2>&1 && fail2ban-client status || echo 'fail2ban not installed'",
    ]


def summarize(outputs: dict[str, str]) -> str:
    def first_nonempty_line(text: str, fallback: str = "") -> str:
        for line in text.splitlines():
            if line.strip():
                return line.strip()
        return fallback

    os_release = outputs.get("cat /etc/os-release", "")
    uptime = outputs.get("uptime", "")
    ip_addr = outputs.get("ip -brief address", "")
    routes = outputs.get("ip route show", "")
    sockets = outputs.get("ss -tulpn", "")
    failed = outputs.get("systemctl --failed --no-pager", "")
    df = outputs.get("df -hT", "")
    free = outputs.get("free -h", "")
    sshd = outputs.get(r"grep -h -E '^(Port|PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|AllowUsers|AllowGroups)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null || true", "")

    lines = [
        "# Resumo Linux Debian/Ubuntu",
        "",
        "## Sistema",
        f"- {first_nonempty_line(os_release, 'Sem /etc/os-release')}",
        "",
        "## Uptime",
        f"- {uptime.strip() or 'Sem saída de uptime'}",
        "",
        "## Endereços",
        "```",
        ip_addr.strip() or "Sem saída de ip address",
        "```",
        "",
        "## Rotas",
        "```",
        routes.strip() or "Sem saída de ip route",
        "```",
        "",
        "## Sockets",
        "```",
        sockets.strip() or "Sem saída de ss",
        "```",
        "",
        "## Serviços com falha",
        "```",
        failed.strip() or "Sem saída de systemctl --failed",
        "```",
        "",
        "## Disco",
        "```",
        df.strip() or "Sem saída de df",
        "```",
        "",
        "## Memória",
        "```",
        free.strip() or "Sem saída de free",
        "```",
        "",
        "## SSHD",
        "```",
        sshd.strip() or "Sem linhas relevantes de sshd_config",
        "```",
    ]
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Read-only audit for Debian/Ubuntu Linux servers")
    parser.add_argument("--host", required=True, help="Host address in inventory")
    args = parser.parse_args()

    target, defaults = get_target(args.host)
    dtype = target.get("type", "").strip().lower()
    if dtype not in SUPPORTED_TYPES:
        raise ValueError(f"Tipo de dispositivo não suportado para este script: {dtype}")

    log("INFO", f"Auditando servidor Linux {args.host} ({dtype})")
    cmd_list = commands_for_linux()
    outputs = run_commands(target, cmd_list, defaults)

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_base = Path("reports") / f"linux_debian_ubuntu_audit_{stamp}"
    out_base.mkdir(parents=True, exist_ok=True)
    host_dir = out_base / args.host.replace(".", "_")
    write_command_outputs(host_dir, outputs)

    summary = summarize(outputs)
    (host_dir / "SUMMARY.md").write_text(summary, encoding="utf-8")
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

    log("INFO", f"Auditoria concluída em {host_dir}")


if __name__ == "__main__":
    main()
