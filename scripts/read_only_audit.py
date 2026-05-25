#!/usr/bin/env python3
from datetime import datetime
from pathlib import Path

from lib_router import load_inventory, run_commands, runtime_defaults, write_command_outputs


def mikrotik_read_only_commands():
    return [
        "/system identity print",
        "/system resource print",
        "/ip address print detail",
        "/ip route print detail",
        "/routing rule print detail",
        "/interface print detail",
        "/ip firewall filter print detail",
        "/ip firewall nat print detail",
        "/ip firewall mangle print detail",
        "/ip firewall filter print stats",
        "/ip firewall nat print stats",
    ]


def openwrt_read_only_commands():
    return [
        "uname -a",
        "ubus call system board",
        "ip address show",
        "ip route show",
        "cat /etc/config/network",
        "cat /etc/config/firewall",
        "cat /etc/config/dhcp",
    ]


def commands_for(device_type: str):
    if device_type == "mikrotik":
        return mikrotik_read_only_commands()
    if device_type == "openwrt":
        return openwrt_read_only_commands()
    raise ValueError(f"Tipo de dispositivo não suportado: {device_type}")


def main():
    defaults = runtime_defaults()
    inventory = load_inventory(defaults["inventory_file"])

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_base = Path("reports") / f"readonly_audit_{timestamp}"
    out_base.mkdir(parents=True, exist_ok=True)

    for target in inventory:
        host = target.get("host", "").strip()
        dtype = target.get("type", "").strip().lower()
        if not host or not dtype:
            continue

        host_dir = out_base / host.replace(".", "_")
        print(f"[+] Auditando (read-only) {host} ({dtype})")
        try:
            outputs = run_commands(target, commands_for(dtype), defaults)
            write_command_outputs(host_dir, outputs)
        except Exception as err:
            host_dir.mkdir(parents=True, exist_ok=True)
            (host_dir / "00_connection_error.txt").write_text(str(err), encoding="utf-8")
            print(f"[!] Falha em {host}: {err}")

    print(f"[OK] Auditoria read-only salva em {out_base}")


if __name__ == "__main__":
    main()
