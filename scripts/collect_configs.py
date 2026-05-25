#!/usr/bin/env python3
from datetime import datetime
from pathlib import Path

from lib_router import load_inventory, run_commands, runtime_defaults, write_command_outputs


def commands_for(device_type: str):
    if device_type == "mikrotik":
        return [
            "/system identity print",
            "/system resource print",
            "/ip address print detail",
            "/ip route print detail",
            "/interface print detail",
            "/ip firewall filter print detail",
            "/ip firewall nat print detail",
            "/export hide-sensitive",
        ]
    if device_type == "openwrt":
        return [
            "uname -a",
            "ubus call system board",
            "ip address show",
            "ip route show",
            "uci show",
            "cat /etc/config/network",
            "cat /etc/config/firewall",
            "cat /etc/config/wireless",
            "cat /etc/config/dhcp",
        ]
    raise ValueError(f"Tipo de dispositivo não suportado: {device_type}")


def main():
    defaults = runtime_defaults()
    targets = load_inventory(defaults["inventory_file"])

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_output = Path("data/raw") / timestamp
    base_output.mkdir(parents=True, exist_ok=True)

    for target in targets:
        host = target.get("host", "").strip()
        dtype = target.get("type", "").strip().lower()
        if not host or not dtype:
            print("[!] Entrada inválida no inventário: host/type obrigatórios.")
            continue

        device_output = base_output / host.replace(".", "_")
        print(f"[+] Coletando {host} ({dtype})...")

        try:
            results = run_commands(target, commands_for(dtype), defaults)
            write_command_outputs(device_output, results)
        except Exception as err:
            device_output.mkdir(parents=True, exist_ok=True)
            err_file = device_output / "00_connection_error.txt"
            err_file.write_text(str(err), encoding="utf-8")
            print(f"[!] Erro em {host}: {err}")

    print(f"\n[OK] Coleta finalizada. Saída em: {base_output}")


if __name__ == "__main__":
    main()
