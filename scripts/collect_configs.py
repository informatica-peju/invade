#!/usr/bin/env python3
import json
import os
from datetime import datetime
from pathlib import Path

from netmiko import ConnectHandler


def load_inventory(file_path: str):
    with open(file_path, encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, list):
        raise ValueError("O inventário JSON deve ser uma lista de roteadores.")
    return data


def commands_for(device_type: str):
    if device_type == "mikrotik":
        return [
            "/system identity print",
            "/system resource print",
            "/ip address print detail",
            "/ip route print detail",
            "/interface print detail",
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


def netmiko_type(device_type: str):
    return "mikrotik_routeros" if device_type == "mikrotik" else "linux"


def main():
    inventory_file = os.getenv("INVENTORY_FILE", "configs/inventory.json")
    default_user = os.getenv("ROUTER_USER", "admin")
    default_password = os.getenv("ROUTER_PASSWORD", "")
    default_port = int(os.getenv("ROUTER_PORT", "22"))
    timeout = int(os.getenv("SSH_TIMEOUT", "20"))

    targets = load_inventory(inventory_file)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_output = Path("data/raw") / timestamp
    base_output.mkdir(parents=True, exist_ok=True)

    for target in targets:
        host = target.get("host", "").strip()
        dtype = target.get("type", "").strip().lower()
        user = target.get("username", default_user).strip()
        password = target.get("password", default_password)
        port = int(target.get("port", default_port))
        ssh_key_file = target.get("ssh_key_file")

        if not host or not dtype:
            print("[!] Entrada inválida no inventário: host/type obrigatórios.")
            continue

        device_output = base_output / host.replace(".", "_")
        device_output.mkdir(parents=True, exist_ok=True)

        conn_params = {
            "device_type": netmiko_type(dtype),
            "host": host,
            "username": user,
            "port": port,
            "timeout": timeout,
            "conn_timeout": timeout,
        }
        if password:
            conn_params["password"] = password
        if ssh_key_file:
            conn_params["use_keys"] = True
            conn_params["key_file"] = ssh_key_file

        print(f"[+] Coletando {host} ({dtype})...")
        try:
            with ConnectHandler(**conn_params) as conn:
                for idx, cmd in enumerate(commands_for(dtype), start=1):
                    try:
                        output = conn.send_command(cmd, expect_string=None, read_timeout=timeout)
                    except Exception as cmd_err:
                        output = f"[ERRO] Falha ao executar comando '{cmd}': {cmd_err}"

                    fname = device_output / f"{idx:02d}_{cmd.replace(' ', '_').replace('/', '')[:60]}.txt"
                    fname.write_text(f"$ {cmd}\n\n{output}\n", encoding="utf-8")
        except Exception as err:
            err_file = device_output / "00_connection_error.txt"
            err_file.write_text(str(err), encoding="utf-8")
            print(f"[!] Erro em {host}: {err}")

    print(f"\n[OK] Coleta finalizada. Saída em: {base_output}")


if __name__ == "__main__":
    main()
