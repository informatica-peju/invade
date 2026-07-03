#!/usr/bin/env python3
import json
import os
from pathlib import Path
from typing import Dict, List

from netmiko import ConnectHandler


def load_inventory(file_path: str) -> List[Dict]:
    with open(file_path, encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError("O inventário JSON deve ser uma lista de roteadores.")
    return data


def netmiko_type(device_type: str) -> str:
    if device_type == "mikrotik":
        return "mikrotik_routeros"
    if device_type in {"openwrt", "ubuntu", "ubuntu-server", "debian", "linux"}:
        return "linux"
    raise ValueError(f"Tipo de dispositivo não suportado: {device_type}")


def runtime_defaults() -> Dict:
    return {
        "inventory_file": os.getenv("INVENTORY_FILE", "configs/inventory.json"),
        "default_user": os.getenv("ROUTER_USER", "admin"),
        "default_password": os.getenv("ROUTER_PASSWORD", ""),
        "default_port": int(os.getenv("ROUTER_PORT", "22")),
        "timeout": int(os.getenv("SSH_TIMEOUT", "20")),
    }


def build_connection_params(target: Dict, defaults: Dict) -> Dict:
    host = target.get("host", "").strip()
    dtype = target.get("type", "").strip().lower()
    user = target.get("username", defaults["default_user"]).strip()
    password = target.get("password", defaults["default_password"])
    port = int(target.get("port", defaults["default_port"]))
    ssh_key_file = target.get("ssh_key_file")

    if not host or not dtype:
        raise ValueError("Entrada inválida no inventário: host/type obrigatórios.")

    conn_params = {
        "device_type": netmiko_type(dtype),
        "host": host,
        "username": user,
        "port": port,
        "timeout": defaults["timeout"],
        "conn_timeout": defaults["timeout"],
    }
    if password:
        conn_params["password"] = password
    if ssh_key_file:
        conn_params["use_keys"] = True
        conn_params["key_file"] = ssh_key_file

    return conn_params


def run_commands(target: Dict, commands: List[str], defaults: Dict) -> Dict[str, str]:
    conn_params = build_connection_params(target, defaults)
    timeout = defaults["timeout"]
    results = {}

    with ConnectHandler(**conn_params) as conn:
        for cmd in commands:
            try:
                output = conn.send_command(cmd, expect_string=None, read_timeout=timeout)
            except Exception as cmd_err:
                output = f"[ERRO] Falha ao executar comando '{cmd}': {cmd_err}"
            results[cmd] = output
    return results


def write_command_outputs(base_dir: Path, command_results: Dict[str, str]) -> None:
    base_dir.mkdir(parents=True, exist_ok=True)
    for idx, (cmd, output) in enumerate(command_results.items(), start=1):
        safe_name = cmd.replace(" ", "_").replace("/", "")[:80]
        fname = base_dir / f"{idx:02d}_{safe_name}.txt"
        fname.write_text(f"$ {cmd}\n\n{output}\n", encoding="utf-8")
