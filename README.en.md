# AI Network Diagnostics Toolkit (MikroTik + OpenWrt/Linux)

Dockerized toolkit for AI-assisted network diagnostics over SSH.

## Purpose
This project is designed to:
- collect network configuration/state from routers and Linux gateways,
- generate reproducible diagnostic snapshots,
- support collaborative troubleshooting workflows between humans and AI agents.

## Why Docker
Docker is used to make tool acquisition and execution consistent across environments:
- unified SSH/CLI tooling,
- reproducible Python dependencies,
- zero local dependency drift.

## Included Tooling
- SSH and utilities: `openssh-client`, `sshpass`, `jq`, `yq`, `rsync`, `git`, `curl`
- Python libraries: `netmiko`, `paramiko`, `textfsm`, `pandas`, `pyyaml`, `rich`

## Project Structure
- `scripts/lib_router.py`: shared connection and command-execution layer
- `scripts/collect_configs.py`: standard config/state collector
- `scripts/diagnose_path.py`: targeted path troubleshooting (routing/firewall/connectivity)
- `scripts/read_only_audit.py`: non-invasive read-only audit workflow
- `scripts/analyze_snapshot.py`: basic report generator from collected snapshots
- `configs/inventory.example.json`: inventory template
- `configs/inventory.json`: local inventory with credentials (ignored by Git)
- `data/raw/`: raw command outputs
- `reports/`: generated reports
- `backups/`: local backup workspace (ignored except `.gitkeep`)

## Quick Start
1. Create local environment file:
```bash
cp .env.example .env
```
2. Create local inventory:
```bash
cp configs/inventory.example.json configs/inventory.json
```
3. Edit inventory with real targets and credentials.
4. Build and run:
```bash
docker compose build
docker compose run --rm router-analyzer bash
```
5. Inside container, run workflows:
```bash
python scripts/collect_configs.py
python scripts/diagnose_path.py
python scripts/read_only_audit.py
python scripts/analyze_snapshot.py
```

## Inventory Format
Each JSON entry represents one device.
Required fields: `host`, `type`.

```json
[
  {
    "name": "core-router",
    "host": "192.168.88.1",
    "type": "mikrotik",
    "port": 22,
    "username": "admin",
    "password": "replace-this"
  },
  {
    "name": "edge-linux",
    "host": "192.168.1.1",
    "type": "openwrt",
    "port": 22,
    "username": "root",
    "ssh_key_file": "/workspace/configs/keys/id_ed25519"
  }
]
```

## Security Notes
- Never commit real credentials, private keys, or sensitive dumps.
- `.env` and `configs/inventory.json` are intentionally ignored by Git.
- `backups/*` is ignored to reduce accidental leakage.
- MikroTik collector uses `/export hide-sensitive` to reduce secret exposure.
