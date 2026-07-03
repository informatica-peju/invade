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
- `scripts/audit_linux_debian_ubuntu.py`: read-only audit for Debian/Ubuntu servers
- `scripts/audit_linux_cron.py`: cron and systemd timer discovery
- `scripts/analyze_snapshot.py`: basic report generator from collected snapshots
- `configs/inventory.example.json`: inventory template
- `configs/inventory.json`: local inventory with credentials (ignored by Git)
- `data/raw/`: raw command outputs
- `reports/`: generated reports
- `backups/`: local backup workspace (ignored except `.gitkeep`)

## Quick Start
1. Install Docker and prepare local project files:
```bash
./setup.sh
```
2. Create local environment file, if it does not already exist:
```bash
cp .env.example .env
```
3. Create local inventory, if it does not already exist:
```bash
cp configs/inventory.example.json configs/inventory.json
```
4. Edit inventory with real targets and credentials.
5. Build and run:
```bash
docker compose build
docker compose run --rm router-analyzer bash
```
6. Inside container, run workflows:
```bash
python scripts/collect_configs.py
python scripts/diagnose_path.py
python scripts/read_only_audit.py
python scripts/audit_linux_debian_ubuntu.py --host 10.0.0.197
python scripts/audit_linux_cron.py --host 10.0.0.197
python scripts/analyze_snapshot.py
python scripts/dns_static_toolkit.py backup --host 10.8.0.1
python scripts/dns_static_toolkit.py normalize-apply --host 10.8.0.1
python scripts/dns_static_toolkit.py test --host 10.8.0.1
```

## DNS Static Toolkit
Use `scripts/dns_static_toolkit.py` for repetitive DNS static maintenance on MikroTik:
- `backup`: creates timestamped backup under `backups/`
- `normalize-apply`: rebuilds static DNS entries in an organized format, converts simple regex suffix rules to `name + match-subdomain=yes`, and keeps a local rollback artifact
- `test`: runs quick resolution checks and verifies no `regexp=` entries remain

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
