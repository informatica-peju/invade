# AI Network Diagnostics Toolkit

This repository provides collaborative, AI-assisted scripts to diagnose multi-vendor network environments.

Este repositório fornece scripts colaborativos com IA para diagnóstico de redes multi-vendor.

## Documentation / Documentação
- English: [README.en.md](README.en.md)
- Português (Brasil): [README.pt-BR.md](README.pt-BR.md)

## Quick Start
```bash
cp .env.example .env
cp configs/inventory.example.json configs/inventory.json
docker compose build
docker compose run --rm router-analyzer python scripts/collect_configs.py
```

## Extra Docker Clone
- `backup-server-docker/`: local Docker clone of `backup-server01` with users, permissions and backup directories recreated from the audit.
