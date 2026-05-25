# Router Config Analyzer (MikroTik + OpenWrt)

Ambiente Docker para coletar configurações de roteadores via SSH e gerar artefatos para análise por IA.

## O que inclui
- Cliente SSH e utilitários: `openssh-client`, `sshpass`, `jq`, `yq`, `rsync`, `git`
- Automação Python: `netmiko`, `paramiko`, `textfsm`, `pandas`
- Scripts de coleta e resumo inicial

## Estrutura
- `scripts/collect_configs.py`: coleta comandos de roteadores por SSH
- `scripts/analyze_snapshot.py`: gera um resumo simples do snapshot coletado
- `configs/inventory.json`: inventário local (não versionado)
- `configs/inventory.example.json`: exemplo de inventário
- `data/raw/`: saídas brutas
- `reports/`: relatórios

## Como usar
1. Criar `.env` local:
```bash
cp .env.example .env
```
2. Criar inventário local:
```bash
cp configs/inventory.example.json configs/inventory.json
# edite hosts, usuários e credenciais por roteador
```
3. Subir ambiente:
```bash
docker compose build
docker compose run --rm router-analyzer bash
```
4. Dentro do container, coletar:
```bash
python scripts/collect_configs.py
```
5. Gerar resumo:
```bash
python scripts/analyze_snapshot.py
```

## Formato do inventário JSON
Cada item é um roteador. Campos obrigatórios: `host`, `type`.

Exemplo:
```json
[
  {
    "host": "192.168.88.1",
    "type": "mikrotik",
    "username": "admin",
    "password": "segredo"
  },
  {
    "host": "192.168.1.1",
    "type": "openwrt",
    "username": "root",
    "ssh_key_file": "/workspace/configs/keys/id_ed25519"
  }
]
```

## Segurança
- `.env` e `configs/inventory.json` ficam fora do Git.
- `.env.example` e `configs/inventory.example.json` entram no Git como modelo.
- Nunca commitar chaves privadas ou dumps sensíveis.
- Para MikroTik foi usado `/export hide-sensitive` para reduzir exposição de segredo.
