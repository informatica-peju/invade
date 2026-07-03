# Toolkit de Diagnóstico de Rede com IA (MikroTik + OpenWrt/Linux)

Toolkit em Docker para diagnóstico de redes via SSH com suporte colaborativo entre pessoas e agentes de IA.

## Objetivo
Este projeto foi criado para:
- coletar configuração/estado de roteadores e gateways Linux,
- gerar snapshots reproduzíveis de diagnóstico,
- apoiar fluxos colaborativos de troubleshooting com IA.

## Por que Docker
Docker foi usado para simplificar aquisição e execução das ferramentas:
- ambiente único de SSH/CLI,
- dependências Python reproduzíveis,
- menor variação entre máquinas.

## Ferramentas incluídas
- SSH e utilitários: `openssh-client`, `sshpass`, `jq`, `yq`, `rsync`, `git`, `curl`
- Bibliotecas Python: `netmiko`, `paramiko`, `textfsm`, `pandas`, `pyyaml`, `rich`

## Estrutura do projeto
- `scripts/lib_router.py`: camada compartilhada de conexão e execução
- `scripts/collect_configs.py`: coleta padrão de configuração/estado
- `scripts/diagnose_path.py`: diagnóstico focado de caminho (rota/firewall/conectividade)
- `scripts/read_only_audit.py`: auditoria não invasiva (somente leitura)
- `scripts/analyze_snapshot.py`: resumo básico dos snapshots coletados
- `configs/inventory.example.json`: modelo de inventário
- `configs/inventory.json`: inventário local com credenciais (ignorado pelo Git)
- `data/raw/`: saídas brutas dos comandos
- `reports/`: relatórios gerados
- `backups/`: área local de backup (ignorada, exceto `.gitkeep`)

## Início rápido
1. Instalar Docker, preparar `.env` e o inventário local:
```bash
./setup.sh
```
2. Criar arquivo de ambiente local, se ainda não existir:
```bash
cp .env.example .env
```
3. Criar inventário local, se ainda não existir:
```bash
cp configs/inventory.example.json configs/inventory.json
```
4. Editar inventário com alvos/credenciais reais.
5. Subir e entrar no ambiente:
```bash
docker compose build
docker compose run --rm router-analyzer bash
```
6. Dentro do container, executar fluxos:
```bash
python scripts/collect_configs.py
python scripts/diagnose_path.py
python scripts/read_only_audit.py
python scripts/analyze_snapshot.py
python scripts/dns_static_toolkit.py backup --host 10.8.0.1
python scripts/dns_static_toolkit.py normalize-apply --host 10.8.0.1
python scripts/dns_static_toolkit.py test --host 10.8.0.1
```

## Toolkit DNS Static
Use `scripts/dns_static_toolkit.py` para manutenção repetitiva de DNS estático em MikroTik:
- `backup`: cria backup com timestamp em `backups/`
- `normalize-apply`: recria entradas DNS estáticas de forma organizada, converte regex simples de sufixo para `name + match-subdomain=yes` e salva artefato local de rollback
- `test`: executa validações rápidas de resolução e verifica se não restou `regexp=`

## Formato do inventário
Cada item JSON representa um dispositivo.
Campos obrigatórios: `host`, `type`.

```json
[
  {
    "name": "roteador-core",
    "host": "192.168.88.1",
    "type": "mikrotik",
    "port": 22,
    "username": "admin",
    "password": "troque-isto"
  },
  {
    "name": "gateway-linux",
    "host": "192.168.1.1",
    "type": "openwrt",
    "port": 22,
    "username": "root",
    "ssh_key_file": "/workspace/configs/keys/id_ed25519"
  }
]
```

## Segurança
- Nunca commitar credenciais reais, chaves privadas ou dumps sensíveis.
- `.env` e `configs/inventory.json` ficam fora do Git por padrão.
- `backups/*` é ignorado para reduzir risco de vazamento acidental.
- No MikroTik, a coleta usa `/export hide-sensitive` para reduzir exposição de segredo.
