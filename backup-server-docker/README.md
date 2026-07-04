# backup-server-docker

Clone local em Docker do `backup-server01` (`10.0.0.197`), pensado para reproduzir a estrutura básica do servidor de backup com foco em diretórios, usuários e permissões.

## O que esta instância recria

- Usuários locais:
  - `administrador` com UID/GID `1000`
  - `saude` com UID/GID `1001`
  - `backup_adm` com UID/GID `1002`
- Grupos suplementares observados:
  - `administrador` em `adm`, `sudo`, `cdrom`, `dip`, `plugdev`, `lxd`, `docker`
  - `backup_adm` em `users`
- Diretórios e permissões:
  - `/home/administrador` `750`
  - `/home/backup_adm` `750`
  - `/mnt/backup` `755`
  - `/mnt/backup/saude` `750`
  - `/mnt/backup_adm` `755`
  - `/mnt/backup_adm/versions` `775`
  - `/mnt/backup_adm/versions/compras` `775`
  - `/mnt/backup_adm/versions/esus` `775`
  - `/mnt/backup_adm/versions/pronim` `775`
  - `/mnt/backup_adm/versions/tributos` `775`
  - `/mnt/backup_adm/versions/saude` `755`
- Estrutura inicial `latest`:
  - `compras/latest -> 2026-07-03`
  - `esus/latest -> 2026-07-03`
  - `pronim/latest -> 2026-07-03`
  - `tributos/latest -> 2026-07-03`

## Como subir

```bash
./setup.sh
```

Ou manualmente:

```bash
docker compose up --build -d
docker compose exec backup-server-docker bash
```

## Observação

Esta instância replica a estrutura observada no servidor real, mas não inclui os dados históricos de backup nem os serviços extras que dependem de volumes externos do ambiente de produção.
