#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${BACKUP_SERVER_ROOT:-/}"
SEED_DATE="${BACKUP_SERVER_SEED_DATE:-2026-07-03}"

log() {
  printf '%s [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$1" "$2"
}

ensure_group() {
  local group_name="$1"
  local gid="${2:-}"

  if getent group "$group_name" >/dev/null 2>&1; then
    return 0
  fi

  if [[ -n "$gid" ]] && ! getent group "$gid" >/dev/null 2>&1; then
    log INFO "Criando grupo ${group_name} (GID ${gid})"
    groupadd -g "$gid" "$group_name"
  else
    log INFO "Criando grupo ${group_name}"
    groupadd "$group_name"
  fi
}

ensure_user() {
  local user_name="$1"
  local uid="$2"
  local gid="$3"
  local home_dir="$4"
  local shell_path="$5"
  local groups_csv="${6:-}"

  if id -u "$user_name" >/dev/null 2>&1; then
    log INFO "Usuário ${user_name} já existe; reaproveitando"
  else
    log INFO "Criando usuário ${user_name} (UID ${uid}, GID ${gid})"
    useradd -u "$uid" -g "$gid" -M -d "$home_dir" -s "$shell_path" "$user_name"
  fi

  if [[ -n "$groups_csv" ]]; then
    log INFO "Ajustando grupos suplementares de ${user_name}: ${groups_csv}"
    usermod -aG "$groups_csv" "$user_name"
  fi
}

ensure_dir() {
  local path="$1"
  local owner="$2"
  local mode="$3"

  mkdir -p "${ROOT_DIR}${path}"
  chown "$owner" "${ROOT_DIR}${path}"
  chmod "$mode" "${ROOT_DIR}${path}"
  log INFO "Diretório preparado: ${path} (${owner}, ${mode})"
}

ensure_link() {
  local link_path="$1"
  local target="$2"
  local owner="$3"

  mkdir -p "$(dirname "${ROOT_DIR}${link_path}")"
  ln -sfn "$target" "${ROOT_DIR}${link_path}"
  chown -h "$owner" "${ROOT_DIR}${link_path}"
  log INFO "Link ajustado: ${link_path} -> ${target}"
}

log INFO "Iniciando bootstrap do clone Docker do backup-server01 em ${ROOT_DIR}"

for group_def in \
  "administrador:1000" \
  "saude:1001" \
  "backup_adm:1002" \
  "docker:110" \
  "lxd:101" \
  "users:100"; do
  group_name="${group_def%%:*}"
  gid="${group_def##*:}"
  ensure_group "$group_name" "$gid"
done

ensure_user "administrador" "1000" "1000" "/home/administrador" "/bin/bash" "adm,sudo,cdrom,dip,plugdev,lxd,docker"
ensure_user "saude" "1001" "1001" "/mnt/backup/saude" "/bin/bash"
ensure_user "backup_adm" "1002" "1002" "/home/backup_adm" "/bin/bash" "users"

ensure_dir "/home/administrador" "administrador:administrador" "750"
ensure_dir "/home/backup_adm" "backup_adm:backup_adm" "750"
ensure_dir "/mnt/backup" "root:root" "755"
ensure_dir "/mnt/backup/saude" "saude:saude" "750"
ensure_dir "/mnt/backup_adm" "backup_adm:backup_adm" "755"
ensure_dir "/mnt/backup_adm/versions" "backup_adm:backup_adm" "775"
ensure_dir "/mnt/backup_adm/versions/compras" "backup_adm:backup_adm" "775"
ensure_dir "/mnt/backup_adm/versions/esus" "backup_adm:backup_adm" "775"
ensure_dir "/mnt/backup_adm/versions/pronim" "backup_adm:backup_adm" "775"
ensure_dir "/mnt/backup_adm/versions/tributos" "backup_adm:backup_adm" "775"
ensure_dir "/mnt/backup_adm/versions/saude" "backup_adm:backup_adm" "755"

for project in compras esus pronim tributos; do
  ensure_dir "/mnt/backup_adm/versions/${project}/${SEED_DATE}" "backup_adm:backup_adm" "$(case "$project" in
    compras) printf '750' ;;
    esus) printf '755' ;;
    pronim) printf '770' ;;
    tributos) printf '700' ;;
  esac)"
  ensure_link "/mnt/backup_adm/versions/${project}/latest" "${SEED_DATE}" "backup_adm:backup_adm"
done

log INFO "Bootstrap concluído"
