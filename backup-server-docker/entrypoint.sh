#!/usr/bin/env bash
set -euo pipefail

log() {
  printf '%s [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$1" "$2"
}

log INFO "Executando bootstrap do backup-server-docker"
/usr/local/bin/bootstrap-backup-server.sh

if [[ $# -eq 0 ]]; then
  set -- bash
fi

log INFO "Iniciando processo principal: $*"
exec "$@"
