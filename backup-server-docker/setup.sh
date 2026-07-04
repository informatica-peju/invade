#!/usr/bin/env bash
set -euo pipefail

log() {
  printf '%s [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$1" "$2"
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  DOCKER_BIN="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
  DOCKER_BIN="docker-compose"
else
  log ERROR "Docker Compose não encontrado no PATH"
  exit 1
fi

log INFO "Construindo e subindo a instância backup-server-docker"
${DOCKER_BIN} up --build -d

log INFO "Instância pronta. Para entrar, use:"
log INFO "docker compose -f ${SCRIPT_DIR}/docker-compose.yml exec backup-server-docker bash"
