#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NEEDS_SUDO=0
START_TS="$(date +%s)"
EXIT_CODE=0

if [[ "${EUID}" -ne 0 ]]; then
  NEEDS_SUDO=1
fi

log() {
  local level="$1"
  shift
  printf '%s [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "${level}" "$*"
}

info() {
  log "INFO" "$@"
}

warn() {
  log "WARN" "$@"
}

error() {
  log "ERROR" "$@" >&2
}

on_err() {
  local line="$1"
  local command="$2"
  local func="${3:-main}"
  error "Falha em ${func} na linha ${line}: ${command}"
}

finish() {
  local end_ts elapsed status_label
  end_ts="$(date +%s)"
  elapsed="$((end_ts - START_TS))"
  if [[ "${EXIT_CODE}" -eq 0 ]]; then
    status_label="SUCESSO"
  else
    status_label="FALHA(${EXIT_CODE})"
  fi
  log "INFO" "Finalizando ${status_label} em ${elapsed}s"
}

on_exit() {
  EXIT_CODE="$1"
  finish
}

trap 'on_err "${LINENO}" "${BASH_COMMAND}" "${FUNCNAME[0]:-main}"' ERR
trap 'on_exit "$?"' EXIT

run_as_root() {
  if [[ "${NEEDS_SUDO}" -eq 1 ]]; then
    sudo "$@"
  else
    "$@"
  fi
}

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

apt_repo_distro() {
  local id id_like
  id="$(. /etc/os-release && echo "${ID}")"
  id_like="$(. /etc/os-release && echo "${ID_LIKE:-}")"

  case " ${id} ${id_like} " in
    *" ubuntu "*)
      echo "ubuntu"
      ;;
    *" debian "*)
      echo "debian"
      ;;
    *)
      echo "${id}"
      ;;
  esac
}

reset_docker_apt_repo() {
  if [[ -f /etc/apt/sources.list.d/docker.list ]]; then
    info "Removendo repositório Docker antigo para evitar conflito"
    run_as_root rm -f /etc/apt/sources.list.d/docker.list
  fi
}

detect_pm() {
  if have_cmd apt-get; then
    echo "apt"
    return
  fi
  if have_cmd dnf; then
    echo "dnf"
    return
  fi
  if have_cmd pacman; then
    echo "pacman"
    return
  fi
  echo "unknown"
}

install_docker_apt() {
  info "Instalando Docker via apt"
  reset_docker_apt_repo
  info "Atualizando índice de pacotes"
  run_as_root apt-get update
  info "Instalando pré-requisitos do repositório Docker"
  run_as_root apt-get install -y ca-certificates curl gnupg lsb-release

  info "Configurando chave GPG do repositório Docker"
  run_as_root install -m 0755 -d /etc/apt/keyrings
  if [[ ! -f /etc/apt/keyrings/docker.gpg ]]; then
    curl -fsSL https://download.docker.com/linux/$(. /etc/os-release && echo "${ID}")/gpg \
      | run_as_root gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    run_as_root chmod a+r /etc/apt/keyrings/docker.gpg
  else
    info "Chave GPG do Docker já existe; reaproveitando"
  fi

  ARCH="$(dpkg --print-architecture)"
  CODENAME="$(. /etc/os-release && echo "${VERSION_CODENAME}")"
  DOCKER_DISTRO="$(apt_repo_distro)"
  info "Adicionando repositório Docker para ${DOCKER_DISTRO} ${CODENAME} (${ARCH})"
  echo \
    "deb [arch=${ARCH} signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/${DOCKER_DISTRO} ${CODENAME} stable" \
    | run_as_root tee /etc/apt/sources.list.d/docker.list >/dev/null

  info "Instalando Docker Engine e plugin do Compose"
  run_as_root apt-get update
  run_as_root apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  info "Habilitando serviço docker"
  run_as_root systemctl enable --now docker
}

install_docker_dnf() {
  info "Instalando Docker via dnf"
  info "Instalando dependências do repositório"
  run_as_root dnf -y install dnf-plugins-core
  info "Adicionando repositório Docker"
  run_as_root dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
  info "Instalando Docker Engine e plugin do Compose"
  run_as_root dnf -y install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  info "Habilitando serviço docker"
  run_as_root systemctl enable --now docker
}

install_docker_pacman() {
  info "Instalando Docker via pacman"
  info "Instalando pacotes docker e docker-compose"
  run_as_root pacman -Sy --noconfirm docker docker-compose
  info "Habilitando serviço docker"
  run_as_root systemctl enable --now docker
}

ensure_project_files() {
  if [[ ! -f "${ROOT_DIR}/.env" && -f "${ROOT_DIR}/.env.example" ]]; then
    cp "${ROOT_DIR}/.env.example" "${ROOT_DIR}/.env"
    info "Criado .env a partir do exemplo"
  elif [[ -f "${ROOT_DIR}/.env" ]]; then
    info ".env já existe; mantendo arquivo atual"
  fi

  if [[ ! -f "${ROOT_DIR}/configs/inventory.json" && -f "${ROOT_DIR}/configs/inventory.example.json" ]]; then
    cp "${ROOT_DIR}/configs/inventory.example.json" "${ROOT_DIR}/configs/inventory.json"
    info "Criado configs/inventory.json a partir do exemplo"
  elif [[ -f "${ROOT_DIR}/configs/inventory.json" ]]; then
    info "configs/inventory.json já existe; mantendo arquivo atual"
  fi
}

main() {
  local pm
  info "Iniciando bootstrap do projeto em ${ROOT_DIR}"
  pm="$(detect_pm)"
  info "Gerenciador de pacotes detectado: ${pm}"

  case "${pm}" in
    apt)
      install_docker_apt
      ;;
    dnf)
      install_docker_dnf
      ;;
    pacman)
      install_docker_pacman
      ;;
    *)
      error "Nenhum gerenciador suportado encontrado. Este script espera apt, dnf ou pacman."
      exit 1
      ;;
  esac

  if [[ "${NEEDS_SUDO}" -eq 1 ]] && getent group docker >/dev/null 2>&1; then
    info "Adicionando usuário ao grupo docker"
    if run_as_root usermod -aG docker "${SUDO_USER:-$USER}"; then
      warn "Usuário adicionado ao grupo docker. Faça logout/login para a mudança valer."
    else
      warn "Não foi possível adicionar o usuário ao grupo docker; faça isso manualmente se precisar usar Docker sem sudo."
    fi
  fi

  ensure_project_files

  info "Docker instalado e projeto preparado"
  info "Próximo passo: cd \"${ROOT_DIR}\" && docker compose build"
}

main "$@"
