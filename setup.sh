#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NEEDS_SUDO=0

if [[ "${EUID}" -ne 0 ]]; then
  NEEDS_SUDO=1
fi

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
  run_as_root apt-get update
  run_as_root apt-get install -y ca-certificates curl gnupg lsb-release

  run_as_root install -m 0755 -d /etc/apt/keyrings
  if [[ ! -f /etc/apt/keyrings/docker.gpg ]]; then
    curl -fsSL https://download.docker.com/linux/$(. /etc/os-release && echo "${ID}")/gpg \
      | run_as_root gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    run_as_root chmod a+r /etc/apt/keyrings/docker.gpg
  fi

  ARCH="$(dpkg --print-architecture)"
  CODENAME="$(. /etc/os-release && echo "${VERSION_CODENAME}")"
  echo \
    "deb [arch=${ARCH} signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/$(. /etc/os-release && echo "${ID}") ${CODENAME} stable" \
    | run_as_root tee /etc/apt/sources.list.d/docker.list >/dev/null

  run_as_root apt-get update
  run_as_root apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  run_as_root systemctl enable --now docker
}

install_docker_dnf() {
  run_as_root dnf -y install dnf-plugins-core
  run_as_root dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
  run_as_root dnf -y install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  run_as_root systemctl enable --now docker
}

install_docker_pacman() {
  run_as_root pacman -Sy --noconfirm docker docker-compose
  run_as_root systemctl enable --now docker
}

ensure_project_files() {
  if [[ ! -f "${ROOT_DIR}/.env" && -f "${ROOT_DIR}/.env.example" ]]; then
    cp "${ROOT_DIR}/.env.example" "${ROOT_DIR}/.env"
    echo "[OK] Criado .env a partir do exemplo."
  fi

  if [[ ! -f "${ROOT_DIR}/configs/inventory.json" && -f "${ROOT_DIR}/configs/inventory.example.json" ]]; then
    cp "${ROOT_DIR}/configs/inventory.example.json" "${ROOT_DIR}/configs/inventory.json"
    echo "[OK] Criado configs/inventory.json a partir do exemplo."
  fi
}

main() {
  local pm
  pm="$(detect_pm)"

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
      echo "Nenhum gerenciador suportado encontrado. Este script espera apt, dnf ou pacman." >&2
      exit 1
      ;;
  esac

  if [[ "${NEEDS_SUDO}" -eq 1 ]] && getent group docker >/dev/null 2>&1; then
    run_as_root usermod -aG docker "${SUDO_USER:-$USER}" || true
    echo "[OK] Usuário adicionado ao grupo docker. Faça logout/login para a mudança valer."
  fi

  ensure_project_files

  echo
  echo "[OK] Docker instalado e projeto preparado."
  echo "Próximo passo:"
  echo "  cd \"${ROOT_DIR}\" && docker compose build"
}

main "$@"
