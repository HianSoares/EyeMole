#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

CONFIG_DIR="/etc/eyemole-agent"
CONFIG_FILE="${CONFIG_DIR}/agent.conf"
TOKEN_FILE="${CONFIG_DIR}/token"
INSTALL_PATH="/usr/local/sbin/eyemole-generate-upload-sbom"
LOG_DIR="/var/log/eyemole-agent"
WORK_DIR="/var/lib/eyemole-agent"
SERVICE_PATH="/etc/systemd/system/eyemole-sbom.service"
TIMER_PATH="/etc/systemd/system/eyemole-sbom.timer"

AGENT_ID=""
EYEMOLE_SOAR_URL=""
TOKEN_VALUE=""
TOKEN_SOURCE=""
CA_CERT_PATH=""
SCAN_TARGETS=()

usage() {
  cat <<'EOF'
Usage:
  sudo ./install-agent-script.sh --agent-id <id> --server-url <url> (--token <token> | --token-file <file>) [options]

Options:
  --ca-cert <path>          Optional CA certificate path for self-signed Wazuh TLS.
  --scan-target <target>    Syft target. Can be repeated. Defaults to dpkg or rpm DB.
EOF
}

detect_default_scan_target() {
  if [[ -d /var/lib/dpkg ]]; then
    echo "dir:/var/lib/dpkg"
    return
  fi

  if [[ -d /var/lib/rpm ]]; then
    echo "dir:/var/lib/rpm"
    return
  fi

  echo "dir:/"
}

shell_quote() {
  printf "'%s'" "$(printf "%s" "$1" | sed "s/'/'\\\\''/g")"
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --agent-id)
        AGENT_ID="${2:-}"
        shift 2
        ;;
      --server-url)
        EYEMOLE_SOAR_URL="${2:-}"
        shift 2
        ;;
      --token)
        TOKEN_VALUE="${2:-}"
        shift 2
        ;;
      --token-file)
        TOKEN_SOURCE="${2:-}"
        shift 2
        ;;
      --ca-cert)
        CA_CERT_PATH="${2:-}"
        shift 2
        ;;
      --scan-target)
        SCAN_TARGETS+=("${2:-}")
        shift 2
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        echo "Unknown argument: $1" >&2
        usage >&2
        exit 2
        ;;
    esac
  done
}

validate_args() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "This installer must run as root." >&2
    exit 1
  fi

  if [[ -z "${AGENT_ID}" || -z "${EYEMOLE_SOAR_URL}" ]]; then
    usage >&2
    exit 2
  fi

  if [[ -n "${TOKEN_VALUE}" && -n "${TOKEN_SOURCE}" ]]; then
    echo "Use either --token or --token-file, not both." >&2
    exit 2
  fi

  if [[ -z "${TOKEN_VALUE}" && -z "${TOKEN_SOURCE}" ]]; then
    echo "A token is required via --token or --token-file." >&2
    exit 2
  fi

  if [[ -n "${TOKEN_SOURCE}" && ! -r "${TOKEN_SOURCE}" ]]; then
    echo "Token source is not readable: ${TOKEN_SOURCE}" >&2
    exit 1
  fi

  if [[ -n "${CA_CERT_PATH}" && ! -r "${CA_CERT_PATH}" ]]; then
    echo "CA certificate path is not readable: ${CA_CERT_PATH}" >&2
    exit 1
  fi
}

install_files() {
  install -d -m 0755 "${CONFIG_DIR}" "${LOG_DIR}" "${WORK_DIR}"
  install -m 0755 "${SCRIPT_DIR}/generate_and_upload_sbom.sh" "${INSTALL_PATH}"
  install -m 0644 "${SCRIPT_DIR}/eyemole-sbom.service" "${SERVICE_PATH}"
  install -m 0644 "${SCRIPT_DIR}/eyemole-sbom.timer" "${TIMER_PATH}"

  if [[ -n "${TOKEN_SOURCE}" ]]; then
    install -m 0600 "${TOKEN_SOURCE}" "${TOKEN_FILE}"
  else
    printf '%s\n' "${TOKEN_VALUE}" > "${TOKEN_FILE}"
    chmod 0600 "${TOKEN_FILE}"
  fi
  chown root:root "${TOKEN_FILE}"
}

write_config() {
  if [[ "${#SCAN_TARGETS[@]}" -eq 0 ]]; then
    SCAN_TARGETS+=("$(detect_default_scan_target)")
  fi

  {
    printf 'AGENT_ID=%s\n' "$(shell_quote "${AGENT_ID}")"
    printf 'EYEMOLE_SOAR_URL=%s\n' "$(shell_quote "${EYEMOLE_SOAR_URL}")"
    printf 'TOKEN_FILE=%s\n' "$(shell_quote "${TOKEN_FILE}")"
    printf 'CA_CERT_PATH=%s\n' "$(shell_quote "${CA_CERT_PATH}")"
    printf 'CONNECT_TIMEOUT=10\n'
    printf 'MAX_TIME=180\n'
    printf 'RETRY_COUNT=2\n'
    printf 'SCAN_TARGETS=('
    local target
    for target in "${SCAN_TARGETS[@]}"; do
      printf '%s ' "$(shell_quote "${target}")"
    done
    printf ')\n'
  } > "${CONFIG_FILE}"

  chmod 0644 "${CONFIG_FILE}"
  chown root:root "${CONFIG_FILE}"
}

enable_timer() {
  systemctl daemon-reload
  systemctl enable --now eyemole-sbom.timer
}

main() {
  parse_args "$@"
  validate_args
  install_files
  write_config
  enable_timer
  echo "EyeMole SBOM agent installed. Check with: systemctl status eyemole-sbom.timer"
}

main "$@"
