#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

DASHBOARD_CERT="${DASHBOARD_CERT:-/etc/wazuh-dashboard/certs/dashboard.pem}"
DASHBOARD_KEY="${DASHBOARD_KEY:-/etc/wazuh-dashboard/certs/dashboard-key.pem}"
DASHBOARD_SERVICE="${DASHBOARD_SERVICE:-wazuh-dashboard}"
CERT_DAYS="${CERT_DAYS:-825}"

log() {
  echo "[+] $*"
}

warn() {
  echo "[!] $*" >&2
}

die() {
  echo "[x] $*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Uso:
  sudo ./scripts/regenerate-wazuh-cert-with-san.sh [hostname-fqdn]

Argumentos:
  hostname-fqdn  FQDN externo real usado pelos clientes, ex:
                 wazuh.example.com

Variáveis opcionais:
  DASHBOARD_CERT     Caminho do certificado atual
  DASHBOARD_KEY      Caminho da chave atual
  DASHBOARD_SERVICE  Serviço a reiniciar após substituir o certificado
  CERT_DAYS          Validade do novo certificado em dias
EOF
}

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    die "Execute como root: sudo $0 [hostname-fqdn]"
  fi
}

validate_hostname() {
  local value="$1"
  if [[ -z "${value}" ]]; then
    die "Hostname vazio."
  fi
  if [[ "${value}" =~ [[:space:]/] ]]; then
    die "Hostname inválido: não use espaços ou barras."
  fi
}

resolve_primary_hostname() {
  local provided="${1:-}"
  local detected=""

  if [[ -n "${provided}" ]]; then
    validate_hostname "${provided}"
    printf '%s\n' "${provided}"
    return 0
  fi

  detected="$(hostname -f 2>/dev/null || true)"
  detected="${detected%%$'\r'}"
  validate_hostname "${detected}"

  if [[ "${detected}" != *.* ]]; then
    warn "hostname -f retornou '${detected}', que parece ser apenas hostname curto."
    warn "Isso provavelmente não é o FQDN externo usado pelos clientes."
    die "Reexecute passando o hostname real: sudo $0 <hostname-fqdn>"
  fi

  printf '%s\n' "${detected}"
}

file_owner_group() {
  local path="$1"
  stat -c '%U:%G' "${path}"
}

file_mode() {
  local path="$1"
  stat -c '%a' "${path}"
}

main() {
  if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    usage
    return 0
  fi

  if [[ "$#" -gt 1 ]]; then
    usage >&2
    return 2
  fi

  require_root

  local primary_hostname short_hostname ts workdir openssl_conf
  local cert_owner cert_mode key_owner key_mode
  local new_cert new_key backup_dir

  primary_hostname="$(resolve_primary_hostname "${1:-}")"
  short_hostname="$(hostname -s 2>/dev/null || true)"
  short_hostname="${short_hostname%%$'\r'}"
  validate_hostname "${short_hostname}"

  if [[ ! -f "${DASHBOARD_CERT}" ]]; then
    die "Certificado atual não encontrado: ${DASHBOARD_CERT}"
  fi
  if [[ ! -f "${DASHBOARD_KEY}" ]]; then
    die "Chave atual não encontrada: ${DASHBOARD_KEY}"
  fi

  ts="$(date +%Y%m%d-%H%M%S)"
  backup_dir="$(dirname "${DASHBOARD_CERT}")/backup-san-${ts}"
  workdir="$(mktemp -d)"
  openssl_conf="${workdir}/openssl-san.cnf"
  new_cert="${workdir}/dashboard.pem"
  new_key="${workdir}/dashboard-key.pem"

  cleanup() {
    rm -rf "${workdir}"
  }
  trap cleanup EXIT

  cert_owner="$(file_owner_group "${DASHBOARD_CERT}")"
  cert_mode="$(file_mode "${DASHBOARD_CERT}")"
  key_owner="$(file_owner_group "${DASHBOARD_KEY}")"
  key_mode="$(file_mode "${DASHBOARD_KEY}")"

  install -d -m 0750 "${backup_dir}"
  cp -a "${DASHBOARD_CERT}" "${backup_dir}/"
  cp -a "${DASHBOARD_KEY}" "${backup_dir}/"
  log "Backup criado em ${backup_dir}"

  cat > "${openssl_conf}" <<EOF
[req]
default_bits = 2048
prompt = no
default_md = sha256
x509_extensions = v3_req
distinguished_name = dn

[dn]
CN = ${primary_hostname}

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${primary_hostname}
DNS.2 = ${short_hostname}
IP.1 = 127.0.0.1
EOF

  log "Gerando certificado com SAN principal ${primary_hostname}"
  openssl req -x509 -nodes -newkey rsa:2048 \
    -days "${CERT_DAYS}" \
    -keyout "${new_key}" \
    -out "${new_cert}" \
    -config "${openssl_conf}"

  install -o "${cert_owner%:*}" -g "${cert_owner#*:}" -m "${cert_mode}" "${new_cert}" "${DASHBOARD_CERT}"
  install -o "${key_owner%:*}" -g "${key_owner#*:}" -m "${key_mode}" "${new_key}" "${DASHBOARD_KEY}"

  log "Reiniciando ${DASHBOARD_SERVICE}"
  systemctl restart "${DASHBOARD_SERVICE}"

  log "Validando SAN do certificado final"
  local san_output
  san_output="$(openssl x509 -in "${DASHBOARD_CERT}" -noout -text | grep -A1 'Subject Alternative Name' || true)"
  printf '%s\n' "${san_output}"

  if [[ "${san_output}" != *"DNS:${primary_hostname}"* ]]; then
    die "SAN final não contém DNS:${primary_hostname}"
  fi
  if [[ "${san_output}" != *"DNS:${short_hostname}"* ]]; then
    die "SAN final não contém DNS:${short_hostname}"
  fi
  if [[ "${san_output}" != *"IP Address:127.0.0.1"* ]]; then
    die "SAN final não contém IP Address:127.0.0.1"
  fi

  log "Certificado regenerado com sucesso."
}

main "$@"
