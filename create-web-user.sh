#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

WEB_GROUP="${WEB_GROUP:-www-data}"
HTPASSWD_FILE="${HTPASSWD_FILE:-/etc/nginx/.htpasswd-wazuh-soar}"

usage() {
echo "Uso:"
echo "  sudo ./create-web-user.sh <usuario>"
echo
echo "Exemplo:"
echo "  sudo ./create-web-user.sh admasc"
}

die() {
echo "[x] $*" >&2
exit 1
}

log() {
echo "[+] $*"
}

need_root() {
if [[ "${EUID}" -ne 0 ]]; then
die "Execute como root: sudo ./create-web-user.sh <usuario>"
fi
}

install_htpasswd_if_missing() {
if command -v htpasswd >/dev/null 2>&1; then
return 0
fi

if command -v apt-get >/dev/null 2>&1; then
log "Instalando apache2-utils para usar htpasswd..."
apt-get update -y
apt-get install -y apache2-utils
else
die "Comando htpasswd ausente. Instale apache2-utils manualmente."
fi
}

validate_username() {
local username="$1"

if [[ -z "${username}" ]]; then
usage
exit 1
fi

if [[ ! "${username}" =~ ^[a-zA-Z0-9._-]{2,64}$ ]]; then
die "Usuário inválido. Use apenas letras, números, ponto, hífen ou underline. Tamanho: 2 a 64."
fi
}

prepare_file() {
if ! getent group "${WEB_GROUP}" >/dev/null 2>&1; then
groupadd --system "${WEB_GROUP}"
fi

touch "${HTPASSWD_FILE}"
chown root:"${WEB_GROUP}" "${HTPASSWD_FILE}"
chmod 0640 "${HTPASSWD_FILE}"
}

reload_nginx() {
nginx -t
systemctl reload nginx
}

main() {
need_root

local username="${1:-}"

validate_username "${username}"
install_htpasswd_if_missing
prepare_file

log "Criando/alterando senha web para usuário: ${username}"
htpasswd -B "${HTPASSWD_FILE}" "${username}"

log "Validando Nginx..."
reload_nginx

echo
echo "Usuário web configurado com sucesso."
echo "URL: https://<servidor>/soar/"
echo
echo "Observação:"
echo "Esse usuário é apenas do Basic Auth do Nginx."
echo "Ele não altera usuário Linux, SSH, Wazuh ou GitHub."
}

main "$@"
