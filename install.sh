#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

APP_USER="${APP_USER:-hmg-soar}"
WEB_GROUP="${WEB_GROUP:-www-data}"
APP_DIR="${APP_DIR:-/opt/hmg-soar}"
WEB_DIR="${WEB_DIR:-/var/www/wazuh-soar}"
ETC_DIR="${ETC_DIR:-/etc/hmg-soar}"
HTPASSWD_FILE="${HTPASSWD_FILE:-/etc/nginx/.htpasswd-wazuh-soar}"
SNIPPET_FILE="${SNIPPET_FILE:-/etc/nginx/snippets/eyemole-soar-locations.conf}"
SERVICE_FILE="${SERVICE_FILE:-hmg-soar-report.service}"
TIMER_FILE="${TIMER_FILE:-hmg-soar-report.timer}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TS="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="/opt/backup-eyemole-install-${TS}"

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

need_root() {
if [[ "${EUID}" -ne 0 ]]; then
die "Execute como root: sudo ./install.sh"
fi
}

install_package_if_missing() {
local bin_name="$1"
local pkg_name="$2"

if command -v "${bin_name}" >/dev/null 2>&1; then
return 0
fi

if command -v apt-get >/dev/null 2>&1; then
log "Instalando pacote necessário: ${pkg_name}"
apt-get update -y
apt-get install -y "${pkg_name}"
else
die "Comando '${bin_name}' ausente. Instale o pacote '${pkg_name}' manualmente."
fi
}

backup_path() {
local path="$1"

if [[ -e "${path}" ]]; then
mkdir -p "${BACKUP_DIR}"
cp -a "${path}" "${BACKUP_DIR}/"
log "Backup: ${path} -> ${BACKUP_DIR}/"
fi
}

create_user_and_dirs() {
log "Preparando usuário, grupo e diretórios..."

if ! getent group "${WEB_GROUP}" >/dev/null 2>&1; then
groupadd --system "${WEB_GROUP}"
fi

if ! id "${APP_USER}" >/dev/null 2>&1; then
useradd 
--system 
--home-dir "${APP_DIR}" 
--shell /usr/sbin/nologin 
--gid "${WEB_GROUP}" 
"${APP_USER}"
fi

install -d -o "${APP_USER}" -g "${WEB_GROUP}" -m 0755 "${APP_DIR}"
install -d -o "${APP_USER}" -g "${WEB_GROUP}" -m 0750 "${APP_DIR}/config"
install -d -o "${APP_USER}" -g "${WEB_GROUP}" -m 0755 "${APP_DIR}/assets"
install -d -o "${APP_USER}" -g "${WEB_GROUP}" -m 0755 "${APP_DIR}/output"
install -d -o "${APP_USER}" -g "${WEB_GROUP}" -m 0755 "${APP_DIR}/.hmg_cache"

install -d -o root -g "${WEB_GROUP}" -m 2775 "${WEB_DIR}"
install -d -o "${APP_USER}" -g "${WEB_GROUP}" -m 2775 "${WEB_DIR}/assets"
install -d -o root -g "${WEB_GROUP}" -m 2775 "${WEB_DIR}/data"
install -d -o root -g "${WEB_GROUP}" -m 2775 "${WEB_DIR}/reports"

install -d -o root -g root -m 0755 "${ETC_DIR}"
}

install_app_files() {
  log "Instalando aplicação em ${APP_DIR}..."

  [[ -f "${REPO_ROOT}/opt/hmg-soar/analyserV1.py" ]] || die "Arquivo não encontrado: opt/hmg-soar/analyserV1.py"

  rsync -a --delete \
    --exclude 'config/' \
    --exclude 'output/' \
    --exclude '.hmg_cache/' \
    --exclude '__pycache__/' \
    "${REPO_ROOT}/opt/hmg-soar/" \
    "${APP_DIR}/"

  chown -R "${APP_USER}:${WEB_GROUP}" "${APP_DIR}"

  rm -rf "${APP_DIR}/__pycache__"
  install -d -o "${APP_USER}" -g "${WEB_GROUP}" -m 0755 "${APP_DIR}/__pycache__"

  if [[ -f "${APP_DIR}/assets/eyemole.png" ]]; then
    install -o "${APP_USER}" -g "${WEB_GROUP}" -m 0644 \
      "${APP_DIR}/assets/eyemole.png" \
      "${WEB_DIR}/assets/eyemole.png"
  fi
}

validate_python() {
log "Validando sintaxe Python..."

runuser -u "${APP_USER}" -- python3 -m py_compile "${APP_DIR}/analyserV1.py"

if [[ -f "${APP_DIR}/preview_dashboard.py" ]]; then
runuser -u "${APP_USER}" -- python3 -m py_compile "${APP_DIR}/preview_dashboard.py"
fi

if [[ -f "${APP_DIR}/preview_server.py" ]]; then
runuser -u "${APP_USER}" -- python3 -m py_compile "${APP_DIR}/preview_server.py"
fi
}

install_systemd() {
log "Instalando unidades systemd, se existirem no repositório..."

if [[ -f "${REPO_ROOT}/systemd/${SERVICE_FILE}" ]]; then
install -o root -g root -m 0644 
"${REPO_ROOT}/systemd/${SERVICE_FILE}" 
"/etc/systemd/system/${SERVICE_FILE}"
else
warn "Service não encontrado no repo: systemd/${SERVICE_FILE}"
fi

if [[ -f "${REPO_ROOT}/systemd/${TIMER_FILE}" ]]; then
install -o root -g root -m 0644 
"${REPO_ROOT}/systemd/${TIMER_FILE}" 
"/etc/systemd/system/${TIMER_FILE}"
else
warn "Timer não encontrado no repo: systemd/${TIMER_FILE}"
fi

systemctl daemon-reload

if [[ -f "/etc/systemd/system/${TIMER_FILE}" ]]; then
systemctl enable "${TIMER_FILE}" >/dev/null 2>&1 || true
fi
}

install_nginx_snippet() {
log "Instalando snippet Nginx para /soar/..."

install -d -o root -g root -m 0755 /etc/nginx/snippets

touch "${HTPASSWD_FILE}"
chown root:"${WEB_GROUP}" "${HTPASSWD_FILE}"
chmod 0640 "${HTPASSWD_FILE}"

cat > "${SNIPPET_FILE}" <<EOF
location = /soar {
return 301 /soar/;
}

location ^~ /soar/assets/ {
alias ${WEB_DIR}/assets/;
auth_basic "HMG SOAR - Acesso Restrito";
auth_basic_user_file ${HTPASSWD_FILE};
try_files $uri =404;

```
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
```

}

location ^~ /soar/data/ {
alias ${WEB_DIR}/data/;
auth_basic "HMG SOAR - Acesso Restrito";
auth_basic_user_file ${HTPASSWD_FILE};
try_files $uri =404;

```
default_type application/json;
add_header Cache-Control "no-cache, no-store, must-revalidate" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
```

}

location ^~ /soar/reports/ {
alias ${WEB_DIR}/reports/;
auth_basic "HMG SOAR - Acesso Restrito";
auth_basic_user_file ${HTPASSWD_FILE};
try_files $uri =404;

```
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
```

}

location ^~ /soar/ {
alias ${WEB_DIR}/;
index index.html;
auth_basic "HMG SOAR - Acesso Restrito";
auth_basic_user_file ${HTPASSWD_FILE};
try_files $uri $uri/ =404;

```
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Cache-Control "no-cache, no-store, must-revalidate" always;
```

}

location /soar-api/ {
auth_basic "HMG SOAR - Acesso Restrito";
auth_basic_user_file ${HTPASSWD_FILE};

```
proxy_pass http://127.0.0.1:8765/;
proxy_http_version 1.1;
proxy_set_header Host \$host;
proxy_set_header X-Real-IP \$remote_addr;
proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto \$scheme;
```

}
EOF

chown root:root "${SNIPPET_FILE}"
chmod 0644 "${SNIPPET_FILE}"
}

inject_nginx_include() {
log "Procurando server block do Wazuh Dashboard para incluir /soar/..."

local target_conf=""

target_conf="$(grep -RIl "proxy_pass https://127.0.0.1:5601" 
/etc/nginx/sites-available 
/etc/nginx/conf.d 
/etc/nginx/nginx.conf 2>/dev/null | head -n 1 || true)"

if [[ -z "${target_conf}" ]]; then
warn "Não encontrei automaticamente o server block do Wazuh Dashboard."
warn "Inclua manualmente dentro do server block HTTPS:"
warn "include ${SNIPPET_FILE};"
return 0
fi

if grep -q "${SNIPPET_FILE}" "${target_conf}"; then
log "Include Nginx já existe em: ${target_conf}"
return 0
fi

backup_path "${target_conf}"

python3 - "${target_conf}" "${SNIPPET_FILE}" <<'PY'
import re
import sys
from pathlib import Path

conf_path = Path(sys.argv[1])
snippet = sys.argv[2]

text = conf_path.read_text(encoding="utf-8").splitlines()

include_line = f"    include {snippet};"

if any(snippet in line for line in text):
sys.exit(0)

out = []
inserted = False

for line in text:
if not inserted and re.match(r"^\s*location\s+/\s*{", line):
out.append(include_line)
inserted = True
out.append(line)

if not inserted:
print(f"ERRO: não encontrei 'location / {{' em {conf_path}", file=sys.stderr)
sys.exit(2)

conf_path.write_text("\n".join(out) + "\n", encoding="utf-8")
PY

log "Include inserido em: ${target_conf}"
}

reload_nginx() {
log "Validando e recarregando Nginx..."

nginx -t
systemctl reload nginx
}

run_report_once_if_possible() {
if [[ ! -f "/etc/systemd/system/${SERVICE_FILE}" ]]; then
warn "Service systemd não instalado. Pulando execução."
return 0
fi

if [[ ! -f "${ETC_DIR}/credentials.env" ]]; then
warn "Arquivo ${ETC_DIR}/credentials.env não encontrado."
warn "Instalação concluída, mas o relatório real não será executado até configurar credenciais."
return 0
fi

log "Executando serviço real uma vez para publicar o dashboard..."
systemctl restart "${SERVICE_FILE}"

log "Últimas linhas do serviço:"
journalctl -u "${SERVICE_FILE}" -n 40 --no-pager || true
}

final_message() {
echo
echo "============================================================"
echo "EyeMole SOAR instalado."
echo "App dir : ${APP_DIR}"
echo "Web dir : ${WEB_DIR}"
echo "URL     : https://<servidor>/soar/"
echo
echo "Próximo passo:"
echo "sudo ./create-web-user.sh <usuario>"
echo
echo "Backup desta instalação:"
echo "${BACKUP_DIR}"
echo "============================================================"
}

main() {
need_root

install_package_if_missing python3 python3
install_package_if_missing rsync rsync
install_package_if_missing nginx nginx

mkdir -p "${BACKUP_DIR}"

backup_path "${APP_DIR}"
backup_path "${WEB_DIR}"
backup_path "${HTPASSWD_FILE}"
backup_path "${SNIPPET_FILE}"

create_user_and_dirs
install_app_files
validate_python
install_systemd
install_nginx_snippet
inject_nginx_include
reload_nginx
run_report_once_if_possible
final_message
}

main "$@"
