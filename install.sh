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

# ====================================================================
# MODO DE OPERAÇÃO
# Padrão: MODO SEGURO (sem sudoers, sem NOPASSWD, sem execução manual via web).
# Opt-in (apenas ambiente controlado): habilita execução manual via web,
# instalando wrappers + regra sudoers RESTRITA.
#   EYEMOLE_ENABLE_WEB_RUN=1 sudo ./install.sh
#   sudo ./install.sh --enable-web-run
# ====================================================================
ENABLE_WEB_RUN="${EYEMOLE_ENABLE_WEB_RUN:-0}"
SUDOERS_FILE="${SUDOERS_FILE:-/etc/sudoers.d/hmg-soar-api}"
WRAPPER_RUN_ANALYSIS="/usr/local/sbin/hmg-soar-run-analysis"
WRAPPER_STATUS="/usr/local/sbin/hmg-soar-status"

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

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --enable-web-run)
        ENABLE_WEB_RUN=1
        ;;
      --safe|--no-web-run)
        ENABLE_WEB_RUN=0
        ;;
      -h|--help)
        echo "Uso: sudo ./install.sh [--enable-web-run]"
        echo
        echo "  Padrão (modo seguro): sem sudoers, sem NOPASSWD."
        echo "    A execução manual via web fica DESABILITADA. O relatório é"
        echo "    gerado automaticamente pelo timer hmg-soar-report.timer."
        echo
        echo "  --enable-web-run (opt-in, apenas ambiente controlado/HMG/lab):"
        echo "    instala wrappers + regra sudoers RESTRITA para habilitar o"
        echo "    botão 'Executar análise agora' no dashboard."
        echo "    Equivale a: EYEMOLE_ENABLE_WEB_RUN=1 sudo ./install.sh"
        exit 0
        ;;
      *)
        warn "Argumento ignorado: $1"
        ;;
    esac
    shift
  done
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
    useradd \
      --system \
      --home-dir "${APP_DIR}" \
      --shell /usr/sbin/nologin \
      --gid "${WEB_GROUP}" \
      "${APP_USER}"
  fi

  install -d -o "${APP_USER}" -g "${WEB_GROUP}" -m 0755 "${APP_DIR}"
  install -d -o "${APP_USER}" -g "${WEB_GROUP}" -m 0750 "${APP_DIR}/config"
  install -d -o "${APP_USER}" -g "${WEB_GROUP}" -m 0755 "${APP_DIR}/assets"
  install -d -o "${APP_USER}" -g "${WEB_GROUP}" -m 0755 "${APP_DIR}/output"
  install -d -o "${APP_USER}" -g "${WEB_GROUP}" -m 0755 "${APP_DIR}/.hmg_cache"

  # Diretório exigido pelo sandbox/ReadWritePaths do systemd da API.
  install -d -o "${APP_USER}" -g "${WEB_GROUP}" -m 0750 "${APP_DIR}/audit"
  touch "${APP_DIR}/audit/actions.log"
  chown "${APP_USER}:${WEB_GROUP}" "${APP_DIR}/audit/actions.log"
  chmod 0640 "${APP_DIR}/audit/actions.log"

  install -d -o root -g "${WEB_GROUP}" -m 2775 "${WEB_DIR}"
  install -d -o "${APP_USER}" -g "${WEB_GROUP}" -m 2775 "${WEB_DIR}/assets"
  install -d -o root -g "${WEB_GROUP}" -m 2775 "${WEB_DIR}/data"
  install -d -o root -g "${WEB_GROUP}" -m 2775 "${WEB_DIR}/reports"

  # Arquivo usado pela API para registrar ações exibidas em Status & Auditoria.
  touch "${WEB_DIR}/data/audit_actions.jsonl"
  chown "${APP_USER}:${WEB_GROUP}" "${WEB_DIR}/data/audit_actions.jsonl"
  chmod 0660 "${WEB_DIR}/data/audit_actions.jsonl"

  install -d -o root -g root -m 0755 "${ETC_DIR}"
}

ensure_api_audit_dirs() {
  log "Garantindo diretórios de auditoria da API..."

  install -d -o "${APP_USER}" -g "${WEB_GROUP}" -m 0750 "${APP_DIR}/audit"
  touch "${APP_DIR}/audit/actions.log"
  chown "${APP_USER}:${WEB_GROUP}" "${APP_DIR}/audit/actions.log"
  chmod 0640 "${APP_DIR}/audit/actions.log"

  install -d -o root -g "${WEB_GROUP}" -m 2775 "${WEB_DIR}/data"
  touch "${WEB_DIR}/data/audit_actions.jsonl"
  chown "${APP_USER}:${WEB_GROUP}" "${WEB_DIR}/data/audit_actions.jsonl"
  chmod 0660 "${WEB_DIR}/data/audit_actions.jsonl"
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

if [[ -f "${APP_DIR}/context_bootstrap.py" ]]; then
runuser -u "${APP_USER}" -- python3 -m py_compile "${APP_DIR}/context_bootstrap.py"
fi

if [[ -f "${APP_DIR}/preview_dashboard.py" ]]; then
runuser -u "${APP_USER}" -- python3 -m py_compile "${APP_DIR}/preview_dashboard.py"
fi

if [[ -f "${APP_DIR}/preview_server.py" ]]; then
runuser -u "${APP_USER}" -- python3 -m py_compile "${APP_DIR}/preview_server.py"
fi
}

configure_web_run_mode() {
  # No modo seguro padrão NÃO instalamos sudoers nem wrappers privilegiados.
  # O status do dashboard é lido pela API diretamente via 'systemctl show' (sem sudo).
  if [[ "${ENABLE_WEB_RUN}" == "1" ]]; then
    install_web_run_optin
  else
    enforce_safe_mode_no_sudoers
  fi
}

enforce_safe_mode_no_sudoers() {
  log "Modo seguro ativo: sudoers da API não será instalado. Execução manual via web ficará desabilitada."

  # Remover sudoers de instalação anterior, se existir (com backup).
  if [[ -f "${SUDOERS_FILE}" ]]; then
    backup_path "${SUDOERS_FILE}"
    rm -f "${SUDOERS_FILE}"
    log "Sudoers anterior removido: ${SUDOERS_FILE} (backup em ${BACKUP_DIR})."
  fi

  # Remover wrappers privilegiados antigos (inúteis e indesejados no modo seguro).
  if [[ -f "${WRAPPER_RUN_ANALYSIS}" || -f "${WRAPPER_STATUS}" ]]; then
    rm -f "${WRAPPER_RUN_ANALYSIS}" "${WRAPPER_STATUS}"
    log "Wrappers privilegiados anteriores removidos."
  fi
}

install_web_run_optin() {
  warn "EYEMOLE_ENABLE_WEB_RUN ativo: habilitando execução manual via web (sudoers RESTRITO)."
  warn "Use SOMENTE em ambiente controlado (HMG/lab). Em produção, prefira o modo seguro."

  log "Instalando wrapper de execução (run-analysis)..."
  # Wrapper run-analysis: dispara o serviço oneshot, sem argumentos do cliente.
  cat > "${WRAPPER_RUN_ANALYSIS}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
systemctl start hmg-soar-report.service
EOF

  chmod 0700 "${WRAPPER_RUN_ANALYSIS}"
  chown root:root "${WRAPPER_RUN_ANALYSIS}"

  # Regra sudoers RESTRITA: apenas o wrapper fixo de run-analysis.
  # (O status NÃO precisa de sudo: a API lê via 'systemctl show'.)
  log "Instalando regra sudoers restrita para a API..."
  cat > "${SUDOERS_FILE}" <<'EOF'
hmg-soar ALL=(ALL) NOPASSWD: /usr/local/sbin/hmg-soar-run-analysis
EOF

  chmod 0440 "${SUDOERS_FILE}"
  chown root:root "${SUDOERS_FILE}"

  # Validar sintaxe do sudoers, sem abortar a instalação se visudo faltar.
  if command -v visudo >/dev/null 2>&1; then
    if ! visudo -cf "${SUDOERS_FILE}" >/dev/null 2>&1; then
      warn "visudo reprovou ${SUDOERS_FILE}; removendo por segurança."
      rm -f "${SUDOERS_FILE}"
    fi
  fi
}

secure_credentials_env() {
  local cred="${ETC_DIR}/credentials.env"

  if [[ -f "${cred}" ]]; then
    # EnvironmentFile é lido pelo systemd como root antes de baixar privilégio,
    # portanto o usuário do serviço não precisa de leitura direta. Mantemos 0640
    # com grupo dedicado quando existir; caso contrário, root (sem www-data).
    local grp="root"
    if getent group "${APP_USER}" >/dev/null 2>&1; then
      grp="${APP_USER}"
    fi
    chown "root:${grp}" "${cred}"
    chmod 0640 "${cred}"
    log "Permissões de credentials.env ajustadas: root:${grp} 0640 (nunca www-data)."
  else
    warn "Credenciais não encontradas em ${cred}."
    warn "Crie-as com permissões seguras (sem expor valores em logs):"
    warn "  install -o root -g root -m 0640 /dev/null ${cred}"
    warn "  # edite ${cred} e defina as variáveis necessárias"
  fi
}

install_systemd() {
  log "Instalando unidades systemd, se existirem no repositório..."

  if [[ -f "${REPO_ROOT}/systemd/${SERVICE_FILE}" ]]; then
    install -o root -g root -m 0644 \
      "${REPO_ROOT}/systemd/${SERVICE_FILE}" \
      "/etc/systemd/system/${SERVICE_FILE}"
  else
    warn "Service não encontrado no repo: systemd/${SERVICE_FILE}"
  fi

  if [[ -f "${REPO_ROOT}/systemd/${TIMER_FILE}" ]]; then
    install -o root -g root -m 0644 \
      "${REPO_ROOT}/systemd/${TIMER_FILE}" \
      "/etc/systemd/system/${TIMER_FILE}"
  else
    warn "Timer não encontrado no repo: systemd/${TIMER_FILE}"
  fi

  API_SERVICE_FILE="hmg-soar-api.service"
  if [[ -f "${REPO_ROOT}/systemd/${API_SERVICE_FILE}" ]]; then
    install -o root -g root -m 0644 \
      "${REPO_ROOT}/systemd/${API_SERVICE_FILE}" \
      "/etc/systemd/system/${API_SERVICE_FILE}"
  else
    warn "Service API não encontrado no repo: systemd/${API_SERVICE_FILE}"
  fi

  systemctl daemon-reload

  if [[ -f "/etc/systemd/system/${TIMER_FILE}" ]]; then
    systemctl enable --now "${TIMER_FILE}" >/dev/null 2>&1 || true
  fi

  if [[ -f "/etc/systemd/system/${API_SERVICE_FILE}" ]]; then
    systemctl enable --now "${API_SERVICE_FILE}" >/dev/null 2>&1 || true
    systemctl restart "${API_SERVICE_FILE}" >/dev/null 2>&1 || true
  fi
}

install_nginx_snippet() {
  log "Instalando snippet Nginx para /soar/..."

  install -d -o root -g root -m 0755 /etc/nginx/snippets

  touch "${HTPASSWD_FILE}"
  chown root:"${WEB_GROUP}" "${HTPASSWD_FILE}"
  chmod 0640 "${HTPASSWD_FILE}"

  cat > "${SNIPPET_FILE}" <<NGINX_EYEMOLE_SNIPPET
location = /soar {
    return 301 /soar/;
}

location ^~ /soar/assets/ {
    alias ${WEB_DIR}/assets/;
    autoindex off;
    auth_basic "HMG SOAR - Acesso Restrito";
    auth_basic_user_file ${HTPASSWD_FILE};
    try_files \$uri =404;

    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
}

location ^~ /soar/data/ {
    alias ${WEB_DIR}/data/;
    autoindex off;
    auth_basic "HMG SOAR - Acesso Restrito";
    auth_basic_user_file ${HTPASSWD_FILE};
    try_files \$uri =404;

    default_type application/json;
    add_header Cache-Control "no-cache, no-store, must-revalidate" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
}

location ^~ /soar/reports/ {
    alias ${WEB_DIR}/reports/;
    autoindex off;
    auth_basic "HMG SOAR - Acesso Restrito";
    auth_basic_user_file ${HTPASSWD_FILE};
    try_files \$uri =404;

    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
}

location ^~ /soar/ {
    alias ${WEB_DIR}/;
    index index.html;
    autoindex off;
    auth_basic "HMG SOAR - Acesso Restrito";
    auth_basic_user_file ${HTPASSWD_FILE};
    try_files \$uri \$uri/ =404;

    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Cache-Control "no-cache, no-store, must-revalidate" always;
}

location /soar-api/ {
    auth_basic "HMG SOAR - Acesso Restrito";
    auth_basic_user_file ${HTPASSWD_FILE};

    autoindex off;
    add_header Cache-Control "no-store" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Proxy SOMENTE para a API local em 127.0.0.1:8765 (nunca exposta na rede).
    proxy_pass http://127.0.0.1:8765/;
    proxy_http_version 1.1;
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto \$scheme;
    proxy_set_header X-Remote-User \$remote_user;
}
NGINX_EYEMOLE_SNIPPET

  chown root:root "${SNIPPET_FILE}"
  chmod 0644 "${SNIPPET_FILE}"
}

inject_nginx_include() {
  log "Procurando server block do Wazuh Dashboard para incluir /soar/..."

  local target_conf=""

  # Procurar o server block ATIVO do Wazuh Dashboard, priorizando sites-enabled
  # para evitar instalar o include no arquivo errado (problema visto no HMG).
  local search_paths=(
    /etc/nginx/sites-enabled
    /etc/nginx/sites-available
    /etc/nginx/conf.d
    /etc/nginx/nginx.conf
  )

  local sp
  for sp in "${search_paths[@]}"; do
    [[ -e "${sp}" ]] || continue
    target_conf="$(grep -RIl 'proxy_pass https://127.0.0.1:5601' "${sp}" 2>/dev/null | head -n 1 || true)"
    if [[ -n "${target_conf}" ]]; then
      log "Server block do Wazuh Dashboard encontrado em: ${target_conf} (origem: ${sp})"
      break
    fi
  done

  if [[ -z "${target_conf}" ]]; then
    warn "Não encontrei automaticamente o server block do Wazuh Dashboard."
    warn "Inclua manualmente dentro do server block HTTPS:"
    warn "include ${SNIPPET_FILE};"
    return 0
  fi

  if grep -Fq "include ${SNIPPET_FILE};" "${target_conf}"; then
    log "Include Nginx já existe em: ${target_conf}"
    return 0
  fi

  backup_path "${target_conf}"

  python3 -c '
import re
import sys
from pathlib import Path

conf_path = Path(sys.argv[1])
snippet = sys.argv[2]

lines = conf_path.read_text(encoding="utf-8").splitlines()
include_line = f"    include {snippet};"

if any(snippet in line for line in lines):
    sys.exit(0)

out = []
inserted = False

for line in lines:
    if not inserted and re.match(r"^\s*location\s+/\s*\{", line):
        out.append(include_line)
        inserted = True
    out.append(line)

if not inserted:
    print(f"ERRO: não encontrei location / em {conf_path}", file=sys.stderr)
    sys.exit(2)

conf_path.write_text("\n".join(out) + "\n", encoding="utf-8")
' "${target_conf}" "${SNIPPET_FILE}"

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

  if [[ -f "${ETC_DIR}/credentials.env" ]]; then
    log "Executando serviço real uma vez para publicar o dashboard..."
    systemctl restart "${SERVICE_FILE}" || true
  else
    warn "Arquivo ${ETC_DIR}/credentials.env não encontrado. Gerando bootstrap inicial offline."
  fi

  log "Executando bootstrap de contexto (context_bootstrap.py)..."
  python3 "${APP_DIR}/context_bootstrap.py" --auto || true

  if [[ -f "${ETC_DIR}/credentials.env" ]]; then
    log "Executando novamente hmg-soar-report.service após o bootstrap..."
    systemctl restart "${SERVICE_FILE}" || true
    log "Últimas linhas do serviço:"
    journalctl -u "${SERVICE_FILE}" -n 40 --no-pager || true
  fi
}

final_message() {
echo
echo "============================================================"
echo "EyeMole SOAR instalado."
echo "App dir : ${APP_DIR}"
echo "Web dir : ${WEB_DIR}"
echo "URL     : https://<servidor>/soar/"
if [[ "${ENABLE_WEB_RUN}" == "1" ]]; then
echo "Modo    : WEB-RUN (opt-in) - execução manual via web HABILITADA (sudoers restrito)"
else
echo "Modo    : SEGURO (padrão) - sem sudoers; execução manual via web DESABILITADA"
echo "          Relatório gerado automaticamente pelo timer hmg-soar-report.timer."
echo "          Execução manual (admin): sudo systemctl start hmg-soar-report.service"
fi
echo
echo "Próximo passo:"
echo "sudo ./create-web-user.sh <usuario>"
echo
echo "Backup desta instalação:"
echo "${BACKUP_DIR}"
echo "============================================================"
}

main() {
  parse_args "$@"
  need_root

  install_package_if_missing python3 python3
  install_package_if_missing rsync rsync
  install_package_if_missing nginx nginx

  mkdir -p "${BACKUP_DIR}"

  backup_path "${APP_DIR}"
  backup_path "${WEB_DIR}"
  backup_path "${HTPASSWD_FILE}"
  backup_path "${SNIPPET_FILE}"
  backup_path "${SUDOERS_FILE}"

  create_user_and_dirs
  install_app_files
  ensure_api_audit_dirs
  validate_python
  configure_web_run_mode
  secure_credentials_env
  install_systemd
  install_nginx_snippet
  inject_nginx_include
  reload_nginx
  run_report_once_if_possible
  ensure_api_audit_dirs
  final_message
}

main "$@"