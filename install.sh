#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

APP_USER="${APP_USER:-hmg-soar}"
WEB_GROUP="${WEB_GROUP:-www-data}"
NGINX_USER="${NGINX_USER:-www-data}"
APP_DIR="${APP_DIR:-/opt/hmg-soar}"
WEB_DIR="${WEB_DIR:-/var/www/wazuh-soar}"
ETC_DIR="${ETC_DIR:-/etc/hmg-soar}"
HTPASSWD_FILE="${HTPASSWD_FILE:-/etc/nginx/.htpasswd-wazuh-soar}"
SNIPPET_FILE="${SNIPPET_FILE:-/etc/nginx/snippets/eyemole-soar-locations.conf}"
SERVICE_FILE="${SERVICE_FILE:-hmg-soar-report.service}"
TIMER_FILE="${TIMER_FILE:-hmg-soar-report.timer}"
GRYPE_SERVICE_FILE="${GRYPE_SERVICE_FILE:-hmg-soar-grype.service}"
GRYPE_TIMER_FILE="${GRYPE_TIMER_FILE:-hmg-soar-grype.timer}"
SYSTEMD_UNIT_DIR="${SYSTEMD_UNIT_DIR:-/etc/systemd/system}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TS="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="/opt/backup-eyemole-install-${TS}"

# ====================================================================
# MODO DE OPERAÇÃO
# Padrão: MODO SEGURO (sem sudoers, sem NOPASSWD, sem execução manual via web).
# Opt-in (apenas ambiente controlado): habilita execução manual via web
# instalando uma regra PolicyKit RESTRITA (sem sudoers/NOPASSWD). A API pede
# ao systemd (systemctl start) o start da unidade de relatório; o PolicyKit
# autoriza APENAS o usuário hmg-soar a dar "start" APENAS na unidade
# hmg-soar-report.service. Compatível com NoNewPrivileges=yes do serviço.
#   EYEMOLE_ENABLE_WEB_RUN=1 sudo ./install.sh
#   sudo ./install.sh --enable-web-run
# ====================================================================
ENABLE_WEB_RUN="${EYEMOLE_ENABLE_WEB_RUN:-0}"
SUDOERS_FILE="${SUDOERS_FILE:-/etc/sudoers.d/hmg-soar-api}"
WRAPPER_RUN_ANALYSIS="/usr/local/sbin/hmg-soar-run-analysis"
WRAPPER_STATUS="/usr/local/sbin/hmg-soar-status"
# Mecanismo atual do opt-in: regra PolicyKit + marcador de estado único.
POLKIT_RULE_FILE="${POLKIT_RULE_FILE:-/etc/polkit-1/rules.d/49-hmg-soar.rules}"
WEB_RUN_FLAG="${WEB_RUN_FLAG:-${APP_DIR}/config/web_run.enabled}"
REPORT_SERVICE_UNIT="${REPORT_SERVICE_UNIT:-hmg-soar-report.service}"

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
        echo "    instala uma regra PolicyKit RESTRITA (sem sudoers/NOPASSWD) que"
        echo "    autoriza apenas o usuário hmg-soar a dar 'start' apenas na unidade"
        echo "    hmg-soar-report.service, habilitando o botão 'Executar análise agora'."
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

ensure_python_runtime_dependencies() {
  log "Verificando dependências Python de runtime..."

  if python3 -c "import requests, urllib3" 2>/dev/null; then
    log "Dependências Python de runtime já disponíveis."
    return 0
  fi

  log "Instalando dependências Python de runtime..."
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -y
    apt-get install -y python3-requests python3-urllib3
  else
    die "Módulos Python 'requests' e 'urllib3' ausentes. Instale-os manualmente (python3-requests, python3-urllib3)."
  fi

  if ! python3 -c "import requests, urllib3" 2>/dev/null; then
    die "Módulos Python 'requests' e 'urllib3' continuam indisponíveis após instalação."
  fi
  log "Dependências Python de runtime instaladas com sucesso."
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
  install -d -o "${APP_USER}" -g "${WEB_GROUP}" -m 0750 "${APP_DIR}/sbom"
  install -d -o "${APP_USER}" -g "${WEB_GROUP}" -m 0750 "${APP_DIR}/sbom/pending"
  install -d -o "${APP_USER}" -g "${WEB_GROUP}" -m 0750 "${APP_DIR}/sbom/processed"
  install -d -o "${APP_USER}" -g "${WEB_GROUP}" -m 0750 "${APP_DIR}/sbom/failed"

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

validate_json_configs() {
  log "Validando integridade dos JSONs obrigatórios..."
  local src_config="${REPO_ROOT}/opt/hmg-soar/config"
  local src_templates="${REPO_ROOT}/opt/hmg-soar/remediation/data/remediation_templates.json"

  local json_files=(
    "${src_config}/generic_update_policy.json"
    "${src_config}/remediation_allowlist.json"
    "${src_config}/remediation_providers.json"
    "${src_config}/risk_acceptance.json"
    "${src_config}/sla_policy.json"
    "${src_config}/treatment_policy.json"
    "${src_templates}"
  )

  local f
  for f in "${json_files[@]}"; do
    if [[ ! -f "${f}" ]]; then
      die "JSON obrigatório ausente no repositório: ${f}"
    fi
    if ! python3 -c "import json,sys; json.load(open(sys.argv[1]))" "${f}" 2>/dev/null; then
      die "JSON inválido: ${f}"
    fi
  done
  log "Todos os JSONs obrigatórios são válidos."
}

install_default_configs() {
  log "Instalando configurações padrão (somente se ausentes)..."
  local src_config="${REPO_ROOT}/opt/hmg-soar/config"
  local dest_config="${APP_DIR}/config"

  local config_files=(
    generic_update_policy.json
    remediation_allowlist.json
    remediation_providers.json
    risk_acceptance.json
    sla_policy.json
    treatment_policy.json
  )

  local f
  for f in "${config_files[@]}"; do
    local src="${src_config}/${f}"
    local dest="${dest_config}/${f}"
    if [[ ! -f "${src}" ]]; then
      die "Arquivo de configuração padrão ausente no repositório: ${src}"
    fi
    if [[ -f "${dest}" ]]; then
      log "  Preservado (existente): ${f}"
    else
      install -o "${APP_USER}" -g "${WEB_GROUP}" -m 0640 "${src}" "${dest}"
      log "  Instalado: ${f}"
    fi
  done
}

install_app_files() {
  log "Instalando aplicação em ${APP_DIR}..."

  [[ -f "${REPO_ROOT}/opt/hmg-soar/analyserV1.py" ]] || die "Arquivo não encontrado: opt/hmg-soar/analyserV1.py"

  rsync -a --delete \
    --exclude 'config/' \
    --exclude 'output/' \
    --exclude 'sbom/' \
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
  log "Validando sintaxe Python de todos os módulos de produção..."

  local py_files=()
  py_files+=("${APP_DIR}/analyserV1.py")
  py_files+=("${APP_DIR}/soar_api.py")
  py_files+=("${APP_DIR}/grype_runner.py")

  # Módulos opcionais
  local optional
  for optional in context_bootstrap.py preview_dashboard.py preview_server.py; do
    if [[ -f "${APP_DIR}/${optional}" ]]; then
      py_files+=("${APP_DIR}/${optional}")
    fi
  done

  # Todos os .py em remediation/
  while IFS= read -r -d '' pyf; do
    py_files+=("${pyf}")
  done < <(find "${APP_DIR}/remediation" -name '*.py' -print0 2>/dev/null || true)

  local f
  for f in "${py_files[@]}"; do
    if ! PYTHONDONTWRITEBYTECODE=1 runuser -u "${APP_USER}" -- python3 -c "
import sys, py_compile
try:
    py_compile.compile(sys.argv[1], doraise=True)
except py_compile.PyCompileError as e:
    print(f'Erro de sintaxe: {e}', file=sys.stderr)
    sys.exit(1)
" "${f}"; then
      die "Falha na validação Python: ${f}"
    fi
  done

  # Smoke test de importação (sem iniciar servidor)
  log "Smoke test de importação dos módulos de remediação..."
  if ! PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="${APP_DIR}" runuser -u "${APP_USER}" -- python3 -c "
import importlib, sys
modules = [
    'remediation',
    'remediation.engine',
    'remediation.cache',
    'remediation.rate_limiter',
    'remediation.validation',
    'remediation.templates',
    'remediation.providers.wazuh_provider',
]
for mod in modules:
    try:
        importlib.import_module(mod)
    except Exception as e:
        print(f'Falha ao importar {mod}: {e}', file=sys.stderr)
        sys.exit(1)
"; then
    die "Falha no smoke test de importação dos módulos de remediação."
  fi

  # Limpar bytecode gerado
  find "${APP_DIR}" -type d -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true
  find "${APP_DIR}" -name '*.pyc' -delete 2>/dev/null || true
  log "Validação Python concluída com sucesso."
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

  # Remover a regra PolicyKit do modo opt-in, se existir (com backup).
  if [[ -f "${POLKIT_RULE_FILE}" ]]; then
    backup_path "${POLKIT_RULE_FILE}"
    rm -f "${POLKIT_RULE_FILE}"
    log "Regra PolicyKit removida: ${POLKIT_RULE_FILE} (backup em ${BACKUP_DIR})."
  fi

  # Remover o marcador de estado do web-run (garante action_mode=safe_no_sudoers).
  if [[ -f "${WEB_RUN_FLAG}" ]]; then
    rm -f "${WEB_RUN_FLAG}"
    log "Marcador web-run removido: ${WEB_RUN_FLAG}."
  fi
}

install_web_run_optin() {
  warn "EYEMOLE_ENABLE_WEB_RUN ativo: habilitando execução manual via web (PolicyKit RESTRITO, sem sudoers)."
  warn "Use SOMENTE em ambiente controlado (HMG/lab). Em produção, prefira o modo seguro."

  # Validar que o PolicyKit está presente ANTES de instalar. Sem ele, a regra
  # não seria lida e o botão voltaria a falhar. Falhar claro > instalar quebrado.
  local polkit_dir; polkit_dir="$(dirname "${POLKIT_RULE_FILE}")"
  if [[ ! -d "${polkit_dir}" ]] \
     || ! { command -v pkaction >/dev/null 2>&1 \
            || [[ -x /usr/lib/polkit-1/polkitd ]] \
            || [[ -x /usr/libexec/polkit-1/polkitd ]]; }; then
    die "PolicyKit ausente (${polkit_dir} ou polkitd não encontrados). Instale o pacote 'polkitd' (Ubuntu 24.04) e reexecute com --enable-web-run. O modo opt-in não foi configurado."
  fi

  # Compatibilidade/limpeza: remover o mecanismo antigo (sudoers + wrapper SUID),
  # para NÃO deixar dois caminhos de privilégio ativos ao mesmo tempo (com backup).
  if [[ -f "${SUDOERS_FILE}" ]]; then
    backup_path "${SUDOERS_FILE}"
    rm -f "${SUDOERS_FILE}"
    log "Sudoers legado removido: ${SUDOERS_FILE} (backup em ${BACKUP_DIR})."
  fi
  if [[ -f "${WRAPPER_RUN_ANALYSIS}" || -f "${WRAPPER_STATUS}" ]]; then
    rm -f "${WRAPPER_RUN_ANALYSIS}" "${WRAPPER_STATUS}"
    log "Wrappers privilegiados legados removidos."
  fi

  # Regra PolicyKit RESTRITA: só ${APP_USER}, só ${REPORT_SERVICE_UNIT}, só "start".
  log "Instalando regra PolicyKit restrita para a API..."
  backup_path "${POLKIT_RULE_FILE}"
  cat > "${POLKIT_RULE_FILE}" <<EOF
// Regra PolicyKit gerada por install.sh --enable-web-run (modo opt-in).
// Escopo MINIMO: só o usuário ${APP_USER}, só a unidade ${REPORT_SERVICE_UNIT},
// só o verbo "start". Sem sudoers/NOPASSWD. Removida no modo seguro (padrao).
polkit.addRule(function(action, subject) {
    if (action.id == "org.freedesktop.systemd1.manage-units" &&
        action.lookup("unit") == "${REPORT_SERVICE_UNIT}" &&
        action.lookup("verb") == "start" &&
        subject.user == "${APP_USER}") {
        return polkit.Result.YES;
    }
});
EOF
  chown root:root "${POLKIT_RULE_FILE}"
  chmod 0644 "${POLKIT_RULE_FILE}"

  # Marcador de estado ÚNICO (a API lê para expor action_mode=web_run_enabled).
  install -d -o "${APP_USER}" -g "${WEB_GROUP}" -m 0750 "$(dirname "${WEB_RUN_FLAG}")"
  printf '%s\n' "web-run habilitado via PolicyKit em ${TS}. Para desabilitar, reexecute install.sh no modo seguro (sem --enable-web-run)." > "${WEB_RUN_FLAG}"
  chown root:"${WEB_GROUP}" "${WEB_RUN_FLAG}"
  chmod 0644 "${WEB_RUN_FLAG}"
  log "Marcador web-run criado: ${WEB_RUN_FLAG}."
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
  log "Instalando unidades systemd..."

  if [[ -f "${REPO_ROOT}/systemd/${SERVICE_FILE}" ]]; then
    install -o root -g root -m 0644 \
      "${REPO_ROOT}/systemd/${SERVICE_FILE}" \
      "${SYSTEMD_UNIT_DIR}/${SERVICE_FILE}"
  else
    warn "Service não encontrado no repo: systemd/${SERVICE_FILE}"
  fi

  if [[ -f "${REPO_ROOT}/systemd/${TIMER_FILE}" ]]; then
    install -o root -g root -m 0644 \
      "${REPO_ROOT}/systemd/${TIMER_FILE}" \
      "${SYSTEMD_UNIT_DIR}/${TIMER_FILE}"
  else
    warn "Timer não encontrado no repo: systemd/${TIMER_FILE}"
  fi

  if [[ -f "${REPO_ROOT}/systemd/${GRYPE_SERVICE_FILE}" ]]; then
    install -o root -g root -m 0644 \
      "${REPO_ROOT}/systemd/${GRYPE_SERVICE_FILE}" \
      "${SYSTEMD_UNIT_DIR}/${GRYPE_SERVICE_FILE}"
  else
    warn "Service Grype não encontrado no repo: systemd/${GRYPE_SERVICE_FILE}"
  fi

  if [[ -f "${REPO_ROOT}/systemd/${GRYPE_TIMER_FILE}" ]]; then
    install -o root -g root -m 0644 \
      "${REPO_ROOT}/systemd/${GRYPE_TIMER_FILE}" \
      "${SYSTEMD_UNIT_DIR}/${GRYPE_TIMER_FILE}"
  else
    warn "Timer Grype não encontrado no repo: systemd/${GRYPE_TIMER_FILE}"
  fi

  API_SERVICE_FILE="hmg-soar-api.service"
  if [[ -f "${REPO_ROOT}/systemd/${API_SERVICE_FILE}" ]]; then
    install -o root -g root -m 0644 \
      "${REPO_ROOT}/systemd/${API_SERVICE_FILE}" \
      "${SYSTEMD_UNIT_DIR}/${API_SERVICE_FILE}"
  else
    warn "Service API não encontrado no repo: systemd/${API_SERVICE_FILE}"
  fi

  systemctl daemon-reload

  # Timer: enable e verificar
  if [[ -f "${SYSTEMD_UNIT_DIR}/${TIMER_FILE}" ]]; then
    systemctl enable --now "${TIMER_FILE}"
    if ! systemctl is-active --quiet "${TIMER_FILE}"; then
      warn "Timer ${TIMER_FILE} não está ativo após enable."
      systemctl status "${TIMER_FILE}" --no-pager || true
      die "Falha ao ativar timer ${TIMER_FILE}."
    fi
    log "Timer ${TIMER_FILE} ativo."
  fi

  # Grype: requer instalação operacional prévia do binário em PATH do systemd
  # (preferencialmente /usr/local/bin/grype). O install.sh não instala binários
  # de terceiros.
  if [[ -f "${SYSTEMD_UNIT_DIR}/${GRYPE_TIMER_FILE}" ]]; then
    if command -v grype >/dev/null 2>&1; then
      systemctl enable --now "${GRYPE_TIMER_FILE}"
      if ! systemctl is-active --quiet "${GRYPE_TIMER_FILE}"; then
        warn "Timer ${GRYPE_TIMER_FILE} não está ativo após enable."
        systemctl status "${GRYPE_TIMER_FILE}" --no-pager || true
        die "Falha ao ativar timer ${GRYPE_TIMER_FILE}."
      fi
      log "Timer ${GRYPE_TIMER_FILE} ativo."
    else
      warn "Binário 'grype' ausente no PATH. Timer ${GRYPE_TIMER_FILE} instalado, mas não habilitado."
      warn "Pré-requisito operacional: instale/mova o grype para /usr/local/bin/grype antes de habilitar o timer."
    fi
  fi

  # API: enable, restart e health check
  if [[ -f "${SYSTEMD_UNIT_DIR}/${API_SERVICE_FILE}" ]]; then
    systemctl enable --now "${API_SERVICE_FILE}"
    systemctl restart "${API_SERVICE_FILE}"

    if ! systemctl is-active --quiet "${API_SERVICE_FILE}"; then
      warn "API ${API_SERVICE_FILE} não está ativa após restart."
      systemctl status "${API_SERVICE_FILE}" --no-pager || true
      journalctl -u "${API_SERVICE_FILE}" -n 20 --no-pager || true
      die "Falha ao iniciar a API ${API_SERVICE_FILE}."
    fi

    # Health check local
    log "Verificando health da API em http://127.0.0.1:8765/health..."
    local health_ok=0
    local attempt
    for attempt in 1 2 3 4 5; do
      sleep 2
      if python3 -c "
import urllib.request, json, sys
try:
    req = urllib.request.Request('http://127.0.0.1:8765/health', method='GET')
    with urllib.request.urlopen(req, timeout=5) as resp:
        if resp.status == 200:
            data = json.loads(resp.read())
            if data.get('status') == 'ok':
                sys.exit(0)
        sys.exit(1)
except Exception:
    sys.exit(1)
" 2>/dev/null; then
        health_ok=1
        break
      fi
    done

    if [[ "${health_ok}" -ne 1 ]]; then
      warn "Health check da API falhou após 5 tentativas."
      systemctl status "${API_SERVICE_FILE}" --no-pager || true
      journalctl -u "${API_SERVICE_FILE}" -n 30 --no-pager || true
      die "API não respondeu ao health check em http://127.0.0.1:8765/health."
    fi
    log "API respondendo corretamente ao health check."
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

publish_offline_dashboard_placeholder() {
  local index_file="${WEB_DIR}/index.html"

  if [[ -f "${index_file}" && ! -L "${index_file}" && -s "${index_file}" ]]; then
    log "Dashboard index.html já existe em ${index_file}. Preservando o dashboard atual."
    return 0
  fi

  log "Publicando placeholder offline para o dashboard em ${index_file}..."

  local tmp_file=""
  if ! tmp_file="$(mktemp "${WEB_DIR}/.index.html.tmp.XXXXXX" 2>/dev/null)"; then
    die "Falha ao criar arquivo temporário seguro em ${WEB_DIR}."
  fi

  _cleanup_tmp() {
    if [[ -n "${tmp_file:-}" && ( -e "${tmp_file:-}" || -L "${tmp_file:-}" ) ]]; then
      if ! rm -f "${tmp_file}"; then
        warn "Falha ao remover o arquivo temporário residual: ${tmp_file}"
      fi
    fi
  }

  if ! cat > "${tmp_file}" <<'EOF'
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EyeMole SOAR - Bootstrap Offline</title>
    <style>
        :root {
            --bg-color: #0d1117;
            --card-bg: #161b22;
            --border-color: #30363d;
            --text-primary: #c9d1d9;
            --text-secondary: #8b949e;
            --accent-color: #58a6ff;
            --warning-color: #d29922;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-primary);
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }
        .container {
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 40px;
            max-width: 550px;
            width: 90%;
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.5);
            text-align: center;
        }
        .logo {
            max-width: 120px;
            height: auto;
            margin-bottom: 20px;
        }
        h1 {
            color: #ffffff;
            font-size: 24px;
            margin-top: 0;
            margin-bottom: 16px;
        }
        p {
            color: var(--text-secondary);
            font-size: 15px;
            line-height: 1.6;
            margin-bottom: 20px;
        }
        .status-badge {
            display: inline-block;
            background-color: rgba(210, 153, 34, 0.15);
            color: var(--warning-color);
            border: 1px solid rgba(210, 153, 34, 0.4);
            border-radius: 20px;
            padding: 6px 16px;
            font-size: 13px;
            font-weight: 600;
            margin-bottom: 24px;
        }
        .instruction-box {
            background-color: #0d1117;
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 16px;
            text-align: left;
            margin-top: 20px;
        }
        .instruction-box code {
            font-family: SFMono-Regular, Consolas, "Liberation Mono", Menlo, monospace;
            color: var(--accent-color);
            background-color: rgba(110, 118, 129, 0.1);
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 13px;
        }
    </style>
</head>
<body>
    <div class="container">
        <img src="assets/eyemole.png" alt="EyeMole SOAR" class="logo" onerror="this.style.display='none'">
        <h1>EyeMole SOAR instalado</h1>
        <div class="status-badge">Modo Bootstrap / Offline</div>
        <p>
            O sistema foi instalado com sucesso. O dashboard ainda não possui dados porque as credenciais de integração com o Wazuh / Indexer não foram configuradas.
        </p>
        <div class="instruction-box">
            <p style="margin: 0; color: var(--text-primary); font-weight: 600; margin-bottom: 8px;">Para habilitar o dashboard real:</p>
            <p style="margin: 0;">Configure o arquivo <code>/etc/hmg-soar/credentials.env</code> com as credenciais de integração. O próximo serviço agendado publicará os dados automaticamente.</p>
        </div>
    </div>
</body>
</html>
EOF
  then
    _cleanup_tmp
    die "Falha ao escrever o conteúdo no arquivo temporário ${tmp_file}."
  fi

  if [[ ! -f "${tmp_file}" || -L "${tmp_file}" || ! -s "${tmp_file}" ]]; then
    _cleanup_tmp
    die "Arquivo temporário inválido ou vazio criado em ${tmp_file}."
  fi

  if ! chmod 0644 "${tmp_file}"; then
    _cleanup_tmp
    die "Falha ao definir permissão 0644 no arquivo temporário ${tmp_file}."
  fi

  if ! chown root:"${WEB_GROUP}" "${tmp_file}" 2>/dev/null; then
    if ! chown root:root "${tmp_file}" 2>/dev/null; then
      _cleanup_tmp
      die "Falha ao definir proprietário no arquivo temporário ${tmp_file}."
    else
      warn "chown com grupo ${WEB_GROUP} falhou em ${tmp_file}; ajustado para root:root."
    fi
  fi

  if ! mv -fT "${tmp_file}" "${index_file}"; then
    _cleanup_tmp
    die "Falha ao mover o arquivo temporário ${tmp_file} para ${index_file}."
  fi

  log "Placeholder offline publicado com sucesso em ${index_file}."
}

validate_web_publication() {
  log "Validando publicação web em ${WEB_DIR}..."

  local index_file="${WEB_DIR}/index.html"

  if [[ -L "${index_file}" ]]; then
    die "Validação da publicação web falhou: ${index_file} é um link simbólico."
  fi

  if [[ ! -f "${index_file}" ]]; then
    die "Validação da publicação web falhou: arquivo ${index_file} não existe ou não é um arquivo regular."
  fi

  if [[ ! -s "${index_file}" ]]; then
    die "Validação da publicação web falhou: arquivo ${index_file} está vazio (0 bytes)."
  fi

  if ! command -v runuser >/dev/null 2>&1; then
    die "Comando 'runuser' ausente. Não é possível validar as permissões de leitura do usuário Nginx '${NGINX_USER}'."
  fi

  if ! id "${NGINX_USER}" >/dev/null 2>&1; then
    die "Usuário Nginx '${NGINX_USER}' não encontrado no sistema."
  fi

  if ! runuser -u "${NGINX_USER}" -- test -r "${index_file}" 2>/dev/null; then
    die "Validação da publicação web falhou: o usuário Nginx '${NGINX_USER}' não possui permissão de leitura em ${index_file}."
  fi

  log "Publicação web em ${index_file} validada com sucesso."
}

is_credentials_ready() {
  local cred_file="${ETC_DIR}/credentials.env"

  if [[ ! -f "${cred_file}" || -L "${cred_file}" ]]; then
    return 1
  fi

  local opensearch_pass=""
  local wazuh_pass=""

  while IFS= read -r line || [[ -n "${line}" ]]; do
    line="$(echo "${line}" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
    [[ "${line}" =~ ^# ]] && continue
    [[ -z "${line}" ]] && continue

    if [[ "${line}" =~ ^OPENSEARCH_PASS[[:space:]]*=[[:space:]]*(.*)$ ]]; then
      opensearch_pass="${BASH_REMATCH[1]}"
      opensearch_pass="${opensearch_pass%\"}"
      opensearch_pass="${opensearch_pass#\"}"
      opensearch_pass="${opensearch_pass%\'}"
      opensearch_pass="${opensearch_pass#\'}"
    elif [[ "${line}" =~ ^WAZUH_API_PASS[[:space:]]*=[[:space:]]*(.*)$ ]]; then
      wazuh_pass="${BASH_REMATCH[1]}"
      wazuh_pass="${wazuh_pass%\"}"
      wazuh_pass="${wazuh_pass#\"}"
      wazuh_pass="${wazuh_pass%\'}"
      wazuh_pass="${wazuh_pass#\'}"
    fi
  done < "${cred_file}"

  if [[ -n "${opensearch_pass}" && -n "${wazuh_pass}" ]]; then
    return 0
  else
    return 1
  fi
}

secure_credentials_env() {
  local cred_file="${ETC_DIR}/credentials.env"
  local template_src="${REPO_ROOT}/credentials.env.example"

  if [[ -L "${cred_file}" ]]; then
    die "Erro de segurança: ${cred_file} é um link simbólico."
  fi

  mkdir -p "${ETC_DIR}"

  if [[ -f "${cred_file}" ]]; then
    log "Arquivo de credenciais ${cred_file} já existe. Preservando o conteúdo atual."
  else
    log "Criando arquivo de modelo de credenciais em ${cred_file}..."
    local tmp_cred=""
    if ! tmp_cred="$(mktemp "${ETC_DIR}/.credentials.env.tmp.XXXXXX" 2>/dev/null)"; then
      die "Falha ao criar arquivo temporário de credenciais em ${ETC_DIR}."
    fi

    _cleanup_cred_tmp() {
      if [[ -n "${tmp_cred:-}" && ( -e "${tmp_cred:-}" || -L "${tmp_cred:-}" ) ]]; then
        rm -f "${tmp_cred}" 2>/dev/null || true
      fi
    }

    if [[ -f "${template_src}" ]]; then
      if ! cat "${template_src}" > "${tmp_cred}"; then
        _cleanup_cred_tmp
        die "Falha ao copiar o modelo de credenciais para ${tmp_cred}."
      fi
    else
      if ! cat > "${tmp_cred}" <<'EOF'
# EyeMole SOAR - Credenciais de integração
#
# Este arquivo será instalado em:
# /etc/hmg-soar/credentials.env
#
# Preencha as duas senhas obrigatórias abaixo.
# Não faça commit de credentials.env real.

# OpenSearch / Wazuh Indexer
# OPENSEARCH_HOST=127.0.0.1
# OPENSEARCH_PORT=9200
# OPENSEARCH_USER=admin
OPENSEARCH_PASS=

# Wazuh API
# WAZUH_API_HOST=127.0.0.1
# WAZUH_API_PORT=55000
# WAZUH_API_USER=wazuh-wui
WAZUH_API_PASS=

# Opcional
# HMG_USE_HTTPS=true
EOF
      then
        _cleanup_cred_tmp
        die "Falha ao escrever o modelo de credenciais em ${tmp_cred}."
      fi
    fi

    if ! chmod 0640 "${tmp_cred}"; then
      _cleanup_cred_tmp
      die "Falha ao definir permissão 0640 no arquivo de credenciais temporário."
    fi

    chown root:root "${tmp_cred}" 2>/dev/null || true

    if ! mv -fT "${tmp_cred}" "${cred_file}"; then
      _cleanup_cred_tmp
      die "Falha ao mover o arquivo de credenciais temporário para ${cred_file}."
    fi

    log "Modelo de credenciais criado com sucesso em ${cred_file}."
  fi

  chmod 0640 "${cred_file}"
  chown root:root "${cred_file}" 2>/dev/null || true
}

run_report_once_if_possible() {
  if [[ ! -f "${SYSTEMD_UNIT_DIR}/${SERVICE_FILE}" ]]; then
    warn "Service systemd não instalado. Pulando execução do serviço de relatório."
    if ! is_credentials_ready; then
      publish_offline_dashboard_placeholder
    fi
    return 0
  fi

  if is_credentials_ready; then
    log "Executando serviço real uma vez para publicar o dashboard..."
    if ! systemctl restart "${SERVICE_FILE}"; then
      warn "Falha ao executar ${SERVICE_FILE}."
      systemctl status "${SERVICE_FILE}" --no-pager || true
      journalctl -u "${SERVICE_FILE}" -n 20 --no-pager || true
      die "Execução inicial do serviço de relatório falhou."
    fi
  else
    log "Credenciais de integração não configuradas. Executando bootstrap offline..."
  fi

  log "Executando bootstrap de contexto (context_bootstrap.py)..."
  if ! PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="${APP_DIR}" runuser -u "${APP_USER}" -- python3 "${APP_DIR}/context_bootstrap.py" --auto; then
    die "Falha no bootstrap de contexto (context_bootstrap.py)."
  fi

  if is_credentials_ready; then
    log "Executando novamente ${SERVICE_FILE} após o bootstrap..."
    if ! systemctl restart "${SERVICE_FILE}"; then
      warn "Falha na segunda execução do ${SERVICE_FILE}."
      systemctl status "${SERVICE_FILE}" --no-pager || true
      journalctl -u "${SERVICE_FILE}" -n 20 --no-pager || true
      die "Segunda execução do serviço de relatório falhou."
    fi
    log "Últimas linhas do serviço:"
    journalctl -u "${SERVICE_FILE}" -n 40 --no-pager || true
  else
    publish_offline_dashboard_placeholder
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
    echo "Modo    : WEB-RUN (opt-in) - execução manual via web HABILITADA (PolicyKit restrito, sem sudoers)"
    echo "          Regra: ${POLKIT_RULE_FILE} | Marcador: ${WEB_RUN_FLAG}"
  else
    echo "Modo    : SEGURO (padrão) - sem sudoers; execução manual via web DESABILITADA"
    echo "          Relatório gerado automaticamente pelo timer hmg-soar-report.timer."
    echo "          Execução manual (admin): sudo systemctl start hmg-soar-report.service"
  fi

  if ! is_credentials_ready; then
    echo
    echo "Status  : BOOTSTRAP / OFFLINE (credenciais de integração não configuradas)"
    echo "          O arquivo de credenciais foi criado em:"
    echo "          ${ETC_DIR}/credentials.env"
    echo
    echo "          Para publicar o dashboard real com dados do Wazuh/Indexer:"
    echo "          sudo nano ${ETC_DIR}/credentials.env"
    echo
    echo "          Preencha as variáveis obrigatórias OPENSEARCH_PASS e WAZUH_API_PASS."
    echo "          Após a configuração, o serviço/timer hmg-soar-report publicará os dados."
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

  ensure_python_runtime_dependencies

  mkdir -p "${BACKUP_DIR}"

  backup_path "${APP_DIR}"
  backup_path "${WEB_DIR}"
  backup_path "${HTPASSWD_FILE}"
  backup_path "${SNIPPET_FILE}"
  backup_path "${SUDOERS_FILE}"
  backup_path "${POLKIT_RULE_FILE}"

  create_user_and_dirs
  install_app_files
  validate_json_configs
  install_default_configs
  ensure_api_audit_dirs
  validate_python
  configure_web_run_mode
  secure_credentials_env
  install_systemd
  install_nginx_snippet
  inject_nginx_include
  reload_nginx
  run_report_once_if_possible
  validate_web_publication
  ensure_api_audit_dirs
  final_message
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
