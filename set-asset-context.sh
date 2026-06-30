#!/usr/bin/env bash
#
# set-asset-context.sh - Define o contexto de ativos do EyeMole SOAR.
#

set -Eeuo pipefail
IFS=$'\n\t'

# Garantir execução como root
if [[ "${EUID}" -ne 0 ]]; then
  echo "[x] Erro: Execute como root: sudo ./set-asset-context.sh <agent_id> ..." >&2
  exit 1
fi

usage() {
  echo "Uso:"
  echo "  sudo ./set-asset-context.sh <agent_id> [--technical-owner <owner>] [--business-owner <owner>] [--criticality <criticality>] [--environment <env>]"
  echo
  echo "Valores permitidos para --criticality:"
  echo "  critical, high, medium, low, unknown"
  echo
  echo "Exemplo:"
  echo "  sudo ./set-asset-context.sh 001 --technical-owner \"Equipe Windows\" --business-owner \"Sistemas\" --criticality critical --environment hmg"
}

if [[ $# -lt 1 ]]; then
  usage
  exit 1
fi

# Tratar ajuda ANTES de definir AGENT_ID, para nunca criar um ativo "--help"/"-h".
case "${1}" in
  -h|--help)
    usage
    exit 0
    ;;
  -*)
    echo "[x] Erro: o primeiro argumento deve ser o <agent_id>, recebido: '${1}'" >&2
    usage
    exit 1
    ;;
esac

AGENT_ID="$1"
shift

TECHNICAL_OWNER=""
BUSINESS_OWNER=""
CRITICALITY=""
ENVIRONMENT=""

# Processamento de argumentos
while [[ $# -gt 0 ]]; do
  case "$1" in
    --technical-owner)
      if [[ -z "${2:-}" ]]; then
        echo "[x] Erro: --technical-owner requer um valor." >&2
        exit 1
      fi
      TECHNICAL_OWNER="$2"
      shift 2
      ;;
    --business-owner)
      if [[ -z "${2:-}" ]]; then
        echo "[x] Erro: --business-owner requer um valor." >&2
        exit 1
      fi
      BUSINESS_OWNER="$2"
      shift 2
      ;;
    --criticality)
      if [[ -z "${2:-}" ]]; then
        echo "[x] Erro: --criticality requer um valor." >&2
        exit 1
      fi
      CRITICALITY="$2"
      shift 2
      ;;
    --environment)
      if [[ -z "${2:-}" ]]; then
        echo "[x] Erro: --environment requer um valor." >&2
        exit 1
      fi
      ENVIRONMENT="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "[x] Opção desconhecida: $1" >&2
      usage
      exit 1
      ;;
  esac
done

# Validação do criticality
if [[ -n "${CRITICALITY}" ]]; then
  case "${CRITICALITY}" in
    critical|high|medium|low|unknown)
      ;;
    *)
      echo "[x] Erro: --criticality inválida: '${CRITICALITY}'. Valores permitidos: critical, high, medium, low, unknown" >&2
      exit 1
      ;;
  esac
fi

ASSETS_JSON="/opt/hmg-soar/config/assets_context.json"

# Se o JSON não existir localmente no caminho do SOAR, tentar usar o diretório atual do repo para testes
if [[ ! -f "${ASSETS_JSON}" ]]; then
  if [[ -f "./opt/hmg-soar/config/assets_context.json" ]]; then
    ASSETS_JSON="./opt/hmg-soar/config/assets_context.json"
  else
    echo "[x] Erro: Arquivo de contexto de ativos não encontrado em: ${ASSETS_JSON}" >&2
    exit 1
  fi
fi

# Utilizar Python inline de forma robusta para ler, atualizar e salvar o JSON de contexto mantendo a formatação
python3 -c '
import json
import sys
from pathlib import Path
from datetime import datetime, timezone

json_path = Path(sys.argv[1])
agent_id = sys.argv[2]
tech_owner = sys.argv[3]
bus_owner = sys.argv[4]
crit = sys.argv[5]
env = sys.argv[6]

try:
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
except Exception as e:
    print(f"[x] Erro ao ler JSON: {e}", file=sys.stderr)
    sys.exit(1)

if "agents" not in data:
    data["agents"] = {}

# Garantir entrada inicial do agente caso ainda não exista
if agent_id not in data["agents"]:
    data["agents"][agent_id] = {
        "id": agent_id,
        "asset_name": f"agent-{agent_id}",
        "hostname": f"agent-{agent_id}",
        "criticality": "unknown",
        "technical_owner": "unknown",
        "business_owner": "unknown",
        "environment": "unknown",
        "classification_status": "pending"
    }

agent = data["agents"][agent_id]

# Atualizar campos preenchidos
if tech_owner:
    agent["technical_owner"] = tech_owner
if bus_owner:
    agent["business_owner"] = bus_owner
if crit:
    agent["criticality"] = crit
    if crit != "unknown":
        agent["classification_status"] = "classified"
if env:
    agent["environment"] = env

# Atualizar metadados
if "metadata" not in data:
    data["metadata"] = {}
data["metadata"]["updated_at"] = datetime.now(timezone.utc).isoformat()
data["metadata"]["updated_by"] = "set-asset-context-cli"

try:
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
except Exception as e:
    print(f"[x] Erro ao gravar JSON: {e}", file=sys.stderr)
    sys.exit(1)

print(f"[+] Ativo {agent_id} atualizado com sucesso no JSON de contexto.")
' "${ASSETS_JSON}" "${AGENT_ID}" "${TECHNICAL_OWNER}" "${BUSINESS_OWNER}" "${CRITICALITY}" "${ENVIRONMENT}"

# Ajustar permissões (somente se estiver alterando o caminho de produção em /opt)
if [[ "${ASSETS_JSON}" == "/opt/hmg-soar/config/assets_context.json" ]]; then
  chown hmg-soar:www-data "${ASSETS_JSON}"
  chmod 0640 "${ASSETS_JSON}"
fi

echo "[*] Sugestão: sudo systemctl restart hmg-soar-report.service"
