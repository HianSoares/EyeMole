#!/usr/bin/env bash
set -euo pipefail

CONFIG_FILE="${EYEMOLE_AGENT_CONFIG:-/etc/eyemole-agent/agent.conf}"
LOG_FILE="${EYEMOLE_AGENT_LOG:-/var/log/eyemole-agent/sbom-upload.log}"
TOKEN_FILE="${TOKEN_FILE:-/etc/eyemole-agent/token}"
WORK_DIR="${WORK_DIR:-/var/lib/eyemole-agent}"
CA_CERT_PATH="${CA_CERT_PATH:-}"
CONNECT_TIMEOUT="${CONNECT_TIMEOUT:-10}"
MAX_TIME="${MAX_TIME:-180}"
RETRY_COUNT="${RETRY_COUNT:-2}"
SBOM_FILE=""

SCAN_TARGETS=()

cleanup() {
  if [[ -n "${SBOM_FILE:-}" && -f "${SBOM_FILE}" ]]; then
    rm -f "${SBOM_FILE}"
  fi
}

trap cleanup EXIT

log() {
  local level="$1"
  shift
  printf '%s [%s] %s\n' "$(date -Is)" "${level}" "$*" | tee -a "${LOG_FILE}" >&2
}

load_config() {
  if [[ ! -r "${CONFIG_FILE}" ]]; then
    log ERROR "Config file not readable: ${CONFIG_FILE}"
    exit 1
  fi

  # shellcheck source=/dev/null
  source "${CONFIG_FILE}"
}

validate_config() {
  if [[ -z "${AGENT_ID:-}" ]]; then
    log ERROR "AGENT_ID is required in ${CONFIG_FILE}"
    exit 1
  fi

  if [[ -z "${EYEMOLE_SOAR_URL:-}" ]]; then
    log ERROR "EYEMOLE_SOAR_URL is required in ${CONFIG_FILE}"
    exit 1
  fi

  if [[ "${#SCAN_TARGETS[@]}" -eq 0 ]]; then
    log ERROR "SCAN_TARGETS must contain at least one Syft target"
    exit 1
  fi

  if [[ ! -r "${TOKEN_FILE}" ]]; then
    log ERROR "Token file not readable: ${TOKEN_FILE}"
    exit 1
  fi

  if ! command -v syft >/dev/null 2>&1; then
    log ERROR "syft was not found in PATH"
    exit 1
  fi

  if ! command -v curl >/dev/null 2>&1; then
    log ERROR "curl was not found in PATH"
    exit 1
  fi

  if [[ -n "${CA_CERT_PATH}" && ! -r "${CA_CERT_PATH}" ]]; then
    log ERROR "CA_CERT_PATH is set but not readable: ${CA_CERT_PATH}"
    exit 1
  fi
}

ensure_runtime_dirs() {
  mkdir -p "$(dirname "${LOG_FILE}")" "${WORK_DIR}"
}

generate_single_target_sbom() {
  local output_file="$1"
  local target="${SCAN_TARGETS[0]}"

  log INFO "Generating CycloneDX SBOM for ${target}"
  syft scan "${target}" -o cyclonedx-json > "${output_file}"
}

generate_multi_target_sbom() {
  local output_file="$1"
  local merge_dir
  merge_dir="$(mktemp -d "${WORK_DIR}/sbom-parts.XXXXXX")"
  trap 'rm -rf "${merge_dir}"' RETURN

  local part_files=()
  local index=0

  for target in "${SCAN_TARGETS[@]}"; do
    local part_file="${merge_dir}/part-${index}.json"
    log INFO "Generating CycloneDX SBOM part for ${target}"
    syft scan "${target}" -o cyclonedx-json > "${part_file}"
    part_files+=("${part_file}")
    index=$((index + 1))
  done

  python3 - "$output_file" "${part_files[@]}" <<'PY'
import json
import sys
from pathlib import Path

output = Path(sys.argv[1])
parts = [json.loads(Path(path).read_text(encoding="utf-8")) for path in sys.argv[2:]]

merged = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "version": 1,
    "metadata": {
        "component": {
            "type": "application",
            "name": "eyemole-agent-scan",
        }
    },
    "components": [],
}

seen = set()
for part in parts:
    for component in part.get("components", []):
        key = (
            component.get("bom-ref"),
            component.get("name"),
            component.get("version"),
            component.get("type"),
            component.get("purl"),
        )
        if key in seen:
            continue
        seen.add(key)
        merged["components"].append(component)

output.write_text(json.dumps(merged, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
PY
}

generate_sbom() {
  local output_file="$1"

  if [[ "${#SCAN_TARGETS[@]}" -eq 1 ]]; then
    generate_single_target_sbom "${output_file}"
    return
  fi

  if ! command -v python3 >/dev/null 2>&1; then
    log ERROR "python3 is required when SCAN_TARGETS has more than one entry"
    exit 1
  fi

  generate_multi_target_sbom "${output_file}"
}

upload_sbom() {
  local sbom_path="$1"
  local token
  token="$(tr -d '\r\n' < "${TOKEN_FILE}")"

  if [[ -z "${token}" ]]; then
    log ERROR "Token file is empty: ${TOKEN_FILE}"
    exit 1
  fi

  local upload_url="${EYEMOLE_SOAR_URL%/}/soar-api/sbom/${AGENT_ID}"
  local curl_args=(
    --fail
    --silent
    --show-error
    --connect-timeout "${CONNECT_TIMEOUT}"
    --max-time "${MAX_TIME}"
    --retry "${RETRY_COUNT}"
    --request POST
    --header "Authorization: Bearer ${token}"
    --header "Content-Type: application/json"
    --data-binary "@${sbom_path}"
  )

  if [[ -n "${CA_CERT_PATH}" ]]; then
    curl_args+=(--cacert "${CA_CERT_PATH}")
  fi

  log INFO "Uploading SBOM to ${upload_url}"
  curl "${curl_args[@]}" "${upload_url}" >/dev/null
  log INFO "SBOM upload accepted for agent ${AGENT_ID}"
}

main() {
  ensure_runtime_dirs
  load_config
  validate_config

  SBOM_FILE="$(mktemp "${WORK_DIR}/sbom-${AGENT_ID}.XXXXXX.json")"
  generate_sbom "${SBOM_FILE}"
  upload_sbom "${SBOM_FILE}"
}

main "$@"
