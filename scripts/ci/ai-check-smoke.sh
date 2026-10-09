#!/usr/bin/env bash
# CI smoke test (Linux, root, systemd): `eyemole ai check` runs as eyemole-worker
# with the worker's groups, sandbox and EnvironmentFile.
#
# No credential and no external call: the key is a fake value generated here and
# integrate.api.nvidia.com resolves to localhost, so the request never leaves
# the runner. A loaded key therefore ends in "connection_failed"; a missing key
# in "missing_credentials". The real NVIDIA call is NOT exercised.
set -euo pipefail

[[ "$(id -u)" -eq 0 ]] || { echo "run as root" >&2; exit 2; }
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CLI=("python3" "${REPO_ROOT}/cli/eyemole.py")
FAKE_KEY="fake-ci-key-not-a-credential-$(date +%s%N)"
STARTED="$(date '+%Y-%m-%d %H:%M:%S')"

fail() { echo "FALHA: $*" >&2; exit 1; }
field() { python3 -c 'import json,sys; print(json.loads(sys.stdin.read()).get(sys.argv[1]))' "$1"; }

if ! /usr/bin/python3 -c 'import requests, urllib3' 2>/dev/null; then
  apt-get update -qq && apt-get install -y -qq python3-requests python3-urllib3 >/dev/null
fi

# Accounts and permissions as created by install.sh.
getent group www-data >/dev/null || groupadd --system www-data
getent group eyemole-ops >/dev/null || groupadd --system eyemole-ops
id eyemole-worker >/dev/null 2>&1 || useradd --system --gid eyemole-ops --groups www-data \
  --home-dir /var/lib/eyemole --shell /usr/sbin/nologin eyemole-worker
install -d -o root -g root -m 0755 /opt/hmg-soar /etc/hmg-soar
cp -a "${REPO_ROOT}/opt/hmg-soar/." /opt/hmg-soar/
chown -R root:root /opt/hmg-soar
chmod -R u+rwX,go+rX,go-w /opt/hmg-soar

tmp="$(mktemp)"
echo '{"enabled": true, "users": {}, "projects": {"hmg": {}}}' >"${tmp}"
install -o root -g www-data -m 0640 "${tmp}" /etc/hmg-soar/platform.json
printf 'NVIDIA_API_KEY=%s\n' "${FAKE_KEY}" >"${tmp}"
install -o root -g root -m 0600 "${tmp}" /etc/hmg-soar/integrations.env
rm -f "${tmp}"

# Keep the request on the runner.
cp /etc/hosts /etc/hosts.eyemole-ci
trap 'cp /etc/hosts.eyemole-ci /etc/hosts' EXIT
printf '127.0.0.1 integrate.api.nvidia.com\n::1 integrate.api.nvidia.com\n' >>/etc/hosts
getent ahosts integrate.api.nvidia.com | awk '{print $1}' | sort -u | grep -qvE '^(127\.0\.0\.1|::1)$' \
  && fail "integrate.api.nvidia.com não ficou restrito a localhost"

# 1. The worker account cannot read the secrets file directly.
if runuser -u eyemole-worker -- cat /etc/hmg-soar/integrations.env >/dev/null 2>&1; then
  fail "eyemole-worker lê integrations.env diretamente"
fi
echo "ok: integrations.env (root:root 0600) não é legível por eyemole-worker"

# 2. configure enables NVIDIA, keeps owner/mode and writes no secret.
"${CLI[@]}" ai configure --project hmg --enable --timeout 15
[[ "$(stat -c '%U:%G %a' /etc/hmg-soar/platform.json)" == "root:www-data 640" ]]   || fail "platform.json mudou de dono/modo: $(stat -c '%U:%G %a' /etc/hmg-soar/platform.json)"
grep -q 'integrate.api.nvidia.com' /etc/hmg-soar/platform.json || fail "bloco integrations.ai ausente"
grep -qF "${FAKE_KEY}" /etc/hmg-soar/platform.json && fail "configure gravou a chave"
ls -A /etc/hmg-soar | grep -q '^\.platform-' && fail "temporário de platform.json remanescente"
echo "ok: ai configure preserva root:www-data 0640"

# 3. status (root) reports the key presence, never its value.
status="$("${CLI[@]}" ai status --project hmg)"
[[ "$(field secret_configured <<<"${status}")" == "True" ]] || fail "status sem secret_configured: ${status}"
grep -qF "${FAKE_KEY}" <<<"${status}" && fail "status expôs a chave"
echo "ok: ai status → ${status}"

# 4. check as eyemole-worker: config readable (www-data group), key loaded by systemd.
set +e
out="$("${CLI[@]}" ai check --project hmg 2>/tmp/eyemole-ai-check.err)"; rc=$?; cat /tmp/eyemole-ai-check.err >&2
set -e
echo "ai check (chave fictícia) → rc=${rc} ${out}"
[[ "${rc}" -eq 1 ]] || fail "rc inesperado ${rc}"
[[ "$(field code <<<"${out}")" == "connection_failed" ]] || fail "esperado connection_failed (chave carregada)"
[[ "$(field provider <<<"${out}")" == "nvidia" ]] || fail "provedor inesperado"
grep -qF "${FAKE_KEY}" <<<"${out}" && fail "check expôs a chave"

# 5. Without the key (empty file, then file absent): explicit missing_credentials.
: >/etc/hmg-soar/integrations.env
for state in vazio ausente; do
  set +e
  out="$("${CLI[@]}" ai check --project hmg 2>/tmp/eyemole-ai-check.err)"; rc=$?; cat /tmp/eyemole-ai-check.err >&2
  set -e
  echo "ai check (arquivo ${state}) → rc=${rc} ${out}"
  [[ "${rc}" -eq 1 && "$(field code <<<"${out}")" == "missing_credentials" ]] || fail "esperado missing_credentials (${state})"
  rm -f /etc/hmg-soar/integrations.env
done

# 6. The fake key never reached the journal.
if journalctl --since "${STARTED}" --no-pager 2>/dev/null | grep -qF "${FAKE_KEY}"; then
  fail "chave encontrada no journal"
fi
echo "ok: chave ausente do journal"
echo "ai check smoke: OK"
