"""Structured import of read-only diagnostic results for one installation.

EyeMole never runs shell on the agents. The analyst runs the read-only
diagnostics shown in "Ver correção" and imports their raw output here. The
output is parsed by strict parsers (no evaluation), tied to one installation,
and stored with origin, collection time and a confidence label that is kept
everywhere it is used ("imported by analyst" is never shown as collected by
EyeMole).

Checks:
- identity: output of another package, installed version, architecture or a
  package that is not installed is rejected (it is not this installation);
- context: an operating system or release different from the asset's known
  context is stored as a *conflict* (visible, never used to validate);
- validity: imports expire after `diagnostics_max_age_hours`; expired imports
  are kept as history and a new collection is requested.

Repository URLs from `apt-cache policy` may name internal mirrors: only the
suite/component labels (e.g. trixie-security/main) are kept in parsed data.
"""
import datetime as dt
import hashlib
import json
import re

from .security import OperationError

MAX_RAW = 32 * 1024
CONFIDENCE = "imported_by_analyst"
DEFAULT_MAX_AGE_HOURS = 72
_PACKAGE = r"[a-z0-9][a-z0-9+.-]{0,127}"
_VERSION = r"[A-Za-z0-9.+~:-]{1,128}"
_DPKG = re.compile(rf"^({_PACKAGE})(?::([a-z0-9-]{{1,32}}))?[\t ]+({_VERSION})(?:[\t ]+({_PACKAGE})(?:[\t ]+({_VERSION}))?)?$")
_POLICY_HEAD = re.compile(rf"^({_PACKAGE})(?::([a-z0-9-]{{1,32}}))?:$")
_POLICY_FIELD = re.compile(r"^\s+(Installed|Instalado|Candidate|Candidato):\s*(\S+)\s*$")
_POLICY_VERSION = re.compile(rf"^\s*(\*\*\*)?\s+({_VERSION})\s+(-?\d{{1,5}})\s*$")
_POLICY_ORIGIN = re.compile(r"^\s+(-?\d{1,5})\s+(\S+)(?:\s+([A-Za-z0-9./_-]+))?(?:\s+([a-z0-9-]+))?(?:\s+Packages)?\s*$")
_POLICY_HEADER = {"Version table:", "Tabela de versão:", "Tabela de versões:"}
_NONE = {"(none)", "(nenhum)", "(nenhuma)"}


def _now():
    return dt.datetime.now(dt.timezone.utc)


def _reject(message):
    return OperationError(message, 409)


def parse_dpkg(text, package):
    """`dpkg-query -W` (name, version) or the source-aware format of the diagnostic template."""
    found = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        match = _DPKG.fullmatch(line)
        if not match:
            raise OperationError("Saída do dpkg-query em formato não reconhecido.")
        name, arch, version, source, source_version = match.groups()
        if name == package:
            found.append({"binary_package": name, "architecture": arch, "installed_version": version,
                          "source_package": source, "source_version": source_version or (version if source else None)})
    if not found:
        raise _reject("A saída do dpkg-query não contém o pacote desta instalação.")
    return found


def parse_policy(text, package):
    """`apt-cache policy <pkg>` (English or Portuguese). Keeps suites/architectures, drops repository URLs."""
    blocks, current, entry = {}, None, None
    for raw in (text or "").splitlines():
        if not raw.strip():
            continue
        head = _POLICY_HEAD.fullmatch(raw.rstrip())
        if head:
            current = {"installed": None, "candidate": None, "versions": [], "fields": set()}
            blocks[head.group(1)] = current
            entry = None
            continue
        if current is None:
            raise OperationError("Saída do apt-cache policy em formato não reconhecido.")
        field = _POLICY_FIELD.match(raw)
        if field:
            key = "installed" if field.group(1) in {"Installed", "Instalado"} else "candidate"
            current["fields"].add(key)
            current[key] = None if field.group(2) in _NONE else field.group(2)
            continue
        if raw.strip() in _POLICY_HEADER:
            continue
        version = _POLICY_VERSION.fullmatch(raw.rstrip())
        if version:
            entry = {"version": version.group(2), "installed": bool(version.group(1)),
                     "priority": int(version.group(3)), "suites": [], "architectures": [], "local_status_only": False}
            current["versions"].append(entry)
            continue
        origin = _POLICY_ORIGIN.fullmatch(raw.rstrip())
        if origin and entry is not None:
            location, suite, arch = origin.group(2), origin.group(3), origin.group(4)
            if location.startswith("/"):
                entry["local_status_only"] = location == "/var/lib/dpkg/status" and not entry["suites"]
            elif suite:
                entry["suites"].append(suite[:64])
                if arch:
                    entry["architectures"].append(arch)
            continue
        raise OperationError("Saída do apt-cache policy em formato não reconhecido.")
    block = blocks.get(package)
    if block is None:
        raise _reject("A saída do apt-cache policy não contém o pacote desta instalação.")
    if block["fields"] != {"installed", "candidate"}:
        raise OperationError("apt-cache policy incompleto: faltam os campos Installed/Candidate.")
    if block["installed"] is None:
        raise _reject("apt-cache policy indica que o pacote não está instalado (Installed: none); não é esta instalação.")
    marked = [v for v in block["versions"] if v["installed"]]
    if len(marked) != 1 or marked[0]["version"] != block["installed"]:
        raise OperationError("apt-cache policy inconsistente: a versão marcada com *** difere de Installed.")
    if block["candidate"] is not None and not any(v["version"] == block["candidate"] for v in block["versions"]):
        raise OperationError("apt-cache policy inconsistente: a Candidate não aparece na tabela de versões.")
    for item in block["versions"]:
        if item["suites"]:
            item["local_status_only"] = False
    del block["fields"]
    return block


def parse_os_release(text):
    values = {}
    for line in (text or "").splitlines():
        match = re.fullmatch(r"\s*(ID|VERSION_ID|VERSION_CODENAME)=\"?([A-Za-z0-9._-]{1,32})\"?\s*", line)
        if match:
            values[match.group(1).lower()] = match.group(2).lower()
    if not values.get("id") or not (values.get("version_id") or values.get("version_codename")):
        raise OperationError("Saída de /etc/os-release precisa de ID e VERSION_ID ou VERSION_CODENAME.")
    return values


def context_conflicts(parsed, installation):
    """Disagreements with the asset's known context (stored and shown, never used to validate)."""
    conflicts = []
    os_release = parsed.get("os_release") or {}
    distribution, release = installation.get("distribution"), installation.get("release")
    if os_release.get("id") and distribution and os_release["id"] != distribution:
        conflicts.append(f"/etc/os-release indica {os_release['id']}, mas o ativo está registrado como {distribution}.")
    if os_release.get("version_codename") and release and os_release["version_codename"] != release:
        conflicts.append(f"/etc/os-release indica a release {os_release['version_codename']}, "
                         f"mas o ativo está registrado como {release}.")
    version_id, os_version = os_release.get("version_id"), str(installation.get("os_version") or "")
    if version_id and os_version and version_id.split(".")[0] != os_version.split(".")[0]:
        conflicts.append(f"/etc/os-release indica a versão {version_id}, mas o ativo está registrado com {os_version}.")
    return conflicts


def evaluate(record, settings=None, now=None):
    """Current validity of an import: valid, expired or conflict (with reasons)."""
    if not record:
        return None
    now = now or _now()
    hours = min(max(float((settings or {}).get("diagnostics_max_age_hours", DEFAULT_MAX_AGE_HOURS)), 1), 24 * 30)
    collected = dt.datetime.fromisoformat(record["collected_at"])
    expires = collected + dt.timedelta(hours=hours)
    reasons = list(record.get("conflicts") or [])
    status = "conflict" if reasons else "valid"
    if now >= expires:
        status = "expired"
        reasons.append(f"Diagnóstico coletado em {record['collected_at']} expirou (validade de {hours:g} h); "
                       "colete e importe novamente.")
    return {"status": status, "expires_at": expires.isoformat(timespec="seconds"), "reasons": reasons}


def public(record, settings=None, now=None):
    """Import as shown to users and to the research: provenance, parsed data and validity, no raw output."""
    if not record:
        return None
    out = {k: record.get(k) for k in ("collected_at", "imported_at", "imported_by", "origin", "confidence",
                                      "parsed", "revision", "installed_version", "conflicts")}
    out["validity"] = evaluate(record, settings, now)
    return out


def build_import(body, installation, user, now=None):
    """Validate an import for one installation. Returns the record to store."""
    if not isinstance(body, dict) or set(body) - {"collected_at", "dpkg_query", "apt_cache_policy", "os_release"}:
        raise OperationError("Importação de diagnóstico com campos não permitidos.")
    raws = {k: body.get(k) for k in ("dpkg_query", "apt_cache_policy", "os_release") if body.get(k)}
    if not raws:
        raise OperationError("Informe a saída de pelo menos um diagnóstico.")
    if any(not isinstance(v, str) or len(v.encode()) > MAX_RAW for v in raws.values()):
        raise OperationError("Saída de diagnóstico inválida ou acima do limite.")
    try:
        collected = dt.datetime.fromisoformat(str(body.get("collected_at", "")).replace("Z", "+00:00"))
    except ValueError:
        raise OperationError("Informe a data e hora da coleta (collected_at).")
    if collected.tzinfo is None:
        raise OperationError("collected_at precisa de fuso horário.")
    now = now or _now()
    if collected > now + dt.timedelta(minutes=5):
        raise OperationError("Coleta com data futura.")
    package, installed = installation["package"], installation["version"]
    arch = installation.get("architecture")
    parsed = {}
    if "dpkg_query" in raws:
        rows = parse_dpkg(raws["dpkg_query"], package)
        row = next((r for r in rows if not r["architecture"] or not arch or r["architecture"] == arch), None)
        if row is None:
            raise _reject("dpkg-query mostra outra arquitetura; o diagnóstico não é desta instalação.")
        if row["installed_version"] != installed:
            raise _reject("dpkg-query mostra outra versão instalada; o diagnóstico não é desta instalação.")
        parsed["dpkg"] = row
    if "apt_cache_policy" in raws:
        policy = parse_policy(raws["apt_cache_policy"], package)
        if policy["installed"] != installed:
            raise _reject("apt-cache policy mostra outra versão instalada; o diagnóstico não é desta instalação.")
        architectures = {a for v in policy["versions"] for a in v["architectures"]} - {"all"}
        if arch and architectures and architectures != {arch}:
            raise _reject("apt-cache policy lista outra arquitetura; o diagnóstico não é desta instalação.")
        parsed["policy"] = policy
    if "os_release" in raws:
        parsed["os_release"] = parse_os_release(raws["os_release"])
    collected_at = collected.astimezone(dt.timezone.utc).isoformat(timespec="seconds")
    record = {"finding_id": installation["finding_id"], "agent_ids": [str(installation["agent_id"])],
              "package": package, "installed_version": installed, "architecture": arch,
              "collected_at": collected_at, "imported_at": now.isoformat(timespec="seconds"), "imported_by": user,
              "origin": "manual_import", "confidence": CONFIDENCE, "parsed": parsed, "raw": raws,
              "conflicts": context_conflicts(parsed, installation)}
    record["revision"] = hashlib.sha256(json.dumps([collected_at, parsed, record["conflicts"]],
                                                   sort_keys=True).encode()).hexdigest()
    return record
