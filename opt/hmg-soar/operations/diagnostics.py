"""Structured import of read-only diagnostic results for one installation.

EyeMole never runs shell on the agents. The analyst runs the read-only
diagnostics shown in "Ver correção" and imports their raw output here. The
output is parsed by strict parsers (no evaluation), tied to one installation,
and stored with origin, collection time and a confidence label that is kept
everywhere it is used ("imported by analyst" is never shown as collected by
EyeMole).

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
_PACKAGE = r"[a-z0-9][a-z0-9+.-]{0,127}"
_VERSION = r"[A-Za-z0-9.+~:-]{1,128}"
_DPKG = re.compile(rf"^({_PACKAGE})(?::([a-z0-9-]{{1,32}}))?[\t ]+({_VERSION})(?:[\t ]+({_PACKAGE})(?:[\t ]+({_VERSION}))?)?$")
_POLICY_HEAD = re.compile(rf"^({_PACKAGE})(?::([a-z0-9-]{{1,32}}))?:$")
_POLICY_FIELD = re.compile(r"^\s+(Installed|Instalado|Candidate|Candidato):\s*(\S+)\s*$")
_POLICY_VERSION = re.compile(rf"^\s*(\*\*\*)?\s+({_VERSION})\s+(-?\d{{1,5}})\s*$")
_POLICY_ORIGIN = re.compile(r"^\s+(-?\d{1,5})\s+(\S+)(?:\s+([A-Za-z0-9./_-]+))?(?:\s+([a-z0-9-]+))?(?:\s+Packages)?\s*$")
_NONE = {"(none)", "(nenhum)", "(nenhuma)"}


def _now():
    return dt.datetime.now(dt.timezone.utc)


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
        raise OperationError("A saída do dpkg-query não contém o pacote desta instalação.")
    return found


def parse_policy(text, package):
    """`apt-cache policy <pkg>` (English or Portuguese). Keeps suites, drops repository URLs."""
    blocks, current, entry = {}, None, None
    for raw in (text or "").splitlines():
        if not raw.strip():
            continue
        head = _POLICY_HEAD.fullmatch(raw.rstrip())
        if head:
            current = {"installed": None, "candidate": None, "versions": []}
            blocks[head.group(1)] = current
            entry = None
            continue
        if current is None:
            raise OperationError("Saída do apt-cache policy em formato não reconhecido.")
        field = _POLICY_FIELD.match(raw)
        if field:
            value = None if field.group(2) in _NONE else field.group(2)
            current["installed" if field.group(1) in {"Installed", "Instalado"} else "candidate"] = value
            continue
        if raw.strip() in {"Version table:", "Tabela de versão:", "Tabela de versões:"}:
            continue
        version = _POLICY_VERSION.fullmatch(raw.rstrip())
        if version:
            entry = {"version": version.group(2), "installed": bool(version.group(1)),
                     "priority": int(version.group(3)), "suites": [], "local_status_only": False}
            current["versions"].append(entry)
            continue
        origin = _POLICY_ORIGIN.fullmatch(raw.rstrip())
        if origin and entry is not None:
            location, suite = origin.group(2), origin.group(3)
            if location.startswith("/"):
                entry["local_status_only"] = location == "/var/lib/dpkg/status" and not entry["suites"]
            elif suite:
                entry["suites"].append(suite[:64])
            continue
        raise OperationError("Saída do apt-cache policy em formato não reconhecido.")
    block = blocks.get(package)
    if block is None:
        raise OperationError("A saída do apt-cache policy não contém o pacote desta instalação.")
    for item in block["versions"]:
        if item["suites"]:
            item["local_status_only"] = False
    return block


def parse_os_release(text):
    values = {}
    for line in (text or "").splitlines():
        match = re.fullmatch(r"\s*(ID|VERSION_ID|VERSION_CODENAME)=\"?([A-Za-z0-9._-]{1,32})\"?\s*", line)
        if match:
            values[match.group(1).lower()] = match.group(2)
    if not values:
        raise OperationError("Saída de /etc/os-release sem ID, VERSION_ID ou VERSION_CODENAME.")
    return values


def public(record):
    """Import as shown to users and to the research: provenance and parsed data, no raw output."""
    if not record:
        return None
    return {k: record.get(k) for k in ("collected_at", "imported_at", "imported_by", "origin", "confidence",
                                       "parsed", "revision", "installed_version")}


def build_import(body, installation, user):
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
    if collected > _now() + dt.timedelta(minutes=5):
        raise OperationError("Coleta com data futura.")
    package, installed = installation["package"], installation["version"]
    parsed = {}
    if "dpkg_query" in raws:
        rows = parse_dpkg(raws["dpkg_query"], package)
        arch = installation.get("architecture")
        row = next((r for r in rows if not r["architecture"] or not arch or r["architecture"] == arch), None)
        if row is None or row["installed_version"] != installed:
            raise OperationError("dpkg-query mostra outra versão/arquitetura; o diagnóstico não é desta instalação.", 409)
        parsed["dpkg"] = row
    if "apt_cache_policy" in raws:
        policy = parse_policy(raws["apt_cache_policy"], package)
        if policy["installed"] and policy["installed"] != installed:
            raise OperationError("apt-cache policy mostra outra versão instalada; o diagnóstico não é desta instalação.", 409)
        parsed["policy"] = policy
    if "os_release" in raws:
        parsed["os_release"] = parse_os_release(raws["os_release"])
    record = {"finding_id": installation["finding_id"], "agent_ids": [str(installation["agent_id"])],
              "package": package, "installed_version": installed, "collected_at": collected.isoformat(),
              "imported_at": _now().isoformat(timespec="seconds"), "imported_by": user,
              "origin": "manual_import", "confidence": CONFIDENCE, "parsed": parsed, "raw": raws}
    record["revision"] = hashlib.sha256(json.dumps([record["collected_at"], parsed], sort_keys=True).encode()).hexdigest()
    return record
