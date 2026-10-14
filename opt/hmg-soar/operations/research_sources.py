"""Official remediation sources for the research flow (worker side only).

The backend, not the model, reaches the internet. Each connector:
- talks only to a fixed HTTPS host (no redirects, TLS verified, no proxy
  variables, bounded time and size);
- keeps an on-disk cache with a validity period, conditional revalidation
  and a bounded "stale" fallback when the source is unavailable;
- returns normalized evidence items: URL, publisher, retrieval time, content
  hash, relevant excerpt, distribution/release/package/version scope.

External content is untrusted data: it is parsed into fixed fields, never
interpreted as instructions, and it can only select a path on a fixed host
through a strict pattern (GitHub advisory links), never an arbitrary URL.
"""
import datetime as dt
import hashlib
import json
import os
import re
import time
from html.parser import HTMLParser
from pathlib import Path

import requests

from .security import OperationError

USER_AGENT = "EyeMole-remediation-research/1 (+https://github.com/HianSoares/EyeMole)"
DEFAULT_CACHE_DIR = Path("/var/lib/eyemole/platform/research-cache")
CVE = re.compile(r"CVE-\d{4}-\d{4,7}")
# Only GitHub security advisories of a repository can be followed from source notes.
GHSA_LINK = re.compile(r"https://github\.com/([A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))/([A-Za-z0-9._-]{1,100})/security/advisories/"
                       r"(GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4})")
GHSA_ID = re.compile(r"GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}")
MAX_EXCERPT = 600


class SourceUnavailable(OperationError):
    def __init__(self, message, code="source_unavailable"):
        super().__init__(message, 502)
        self.code = code


def new_session():
    """Factory kept separate so tests inject recorded responses."""
    session = requests.Session()
    session.trust_env = False
    return session


def _now():
    return dt.datetime.now(dt.timezone.utc)


def _iso(moment):
    return moment.isoformat(timespec="seconds")


def _text(value, maximum=MAX_EXCERPT):
    if value is None:
        return None
    text = " ".join("".join(c if ord(c) >= 32 else " " for c in str(value)).split())
    return text[:maximum] or None


def cache_path(cache_dir, url):
    return Path(cache_dir) / (hashlib.sha256(url.encode()).hexdigest() + ".json")


def _read_entry(path, url):
    try:
        entry = json.loads(path.read_text(encoding="utf-8"))
        return entry if entry.get("url") == url else None
    except (OSError, ValueError):
        return None


def cached_entry(url, settings=None):
    """Cached source content without network access (detects evidence changes)."""
    return _read_entry(cache_path((settings or {}).get("cache_dir") or DEFAULT_CACHE_DIR, url), url)


class Fetcher:
    """HTTP GET on allowlisted hosts with a validity-bound disk cache."""

    HOSTS = {"security-tracker.debian.org", "ubuntu.com", "api.github.com"}

    def __init__(self, settings=None, session=None, clock=None):
        settings = settings or {}
        self.cache_dir = Path(settings.get("cache_dir") or DEFAULT_CACHE_DIR)
        self.ttl = dt.timedelta(hours=min(max(float(settings.get("cache_ttl_hours", 6)), 0.25), 168))
        self.max_stale = dt.timedelta(hours=min(max(float(settings.get("max_stale_hours", 72)), 0), 720))
        self.negative_ttl = dt.timedelta(minutes=10)
        self.timeout = min(max(int(settings.get("timeout_seconds", 20)), 5), 60)
        self.budget = min(max(int(settings.get("budget_seconds", 90)), 15), 300)
        self.session = session or new_session()
        self.clock = clock or (lambda: _now())  # resolved at call time (controllable in tests)
        self.started = time.monotonic()

    def _path(self, url):
        return cache_path(self.cache_dir, url)

    def _read(self, url):
        return _read_entry(self._path(url), url)

    def _write(self, url, entry):
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        path = self._path(url)
        temporary = path.with_name(path.name + ".tmp-" + os.urandom(4).hex())
        temporary.write_text(json.dumps(entry, ensure_ascii=False), encoding="utf-8")
        temporary.replace(path)

    def cached(self, url):
        """Cache entry without network (used to detect evidence changes)."""
        return self._read(url)

    def get(self, url, maximum, accept="application/json"):
        """Returns {url, content, content_sha256, retrieved_at, cached, stale}. Raises SourceUnavailable."""
        parts = re.match(r"https://([^/:?#]+)(/[^?#]*)(\?[^#]*)?$", url)
        if not parts or parts.group(1) not in self.HOSTS or ".." in parts.group(2).split("/"):
            raise SourceUnavailable("Destino de pesquisa fora da lista permitida.", "destination_refused")
        now = self.clock()
        entry = self._read(url)
        if entry and (entry.get("content") is not None or entry.get("not_found")):
            # Valid answers, including "this CVE is not registered" (404), are reused within the validity period.
            if now - dt.datetime.fromisoformat(entry["checked_at"]) < self.ttl:
                return dict(entry, cached=True, stale=False)
        elif entry and entry.get("failed_at") and now - dt.datetime.fromisoformat(entry["failed_at"]) < self.negative_ttl:
            raise SourceUnavailable(entry.get("error") or "Fonte indisponível (falha recente em cache).")
        if time.monotonic() - self.started > self.budget:
            return self._fallback(url, entry, now, "Orçamento de tempo da pesquisa esgotado.")
        headers = {"User-Agent": USER_AGENT, "Accept": accept}
        if entry and entry.get("content") is not None:
            if entry.get("etag"):
                headers["If-None-Match"] = entry["etag"]
            if entry.get("last_modified"):
                headers["If-Modified-Since"] = entry["last_modified"]
        try:
            with self.session.request("GET", url, headers=headers, timeout=(5, self.timeout), allow_redirects=False,
                                      verify=True, stream=True) as response:
                status = response.status_code
                if status == 304 and entry and entry.get("content") is not None:
                    entry.update(checked_at=_iso(now))
                    self._write(url, entry)
                    return dict(entry, cached=True, stale=False)
                if status == 404:
                    content = None
                elif 300 <= status < 400:
                    return self._fallback(url, entry, now, f"Fonte respondeu redirecionamento (HTTP {status}); não seguido.")
                elif not 200 <= status < 300:
                    return self._fallback(url, entry, now, f"Fonte indisponível (HTTP {status}).")
                else:
                    body = bytearray()
                    for chunk in response.iter_content(65536):
                        body.extend(chunk)
                        if len(body) > maximum:
                            return self._fallback(url, entry, now, "Resposta da fonte acima do limite.")
                    content = body.decode("utf-8", errors="replace")
                headers_in = getattr(response, "headers", {}) or {}
                fresh = {"url": url, "content": content, "not_found": content is None,
                         "content_sha256": hashlib.sha256((content or "").encode()).hexdigest(),
                         "retrieved_at": _iso(now), "checked_at": _iso(now),
                         "etag": headers_in.get("ETag"), "last_modified": headers_in.get("Last-Modified")}
                self._write(url, fresh)
                return dict(fresh, cached=False, stale=False)
        except requests.RequestException:
            return self._fallback(url, entry, now, "Falha de conexão, DNS ou TLS com a fonte.")

    def _fallback(self, url, entry, now, reason):
        if entry and entry.get("content") is not None and entry.get("retrieved_at"):
            if now - dt.datetime.fromisoformat(entry["retrieved_at"]) <= self.max_stale:
                return dict(entry, cached=True, stale=True, stale_reason=reason)
        self._write(url, {"url": url, "content": None, "failed_at": _iso(now), "error": reason})
        raise SourceUnavailable(reason)


def _evidence(source, publisher, fetched, eid, kind, excerpt, **scope):
    item = {"id": eid, "source": source, "publisher": publisher, "url": fetched["url"], "kind": kind,
            "retrieved_at": fetched["retrieved_at"], "checked_at": fetched.get("checked_at") or fetched["retrieved_at"],
            "cached": bool(fetched.get("cached")),
            "stale": bool(fetched.get("stale")), "content_sha256": fetched["content_sha256"],
            "excerpt": _text(excerpt)}
    item.update({k: v for k, v in scope.items() if v not in (None, "", [])})
    return item


# ----------------------------------------------------------------------
# Debian Security Tracker (per-CVE page; the full JSON feed is ~80 MB)
# ----------------------------------------------------------------------

class _Tables(HTMLParser):
    """Collects table rows (cell text) and link targets; scripts and styles ignored."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tables, self.links, self.pre = [], [], []
        self._row = self._cell = None
        self._skip = 0
        self._in_pre = False

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style"}:
            self._skip += 1
        elif tag == "table":
            self.tables.append([])
        elif tag == "tr" and self.tables:
            self._row = []
        elif tag in {"td", "th"} and self._row is not None:
            self._cell = []
        elif tag == "a":
            href = dict(attrs).get("href")
            if href:
                self.links.append(href)
        elif tag == "pre":
            self._in_pre = True
        elif tag == "br" and self._in_pre:
            self.pre.append("\n")

    def handle_endtag(self, tag):
        if tag in {"script", "style"}:
            self._skip = max(0, self._skip - 1)
        elif tag in {"td", "th"} and self._cell is not None and self._row is not None:
            self._row.append(" ".join("".join(self._cell).split()))
            self._cell = None
        elif tag == "tr" and self._row is not None:
            self.tables[-1].append(self._row)
            self._row = None
        elif tag == "pre":
            self._in_pre = False

    def handle_data(self, data):
        if self._skip:
            return
        if self._cell is not None:
            self._cell.append(data)
        if self._in_pre:
            self.pre.append(data)


def _table_with(tables, header):
    for table in tables:
        if table and table[0] and table[0][0] == header:
            return table
    return None


def debian_tracker(cve, fetcher):
    """Evidence from https://security-tracker.debian.org/tracker/<CVE>."""
    url = "https://security-tracker.debian.org/tracker/" + cve
    fetched = fetcher.get(url, 1024 * 1024, accept="text/html")
    publisher = "Debian Security Tracker"
    if fetched.get("not_found"):
        return {"source": "debian_security_tracker", "available": True, "found": False, "url": url,
                "retrieved_at": fetched["retrieved_at"], "evidence": [], "links": []}
    parser = _Tables()
    parser.feed(fetched["content"] or "")
    if not parser.tables:
        raise SourceUnavailable("Formato inesperado no Debian Security Tracker.", "unexpected_format")
    evidence = []
    status_table = _table_with(parser.tables, "Source Package") or []
    current = None
    for index, row in enumerate(status_table[1:]):
        if len(row) != 4:
            continue
        package = row[0].split(" (")[0].strip() or current
        current = package
        releases = [r.strip() for r in row[1].split(",") if r.strip()]
        for label in releases:
            release, _, pocket = label.partition(" (")  # "trixie (security)"
            evidence.append(_evidence(
                "debian_security_tracker", publisher, fetched, f"debian:{cve}:status:{index}:{label.replace(' ', '')}",
                "distribution_status", f"{package} em {label}: versão {row[2]}, estado {row[3]}",
                distribution="debian", release=release, pocket=pocket.rstrip(")") or None, source_package=package,
                package_type="source", version=row[2], status=row[3].lower()))
    fixed_table = _table_with(parser.tables, "Package") or []
    for index, row in enumerate(fixed_table[1:]):
        if len(row) < 5:
            continue
        release = row[2].strip("()")
        release = "sid" if release == "unstable" else release
        fixed = row[3]
        state = "unfixed" if fixed == "(unfixed)" else "not-affected" if fixed == "(not affected)" else "fixed"
        evidence.append(_evidence(
            "debian_security_tracker", publisher, fetched, f"debian:{cve}:fixed:{index}",
            "distribution_fix" if state == "fixed" else "distribution_status",
            f"{row[0]} ({row[1]}) em {row[2]}: versão corrigida {fixed}" + (f", urgência {row[4]}" if row[4] else ""),
            distribution="debian", release=release, source_package=row[0], package_type=row[1],
            fixed_version=fixed if state == "fixed" else None, status=state, urgency=row[4] or None))
    notes = _text("".join(parser.pre), 1200)
    if notes:
        evidence.append(_evidence("debian_security_tracker", publisher, fetched, f"debian:{cve}:notes", "note", notes,
                                  distribution="debian"))
    return {"source": "debian_security_tracker", "available": True, "found": True, "url": url,
            "retrieved_at": fetched["retrieved_at"], "cached": fetched.get("cached"), "stale": fetched.get("stale"),
            "evidence": evidence, "links": [l for l in parser.links if GHSA_LINK.fullmatch(l)]}


# ----------------------------------------------------------------------
# Ubuntu CVE tracker (https://ubuntu.com/security/cves/<CVE>.json)
# ----------------------------------------------------------------------

def ubuntu_cve(cve, fetcher):
    url = f"https://ubuntu.com/security/cves/{cve}.json"
    fetched = fetcher.get(url, 2 * 1024 * 1024)
    publisher = "Ubuntu Security (Canonical)"
    if fetched.get("not_found"):
        return {"source": "ubuntu_cve_tracker", "available": True, "found": False, "url": url,
                "retrieved_at": fetched["retrieved_at"], "evidence": [], "links": []}
    try:
        data = json.loads(fetched["content"])
    except ValueError:
        raise SourceUnavailable("Formato inesperado no Ubuntu CVE tracker.", "unexpected_format")
    if not isinstance(data, dict) or data.get("id") != cve or not isinstance(data.get("packages", []), list):
        raise SourceUnavailable("Formato inesperado no Ubuntu CVE tracker.", "unexpected_format")
    evidence = []
    for package in data.get("packages") or []:
        name = package.get("name") if isinstance(package, dict) else None
        if not isinstance(name, str):
            continue
        for status in package.get("statuses") or []:
            if not isinstance(status, dict):
                continue
            release, state = str(status.get("release_codename") or ""), str(status.get("status") or "").lower()
            version = status.get("description") if state == "released" else None
            evidence.append(_evidence(
                "ubuntu_cve_tracker", publisher, fetched, f"ubuntu:{cve}:{name}:{release}",
                "upstream_fix" if release == "upstream" and version else
                "distribution_fix" if version else "distribution_status",
                f"{name} em {release}: {state}" + (f" ({version}, pocket {status.get('pocket')})" if version else
                                                   (f" — {status.get('description')}" if status.get("description") else "")),
                distribution="ubuntu" if release != "upstream" else None, release=release, source_package=name,
                package_type="source", fixed_version=_text(version, 128), status=state,
                pocket=_text(status.get("pocket"), 40)))
    if _text(data.get("mitigation")):
        evidence.append(_evidence("ubuntu_cve_tracker", publisher, fetched, f"ubuntu:{cve}:mitigation", "mitigation",
                                  data["mitigation"], distribution="ubuntu"))
    links = [r for r in (data.get("references") or []) if isinstance(r, str) and GHSA_LINK.fullmatch(r)]
    return {"source": "ubuntu_cve_tracker", "available": True, "found": True, "url": url,
            "retrieved_at": fetched["retrieved_at"], "cached": fetched.get("cached"), "stale": fetched.get("stale"),
            "evidence": evidence, "links": links,
            "notices": [n for n in (data.get("notices_ids") or []) if isinstance(n, str)][:10]}


# ----------------------------------------------------------------------
# Upstream project advisories (GitHub Security Advisories)
# ----------------------------------------------------------------------

def _patched(value):
    """'v9.2.0847' / '>= 1.2.3' → '9.2.0847' / '1.2.3' (only simple single versions)."""
    text = str(value or "").strip()
    match = re.fullmatch(r"(?:>=\s*)?v?([0-9][0-9A-Za-z.+~:-]{0,63})", text)
    return match.group(1) if match else None


def github_advisory(link, cve, fetcher):
    """Repository advisory referenced by an official source (owner/repo/GHSA from a strict pattern)."""
    match = GHSA_LINK.fullmatch(link)
    if not match:
        raise SourceUnavailable("Link de advisory não reconhecido.", "destination_refused")
    owner, repo, ghsa = match.groups()
    url = f"https://api.github.com/repos/{owner}/{repo}/security-advisories/{ghsa}"
    fetched = fetcher.get(url, 1024 * 1024, accept="application/vnd.github+json")
    if fetched.get("not_found"):
        return {"source": "upstream_advisory", "available": True, "found": False, "url": url,
                "retrieved_at": fetched["retrieved_at"], "evidence": []}
    try:
        data = json.loads(fetched["content"])
    except ValueError:
        raise SourceUnavailable("Formato inesperado no advisory do GitHub.", "unexpected_format")
    if not isinstance(data, dict) or data.get("ghsa_id") != ghsa:
        raise SourceUnavailable("Formato inesperado no advisory do GitHub.", "unexpected_format")
    if data.get("cve_id") not in (None, cve) or data.get("state") not in (None, "published") or data.get("withdrawn_at"):
        return {"source": "upstream_advisory", "available": True, "found": False, "url": url,
                "retrieved_at": fetched["retrieved_at"], "evidence": []}
    publisher = f"{owner}/{repo} (GitHub Security Advisory)"
    evidence = []
    for index, vulnerability in enumerate(data.get("vulnerabilities") or []):
        if not isinstance(vulnerability, dict):
            continue
        package = (vulnerability.get("package") or {}).get("name")
        patched = _patched(vulnerability.get("patched_versions"))
        evidence.append(_evidence(
            "upstream_advisory", publisher, fetched, f"upstream:{ghsa}:{index}", "upstream_fix" if patched else "note",
            f"{data.get('summary') or ghsa}. Vulnerável: {vulnerability.get('vulnerable_version_range')}; "
            f"corrigido em: {vulnerability.get('patched_versions')}",
            upstream_project=f"{owner}/{repo}", package=_text(package, 100), fixed_version=patched,
            published_at=_text(data.get("published_at"), 40), advisory=ghsa))
    return {"source": "upstream_advisory", "available": True, "found": True, "url": url,
            "retrieved_at": fetched["retrieved_at"], "cached": fetched.get("cached"), "stale": fetched.get("stale"),
            "evidence": evidence}


SOURCES = {
    "debian": [("debian_security_tracker", debian_tracker)],
    "ubuntu": [("ubuntu_cve_tracker", ubuntu_cve)],
}


def collect(cve, distribution, settings=None, session=None, clock=None):
    """Query the distribution's official tracker, then upstream advisories it references.

    Returns {"sources": [{source, available, found, url, error?...}], "evidence": [...]}.
    Unavailable sources are reported, never treated as "no fix".
    """
    if not CVE.fullmatch(str(cve or "")):
        raise OperationError("CVE inválida para pesquisa.")
    settings = settings or {}
    enabled = set(settings.get("sources") or ("debian_security_tracker", "ubuntu_cve_tracker", "upstream_advisory"))
    fetcher = Fetcher(settings, session=session, clock=clock)
    sources, evidence, links = [], [], []
    for name, connector in SOURCES.get(distribution, []):
        if name not in enabled:
            continue
        try:
            result = connector(cve, fetcher)
            links.extend(result.pop("links", []))
            evidence.extend(result.pop("evidence"))
            sources.append(result)
        except SourceUnavailable as exc:
            sources.append({"source": name, "available": False, "found": False, "error": str(exc), "code": exc.code})
    if "upstream_advisory" in enabled:
        for link in list(dict.fromkeys(links))[:5]:
            try:
                result = github_advisory(link, cve, fetcher)
                evidence.extend(result.pop("evidence"))
                sources.append(result)
            except SourceUnavailable as exc:
                sources.append({"source": "upstream_advisory", "available": False, "found": False,
                                "url": link, "error": str(exc), "code": exc.code})
    return {"sources": sources, "evidence": evidence}
