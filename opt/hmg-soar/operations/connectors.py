"""Bounded official APIs; only worker processes receive integration secrets."""
import hashlib
import json
import re
import time
from urllib.parse import urlencode, urlsplit

import requests
from .security import OperationError
from .store import now


class Client:
    def __init__(self, base, headers=None, ca=None):
        parsed = urlsplit(base)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise OperationError("Integração exige URL HTTPS sem credenciais ou query.")
        self.base = base.rstrip("/")
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.headers.update(headers or {})
        self.session.verify = ca or True
        self.started = time.monotonic()
        self.calls = 0

    def call(self, method, path, payload=None, headers=None, maximum=8 * 1024 * 1024):
        self.calls += 1
        if self.calls > 500 or time.monotonic() - self.started > 300:
            raise OperationError("Conector excedeu orçamento de chamadas/prazo; reduza o escopo.", 504)
        if not path.startswith("/") or path.startswith("//") or ".." in path.split("/"):
            raise OperationError("Caminho de integração inválido.")
        try:
            with self.session.request(method, self.base + path, json=payload, headers=headers,
                                      timeout=(5, 30), allow_redirects=False, stream=True) as response:
                if not 200 <= response.status_code < 300:
                    raise OperationError("Integração retornou HTTP " + str(response.status_code), 502)
                content = bytearray()
                for part in response.iter_content(65536):
                    content.extend(part)
                    if len(content) > maximum:
                        raise OperationError("Resposta da integração acima do limite.", 502)
                return json.loads(content) if content else {}
        except OperationError:
            raise
        except (requests.RequestException, ValueError):
            raise OperationError("Falha de conexão ou formato na integração.", 502)


class GLPI:
    def __init__(self, settings, secrets):
        self.client = Client(settings["url"], {"App-Token": secrets["GLPI_APP_TOKEN"]}, settings.get("ca"))
        self.user_token = secrets["GLPI_USER_TOKEN"]

    def session(self):
        response = self.client.call("GET", "/initSession", headers={"Authorization": "user_token " + self.user_token})
        token = response.get("session_token")
        if not isinstance(token, str) or not token:
            raise OperationError("GLPI não retornou sessão válida.", 502)
        self.client.session.headers["Session-Token"] = token

    def close(self):
        try:
            self.client.call("GET", "/killSession")
        except OperationError:
            pass  # Cleanup must not discard an acknowledged ticket ID.
        finally:
            self.client.session.close()

    def create(self, campaign):
        self.session()
        try:
            # This is an external identifier for reconciliation, not HTML or secrets.
            marker = f"[EyeMole:{campaign['project']}:{campaign['id']}]"
            result = self.client.call("POST", "/Ticket", {"input": {
                "name": marker + " " + campaign["name"],
                "content": f"Campanha: {campaign['id']}\nResponsável: {campaign['owner']}\nExposições: {campaign['exposure_count']}\nEstado: {campaign['status']}\nPrazo: {campaign.get('due_at') or 'não definido'}",
                "type": 1, "urgency": 3, "impact": 3}})
            ticket_id = result.get("id")
            if not isinstance(ticket_id, int) or ticket_id <= 0:
                raise OperationError("GLPI não retornou ID válido; reconciliar antes de repetir.", 502)
            return {"ticket_id": ticket_id, "marker": marker, "provider": "glpi", "created_at": now()}
        finally:
            self.close()

    def read(self, ticket_id):
        self.session()
        try:
            return self.client.call("GET", "/Ticket/" + str(int(ticket_id)))
        finally:
            self.close()


class QRadar:
    def __init__(self, settings, secrets):
        self.client = Client(settings["url"], {"SEC": secrets["QRADAR_TOKEN"],
                             "Version": settings.get("api_version", "20.0"), "Accept": "application/json"}, settings.get("ca"))

    def incidents(self):
        output = []
        complete = False
        for page in range(20):
            rows = self.client.call("GET", "/siem/offenses?filter=status%3DOPEN",
                                    headers={"Range": f"items={page * 100}-{page * 100 + 99}"})
            if not isinstance(rows, list):
                raise OperationError("Lista QRadar inválida.", 502)
            for row in rows:
                observables = []
                for key, endpoint in (("source_address_ids", "source_addresses"),
                                      ("local_destination_address_ids", "local_destination_addresses")):
                    for identifier in row.get(key, [])[:50]:
                        address = self.client.call("GET", f"/siem/{endpoint}/{int(identifier)}")
                        if address.get("ip"):
                            observables.append(str(address["ip"]))
                output.append({"provider": "qradar", "external_id": str(row["id"]),
                               "title": str(row.get("description", ""))[:500], "severity": row.get("magnitude"),
                               "observables": sorted(set(observables)), "observed_at": now()})
            if len(rows) < 100:
                complete = True
                break
        return output, complete


class VisionOne:
    def __init__(self, settings, secrets):
        self.client = Client(settings["url"], {"Authorization": "Bearer " + secrets["VISION_ONE_TOKEN"]}, settings.get("ca"))

    def incidents(self):
        path = "/v3.0/workbench/alerts?top=100"
        output, complete = [], False
        for _ in range(20):
            page = self.client.call("GET", path)
            rows = page.get("items")
            if not isinstance(rows, list):
                raise OperationError("Lista Vision One inválida.", 502)
            for row in rows:
                observables = set()
                for entity in row.get("impactScope", {}).get("entities", []):
                    value = entity.get("entityValue", {})
                    if isinstance(value, dict):
                        observables.update(str(a) for a in value.get("ips", []))
                        if value.get("name"):
                            observables.add(str(value["name"]))
                    elif isinstance(value, str):
                        observables.add(value)
                output.append({"provider": "vision_one", "external_id": str(row["id"]),
                               "title": str(row.get("model", ""))[:500], "severity": row.get("severity"),
                               "observables": sorted(observables), "observed_at": now()})
            link = page.get("nextLink")
            if not link:
                complete = True
                break
            # Never send the bearer token to a paginated URL on another origin.
            if not link.startswith(self.client.base + "/v3.0/workbench/alerts?"):
                raise OperationError("Paginação Vision One fora da origem aprovada.", 502)
            path = link[len(self.client.base):]
        return output, complete


class Wazuh:
    def __init__(self, settings, secrets):
        self.client = Client(settings["url"], ca=settings.get("ca"))
        self.auth = (secrets["EYEMOLE_WAZUH_USER"], secrets["EYEMOLE_WAZUH_PASSWORD"])

    def login(self):
        # Use the same transport limits and refuse redirects during authentication.
        self.client.session.auth = self.auth
        response = self.client.call("POST", "/security/user/authenticate")
        self.client.session.auth = None
        token = response.get("data", {}).get("token")
        if not isinstance(token, str) or not token:
            raise OperationError("Autenticação Wazuh inválida.", 502)
        self.client.session.headers["Authorization"] = "Bearer " + token

    def inventory(self, agent):
        if not re.fullmatch(r"[0-9]{3,8}", agent) or int(agent) == 0:
            raise OperationError("ID Wazuh inválido; manager não é alvo.")
        result = {"observed_at": now(), "source": "wazuh_api", "agent_ids": [agent], "packages": {},
                  "hotfixes": [], "roles_collection_state": "unavailable", "roles": [], "reboot_pending": "unknown"}
        result["retrieved_at"] = now()
        observed = []
        state = self.client.call("GET", "/agents?agents_list=" + agent)
        agents = state.get("data", {}).get("affected_items", [])
        result["agent_status"] = agents[0].get("status", "unknown") if agents else "unknown"
        os_data = self.client.call("GET", f"/syscollector/{agent}/os")
        items = os_data.get("data", {}).get("affected_items", [])
        if items:
            result.update(os=items[0].get("os", {}), architecture=items[0].get("architecture", "unknown"))
        total = 0
        for page in range(50):
            package_data = self.client.call("GET", f"/syscollector/{agent}/packages?limit=500&offset={page * 500}")
            items = package_data.get("data", {}).get("affected_items", [])
            total += len(items)
            for row in items:
                if row.get("scan", {}).get("time"):
                    observed.append(str(row["scan"]["time"]))
                if row.get("name") and row.get("version"):
                    # Multiple installations must not be hidden behind one arbitrary version.
                    previous = result["packages"].get(row["name"])
                    if previous is not None and previous != row["version"]:
                        result["packages"][row["name"]] = "ambiguous"
                    else:
                        result["packages"][row["name"]] = row["version"]
            if total >= package_data.get("data", {}).get("total_affected_items", total):
                result["packages_complete"] = True
                break
        result.setdefault("packages_complete", False)
        # Retrieval time is not inventory scan time. Missing coverage blocks confirmation.
        result["observed_at"] = min(observed) if observed and result["packages_complete"] else None
        return result

    def dispatch(self, agent, argument):
        return self.client.call("PUT", "/active-response?" + urlencode({"agents_list": agent, "wait_for_complete": "true"}),
                                {"command": "!eyemole-remediate", "custom": True, "arguments": [argument], "alert": {}})


def vendor_evidence(cve, product, month=None):
    """Official source material is evidence, never an automatic applicability decision."""
    if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve):
        raise OperationError("CVE inválida.")
    product = str(product).lower()
    if "windows" in product or "microsoft" in product:
        if not month or not re.fullmatch(r"\d{4}-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)", month):
            raise OperationError("Configure evidence_month (AAAA-Mmm) para consultar o CVRF Microsoft.")
        client = Client("https://api.msrc.microsoft.com/cvrf/v3.0", {"Accept": "application/json"})
        path = "/cvrf/" + month
        doc = client.call("GET", path)
        vulnerabilities = [v for v in doc.get("Vulnerability", []) if v.get("CVE") == cve]
        material = {"ProductTree": doc.get("ProductTree", {}), "Vulnerability": vulnerabilities}
    elif any(p in product for p in ("rhel", "red hat", "rocky", "alma")):
        client = Client("https://access.redhat.com/hydra/rest/securitydata")
        path = "/cve/" + cve + ".json"
        material = client.call("GET", path)
    elif "ubuntu" in product:
        client = Client("https://ubuntu.com")
        path = "/security/cves.json?" + urlencode({"q": cve, "limit": 10})
        material = client.call("GET", path)
    else:
        raise OperationError("Fornecedor sem provider de evidência; use a fonte oficial e curadoria local.")
    encoded = json.dumps(material, sort_keys=True)
    return {"cve": cve, "url": client.base + path, "retrieved_at": now(),
            "content_sha256": hashlib.sha256(encoded.encode()).hexdigest(), "material": material,
            "applicability": "needs_review"}
