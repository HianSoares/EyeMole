"""Transport, inventory freshness, SSO, and execution boundaries; no real integrations."""
import json
import sys
from pathlib import Path
from types import SimpleNamespace
import pytest
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from operations import connectors, security, worker
from operations.security import OperationError


class Response:
    def __init__(self, value, status=200):
        self.value = value
        self.status_code = status
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def iter_content(self, size): yield json.dumps(self.value).encode()


@pytest.mark.parametrize('status', [301, 302, 401, 500])
def test_transport_refuses_redirects_and_remote_error_bodies(monkeypatch, status):
    client = connectors.Client('https://example.com/api', {'Authorization': 'fixture-token'})
    seen = {}
    def request(*args, **kwargs):
        seen.update(kwargs)
        return Response({'secret': 'must-not-be-shown'}, status)
    monkeypatch.setattr(client.session, 'request', request)
    with pytest.raises(OperationError) as error:
        client.call('GET', '/items')
    assert 'must-not-be-shown' not in str(error.value)
    assert seen['allow_redirects'] is False and seen['timeout'] == (5, 30)
    assert client.session.trust_env is False and client.session.verify is True


def test_transport_caps_streamed_response(monkeypatch):
    client = connectors.Client('https://example.com')
    monkeypatch.setattr(client.session, 'request', lambda *a, **k: Response({'data': 'x' * 100}))
    with pytest.raises(OperationError, match='acima do limite'):
        client.call('GET', '/data', maximum=20)


def test_vision_one_cannot_send_token_to_foreign_next_link(monkeypatch):
    client = connectors.VisionOne({'url': 'https://example.com'}, {'VISION_ONE_TOKEN': 'fixture'})
    monkeypatch.setattr(client.client, 'call', lambda *a, **k: {'items': [], 'nextLink': 'https://elsewhere.example/v3.0/workbench/alerts?skip=100'})
    with pytest.raises(OperationError, match='origem'):
        client.incidents()


@pytest.mark.parametrize('scan', ['2026-01-01T10:00:00Z', None])
def test_inventory_uses_actual_scan_time_and_preserves_ambiguous_installations(monkeypatch, scan):
    client = connectors.Wazuh({'url': 'https://example.com'}, {'EYEMOLE_WAZUH_USER': 'fixture', 'EYEMOLE_WAZUH_PASSWORD': 'fixture'})
    def call(method, path):
        if path.startswith('/agents'):
            return {'data': {'affected_items': [{'status': 'active'}]}}
        if path.endswith('/os'):
            return {'data': {'affected_items': [{'architecture': 'x86_64'}]}}
        return {'data': {'total_affected_items': 2, 'affected_items': [{'name': 'openssl', 'version': v, 'scan': {'time': scan}} for v in ['1.0', '1.1']]}}
    monkeypatch.setattr(client.client, 'call', call)
    inventory = client.inventory('001')
    assert inventory['observed_at'] == scan
    assert inventory['packages']['openssl'] == 'ambiguous'
    assert inventory['retrieved_at'] != scan


@pytest.mark.parametrize('url', ['https://external.example/oauth2/auth', 'http://127.0.0.1:4180/other', 'http://user@127.0.0.1:4180/oauth2/auth'])
def test_sso_rejects_nonlocal_auth_proxy_before_sending_cookies(url):
    with pytest.raises(OperationError, match='Auth proxy'):
        security.authenticated_identity({'Cookie': 'fixture'}, {'authentication': {'mode': 'oidc', 'auth_proxy_url': url}})


def test_sso_requires_validated_proxy_identity_not_supplied_user_header(monkeypatch):
    class ProxyResponse:
        headers = {'X-Auth-Request-User': 'corporate-user'}
        def geturl(self): return 'http://127.0.0.1:4180/oauth2/auth'
        def __enter__(self): return self
        def __exit__(self, *args): pass
    seen = {}
    def open_request(request, timeout):
        seen.update(cookie=request.get_header('Cookie'), timeout=timeout)
        return ProxyResponse()
    monkeypatch.setattr(security, 'build_opener', lambda *args: SimpleNamespace(open=open_request))
    result = security.authenticated_identity({'Cookie': 'fixture', 'X-Remote-User': 'spoofed'}, {'authentication': {'mode': 'oidc'}})
    assert result == 'corporate-user' and seen == {'cookie': 'fixture', 'timeout': 5}


def test_execution_does_not_use_llm_or_grouped_shell_commands():
    base = {'package': 'openssl', 'fixed_version': '2.0', 'installed_version': '1.0', 'package_manager': 'apt', 'command': 'apt-get upgrade openssl', 'confidence': 'high'}
    action = worker.execution_action(base)
    assert action['argv'][-1] == 'openssl=2.0'
    assert worker.execution_action(dict(base, confidence='low')) is None
    assert worker.execution_action(dict(base, assumptions=['Comando agrupado com dependências'])) is None
    assert worker.execution_action(dict(base, package='openssl;id')) is None


def test_kiro_text_banners_do_not_hide_ambiguous_contracts_or_extra_fields():
    from operations.kiro import parse_output
    value = {'summary': 'Contexto insuficiente', 'recommendations': [{'finding_id': 'finding', 'evidence_ids': ['official'], 'explanation': 'Revisar produto e versão.'}]}
    answer = json.dumps(value)
    assert parse_output(('\x1b[32mKiro\x1b[0m\n```json\n' + answer + '\n```').encode(), {'official'}, {'finding'}) == value
    with pytest.raises(OperationError, match='única resposta'):
        parse_output((answer + '\n' + answer).encode(), {'official'}, {'finding'})
    unsafe = json.dumps(dict(value, command='must not become an action'))
    with pytest.raises(OperationError):
        parse_output(unsafe.encode(), {'official'}, {'finding'})
