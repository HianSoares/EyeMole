"""
Consistência da orientação quando as fontes mudam DURANTE a geração.

Cada teste troca um arquivo de fonte no meio da geração (via hook nos
providers) e verifica que:
- a orientação devolvida corresponde a um único conjunto estável de revisões;
- snapshot_revision identifica exatamente as revisões lidas;
- fontes instáveis resultam em falha fechada (sem resultado parcial);
- um resultado gerado enquanto as fontes mudavam não fica preso no cache.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from remediation.cache import GuidanceCache
from remediation.engine import MAX_GENERATION_ATTEMPTS, RemediationEngine
from remediation.models import generate_finding_id

TEMPLATES_PATH = Path(__file__).parent.parent / "remediation" / "data" / "remediation_templates.json"


def _vuln(**overrides):
    base = {
        "cve": "CVE-2026-0001", "agent_id": "001", "agent_name": "srv-01",
        "package": "demo", "version": "1.0-1", "severity": "High",
        "operating_system": "ubuntu", "package_type": "deb", "fixed_version": "2.0-1",
    }
    base.update(overrides)
    return base


def _fid(v):
    return generate_finding_id(v["cve"], v["agent_id"], v["package"], v["version"], v.get("package_type", ""))


def _replace(path: Path, content: str) -> None:
    """Substituição atômica com mtime distinto (como os publicadores fazem)."""
    tmp = path.with_name(path.name + ".swap")
    tmp.write_text(content, encoding="utf-8")
    old = path.stat().st_mtime_ns if path.exists() else 0
    os.utime(tmp, ns=(old + 5_000_000_000, old + 5_000_000_000))
    os.replace(tmp, path)


def _engine(tmp_path, vulns, grype_vulns=None, grype=False):
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "remediation_providers.json").write_text(json.dumps({"providers": [
        {"name": "wazuh_snapshot", "enabled": True},
        {"name": "grype_snapshot", "enabled": grype}]}), encoding="utf-8")
    (cfg / "assets_context.json").write_text(json.dumps({"agents": {}}), encoding="utf-8")
    snapshot = tmp_path / "latest.json"
    snapshot.write_text(json.dumps({"vulnerabilities": vulns}), encoding="utf-8")
    out = tmp_path / "output"
    out.mkdir()
    gpath = out / "grype_latest.json"
    if grype_vulns is not None:
        gpath.write_text(json.dumps({"vulnerabilities": grype_vulns}), encoding="utf-8")
    return RemediationEngine(config_dir=cfg, snapshot_path=snapshot,
                             templates_path=TEMPLATES_PATH, grype_snapshot_path=gpath)


def _hook_once(obj, name, action):
    """Executa `action` uma única vez, logo após a primeira chamada de obj.name."""
    original = getattr(obj, name)
    state = {"done": False, "calls": 0}

    def wrapper(*args, **kwargs):
        result = original(*args, **kwargs)
        state["calls"] += 1
        if not state["done"]:
            state["done"] = True
            action()
        return result

    setattr(obj, name, wrapper)
    return state


class TestSourceChangesDuringGeneration:

    def test_wazuh_snapshot_replaced_mid_generation_is_regenerated(self, tmp_path):
        v1 = _vuln(version="1.0-1")
        engine = _engine(tmp_path, [v1])
        v1b = _vuln(version="1.0-1", fixed_version="3.0-1")  # mesma instância, novo dado
        state = _hook_once(engine._wazuh_provider, "query", lambda: _replace(
            tmp_path / "latest.json", json.dumps({"vulnerabilities": [v1b]})))

        g = engine.generate_guidance(_fid(v1))

        assert state["calls"] == 2  # 1ª tentativa descartada, 2ª estável
        assert g.status == "success"
        assert g.fixed_version == "3.0-1"  # nunca o dado da revisão superada
        stable = engine.generate_guidance(_fid(v1))
        assert stable.snapshot_revision == g.snapshot_revision

    def test_grype_view_is_pinned_between_correlation_and_branches(self, tmp_path):
        v = _vuln(fixed_version="2.0-1")
        grype_row = {"cve": "CVE-2026-0001", "agent_id": "001", "package_name": "demo",
                     "installed_version": "1.0-1", "fixed_version": "3.0-1",
                     "fixed_versions": ["3.0-1", "2.0-1"], "confidence": "high", "status": "fixed"}
        engine = _engine(tmp_path, [v], [grype_row], grype=True)
        gpath = tmp_path / "output" / "grype_latest.json"

        seen_views = []
        real_branches = engine._grype_provider.fixed_versions_for

        def spy_branches(record, view=None):
            seen_views.append(view)
            return real_branches(record, view=view)

        engine._grype_provider.fixed_versions_for = spy_branches
        # Logo após a correlação, o Grype passa a NÃO listar o ramo 2.0-1.
        changed = dict(grype_row, fixed_versions=["3.0-1"])
        _hook_once(engine._grype_provider, "query_record",
                   lambda: _replace(gpath, json.dumps({"vulnerabilities": [changed]})))

        g = engine.generate_guidance(_fid(v))

        # 1ª tentativa: ramos lidos da MESMA visão da correlação (não do arquivo novo)
        assert seen_views[0] is not None
        assert "2.0-1" in real_branches(v, view=seen_views[0])
        # Resultado final usa só a revisão nova: divergência → sem comando
        assert g.command is None
        assert "divergem" in (g.reason or "")

    def test_assets_context_change_during_grouping_is_not_mixed(self, tmp_path):
        main = _vuln(package="libssl3", package_type="", operating_system="")
        related = _vuln(package="openssl", package_type="", operating_system="")
        engine = _engine(tmp_path, [main, related])
        assets = tmp_path / "config" / "assets_context.json"
        _replace(assets, json.dumps({"agents": {"001": {"operating_system": "ubuntu"}}}))

        resolved = []
        real_resolve = engine._wazuh_provider._resolve_os

        def spy_resolve(*args, **kwargs):
            result = real_resolve(*args, **kwargs)
            resolved.append(result)
            if len(resolved) == 1:
                _replace(assets, json.dumps({"agents": {"001": {"operating_system": "rocky"}}}))
            return result

        engine._wazuh_provider._resolve_os = spy_resolve
        g = engine.generate_guidance(_fid(main))

        # Na 1ª tentativa todas as linhas usaram a MESMA revisão (ubuntu),
        # mesmo com o arquivo trocado no meio; a 2ª tentativa usa só "rocky".
        first_attempt = resolved[:2]
        assert first_attempt == ["ubuntu", "ubuntu"]
        assert g.operating_system == "rocky"
        assert g.package_manager == "dnf"

    def test_unstable_sources_fail_closed(self, tmp_path):
        v = _vuln()
        engine = _engine(tmp_path, [v])
        counter = {"n": 0}
        real_query = engine._wazuh_provider.query

        def always_changing(*args, **kwargs):
            result = real_query(*args, **kwargs)
            counter["n"] += 1
            _replace(tmp_path / "latest.json", json.dumps({"vulnerabilities": [v], "n": counter["n"]}))
            return result

        engine._wazuh_provider.query = always_changing
        g = engine.generate_guidance(_fid(v))

        assert counter["n"] == MAX_GENERATION_ATTEMPTS
        assert g.status == "provider_unavailable"
        assert g.command is None and g.fixed_version is None
        assert "mudaram durante a geração" in g.reason

    def test_revision_covers_every_source(self, tmp_path):
        v = _vuln()
        engine = _engine(tmp_path, [v], [], grype=True)
        base = engine.generate_guidance(_fid(v)).snapshot_revision
        assert base and engine.generate_guidance(_fid(v)).snapshot_revision == base
        assert set(engine._pins) == {
            "wazuh", "grype", "assets_context", "allowlist", "providers_config",
            "generic_policy", "templates", "evidence",
        }

        revisions = {base}
        for path in (tmp_path / "output" / "grype_latest.json",
                     tmp_path / "config" / "assets_context.json"):
            _replace(path, path.read_text(encoding="utf-8") + " ")
            revisions.add(engine.generate_guidance(_fid(v)).snapshot_revision)
        assert len(revisions) == 3


class TestApiDoesNotCacheMixedResults:

    def test_result_generated_while_sources_changed_is_not_cached(self, tmp_path):
        import soar_api

        v = _vuln()
        engine = _engine(tmp_path, [v])
        cache = GuidanceCache(snapshot_path=tmp_path / "latest.json",
                              dependency_paths=engine.dependency_paths)
        assets = tmp_path / "config" / "assets_context.json"
        # Muda uma fonte depois que a API capturou a assinatura, durante a geração.
        _hook_once(engine._wazuh_provider, "query",
                   lambda: _replace(assets, json.dumps({"agents": {"001": {}}})))

        handler = MagicMock()
        handler._get_remote_user.return_value = "analyst"
        handler._get_client_ip.return_value = "127.0.0.1"
        handler.headers = {}
        parsed = MagicMock(path="/remediation-guidance/" + _fid(v), query="")

        with patch.object(soar_api, "_init_remediation_module", return_value=True), \
             patch.object(soar_api, "_remediation_engine", engine), \
             patch.object(soar_api, "_guidance_cache", cache):
            soar_api.SoarAPIHandler._handle_remediation_guidance_get_internal(handler, parsed)
            first = handler._send_guidance_response.call_args[0][0]
            assert first.status == "success"
            assert cache.size() == 0  # não armazenado: fontes mudaram no meio

            soar_api.SoarAPIHandler._handle_remediation_guidance_get_internal(handler, parsed)
            assert cache.size() == 1  # geração estável é armazenada
            second = handler._send_guidance_response.call_args[0][0]
            assert second.snapshot_revision == first.snapshot_revision
