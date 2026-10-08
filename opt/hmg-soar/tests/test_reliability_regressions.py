"""
Regressões de confiabilidade do fluxo "Ver correção" (revisão técnica 08/10/2026).

Cada classe reproduz um achado confirmado contra o commit 42ac9e4 e demonstra
a correção. Dados sintéticos e mocks: nenhuma rede, nenhum comando executado.
"""

from __future__ import annotations

import builtins
import json
import os
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import grype_runner
from remediation.cache import GuidanceCache
from remediation.engine import RemediationEngine, SnapshotCache
from remediation.models import (
    GrypeVulnRecord,
    GuidanceRecord,
    ProviderResult,
    VulnRecord,
    generate_finding_id,
    generate_vulnerability_key,
)
from remediation.providers.wazuh_provider import WazuhProvider
from remediation.templates import TemplateRepository
from remediation.versioning import compare_versions

TEMPLATES_PATH = Path(__file__).parent.parent / "remediation" / "data" / "remediation_templates.json"


# ==========================================================================
# Helpers
# ==========================================================================

def _vuln(**overrides) -> dict:
    base = {
        "cve": "CVE-2026-0001",
        "agent_id": "001",
        "agent_name": "srv-01",
        "package": "demo",
        "version": "1.0-1",
        "severity": "High",
        "operating_system": "ubuntu",
        "package_type": "deb",
    }
    base.update(overrides)
    return base


def _fid(v: dict) -> str:
    return generate_finding_id(
        v["cve"], v["agent_id"], v["package"], v["version"],
        v.get("package_type", ""), v.get("package_architecture", ""), v.get("package_path", ""),
    )


def _write_snapshot(path: Path, vulns: list) -> None:
    path.write_text(json.dumps({"vulnerabilities": vulns}), encoding="utf-8")


def _replace_atomically(path: Path, vulns: list, keep_stat: bool = False) -> None:
    """Substitui via rename (como o analisador publica). keep_stat força mesmo mtime."""
    old = path.stat()
    tmp = path.with_name(".tmp-" + path.name)
    tmp.write_text(json.dumps({"vulnerabilities": vulns}), encoding="utf-8")
    if keep_stat:
        os.utime(tmp, ns=(old.st_atime_ns, old.st_mtime_ns))
    else:
        bump = old.st_mtime_ns + 5_000_000_000
        os.utime(tmp, ns=(bump, bump))
    os.replace(tmp, path)


def _config(config_dir: Path, wazuh=True, grype=False, extra_providers=None) -> Path:
    config_dir.mkdir(parents=True, exist_ok=True)
    providers = [
        {"name": "wazuh_snapshot", "enabled": wazuh, "priority": 1},
        {"name": "grype_snapshot", "enabled": grype, "priority": 2},
    ]
    (config_dir / "remediation_providers.json").write_text(
        json.dumps({"providers": providers}), encoding="utf-8")
    (config_dir / "generic_update_policy.json").write_text(
        json.dumps({"enabled": False, "allowed_combinations": []}), encoding="utf-8")
    (config_dir / "assets_context.json").write_text(json.dumps({"agents": {}}), encoding="utf-8")
    (config_dir / "remediation_allowlist.json").write_text(json.dumps({
        "os_to_package_manager": {"ubuntu": "apt", "rocky": "dnf", "sles": "zypper",
                                  "alpine": "apk", "windows": "windows"},
        "package_type_to_package_manager": {"deb": "apt", "windows": "windows"},
        "package_type_os_to_package_manager": {"rpm": {"rocky": "dnf", "sles": "zypper"}},
    }), encoding="utf-8")
    return config_dir


def _engine(tmp_path: Path, vulns: list, grype_vulns=None, wazuh=True, grype=False) -> RemediationEngine:
    config_dir = _config(tmp_path / "config", wazuh=wazuh, grype=grype)
    snapshot = tmp_path / "latest.json"
    _write_snapshot(snapshot, vulns)
    output = tmp_path / "output"
    output.mkdir(exist_ok=True)
    grype_path = output / "grype_latest.json"
    if grype_vulns is not None:
        grype_path.write_text(json.dumps({"vulnerabilities": grype_vulns}), encoding="utf-8")
    return RemediationEngine(
        config_dir=config_dir, snapshot_path=snapshot, templates_path=TEMPLATES_PATH,
        grype_snapshot_path=grype_path,
    )


def _grype(**overrides) -> dict:
    base = {
        "cve": "CVE-2026-0001", "advisory_id": "GHSA-x", "agent_id": "001",
        "package_name": "demo", "installed_version": "1.0-1", "fixed_version": "2.0-1",
        "fixed_versions": ["2.0-1"], "confidence": "high", "match_type": "exact-direct-match",
        "status": "fixed", "purl": "",
    }
    base.update(overrides)
    return base


# ==========================================================================
# Achado 1 — Snapshot Wazuh sempre na revisão atual
# ==========================================================================

class TestWazuhSnapshotRevision:

    def _provider(self, tmp_path, vulns):
        snapshot = tmp_path / "latest.json"
        _write_snapshot(snapshot, vulns)
        return snapshot, WazuhProvider(snapshot, tmp_path / "assets.json", tmp_path / "allow.json")

    def test_query_sees_replaced_snapshot(self, tmp_path):
        v1 = _vuln(version="1.0-1")
        snapshot, provider = self._provider(tmp_path, [v1])
        legacy = generate_vulnerability_key(v1["cve"], "001", "demo", "High")
        assert provider.query(legacy).installed_version == "1.0-1"

        _replace_atomically(snapshot, [_vuln(version="2.0-1")])

        assert provider.query(legacy).installed_version == "2.0-1"
        assert provider.resolve_finding(legacy)["version"] == "2.0-1"

    def test_atomic_replace_with_same_mtime_and_size_is_detected(self, tmp_path):
        v1 = _vuln(version="1.0-1")
        snapshot, provider = self._provider(tmp_path, [v1])
        legacy = generate_vulnerability_key(v1["cve"], "001", "demo", "High")
        provider.query(legacy)
        # Mesmo tamanho e mesmo mtime: só o inode muda.
        _replace_atomically(snapshot, [_vuln(version="3.0-1")], keep_stat=True)
        assert provider.query(legacy).installed_version == "3.0-1"

    def test_removed_snapshot_drops_previous_data(self, tmp_path):
        v1 = _vuln()
        snapshot, provider = self._provider(tmp_path, [v1])
        assert provider.query(_fid(v1)) is not None
        snapshot.unlink()
        assert provider.query(_fid(v1)) is None
        assert provider.resolve_finding(_fid(v1)) is None
        assert provider.current_view() is None

    def test_invalid_snapshot_drops_previous_data(self, tmp_path):
        v1 = _vuln()
        snapshot, provider = self._provider(tmp_path, [v1])
        assert provider.query(_fid(v1)) is not None
        tmp = snapshot.with_name("broken.json")
        tmp.write_text("{not json", encoding="utf-8")
        os.replace(tmp, snapshot)
        assert provider.query(_fid(v1)) is None

    def test_assets_context_change_is_reloaded(self, tmp_path):
        v1 = _vuln(operating_system="", package_type="")
        snapshot, _ = self._provider(tmp_path, [v1])
        assets = tmp_path / "assets.json"
        assets.write_text(json.dumps({"agents": {"001": {"operating_system": "ubuntu"}}}), encoding="utf-8")
        provider = WazuhProvider(snapshot, assets, tmp_path / "allow.json")
        assert provider.query(_fid(v1)).package_manager == "apt"

        tmp = assets.with_name("assets.tmp")
        tmp.write_text(json.dumps({"agents": {"001": {"operating_system": "rocky"}}}), encoding="utf-8")
        os.replace(tmp, assets)
        assert provider.query(_fid(v1)).package_manager == "dnf"

    def test_engine_guidance_follows_new_revision(self, tmp_path):
        v1 = _vuln(version="1.0-1", fixed_version="2.0-1")
        engine = _engine(tmp_path, [v1])
        legacy = generate_vulnerability_key(v1["cve"], "001", "demo", "High")
        first = engine.generate_guidance(legacy)
        assert first.installed_version == "1.0-1"

        _replace_atomically(tmp_path / "latest.json", [_vuln(version="1.5-1", fixed_version="2.0-1")])
        second = engine.generate_guidance(legacy)
        assert second.installed_version == "1.5-1"
        assert second.snapshot_revision and second.snapshot_revision != first.snapshot_revision

    def test_grouping_uses_the_same_revision_as_the_query(self, tmp_path):
        main = _vuln(package="libssl3", fixed_version="2.0-1")
        related = _vuln(package="openssl", fixed_version="2.0-1")
        engine = _engine(tmp_path, [main, related])
        view = engine._wazuh_provider.current_view()
        pr = engine._wazuh_provider.query(_fid(main), view=view)

        # Arquivo muda no meio da requisição: o agrupamento continua na revisão fixada.
        _replace_atomically(tmp_path / "latest.json", [main])
        names, _ = engine._find_related_apt_packages(pr, view)
        assert names == ["libssl3", "openssl"]

    def test_legacy_snapshot_cache_reloads_on_replacement(self, tmp_path):
        snapshot = tmp_path / "latest.json"
        _write_snapshot(snapshot, [_vuln()])
        cache = SnapshotCache(snapshot)
        assert len(cache.get_data()["vulnerabilities"]) == 1
        _replace_atomically(snapshot, [])
        assert cache.get_data()["vulnerabilities"] == []
        snapshot.unlink()
        assert cache.get_data() is None


# ==========================================================================
# Achado 2 — Persistência do Grype por agente
# ==========================================================================

def _grec(agent_id: str, cve: str = "CVE-2021-23337") -> GrypeVulnRecord:
    return GrypeVulnRecord(
        cve=cve, advisory_id="GHSA-x", agent_id=agent_id, package_name="lodash",
        installed_version="4.17.15", fixed_version="4.17.21", fixed_versions=["4.17.21"],
        confidence="high", match_type="exact-direct-match", purl="pkg:npm/lodash@4.17.15",
        db_version="v6", status="fixed",
    )


class TestGrypePersistence:

    @pytest.fixture
    def dirs(self, tmp_path):
        pending = tmp_path / "sbom" / "pending"
        pending.mkdir(parents=True)
        return dict(
            pending_dir=pending,
            processed_dir=tmp_path / "sbom" / "processed",
            failed_dir=tmp_path / "sbom" / "failed",
            output_path=tmp_path / "output" / "grype_latest.json",
        )

    def _run(self, dirs, results):
        """results: {agent_id: list[GrypeVulnRecord] | Exception}"""
        for agent_id in results:
            (dirs["pending_dir"] / f"{agent_id}.json").write_text("{}", encoding="utf-8")

        def fake(path, timeout_seconds):
            value = results[path.stem]
            if isinstance(value, Exception):
                raise value
            return value

        with patch.object(grype_runner, "process_sbom", fake):
            return grype_runner.process_pending(**dirs)

    def _snapshot(self, dirs):
        return json.loads(dirs["output_path"].read_text(encoding="utf-8"))

    def test_empty_batch_preserves_existing_results(self, dirs):
        self._run(dirs, {"003": [_grec("003")]})
        before = dirs["output_path"].stat().st_mtime_ns

        meta = self._run(dirs, {})

        assert meta["written"] is False
        assert dirs["output_path"].stat().st_mtime_ns == before
        assert len(self._snapshot(dirs)["vulnerabilities"]) == 1

    def test_agent_update_preserves_other_agents(self, dirs):
        self._run(dirs, {"003": [_grec("003")], "004": [_grec("004")]})
        self._run(dirs, {"003": [_grec("003", cve="CVE-2020-8203")]})

        vulns = self._snapshot(dirs)["vulnerabilities"]
        by_agent = {(v["agent_id"], v["cve"]) for v in vulns}
        assert by_agent == {("003", "CVE-2020-8203"), ("004", "CVE-2021-23337")}

    def test_valid_scan_without_findings_clears_only_that_agent(self, dirs):
        self._run(dirs, {"003": [_grec("003")], "004": [_grec("004")]})
        self._run(dirs, {"003": []})

        vulns = self._snapshot(dirs)["vulnerabilities"]
        assert [v["agent_id"] for v in vulns] == ["004"]
        agents = self._snapshot(dirs)["metadata"]["agents"]
        assert agents["003"]["vulnerability_count"] == 0
        assert agents["003"]["last_error"] is None

    def test_failed_scan_preserves_previous_evidence_marked_stale(self, dirs):
        self._run(dirs, {"003": [_grec("003")]})
        meta = self._run(dirs, {"003": RuntimeError("grype retornou 1")})

        assert meta["failed_count"] == 1
        snap = self._snapshot(dirs)
        assert len(snap["vulnerabilities"]) == 1
        state = snap["metadata"]["agents"]["003"]
        assert state["stale"] is True
        assert state["last_error"] == "RuntimeError"
        assert state["last_error_at"] and state["last_success_at"]

    def test_legacy_consolidated_is_migrated_not_erased(self, dirs):
        dirs["output_path"].parent.mkdir(parents=True)
        dirs["output_path"].write_text(json.dumps({
            "metadata": {"generated_at": "2026-08-11T00:00:00+00:00"},
            "vulnerabilities": [_grec("003").to_dict()],
        }), encoding="utf-8")

        self._run(dirs, {"004": [_grec("004")]})

        agents = sorted(v["agent_id"] for v in self._snapshot(dirs)["vulnerabilities"])
        assert agents == ["003", "004"]

    def test_unreadable_state_changes_nothing(self, dirs):
        self._run(dirs, {"003": [_grec("003")]})
        state = grype_runner.state_path_for(dirs["output_path"])
        state.write_text("{corrompido", encoding="utf-8")
        before = dirs["output_path"].read_text(encoding="utf-8")

        with pytest.raises(grype_runner.StateUnavailableError):
            self._run(dirs, {"004": [_grec("004")]})

        assert dirs["output_path"].read_text(encoding="utf-8") == before
        assert (dirs["pending_dir"] / "004.json").exists()  # SBOM permanece pendente

    def test_provider_warns_about_stale_and_ignores_expired_scan(self, tmp_path, dirs):
        self._run(dirs, {"001": [GrypeVulnRecord(
            cve="CVE-2026-0001", advisory_id="x", agent_id="001", package_name="demo",
            installed_version="1.0-1", fixed_version="2.0-1", fixed_versions=["2.0-1"],
            confidence="high", match_type="exact-direct-match", status="fixed")]})
        self._run(dirs, {"001": RuntimeError("falha")})

        snapshot = tmp_path / "latest.json"
        _write_snapshot(snapshot, [_vuln()])
        from remediation.providers.grype_provider import GrypeProvider
        wazuh = WazuhProvider(snapshot, tmp_path / "a.json", tmp_path / "b.json")
        provider = GrypeProvider(wazuh, dirs["output_path"])
        res = provider.query_record(_vuln())
        assert res is not None and any("falhou" in w for w in res.warnings)

        expired = GrypeProvider(wazuh, dirs["output_path"], max_scan_age_hours=1)
        data = json.loads(dirs["output_path"].read_text(encoding="utf-8"))
        data["metadata"]["agents"]["001"]["last_success_at"] = "2026-01-01T00:00:00+00:00"
        dirs["output_path"].write_text(json.dumps(data), encoding="utf-8")
        assert expired.query_record(_vuln()) is None


# ==========================================================================
# Achado 3 — Fusão: confirmação da vulnerabilidade ≠ confirmação da correção
# ==========================================================================

class TestFusion:

    def test_divergent_fix_with_low_confidence_match_blocks_command(self, tmp_path):
        v = _vuln(fixed_version="2.0-1")
        engine = _engine(tmp_path, [v], [_grype(fixed_version="9.0-1", fixed_versions=["9.0-1"],
                                                confidence="low", match_type="cpe-match")], grype=True)
        g = engine.generate_guidance(_fid(v))

        assert g.command is None
        assert g.status == "no_guidance"
        assert g.confidence != "high"
        assert "Wazuh indica 2.0-1" in g.reason and "Grype indica 9.0-1" in g.reason
        assert any("divergem" in w for w in g.warnings)

    def test_divergent_fix_even_with_high_confidence_blocks_command(self, tmp_path):
        v = _vuln(fixed_version="2.0-1")
        engine = _engine(tmp_path, [v], [_grype(fixed_version="3.0-1", fixed_versions=["3.0-1"])], grype=True)
        g = engine.generate_guidance(_fid(v))
        assert g.command is None
        assert "divergem" in g.reason

    def test_branch_listed_by_grype_reconciles(self, tmp_path):
        v = _vuln(fixed_version="2.0-1")
        engine = _engine(tmp_path, [v], [_grype(fixed_version="3.0-1",
                                                fixed_versions=["3.0-1", "2.0-1"])], grype=True)
        g = engine.generate_guidance(_fid(v))
        assert g.status == "success"
        assert g.fixed_version == "2.0-1"
        assert any("múltiplos ramos" in a for a in g.assumptions)

    def test_agreement_is_high_confidence(self, tmp_path):
        v = _vuln(fixed_version="2.0-1")
        engine = _engine(tmp_path, [v], [_grype()], grype=True)
        g = engine.generate_guidance(_fid(v))
        assert g.status == "success" and g.confidence == "high"

    def test_low_confidence_grype_fix_does_not_become_high(self, tmp_path):
        v = _vuln()  # Wazuh sem fixed_version
        engine = _engine(tmp_path, [v], [_grype(confidence="low", match_type="cpe-match")], grype=True)
        g = engine.generate_guidance(_fid(v))
        assert g.confidence == "low"
        assert g.command is None

    def test_ecosystem_mismatch_is_not_consensus(self, tmp_path):
        v = _vuln(fixed_version="2.0-1")
        engine = _engine(tmp_path, [v], [_grype(purl="pkg:npm/demo@1.0-1")], grype=True)
        g = engine.generate_guidance(_fid(v))
        # Correlação descartada: Grype não confirma; nada é tratado como consenso.
        assert g.source == "wazuh_snapshot"
        assert any("não confirmada pelo scanner Grype" in w for w in g.warnings)

    def test_fuse_rejects_declared_ecosystem_mismatch(self, tmp_path):
        engine = _engine(tmp_path, [_vuln()])
        w = ProviderResult(cve="CVE-2026-0001", package_name="demo", installed_version="1.0-1",
                           fixed_version="2.0-1", package_manager="apt", confidence="high",
                           package_type="deb", fix_confidence="high", source="wazuh_snapshot")
        gr = ProviderResult(cve="CVE-2026-0001", package_name="demo", installed_version="1.0-1",
                            fixed_version="2.0-1", confidence="high", status="fixed",
                            package_type="npm", fix_confidence="high", source="grype_snapshot")
        fused = engine._fuse_results(w, gr)
        assert fused.blocking_reason and fused.fixed_version is None


# ==========================================================================
# Achado 4 — package_type em todos os caminhos e veto de status no provider único
# ==========================================================================

class TestPackageTypeAndStatusVeto:

    def _lodash(self, **o):
        return _vuln(package="lodash", version="4.17.15", package_type="npm", **o)

    def _glodash(self, **o):
        return _grype(package_name="lodash", installed_version="4.17.15", fixed_version="4.17.21",
                      fixed_versions=["4.17.21"], purl="pkg:npm/lodash@4.17.15", **o)

    def test_grype_only_npm_never_gets_apt(self, tmp_path):
        v = self._lodash()
        engine = _engine(tmp_path, [v], [self._glodash()], wazuh=False, grype=True)
        g = engine.generate_guidance(_fid(v))
        assert g.command is None
        assert g.package_manager == ""
        assert g.package_type == "npm"
        assert any("npm" in w for w in g.warnings)

    @pytest.mark.parametrize("state", ["not-fixed", "wont-fix", "unknown"])
    def test_grype_only_not_fixed_states_veto_command(self, tmp_path, state):
        v = _vuln()
        engine = _engine(tmp_path, [v], [_grype(status=state)], wazuh=False, grype=True)
        g = engine.generate_guidance(_fid(v))
        assert g.status == "insufficient_confidence"
        assert g.fixed_version is None and g.command is None

    def test_grype_provider_ignores_fixed_version_without_fixed_status(self, tmp_path):
        snapshot = tmp_path / "latest.json"
        _write_snapshot(snapshot, [_vuln()])
        gpath = tmp_path / "g.json"
        gpath.write_text(json.dumps({"vulnerabilities": [_grype(status="wont-fix")]}), encoding="utf-8")
        from remediation.providers.grype_provider import GrypeProvider
        provider = GrypeProvider(WazuhProvider(snapshot, tmp_path / "a", tmp_path / "b"), gpath)
        assert provider.query_record(_vuln()).fixed_version is None


# ==========================================================================
# Achado 5 — Validação semântica de versões / sem downgrade
# ==========================================================================

class TestVersionSemantics:

    @pytest.mark.parametrize("a,b,expected", [
        ("1.0-1", "1.0-2", -1),
        ("1:1.0", "2.0", 1),            # epoch vence
        ("1.0~rc1", "1.0", -1),         # til ordena antes
        ("2.9", "2.10", -1),            # numérico, não lexicográfico
        ("1.2.3-0ubuntu1", "1.2.3-0ubuntu1.1", -1),
        ("3.0.2-0ubuntu1.10", "3.0.2-0ubuntu1.9", 1),
    ])
    def test_dpkg(self, a, b, expected):
        assert compare_versions("dpkg", a, b) == expected

    @pytest.mark.parametrize("a,b,expected", [
        ("4.18.0-553.el8", "4.18.0-553.5.1.el8", -1),
        ("1.0~beta", "1.0", -1),
        ("1.0^git1", "1.0", 1),
        ("1:1.0-1", "2.0-1", 1),
        ("1.10-1", "1.9-1", 1),
        ("1.0a-1", "1.0-1", 1),
    ])
    def test_rpm(self, a, b, expected):
        assert compare_versions("rpm", a, b) == expected

    def test_windows_compares_only_within_branch(self):
        assert compare_versions("windows", "10.0.17763.7919", "10.0.17763.7922") == -1
        assert compare_versions("windows", "10.0.17763.7919", "10.0.20348.100") is None

    def test_unknown_ecosystem_is_not_comparable(self):
        assert compare_versions("apk", "1.0-r0", "1.1-r0") is None
        assert compare_versions(None, "1", "2") is None

    def test_zypper_template_has_no_oldpackage_and_blocks_downgrade(self):
        repo = TemplateRepository(TEMPLATES_PATH)
        assert repo.render_command("zypper", "demo", "5.0-1", "4.0-1") is None
        up = repo.render_command("zypper", "demo", "4.0-1", "5.0-1")
        assert up is not None and "--oldpackage" not in up.remediation
        raw = json.loads(TEMPLATES_PATH.read_text(encoding="utf-8"))
        for profile in raw["templates"].values():
            assert "--oldpackage" not in json.dumps(profile.get("remediation", {}))

    def test_engine_blocks_dnf_downgrade(self, tmp_path):
        v = _vuln(operating_system="rocky", package_type="rpm", version="5.0-1", fixed_version="4.0-1")
        g = _engine(tmp_path, [v]).generate_guidance(_fid(v))
        assert g.command is None and "downgrade" in g.reason

    def test_lexicographic_trap_still_generates_upgrade(self, tmp_path):
        v = _vuln(version="2.9-1", fixed_version="2.10-1")
        g = _engine(tmp_path, [v]).generate_guidance(_fid(v))
        assert g.status == "success"

    def test_apk_pin_is_blocked_without_comparator(self, tmp_path):
        v = _vuln(operating_system="alpine", package_type="", version="1.0-r0", fixed_version="1.1-r0")
        g = _engine(tmp_path, [v]).generate_guidance(_fid(v))
        assert g.command is None
        assert "validar" in g.reason
        assert g.guidance_text and "1.1-r0" in g.guidance_text

    def test_apt_success_requires_candidate_check(self, tmp_path):
        v = _vuln(fixed_version="2.0-1")
        g = _engine(tmp_path, [v]).generate_guidance(_fid(v))
        assert g.status == "success"
        assert any("apt-cache policy" in d["script"] for d in g.diagnostics)
        assert any("Candidate" in p for p in g.prerequisites)
        assert "Candidate" in g.rationale


# ==========================================================================
# Achado 6 — Identidade da instância
# ==========================================================================

class TestFindingIdentity:

    def test_versions_get_distinct_ids(self):
        a = generate_finding_id("CVE-1", "001", "demo", "1.0")
        b = generate_finding_id("CVE-1", "001", "demo", "3.0")
        assert a != b
        c = generate_finding_id("CVE-1", "001", "demo", "1.0", "npm", "", "/srv/app1/node_modules/demo")
        d = generate_finding_id("CVE-1", "001", "demo", "1.0", "npm", "", "/srv/app2/node_modules/demo")
        assert c != d

    def test_identity_ignores_severity_and_differs_from_legacy(self):
        rec = VulnRecord("001", "srv", "CVE-1", "demo", "1.0", "High", 8.0, False, False, None)
        rec2 = VulnRecord("001", "srv", "CVE-1", "demo", "1.0", "Critical", 9.0, False, False, None)
        assert rec.finding_id == rec2.finding_id
        assert rec.finding_id != generate_vulnerability_key("CVE-1", "001", "demo", "High")
        assert rec.to_dict()["finding_id"] == rec.finding_id

    def test_each_instance_resolves_to_its_own_record(self, tmp_path):
        v1, v3 = _vuln(version="1.0-1"), _vuln(version="3.0-1")
        engine = _engine(tmp_path, [v1, v3])
        assert engine.generate_guidance(_fid(v1)).installed_version == "1.0-1"
        assert engine.generate_guidance(_fid(v3)).installed_version == "3.0-1"

    def test_ambiguous_legacy_id_is_rejected(self, tmp_path):
        v1, v3 = _vuln(version="1.0-1"), _vuln(version="3.0-1")
        engine = _engine(tmp_path, [v1, v3])
        legacy = generate_vulnerability_key(v1["cve"], "001", "demo", "High")
        g = engine.generate_guidance(legacy)
        assert g.status == "ambiguous_finding"
        assert g.command is None and g.installed_version == ""
        assert "2 instâncias" in g.reason

    def test_unique_legacy_id_still_resolves(self, tmp_path):
        v1 = _vuln()
        engine = _engine(tmp_path, [v1])
        legacy = generate_vulnerability_key(v1["cve"], "001", "demo", "High")
        g = engine.generate_guidance(legacy)
        assert g.status != "not_found"
        assert any("identificador legado" in a for a in g.assumptions)

    def test_analyser_dedup_keeps_distinct_installations(self):
        import analyserV1

        def hit(version):
            return {"_source": {
                "agent": {"id": "1", "name": "srv"},
                "vulnerability": {"id": "CVE-2026-0006", "severity": "High"},
                "package": {"name": "demo", "version": version, "type": "deb", "architecture": "amd64"},
            }}

        ctx = MagicMock(cvss_threshold=6.0, epss_threshold=0.2)
        records = analyserV1.analyze_vulnerabilities(ctx, [hit("1.0"), hit("3.0"), hit("3.0")], {}, {})
        assert sorted(r.version for r in records) == ["1.0", "3.0"]
        assert records[0].package_architecture == "amd64"


# ==========================================================================
# Achado 7 — TLS
# ==========================================================================

class TestTLS:

    def test_default_sessions_verify_certificates(self):
        import analyserV1
        with patch.object(analyserV1, "INTERNAL_CA_BUNDLE", ""), \
             patch.object(analyserV1, "INTERNAL_TLS_INSECURE", False):
            ctx = analyserV1.AppContext()
        assert ctx.session.verify is True
        assert ctx.public_session.verify is True
        assert ctx.session is not ctx.public_session

    def test_internal_ca_bundle_is_used_only_for_internal_session(self, tmp_path):
        import analyserV1
        ca = tmp_path / "root-ca.pem"
        ca.write_text("dummy", encoding="utf-8")
        with patch.object(analyserV1, "INTERNAL_CA_BUNDLE", str(ca)), \
             patch.object(analyserV1, "INTERNAL_TLS_INSECURE", False):
            ctx = analyserV1.AppContext()
        assert ctx.session.verify == str(ca)
        assert ctx.public_session.verify is True

    def test_missing_ca_bundle_fails_closed(self, tmp_path):
        import analyserV1
        with patch.object(analyserV1, "INTERNAL_CA_BUNDLE", str(tmp_path / "nope.pem")), \
             patch.object(analyserV1, "INTERNAL_TLS_INSECURE", False):
            with pytest.raises(RuntimeError):
                analyserV1.AppContext()

    def test_insecure_opt_in_never_affects_public_sources(self):
        import analyserV1
        with patch.object(analyserV1, "INTERNAL_TLS_INSECURE", True):
            ctx = analyserV1.AppContext()
        assert ctx.session.verify is False
        assert ctx.public_session.verify is True

    def test_public_feeds_use_public_session(self):
        import inspect
        import analyserV1
        src = inspect.getsource(analyserV1.get_cisa_kev) + inspect.getsource(analyserV1.get_epss_data)
        assert "ctx.session." not in src
        assert "ctx.public_session.get" in src


# ==========================================================================
# Achado 8 — Paginação incompleta
# ==========================================================================

class _Resp:
    def __init__(self, code, body):
        self.status_code = code
        self._body = body
        self.text = ""

    def json(self):
        return self._body


class TestIndexerPagination:

    def _ctx(self, responses):
        import analyserV1
        ctx = analyserV1.AppContext()
        it = iter(responses)
        ctx.session.post = MagicMock(side_effect=lambda *a, **k: next(it))
        ctx.session.delete = MagicMock()
        return ctx

    def _page(self, n, total=None):
        import analyserV1
        body = {"_scroll_id": "s1", "hits": {"hits": [{"_id": str(i)} for i in range(n)]}}
        if total is not None:
            body["hits"]["total"] = {"value": total, "relation": "eq"}
        return body

    def test_http_error_on_second_page_raises_incomplete(self):
        import analyserV1
        size = analyserV1.SCROLL_PAGE_SIZE
        ctx = self._ctx([_Resp(200, self._page(size, total=size + 10)), _Resp(500, {})])
        with pytest.raises(analyserV1.IncompleteCollectionError) as exc:
            analyserV1.query_indexer_vulnerabilities(ctx, ["001"])
        assert exc.value.received == size and exc.value.expected == size + 10
        ctx.session.delete.assert_called_once()  # scroll limpo mesmo na falha

    def test_exception_on_second_page_raises_incomplete(self):
        import analyserV1
        import requests
        size = analyserV1.SCROLL_PAGE_SIZE
        it = iter([_Resp(200, self._page(size))])

        def post(*a, **k):
            try:
                return next(it)
            except StopIteration:
                raise requests.exceptions.ConnectionError("reset")

        ctx = analyserV1.AppContext()
        ctx.session.post = post
        ctx.session.delete = MagicMock()
        with pytest.raises(analyserV1.IncompleteCollectionError):
            analyserV1.query_indexer_vulnerabilities(ctx, ["001"])

    def test_total_mismatch_raises_incomplete(self):
        import analyserV1
        ctx = self._ctx([_Resp(200, self._page(3, total=7))])
        with pytest.raises(analyserV1.IncompleteCollectionError):
            analyserV1.query_indexer_vulnerabilities(ctx, ["001"])

    def test_complete_collection_is_flagged(self):
        import analyserV1
        ctx = self._ctx([_Resp(200, self._page(3, total=3))])
        hits = analyserV1.query_indexer_vulnerabilities(ctx, ["001"])
        assert len(hits) == 3
        assert ctx.collection == {"complete": True, "expected": 3, "received": 3}

    def test_main_does_not_publish_incomplete_collection(self):
        import analyserV1
        err = analyserV1.IncompleteCollectionError("falha", 10, 5)
        with patch.object(sys, "argv", ["analyserV1.py", "--agent", "001", "--web-output-dir", "/nao/usar"]), \
             patch.object(analyserV1, "require_passwords"), \
             patch.object(analyserV1, "get_cisa_kev", return_value={}), \
             patch.object(analyserV1, "get_epss_data", return_value={}), \
             patch.object(analyserV1, "query_indexer_vulnerabilities", side_effect=err), \
             patch.object(analyserV1, "publish_to_web") as publish, \
             patch.object(analyserV1, "export_csv") as export_csv, \
             patch.object(analyserV1, "generate_risk_intelligence") as risk:
            assert analyserV1.main() == 2
        publish.assert_not_called()
        export_csv.assert_not_called()
        risk.assert_not_called()


# ==========================================================================
# Achado 9 — Fallback de import do rate limiter
# ==========================================================================

class TestRateLimiterImportFallback:

    def test_fresh_import_survives_rate_limiter_import_error(self, caplog):
        saved = sys.modules.pop("soar_api", None)
        real_import = builtins.__import__

        def failing_import(name, *args, **kwargs):
            if name == "remediation.rate_limiter":
                raise ImportError("simulado")
            return real_import(name, *args, **kwargs)

        try:
            with patch.object(builtins, "__import__", failing_import), caplog.at_level("ERROR"):
                import soar_api  # importação NOVA (não reload): logger ainda não existia
            assert soar_api._guidance_rate_limiter is None
            assert soar_api._sbom_rate_limiter is None
            assert "Falha ao carregar rate limiter" in caplog.text
        finally:
            sys.modules.pop("soar_api", None)
            if saved is not None:
                sys.modules["soar_api"] = saved

    def test_missing_limiter_returns_controlled_503(self):
        import soar_api
        handler = MagicMock()
        handler._get_remote_user.return_value = "analyst"
        handler._get_client_ip.return_value = "127.0.0.1"
        handler.headers = {}
        parsed = MagicMock(path="/remediation-guidance/" + "a" * 64, query="")
        with patch.object(soar_api, "_guidance_rate_limiter", None):
            soar_api.SoarAPIHandler._handle_remediation_guidance_get_internal(handler, parsed)
        assert handler._send_guidance_json.call_args[0][0] == 503


# ==========================================================================
# Achado 10 — Contrato: texto, comando, diagnósticos e justificativa separados
# ==========================================================================

class TestGuidanceContract:

    def test_text_never_becomes_command(self):
        rec = GuidanceRecord(status="textual_guidance", command="texto qualquer",
                             guidance_text="Aplique a atualização.")
        d = rec.to_dict()
        assert "command" not in d and d["guidance_kind"] == "textual"
        assert d["guidance_text"] == "Aplique a atualização."
        assert d["execution_allowed"] is False

    def test_diagnostics_are_separate_from_command(self):
        rec = GuidanceRecord(status="no_guidance", diagnostics=[
            {"label": "Build", "script": "Get-ItemProperty x", "shell": "powershell"},
            {"label": "vazio", "script": "  "},
        ])
        d = rec.to_dict()
        assert "command" not in d
        assert d["diagnostics"] == [{"label": "Build", "script": "Get-ItemProperty x", "shell": "powershell"}]

    def test_success_record_has_rationale_and_v1_fields(self, tmp_path):
        v = _vuln(fixed_version="2.0-1")
        d = _engine(tmp_path, [v]).generate_guidance(_fid(v)).to_dict()
        assert d["status"] == "success" and d["guidance_kind"] == "command"
        assert d["rationale"] and d["command"] and d["verification_command"]
        assert d["shell"] == "bash"
        assert d["contract_version"] == "2"
        assert d["verification_steps"] and d["expected_result"]

    def test_frontend_renders_v2_sections(self):
        import analyserV1
        tpl = analyserV1.HTML_TEMPLATE
        for needle in (
            "renderGuidanceExtras(record, guidanceKind)",
            "record.warnings", "record.assumptions", "record.recommendation",
            "record.guidance_text", "record.diagnostics", "record.missing_context",
            "record.sources", "resp.status === 409", "guidanceKind === 'command'",
            "url.startsWith('https://')",
        ):
            assert needle in tpl, needle
        # Textos longos quebram linha no modal
        assert "white-space: pre-wrap" in tpl


# ==========================================================================
# Achado 11 — Cache acompanha todas as dependências
# ==========================================================================

class TestCacheDependencies:

    def test_grype_change_invalidates_guidance_cache(self, tmp_path):
        v = _vuln()
        engine = _engine(tmp_path, [v], [_grype()], grype=True)
        cache = GuidanceCache(snapshot_path=tmp_path / "latest.json",
                              dependency_paths=engine.dependency_paths)
        cache.get_by_finding_id("x" * 64)
        cache.put("x" * 64, GuidanceRecord(finding_id="x" * 64))

        gpath = tmp_path / "output" / "grype_latest.json"
        tmp = gpath.with_name("g.tmp")
        tmp.write_text(json.dumps({"vulnerabilities": []}), encoding="utf-8")
        os.replace(tmp, gpath)

        assert cache.get_by_finding_id("x" * 64) is None

    @pytest.mark.parametrize("name", ["assets_context.json", "remediation_providers.json",
                                      "generic_update_policy.json", "remediation_allowlist.json"])
    def test_config_change_invalidates_guidance_cache(self, tmp_path, name):
        engine = _engine(tmp_path, [_vuln()])
        cache = GuidanceCache(dependency_paths=engine.dependency_paths)
        cache.get_by_finding_id("x" * 64)
        cache.put("x" * 64, GuidanceRecord(finding_id="x" * 64))
        target = tmp_path / "config" / name
        tmp = target.with_name(name + ".tmp")
        tmp.write_text(target.read_text(encoding="utf-8") + " ", encoding="utf-8")
        os.replace(tmp, target)
        assert cache.get_by_finding_id("x" * 64) is None

    def test_engine_dependencies_cover_templates_and_evidence(self, tmp_path):
        paths = _engine(tmp_path, [_vuln()]).dependency_paths()
        names = {p.name for p in paths}
        assert {"latest.json", "grype_latest.json", "assets_context.json", "remediation_allowlist.json",
                "remediation_providers.json", "generic_update_policy.json",
                "remediation_templates.json", "vendor_evidence.json"} <= names

    def test_result_generated_under_old_revision_is_not_cached(self, tmp_path):
        snapshot = tmp_path / "latest.json"
        _write_snapshot(snapshot, [_vuln()])
        cache = GuidanceCache(snapshot_path=snapshot)
        sig = cache.dependency_signature()
        _replace_atomically(snapshot, [])  # muda durante a geração
        assert cache.put("y" * 64, GuidanceRecord(finding_id="y" * 64), expected_signature=sig) is False
        assert cache.get_by_finding_id("y" * 64) is None

    def test_engine_reloads_provider_config_without_restart(self, tmp_path):
        v = _vuln(fixed_version="2.0-1")
        engine = _engine(tmp_path, [v], [_grype()], grype=False)
        assert engine.generate_guidance(_fid(v)).source == "wazuh_snapshot"
        _config(tmp_path / "config", grype=True)
        cfg = tmp_path / "config" / "remediation_providers.json"
        st = cfg.stat()
        os.utime(cfg, ns=(st.st_atime_ns, st.st_mtime_ns + 5_000_000_000))
        assert engine.generate_guidance(_fid(v)).source == "fusion_consensus"


# ==========================================================================
# Achado 12 — Contexto propagado (campo ausente permanece desconhecido)
# ==========================================================================

class TestContextPropagation:

    def test_context_fields_reach_public_contract(self, tmp_path):
        v = _vuln(fixed_version="2.0-1", os_version="22.04", package_architecture="amd64")
        d = _engine(tmp_path, [v]).generate_guidance(_fid(v)).to_dict()
        assert d["os_version"] == "22.04"
        assert d["package_type"] == "deb"
        assert d["architecture"] == "amd64"

    def test_missing_context_is_not_invented(self, tmp_path):
        v = _vuln(fixed_version="2.0-1")
        d = _engine(tmp_path, [v]).generate_guidance(_fid(v)).to_dict()
        assert "architecture" not in d
        assert "os_version" not in d
