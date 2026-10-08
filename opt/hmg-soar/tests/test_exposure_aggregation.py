"""
Reconciliação entre identidade de INSTÂNCIA (finding_id v2) e as agregações
de risco, tendência e SLA, que operam por EXPOSIÇÃO (agente + CVE + pacote).

- A tabela e o "Ver correção" continuam por instância (versão/instalação).
- Snapshot de risco, delta, score por ativo e relógio de SLA usam exposição,
  mantendo a continuidade com os snapshots históricos (campo "key").
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import analyserV1
from remediation.models import VulnRecord

EXPOSURE_KEY = "001|CVE-2026-0006|demo"


def _rec(version, path="", severity="High", cve="CVE-2026-0006", package="demo", agent="001"):
    return VulnRecord(
        agent, "srv-01", cve, package, version, severity, 8.0, False, False, 0.1,
        priority="Priority 2", agent_os="ubuntu", package_type="npm", package_path=path,
    )


def _run(tmp_path, records):
    ctx = analyserV1.AppContext()
    with patch.object(analyserV1, "load_assets_context", return_value={}), \
         patch.object(analyserV1, "load_exposure_context", return_value={}), \
         patch.object(analyserV1, "load_risk_acceptance", return_value={"rules": []}):
        analyserV1.generate_risk_intelligence(ctx, records, ["001"], str(tmp_path))
    data = tmp_path / "data"

    def load(name):
        return json.loads((data / name).read_text(encoding="utf-8"))

    return load


def _risky_asset(load, agent_id):
    for name in ("asset_context_summary.json", "risk_summary.json"):
        doc = load(name)
        for item in doc.get("top_risky_assets", []) or []:
            if item.get("agent_id") == agent_id:
                return item
    raise AssertionError("ativo não encontrado em top_risky_assets")


def _legacy_snapshot(ts, severity="High"):
    """Snapshot no formato anterior à identidade de instância (sem finding_ids)."""
    return {
        "timestamp": ts,
        "agent_vulnerabilities": [{
            "key": EXPOSURE_KEY, "agent_id": "001", "agent_name": "srv-01",
            "cve": "CVE-2026-0006", "package_name": "demo", "severity": severity,
            "is_kev": False, "cvss_score": 8.0, "epss_score": 0.1,
        }],
    }


class TestRiskSnapshotPerExposure:

    def test_instances_collapse_into_one_exposure_row(self, tmp_path):
        a, b = _rec("1.0", "/srv/a"), _rec("3.0", "/srv/b")
        load = _run(tmp_path, [a, b])

        rows = load("snapshots/latest_snapshot.json")["agent_vulnerabilities"]
        assert len(rows) == 1
        row = rows[0]
        assert row["key"] == EXPOSURE_KEY
        assert row["instance_count"] == 2
        assert sorted(row["finding_ids"]) == sorted([a.finding_id, b.finding_id])
        assert row["installed_versions"] == ["1.0", "3.0"]
        assert load("risk_summary.json")["summary"]["total_vulnerabilities"] == 1
        assert load("sla_summary.json")["summary"]["total_open"] == 1

    def test_extra_installation_does_not_inflate_asset_risk(self, tmp_path):
        single = _risky_asset(_run(tmp_path / "one", [_rec("1.0", "/srv/a")]), "001")
        double = _risky_asset(_run(tmp_path / "two", [_rec("1.0", "/srv/a"), _rec("3.0", "/srv/b")]), "001")
        assert double["risk_score"] == single["risk_score"]
        assert double["vuln_count"] == single["vuln_count"] == 1

    def test_representative_is_the_most_severe_instance(self, tmp_path):
        load = _run(tmp_path, [_rec("1.0", "/a", severity="Medium"), _rec("2.0", "/b", severity="Critical")])
        assert load("snapshots/latest_snapshot.json")["agent_vulnerabilities"][0]["severity"] == "Critical"


class TestDeltaContinuity:

    def test_legacy_previous_snapshot_is_persistent_not_new(self, tmp_path):
        snapshots = tmp_path / "data" / "snapshots"
        snapshots.mkdir(parents=True)
        (snapshots / "latest_snapshot.json").write_text(
            json.dumps(_legacy_snapshot("2026-09-01T00:00:00Z")), encoding="utf-8")

        load = _run(tmp_path, [_rec("1.0", "/srv/a"), _rec("3.0", "/srv/b")])
        delta = load("risk_delta.json")["delta"]

        assert delta["new_vulnerabilities"] == 0
        assert delta["resolved_vulnerabilities"] == 0
        assert delta["persistent_vulnerabilities"] == 1
        assert delta["agents_worsened"] == 0  # sem "piora" artificial na migração


class TestSlaClockPerExposure:

    def test_history_keeps_first_seen_across_version_and_severity_change(self, tmp_path):
        snapshots = tmp_path / "data" / "snapshots"
        snapshots.mkdir(parents=True)
        (snapshots / "snapshot_20260101_000000.json").write_text(
            json.dumps(_legacy_snapshot("2026-01-01T00:00:00Z", severity="Medium")), encoding="utf-8")

        # Versão nova (upgrade parcial) e severidade reavaliada: mesma exposição.
        load = _run(tmp_path, [_rec("2.0", severity="High")])
        row = load("snapshots/latest_snapshot.json")["agent_vulnerabilities"][0]

        assert row["first_seen"] == "2026-01-01T00:00:00Z"
        assert row["first_seen_estimated"] is False
        assert row["snapshot_occurrences"] == 2

    def test_render_html_rows_share_exposure_sla_and_carry_exposure_key(self, tmp_path):
        snapshots = tmp_path / "snapshots"
        snapshots.mkdir()
        (snapshots / "snapshot_20260101_000000.json").write_text(
            json.dumps(_legacy_snapshot("2026-01-01T00:00:00Z")), encoding="utf-8")
        a, b = _rec("1.0", "/srv/a"), _rec("3.0", "/srv/b")

        captured = {}
        real_dumps = analyserV1.json.dumps

        def spy(obj, *args, **kwargs):
            if isinstance(obj, list) and obj and isinstance(obj[0], dict) and "exposure_key" in obj[0]:
                captured["rows"] = obj
            return real_dumps(obj, *args, **kwargs)

        original_path = analyserV1.Path

        def fake_path(p, *args):
            if str(p) == "/var/www/wazuh-soar/data/snapshots":
                return snapshots
            return original_path(p, *args)

        with patch.object(analyserV1, "load_assets_context", return_value={}), \
             patch.object(analyserV1, "load_exposure_context", return_value={}), \
             patch.object(analyserV1.json, "dumps", side_effect=spy), \
             patch.object(analyserV1, "Path", side_effect=fake_path):
            analyserV1.render_html(analyserV1.AppContext(), [a, b], ["001"], "audit")

        rows = captured["rows"]
        assert [r["finding_id"] for r in rows] == [a.finding_id, b.finding_id]
        assert {r["exposure_key"] for r in rows} == {EXPOSURE_KEY}
        assert {r["exposure_instance_count"] for r in rows} == {2}
        assert {r["first_seen"] for r in rows} == {"2026-01-01T00:00:00Z"}


class TestFrontendExposureAggregation:

    def _js_helpers(self):
        tpl = analyserV1.HTML_TEMPLATE
        start = tpl.index("function exposureKeyOf(v)")
        end = tpl.index("const exposureData = dedupeExposures(rawData);")
        return tpl[start:end]

    def test_aggregates_use_exposures_and_table_uses_instances(self):
        tpl = analyserV1.HTML_TEMPLATE
        assert "const exposureData = dedupeExposures(rawData);" in tpl
        cc = tpl[tpl.index("function renderCommandCenter()"):tpl.index("function vmDeriveAssets()")]
        assert "const data = exposureData;" in cc
        assert "exposureData.forEach" in tpl[tpl.index("function vmDeriveAssets()"):]
        div = tpl[tpl.index("function reportSourceDivergence"):]
        assert "exposureData.length" in div[:600]
        assert "let filteredData = [...rawData];" in tpl  # tabela: uma linha por instalação

    def test_dedupe_semantics_in_node(self):
        node = shutil.which("node")
        if node is None:
            pytest.skip("Node.js não disponível")
        script = self._js_helpers() + """
const rows = [
  {exposure_key: 'a|CVE-1|p', finding_id: '1'},
  {exposure_key: 'a|CVE-1|p', finding_id: '2'},
  {agent_id: 'b', cve: 'CVE-1', package: 'p', finding_id: '3'},
  {agent_id: 'b', cve: 'CVE-1', package: 'p', finding_id: '4'},
  null
];
const out = dedupeExposures(rows).map(r => r.finding_id).join(',');
if (out !== '1,3') { console.error(out); process.exit(1); }
"""
        result = subprocess.run([node, "-e", script], capture_output=True, text=True, timeout=30)
        assert result.returncode == 0, result.stderr
