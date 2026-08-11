"""
Testes unitários do runner assíncrono de SBOMs do Grype.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import uuid
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent))

import grype_runner
from remediation.models import GrypeVulnRecord


def make_record(agent_id: str = "003") -> GrypeVulnRecord:
    return GrypeVulnRecord(
        cve="CVE-2021-23337",
        advisory_id="GHSA-35jh-r3h4-6jhm",
        agent_id=agent_id,
        package_name="lodash",
        installed_version="4.17.15",
        fixed_version="4.17.21",
        fixed_versions=["4.17.21"],
        confidence="high",
        match_type="exact-direct-match",
        purl="pkg:npm/lodash@4.17.15",
        db_version="v6.1.9 (built: 2026-08-11T06:26:49Z)",
        status="fixed",
    )


@contextmanager
def runner_dirs():
    temp_root = Path(__file__).resolve().parent.parent / ".test-tmp-grype-runner"
    base = temp_root / uuid.uuid4().hex
    pending = base / "sbom" / "pending"
    processed = base / "sbom" / "processed"
    failed = base / "sbom" / "failed"
    output = base / "output" / "grype_latest.json"
    pending.mkdir(parents=True)
    try:
        yield pending, processed, failed, output
    finally:
        shutil.rmtree(base, ignore_errors=True)
        try:
            temp_root.rmdir()
        except OSError:
            pass


def read_snapshot(output_path: Path) -> dict:
    return json.loads(output_path.read_text(encoding="utf-8"))


def test_valid_sbom_processed_successfully():
    with runner_dirs() as (pending, processed, failed, output):
        sbom_path = pending / "003.json"
        sbom_path.write_text("{}", encoding="utf-8")

        def fake_process_sbom(path, timeout_seconds):
            assert path == sbom_path
            assert timeout_seconds == 123
            return [make_record(agent_id="003")]

        with patch.object(grype_runner, "process_sbom", fake_process_sbom):
            metadata = grype_runner.process_pending(
                pending_dir=pending,
                processed_dir=processed,
                failed_dir=failed,
                output_path=output,
                timeout_seconds=123,
            )

        assert metadata["processed_count"] == 1
        assert metadata["failed_count"] == 0
        assert metadata["vulnerability_count"] == 1
        assert not sbom_path.exists()
        assert len(list(processed.glob("003.*.json"))) == 1
        assert list(failed.glob("*.json")) == []

        snapshot = read_snapshot(output)
        assert snapshot["metadata"]["source"] == "grype_runner"
        assert snapshot["vulnerabilities"][0]["agent_id"] == "003"


def test_corrupted_sbom_does_not_interrupt_batch():
    with runner_dirs() as (pending, processed, failed, output):
        bad_sbom = pending / "bad.json"
        good_sbom = pending / "003.json"
        bad_sbom.write_text("{", encoding="utf-8")
        good_sbom.write_text("{}", encoding="utf-8")

        def fake_process_sbom(path, timeout_seconds):
            if path.name == "bad.json":
                raise ValueError("json inválido")
            return [make_record(agent_id="003")]

        with patch.object(grype_runner, "process_sbom", fake_process_sbom):
            metadata = grype_runner.process_pending(
                pending_dir=pending,
                processed_dir=processed,
                failed_dir=failed,
                output_path=output,
            )

        assert metadata["processed_count"] == 1
        assert metadata["failed_count"] == 1
        assert metadata["vulnerability_count"] == 1
        assert len(list(processed.glob("003.*.json"))) == 1
        assert len(list(failed.glob("bad.*.json"))) == 1

        snapshot = read_snapshot(output)
        assert len(snapshot["vulnerabilities"]) == 1
        assert snapshot["vulnerabilities"][0]["cve"] == "CVE-2021-23337"


def test_empty_pending_dir_writes_empty_snapshot():
    with runner_dirs() as (pending, processed, failed, output):
        metadata = grype_runner.process_pending(
            pending_dir=pending,
            processed_dir=processed,
            failed_dir=failed,
            output_path=output,
        )

        assert metadata["processed_count"] == 0
        assert metadata["failed_count"] == 0
        assert metadata["vulnerability_count"] == 0

        snapshot = read_snapshot(output)
        assert snapshot["metadata"]["source"] == "grype_runner"
        assert snapshot["vulnerabilities"] == []


def test_snapshot_final_has_grype_record_schema():
    with runner_dirs() as (_, _, _, output):
        record = make_record(agent_id="003")
        metadata = {
            "generated_at": "2026-08-11T00:00:00+00:00",
            "source": "grype_runner",
            "pending_dir": "/opt/hmg-soar/sbom/pending",
            "processed_count": 1,
            "failed_count": 0,
            "vulnerability_count": 1,
        }

        grype_runner.write_snapshot(output, [record], metadata)

        snapshot = read_snapshot(output)
        assert snapshot["metadata"] == metadata
        assert snapshot["vulnerabilities"] == [record.to_dict()]


def test_run_grype_uses_sbom_scheme_and_json_output():
    with runner_dirs() as (pending, _, _, _):
        sbom_path = pending / "003.json"
        sbom_path.write_text("{}", encoding="utf-8")

        calls = []

        def fake_run(args, check, capture_output, text, timeout):
            calls.append(
                {
                    "args": args,
                    "check": check,
                    "capture_output": capture_output,
                    "text": text,
                    "timeout": timeout,
                }
            )
            return SimpleNamespace(returncode=0, stdout='{"matches": []}', stderr="")

        with patch.object(subprocess, "run", fake_run):
            assert grype_runner.run_grype(sbom_path, timeout_seconds=42) == {"matches": []}

        assert calls == [
            {
                "args": ["grype", f"sbom:{sbom_path}", "-o", "json"],
                "check": False,
                "capture_output": True,
                "text": True,
                "timeout": 42,
            }
        ]


def test_agent_id_contract_requires_exact_agent_id_filename():
    assert grype_runner.agent_id_from_sbom(Path("003.json")) == "003"

    # Lacuna documentada: a Etapa 4 deve gravar exatamente {agent_id}.json.
    assert grype_runner.agent_id_from_sbom(Path("003.scan.json")) == "003.scan"
