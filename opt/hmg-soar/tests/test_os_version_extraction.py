from __future__ import annotations

import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parent.parent))

from analyserV1 import extract_record


def _hit_with_os(os_payload: dict) -> dict:
    return {
        "_source": {
            "agent": {"id": "3", "name": "linux-server"},
            "host": {"os": os_payload},
            "vulnerability": {
                "id": "CVE-2024-26714",
                "severity": "High",
            },
            "package": {
                "name": "linux-image-5.15.0-186-generic",
                "version": "5.15.0-186.196",
            },
        }
    }


def _hit_with_scanner(scanner_payload: dict | None) -> dict:
    hit = _hit_with_os({"platform": "ubuntu", "version": "22.04.5"})
    if scanner_payload is not None:
        hit["_source"]["vulnerability"]["scanner"] = scanner_payload
    return hit


def test_extract_record_reads_host_os_version_when_present():
    record = extract_record(
        _hit_with_os({"platform": "ubuntu", "version": "22.04.5"}),
        cisa_kev={},
        epss_data={},
    )

    assert record is not None
    assert record.agent_id == "003"
    assert record.agent_os == "ubuntu"
    assert record.os_version == "22.04.5"

    serialized = record.to_dict()
    assert serialized["operating_system"] == "ubuntu"
    assert serialized["os_version"] == "22.04.5"


def test_extract_record_leaves_os_version_empty_when_absent():
    record = extract_record(
        _hit_with_os({"platform": "ubuntu"}),
        cisa_kev={},
        epss_data={},
    )

    assert record is not None
    assert record.agent_os == "ubuntu"
    assert record.os_version == ""
    assert record.to_dict()["os_version"] == ""


def test_extract_record_reads_scanner_condition_when_present():
    record = extract_record(
        _hit_with_scanner({"condition": "Package less than 6.12.96-1"}),
        cisa_kev={},
        epss_data={},
    )

    assert record is not None
    assert record.scanner_condition == "Package less than 6.12.96-1"
    assert record.to_dict()["scanner_condition"] == "Package less than 6.12.96-1"


def test_extract_record_leaves_scanner_condition_empty_when_absent():
    record = extract_record(
        _hit_with_scanner(None),
        cisa_kev={},
        epss_data={},
    )

    assert record is not None
    assert record.scanner_condition == ""
    assert record.to_dict()["scanner_condition"] == ""
