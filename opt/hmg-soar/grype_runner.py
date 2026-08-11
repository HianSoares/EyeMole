"""
Runner assíncrono para processar SBOMs pendentes com Anchore Grype.
"""

from __future__ import annotations

import argparse
import json
import logging
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, List

from remediation.models import GrypeVulnRecord
from remediation.providers.grype_parser import parse_grype_output


logger = logging.getLogger("hmg-soar-grype-runner")

DEFAULT_PENDING_DIR = Path("/opt/hmg-soar/sbom/pending")
DEFAULT_PROCESSED_DIR = Path("/opt/hmg-soar/sbom/processed")
DEFAULT_FAILED_DIR = Path("/opt/hmg-soar/sbom/failed")
DEFAULT_OUTPUT_PATH = Path("/opt/hmg-soar/output/grype_latest.json")
DEFAULT_TIMEOUT_SECONDS = 900


def utc_timestamp() -> str:
    """Retorna timestamp UTC compacto para nomes de arquivo."""
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def agent_id_from_sbom(path: Path) -> str:
    """Extrai agent_id do nome do arquivo.

    Contrato formal com a Etapa 4: SBOMs em pending/ devem se chamar
    exatamente {agent_id}.json. Sufixos extras viram parte do agent_id.
    """
    return path.stem.strip()


def move_with_timestamp(path: Path, destination_dir: Path) -> Path:
    """Move um SBOM para destino preservando rastreabilidade por timestamp."""
    destination_dir.mkdir(parents=True, exist_ok=True)
    destination = destination_dir / f"{path.stem}.{utc_timestamp()}{path.suffix}"
    shutil.move(str(path), str(destination))
    return destination


def run_grype(sbom_path: Path, timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS) -> dict:
    """Executa grype contra um SBOM e retorna o JSON bruto."""
    result = subprocess.run(
        ["grype", f"sbom:{sbom_path}", "-o", "json"],
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
    )

    if result.returncode != 0:
        stderr = result.stderr.strip() or "sem stderr"
        raise RuntimeError(f"grype retornou {result.returncode}: {stderr}")

    return json.loads(result.stdout)


def process_sbom(path: Path, timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS) -> List[GrypeVulnRecord]:
    """Processa um SBOM individual e normaliza os matches via parser central."""
    raw_output = run_grype(path, timeout_seconds=timeout_seconds)
    return parse_grype_output(raw_output, agent_id=agent_id_from_sbom(path))


def write_snapshot(output_path: Path, records: Iterable[GrypeVulnRecord], metadata: dict) -> None:
    """Escreve snapshot consolidado do Grype de forma atômica."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "metadata": metadata,
        "vulnerabilities": [record.to_dict() for record in records],
    }

    tmp_path = output_path.with_name(f".{output_path.name}.tmp")
    tmp_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    tmp_path.replace(output_path)


def process_pending(
    pending_dir: Path = DEFAULT_PENDING_DIR,
    processed_dir: Path = DEFAULT_PROCESSED_DIR,
    failed_dir: Path = DEFAULT_FAILED_DIR,
    output_path: Path = DEFAULT_OUTPUT_PATH,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> dict:
    """Processa todos os SBOMs pendentes sem interromper o batch por erro individual."""
    pending_dir.mkdir(parents=True, exist_ok=True)
    processed_dir.mkdir(parents=True, exist_ok=True)
    failed_dir.mkdir(parents=True, exist_ok=True)

    records: List[GrypeVulnRecord] = []
    processed_count = 0
    failed_count = 0

    for sbom_path in sorted(pending_dir.glob("*.json")):
        try:
            sbom_records = process_sbom(sbom_path, timeout_seconds=timeout_seconds)
            records.extend(sbom_records)
            move_with_timestamp(sbom_path, processed_dir)
            processed_count += 1
            logger.info(
                "SBOM processado: %s (%d vulnerabilidades)",
                sbom_path.name,
                len(sbom_records),
            )
        except Exception as exc:
            failed_count += 1
            logger.exception("Falha ao processar SBOM %s: %s", sbom_path, exc)
            try:
                move_with_timestamp(sbom_path, failed_dir)
            except OSError:
                logger.exception("Falha ao mover SBOM com erro para failed/: %s", sbom_path)

    metadata = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": "grype_runner",
        "pending_dir": str(pending_dir),
        "processed_count": processed_count,
        "failed_count": failed_count,
        "vulnerability_count": len(records),
    }
    write_snapshot(output_path, records, metadata)
    return metadata


def main() -> int:
    """Entrada CLI para execução via systemd."""
    parser = argparse.ArgumentParser(description="Processa SBOMs pendentes com Grype.")
    parser.add_argument("--pending-dir", type=Path, default=DEFAULT_PENDING_DIR)
    parser.add_argument("--processed-dir", type=Path, default=DEFAULT_PROCESSED_DIR)
    parser.add_argument("--failed-dir", type=Path, default=DEFAULT_FAILED_DIR)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT_PATH)
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_SECONDS)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    process_pending(
        pending_dir=args.pending_dir,
        processed_dir=args.processed_dir,
        failed_dir=args.failed_dir,
        output_path=args.output,
        timeout_seconds=args.timeout,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
