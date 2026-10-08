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
from typing import Dict, Iterable, List

from remediation.models import GrypeVulnRecord
from remediation.providers.grype_parser import parse_grype_output


logger = logging.getLogger("hmg-soar-grype-runner")

DEFAULT_PENDING_DIR = Path("/opt/hmg-soar/sbom/pending")
DEFAULT_PROCESSED_DIR = Path("/opt/hmg-soar/sbom/processed")
DEFAULT_FAILED_DIR = Path("/opt/hmg-soar/sbom/failed")
DEFAULT_OUTPUT_PATH = Path("/opt/hmg-soar/output/grype_latest.json")
DEFAULT_TIMEOUT_SECONDS = 900
STATE_FILENAME = "grype_state.json"


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
    payload = {
        "metadata": metadata,
        "vulnerabilities": [record.to_dict() for record in records],
    }
    _atomic_write_json(output_path, payload)


def _atomic_write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(f".{path.name}.tmp")
    tmp_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    tmp_path.replace(path)


def state_path_for(output_path: Path) -> Path:
    """Estado por agente fica ao lado do consolidado (diretório gravável do serviço)."""
    return output_path.with_name(STATE_FILENAME)


def load_state(state_path: Path, output_path: Path) -> Dict[str, dict]:
    """Carrega o último scan válido por agente.

    Migração: sem arquivo de estado, reconstrói a partir do consolidado legado
    (agrupando por agent_id), para não perder resultados já publicados.
    """
    if state_path.is_file():
        try:
            data = json.loads(state_path.read_text(encoding="utf-8"))
            agents = data.get("agents") if isinstance(data, dict) else None
            if isinstance(agents, dict):
                return {str(k): v for k, v in agents.items() if isinstance(v, dict)}
            logger.error("Estado Grype com formato inválido; consolidado será preservado.")
        except (json.JSONDecodeError, OSError, UnicodeDecodeError):
            logger.exception("Falha ao ler estado Grype; consolidado será preservado.")
        raise StateUnavailableError(str(state_path))

    if not output_path.is_file():
        return {}

    try:
        legacy = json.loads(output_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError, UnicodeDecodeError):
        logger.warning("Consolidado legado ilegível; iniciando estado vazio.")
        return {}

    generated_at = ""
    if isinstance(legacy, dict) and isinstance(legacy.get("metadata"), dict):
        generated_at = str(legacy["metadata"].get("generated_at") or "")
    agents: Dict[str, dict] = {}
    for vuln in (legacy.get("vulnerabilities") or []) if isinstance(legacy, dict) else []:
        if not isinstance(vuln, dict) or not vuln.get("agent_id"):
            continue
        entry = agents.setdefault(str(vuln["agent_id"]), {
            "last_success_at": generated_at or None,
            "last_error": None,
            "last_error_at": None,
            "db_version": vuln.get("db_version") or "unknown",
            "source_sbom": None,
            "migrated_from_legacy": True,
            "vulnerabilities": [],
        })
        entry["vulnerabilities"].append(vuln)
    if agents:
        logger.info("Estado Grype migrado do consolidado legado: %d agentes.", len(agents))
    return agents


class StateUnavailableError(RuntimeError):
    """Estado existente porém ilegível: não sobrescrever nada."""


def _consolidate(agents: Dict[str, dict]) -> List[dict]:
    vulnerabilities: List[dict] = []
    for agent_id in sorted(agents):
        for vuln in agents[agent_id].get("vulnerabilities") or []:
            if isinstance(vuln, dict):
                vulnerabilities.append(vuln)
    return vulnerabilities


def _agents_summary(agents: Dict[str, dict]) -> Dict[str, dict]:
    return {
        agent_id: {
            "last_success_at": state.get("last_success_at"),
            "last_error": state.get("last_error"),
            "last_error_at": state.get("last_error_at"),
            "db_version": state.get("db_version"),
            "stale": bool(state.get("last_error")),
            "vulnerability_count": len(state.get("vulnerabilities") or []),
        }
        for agent_id, state in sorted(agents.items())
    }


def process_pending(
    pending_dir: Path = DEFAULT_PENDING_DIR,
    processed_dir: Path = DEFAULT_PROCESSED_DIR,
    failed_dir: Path = DEFAULT_FAILED_DIR,
    output_path: Path = DEFAULT_OUTPUT_PATH,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> dict:
    """Processa SBOMs pendentes preservando o último scan válido por agente.

    - Lote sem arquivos: nenhum agente é alterado (consolidado preservado).
    - Scan válido sem vulnerabilidades: limpa apenas os achados daquele agente.
    - Scan de um agente: os demais agentes permanecem inalterados.
    - Falha de scan: preserva a evidência anterior e a marca com erro/idade.
    """
    pending_dir.mkdir(parents=True, exist_ok=True)
    processed_dir.mkdir(parents=True, exist_ok=True)
    failed_dir.mkdir(parents=True, exist_ok=True)

    state_path = state_path_for(output_path)
    agents = load_state(state_path, output_path)

    processed_count = 0
    failed_count = 0
    batch_vulnerabilities = 0
    changed = False

    for sbom_path in sorted(pending_dir.glob("*.json")):
        agent_id = agent_id_from_sbom(sbom_path)
        now_iso = datetime.now(timezone.utc).isoformat()
        try:
            sbom_records = process_sbom(sbom_path, timeout_seconds=timeout_seconds)
            destination = move_with_timestamp(sbom_path, processed_dir)
            db_version = sbom_records[0].db_version if sbom_records else "unknown"
            agents[agent_id] = {
                "last_success_at": now_iso,
                "last_error": None,
                "last_error_at": None,
                "db_version": db_version,
                "source_sbom": destination.name,
                "vulnerabilities": [record.to_dict() for record in sbom_records],
            }
            processed_count += 1
            batch_vulnerabilities += len(sbom_records)
            changed = True
            logger.info(
                "SBOM processado: %s (%d vulnerabilidades)",
                sbom_path.name,
                len(sbom_records),
            )
        except Exception as exc:
            failed_count += 1
            changed = True
            logger.exception("Falha ao processar SBOM %s: %s", sbom_path, exc)
            previous = agents.get(agent_id)
            if previous is None:
                previous = agents[agent_id] = {
                    "last_success_at": None,
                    "db_version": "unknown",
                    "source_sbom": None,
                    "vulnerabilities": [],
                }
            if previous is not None:
                # Evidência anterior preservada, explicitamente marcada com o erro.
                previous["last_error"] = f"{type(exc).__name__}"
                previous["last_error_at"] = now_iso
            try:
                move_with_timestamp(sbom_path, failed_dir)
            except OSError:
                logger.exception("Falha ao mover SBOM com erro para failed/: %s", sbom_path)

    vulnerabilities = _consolidate(agents)
    metadata = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": "grype_runner",
        "schema": "per_agent_v1",
        "pending_dir": str(pending_dir),
        "processed_count": processed_count,
        "failed_count": failed_count,
        "batch_vulnerability_count": batch_vulnerabilities,
        "vulnerability_count": len(vulnerabilities),
        "agents": _agents_summary(agents),
    }

    if not changed and output_path.is_file():
        # Lote vazio: consolidado vigente permanece intacto (mesma revisão).
        metadata["written"] = False
        return metadata

    _atomic_write_json(state_path, {"schema": "per_agent_v1", "agents": agents})
    _atomic_write_json(output_path, {"metadata": metadata, "vulnerabilities": vulnerabilities})
    metadata["written"] = True
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
    try:
        process_pending(
            pending_dir=args.pending_dir,
            processed_dir=args.processed_dir,
            failed_dir=args.failed_dir,
            output_path=args.output,
            timeout_seconds=args.timeout,
        )
    except StateUnavailableError:
        logger.error("Estado Grype ilegível; nenhum arquivo foi alterado e os SBOMs permanecem pendentes.")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
