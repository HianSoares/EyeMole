"""Validate the configured AI provider with synthetic data only.

Run through `sudo eyemole ai check --project <projeto>`, which starts this
module as eyemole-worker with the same EnvironmentFile the worker uses. No
asset, snapshot or campaign data is sent; the key is never printed.
"""
import argparse
import json
import os
import sys
import time

from . import ai
from .security import OperationError, load_config, project_config

SYNTHETIC_PLAN = {
    "finding_id": "0" * 64,
    "cve": "CVE-2024-0001",
    "package_name": "pacote-exemplo",
    "installed_version": "1.0-1",
    "fixed_version": None,
    "operating_system": "linux",
    "status": "no_guidance",
    "guidance_kind": "textual",
    "confidence": "low",
    "missing_context": ["vendor_fix_evidence", "fixed_version"],
    "rationale": "Teste sintético de conectividade do EyeMole; não contém dados de ativos.",
}


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python3 -m operations.ai_check")
    parser.add_argument("--project", required=True)
    args = parser.parse_args(argv)
    output = {"ok": False, "project": args.project}
    try:
        cfg = project_config(load_config(), args.project)
        status = ai.public_status(cfg)
        output.update(provider=status.get("provider"), model=status.get("model"))
        if not status.get("enabled"):
            raise OperationError(status.get("reason") or "Explicação por IA desabilitada.", 503)
        if status.get("provider") == "kiro":
            raise OperationError("Provedor Kiro (legado) não é validado por este comando.", 400)
        started = time.monotonic()
        result = ai.explain_plans([dict(SYNTHETIC_PLAN)], cfg, ai.scoped_secrets(cfg, dict(os.environ)))
        output.update(ok=True, served_model=result.get("served_model"),
                      latency_ms=int((time.monotonic() - started) * 1000),
                      contract="valid", recommendations=len(result["recommendations"]))
    except OperationError as exc:
        output.update(error=str(exc), code=getattr(exc, "code", None))
    print(json.dumps(output, ensure_ascii=False))
    return 0 if output["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
