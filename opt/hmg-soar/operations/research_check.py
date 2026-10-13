"""Check access to the official research sources for one CVE (no asset data).

Run through `sudo eyemole research check --project <p> --cve <CVE> --distribution debian|ubuntu`,
which starts this module as eyemole-worker with the worker sandbox. It only
fetches public advisories (through the same cache) and prints which sources
answered; no asset, snapshot or secret is used or printed.
"""
import argparse
import json
import sys

from . import research_sources
from .security import OperationError, load_config, project_config


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python3 -m operations.research_check")
    parser.add_argument("--project", required=True)
    parser.add_argument("--cve", required=True)
    parser.add_argument("--distribution", required=True, choices=sorted(research_sources.SOURCES))
    args = parser.parse_args(argv)
    output = {"ok": False, "project": args.project, "cve": args.cve}
    try:
        cfg = project_config(load_config(), args.project)
        settings = (cfg.get("integrations") or {}).get("research")
        if not isinstance(settings, dict) or not settings.get("enabled"):
            raise OperationError("Pesquisa de correção desabilitada no projeto.", 503)
        collection = research_sources.collect(args.cve, args.distribution, settings)
        output["sources"] = [{k: s.get(k) for k in ("source", "available", "found", "url", "retrieved_at",
                                                     "cached", "stale", "error", "code")} for s in collection["sources"]]
        output["evidence_items"] = len(collection["evidence"])
        output["ok"] = any(s.get("available") for s in collection["sources"])
    except OperationError as exc:
        output.update(error=str(exc), code=getattr(exc, "code", None))
    print(json.dumps(output, ensure_ascii=False))
    return 0 if output["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
