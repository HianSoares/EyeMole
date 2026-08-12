#!/usr/bin/env python3
"""
Gera ou rotaciona o token de upload de SBOM de um agente.

O token em claro e impresso uma unica vez. O assets_context.json recebe apenas
o hash SHA-256 associado ao agent_id.
"""

from __future__ import annotations

import argparse
import sys

import soar_api


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Gera token Bearer para upload de SBOM por agente."
    )
    parser.add_argument("agent_id", help="ID do agente existente em assets_context.json")
    parser.add_argument(
        "--disable-upload",
        action="store_true",
        help="Grava o token, mas deixa sbom_upload_enabled=false.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    token = soar_api.generate_agent_token()

    try:
        soar_api.set_agent_sbom_token(
            args.agent_id,
            token,
            enabled=not args.disable_upload,
        )
    except KeyError:
        print("Erro: agent_id desconhecido em assets_context.json.", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"Erro: {exc}", file=sys.stderr)
        return 2
    except OSError:
        print("Erro: falha ao gravar assets_context.json.", file=sys.stderr)
        return 1

    print(token)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
