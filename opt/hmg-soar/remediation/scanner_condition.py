"""
Parser estrito de vulnerability.scanner.condition do Wazuh.

O campo é dado real vindo do scanner usado pelo Wazuh. Não há inferência:
formatos desconhecidos falham fechados e são logados para investigação.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional


logger = logging.getLogger("hmg-soar-remediation.scanner_condition")

PACKAGE_DEFAULT_STATUS = "Package default status"
PACKAGE_LESS_THAN_PREFIX = "Package less than "


@dataclass(frozen=True)
class ParsedScannerCondition:
    fixed_version: Optional[str]
    confidence: str
    status: str


def parse_scanner_condition(condition: str) -> ParsedScannerCondition:
    """Extrai fixed_version de vulnerability.scanner.condition."""
    text = str(condition or "").strip()

    if not text:
        return ParsedScannerCondition(
            fixed_version=None,
            confidence="none",
            status="missing",
        )

    if text == PACKAGE_DEFAULT_STATUS:
        return ParsedScannerCondition(
            fixed_version=None,
            confidence="none",
            status="default_status",
        )

    if text.startswith(PACKAGE_LESS_THAN_PREFIX):
        fixed_version = text[len(PACKAGE_LESS_THAN_PREFIX):].strip()
        if fixed_version:
            return ParsedScannerCondition(
                fixed_version=fixed_version,
                confidence="high",
                status="fixed",
            )

    logger.warning("Formato scanner.condition não reconhecido: %r", text)
    return ParsedScannerCondition(
        fixed_version=None,
        confidence="none",
        status="unknown_format",
    )
