"""
Comparadores de versão por ecossistema para o módulo de Remediation Guidance.

Implementa as regras oficiais de cada formato em vez de comparação de strings:
- dpkg (Debian/Ubuntu): epoch, upstream e revisão com o algoritmo verrevcmp.
- rpm (RHEL/Rocky/SUSE): epoch, version e release com o algoritmo rpmvercmp.
- windows: major.minor.build.UBR; só compara UBR dentro do mesmo build (ramo).

Quando não existe comparador confiável para o ecossistema, ou as versões não
pertencem ao mesmo ramo, retorna None. O chamador DEVE tratar None como
"não validado" e não gerar comando com pin de versão (falha fechada).

Invariantes:
- Nenhum subprocess, eval, exec, rede
- Nenhuma comparação lexicográfica da versão inteira
"""

from __future__ import annotations

import re
from typing import Optional, Tuple

_DIGITS = "0123456789"

# Gerenciador de pacotes → ecossistema de versão
_PACKAGE_MANAGER_TO_ECOSYSTEM = {
    "apt": "dpkg",
    "dnf": "rpm",
    "yum": "rpm",
    "zypper": "rpm",
    "windows": "windows",
    # apk: sem comparador implementado → None (pin bloqueado)
}

_WINDOWS_BUILD_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)\.(\d+)$")
_EPOCH_RE = re.compile(r"^\d+$")


def ecosystem_for_package_manager(package_manager: str) -> Optional[str]:
    """Retorna o ecossistema de versão para o gerenciador, ou None."""
    return _PACKAGE_MANAGER_TO_ECOSYSTEM.get(str(package_manager or "").lower().strip())


def compare_versions(ecosystem: Optional[str], left: str, right: str) -> Optional[int]:
    """Compara duas versões no ecossistema informado.

    Retorna -1 (left < right), 0 (iguais), 1 (left > right) ou None quando a
    comparação não é confiável (ecossistema sem comparador, formato inválido
    ou ramos diferentes).
    """
    if not ecosystem or not left or not right:
        return None
    left = str(left).strip()
    right = str(right).strip()
    try:
        if ecosystem == "dpkg":
            result = _compare_dpkg(left, right)
        elif ecosystem == "rpm":
            result = _compare_rpm_evr(left, right)
        elif ecosystem == "windows":
            result = _compare_windows_build(left, right)
        else:
            return None
    except (ValueError, IndexError):
        return None
    if result is None:
        return None
    return (result > 0) - (result < 0)


def is_upgrade(ecosystem: Optional[str], installed: str, target: str) -> Optional[bool]:
    """True se target é estritamente posterior a installed; None se não validável."""
    cmp = compare_versions(ecosystem, installed, target)
    if cmp is None:
        return None
    return cmp < 0


# ==========================================================================
# dpkg
# ==========================================================================

def _dpkg_order(char: str) -> int:
    if char in _DIGITS:
        return 0
    if char.isalpha():
        return ord(char)
    if char == "~":
        return -1
    if char:
        return ord(char) + 256
    return 0


def _verrevcmp(a: str, b: str) -> int:
    i = j = 0
    len_a, len_b = len(a), len(b)
    while i < len_a or j < len_b:
        first_diff = 0
        while (i < len_a and a[i] not in _DIGITS) or (j < len_b and b[j] not in _DIGITS):
            ac = _dpkg_order(a[i]) if i < len_a else 0
            bc = _dpkg_order(b[j]) if j < len_b else 0
            if ac != bc:
                return ac - bc
            i += 1
            j += 1
        while i < len_a and a[i] == "0":
            i += 1
        while j < len_b and b[j] == "0":
            j += 1
        while i < len_a and a[i] in _DIGITS and j < len_b and b[j] in _DIGITS:
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len_a and a[i] in _DIGITS:
            return 1
        if j < len_b and b[j] in _DIGITS:
            return -1
        if first_diff:
            return first_diff
    return 0


def _parse_dpkg(version: str) -> Tuple[int, str, str]:
    epoch = 0
    rest = version
    if ":" in version:
        epoch_str, rest = version.split(":", 1)
        if not _EPOCH_RE.match(epoch_str):
            raise ValueError("epoch inválido")
        epoch = int(epoch_str)
    if "-" in rest:
        upstream, revision = rest.rsplit("-", 1)
    else:
        upstream, revision = rest, ""
    if not upstream or upstream[0] not in _DIGITS:
        raise ValueError("upstream deve iniciar com dígito")
    return epoch, upstream, revision


def _compare_dpkg(left: str, right: str) -> int:
    le, lu, lr = _parse_dpkg(left)
    re_, ru, rr = _parse_dpkg(right)
    if le != re_:
        return le - re_
    result = _verrevcmp(lu, ru)
    if result:
        return result
    return _verrevcmp(lr, rr)


# ==========================================================================
# rpm
# ==========================================================================

def _rpmvercmp(a: str, b: str) -> int:
    if a == b:
        return 0
    i = j = 0
    len_a, len_b = len(a), len(b)

    def _sep(c: str) -> bool:
        return not c.isalnum() and c not in "~^"

    while i < len_a or j < len_b:
        while i < len_a and _sep(a[i]):
            i += 1
        while j < len_b and _sep(b[j]):
            j += 1

        a_tilde = i < len_a and a[i] == "~"
        b_tilde = j < len_b and b[j] == "~"
        if a_tilde or b_tilde:
            if not a_tilde:
                return 1
            if not b_tilde:
                return -1
            i += 1
            j += 1
            continue

        a_caret = i < len_a and a[i] == "^"
        b_caret = j < len_b and b[j] == "^"
        if a_caret or b_caret:
            if i >= len_a:
                return -1
            if j >= len_b:
                return 1
            if not a_caret:
                return 1
            if not b_caret:
                return -1
            i += 1
            j += 1
            continue

        if not (i < len_a and j < len_b):
            break

        start_i, start_j = i, j
        if a[i] in _DIGITS:
            is_num = True
            while i < len_a and a[i] in _DIGITS:
                i += 1
            while j < len_b and b[j] in _DIGITS:
                j += 1
        else:
            is_num = False
            while i < len_a and a[i].isalpha():
                i += 1
            while j < len_b and b[j].isalpha():
                j += 1

        seg_a = a[start_i:i]
        seg_b = b[start_j:j]
        if not seg_b:
            # Segmentos de tipos diferentes: numérico é mais novo
            return 1 if is_num else -1

        if is_num:
            seg_a = seg_a.lstrip("0")
            seg_b = seg_b.lstrip("0")
            if len(seg_a) != len(seg_b):
                return 1 if len(seg_a) > len(seg_b) else -1
        if seg_a != seg_b:
            return 1 if seg_a > seg_b else -1

    if i >= len_a and j >= len_b:
        return 0
    return -1 if i >= len_a else 1


def _parse_rpm_evr(version: str) -> Tuple[int, str, Optional[str]]:
    epoch = 0
    rest = version
    if ":" in version:
        epoch_str, rest = version.split(":", 1)
        if not _EPOCH_RE.match(epoch_str):
            raise ValueError("epoch inválido")
        epoch = int(epoch_str)
    if "-" in rest:
        ver, release = rest.rsplit("-", 1)
    else:
        ver, release = rest, None
    if not ver:
        raise ValueError("version vazia")
    return epoch, ver, release


def _compare_rpm_evr(left: str, right: str) -> int:
    le, lv, lr = _parse_rpm_evr(left)
    re_, rv, rr = _parse_rpm_evr(right)
    if le != re_:
        return le - re_
    result = _rpmvercmp(lv, rv)
    if result:
        return result
    # Release só participa quando ambos o informam (semântica do rpm)
    if lr is None or rr is None:
        return 0
    return _rpmvercmp(lr, rr)


# ==========================================================================
# windows
# ==========================================================================

def parse_windows_build(version: str) -> Optional[Tuple[int, int, int, int]]:
    """Retorna (major, minor, build, ubr) ou None se o formato não for X.Y.BUILD.UBR."""
    match = _WINDOWS_BUILD_RE.match(str(version or "").strip())
    if not match:
        return None
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def _compare_windows_build(left: str, right: str) -> Optional[int]:
    lp = parse_windows_build(left)
    rp = parse_windows_build(right)
    if lp is None or rp is None:
        return None
    # Builds diferentes são ramos/produtos diferentes: UBR não é comparável.
    if lp[:3] != rp[:3]:
        return None
    return lp[3] - rp[3]
