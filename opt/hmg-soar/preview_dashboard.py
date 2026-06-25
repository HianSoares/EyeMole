#!/usr/bin/env python3
"""
preview_dashboard.py - Gera HTML do Premium Dashboard com dados mockados.

IMPORTANTE:
- NAO conecta em rede (Wazuh, OpenSearch, CISA, EPSS)
- NAO usa credenciais ou senhas
- NAO executa analise real
- NAO altera o ambiente produtivo
- E somente um preview visual mockado para validacao do CSS/UI

Uso:
    python preview_dashboard.py

Output:
    ../var-www-wazuh-soar/index.html  (abrir no browser)
    O arquivo de output esta no .gitignore e nao sera versionado.
"""

import os
import sys
from pathlib import Path

# Garantir que o diretorio do script esta no path para import local
sys.path.insert(0, str(Path(__file__).resolve().parent))

from analyserV1 import AppContext, VulnRecord, render_html  # noqa: E402


def main() -> int:
    """Gera preview HTML mockado sem rede e sem credenciais."""

    script_dir = Path(__file__).resolve().parent
    os.chdir(script_dir)

    # 1. AppContext minimo  sem senhas, sem conexao
    ctx = AppContext(
        indexer_pass=None,
        wazuh_pass=None,
        cvss_threshold=6.0,
        epss_threshold=0.20,
    )

    # 2. Records mockados cobrindo todos cenarios de prioridade e severidade
    # ponytail: minimo necessario para exercitar todos os branches visuais do dashboard
    mock_records = [
        # Priority 1+ (KEV + EPSS alto + ransomware + Critical)
        VulnRecord("001", "windows-server-sscapps", "CVE-2024-21762",
                   "openssl", "1.1.1k-1", "Critical", 9.8, True, True, 0.95, "Priority 1+"),
        # Priority 1+ (KEV + ransomware + EPSS alto)
        VulnRecord("005", "linux-siemapps", "CVE-2023-46604",
                   "activemq", "5.17.6-1", "Critical", 9.8, True, True, 0.91, "Priority 1+"),
        # Priority 1 (KEV + CVSS 10.0, sem ransomware)
        VulnRecord("001", "windows-server-sscapps", "CVE-2024-3400",
                   "panos", "10.2.3", "Critical", 10.0, True, False, 0.78, "Priority 1"),
        # Priority 1 (KEV + EPSS=None  testa graceful handling)
        VulnRecord("004", "linux-server-asc-linux-01", "CVE-2024-1086",
                   "kernel", "6.1.0-18", "High", 7.8, True, False, None, "Priority 1"),
        # Priority 2 (EPSS alto, sem KEV)
        VulnRecord("003", "linux-server-asc-linux-02", "CVE-2023-44487",
                   "nginx", "1.24.0-1", "High", 7.5, False, False, 0.65, "Priority 2"),
        # Priority 2 (EPSS moderado)
        VulnRecord("004", "linux-server-asc-linux-01", "CVE-2023-38545",
                   "curl", "7.88.1-1", "High", 8.1, False, False, 0.42, "Priority 2"),
        # Priority 3 (CVSS acima do threshold, EPSS baixo)
        VulnRecord("003", "linux-server-asc-linux-02", "CVE-2023-4911",
                   "glibc", "2.36-9", "High", 7.8, False, False, 0.15, "Priority 3"),
        # Priority 3 (Medium severity)
        VulnRecord("005", "linux-siemapps", "CVE-2024-0567",
                   "gnutls", "3.7.9-2", "Medium", 6.5, False, False, 0.08, "Priority 3"),
        # Priority 3 (CVSS ~6.2 threshold edge)
        VulnRecord("004", "linux-server-asc-linux-01", "CVE-2023-52425",
                   "expat", "2.5.0-1", "Medium", 6.2, False, False, 0.05, "Priority 3"),
        # Priority 4 (Low risk)
        VulnRecord("001", "windows-server-sscapps", "CVE-2023-45853",
                   "zlib", "1.2.13-1", "Low", 4.3, False, False, 0.02, "Priority 4"),
        # Priority 4 (Low CVSS)
        VulnRecord("005", "linux-siemapps", "CVE-2024-2511",
                   "openssl", "3.0.13-1", "Low", 3.7, False, False, 0.01, "Priority 4"),
        # Priority 4 (Low risk multi-agent)
        VulnRecord("003", "linux-server-asc-linux-02", "CVE-2023-50495",
                   "ncurses", "6.4-4", "Low", 5.5, False, False, 0.03, "Priority 4"),
    ]

    # 3. Agent IDs derivados dos records
    agent_ids = sorted(set(r.agent_id for r in mock_records))

    # 4. Gerar HTML via render_html (sem rede, sem credenciais)
    print("[*] Gerando preview mockado do Premium Dashboard...")
    html = render_html(ctx, mock_records, agent_ids, mode="audit")

    # 5. Gravar output (arquivo ja ignorado pelo .gitignore)
    output_path = Path(__file__).resolve().parent.parent.parent / "var-www-wazuh-soar" / "index.html"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")

    # Copiar assets para preview local
    assets_src = Path(__file__).resolve().parent / "assets"
    assets_dst = output_path.parent / "assets"
    if assets_src.exists():
        assets_dst.mkdir(parents=True, exist_ok=True)
        import shutil as _shutil
        for asset_file in assets_src.iterdir():
            if asset_file.is_file():
                _shutil.copy2(asset_file, assets_dst / asset_file.name)
        print(f"     Assets copiados: {assets_dst}")

    print(f"[OK] Preview gerado: {output_path}")
    print(f"     Tamanho: {output_path.stat().st_size:,} bytes")
    print(f"     Records mockados: {len(mock_records)}")
    print(f"     Agentes: {', '.join(agent_ids)}")
    print(f"     Prioridades: 1+ ({sum(1 for r in mock_records if r.priority == 'Priority 1+')}), "
          f"1 ({sum(1 for r in mock_records if r.priority == 'Priority 1')}), "
          f"2 ({sum(1 for r in mock_records if r.priority == 'Priority 2')}), "
          f"3 ({sum(1 for r in mock_records if r.priority == 'Priority 3')}), "
          f"4 ({sum(1 for r in mock_records if r.priority == 'Priority 4')})")
    print()
    print("     Abrir no browser para validacao visual:")
    print(f"     Start-Process \"{output_path}\"")
    print()
    print("     NOTA: Este preview usa dados FICTICIOS.")
    print("     NAO conectou em rede. NAO usou credenciais.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
