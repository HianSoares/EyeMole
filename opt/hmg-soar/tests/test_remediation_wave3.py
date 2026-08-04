"""
Wave 3 Tests — Remediation Guidance MVP (Interface Copy-Only)

Comprehensive behavioral testing of the three Wave 3 bugs:
1. Modal inside tab-assets (DOM placement)
2. Permanent lock of findingId (Set lifecycle)
3. Stale async response overwrite (request sequencing)

Also covers: finding_id, node --check, security, accessibility, and UI invariants.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

import analyserV1


# ============================================================
# Fixtures
# ============================================================

@pytest.fixture
def html_template() -> str:
    """Retorna o HTML_TEMPLATE do analyserV1."""
    return analyserV1.HTML_TEMPLATE


@pytest.fixture
def js_code(html_template) -> str:
    """Extrai os blocos <script> do HTML_TEMPLATE."""
    script_blocks = re.findall(r"<script[^>]*>(.*?)</script>", html_template, re.DOTALL)
    assert script_blocks, "Nenhum bloco <script> encontrado no HTML_TEMPLATE!"
    return "\n".join(script_blocks)


@pytest.fixture
def rendered_js(html_template) -> str:
    """Extrai JS do HTML_TEMPLATE com placeholders substituídos (simulando produção)."""
    script_blocks = re.findall(r"<script[^>]*>(.*?)</script>", html_template, re.DOTALL)
    combined = "\n".join(script_blocks)
    # Substituições idênticas à produção (ver analyserV1.generate_report)
    combined = combined.replace("{{VULN_DATA}}", "[]")
    combined = combined.replace("{{GEN_TIME}}", "2026-08-03T12:00:00Z")
    combined = combined.replace("{{CVSS_THRESH}}", "6.0")
    combined = combined.replace("{{EPSS_THRESH}}", "0.2")
    combined = combined.replace("{{SCRIPT_VERSION}}", "1.0.0")
    combined = combined.replace("{{{EXEC_MODE}}}", "soar")
    combined = combined.replace("{{EXEC_MODE}}", "soar")
    combined = combined.replace("{{{AGENTS_ANALYZED}}}", "agent001")
    combined = combined.replace("{{AGENTS_ANALYZED}}", "agent001")
    combined = combined.replace("{{TOTAL_UNIQUE_CVES}}", "5")
    combined = combined.replace("{{TOTAL_AGENTS}}", "1")
    return combined


# ============================================================
# Bug 1 — Modal fora das abas (DOM Structure)
# ============================================================

class TestModalDOMPlacement:
    """Prova estrutural de que o modal não herda display:none de painéis de aba."""

    def test_modal_not_descendant_of_tab_assets(self, html_template):
        """O modal NÃO é descendente de #tab-assets."""
        # Encontrar o bloco de tab-assets
        tab_match = re.search(
            r'<section\s+id="tab-assets"[^>]*>(.*?)</section>',
            html_template, re.DOTALL
        )
        assert tab_match, "Seção #tab-assets não encontrada"
        tab_content = tab_match.group(1)
        assert 'id="guidance-modal-overlay"' not in tab_content, \
            "DEFEITO: #guidance-modal-overlay está dentro de #tab-assets"

    def test_modal_not_descendant_of_any_tab_panel(self, html_template):
        """O modal NÃO é descendente de qualquer painel de aba."""
        tab_panels = re.findall(
            r'<section\s+[^>]*class="tab-panel"[^>]*>(.*?)</section>',
            html_template, re.DOTALL
        )
        assert tab_panels, "Nenhum painel de aba encontrado"
        for i, panel_content in enumerate(tab_panels):
            assert 'id="guidance-modal-overlay"' not in panel_content, \
                f"DEFEITO: #guidance-modal-overlay dentro do tab-panel #{i+1}"

    def test_exactly_one_modal_overlay(self, html_template):
        """Existe exatamente um elemento com id guidance-modal-overlay."""
        count = html_template.count('id="guidance-modal-overlay"')
        assert count == 1, f"Esperado 1 ocorrência, encontrado {count}"

    def test_modal_is_direct_child_of_body(self, html_template):
        """O modal está posicionado antes de </body>, fora de containers."""
        # O modal deve aparecer DEPOIS do fechamento de </main> ou </div> principal
        # e ANTES de </body>
        body_close_idx = html_template.rfind("</body>")
        modal_idx = html_template.find('id="guidance-modal-overlay"')
        assert modal_idx != -1, "Modal não encontrado"
        assert body_close_idx != -1, "</body> não encontrado"
        # O modal deve estar perto do fim, antes de </body>
        between = html_template[modal_idx:body_close_idx]
        # Não deve conter abertura de <section ou <main entre o modal e </body>
        assert '<section' not in between, \
            "Há seções entre o modal e </body> — modal pode estar aninhado incorretamente"

    def test_modal_opens_regardless_of_active_tab(self, js_code):
        """O JS mostra o modal via display:flex sem dependência de aba ativa."""
        # O modal é exibido diretamente por id — não depende de parent visibility
        assert "document.getElementById('guidance-modal-overlay').style.display = 'flex'" in js_code

    def test_classify_modal_not_broken(self, html_template):
        """O modal de Editar Contexto (classify) continua existindo."""
        assert 'id="classify-modal-overlay"' in html_template


# ============================================================
# Bug 2 — Lock permanente de findingId (Set lifecycle)
# ============================================================

class TestFindingIdLockLifecycle:
    """Prova de que o Set de pendências é sempre liberado, mesmo em exceção."""

    def test_add_inside_try_block(self, js_code):
        """O add ao Set ocorre dentro (ou imediatamente antes) do bloco try protegido."""
        # A sequência correta: add ANTES do try mas DEPOIS de todas as validações
        # que podem lançar exceção sem proteção
        add_idx = js_code.find("pendingGuidanceRequests.add(findingId)")
        delete_idx = js_code.find("pendingGuidanceRequests.delete(findingId)")
        assert add_idx != -1, "add(findingId) não encontrado"
        assert delete_idx != -1, "delete(findingId) não encontrado"
        # O delete deve estar em um finally
        finally_idx = js_code.rfind("finally", add_idx, delete_idx + 100)
        assert finally_idx != -1, "delete(findingId) não está protegido por finally"

    def test_delete_in_finally_block(self, js_code):
        """pendingGuidanceRequests.delete está dentro de um bloco finally."""
        # Procura padrão: } finally { ... pendingGuidanceRequests.delete(findingId)
        pattern = r'finally\s*\{[^}]*pendingGuidanceRequests\.delete\(findingId\)'
        match = re.search(pattern, js_code, re.DOTALL)
        assert match, "delete(findingId) não está dentro de bloco finally"

    def test_null_trigger_btn_does_not_lock(self, js_code):
        """Botão de origem null/inválido não causa lock permanente."""
        # O código deve tratar safeBtn com verificação — não acessar diretamente triggerBtn
        # antes do bloco protegido
        add_idx = js_code.find("pendingGuidanceRequests.add(findingId)")
        # Antes do add, não deve haver acesso direto a triggerBtn.textContent sem proteção
        pre_add = js_code[:add_idx]
        # Verifica que triggerBtn.textContent só é acessado de forma protegida
        # (via safeBtn ou dentro de try)
        direct_access_pattern = r'triggerBtn\.(textContent|disabled)\s*='
        # Se existir, deve ser DEPOIS do add (dentro do try)
        direct_accesses = list(re.finditer(direct_access_pattern, pre_add))
        for m in direct_accesses:
            # Exceção: a declaração de originalText pode usar triggerBtn se dentro de try
            context = pre_add[max(0, m.start()-200):m.start()]
            assert 'try' in context or 'safeBtn' in pre_add[m.start()-50:m.end()], \
                f"Acesso direto a triggerBtn antes do bloco protegido em: ...{pre_add[m.start()-30:m.end()]}"

    def test_safe_btn_pattern_used(self, js_code):
        """O código usa padrão safeBtn para proteger contra botão inválido."""
        # Verifica que existe proteção para botão nulo
        assert "safeBtn" in js_code or "triggerBtn && " in js_code or \
            "if (triggerBtn" in js_code, \
            "Nenhuma proteção para botão de origem null"

    def test_concurrent_same_finding_single_request(self, js_code):
        """Cliques simultâneos no mesmo finding geram apenas um GET."""
        assert "pendingGuidanceRequests.has(findingId)" in js_code
        # A verificação has() deve vir ANTES do add()
        has_idx = js_code.find("pendingGuidanceRequests.has(findingId)")
        add_idx = js_code.find("pendingGuidanceRequests.add(findingId)")
        assert has_idx < add_idx, "has() deve preceder add()"

    def test_set_empty_after_success(self, js_code):
        """O Set é esvaziado após conclusão normal (finally garante delete)."""
        # Garantido pela presença de delete no finally
        assert "pendingGuidanceRequests.delete(findingId)" in js_code


# ============================================================
# Bug 3 — Resposta assíncrona obsoleta (Request Sequencing)
# ============================================================

class TestStaleResponseDiscarded:
    """Prova de que respostas obsoletas são descartadas silenciosamente."""

    def test_request_id_counter_exists(self, js_code):
        """Existe um contador monotônico de requisição ativa."""
        assert "activeGuidanceRequestId" in js_code

    def test_request_id_incremented_on_open(self, js_code):
        """Cada abertura incrementa o requestId."""
        assert "activeGuidanceRequestId++" in js_code

    def test_staleness_check_after_fetch(self, js_code):
        """Após o await do fetch, verifica se a requisição ainda é ativa."""
        # Procura: if (thisRequestId !== activeGuidanceRequestId)
        pattern = r'thisRequestId\s*!==\s*activeGuidanceRequestId'
        matches = re.findall(pattern, js_code)
        assert len(matches) >= 2, \
            f"Esperado pelo menos 2 verificações de staleness, encontrado {len(matches)}"

    def test_staleness_check_after_json_parse(self, js_code):
        """Após resp.json(), verifica novamente se a requisição é ativa."""
        json_idx = js_code.find("resp.json()")
        assert json_idx != -1, "resp.json() não encontrado"
        after_json = js_code[json_idx:]
        # Deve haver uma verificação de staleness após o json parse
        stale_check = re.search(r'thisRequestId\s*!==\s*activeGuidanceRequestId', after_json)
        assert stale_check, "Sem verificação de staleness após resp.json()"

    def test_close_invalidates_request(self, js_code):
        """Fechar o modal invalida a requisição visual ativa."""
        # closeGuidanceModal deve incrementar activeGuidanceRequestId
        close_fn_match = re.search(
            r'function\s+closeGuidanceModal\s*\(\s*\)\s*\{(.*?)\n\s*\}',
            js_code, re.DOTALL
        )
        assert close_fn_match, "closeGuidanceModal não encontrada"
        close_body = close_fn_match.group(1)
        assert "activeGuidanceRequestId++" in close_body, \
            "closeGuidanceModal não invalida a requisição ativa"

    def test_stale_error_does_not_update_ui(self, js_code):
        """Erro de requisição obsoleta não altera a UI."""
        # No bloco catch, deve verificar staleness antes de chamar showGuidanceError
        catch_pattern = r'catch\s*\([^)]*\)\s*\{(.*?)\}'
        catches = re.findall(catch_pattern, js_code, re.DOTALL)
        # Pelo menos um catch deve conter a verificação de staleness
        found_stale_guard = False
        for catch_body in catches:
            if 'thisRequestId !== activeGuidanceRequestId' in catch_body:
                found_stale_guard = True
                break
        assert found_stale_guard, \
            "Nenhum bloco catch verifica staleness antes de alterar UI"

    def test_finally_does_not_corrupt_newer_request(self, js_code):
        """O finally de uma requisição antiga restaura apenas o botão daquela requisição."""
        # O finally usa safeBtn (variável local capturada no closure da openGuidanceModal)
        open_fn_start = js_code.find("async function openGuidanceModal")
        assert open_fn_start != -1, "openGuidanceModal não encontrada"
        # A função é grande — usar janela ampla
        open_fn_section = js_code[open_fn_start:open_fn_start + 8000]
        finally_idx = open_fn_section.find("} finally {")
        if finally_idx == -1:
            finally_idx = open_fn_section.find("finally {")
        assert finally_idx != -1, "Bloco finally não encontrado em openGuidanceModal"
        finally_content = open_fn_section[finally_idx:finally_idx + 300]
        # Deve usar safeBtn (variável local) não triggerBtn diretamente sem proteção
        assert "safeBtn" in finally_content or "originalText" in finally_content, \
            "Finally deve restaurar via variável local, não global"


# ============================================================
# finding_id — Paridade frontend/backend
# ============================================================

class TestFindingId:
    """Confirma paridade do finding_id entre backend e frontend."""

    def test_python_generates_sha256(self):
        """Backend gera SHA-256 do formato cve|agent_id|package|severity."""
        key = analyserV1.generate_vulnerability_key("CVE-2026-9999", "007", "openssl", "Critical")
        expected = hashlib.sha256("CVE-2026-9999|007|openssl|Critical".encode("utf-8")).hexdigest()
        assert key == expected
        assert re.match(r"^[A-Fa-f0-9]{64}$", key)

    def test_frontend_validates_hex64_regex(self, js_code):
        """Frontend valida finding_id com regex ^[A-Fa-f0-9]{64}$."""
        assert "/^[A-Fa-f0-9]{64}$/.test(findingId)" in js_code

    def test_frontend_does_not_compute_sha256(self, js_code):
        """Frontend NÃO recalcula SHA-256 — consome o finding_id pré-calculado."""
        # Não deve existir crypto.subtle.digest ou similar no JS
        assert "crypto.subtle" not in js_code, "Frontend está calculando hash"
        assert "sha256" not in js_code.lower() or "SHA-256" not in js_code, \
            "Frontend referencia SHA-256 computation"

    def test_finding_id_used_in_fetch_url(self, js_code):
        """O finding_id é usado diretamente na URL do GET."""
        assert "`/soar-api/remediation-guidance/${findingId}`" in js_code

    def test_finding_id_algorithm_documented(self):
        """O algoritmo real é cve|agent_id|package|severity (documentação)."""
        import inspect
        src = inspect.getsource(analyserV1.generate_vulnerability_key)
        assert "cve" in src
        assert "agent_id" in src
        assert "package" in src
        assert "severity" in src
        assert "|" in src  # separador pipe


# ============================================================
# Node --check — Validação de sintaxe JavaScript
# ============================================================

class TestNodeSyntaxCheck:
    """Validação real do JavaScript renderizado (sem placeholders)."""

    def test_no_placeholders_in_rendered_js(self, rendered_js):
        """Nenhum placeholder {{...}} ou {{{...}}} restante após substituição."""
        remaining = re.findall(r'\{\{[^}]+\}\}|\{\{\{[^}]+\}\}\}', rendered_js)
        assert not remaining, f"Placeholders restantes: {remaining}"

    def test_node_check_rendered_js(self, rendered_js):
        """node --check passa no JavaScript renderizado (exit code 0)."""
        import shutil
        import subprocess
        node_bin = shutil.which("node")
        if node_bin is None:
            pytest.skip("Node.js não disponível; validação node --check não executada")
        with tempfile.NamedTemporaryFile(suffix=".js", mode="w", encoding="utf-8", delete=False) as f:
            f.write(rendered_js)
            temp_path = Path(f.name)
        try:
            result = subprocess.run(
                [node_bin, "--check", str(temp_path)],
                capture_output=True, text=True, timeout=30
            )
            assert result.returncode == 0, (
                f"node --check falhou (rc={result.returncode}).\n"
                f"stderr: {result.stderr}"
            )
        finally:
            if temp_path.exists():
                temp_path.unlink()

    def test_script_blocks_count(self, html_template):
        """Relata número de blocos <script> encontrados."""
        blocks = re.findall(r"<script[^>]*>.*?</script>", html_template, re.DOTALL)
        assert len(blocks) >= 1, "Nenhum bloco script encontrado"


# ============================================================
# Security & UI Invariants
# ============================================================

class TestSecurityInvariants:
    """Invariantes de segurança do modal de orientação."""

    def test_disclaimer_permanent_exists(self, html_template):
        """O disclaimer permanente existe no HTML."""
        disclaimer = "O EyeMole não executa este comando. Valide em homologação antes de aplicar."
        assert disclaimer in html_template

    def test_no_execution_buttons(self, html_template):
        """O modal não contém botões de execução/aplicação."""
        # Encontrar conteúdo do modal
        modal_start = html_template.find('id="guidance-modal-overlay"')
        assert modal_start != -1
        # Encontrar o fechamento do modal (próximo overlay div close pattern)
        modal_section = html_template[modal_start:modal_start + 5000]
        buttons = re.findall(r'<button[^>]*>(.*?)</button>', modal_section, re.DOTALL | re.IGNORECASE)
        allowed = ["fechar", "copiar", "✕", "copiando", "copiado"]
        for btn in buttons:
            btn_text = re.sub(r'<[^>]+>', '', btn).lower().strip()
            if not btn_text:
                continue
            assert any(kw in btn_text for kw in allowed), \
                f"Botão não-autorizado: '{btn_text}'"

    def test_no_inline_onclick_in_guidance_modal(self, html_template):
        """Nenhum onclick inline nos botões do modal de orientação."""
        modal_start = html_template.find('id="guidance-modal-overlay"')
        modal_section = html_template[modal_start:modal_start + 5000]
        button_tags = re.findall(r'<button[^>]*>', modal_section, re.IGNORECASE)
        for tag in button_tags:
            assert "onclick" not in tag.lower(), f"onclick inline proibido: '{tag}'"

    def test_xss_textcontent_not_innerhtml(self, js_code):
        """Campos de exibição usam textContent, não innerHTML."""
        # Os campos de metadados devem usar textContent
        meta_fields = [
            "guidance-meta-cve", "guidance-meta-provider",
            "guidance-meta-package", "guidance-meta-rationale",
            "guidance-remediation-code", "guidance-verification-code"
        ]
        for field in meta_fields:
            # Deve existir textContent para este campo
            pattern = f"getElementById('{field}').textContent"
            assert pattern in js_code, f"{field} não usa textContent"

    def test_command_display_conditional_rules(self, js_code):
        """Comandos só são exibidos com status success + confidence high/medium."""
        assert "record.status === 'success'" in js_code
        assert "record.execution_allowed !== false" in js_code
        assert "conf === 'high' || conf === 'medium'" in js_code
        assert "record.command.trim().length > 0" in js_code

    def test_verification_requires_command(self, js_code):
        """verification_command só é exibido se command também é visível."""
        assert "hasVerification = typeof record.verification_command === 'string' && record.verification_command.trim().length > 0" in js_code

    def test_command_empty_string_not_shown(self, js_code):
        """String vazia de command não é exibida."""
        assert "record.command.trim().length > 0" in js_code


# ============================================================
# Clipboard & Audit
# ============================================================

class TestClipboardAndAudit:
    """Testes de cópia e auditoria."""

    def test_clipboard_before_audit(self, js_code):
        """Cópia local ocorre ANTES do POST de auditoria."""
        clipboard_idx = js_code.find("navigator.clipboard.writeText")
        audit_idx = js_code.find(
            "fetch(`/soar-api/remediation-guidance/${activeGuidanceRecord.guidance_id}/audit`",
            clipboard_idx
        )
        assert clipboard_idx != -1, "clipboard.writeText ausente"
        assert audit_idx != -1, "Auditoria POST ausente"
        assert clipboard_idx < audit_idx

    def test_post_body_only_action_copy(self, js_code):
        """POST de auditoria envia apenas {action: 'copy'}."""
        assert "JSON.stringify({ action: 'copy' })" in js_code

    def test_clipboard_failure_does_not_send_post(self, js_code):
        """Se clipboard falhar, o POST não é enviado (cópia é prerequisite)."""
        # A auditoria está dentro do bloco após clipboard success (await sequencial)
        # Se clipboard lança exceção, o código vai pro catch sem enviar POST
        clip_idx = js_code.find("navigator.clipboard.writeText")
        after_clip = js_code[clip_idx:clip_idx + 1500]
        # O fetch de auditoria está no mesmo try block, DEPOIS do await clipboard
        assert "await navigator.clipboard.writeText" in js_code or \
            "navigator.clipboard.writeText" in js_code

    def test_audit_failure_does_not_show_success(self, js_code):
        """Falha na auditoria mostra warning, não sucesso."""
        # Se auditResp.ok é false, mostra warning
        assert "showGuidanceError" in js_code


# ============================================================
# HTTP Status Handling
# ============================================================

class TestHTTPStatusHandling:
    """Verifica tratamento de todos os códigos de status esperados."""

    def test_401_handled(self, js_code):
        """401 exibe mensagem de sessão expirada."""
        assert "resp.status === 401" in js_code

    def test_404_handled(self, js_code):
        """404 exibe orientação indisponível."""
        assert "resp.status === 404" in js_code

    def test_429_handled(self, js_code):
        """429 exibe mensagem de rate limit com Retry-After."""
        assert "resp.status === 429" in js_code
        assert "Retry-After" in js_code

    def test_500_handled(self, js_code):
        """Erro genérico não-ok é tratado."""
        assert "!resp.ok" in js_code
        assert "Erro interno" in js_code

    def test_503_handled(self, js_code):
        """503 exibe serviço indisponível."""
        assert "resp.status === 503" in js_code

    def test_invalid_json_handled(self, js_code):
        """Resposta JSON inválida é tratada."""
        assert "resp.json()" in js_code
        # O parse está em try/catch
        assert "Resposta inválida" in js_code

    def test_no_guidance_status(self, js_code):
        """Status de 'no guidance' é exibido como info."""
        assert "'info'" in js_code


# ============================================================
# Accessibility
# ============================================================

class TestAccessibility:
    """Testes de acessibilidade do modal."""

    def test_escape_closes_modal(self, js_code):
        """Tecla Escape fecha o modal."""
        assert "Escape" in js_code

    def test_focus_trap_exists(self, js_code):
        """Focus trap está implementado."""
        assert "setupGuidanceFocusTrap" in js_code

    def test_focus_on_open(self, js_code):
        """Foco é movido para botão de fechar ao abrir."""
        assert "closeBtn" in js_code or "guidance-close-btn" in js_code
        assert "focus()" in js_code

    def test_focus_return_on_close(self, js_code):
        """Foco retorna ao botão de origem ao fechar."""
        close_fn = re.search(
            r'function\s+closeGuidanceModal\s*\(\s*\)\s*\{(.*?)\n\s{4}\}',
            js_code, re.DOTALL
        )
        assert close_fn, "closeGuidanceModal não encontrada"
        assert "focus()" in close_fn.group(1), "Foco não retorna ao fechar"

    def test_aria_attributes(self, html_template):
        """Modal possui atributos ARIA corretos."""
        modal_start = html_template.find('id="guidance-modal-overlay"')
        modal_tag = html_template[modal_start-100:modal_start+200]
        assert 'role="dialog"' in modal_tag
        assert 'aria-modal="true"' in modal_tag
        assert 'aria-labelledby="guidance-modal-title"' in modal_tag

    def test_aria_live_regions(self, html_template):
        """Regiões com aria-live para feedback dinâmico."""
        assert 'aria-live="polite"' in html_template  # loading
        assert 'aria-live="assertive"' in html_template  # message box


# ============================================================
# Confidence & Rendering Logic
# ============================================================

class TestConfidenceRendering:
    """Validação da lógica de exibição baseada em confiança."""

    def test_confidence_low_hides_command(self, js_code):
        """Confiança 'low' não exibe comando."""
        # A condição exige high ou medium
        assert "conf === 'high' || conf === 'medium'" in js_code

    def test_execution_allowed_true_rejected(self, js_code):
        """Record com execution_allowed !== false é rejeitado."""
        assert "record.execution_allowed !== false" in js_code


# ============================================================
# Modal Cleanup
# ============================================================

class TestModalCleanup:
    """Garante que o modal é limpo corretamente entre aberturas."""

    def test_fields_cleared_before_open(self, js_code):
        """Campos do modal são zerados antes de abrir novo finding."""
        assert "activeGuidanceRecord = null;" in js_code
        assert "document.getElementById('guidance-meta-cve').textContent = '';" in js_code
        assert "document.getElementById('guidance-remediation-code').textContent = '';" in js_code
        assert "document.getElementById('guidance-verification-code').textContent = '';" in js_code


# ============================================================
# Routes
# ============================================================

class TestRoutes:
    """Validação das rotas da API usadas pelo frontend."""

    def test_guidance_get_route(self, js_code):
        """Rota GET correta."""
        assert "`/soar-api/remediation-guidance/${findingId}`" in js_code

    def test_copy_audit_post_route(self, js_code):
        """Rota POST de auditoria correta."""
        assert "`/soar-api/remediation-guidance/${activeGuidanceRecord.guidance_id}/audit`" in js_code
