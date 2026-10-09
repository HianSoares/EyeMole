# CHANGELOG - HMG Wazuh SOAR Brain

## [Unreleased]

### Plataforma operacional

- Campanhas por instância/exposição, responsáveis, prazos, janelas, aceitação temporária e validação posterior por coleta e inventário.
- API modular, SQLite transacional, fila durável, auditoria encadeada e worker separado com credenciais próprias.
- RBAC por projeto/ativo, proteção do dashboard legado e SSO opcional via OAuth2 Proxy local.
- Conectores opcionais Kiro headless sem ferramentas, GLPI V1, QRadar, Vision One, Wazuh e evidências oficiais Microsoft/Red Hat/Ubuntu.
- Execução piloto Linux apt/dnf/yum via Active Response Wazuh 4.x, aprovação, allowlist, assinatura, validade e proteção contra replay.
- Diagnóstico CLI, snapshots comprimidos verificados, preflight de espaço, recuperação automática do updater e retenção configurável.
- CI Linux Python 3.12/3.13, verificação de sintaxe e workflow de releases por tag com SHA-256.
- Guia de ativação, limites e validação em `docs/PLATFORM.md`; atualizadas as instruções de atualização e recuperação.


### Adicionado

- CLI `eyemole version`, `eyemole check-update` e `sudo eyemole update`: revisão instalada registrada, atualização pelo SHA da main, preflight TLS, backup privado, bloqueio de concorrência e preservação do modo de operação.
- Consulta de versão duas vezes ao dia, endpoint local somente leitura e aviso no painel. Primeira instalação continua pelo README; instalações anteriores precisam instalar a CLI uma vez.

### Corrigido

- fix(installer): detectar o comando `setfacl` e instalar o pacote Ubuntu/Debian `acl`; corrigida a inversão que interrompia a atualização antes do backup e da instalação da aplicação.
- fix(installer): install default remediation configs on fresh install
- fix(installer): validate all Python modules including soar_api.py and remediation/
- fix(installer): remove || true masking from critical systemd operations
- fix(installer): add API health check validation
- fix(installer): add JSON validation for all configuration files
- fix(installer): ensure requests and urllib3 are available before install
- fix(installer): use SYSTEMD_UNIT_DIR for testable systemd paths
- fix(tests): skip node --check when Node.js unavailable
- fix(tests): remove dependency on var-www-wazuh-soar/index.html in clone
- fix(remediation): providers Wazuh/Grype verificam a revisão do snapshot (mtime_ns, size, inode) em toda consulta; arquivo removido/inválido descarta dados antigos; consulta, agrupamento apt e orientação usam a mesma revisão
- fix(remediation): cache de orientação invalida por Grype, contexto de ativos, allowlist, políticas, templates e evidências; resultado gerado sob revisão superada não é armazenado
- fix(grype): consolidado preserva o último scan válido por agente (lote vazio não apaga; falha mantém evidência marcada com erro/idade)
- fix(remediation): fusão separa confirmação da vulnerabilidade e da correção; divergência de versão/ecossistema bloqueia o comando; match de baixa confiança não vira alta
- fix(remediation): package.type propagado no caminho somente-Grype (npm não recebe apt); veto not-fixed/wont-fix/unknown também no provider único
- fix(remediation): validação semântica de versão (dpkg, rpm, build/UBR Windows); downgrade bloqueado; --oldpackage removido do zypper; pin sem comparador (apk) vira orientação textual
- fix(remediation): identidade de instância (finding_id v2 com versão/tipo/arquitetura/caminho); ID legado ambíguo retorna 409; analisador não descarta mais instalações distintas
- fix(analyser): TLS validado por padrão (CA interna configurável, opt-in inseguro só na sessão interna); paginação incompleta não publica snapshot
- fix(api): logger inicializado antes do fallback do rate limiter; sem limiter, endpoints dependentes respondem 503
- fix(analyser): risco, delta, tendência e SLA agregam por exposição (agente+CVE+pacote); instâncias (finding_id v2) ficam listadas na exposição e não inflam score/contagens; relógio de SLA não reinicia por nova versão, nova instalação ou reavaliação de severidade
- fix(remediation): orientação vinculada a um conjunto estável de revisões (Wazuh, Grype, contexto, allowlist, configs, templates, evidências); fonte alterada durante a geração → regeneração (até 3 tentativas) ou 503; snapshot_revision reflete as revisões efetivamente lidas
- feat(remediation): contrato v2 do "Ver correção" (guidance_kind, guidance_text, rationale, diagnostics, verification_steps, prerequisites, missing_context, sources, reboot_required); Windows recebe orientação textual + diagnósticos, nunca texto no campo de comando

### Documentação

- docs: document remediation guidance installation and operations
- docs: REMEDIATION_GUIDANCE.md (instância × exposição, prazo de SLA, contrato v2, confiança TLS, validação Linux pendente, próximos passos Kiro) e TEST_ENVIRONMENT_NOTES.md (falhas Git Bash por teste)

### Adicionado

- feat(uninstaller): add safe EyeMole removal workflow with dry-run, preserve, purge modes
- fix(uninstaller): selective preservation of state data only (not code or assets)

---

## [Fase 4] - 2026-06-23 - Premium Dashboard

### Adicionado

- CSS Design Tokens: variaveis de spacing, border-radius, shadows, transitions e surfaces
- Scrollbar global customizada (thin, dark, premium)
- Smooth scroll (html scroll-behavior)
- Header gradient animado (blue-purple-red, 8s loop)
- Tab nav refinada: hover com tint azul, focus-visible acessivel, active com inner glow
- Cards: skeleton shimmer loading animation (keyframes shimmer)
- Cards: glow por tipo no hover (red para P1+, blue para P3/all)
- Tabelas: alternating rows (nth-child even)
- Tabelas: row hover highlight com tint azul
- Tabelas: sticky thead
- Tabelas: header hover interativo e sort-active indicator
- Typography: classe .section-title com border-bottom e spacing
- Typography: classe .section-subtitle
- Spacing utilities: .section-gap, .section-gap-sm
- SVG Chart: animacao fade-in (keyframes chartFadeIn)
- SVG Chart: classe .chart-tooltip com estilo premium
- Loading: .loading-overlay com spinner CSS puro
- Loading: .loading-spinner (border animation)
- Error: .widget-error com icone e fundo vermelho sutil
- Empty: .widget-empty com icone e borda dashed
- Utilities: .fade-in, .fade-out
- Links: .cve-link com hover, transition e focus-visible
- Acessibilidade: :focus-visible global com outline azul
- Acessibilidade: ::selection com tint azul
- Footer institucional: versao, timestamp, modo, indicacao passivo

### Alterado

- Meta-badges: agora usam surface tokens, hover state, flex-wrap
- Container: max-width ajustado para 1440px
- Toolbar: usa design tokens (radius-lg, space-md, space-lg)
- h1: font-size 1.85rem, letter-spacing -0.03em, gradient 135deg
- .metric-title: font-size reduzido para 0.75rem
- .metric-value: transition de opacity adicionada
- .grid-metrics: gap e margin usando tokens

### Nao alterado

- soar_api.py
- systemd/*.service e *.timer
- nginx/wazuh-*
- config/*.json
- Endpoints da API
- Logica Python de analise e geracao de relatorios
- Template variables ({{VULN_DATA}}, {{{EXEC_MODE}}}, etc.)

### Seguranca

- Nenhuma dependencia externa adicionada
- Zero CDN
- Zero Chart.js/D3.js
- Zero eval/exec/shell=True
- Painel continua 100% passivo e analitico
- Sem Active Response ou self-healing
