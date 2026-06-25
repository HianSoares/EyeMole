# CHANGELOG - HMG Wazuh SOAR Brain

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
