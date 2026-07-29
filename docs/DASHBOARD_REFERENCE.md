---
title: Referência Técnica do Dashboard — EyeMole SOAR
version: 1.0.0
last_updated: 2026-07-29
audience:
  - desenvolvedor
  - analista de segurança sênior
---

# Referência Técnica do Dashboard

Documentação completa de todos os componentes visuais do Dashboard EyeMole SOAR, agrupados pelas 7 abas. Cada componente indica: o que mostra, fonte dos dados, unidade, como interpretar, filtros que afetam, quando merece atenção e limitações.

Todas as informações foram confirmadas diretamente no `HTML_TEMPLATE` e JavaScript embutido de `analyserV1.py`.

---

## Sumário

- [Componentes Globais](#componentes-globais)
- [Aba 1 — Dashboard (Visão Geral)](#aba-1--dashboard-visão-geral)
- [Aba 2 — Vulnerabilidades](#aba-2--vulnerabilidades)
- [Aba 3 — Ativos & Exposição](#aba-3--ativos--exposição)
- [Aba 4 — Tratamento & SLA](#aba-4--tratamento--sla)
- [Aba 5 — Priorização](#aba-5--priorização)
- [Aba 6 — Tendências](#aba-6--tendências)
- [Aba 7 — Status & Auditoria](#aba-7--status--auditoria)

---

## Navegação entre Abas

| # | `data-tab` | Nome na Sidebar | Descrição |
|---|---|---|---|
| 1 | `overview` | Dashboard | Visão geral executiva — Risk Command Center |
| 2 | `risk` | Vulnerabilidades | Lista filtrada de achados priorizados |
| 3 | `assets` | Ativos & Exposição | Inventário e classificação de ativos |
| 4 | `sla` | Tratamento & SLA | Backlog, fila de remediação, prazos |
| 5 | `governance` | Priorização | Exceções de risco e decisões de governança |
| 6 | `trends` | Tendencias | Evolução do risco ao longo do tempo |
| 7 | `status` | Status & Auditoria | Status operacional e execução manual |

---

## Componentes Globais

### Barra de Filtros Globais

**ID ou seletor:** seção `global-filterbar`

**O que mostra:** 6 campos de filtro + 2 botões de ação que controlam o subconjunto de dados visível na aba Vulnerabilidades e em componentes filtráveis.

**Campos:**

| Campo | ID | Opções |
|---|---|---|
| Fonte / Agente | `filter-agent-ui` | Todos os agentes (dinâmico) |
| Severidade | `filter-severity-ui` | Todas, Critical, High, Medium, Low |
| Criticidade | `filter-criticality-ui` | Todas, critical, high, medium, low, unknown |
| Exposição | `filter-exposure-ui` | Todas, internet, dmz, internal, unknown |
| Ambiente | `filter-env-ui` | Todos, production, hmg, development, lab, unknown |
| Status SLA | `filter-status-ui` | Todos, Dentro do SLA, Proximo SLA, Vencido |

**Botões:**
- **Aplicar** (`applyVisualFilters()`) — aplica os filtros selecionados ao conjunto de dados da aba Vulnerabilidades.
- **Reset Filters** (`resetVisualFilters()`) — restaura todos os filtros para "Todos/Todas" e reexibe o conjunto completo.

**Escopo de atuação:** os filtros afetam a aba Vulnerabilidades integralmente — cards de prioridade, strip de métricas, Sankey (Panorama de Risco), Top Pacotes e tabela de registros compartilham o mesmo `filteredData`. A aba Dashboard (Risk Command Center, Sinais de Risco, Top 10 Overview) opera com dados globais e **não é afetada** pelos filtros.

**Limitações:** Os filtros são cumulativos (AND) — selecionar "Critical" + "internet" mostra apenas achados que atendem ambas as condições.

### Botão Recarregar Dados da API

**ID:** `btn-global-reload`

**O que faz:** consulta em paralelo todos os endpoints da SOAR API local:
- `/status` (status operacional)
- `/risk-summary` (inteligência de risco)
- `/assets-context` e `/exposure-context` (contexto de ativos)
- `/sla-summary` (SLA)
- `/risk-acceptance` (governança)
- `/treatment-plan` (plano de tratativa)
- `/trend-summary` (tendências)

Após as respostas, re-renderiza o Command Center e as demais abas.

**O que NÃO faz:** não inicia nova análise de vulnerabilidades, não executa `systemctl`, não gera novo snapshot.

**Quando merece atenção:** usar quando o timer gerou um novo relatório e a interface ainda mostra dados antigos.

### Header de Metadados

**O que mostra:** badges informativos com:
- Timestamp de geração (`generation-time`)
- Modo de execução (audit/interactive)
- Quantidade de agentes analisados vs total de ativos
- CVEs únicos
- Limiares configurados (CVSS e EPSS)
- Status da API e do Timer

**Fonte:** dados embutidos no HTML pelo Python no momento da geração + consultas assíncronas à API.

---

## Aba 1 — Dashboard (Visão Geral)

**Seção HTML:** `tab-overview`

Todos os componentes desta aba utilizam **dados globais** (snapshot completo). Os filtros da barra global não afetam esta aba. Um aviso explícito é exibido: "Visão global — os filtros da aba Vulnerabilidades não se aplicam a este painel."

### Risk Score Contextual (Dashboard)

**ID:** `ccv-score` (valor), `ccv-gauge` (barra), `ccv-score-cap` (legenda)

**O que mostra:** pontuação agregada de 0 a 100 representando a postura de risco do ambiente.

**Fonte dos dados:** calculado no JavaScript `renderCommandCenter()` a partir de `rawData` (snapshot embutido).

**Unidade:** índice adimensional (não é probabilidade de ataque).

**Fórmula:** `Math.round((crit*3 + high*1.5 + kev*4 + epss*2 + exposedFindings*2 + critAssetFindings*2.5) / findings * 12)`, clamped [0, 100]. Ver [METRICS_AND_SCORING.md](METRICS_AND_SCORING.md#risk-score-do-dashboard-agregado).

**Denominador:** achados (findings = total de ocorrências CVE×agente×pacote×severidade), não CVEs únicos.

**Como interpretar:** ≥ 70 = "Risco elevado"; 40–69 = "Risco moderado"; < 40 = "Risco controlado".

**Filtros que afetam:** nenhum — utiliza dados globais.

**Quando merece atenção:** score persistentemente acima de 70 indica concentração elevada de achados críticos, KEV ou expostos.

**Limitações:** É uma média ponderada. Ambientes com muitos achados low/medium podem diluir o score mesmo com alguns achados críticos.

### Cards do Risk Command Center

| ID | Título | O que mostra | Unidade |
|---|---|---|---|
| `ccv-total` | CVEs únicos | CVEs distintos no snapshot | CVEs |
| `ccv-crit` | Críticas | Achados com severidade critical | Achados |
| `ccv-high` | Altas | Achados com severidade high | Achados |
| `ccv-kev` | KEV | Achados com CVE no catálogo CISA KEV | Achados |
| `ccv-epss` | EPSS alto | Achados com EPSS ≥ threshold | Achados |
| `ccv-exposed` | Ativos expostos | Ativos distintos com exposição internet/DMZ | Ativos |
| `ccv-unclass` | Sem classificação | Ativos sem criticidade definida | Ativos |
| `ccv-sla` | Backlog / SLA | Achados com SLA overdue ou due_soon | Achados |

**Fonte:** `renderCommandCenter()` lê `rawData` (global).

**Filtros que afetam:** nenhum.

**Quando merece atenção:** KEV > 0, Sem classificação elevado, SLA vencido crescente.

### Sinais de Risco e Priorização

**IDs:** `fnv-1` a `fnv-7` (valores), `fnb-1` a `fnb-7` (barras de progresso)

**O que mostra:** 7 sinais de risco independentes (não cumulativos). Cada sinal mede uma dimensão distinta.

| # | ID valor | Sinal | Unidade | Denominador |
|---|---|---|---|---|
| 1 | `fnv-1` | Críticas e altas | Achados | findings |
| 2 | `fnv-2` | KEV conhecido | Achados | findings |
| 3 | `fnv-3` | EPSS ≥ limiar | Achados | findings |
| 4 | `fnv-4` | Correção disponível | **N/D** | — |
| 5 | `fnv-5` | Ativos expostos | Ativos distintos | total de ativos |
| 6 | `fnv-6` | Ativos críticos | Ativos distintos | total de ativos |
| 7 | `fnv-7` | Risco de SLA | Achados | findings |

**Sinal 4 (Correção disponível):** sempre exibe "N/D" com nota "dado não fornecido pelo índice". Não contribui para nenhum cálculo. O valor `null` no array de sinais é saltado pelo loop de renderização.

**Filtros que afetam:** nenhum — dados globais.

**Como interpretar:** a barra de progresso mostra `valor / denominador × 100%`.

### Top 10 Prioridades (Overview)

**ID:** `overview-top10-tbody`

**O que mostra:** tabela com as 10 vulnerabilidades de maior priority_score (acionáveis).

**Fonte:** campo `top_actionable_priorities` de `/risk-summary` (API). Dados pré-calculados pelo Analyser, não derivados de filteredData.

**Filtros que afetam:** nenhum — dados da API (globais).

**Colunas:** Rank, CVE, Pacote, CVSS, EPSS, Severidade, Tags/Motivo.

### Top 10 Prioridades (Overview)

**ID:** `overview-top10-tbody`

**O que mostra:** tabela com as 10 vulnerabilidades de maior priority_score (acionáveis).

**Fonte:** campo `top_actionable_priorities` de `/risk-summary` (API). Dados pré-calculados pelo Analyser, não derivados de filteredData.

**Filtros que afetam:** nenhum — dados da API (globais).

**Colunas:** Rank, CVE, Pacote, CVSS, EPSS, Severidade, Tags/Motivo.

---

## Aba 2 — Vulnerabilidades

**Seção HTML:** `tab-risk`

Os componentes desta aba são **filtráveis** — respondem à barra de filtros global. Quando filtros são aplicados, os cards de prioridade e a strip de métricas são **recalculados** para refletir apenas o subconjunto filtrado. O botão "Reset Filters" restaura o conjunto completo.

### Cards de Prioridade (12 cards totais: 6 prioridade + 6 métricas)

#### 6 Cards de Prioridade

| ID | Título | O que conta |
|---|---|---|
| `count-total` | Total de Vulnerabilidades | Todos os achados (filtrados) |
| `count-p1plus` | Priority 1+ (KEV Ativo) | Achados Priority 1+ (filtrados) |
| `count-p1` | Priority 1 (Alto CVSS & EPSS) | Achados Priority 1 (filtrados) |
| `count-p2` | Priority 2 (CVSS Alto) | Achados Priority 2 (filtrados) |
| `count-p3` | Priority 3 (EPSS Alto) | Achados Priority 3 (filtrados) |
| `count-p4` | Priority 4 (Baixo Risco) | Achados Priority 4 (filtrados) |

**Interação:** clicar em um card filtra a tabela de registros por aquele nível de prioridade.

**Filtros que afetam:** todos os 6 filtros globais + checkbox ransomware. São **recalculados** a cada aplicação de filtro.

#### 6 Cards de Métricas (Strip)

| ID | Título | O que mostra |
|---|---|---|
| `vs-total` | Total | Contagem total filtrada |
| `vs-crit` | Críticas | Achados com severidade critical (filtrados) |
| `vs-high` | Altas | Achados com severidade high (filtrados) |
| `vs-kev` | KEV | Achados KEV (filtrados) |
| `vs-epss` | EPSS alto | Achados com EPSS ≥ limiar (filtrados) |
| `vs-fix` | Correção disponível | Sempre **N/D** |

**Importante:** `vs-fix` é sempre "N/D" — o índice de vulnerabilidades não fornece informação sobre disponibilidade de patch.

### Filtros Específicos da Aba

Além da barra global, a aba possui:

| Componente | ID | Função |
|---|---|---|
| Busca textual | `search-box` | Filtra por CVE, pacote ou agente (texto livre) |
| Checkbox Ransomware | `filter-ransomware` | Mostra apenas achados associados a ransomware (is_ransomware=true) |
| Botão Limpar Filtros | — | `resetFilters()` — restaura filtros internos da aba |
| Exportar CSV Filtrado | — | `exportFilteredCSV()` — exporta dados visíveis para CSV |

### Panorama de Risco & Concentração (Sankey)

**ID do container:** `risk-flow-panel-container`, SVG `risk-flow-svg`

**Localização:** aba Vulnerabilidades (tab-risk), não na aba Dashboard.

**O que mostra:** diagrama alluvial de 3 camadas: Severidade → Prioridade → Top 5 Agentes afetados.

**Fonte dos dados:** `filteredData` — a mesma coleção filtrada usada pela tabela e pelos cards de prioridade.

**Função de renderização:** `renderRiskFlowPanel('risk-flow-panel-container', filteredData)`, chamada dentro de `sortData()` após cada aplicação de filtros.

**Badges informativos:** "CISA KEV Ativo" (`badge-kev-count`) e "EPSS ≥ 20%" (`badge-epss-count`) — contagens recalculadas sobre o dataset filtrado.

**Rótulo de escopo:** `risk-flow-total-label` exibe "{N} achados no escopo atual".

**Interação:** hover destaca o fluxo específico; tooltip mostra contagem de vulnerabilidades no fluxo.

**Filtros que afetam:** todos (agente, severidade, criticidade, exposição, ambiente, status SLA, prioridade, ransomware, busca textual).

**Estado vazio:** quando `filteredData.length === 0`, exibe "Sem achados para a seleção de filtros atual."

**Limitações:** agentes com muitas vulnerabilidades podem saturar visualmente os fluxos.

### Top Pacotes por Recorrência (Nuvem de Tags)

**ID:** `risk-flow-packages-cloud`

**Localização:** rodapé do painel Sankey (aba Vulnerabilidades).

**O que mostra:** os 10 pacotes mais recorrentes no dataset filtrado, em formato de nuvem de tags com tamanho proporcional à contagem.

**Fonte dos dados:** `dataset` (= `filteredData`) dentro de `renderRiskFlowPanel`.

**Filtros que afetam:** todos — segue o mesmo dataset do Sankey.

**Estado vazio:** "Nenhum pacote identificado".

### Tabela de Registros Priorizados

**O que mostra:** lista completa de achados (filtrados), ordenada por prioridade e CVSS.

**Colunas:** CVE, Pacote, Versão, Severidade, CVSS, EPSS, KEV, Ransomware, Agente, Prioridade, Status SLA.

**Filtros que afetam:** todos os filtros globais + busca textual + checkbox ransomware + seleção de card de prioridade.

**Estado vazio:** quando nenhum achado corresponde aos filtros, exibe mensagem centralizada.

---

## Aba 3 — Ativos & Exposição

**Seção HTML:** `tab-assets`

### Tabela de Ativos

**O que mostra:** visão consolidada por ativo — criticidade, exposição, ambiente, quantidade de vulnerabilidades, score de risco cumulativo.

**Fonte:** derivado de `rawData` agrupado por `agent_id`, enriquecido com dados de `/assets-context` e `/exposure-context`.

**Colunas:** ID, Host, Criticidade, Exposição, Ambiente, Vulnerabilidades, Score.

**Filtros que afetam:** filtros de criticidade, exposição e ambiente da barra global se aplicáveis via `applyVisualFilters`.

### Modal de Classificação de Ativos

**ID:** `classify-modal-overlay`

**O que faz:** permite classificar ou reclassificar um ativo diretamente pela interface web.

**Campos do formulário:**

| Campo | Tipo | Valores / Restrição |
|---|---|---|
| ID do agente | texto (somente leitura) | — |
| Nome/Hostname | texto (somente leitura) | — |
| Criticidade | select | unknown, low, medium, high, critical |
| Ambiente | select | unknown, prod, hmg, dev, test |
| Exposição | select | unknown, internal, dmz, internet |
| Dono técnico | texto | máximo 256 caracteres |
| Dono de negócio | texto | máximo 256 caracteres |
| Serviço crítico | select | Não, Sim |
| Observações | textarea | máximo 1000 caracteres |

**Ação:** submete via `POST /assets-context/<agent_id>` à SOAR API.

**Quando usar:** ao identificar ativos sem classificação (card `ccv-unclass`) ou ao revisar classificações existentes.

**Limitação conhecida — valores de ambiente:** os valores oferecidos pelo campo Ambiente (`prod`, `dev`, `test`) não correspondem diretamente às chaves do dicionário de pesos do Analyser (`production`, `development`, `lab`). Nesses casos, o peso ambiental aplicado no Risk Score será o de `unknown` (3 pontos). Apenas `hmg` possui correspondência direta. Consulte [METRICS_AND_SCORING.md — Compatibilidade dos valores de ambiente](METRICS_AND_SCORING.md#compatibilidade-dos-valores-de-ambiente) para detalhes.

---

## Aba 4 — Tratamento & SLA

**Seção HTML:** `tab-sla`

### Cards de SLA

| ID | Título | O que mostra |
|---|---|---|
| `sx-overdue` | Vencido | Achados com SLA ultrapassado |
| `sx-nearsla` | Próximo SLA | Achados dentro de 5 dias do vencimento |
| `sx-withinsla` | Dentro do SLA | Achados dentro do prazo |
| `sx-backlog` | Backlog total | Total de itens acionáveis |

**Fonte:** dados de `/sla-summary` via API.

### Fila por Prioridade (Remediation Queue)

| ID | Título |
|---|---|
| `qx-p0` | Priority 1+ (KEV ativo / risco máximo) |
| `qx-p1` | Priority 1 |
| `qx-p2` | Priority 2 |
| `qx-p3` | Priority 3 |
| `qx-p4` | Priority 4 |

**O que mostra:** volume de achados pendentes de remediação por nível de prioridade.

### Workload Profiles

**O que mostra:** distribuição de carga de trabalho por agente/ativo, com barras segmentadas.

**Fonte:** derivado do plano de tratativa (`/treatment-plan`).

---

## Aba 5 — Priorização

**Seção HTML:** `tab-governance`

### Top 10 Prioridades Acionáveis

**O que mostra:** as 10 vulnerabilidades de maior priority_score **excluindo** aceites válidos (accepted, false_positive, out_of_scope, duplicate não expirados).

**Fonte:** `/risk-summary` (campo `top_actionable_priorities`).

### Exceções de Risco (Risk Acceptance)

**O que mostra:** regras de exceção vigentes, categorizadas em:
- Aceitos (`accepted`)
- Falsos Positivos (`false_positive`)
- Correções Planejadas (`planned_remediation`)
- Controles Compensatórios (`compensating_control`)
- Expirados

**Fonte:** `/risk-acceptance`.

### Gráfico de Distribuição de Exceções

**O que mostra:** gráfico de barras horizontais com a distribuição por tipo de exceção.

---

## Aba 6 — Tendências

**Seção HTML:** `tab-trends`

### Sinais de Inteligência

| ID | Título | O que mostra |
|---|---|---|
| `ti-kev` | KEV | Contagem de achados KEV no trend |
| `ti-epss` | EPSS alto | Achados com EPSS alto |
| `ti-ransom` | Ransomware | Achados associados a ransomware |
| `ti-fix` | Correção disponível | Sempre **N/D** |

### Conclusões (Trend Insights)

**O que mostra:** leitura executiva do momento de risco — insights automáticos sobre severidade, ativos pendentes, exploração ativa e SLA.

**Fonte:** `/trend-summary`.

---

## Aba 7 — Status & Auditoria

**Seção HTML:** `tab-status`

### Botão "Executar análise agora"

**ID:** `btn-run-analysis`

**Comportamento conforme modo de operação:**

| Modo | Comportamento |
|---|---|
| **Modo Seguro** (`safe_no_sudoers`) | Botão **oculto** (`display: none`) + desabilitado; mensagem informativa exibida |
| **Web-Run** (`web_run_enabled`) | Botão **visível** e habilitado; ao clicar, envia `POST /run-analysis` que dispara `systemctl start hmg-soar-report.service` via PolicyKit |

**Fonte:** `applyActionMode()` no JavaScript determina a visibilidade com base na resposta de `/status`.

**Quando merece atenção:** usar apenas quando necessária uma análise fora do ciclo do timer (ex: após patch emergencial).

### Status Operacional

**O que mostra:** status da API, do timer, modo de operação, última execução, última geração de relatório.

**Fonte:** `/status` endpoint.

### Auditoria

**O que mostra:** log de ações administrativas (classificação de ativos, execução manual).

**Fonte:** `/audit-actions` endpoint (lê `audit_actions.jsonl`).

---

## Resumo: Componentes Globais vs. Filtráveis

| Componente | Aba | Dados | Função de renderização |
|---|---|---|---|
| Risk Score + 8 Cards (Command Center) | Dashboard | **Global** (`rawData`) | `renderCommandCenter()` |
| 7 Sinais de Risco | Dashboard | **Global** (`rawData`) | `renderCommandCenter()` |
| Top 10 Prioridades (Overview) | Dashboard | **Global** (API `/risk-summary`) | `refreshRiskIntelligence` → `runBlock('overview-top10')` |
| 6 cards de prioridade | Vulnerabilidades | **Filtrado** (`filteredData`) | `updateVulnerabilityFilterMetrics(filteredData)` |
| 6 cards de métricas strip | Vulnerabilidades | **Filtrado** (`filteredData`) | `updateVulnerabilityFilterMetrics(filteredData)` |
| Sankey (Panorama de Risco) | Vulnerabilidades | **Filtrado** (`filteredData`) | `renderRiskFlowPanel(container, filteredData)` |
| Top Pacotes (nuvem de tags) | Vulnerabilidades | **Filtrado** (`filteredData`) | dentro de `renderRiskFlowPanel` |
| Tabela de registros | Vulnerabilidades | **Filtrado** (`filteredData`) | `renderTable()` |
| Ativos & Exposição | Ativos | Derivado + API | `refreshAssetContext()` |
| SLA, Priorização, Tendências, Status | Respectivas | API (independente dos filtros visuais) | Funções `refresh*()` |

### Comportamento dos Filtros — Confirmação no Código

- **`applyFilters()`** gera `filteredData` a partir de `rawData` com todos os filtros ativos.
- **`sortData()`** (chamada ao final de `applyFilters`) ordena `filteredData` e em seguida chama:
  - `renderTable()` — tabela de registros
  - `renderRiskFlowPanel('risk-flow-panel-container', filteredData)` — Sankey + Top Pacotes
- **`updateVulnerabilityFilterMetrics(filteredData)`** — atualiza os 12 cards (6 prioridade + 6 métricas).
- **`renderCommandCenter()`** — usa `rawData` diretamente, nunca `filteredData`.
- **Reset Filters** (`resetVisualFilters()`) → reseta selects + chama `resetFilters()` → `filterByPriority('ALL')` → `applyFilters()` com todos os filtros em "ALL" → `filteredData = rawData` (conjunto completo restaurado).

---

*Documento gerado a partir do código-fonte atual (`analyserV1.py`, `soar_api.py`). Informações não confirmáveis estão marcadas com ⚠️.*
