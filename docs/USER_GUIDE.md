---
title: Guia do Usuário — EyeMole SOAR
version: 1.0.0
last_updated: 2026-07-29
audience:
  - operador-soc
---

# Guia do Usuário do EyeMole SOAR

## O que é o EyeMole

O EyeMole SOAR é uma ferramenta de priorização e visualização de vulnerabilidades que opera sobre dados do Wazuh. Ele resolve um problema comum em ambientes monitorados: o volume bruto de alertas de vulnerabilidade dificulta a ação efetiva do time de segurança.

**O que faz:**

- Coleta vulnerabilidades detectadas pelo Wazuh Indexer (OpenSearch)
- Cruza com fontes de inteligência: catálogo CISA KEV (exploração ativa confirmada) e EPSS (probabilidade de exploração)
- Classifica cada achado em níveis de prioridade (1+ a 4)
- Calcula um Risk Score Contextual considerando severidade, exploração, exposição do ativo, criticidade e SLA
- Publica um Dashboard interativo com filtros, tendências, SLA e auditoria
- Registra ações de classificação e execução em log de auditoria

**O que NÃO faz:**

- Não aplica patches nem executa correções automáticas
- Não altera configurações do Wazuh, dos agentes ou do sistema operacional
- Não substitui o Wazuh Dashboard — complementa com uma camada de priorização
- Não é um scanner de vulnerabilidades — depende dos dados já coletados pelo Wazuh

O Analyser sempre executa em `--mode audit`, garantindo que nenhuma ação corretiva seja disparada automaticamente.

---

## Origem e atualização dos dados

### Fonte primária

Os dados de vulnerabilidades vêm do **Wazuh Indexer** (OpenSearch), índice `wazuh-states-vulnerabilities-*`. O Analyser consulta esse índice via scroll API para obter todas as vulnerabilidades detectadas nos agentes monitorados.

### Enriquecimento

Cada vulnerabilidade é cruzada com:

- **CISA KEV** — catálogo de vulnerabilidades com exploração ativa confirmada (cache de 6 horas)
- **EPSS** — score de probabilidade de exploração (cache de 24 horas para o CSV diário)

### Geração do snapshot

O serviço `hmg-soar-report.service` (oneshot) executa o Analyser, que:

1. Consulta o Wazuh Indexer
2. Enriquece com KEV e EPSS
3. Classifica prioridades e calcula scores
4. Publica HTML + JSONs em `/var/www/wazuh-soar/`

### Agendamento

O timer `hmg-soar-report.timer` executa a cada 6 horas (aproximadamente 00:00, 06:00, 12:00, 18:00), com até 5 minutos de atraso aleatório.

### Diferença entre Recarregar e Nova Análise

| Ação | O que faz | Gera novo snapshot? |
|---|---|---|
| **Recarregar Dados da API** (botão no Dashboard) | Consulta a API e atualiza a interface com os JSONs já publicados | Não |
| **Executar análise agora** (apenas modo web-run) | Inicia o serviço de relatório que gera novo snapshot a partir do Wazuh Indexer | Sim |

O botão "Recarregar Dados da API" **não executa shell, não dispara systemctl e não gera novo snapshot**. Apenas relê os dados já publicados pela última análise.

---

## Acesso e navegação

### URL de acesso

```
https://<servidor>/soar/
```

### Autenticação

O acesso é protegido por **Basic Auth** (HTTPS + usuário/senha). As credenciais são gerenciadas pelo administrador do sistema.

### Sidebar (barra lateral)

A sidebar à esquerda contém links para as 7 abas do Dashboard:

1. Dashboard
2. Vulnerabilidades
3. Ativos & Exposição
4. Tratamento & SLA
5. Priorização
6. Tendencias
7. Status & Auditoria

### Header (cabeçalho)

O header exibe badges informativos com:

- Timestamp de geração do snapshot
- Modo de execução (audit)
- Quantidade de agentes analisados
- CVEs únicos no snapshot
- Limiares configurados (CVSS e EPSS)
- Status da API e do Timer

### Chips globais

Os chips no header mostram métricas globais do snapshot e **não são afetados pelos filtros** da aba Vulnerabilidades.

---

## Conceitos fundamentais

| Conceito | Definição |
|---|---|
| **Achado (finding)** | Uma ocorrência única de vulnerabilidade: combinação de agente × pacote × CVE. O mesmo CVE em 3 agentes = 3 achados |
| **CVE** | Identificador único de vulnerabilidade (ex: CVE-2024-00001) |
| **Agente** | Host monitorado pelo Wazuh com um agent_id único |
| **Ativo** | Mesmo que agente, no contexto de classificação e exposição |
| **Pacote** | Software instalado no agente onde a vulnerabilidade foi detectada |
| **CVSS** | Score de severidade técnica da vulnerabilidade (0 a 10) |
| **EPSS** | Probabilidade estimada de exploração nos próximos 30 dias (0 a 1) |
| **KEV** | Catálogo CISA de vulnerabilidades com exploração ativa confirmada |
| **Exposição** | Nível de acessibilidade do ativo: internet, dmz, internal, unknown |
| **Criticidade** | Importância do ativo para o negócio: critical, high, medium, low, unknown |
| **Prioridade** | Nível calculado de urgência: 1+ (KEV), 1, 2, 3 ou 4 |
| **SLA** | Prazo máximo para tratativa da vulnerabilidade, conforme severidade e contexto |
| **Backlog** | Total de achados pendentes de tratativa |
| **Risk Score** | Pontuação agregada (0–100) representando a postura de risco do ambiente |

Para detalhes das fórmulas e pesos, consulte:
- [Métricas e Fórmulas de Pontuação](METRICS_AND_SCORING.md)
- [Referência Técnica do Dashboard](DASHBOARD_REFERENCE.md)

---

## Abas

### Aba 1 — Dashboard (Visão Geral)

**Propósito:** visão executiva da postura de risco do ambiente.

**Componentes principais:**

- Risk Score Contextual (gauge 0–100)
- 8 cards do Risk Command Center (CVEs únicos, Críticas, Altas, KEV, EPSS alto, Ativos expostos, Sem classificação, Backlog SLA)
- 7 Sinais de Risco (barras de progresso independentes)
- Top 10 Prioridades acionáveis

**Decisões suportadas:** avaliação rápida da postura de risco, identificação de sinais que requerem atenção imediata (KEV > 0, ativos sem classificação, SLA vencido crescente).

**Filtros:** nenhum — esta aba opera com dados globais (snapshot completo). Um aviso é exibido: "Visão global — os filtros da aba Vulnerabilidades não se aplicam a este painel."

**Limitações:**

- O Risk Score é uma média ponderada; muitos achados low/medium podem diluir o score mesmo com achados críticos presentes
- O sinal "Correção Disponível" é sempre N/D (dado não fornecido pelo índice)
- Top 10 usa dados pré-calculados da API, não da interface

### Aba 2 — Vulnerabilidades

**Propósito:** lista completa de achados priorizados com filtros detalhados.

**Componentes principais:**

- 6 cards de prioridade (Total, P1+, P1, P2, P3, P4)
- 6 cards de métricas (Total, Críticas, Altas, KEV, EPSS alto, Correção disponível)
- Panorama de Risco (diagrama Sankey): Severidade → Prioridade → Top 5 Agentes
- Top Pacotes por Recorrência (nuvem de tags)
- Tabela de registros priorizados

**Decisões suportadas:** identificar quais vulnerabilidades tratar primeiro, filtrar por agente/severidade/exposição/criticidade/ambiente/SLA, exportar lista filtrada para CSV.

**Filtros:** todos os 6 filtros globais + busca textual + checkbox ransomware + seleção por card de prioridade. Os filtros são cumulativos (AND).

**Limitações:**

- "Correção Disponível" (vs-fix) é sempre N/D
- Agentes com muitas vulnerabilidades podem saturar visualmente o Sankey

### Aba 3 — Ativos & Exposição

**Propósito:** inventário consolidado de ativos com classificação e scores cumulativos.

**Componentes principais:**

- Tabela de ativos (ID, Host, Criticidade, Exposição, Ambiente, Vulnerabilidades, Score)
- Modal de classificação de ativos

**Decisões suportadas:** identificar ativos sem classificação, priorizar classificação de ativos expostos, revisar distribuição de criticidade.

**Filtros:** criticidade, exposição e ambiente (quando aplicáveis via barra global).

**Limitações:** o score cumulativo por ativo pode ultrapassar 100 (é a soma dos scores individuais de cada vulnerabilidade do ativo, não clampeado).

### Aba 4 — Tratamento & SLA

**Propósito:** acompanhamento de prazos e fila de remediação.

**Componentes principais:**

- Cards de SLA (Vencido, Próximo SLA, Dentro do SLA, Backlog total)
- Fila por Prioridade (P1+ a P4)
- Workload Profiles (distribuição de carga por ativo)

**Decisões suportadas:** identificar achados com SLA vencido, planejar capacidade de remediação, priorizar fila de trabalho.

**Filtros:** dados vêm da API (`/sla-summary`, `/treatment-plan`), independentes dos filtros visuais.

**Limitações:** SLA é calculado com base na data de detecção; se o snapshot for antigo, os prazos refletem o momento da última análise.

### Aba 5 — Priorização

**Propósito:** governança de exceções e decisões de risco.

**Componentes principais:**

- Top 10 Prioridades Acionáveis (excluindo exceções válidas)
- Exceções de Risco (aceitos, falsos positivos, correções planejadas, controles compensatórios, expirados)
- Gráfico de distribuição de exceções

**Decisões suportadas:** validar exceções vigentes, identificar exceções expiradas que requerem reavaliação, verificar se decisões de risco estão documentadas.

**Filtros:** dados da API (`/risk-summary`, `/risk-acceptance`), independentes dos filtros visuais.

**Limitações:** exceções expiradas recebem +10 pontos no Risk Score Contextual — requerem ação.

### Aba 6 — Tendências

**Nome na UI:** "Tendencias" (sem acento — comportamento intencional da interface).

**Propósito:** evolução do risco ao longo do tempo.

**Componentes principais:**

- Sinais de Inteligência (KEV, EPSS alto, Ransomware, Correção disponível)
- Conclusões (Trend Insights) — leitura executiva automática

**Decisões suportadas:** avaliar se o risco está crescendo ou diminuindo, identificar tendências de exploração.

**Filtros:** dados da API (`/trend-summary`), independentes dos filtros visuais.

**Limitações:**

- "Correção disponível" é sempre N/D
- Tendências dependem do histórico de snapshots; com poucos snapshots, os insights são limitados

### Aba 7 — Status & Auditoria

**Propósito:** monitoramento operacional e registro de ações.

**Componentes principais:**

- Status da API (online/offline)
- Status do Timer (ativo/inativo)
- Status do Serviço de Relatório (executando/pronto/falha)
- Botão "Executar análise agora" (visível apenas no modo web-run)
- Log de Auditoria (classificações de ativos, execuções manuais)

**Decisões suportadas:** verificar se a geração de dados está funcionando, consultar histórico de ações administrativas.

**Filtros:** nenhum — dados operacionais.

**Limitações:**

- O serviço de relatório em estado `inactive (dead)` é **normal** (oneshot concluído com sucesso)
- O botão de execução manual só aparece com modo web-run habilitado

---

## Filtros da aba Vulnerabilidades

### Campos de filtro

| Campo | Opções |
|---|---|
| Fonte / Agente | Todos os agentes (dinâmico) |
| Severidade | Todas, Critical, High, Medium, Low |
| Criticidade | Todas, critical, high, medium, low, unknown |
| Exposição | Todas, internet, dmz, internal, unknown |
| Ambiente | Todos, production, hmg, development, lab, unknown |
| Status SLA | Todos, Dentro do SLA, Proximo SLA, Vencido |

### Comportamento

- Filtros são **cumulativos (AND)**: selecionar "Critical" + "internet" mostra apenas achados que atendem ambas as condições
- Botão **Aplicar** aplica os filtros selecionados
- Botão **Reset Filters** restaura todos os filtros para "Todos/Todas" e reexibe o conjunto completo

### O que responde aos filtros (usa `filteredData`)

- 6 cards de prioridade (Total, P1+, P1, P2, P3, P4)
- 6 cards de métricas (Total, Críticas, Altas, KEV, EPSS alto, Correção disponível)
- Diagrama Sankey (Panorama de Risco & Concentração)
- Top Pacotes por Recorrência (nuvem de tags)
- Tabela de registros priorizados

**Total: 12 cards + Sankey + Top Pacotes + Tabela**

### O que NÃO responde aos filtros (usa `rawData` ou API)

- Risk Command Center (aba Dashboard)
- Sinais de Risco (aba Dashboard)
- Top 10 Prioridades Overview (aba Dashboard)
- Chips globais do header

### Reset

O botão "Reset Filters" restaura `filteredData = rawData` (conjunto completo). Todos os componentes filtráveis voltam a exibir o universo total.

---

## Classificação de ativos

### Modal de classificação

Na aba "Ativos & Exposição", clicar em um ativo abre o modal de classificação (`classify-modal-overlay`).

**Campos do formulário:**

| Campo | Tipo | Valores |
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

### Significado dos campos

- **Criticidade:** importância do ativo para o negócio. Quanto maior, menor o prazo de SLA e maior o peso no Risk Score
- **Exposição:** nível de acessibilidade de rede. Ativos com exposição `internet` ou `dmz` recebem pesos maiores no cálculo de risco
- **Ambiente:** contexto operacional. `production` tem peso significativamente maior que `lab` ou `development`

> **Limitação conhecida:** alguns valores de ambiente oferecidos pela interface (`prod`, `dev`, `test`) usam nomes abreviados que não correspondem diretamente às chaves do mecanismo de pontuação (`production`, `development`, `lab`). Nesses casos, o peso ambiental aplicado no Risk Score utiliza o fallback `unknown` (3 pontos). Apenas `hmg` possui correspondência direta. Isso não afeta CVSS, EPSS, KEV nem a Priority Classification — apenas o componente ambiental do Risk Score Contextual.

### Auditoria

Toda classificação é registrada no log de auditoria (`audit_actions.jsonl`) com timestamp, usuário, campos alterados e resultado.

### Quando é recalculado

A classificação é salva imediatamente no JSON de contexto. Porém, o **Risk Score e os SLAs só são recalculados na próxima execução do Analyser** (timer ou execução manual).

### CLI alternativa

Para classificação via linha de comando, consulte a seção "Contexto de ativos" em [OPERATIONS.md](OPERATIONS.md#contexto-de-ativos).

---

## Tratamento e SLA

### Status de SLA

| Status | Significado |
|---|---|
| `overdue` | Prazo ultrapassado — achado requer ação urgente |
| `due_soon` | Dentro de 5 dias do vencimento — atenção redobrada |
| `within_sla` | Dentro do prazo — acompanhar normalmente |

### Backlog

O backlog é o total de achados acionáveis pendentes de tratativa (soma de overdue + due_soon + within_sla).

### Risk Acceptance vs Remediação

| Abordagem | Quando usar | Efeito no score |
|---|---|---|
| **Remediação** | Vulnerabilidade pode ser corrigida (patch, atualização, reconfiguração) | Achado removido do próximo snapshot |
| **Risk Acceptance** | Risco aceito formalmente com justificativa, aprovador e prazo | Score reduzido em 30 pontos (status `accepted`) ou 15 pontos (controle compensatório) |

Exceções de risco expiradas recebem **+10 pontos** no score — devem ser renovadas ou remediadas.

---

## Status e auditoria

### API

O endpoint `/health` retorna o status da API. Se online, o Dashboard funciona normalmente.

### Serviço de relatório

- **Tipo:** oneshot — executa e termina
- **Estado normal após conclusão:** `inactive (dead)` com resultado `success`
- **Não confundir** `inactive (dead)` com falha — para um oneshot, esse é o estado esperado

### Timer

- Executa a cada 6 horas
- Estado normal: `active (waiting)` — aguardando próxima execução
- `Persistent=true` — se o servidor estava desligado no horário agendado, executa ao ligar

### Log de auditoria

A aba Status & Auditoria exibe as últimas ações registradas:
- Classificações de ativos (quem, quando, quais campos)
- Execuções manuais de análise (quando modo web-run ativo)

### Botão "Executar análise agora"

- **Modo seguro (padrão):** botão oculto e desabilitado. Mensagem informativa é exibida
- **Modo web-run (opt-in):** botão visível. Ao clicar, dispara nova análise via PolicyKit restrito

---

## Estados e valores especiais

| Estado/Valor | Significado |
|---|---|
| **0** (em cards) | Nenhum achado naquela categoria — pode ser positivo (ex: 0 KEV) |
| **N/D** | Dado não disponível. No campo "Correção Disponível", significa que o índice não fornece essa informação |
| **unknown** | Classificação pendente — ativo não foi classificado pelo operador |
| **unclassified** | Equivalente a unknown no contexto de ativos |
| **"Sem achados para a seleção de filtros atual"** | Filtros ativos não correspondem a nenhum registro — tente Reset Filters |
| **"Nenhum pacote identificado"** | Top Pacotes vazio para o filtro atual |
| **API indisponível** | A API local não está respondendo — verificar serviço `hmg-soar-api.service` |
| **Dados obsoletos (stale)** | O timestamp de geração é antigo — verificar se o timer está ativo e se a última análise teve sucesso |
| **inactive (dead)** no serviço de relatório | **Normal** — oneshot concluído com sucesso |

---

## Boas práticas

1. **Priorize KEV:** vulnerabilidades no catálogo CISA KEV têm exploração ativa confirmada. Trate-as primeiro, independente do CVSS
2. **Avalie o EPSS:** EPSS alto (≥ 0.20) indica probabilidade significativa de exploração nos próximos 30 dias. Combine com CVSS para decisões informadas
3. **Considere exposição e criticidade:** um achado medium em ativo critical/internet pode ser mais urgente que um high em ativo low/internal
4. **Respeite o SLA:** achados com status `overdue` indicam prazo ultrapassado. Priorize-os para reduzir risco operacional
5. **Valide correções:** após aplicar patch, aguarde a próxima execução do Analyser para confirmar que a vulnerabilidade não aparece mais
6. **Score baixo ≠ sem risco:** o Risk Score é uma média ponderada. Mesmo com score baixo, podem existir achados individuais críticos ou KEV que requerem ação imediata
7. **Atualize a classificação de ativos:** ativos com criticidade `unknown` recebem peso intermediário. Classifique-os corretamente para que os scores reflitam a realidade
8. **Documente decisões de risco:** use Risk Acceptance com justificativa, aprovador e prazo. Exceções expiradas penalizam o score
9. **Use filtros para investigar:** combine agente + severidade + exposição para focar em cenários específicos. Reset restaura a visão completa
10. **Não confunda achados com CVEs únicos:** o total de achados inclui a mesma CVE em múltiplos agentes/pacotes. O card "CVEs únicos" mostra identificadores distintos
