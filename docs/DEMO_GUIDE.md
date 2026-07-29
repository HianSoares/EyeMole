---
title: Roteiro de Demonstração — EyeMole SOAR
version: 1.0.0
last_updated: 2026-07-29
audience:
  - gestor
---

# Roteiro de Demonstração do EyeMole SOAR

## Objetivo

**Mensagem principal:** O EyeMole transforma o volume técnico de vulnerabilidades do Wazuh em priorização operacional baseada em severidade, exploração, exposição, criticidade e SLA.

A demonstração deve transmitir:

- O Wazuh detecta — o EyeMole prioriza
- Priorização baseada em inteligência (KEV, EPSS), não apenas CVSS
- Contexto de ativo e exposição influenciam diretamente o risco calculado
- SLA garante que nenhum achado crítico fique sem prazo
- Tudo auditável — classificações, exceções, execuções

---

## Preparação

### Checklist pré-demonstração

| # | Item | Como verificar |
|---|---|---|
| 1 | Snapshot atualizado (< 6h) | Verificar timestamp no header do Dashboard |
| 2 | API online | Badge "API" verde no header |
| 3 | Timer ativo | Badge "Timer" ativo no header ou aba Status |
| 4 | Usuário web testado | Login com credenciais da demo funciona |
| 5 | Filtros testados | Aplicar e resetar filtros — cards atualizam |
| 6 | Console do navegador limpo | F12 → Console: sem erros JavaScript |
| 7 | Nenhuma informação sensível visível | Hostnames reais, IPs internos, nomes de pessoas |
| 8 | Plano de fallback | Capturas de tela preparadas caso API esteja indisponível |

### Dica

Execute uma análise manual 30 minutos antes da demonstração para garantir dados frescos:

```bash
sudo systemctl start hmg-soar-report.service
```

---

## Apresentação de 5 minutos

### Roteiro

| Passo | Ação no Dashboard | Fala sugerida | Mensagem principal |
|---|---|---|---|
| 1 | — (slide ou fala) | "O Wazuh detecta centenas de vulnerabilidades por dia. O desafio não é encontrar — é saber por onde começar." | Problema de volume |
| 2 | Aba Dashboard | "Este é o painel executivo. O Risk Score resume a postura de risco do ambiente em um número." | Visão consolidada |
| 3 | Apontar Risk Score | "Score de X — indica risco [controlado/moderado/elevado]. Os fatores que mais pesam são KEV, EPSS e exposição." | Score contextual |
| 4 | Aba Vulnerabilidades | "Aqui temos todos os achados priorizados. Priority 1+ são KEV — exploração ativa confirmada. São esses que tratamos primeiro." | Priorização por inteligência |
| 5 | Filtrar por agente | "Posso filtrar por agente específico e ver apenas as vulnerabilidades daquele ativo, com cards e Sankey atualizando." | Filtros operacionais |
| 6 | Reset + encerrar | "O EyeMole não aplica patches — ele garante que o time sabe exatamente o que tratar primeiro e por quê." | Conclusão |

### Tempo por passo

- Passos 1–2: 1 minuto
- Passos 3–4: 2 minutos
- Passos 5–6: 2 minutos

---

## Apresentação de 15 minutos

### Roteiro expandido

| # | Tema | Ação | Fala sugerida |
|---|---|---|---|
| 1 | Problema | — | "Ambientes monitorados geram centenas de CVEs. Sem priorização, tudo parece urgente — e nada é tratado." |
| 2 | Origem dos dados | Header (badges) | "Os dados vêm do Wazuh Indexer, cruzados com CISA KEV e EPSS. A cada 6 horas o sistema gera um novo snapshot." |
| 3 | Dashboard | Aba Dashboard | "Visão executiva: Risk Score, sinais de risco, Top 10 prioridades. Tudo global — não afetado por filtros." |
| 4 | Risk Score | Apontar gauge | "O score pondera severidade, KEV, EPSS, exposição e criticidade do ativo. Fórmula transparente e documentada." |
| 5 | Sinais de Risco | Barras de progresso | "7 sinais independentes. KEV e EPSS mostram o que pode ser explorado. Ativos expostos mostram a superfície de ataque." |
| 6 | Top 10 | Tabela Top 10 | "As 10 vulnerabilidades mais acionáveis — priorizadas por score, excluindo exceções válidas." |
| 7 | Vulnerabilidades | Aba Vulnerabilidades | "Lista completa de achados. Cards de prioridade permitem entender a distribuição: P1+ (KEV), P1 (CVSS+EPSS alto), P2, P3, P4." |
| 8 | Filtros | Aplicar filtro de severidade | "Filtros cumulativos — combino agente, severidade, exposição. Tudo atualiza: cards, Sankey, tabela." |
| 9 | Sankey | Diagrama | "Fluxo visual: Severidade → Prioridade → Agentes mais afetados. Mostra concentração de risco." |
| 10 | Top Pacotes | Nuvem de tags | "Os pacotes mais recorrentes no escopo filtrado. Útil para planejar patches em lote." |
| 11 | Ativos | Aba Ativos & Exposição | "Inventário classificado: criticidade, exposição, ambiente. Ativos sem classificação recebem peso intermediário." |
| 12 | SLA | Aba Tratamento & SLA | "Prazos por severidade e contexto. Vencidos, próximos e dentro do SLA — fila de remediação por prioridade." |
| 13 | Tendências | Aba Tendencias | "Evolução ao longo do tempo: o risco está crescendo ou diminuindo? Insights automáticos." |
| 14 | Auditoria | Aba Status & Auditoria | "Tudo é auditável. Classificações, execuções manuais — quem fez, quando, o quê." |

### Tempo sugerido

- Itens 1–2: 2 minutos
- Itens 3–6: 4 minutos
- Itens 7–10: 4 minutos
- Itens 11–14: 5 minutos

---

## Apresentação técnica de 30 minutos

Inclui todo o roteiro de 15 minutos, acrescido de:

### Bloco adicional: Arquitetura e operação (15 minutos)

| # | Tema | Detalhamento |
|---|---|---|
| 15 | Arquitetura | Componentes: Analyser, API, Nginx, systemd. Diagrama de fluxo de dados |
| 16 | API | Endpoints: /health, /status, /risk-summary, /assets-context, /sla-summary. API local (127.0.0.1:8765), proxy Nginx |
| 17 | Timer | OnCalendar a cada 6h, Persistent=true, RandomizedDelaySec=300. Estado normal: active (waiting) |
| 18 | Modo seguro | Padrão: sem sudoers, execução manual somente via SSH. Botão oculto no Dashboard |
| 19 | Web-run | Opt-in: PolicyKit restrito, apenas start da unidade de relatório. Apenas HMG/lab |
| 20 | Fórmulas | Priority classification (KEV → P1+, CVSS+EPSS → P1/P2/P3/P4). Risk Score do Dashboard: (crit×3 + high×1.5 + kev×4 + epss×2 + exposed×2 + critAsset×2.5) / findings × 12 |
| 21 | Contexto de ativos | Modal web ou CLI (set-asset-context.sh). Pesos por criticidade/exposição/ambiente. Recalculado na próxima análise |
| 22 | Auditoria | JSONL append-only. Registra classificações e execuções com timestamp, usuário, campos alterados |
| 23 | Atualização | git pull --ff-only → validações → install.sh → smoke test. Backups automáticos em /opt/backup-eyemole-install-{timestamp}/ |
| 24 | Limitações | Não aplica patches, não é real-time (snapshot a cada 6h), "Correção Disponível" é N/D, EPSS null → 0.0 (nunca alto) |

---

## Exemplo fictício para demonstração

### Cenário

Ambiente com 3 agentes fictícios e vulnerabilidades variadas:

| Agent ID | Hostname fictício | Criticidade | Exposição | Ambiente |
|---|---|---|---|---|
| 001 | srv-app-alpha | critical | internet | production |
| 002 | srv-db-beta | high | internal | production |
| 003 | ws-dev-gamma | low | internal | development |

### Vulnerabilidades fictícias

| CVE (fictício) | Pacote | CVSS | EPSS | KEV? | Agente | Prioridade |
|---|---|---|---|---|---|---|
| CVE-2024-00001 | openssl | 9.8 | 0.92 | Sim | 001 | 1+ |
| CVE-2024-00002 | curl | 7.5 | 0.35 | Não | 001 | 1 |
| CVE-2024-00003 | sudo | 8.1 | 0.05 | Não | 002 | 2 |
| CVE-2024-00004 | python3 | 4.3 | 0.42 | Não | 002 | 3 |
| CVE-2024-00005 | vim | 3.1 | 0.02 | Não | 003 | 4 |
| CVE-2024-00006 | openssh | 7.8 | 0.28 | Não | 001 | 1 |

### Roteiro de demonstração com o cenário

1. **Visão geral:** mostrar que o Risk Score é elevado devido ao agente 001 (critical + internet + KEV)
2. **Filtrar por agente 001:** cards mostram 3 achados, sendo 1 KEV (P1+) e 2 P1. Sankey concentra fluxo em severidade Critical/High
3. **Combinar com severidade Critical:** reduz para 1 achado (CVE-2024-00001, KEV). Cards mostram apenas P1+
4. **Reset Filters:** volta à visão completa com 6 achados distribuídos em P1+ a P4
5. **Classificação:** abrir modal do agente 003, mostrar que está como `low` — explicar que por isso seu único achado (P4) tem score baixo
6. **Conclusão:** "O mesmo CVE-2024-00003 (CVSS 8.1) tem prioridade diferente em um ativo critical/internet vs low/internal"

---

## Perguntas frequentes e respostas

### Por que há muitas vulnerabilidades mas o score é baixo?

O Risk Score é uma **média ponderada**. Se a maioria dos achados tem severidade low/medium, sem KEV, sem EPSS alto e em ativos não expostos, o score agregado será baixo. Isso não significa ausência de risco — verifique os achados individuais de maior prioridade.

### Qual a diferença entre achados (findings) e CVEs únicos?

**Achados** = total de ocorrências (agente × pacote × CVE). O mesmo CVE em 3 agentes = 3 achados. **CVEs únicos** = identificadores CVE distintos. O card "CVEs únicos" do Dashboard conta identificadores; o denominador do score usa achados.

### O EyeMole aplica patches ou corrige vulnerabilidades automaticamente?

**Não.** O EyeMole executa exclusivamente em `--mode audit`. Ele prioriza e visualiza — a correção é responsabilidade do time operacional.

### O que é KEV?

CISA KEV (Known Exploited Vulnerabilities) é um catálogo mantido pelo governo dos EUA com vulnerabilidades que têm **exploração ativa confirmada**. Se um CVE está no KEV, alguém já está explorando. Prioridade máxima (1+).

### O que é EPSS?

EPSS (Exploit Prediction Scoring System) estima a **probabilidade de exploração nos próximos 30 dias** (0 a 1). O EyeMole usa threshold padrão de 0.20 (20%). EPSS alto não garante exploração — indica probabilidade elevada.

### Como são calculadas as prioridades?

| Prioridade | Condição |
|---|---|
| 1+ | CVE no catálogo CISA KEV (prevalece sobre tudo) |
| 1 | CVSS ≥ 6.0 **E** EPSS ≥ 0.20 |
| 2 | CVSS ≥ 6.0 **E** EPSS < 0.20 |
| 3 | CVSS < 6.0 **E** EPSS ≥ 0.20 |
| 4 | Nenhuma das condições anteriores |

### O filtro altera os cards do Risk Command Center (aba Dashboard)?

**Não.** O Risk Command Center, os Sinais de Risco e o Top 10 Overview usam dados globais e não são afetados pelos filtros. Apenas a aba Vulnerabilidades (cards de prioridade, métricas, Sankey, Top Pacotes, tabela) responde aos filtros.

### O Sankey responde ao filtro?

**Sim.** O diagrama Sankey está na aba Vulnerabilidades e usa `filteredData` — responde a todos os filtros aplicados.

### O que significa N/D?

**Não Disponível.** Aparece no campo "Correção Disponível" porque o índice de vulnerabilidades do Wazuh não fornece informação sobre disponibilidade de patch. Não é zero, não é ausência de correção — é dado não fornecido.

### O dashboard é tempo real?

**Não.** O Dashboard exibe o último snapshot gerado pelo Analyser (a cada ~6 horas). O botão "Recarregar Dados da API" relê os JSONs publicados mas não gera novo snapshot. Para dados atualizados, é necessário nova execução do Analyser.

### Como classificar um ativo?

Na aba "Ativos & Exposição", clique em um ativo para abrir o modal de classificação. Defina criticidade, exposição, ambiente, donos e observações. A classificação é salva imediatamente e terá efeito nos scores na próxima análise.

### Como iniciar uma nova análise?

- **Modo seguro (padrão):** via SSH: `sudo systemctl start hmg-soar-report.service`
- **Modo web-run:** botão "Executar análise agora" na aba Status & Auditoria

### O que é web-run?

Modo opt-in que habilita o botão de execução manual no Dashboard. Usa PolicyKit restrito (não sudoers). Recomendado apenas para ambientes controlados (homologação, laboratório).

### Como as ações são auditadas?

Toda classificação de ativo e execução manual é registrada em `audit_actions.jsonl` com: timestamp UTC, usuário autenticado (via X-Remote-User), ação realizada, campos alterados e resultado. Visível na aba Status & Auditoria.

### Como confirmar que uma vulnerabilidade foi corrigida?

Após aplicar o patch no host, aguarde a próxima execução do Analyser (timer ou manual). Se a vulnerabilidade não aparecer no novo snapshot, foi resolvida. O delta comparativo (`/risk-delta`) mostra explicitamente itens resolvidos.

### Qual a diferença entre o score individual e o score do Dashboard?

- **Score individual** (Risk Score Contextual): calculado por vulnerabilidade, considera base técnica + contexto do ativo + exposição + SLA + risk acceptance. Clampeado em [0, 100]
- **Score do Dashboard** (agregado): média ponderada sobre todos os achados do snapshot. Fórmula: (crit×3 + high×1.5 + kev×4 + epss×2 + exposed×2 + critAsset×2.5) / findings × 12, clampeado em [0, 100]

---

## Mensagens que devem ser evitadas

| ❌ Não diga | ✅ Diga em vez disso |
|---|---|
| "Score baixo significa que estamos seguros" | "Score baixo indica risco controlado na média, mas verifique achados individuais de alta prioridade" |
| "EPSS garante que será explorado" | "EPSS indica probabilidade elevada de exploração — não é certeza" |
| "Se está no KEV, já fomos comprometidos" | "KEV confirma exploração ativa no ecossistema — não necessariamente no nosso ambiente" |
| "O EyeMole aplica os patches" | "O EyeMole prioriza — a correção é responsabilidade do time operacional" |
| "Unknown significa sem exposição" | "Unknown significa não classificado — pode ter qualquer nível de exposição real" |
| "Clicar em Recarregar gera uma nova análise" | "Recarregar relê os dados já publicados. Nova análise requer execução do serviço de relatório" |
| "Todos os números são CVEs únicos" | "O total de achados inclui a mesma CVE em múltiplos agentes. CVEs únicos é uma contagem distinta" |

---

## Encerramento sugerido

### Para supervisores e gestores

> "O EyeMole SOAR resolve um problema operacional concreto: transformar volume em ação. Com priorização baseada em inteligência de exploração, contexto de ativo e prazos de SLA, o time de segurança sabe exatamente o que tratar primeiro e pode demonstrar conformidade com prazos documentados.
>
> O sistema não substitui nenhuma ferramenta existente — complementa o Wazuh com uma camada de decisão que antes dependia de planilhas manuais. Tudo é auditável, transparente e documentado.
>
> Próximos passos sugeridos: classificar os ativos de maior importância, validar as exceções de risco vigentes e acompanhar a evolução do score nas próximas semanas."
