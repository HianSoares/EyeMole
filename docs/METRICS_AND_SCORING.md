---
title: Métricas e Fórmulas de Pontuação — EyeMole SOAR
version: 1.0.0
last_updated: 2026-07-29
audience:
  - analista de risco
  - auditor
---

# Métricas e Fórmulas de Pontuação

Documentação oficial de todas as fórmulas, algoritmos de pontuação e critérios de classificação implementados no EyeMole SOAR. Todas as informações foram extraídas diretamente do código-fonte atual (`analyserV1.py`).

---

## Sumário

- [Priority Classification](#priority-classification)
- [Risk Score Contextual (por vulnerabilidade)](#risk-score-contextual-por-vulnerabilidade)
- [Risk Score do Dashboard (agregado)](#risk-score-do-dashboard-agregado)
- [Pesos por Dimensão](#pesos-por-dimensão)
- [Política de SLA](#política-de-sla)
- [Score SLA Operacional](#score-sla-operacional)
- [Validação de Risk Acceptance](#validação-de-risk-acceptance)
- [Sinais de Risco do Dashboard](#sinais-de-risco-do-dashboard)
- [Normalização de Severidade](#normalização-de-severidade)
- [Deduplicação](#deduplicação)
- [Tratamento de Valores Ausentes](#tratamento-de-valores-ausentes)
- [Correção Disponível](#correção-disponível)

---

## Priority Classification

**Fonte:** função `classify_priority` em `analyserV1.py` (linha 4780).

### Limiares Padrão

| Parâmetro | Constante | Valor padrão |
|---|---|---|
| CVSS threshold | `DEFAULT_CVSS_THRESHOLD` | **6.0** |
| EPSS threshold | `DEFAULT_EPSS_THRESHOLD` | **0.20** (20%) |

Os limiares podem ser ajustados via argumento de linha de comando (`--cvss-threshold`, `--epss-threshold`) e ficam armazenados no objeto `AppContext`.

### Regras de Classificação (ordem de avaliação)

As regras são **mutuamente exclusivas** e avaliadas em cadeia `if → elif → elif → elif → else`. A primeira condição verdadeira determina o nível; as demais não são testadas.

| Ordem | Nível | Condição | Descrição |
|---|---|---|---|
| 1 | **Priority 1+** | `record.is_kev == True` | CVE presente no catálogo CISA KEV (exploração ativa confirmada) |
| 2 | **Priority 1** | `cvss >= cvss_threshold` **E** `epss >= epss_threshold` | Severidade técnica alta com probabilidade de exploração alta |
| 3 | **Priority 2** | `cvss >= cvss_threshold` **E** `epss < epss_threshold` | Severidade técnica alta, mas probabilidade de exploração baixa |
| 4 | **Priority 3** | `cvss < cvss_threshold` **E** `epss >= epss_threshold` | Severidade técnica baixa, mas probabilidade de exploração alta |
| 5 | **Priority 4** | Nenhuma das condições anteriores | Baixo risco técnico e baixa probabilidade de exploração |

### Comportamentos Importantes

- **KEV tem precedência absoluta**: se a CVE está no catálogo KEV, a classificação é `Priority 1+` independentemente de CVSS e EPSS.
- **EPSS ausente ou inválido → 0.0**: o código usa `record.epss_score or 0.0`. Se o EPSS for `None` (CVE sem score disponível), é tratado como 0.0 — portanto **nunca será classificado como "alto"**.
- **CVSS ausente → 0.0**: o código usa `record.cvss_score or 0.0`. Se nulo, resultado será `Priority 4` (a menos que seja KEV).
- **is_kev é booleano puro**: determinado por `cve in cisa_kev` (teste de pertencimento no dicionário). A string `"false"` nunca aparece neste campo — é `True` ou `False` nativo do Python.
- **Soma das prioridades**: todo achado recebe exatamente uma prioridade. A soma `count_p1plus + count_p1 + count_p2 + count_p3 + count_p4` é igual ao total de achados (após deduplicação).

### Exemplo Fictício

| CVE | CVSS | EPSS | KEV? | Resultado |
|---|---|---|---|---|
| CVE-2024-00001 | 9.8 | 0.85 | Sim | Priority 1+ (KEV prevalece) |
| CVE-2024-00002 | 7.5 | 0.35 | Não | Priority 1 (CVSS ≥ 6.0 E EPSS ≥ 0.20) |
| CVE-2024-00003 | 8.1 | 0.05 | Não | Priority 2 (CVSS ≥ 6.0 E EPSS < 0.20) |
| CVE-2024-00004 | 4.3 | 0.42 | Não | Priority 3 (CVSS < 6.0 E EPSS ≥ 0.20) |
| CVE-2024-00005 | 3.1 | 0.02 | Não | Priority 4 (ambos abaixo dos limiares) |
| CVE-2024-00006 | None | None | Não | Priority 4 (valores nulos → 0.0) |

---

## Risk Score Contextual (por vulnerabilidade)

**Fonte:** função `generate_risk_intelligence` em `analyserV1.py` (linha ~1800-1870).

Este score é calculado **por vulnerabilidade** (agrupada por CVE + pacote) e representa a prioridade operacional ponderada pelo contexto do ativo mais afetado.

### Fórmula

```
score_individual = base_técnica + asset_score + exposure_score + sla_op_score + ajuste_risk_acceptance
score_final = clamp(score_individual, 0, 100)
```

O código aplica `max(0.0, min(100.0, cand_score))` — ou seja, o resultado é sempre um inteiro entre 0 e 100 (arredondado com `int()` na saída JSON).

### 1. Base Técnica

Calculada uma vez por grupo (CVE + pacote), somando pontos conforme condições:

| Condição | Pontos | Observação |
|---|---|---|
| KEV ativo (`is_kev == True`) | +40 | Exploração ativa confirmada |
| Severidade `critical` | +25 | — |
| Severidade `high` | +15 | Exclusivo com critical |
| EPSS ≥ 0.50 (muito alto) | +30 | Patamar fixo independente do threshold |
| EPSS ≥ `epss_threshold` (alto) | +20 | Exclusivo com o anterior (elif) |
| Múltiplos agentes afetados | +min(affected_count × 3, 15) | Cap de 15 pontos |
| Pacote sensível | +10 | Pertence ao conjunto `sensitive_packages` |

**Pacotes sensíveis**: `openssl`, `curl`, `sudo`, `openssh`, `openssh-server`, `kernel`, `linux-image`, `glibc`, `libc`, `apache`, `nginx`, `php`, `python`, `java`, `log4j`, `docker`, `containerd`, `kubernetes`.

### 2. Asset Score (Criticidade do Ativo)

**Fonte:** função `calculate_agent_risk_modifiers` (linha 946).

```
asset_score = WEIGHT_CRITICALITY[crit] + WEIGHT_EXPOSURE[expo] + WEIGHT_ENVIRONMENT[env] + WEIGHT_ASSET_TYPE[atype]
```

Onde `crit`, `expo`, `env` e `atype` são obtidos do `assets_context.json` do ativo. Se o valor não for encontrado no dicionário de pesos, usa-se o peso de `"unknown"`.

### 3. Exposure Score (Superfície de Ataque)

**Fonte:** função `calculate_agent_risk_modifiers` (linha 946).

```
exposure_score = level_weight + zone_weight + flags_weight + services_weight
```

Onde:
- `level_weight` = `WEIGHT_EXPOSURE_LEVEL[exposure_level]`
- `zone_weight` = `WEIGHT_NETWORK_ZONE[network_zone]`
- `flags_weight` = soma das flags booleanas:
  - `internet_facing` → +15
  - `dmz` → +10
  - `has_public_ip` → +10
  - `has_public_dns` → +8
  - `exposure_level == "unknown"` → +5
- `services_weight` = min(soma dos pesos de serviços abertos, **25**) — cap fixo de 25 pontos

### 4. Score SLA Operacional

Adicionado ao score com base no status de SLA da vulnerabilidade. Ver seção [Score SLA Operacional](#score-sla-operacional).

### 5. Ajuste de Risk Acceptance

| Status da exceção | Ajuste |
|---|---|
| `accepted` | −30 pontos |
| `compensating_control` | −15 pontos |
| `expired` (ou flag `is_expired == True`) | +10 pontos |
| Qualquer outro status | 0 (sem ajuste) |

### 6. Clamp Final

```python
score_final = max(0.0, min(100.0, score_individual))
```

O score é armazenado como inteiro (`int(best_final_score)`) no JSON publicado (`priority_score`).

### Seleção do Agente Representativo

Quando uma vulnerabilidade (CVE + pacote) afeta múltiplos agentes, o sistema calcula o score para **cada agente** e seleciona aquele com o **maior score final** como representante. Isso garante que o pior cenário operacional seja destacado.

### Exemplo Aritmético Fictício

Vulnerabilidade CVE-2024-99999 no pacote `openssl`, afetando 3 agentes. Agente com maior score: ativo classificado como `critical`/`internet`/`production`/`web_server`, exposição `internet`, zona `external`, com `internet_facing=true`, `has_public_ip=true`, SLA vencido, sem risk acceptance.

```
Base técnica:
  KEV ativo       = 0  (não está no KEV)
  Severidade high = +15
  EPSS 0.55       = +30  (≥ 0.50)
  3 agentes       = +9   (min(3×3, 15) = 9)
  Pacote sensível = +10  (openssl)
  Subtotal base   = 64

Asset Score:
  WEIGHT_CRITICALITY[critical] = 20
  WEIGHT_EXPOSURE[internet]    = 20
  WEIGHT_ENVIRONMENT[production] = 15
  WEIGHT_ASSET_TYPE[web_server] = 10
  Subtotal asset = 65

Exposure Score:
  WEIGHT_EXPOSURE_LEVEL[internet] = 25
  WEIGHT_NETWORK_ZONE[external]   = 25
  internet_facing                 = +15
  has_public_ip                   = +10
  services_weight (https/internet)= +10
  Subtotal exposure = 85

SLA Operacional (overdue, critical asset, internet_facing):
  overdue base     = +15
  asset critical   = +10
  internet_facing  = +10
  Subtotal SLA     = 35

Total bruto = 64 + 65 + 85 + 35 = 249
Clamp [0, 100] → score_final = 100
```

> **Nota:** O score é clampeado em 100. Valores brutos acima de 100 são comuns em ativos críticos expostos — o clamp impede que o score ultrapasse a escala.

### Faixas de Classificação do Score

O score por vulnerabilidade é usado para **ordenação** (maior = mais urgente). As faixas textuais são exibidas apenas no agregado do Dashboard (ver seção seguinte).

### O Que o Risk Score Contextual NÃO É

- **Não é uma probabilidade de ataque.** É uma pontuação ordinal de priorização operacional.
- **Não é um percentual de risco.** O valor 80 não significa "80% de chance de exploração".
- **Não substitui CVSS.** É complementar — incorpora contexto de ativo, exposição e SLA que o CVSS não possui.

---

## Risk Score do Dashboard (agregado)

**Fonte:** JavaScript em `renderCommandCenter` dentro do `HTML_TEMPLATE` (linha ~8826).

Este score é exibido no card `ccv-score` da aba "Dashboard" (Visão Geral) e representa a **postura de risco geral** do ambiente no snapshot atual.

### Diferença entre Achados e CVEs Únicos

| Conceito | Variável JS | Descrição |
|---|---|---|
| **Achados (findings)** | `data.length` | Total de ocorrências = combinações únicas de (CVE × agente × pacote × severidade) |
| **CVEs únicos** | `uniqueCves.size` | Número de identificadores CVE distintos (sem considerar quantos agentes afeta) |

O score do Dashboard utiliza **achados** como denominador, não CVEs únicos. O card "Total de Vulnerabilidades" (`ccv-total`) exibe CVEs únicos; já o denominador do score usa achados.

### Fórmula do Score Agregado

```javascript
if (findings > 0) {
  const raw = (crit * 3 + high * 1.5 + kev * 4 + epss * 2 + exposedFindings * 2 + critAssetFindings * 2.5) / findings;
  score = Math.max(0, Math.min(100, Math.round(raw * 12)));
}
```

| Variável | Peso | Descrição |
|---|---|---|
| `crit` | ×3 | Achados com severidade `critical` |
| `high` | ×1.5 | Achados com severidade `high` |
| `kev` | ×4 | Achados com `is_kev == true` |
| `epss` | ×2 | Achados com EPSS ≥ threshold |
| `exposedFindings` | ×2 | Achados em ativos expostos (internet ou DMZ) |
| `critAssetFindings` | ×2.5 | Achados em ativos com criticidade `critical` |

**Denominador:** `findings` (total de achados no snapshot).

**Fator de escala:** resultado da divisão é multiplicado por **12**.

**Arredondamento:** `Math.round()` — arredondamento padrão JavaScript (metade para cima).

**Clamp:** `Math.max(0, Math.min(100, ...))` — resultado final entre 0 e 100.

### Faixas Textuais

| Faixa | Rótulo |
|---|---|
| score ≥ 70 | "Risco elevado" |
| 40 ≤ score < 70 | "Risco moderado" |
| score < 40 | "Risco controlado" |

A legenda exibida é: `"{rótulo} · {findings} achados no snapshot"`.

### Exemplo Aritmético Fictício (Dashboard)

Snapshot com 50 achados: 5 critical, 10 high, 3 KEV, 8 EPSS alto, 6 expostos, 4 em ativos críticos.

```
raw = (5×3 + 10×1.5 + 3×4 + 8×2 + 6×2 + 4×2.5) / 50
    = (15 + 15 + 12 + 16 + 12 + 10) / 50
    = 80 / 50
    = 1.6

score = Math.round(1.6 × 12) = Math.round(19.2) = 19
Clamp [0, 100] → 19
Faixa: "Risco controlado"
```

### Score Cumulativo por Ativo

**Fonte:** `generate_risk_intelligence`, seção "Calcular risco cumulativo para os top ativos" (linha ~2023).

Para o ranking de ativos mais arriscados (`top_risky_assets`), o sistema soma o score individual (clampeado em [0,100]) de **cada vulnerabilidade** do ativo:

```
risk_score_ativo = Σ (score_individual de cada vuln do ativo)
```

Este valor **não é clampeado em 100** — é uma soma cumulativa que pode ultrapassar 100.

---

## Pesos por Dimensão

Todas as constantes são definidas no topo de `analyserV1.py`.

### WEIGHT_CRITICALITY (Criticidade do Ativo)

| Valor | Peso |
|---|---|
| `critical` | 20 |
| `high` | 15 |
| `medium` | 7 |
| `low` | 0 |
| `unknown` | 5 |

### WEIGHT_EXPOSURE (Exposição do Ativo — assets_context)

| Valor | Peso |
|---|---|
| `internet` | 20 |
| `dmz` | 15 |
| `internal` | 5 |
| `isolated` | 0 |
| `unknown` | 5 |

### WEIGHT_ENVIRONMENT (Ambiente)

| Valor | Peso |
|---|---|
| `production` | 15 |
| `hmg` | 3 |
| `development` | 2 |
| `lab` | 0 |
| `unknown` | 3 |

#### Compatibilidade dos valores de ambiente

A interface web e a API aceitam os valores `prod`, `hmg`, `dev`, `test` e `unknown`. Porém, as chaves reconhecidas pelo dicionário `WEIGHT_ENVIRONMENT` são `production`, `hmg`, `development`, `lab` e `unknown`. Quando o valor armazenado não possui correspondência direta, o peso aplicado é o de `unknown` (3).

| Origem | Valor armazenado | Chave reconhecida diretamente? | Peso efetivo |
|---|---|---|---|
| Modal web / API | `prod` | Não (`production` ≠ `prod`) | 3 (fallback `unknown`) |
| Modal web / API | `hmg` | **Sim** | 3 |
| Modal web / API | `dev` | Não (`development` ≠ `dev`) | 3 (fallback `unknown`) |
| Modal web / API | `test` | Não (`lab` ≠ `test`) | 3 (fallback `unknown`) |
| Modal web / API | `unknown` | **Sim** | 3 |
| Edição manual do JSON | `production` | **Sim** | 15 |
| Edição manual do JSON | `development` | **Sim** | 2 |
| Edição manual do JSON | `lab` | **Sim** | 0 |

**Impacto prático:** na configuração atual, os valores oferecidos pela interface (`prod`, `dev`, `test`) resultam no mesmo peso ambiental que `unknown` (3 pontos). Apenas `hmg` possui correspondência direta. Para obter o peso máximo de `production` (15 pontos), seria necessário que o valor armazenado no JSON fosse exatamente `production`.

**Escopo do impacto:** essa diferença afeta exclusivamente o componente `asset_score` do Risk Score Contextual (dimensão ambiental). Não altera CVSS, EPSS, KEV, Priority Classification ou cálculos de SLA.

### WEIGHT_ASSET_TYPE (Tipo de Ativo)

| Valor | Peso |
|---|---|
| `domain_controller` | 20 |
| `database` | 18 |
| `cyberark` | 18 |
| `qradar` | 15 |
| `siem` | 15 |
| `wazuh` | 15 |
| `firewall` | 15 |
| `vpn` | 12 |
| `web_server` | 10 |
| `application_server` | 10 |
| `file_server` | 8 |
| `linux_server` | 5 |
| `windows_server` | 5 |
| `endpoint` | 3 |
| `unknown` | 3 |

### WEIGHT_EXPOSURE_LEVEL (Nível de Exposição — exposure_context)

| Valor | Peso |
|---|---|
| `internet` | 25 |
| `dmz` | 18 |
| `internal` | 5 |
| `isolated` | 0 |
| `unknown` | 7 |

### WEIGHT_NETWORK_ZONE (Zona de Rede)

| Valor | Peso |
|---|---|
| `external` | 25 |
| `dmz` | 18 |
| `management` | 15 |
| `security` | 12 |
| `database` | 12 |
| `server_vlan` | 8 |
| `lan` | 5 |
| `endpoint` | 3 |
| `isolated` | 0 |
| `unknown` | 5 |

### WEIGHT_SERVICES (Serviços Abertos por Exposição)

| Serviço | Exposição | Peso |
|---|---|---|
| `rdp` | internet | 20 |
| `rdp` | internal | 8 |
| `ssh` | internet | 15 |
| `ssh` | internal | 5 |
| `vpn` | internet | 20 |
| `https` | internet | 10 |
| `https` | internal | 3 |
| `http` | internet | 12 |
| `http` | internal | 4 |
| `database` | internet | 25 |
| `database` | internal | 10 |
| `smb` | internet | 25 |
| `smb` | internal | 8 |
| `ldap` | internet | 20 |
| `ldap` | internal | 8 |
| `winrm` | internet | 18 |
| `winrm` | internal | 6 |
| `admin_ui` | internet | 18 |
| `admin_ui` | internal | 8 |
| `kibana` | internet | 18 |
| `kibana` | internal | 8 |
| `wazuh` | internet | 18 |
| `wazuh` | internal | 8 |
| `qradar` | internet | 18 |
| `qradar` | internal | 8 |
| `cyberark` | internet | 20 |
| `cyberark` | internal | 10 |

**Cap de serviços:** a soma de todos os pesos de serviços abertos é limitada a **25 pontos** (`min(services_sum, 25)`).

---

## Política de SLA

**Fonte:** constante `DEFAULT_SLA_POLICY` em `analyserV1.py` (linha 233) e função `calculate_sla_days` (linha 868).

### Prazos Padrão (dias corridos)

| Severidade | Padrão | KEV | Internet-facing | DMZ | Ativo Crítico | Ativo High | Serviço Sensível |
|---|---|---|---|---|---|---|---|
| `critical` | 15 | 7 | 7 | 10 | 7 | 10 | 7 |
| `high` | 30 | 15 | 15 | 20 | 15 | 20 | 15 |
| `medium` | 60 | 30 | 30 | 45 | 30 | 45 | 30 |
| `low` | 90 | 60 | 60 | 75 | 60 | 75 | 60 |

### Lógica de Seleção do Prazo

A função `calculate_sla_days` coleta todos os prazos aplicáveis como candidatos e retorna o **menor** (`min(sla_candidates)`). Isso garante que o SLA mais restritivo seja aplicado.

Candidatos avaliados (em ordem):
1. `defaults[severity]` — sempre incluído
2. `kev[severity]` — se `is_kev == True`
3. `internet_facing[severity]` — se `expo_ctx.internet_facing == True`
4. `dmz[severity]` — se `expo_ctx.dmz == True`
5. `critical_asset[severity]` — se `asset_ctx.criticality == "critical"`
6. `high_asset[severity]` — se `asset_ctx.criticality == "high"`
7. `sensitive_service[severity]` — se o ativo possui serviço sensível declarado

### Thresholds Operacionais

| Parâmetro | Valor padrão | Descrição |
|---|---|---|
| `near_due_threshold_days` | 5 | Dias restantes para considerar "próximo ao vencimento" |
| `persistent_threshold_days` | 30 | Dias de idade para marcar como "persistente" |
| `recurring_threshold_count` | 3 | Ocorrências em snapshots para marcar como "recorrente" |
| `business_days_only` | `false` | Se `true`, contagens usam apenas dias úteis |

### Status de SLA

| Status | Condição |
|---|---|
| `overdue` | `days_to_due < 0` (prazo ultrapassado) |
| `due_soon` | `0 <= days_to_due <= near_due_threshold_days` |
| `within_sla` | `days_to_due > near_due_threshold_days` |

### Serviços Sensíveis (para aplicação da política `sensitive_service`)

Conjunto fixo no código: `rdp`, `ssh`, `vpn`, `database`, `smb`, `ldap`, `winrm`, `admin_ui`, `kibana`, `wazuh`, `qradar`, `cyberark`.

---

## Score SLA Operacional

**Fonte:** função `calculate_sla_operational_score` em `analyserV1.py` (linha 918).

Acréscimo ao Risk Score Contextual baseado na situação de SLA e contexto.

### Acréscimos Condicionais

```python
def calculate_sla_operational_score(sla_status, persistent, recurring, asset_crit, is_kev, internet_facing):
    score = 0.0
    if sla_status == "overdue":
        score += 15.0
        if asset_crit == "critical":
            score += 10.0
        if is_kev:
            score += 10.0
        if internet_facing:
            score += 10.0
    elif sla_status == "due_soon":
        score += 8.0
    if persistent:
        score += 10.0
    if recurring:
        score += 5.0
    return score
```

| Condição | Pontos | Observação |
|---|---|---|
| SLA vencido (`overdue`) | +15 | Base |
| Overdue + ativo `critical` | +10 | Cumulativo |
| Overdue + KEV ativo | +10 | Cumulativo |
| Overdue + `internet_facing` | +10 | Cumulativo |
| Próximo ao vencimento (`due_soon`) | +8 | Exclusivo com overdue (elif) |
| Persistente (idade ≥ 30 dias) | +10 | Independente do status de SLA |
| Recorrente (≥ 3 snapshots) | +5 | Independente do status de SLA |

**Score máximo teórico:** 15 + 10 + 10 + 10 + 10 + 5 = **60** (overdue + critical + KEV + internet + persistent + recurring).

---

## Validação de Risk Acceptance

**Fonte:** função `validate_risk_acceptance_rules` em `analyserV1.py` (linha 465).

A validação é **sequencial** — cada regra passa por 8 etapas na ordem. Falha em qualquer etapa classifica a regra como inválida e interrompe a validação dessa regra (as demais regras continuam sendo processadas).

### Etapas de Validação

| # | Verificação | Critério de Falha |
|---|---|---|
| 1 | Presença de `id` | Campo `id` ausente ou vazio |
| 2 | Unicidade de `id` | ID já encontrado em regra anterior |
| 3 | Campo `enabled` | Valor não é booleano (quando presente) |
| 4 | Campo `status` | Valor fora do conjunto permitido |
| 5 | Bloco `match` | Ausente, vazio ou não é um dicionário |
| 6 | Campo `reason` | Vazio quando `defaults.require_reason == true` |
| 7 | Campo `approved_by` | Vazio quando `defaults.require_approver == true` |
| 8 | Campo `valid_until` + `max_acceptance_days` | Formato não ISO 8601, ou duração excede `max_acceptance_days` |

### Status Permitidos

Conjunto de status válidos para o campo `status` de uma regra:

```
accepted, false_positive, planned_remediation, compensating_control,
waiting_change_window, out_of_scope, duplicate, under_review
```

> **Nota:** `none`, `expired` e `invalid` existem na constante `ALLOWED_RISK_ACCEPTANCE_STATUSES` de nível de módulo, mas a validação interna usa um subconjunto restrito (8 valores acima).

### Defaults Configuráveis

| Campo | Padrão | Efeito |
|---|---|---|
| `require_expiration` | `true` | Exige campo `valid_until` |
| `require_approver` | `true` | Exige campo `approved_by` |
| `require_reason` | `true` | Exige campo `reason` |
| `max_acceptance_days` | `null` (sem limite) | Se definido, valida que `valid_until - approved_at` não excede N dias |

### Retorno

```python
(valid_rules: List[dict], invalid_rules: List[dict], alerts: List[dict])
```

---

## Sinais de Risco do Dashboard

**Fonte:** JavaScript `renderCommandCenter` (linha ~8856) e HTML do Risk Command Center.

O Dashboard exibe 7 sinais de risco no painel "Risk Command Center". Cada sinal é **independente** — um achado pode contribuir para múltiplos sinais simultaneamente.

| # | Sinal | Condição | Universo | Denominador |
|---|---|---|---|---|
| 1 | Severidade Alta/Crítica | `severity == "critical"` ou `severity == "high"` | Achados | findings |
| 2 | KEV Conhecido | `is_kev == true` | Achados | findings |
| 3 | EPSS ≥ threshold | `epss_score >= epss_threshold` | Achados | findings |
| 4 | Correção Disponível | **N/D** — dado não fornecido pelo índice | — | — |
| 5 | Ativos Expostos | Ativo com exposição internet ou DMZ | Ativos distintos | total de ativos |
| 6 | Ativos Críticos | Ativo com `criticality == "critical"` | Ativos distintos | total de ativos |
| 7 | Risco SLA | `sla_status` em {`overdue`, `due_soon`} | Achados | findings |

### Observações

- O **Sinal 4 (Correção Disponível)** é sempre `N/D`. O índice de vulnerabilidades do Wazuh/OpenSearch não fornece informação sobre disponibilidade de patch. O valor nunca é convertido em zero nem usado no cálculo do score.
- Os sinais 5 e 6 contam **ativos distintos** (deduplicados por `agent_id`), não achados.
- A barra de progresso de cada sinal representa `valor / denominador × 100%`.

---

## Normalização de Severidade

**Fonte:** função `calculate_sla_days` (linha 868).

```python
sev = str(severity).lower().strip()
if sev not in ["critical", "high", "medium", "low"]:
    sev = "medium"
```

Qualquer valor de severidade fora do conjunto `{critical, high, medium, low}` (incluindo `"N/A"`, strings vazias, ou valores desconhecidos) é normalizado para `"medium"` no contexto do cálculo de SLA.

Esta normalização **não altera** o campo `severity` original do registro — aplica-se somente ao cálculo de prazo de SLA.

---

## Deduplicação

**Fonte:** função `analyze_vulnerabilities` em `analyserV1.py` (linha 4797).

### Regra de Deduplicação

Chave de deduplicação: `(agent_id, package_name, cve)`.

Se a mesma combinação (agente + pacote + CVE) aparece mais de uma vez nos resultados do indexador, apenas a **primeira ocorrência** é mantida. As demais são descartadas silenciosamente.

```python
dedup_key = (record.agent_id, record.package_name)
if record.cve in seen_cves[dedup_key]:
    duplicates_skipped += 1
    continue
seen_cves[dedup_key].add(record.cve)
```

### Implicação para Contagens

- **Achados (findings):** total de registros após deduplicação = combinações únicas de (agente × pacote × CVE).
- **CVEs únicos:** derivado no JavaScript com `new Set()` sobre todos os `cve` dos achados.
- Um mesmo CVE pode aparecer múltiplas vezes nos achados (em agentes ou pacotes diferentes).

---

## Tratamento de Valores Ausentes

### EPSS

**Fonte:** `extract_record` (linha 4717) e `_parse_epss_stream` (linha 4291).

- O EPSS é filtrado por threshold durante o carregamento: apenas CVEs com `score >= epss_threshold` são retidos no dicionário.
- Se um CVE não está no dicionário EPSS, `epss_data.get(cve)` retorna `None`.
- Na classificação de prioridade: `record.epss_score or 0.0` → `None` vira **0.0**.
- Na base técnica do Risk Score: condições `if epss_score is not None` protegem contra None — EPSS ausente **não contribui pontos**.
- **Comportamento seguro:** EPSS vazio ou inválido jamais é tratado como alto.

### CVSS

**Fonte:** `extract_record` (linha 4717).

Hierarquia de extração:
1. `vulnerability.cvss3.base_score` ou `vulnerability.cvss3.score`
2. `vulnerability.cvss2.base_score` ou `vulnerability.cvss2.score`
3. `vulnerability.cvss.score`
4. Se todos nulos → fallback por severidade: critical=9.5, high=8.0, medium=5.5, low=2.5
5. Se severidade também não mapeável → `None`

Na classificação: `record.cvss_score or 0.0` → `None` vira **0.0**.

### KEV

**Fonte:** `extract_record` (linha 4763).

```python
is_kev = cve in cisa_kev
```

Teste booleano puro de pertencimento ao dicionário. Não há parsing de string — o resultado é `True` ou `False` nativo do Python.

---

## Correção Disponível

**Fonte:** HTML_TEMPLATE, Sinal 4 (linha ~6911) e JavaScript (linha ~8920).

O campo "Correção Disponível" (Fix Available) é exibido como **N/D** (Não Disponível) em todas as abas e cards onde aparece. O código contém o seguinte comentário:

> "correção disponível" não é mensurável com os dados atuais. [...] O chip "Fix Available" foi removido por ser uma afirmação não sustentada pelo dado do índice.

O índice de vulnerabilidades do Wazuh/OpenSearch (`wazuh-states-vulnerabilities-*`) não fornece informação sobre disponibilidade de patch/correção. Portanto:

- O valor é sempre `N/D` (string literal).
- **N/D não é convertido em zero** nem contribui para nenhum cálculo de score.
- O sinal 4 no painel de sinais tem `value: null` e é saltado no loop de renderização.
- O campo `version` do pacote representa a versão **instalada**, não indica disponibilidade de atualização.

---

## Métricas Filtradas da Aba Vulnerabilidades

Os cards de prioridade na aba "Vulnerabilidades" (`count-total`, `count-p1plus`, `count-p1`, `count-p2`, `count-p3`, `count-p4`) exibem **contagens filtradas** — ou seja, refletem apenas os achados visíveis após aplicação de todos os filtros ativos (agente, severidade, criticidade, exposição, ambiente, status SLA, busca textual, checkbox ransomware).

Quando nenhum filtro está ativo, exibem o total de achados por nível de prioridade.

Os cards de métricas estatísticas na strip superior (`vs-total`, `vs-crit`, `vs-high`, `vs-kev`, `vs-epss`, `vs-fix`) também refletem o universo filtrado. `vs-fix` é sempre `N/D`.

---

*Documento gerado a partir do código-fonte atual. Informações não confirmáveis estão marcadas com ⚠️.*
