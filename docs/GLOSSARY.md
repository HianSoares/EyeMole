---
title: Glossário — EyeMole SOAR
version: 1.0.0
last_updated: 2026-07-29
audience:
  - desenvolvedor
  - operador-soc
  - gestor
  - auditor
  - administrador
---

# Glossário — EyeMole SOAR

Glossário de termos utilizados na documentação do produto EyeMole SOAR. Os termos estão em ordem alfabética (A–Z, ignorando acentos para ordenação).

---

## Aceitação de risco

**Definição:** decisão formal e documentada de aceitar o risco associado a uma vulnerabilidade, em vez de corrigi-la imediatamente.

**No EyeMole:** registrada em `risk_acceptance.json` com justificativa, aprovador e prazo de validade. Reduz o Risk Score Contextual em 30 pontos (status `accepted`) ou 15 pontos (status `compensating_control`). Exceções expiradas adicionam +10 pontos ao score.

**Não confundir com:** remediação. Aceitação de risco não elimina a vulnerabilidade — apenas documenta a decisão de conviver com ela temporariamente.

**Referências:** [METRICS_AND_SCORING.md — Validação de Risk Acceptance](METRICS_AND_SCORING.md#validação-de-risk-acceptance)

---

## Achado

**Definição:** uma ocorrência única de vulnerabilidade no ambiente monitorado.

**No EyeMole:** corresponde à combinação única de agente × pacote × CVE. O mesmo CVE em 3 agentes distintos gera 3 achados independentes. É a unidade de contagem principal para cards, filtros e denominador do Risk Score do Dashboard.

**Não confundir com:** CVE única. O total de achados (findings) é sempre ≥ o total de CVEs únicos.

**Referências:** [METRICS_AND_SCORING.md — Deduplicação](METRICS_AND_SCORING.md#deduplicação)

---

## Agente

**Definição:** host monitorado pelo Wazuh, identificado por um `agent_id` único.

**No EyeMole:** cada agente pode ter múltiplas vulnerabilidades associadas. O Analyser consulta o Wazuh Indexer para obter todos os achados por agente. Agentes são listados na aba Ativos & Exposição e podem ser classificados via modal.

**Referências:** [USER_GUIDE.md — Classificação de ativos](USER_GUIDE.md#classificação-de-ativos)

---

## Ambiente

**Definição:** contexto operacional em que um ativo está inserido, indicando seu nível de importância para o negócio.

**No EyeMole:** utilizado no cálculo do Asset Score. Os valores aceitos pela interface (modal) são: `prod`, `hmg`, `dev`, `test`, `unknown`. O dicionário `WEIGHT_ENVIRONMENT` do Analyser reconhece as chaves: `production` (peso 15), `hmg` (peso 3), `development` (peso 2), `lab` (peso 0), `unknown` (peso 3).

**Unidade ou escala:** peso numérico de 0 a 15.

**Não confundir com:** exposição (acessibilidade de rede) ou criticidade (importância do ativo).

**Limitação conhecida:** os valores `prod`, `dev` e `test` oferecidos pela interface não possuem correspondência direta com as chaves do dicionário de pesos e recebem fallback para o peso de `unknown` (3). Apenas `hmg` possui correspondência direta. O valor `test` **não** equivale a `lab`.

**Referências:** [METRICS_AND_SCORING.md — WEIGHT_ENVIRONMENT](METRICS_AND_SCORING.md#weight_environment-ambiente)

---

## API

**Definição:** interface programática que expõe dados processados pelo Analyser para consumo pelo Dashboard e integrações.

**No EyeMole:** a SOAR API escuta em `127.0.0.1:8765` (somente loopback) e é exposta externamente via Nginx em `/soar-api/`. Serve JSONs publicados, aceita classificação de ativos, reporta status operacional e permite execução manual (modo web-run).

**Referências:** [ARCHITECTURE.md — SOAR API](ARCHITECTURE.md#soar-api-soar_apipy)

---

## Asset Score

**Definição:** pontuação que representa o nível de risco inerente de um ativo com base em suas características contextuais.

**No EyeMole:** calculado como a soma de quatro dimensões de peso: `WEIGHT_CRITICALITY + WEIGHT_EXPOSURE + WEIGHT_ENVIRONMENT + WEIGHT_ASSET_TYPE`. Compõe o Risk Score Contextual de cada vulnerabilidade associada ao ativo.

**Unidade ou escala:** pontos (valor teórico máximo: 20 + 20 + 15 + 20 = 75).

**Referências:** [METRICS_AND_SCORING.md — Risk Score Contextual](METRICS_AND_SCORING.md#risk-score-contextual-por-vulnerabilidade)

---

## Ativo

**Definição:** recurso de TI monitorado pelo Wazuh.

**No EyeMole:** sinônimo de agente no contexto de classificação e exposição. Cada ativo pode ser classificado com criticidade, exposição, ambiente, donos e observações via modal ou CLI.

**Não confundir com:** achado (finding). O ativo é o host; o achado é a ocorrência de vulnerabilidade nele.

---

## Ativo crítico

**Definição:** ativo classificado com criticidade `critical`, indicando máxima importância para o negócio.

**No EyeMole:** recebe peso 20 no dicionário `WEIGHT_CRITICALITY`. Achados em ativos críticos com SLA vencido recebem +10 pontos adicionais no Score SLA Operacional. Também contribui com fator ×2.5 no Risk Score do Dashboard.

**Unidade ou escala:** peso 20 (máximo da dimensão criticidade).

**Referências:** [METRICS_AND_SCORING.md — WEIGHT_CRITICALITY](METRICS_AND_SCORING.md#weight_criticality-criticidade-do-ativo)

---

## Ativo exposto

**Definição:** ativo com nível de exposição de rede `internet` ou `dmz`, acessível de fora da rede interna.

**No EyeMole:** contribui com fator ×2 no Risk Score do Dashboard (variável `exposedFindings`). No Risk Score Contextual, ativos com exposição `internet` recebem peso 20 e `dmz` recebe peso 15 no `WEIGHT_EXPOSURE`.

**Referências:** [METRICS_AND_SCORING.md — WEIGHT_EXPOSURE](METRICS_AND_SCORING.md#weight_exposure-exposição-do-ativo--assets_context)

---

## Ativo não classificado

**Definição:** ativo cuja criticidade ainda não foi definida pelo operador (valor `unknown`).

**No EyeMole:** recebe peso intermediário de 5 no `WEIGHT_CRITICALITY`. É contabilizado no card "Sem classificação" do Risk Command Center. Recomenda-se classificar todos os ativos para que os scores reflitam a realidade operacional.

**Unidade ou escala:** peso 5 (intermediário).

**Referências:** [USER_GUIDE.md — Classificação de ativos](USER_GUIDE.md#classificação-de-ativos)

---

## Auditoria

**Definição:** registro formal de ações administrativas realizadas no sistema.

**No EyeMole:** gravada em `audit_actions.jsonl` (formato JSON Lines, append-only). Registra classificações de ativos e execuções manuais de análise com timestamp UTC, usuário autenticado (via `X-Remote-User`), ação realizada, campos alterados e resultado. Visível na aba Status & Auditoria.

**Referências:** [OPERATIONS.md — Contexto de ativos](OPERATIONS.md#contexto-de-ativos)

---

## Backlog

**Definição:** total de achados acionáveis pendentes de remediação.

**No EyeMole:** soma de achados com status SLA `overdue` + `due_soon` + `within_sla`. Exibido no card "Backlog total" da aba Tratamento & SLA e no card `ccv-sla` do Risk Command Center (que conta apenas overdue + due_soon).

**Referências:** [DASHBOARD_REFERENCE.md — Cards de SLA](DASHBOARD_REFERENCE.md#cards-de-sla)

---

## Basic Auth

**Definição:** mecanismo de autenticação HTTP onde credenciais (usuário e senha) são enviadas em cada requisição.

**No EyeMole:** implementado via Nginx utilizando arquivo htpasswd. Protege o acesso ao Dashboard (`/soar/`) e à API (`/soar-api/`). Credenciais são gerenciadas pelo administrador através do script `create-web-user.sh`.

**Referências:** [SECURITY_HARDENING.md](SECURITY_HARDENING.md)

---

## CISA KEV

**Definição:** catálogo de Known Exploited Vulnerabilities (Vulnerabilidades Exploradas Conhecidas) mantido pela CISA (Cybersecurity and Infrastructure Security Agency) do governo dos EUA. Lista CVEs com exploração ativa confirmada no ecossistema.

**No EyeMole:** CVEs presentes no catálogo KEV recebem classificação Priority 1+ (máxima) independentemente de CVSS e EPSS. Contribuem com +40 pontos na base técnica do Risk Score Contextual e fator ×4 no Risk Score do Dashboard.

**Não confundir com:** confirmação de comprometimento local. Estar no KEV significa que a CVE está sendo explorada ativamente em algum lugar — não que o ativo local foi comprometido.

**Referências:** [METRICS_AND_SCORING.md — Priority Classification](METRICS_AND_SCORING.md#priority-classification)

---

## Correção disponível

**Definição:** indicador de que um patch ou atualização está disponível para corrigir a vulnerabilidade.

**No EyeMole:** sempre exibido como **N/D** (Não Disponível). O índice de vulnerabilidades do Wazuh/OpenSearch (`wazuh-states-vulnerabilities-*`) não fornece informação sobre disponibilidade de correção. O Sinal 4 do Risk Command Center tem valor `null` e é saltado na renderização.

**Não confundir com:** zero (ausência de correções) ou com a versão do pacote instalado (que indica a versão atual, não a existência de atualização).

**Referências:** [METRICS_AND_SCORING.md — Correção Disponível](METRICS_AND_SCORING.md#correção-disponível)

---

## CVE

**Definição:** Common Vulnerabilities and Exposures — identificador único padronizado para vulnerabilidades de segurança (ex: CVE-2024-00001).

**No EyeMole:** campo principal de identificação de vulnerabilidades. Utilizado para cruzamento com o catálogo CISA KEV e dados EPSS. Cada achado possui exatamente um CVE associado.

---

## CVE única

**Definição:** contagem de identificadores CVE distintos em um snapshot, sem considerar em quantos agentes ou pacotes cada CVE aparece.

**No EyeMole:** exibida no card "CVEs únicos" (`ccv-total`) do Risk Command Center. Derivada via `new Set()` sobre todos os CVEs dos achados.

**Não confundir com:** total de achados (findings). Um snapshot com 100 achados pode ter apenas 40 CVEs únicos se as mesmas CVEs afetam múltiplos agentes.

---

## CVSS

**Definição:** Common Vulnerability Scoring System — sistema de pontuação que mede a severidade técnica de uma vulnerabilidade.

**No EyeMole:** score de 0 a 10. O threshold padrão é 6.0 (`DEFAULT_CVSS_THRESHOLD`). Utilizado na classificação de prioridade: CVSS ≥ 6.0 classifica como Priority 1 (com EPSS alto) ou Priority 2 (com EPSS baixo). CVSS ausente é tratado como 0.0.

**Unidade ou escala:** 0 a 10 (contínuo).

**Referências:** [METRICS_AND_SCORING.md — Priority Classification](METRICS_AND_SCORING.md#priority-classification)

---

## Deduplicação

**Definição:** processo de eliminação de registros duplicados para garantir contagem precisa.

**No EyeMole:** a chave de deduplicação é `(agent_id, package_name, cve)`. Se a mesma combinação aparece mais de uma vez nos resultados do indexador, apenas a primeira ocorrência é mantida. As demais são descartadas silenciosamente.

**Referências:** [METRICS_AND_SCORING.md — Deduplicação](METRICS_AND_SCORING.md#deduplicação)

---

## EPSS

**Definição:** Exploit Prediction Scoring System — modelo que estima a probabilidade de uma CVE ser explorada nos próximos 30 dias.

**No EyeMole:** score de 0 a 1. O threshold padrão é 0.20 (20%, constante `DEFAULT_EPSS_THRESHOLD`). EPSS ≥ threshold classifica o achado como prioridade elevada (P1 ou P3). EPSS ausente ou inválido é tratado como 0.0 — nunca é classificado como alto.

**Unidade ou escala:** 0 a 1 (probabilidade).

**Não confundir com:** garantia de exploração. EPSS indica probabilidade — não certeza de que o ativo será atacado.

**Referências:** [METRICS_AND_SCORING.md — Priority Classification](METRICS_AND_SCORING.md#priority-classification)

---

## Exposição

**Definição:** nível de acessibilidade de rede de um ativo, indicando o grau de alcance que um atacante externo teria.

**No EyeMole:** valores possíveis: `internet`, `dmz`, `internal`, `unknown`. Compõe o Asset Score via `WEIGHT_EXPOSURE` (internet=20, dmz=15, internal=5, unknown=5) e influencia o cálculo do Risk Score Contextual e a política de SLA.

**Unidade ou escala:** peso de 0 a 20.

**Referências:** [METRICS_AND_SCORING.md — WEIGHT_EXPOSURE](METRICS_AND_SCORING.md#weight_exposure-exposição-do-ativo--assets_context)

---

## Filtro cumulativo

**Definição:** mecanismo de filtragem onde múltiplos critérios são combinados com lógica AND, restringindo progressivamente os resultados.

**No EyeMole:** na aba Vulnerabilidades, selecionar "Critical" + "internet" mostra apenas achados que atendem **ambas** as condições. Todos os 6 filtros globais + busca textual + checkbox ransomware operam com lógica AND.

**Referências:** [DASHBOARD_REFERENCE.md — Barra de Filtros Globais](DASHBOARD_REFERENCE.md#barra-de-filtros-globais)

---

## HMG

**Definição:** abreviação de Homologação — ambiente de staging utilizado para validação antes da produção.

**No EyeMole:** o ambiente `hmg` possui correspondência direta no dicionário `WEIGHT_ENVIRONMENT` com peso 3. É o único valor abreviado da interface que tem match direto com as chaves do Analyser. O prefixo `hmg-soar` é utilizado nos nomes dos serviços systemd.

---

## Indicador

**Definição:** sinal visual no Dashboard que comunica o estado de uma dimensão de risco.

**No EyeMole:** o Risk Command Center exibe 7 sinais de risco independentes (barras de progresso). Cada sinal mede uma dimensão distinta: severidade alta/crítica, KEV, EPSS, correção disponível (N/D), ativos expostos, ativos críticos e risco SLA. Um achado pode contribuir para múltiplos sinais simultaneamente.

**Referências:** [DASHBOARD_REFERENCE.md — Sinais de Risco e Priorização](DASHBOARD_REFERENCE.md#sinais-de-risco-e-priorização)

---

## KEV

**Definição:** forma abreviada de CISA KEV (Known Exploited Vulnerabilities).

**No EyeMole:** ver [CISA KEV](#cisa-kev).

---

## N/D

**Definição:** Não Disponível — indica que um dado não é fornecido pela fonte de dados.

**No EyeMole:** utilizado no campo "Correção Disponível" em todas as abas onde aparece. O índice de vulnerabilidades do Wazuh/OpenSearch não fornece informação sobre disponibilidade de patch.

**Não confundir com:** zero (nenhuma correção existe), ausência (campo vazio) ou falha de consulta. N/D é uma condição permanente — o dado simplesmente não está disponível na fonte.

**Referências:** [METRICS_AND_SCORING.md — Correção Disponível](METRICS_AND_SCORING.md#correção-disponível)

---

## Nginx

**Definição:** servidor web e proxy reverso de alto desempenho.

**No EyeMole:** serve o Dashboard estático em `/soar/` e faz proxy reverso da API local em `/soar-api/` (encaminhando para `127.0.0.1:8765`). Implementa autenticação Basic Auth via htpasswd, HTTPS/TLS e headers de segurança. Encaminha o header `X-Remote-User` à API para identificação do operador.

**Referências:** [ARCHITECTURE.md — Nginx](ARCHITECTURE.md#nginx-proxy-reverso)

---

## OpenSearch

**Definição:** motor de busca e análise distribuído, fork open-source do Elasticsearch.

**No EyeMole:** backend de armazenamento do Wazuh Indexer. O Analyser consulta o índice `wazuh-states-vulnerabilities-*` via scroll API para obter todas as vulnerabilidades detectadas nos agentes monitorados.

**Referências:** [ARCHITECTURE.md — Fontes de Inteligência](ARCHITECTURE.md#fontes-de-inteligência)

---

## Pacote

**Definição:** software instalado em um host onde uma vulnerabilidade foi detectada.

**No EyeMole:** compõe a chave de deduplicação junto com `agent_id` e `cve`. Pacotes considerados sensíveis (`openssl`, `curl`, `sudo`, `openssh`, `kernel`, `docker`, entre outros) recebem +10 pontos na base técnica do Risk Score Contextual. Os 10 pacotes mais recorrentes no escopo filtrado são exibidos na nuvem de tags "Top Pacotes".

**Referências:** [METRICS_AND_SCORING.md — Base Técnica](METRICS_AND_SCORING.md#1-base-técnica)

---

## Panorama de Risco

**Definição:** visualização do tipo diagrama Sankey (alluvial) que mostra fluxos de concentração de risco.

**No EyeMole:** localizado na aba Vulnerabilidades. Apresenta 3 camadas: Severidade → Prioridade → Top 5 Agentes afetados. Utiliza `filteredData` e responde a todos os filtros aplicados.

**Não confundir com:** Risk Command Center (aba Dashboard, dados globais). O Panorama de Risco é filtrável; o Command Center não.

**Referências:** [DASHBOARD_REFERENCE.md — Panorama de Risco & Concentração](DASHBOARD_REFERENCE.md#panorama-de-risco--concentração-sankey)

---

## PolicyKit

**Definição:** framework de autorização do Linux que permite controle granular de privilégios para operações específicas.

**No EyeMole:** utilizado no modo web-run para autorizar exclusivamente o usuário `hmg-soar` a iniciar (`start`) a unidade `hmg-soar-report.service`. Nenhuma outra unidade, verbo ou usuário é autorizado pela regra. Restrito a ambientes de homologação e laboratório.

**Referências:** [OPERATIONS.md — Web-run](OPERATIONS.md#web-run)

---

## Priority 1+

**Definição:** nível máximo de prioridade, atribuído a achados com exploração ativa confirmada.

**No EyeMole:** classificação atribuída quando a CVE está presente no catálogo CISA KEV. Prevalece sobre qualquer combinação de CVSS e EPSS. Mutuamente exclusiva com os demais níveis de prioridade.

**Referências:** [METRICS_AND_SCORING.md — Priority Classification](METRICS_AND_SCORING.md#priority-classification)

---

## Priority 1

**Definição:** nível de prioridade alta, combinando severidade técnica elevada com probabilidade significativa de exploração.

**No EyeMole:** atribuída quando CVSS ≥ 6.0 **E** EPSS ≥ 0.20 (e a CVE não está no KEV).

**Referências:** [METRICS_AND_SCORING.md — Priority Classification](METRICS_AND_SCORING.md#priority-classification)

---

## Priority 2

**Definição:** nível de prioridade moderada-alta, com severidade técnica elevada mas baixa probabilidade de exploração.

**No EyeMole:** atribuída quando CVSS ≥ 6.0 **E** EPSS < 0.20 (e a CVE não está no KEV).

**Referências:** [METRICS_AND_SCORING.md — Priority Classification](METRICS_AND_SCORING.md#priority-classification)

---

## Priority 3

**Definição:** nível de prioridade moderada-baixa, com baixa severidade técnica mas probabilidade significativa de exploração.

**No EyeMole:** atribuída quando CVSS < 6.0 **E** EPSS ≥ 0.20 (e a CVE não está no KEV).

**Referências:** [METRICS_AND_SCORING.md — Priority Classification](METRICS_AND_SCORING.md#priority-classification)

---

## Priority 4

**Definição:** nível de prioridade mais baixo, indicando risco reduzido em ambas as dimensões.

**No EyeMole:** atribuída quando nenhuma das condições anteriores é atendida (CVSS < 6.0 E EPSS < 0.20, sem KEV). Inclui também achados com CVSS ou EPSS ausentes (tratados como 0.0).

**Referências:** [METRICS_AND_SCORING.md — Priority Classification](METRICS_AND_SCORING.md#priority-classification)

---

## Priorização

**Definição:** processo de classificação de vulnerabilidades em níveis de urgência para direcionar o esforço de remediação.

**No EyeMole:** baseada em múltiplos fatores: presença no catálogo CISA KEV, score CVSS, probabilidade EPSS e contexto do ativo (criticidade, exposição, ambiente). Resulta em 5 níveis mutuamente exclusivos: Priority 1+ a Priority 4.

**Referências:** [METRICS_AND_SCORING.md — Priority Classification](METRICS_AND_SCORING.md#priority-classification)

---

## Recarregar Dados

**Definição:** ação no Dashboard que atualiza a interface com os dados já publicados pela última análise.

**No EyeMole:** o botão "Recarregar Dados da API" consulta todos os endpoints da SOAR API em paralelo e re-renderiza a interface. **Não** inicia nova análise de vulnerabilidades, **não** executa shell ou systemctl e **não** gera novo snapshot.

**Não confundir com:** executar nova análise (que requer o serviço `hmg-soar-report.service`).

**Referências:** [DASHBOARD_REFERENCE.md — Botão Recarregar Dados da API](DASHBOARD_REFERENCE.md#botão-recarregar-dados-da-api)

---

## Risk Acceptance

**Definição:** ver [Aceitação de risco](#aceitação-de-risco).

---

## Risk Command Center

**Definição:** painel executivo com visão global consolidada do risco no ambiente.

**No EyeMole:** localizado na aba Dashboard (Visão Geral). Exibe o Risk Score agregado, 8 cards de métricas globais, 7 sinais de risco independentes e Top 10 prioridades acionáveis. Utiliza dados globais (`rawData`) e **não** é afetado pelos filtros da aba Vulnerabilidades.

**Não confundir com:** a aba Vulnerabilidades (que responde a filtros) ou o Panorama de Risco (Sankey, que é filtrável).

**Referências:** [DASHBOARD_REFERENCE.md — Aba 1](DASHBOARD_REFERENCE.md#aba-1--dashboard-visão-geral)

---

## Risk Score Contextual

**Definição:** pontuação calculada por vulnerabilidade que representa a prioridade operacional ponderada pelo contexto do ativo mais afetado.

**No EyeMole:** fórmula: `base_técnica + asset_score + exposure_score + sla_op_score ± ajuste_risk_acceptance`, clampeada no intervalo [0, 100]. Quando uma CVE afeta múltiplos agentes, o sistema seleciona o agente com o maior score final como representante.

**Unidade ou escala:** 0 a 100 (índice ordinal, não probabilidade).

**Não confundir com:** probabilidade de ataque (não é percentual de chance), Risk Score do Dashboard (que é um agregado sobre todos os achados) ou CVSS (que é apenas severidade técnica).

**Referências:** [METRICS_AND_SCORING.md — Risk Score Contextual](METRICS_AND_SCORING.md#risk-score-contextual-por-vulnerabilidade)

---

## Risk Score do Dashboard

**Definição:** pontuação agregada que representa a postura de risco geral do ambiente no snapshot atual.

**No EyeMole:** fórmula: `(crit×3 + high×1.5 + kev×4 + epss×2 + exposed×2 + critAsset×2.5) / findings × 12`, clampeada [0, 100]. O denominador é o total de achados (findings), não CVEs únicos. Faixas textuais: ≥70 "Risco elevado", 40–69 "Risco moderado", <40 "Risco controlado".

**Unidade ou escala:** 0 a 100 (índice adimensional).

**Referências:** [METRICS_AND_SCORING.md — Risk Score do Dashboard](METRICS_AND_SCORING.md#risk-score-do-dashboard-agregado)

---

## Risco acumulado do ativo

**Definição:** soma dos Risk Scores Contextuais individuais de todas as vulnerabilidades de um ativo.

**No EyeMole:** utilizado no ranking de ativos mais arriscados (`top_risky_assets`). Soma o score individual (clampeado em [0,100]) de cada vulnerabilidade do ativo. Este valor **não** é clampeado em 100 — pode exceder esse limite para ativos com muitas vulnerabilidades de alto score.

**Unidade ou escala:** pontos (sem limite superior).

**Referências:** [METRICS_AND_SCORING.md — Score Cumulativo por Ativo](METRICS_AND_SCORING.md#score-cumulativo-por-ativo)

---

## Sankey

**Definição:** ver [Panorama de Risco](#panorama-de-risco).

---

## Severidade

**Definição:** classificação da gravidade técnica de uma vulnerabilidade.

**No EyeMole:** valores possíveis: `critical`, `high`, `medium`, `low`. Normalizada para lowercase internamente. Valores fora desse conjunto são normalizados para `medium` no contexto de cálculo de SLA (sem alterar o campo original do registro).

**Referências:** [METRICS_AND_SCORING.md — Normalização de Severidade](METRICS_AND_SCORING.md#normalização-de-severidade)

---

## Sinais de Risco

**Definição:** conjunto de 7 indicadores independentes exibidos no Risk Command Center, cada um medindo uma dimensão distinta de risco.

**No EyeMole:** os 7 sinais são: (1) Severidade alta/crítica, (2) KEV conhecido, (3) EPSS ≥ limiar, (4) Correção disponível (sempre N/D), (5) Ativos expostos, (6) Ativos críticos, (7) Risco SLA. Cada sinal é independente — um achado pode contribuir para múltiplos sinais simultaneamente.

**Não confundir com:** filtros (sinais são informativos, não restritivos).

**Referências:** [METRICS_AND_SCORING.md — Sinais de Risco do Dashboard](METRICS_AND_SCORING.md#sinais-de-risco-do-dashboard)

---

## SLA

**Definição:** Service Level Agreement — prazo máximo para tratativa de uma vulnerabilidade, definido conforme severidade e contexto do ativo.

**No EyeMole:** calculado como o **mínimo** entre todos os prazos aplicáveis (padrão, KEV, internet-facing, DMZ, ativo crítico, ativo high, serviço sensível). Exemplos: critical padrão = 15 dias; critical + KEV = 7 dias. Status: `overdue` (vencido), `due_soon` (≤ 5 dias) ou `within_sla` (dentro do prazo).

**Unidade ou escala:** dias corridos.

**Referências:** [METRICS_AND_SCORING.md — Política de SLA](METRICS_AND_SCORING.md#política-de-sla)

---

## Snapshot

**Definição:** captura pontual (point-in-time) de todas as vulnerabilidades do ambiente em um determinado momento.

**No EyeMole:** gerado a cada ~6 horas pelo timer `hmg-soar-report.timer`. O Analyser consulta o Wazuh Indexer, processa os dados e publica HTML + JSONs em `/var/www/wazuh-soar/`. O timestamp de geração é exibido no header do Dashboard.

**Referências:** [OPERATIONS.md — Agendamento](OPERATIONS.md#agendamento)

---

## SOAR

**Definição:** Security Orchestration, Automation and Response — categoria de ferramentas que combinam orquestração, automação e resposta de segurança.

**No EyeMole:** o foco é em priorização e visualização de vulnerabilidades, não em remediação automatizada. O Analyser sempre executa em `--mode audit`, garantindo que nenhuma ação corretiva seja disparada automaticamente. O EyeMole prioriza — a correção é responsabilidade do time operacional.

---

## Systemd

**Definição:** gerenciador de serviços e sistema init do Linux.

**No EyeMole:** gerencia 3 unidades: `hmg-soar-api.service` (API, tipo simple, contínuo), `hmg-soar-report.service` (Analyser, tipo oneshot, executa e termina) e `hmg-soar-report.timer` (agendamento a cada 6 horas).

**Referências:** [OPERATIONS.md — Serviços](OPERATIONS.md#serviços)

---

## Timer

**Definição:** unidade systemd que dispara a execução de um serviço em intervalos programados.

**No EyeMole:** `hmg-soar-report.timer` executa a cada 6 horas (`OnCalendar=*-*-* 00/6:00:00`) com até 5 minutos de atraso aleatório (`RandomizedDelaySec=300`). `Persistent=true` garante que, se o servidor estava desligado no horário agendado, a execução ocorre ao ligar.

**Referências:** [OPERATIONS.md — Agendamento](OPERATIONS.md#agendamento)

---

## Top Pacotes

**Definição:** visualização em nuvem de tags dos pacotes mais recorrentes no escopo filtrado.

**No EyeMole:** exibe os 10 pacotes com maior contagem de achados no `filteredData` atual. Localizado no rodapé do painel Sankey (aba Vulnerabilidades). Responde a todos os filtros aplicados. Estado vazio: "Nenhum pacote identificado".

**Referências:** [DASHBOARD_REFERENCE.md — Top Pacotes por Recorrência](DASHBOARD_REFERENCE.md#top-pacotes-por-recorrência-nuvem-de-tags)

---

## Tratamento

**Definição:** processo completo de remediação de uma vulnerabilidade, da detecção até a verificação de correção.

**No EyeMole:** o ciclo de tratamento compreende: detecção (Wazuh) → priorização (Analyser) → atribuição (operador/gestor) → correção (time operacional) → verificação (próximo snapshot confirma remoção do achado). A aba Tratamento & SLA acompanha o backlog e os prazos.

**Referências:** [USER_GUIDE.md — Tratamento e SLA](USER_GUIDE.md#tratamento-e-sla)

---

## Vulnerabilidade

**Definição:** fraqueza de segurança identificada em um software, que pode ser explorada por um atacante para comprometer confidencialidade, integridade ou disponibilidade.

**No EyeMole:** identificada por um CVE. Detectada pelo Wazuh nos agentes monitorados e registrada no Wazuh Indexer. O EyeMole não detecta vulnerabilidades — prioriza as já coletadas.

---

## Wazuh

**Definição:** plataforma open-source de segurança que fornece detecção de ameaças, monitoramento de integridade, resposta a incidentes e avaliação de vulnerabilidades.

**No EyeMole:** é a fonte primária de dados de vulnerabilidades. O Analyser consulta o Wazuh Indexer (OpenSearch) para obter os achados brutos. O EyeMole complementa o Wazuh com uma camada de priorização contextual — não o substitui.

**Referências:** [ARCHITECTURE.md — Visão Geral](ARCHITECTURE.md#visão-geral)

---

## Wazuh Indexer

**Definição:** componente de armazenamento do Wazuh baseado em OpenSearch, responsável por indexar e permitir consultas sobre dados de segurança.

**No EyeMole:** o Analyser consulta o índice `wazuh-states-vulnerabilities-*` via scroll API. As credenciais de acesso ficam em `/etc/hmg-soar/credentials.env`, lidas exclusivamente pelo Report Service via `EnvironmentFile`.

**Referências:** [ARCHITECTURE.md — Fontes de Inteligência](ARCHITECTURE.md#fontes-de-inteligência)

---

## Web-run

**Definição:** modo de operação opt-in que habilita a execução manual de análise via interface web do Dashboard.

**No EyeMole:** ativado com `install.sh --enable-web-run`. Instala uma regra PolicyKit restrita que autoriza apenas o usuário `hmg-soar` a iniciar `hmg-soar-report.service`. Recomendado apenas para ambientes controlados (homologação, laboratório). Em produção, o modo seguro (padrão) mantém o botão oculto e desabilitado.

**Referências:** [OPERATIONS.md — Web-run](OPERATIONS.md#web-run)
