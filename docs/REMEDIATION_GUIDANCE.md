# Orientação de correção ("Ver correção")

Estado do fluxo após a correção de confiabilidade (branch
`fix/remediation-reliability`). O EyeMole **não executa** comandos:
`execution_allowed` é sempre `false`, e a aplicação continua com o operador e
o processo de mudança.

## Instância e exposição

| Unidade | Identificador | Usada em |
|---|---|---|
| **Instância** | `finding_id` v2 — SHA-256 de CVE, agente, pacote, versão, tipo, arquitetura e caminho | Linhas da tabela de vulnerabilidades e `GET /remediation-guidance/<finding_id>` |
| **Exposição** | `agente\|CVE\|pacote` (campo `key` dos snapshots) | Risk Score, sinais do Command Center, delta, tendência, SLA e score por ativo |

- Versões ou instalações diferentes do mesmo pacote são instâncias distintas,
  cada uma com sua orientação.
- Agregações contam cada exposição uma vez. O snapshot de risco lista as
  instâncias em `instance_count`, `finding_ids` e `installed_versions`.
- IDs legados (`cve|agente|pacote|severidade`) continuam resolvendo quando
  correspondem a uma única instância. Se corresponderem a mais de uma, a API
  responde `409` e não escolhe nenhuma.

Detalhes: [METRICS_AND_SCORING.md — Deduplicação](METRICS_AND_SCORING.md#deduplicação).

## Prazo de SLA

O `first_seen` é calculado por **exposição**. Nova versão ainda vulnerável,
nova instalação do mesmo pacote ou reavaliação de severidade **não** reiniciam
o prazo. Antes desta correção, a chave incluía a severidade e uma reavaliação
reiniciava o relógio.

Detalhes: [METRICS_AND_SCORING.md — Início do relógio de SLA](METRICS_AND_SCORING.md#início-do-relógio-de-sla).

## Contrato da orientação (v2)

Campos v1 mantidos (`command`, `verification_command`, `reason`,
`recommendation`, `warnings`, `assumptions`). Campos adicionados:

- `guidance_kind`: `command` (comando validado), `textual` ou `none`.
  Texto nunca é publicado no campo de comando.
- `guidance_text`, `rationale`, `verification_steps`, `expected_result`,
  `prerequisites`, `missing_context`, `sources`, `reboot_required`.
- `diagnostics`: comandos **somente leitura** (`{label, script, shell}`),
  separados do comando de instalação.
- `snapshot_revision`: revisão exata das fontes lidas (Wazuh, Grype, contexto
  de ativos, allowlist, configurações, templates e evidências).

Garantias de consistência:

- Todas as fontes são lidas uma vez por geração. Se alguma mudar durante a
  geração, a orientação é regenerada (até 3 tentativas). Persistindo a
  instabilidade, a API responde `503`, sem resultado parcial.
- Uma orientação gerada enquanto as fontes mudavam não é armazenada em cache.
- A versão alvo é validada pelas regras do ecossistema (dpkg, rpm, build/UBR
  do Windows no mesmo ramo). Downgrade é bloqueado. Sem comparador confiável
  (ex.: apk), não há pin de versão, apenas orientação textual.
- Windows recebe orientação textual e diagnósticos, nunca comando de
  instalação. KB, URL e nome de arquivo nunca são inventados; evidências do
  fabricante vêm de `remediation/data/vendor_evidence.json`, verificado
  manualmente.

## Confiança TLS

- **Serviços internos** (Indexer/OpenSearch e API Wazuh): validação de
  certificado obrigatória. Se a CA não for confiável pelo sistema, configure `HMG_INTERNAL_CA_BUNDLE` em
  `/etc/hmg-soar/credentials.env` com a CA que assina os certificados internos.
  O arquivo precisa ser legível pelo usuário do serviço, e o certificado precisa
  ter SAN correspondente a `OPENSEARCH_HOST`/`WAZUH_API_HOST`. Falha de confiança
  ou de correspondência do host impede a coleta.
- **Fontes públicas** (CISA KEV, EPSS/FIRST): sempre validam TLS com o
  repositório de CAs padrão.
- `HMG_INTERNAL_TLS_INSECURE=true` é um opt-in explícito de laboratório que
  desliga a validação apenas na sessão interna.
- Coleta paginada incompleta encerra a execução com código 2, sem publicar
  relatórios nem snapshot; o último resultado completo é preservado.

Exemplo: [credentials.env.example](../credentials.env.example).

## Validação pendente antes da implantação

As suítes `tests/test_installation.py` e `tests/test_uninstallation.py`
precisam passar (150/150) em um host **Linux** de homologação antes de qualquer
implantação. No Windows/Git Bash, 20 testes falham por limitações do ambiente,
iguais às do código de referência `42ac9e4`.

Detalhes por teste: [TEST_ENVIRONMENT_NOTES.md](TEST_ENVIRONMENT_NOTES.md).
Checklist: [OPERATIONS.md — Validações antes do deploy](OPERATIONS.md#validações-antes-do-deploy).

## Explicação por IA e comandos específicos

A explicação por IA está implementada na plataforma operacional, com a NVIDIA
como provedor padrão (detalhes em [AI_PROVIDER.md](AI_PROVIDER.md)). Ela explica
a orientação determinística de uma instalação ("Ver correção") ou os planos de
uma campanha, por jobs do worker, com resposta estruturada validada e associada
à instância, à revisão do plano/evidências e ao provedor/modelo. A IA não gera
nem substitui comandos.

Itens ainda pendentes para produzir comandos específicos por ativo (o worker,
a saída estruturada validada e os jobs assíncronos já existem):

1. **Inventário do ativo:** coletar arquitetura, UBR, papéis instalados (ex.:
   WSUS, distinguindo papel ausente de falha de coleta), reinício pendente,
   canal de atualização e atualizações instaladas. Hoje esses dados aparecem
   em `missing_context`.
2. **Provider de evidências oficiais:** consultar fontes específicas por
   ecossistema (ex.: Microsoft Security Update Guide por CVE/produto/KB/build).
   URLs, redirecionamentos, tipos e tamanho de conteúdo controlados pelo
   backend; evidência registrada com data e revisão. Substitui a curadoria
   manual de `vendor_evidence.json`.
3. **Seleção de template pela IA (opcional):** ampliar o contrato para que a IA
   possa indicar, entre IDs de templates aprovados, o procedimento aplicável —
   sem definir confiança, `execution_allowed` nem texto de comando.
4. **Comandos montados pelo backend:** o template local renderiza o comando
   específico (ex.: pacote offline com artefato e assinatura validados) apenas
   quando produto, arquitetura, aplicabilidade e pré-requisitos estiverem
   confirmados. Caso contrário, a resposta permanece textual com
   `missing_context`.
5. **Piloto:** validar com a chave organizacional e o caso CVE-2025-59287
   (Windows Server 2019) antes de ampliar para outros ecossistemas.
