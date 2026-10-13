# Pesquisa e proposta de remediação ("Pesquisar correção")

Ao abrir uma instalação em **Ver correção**, o analista pode pedir a pesquisa de
correção. A ausência de `fixed_version` no Wazuh **inicia** a pesquisa, em vez de
encerrar o fluxo.

| Etapa | Quem faz | O que faz |
|---|---|---|
| Coleta | Backend (worker) | Consulta fontes oficiais e resolve o contexto do pacote. |
| Proposta | IA (opcional) | Analisa as evidências e propõe alternativas, num contrato próprio. |
| Validação | Motor determinístico | Verifica a aplicabilidade com as regras Debian, classifica e gera os comandos por template. |

A explicação por IA existente continua igual, com contrato separado (ver
[AI_PROVIDER.md](AI_PROVIDER.md)). Pesquisar e propor **não executa mudanças** no
ativo; a execução continua dependendo do fluxo de aprovação da campanha.

## Classificação

| Categoria | Quando |
|---|---|
| Correção validada para a instalação | A distribuição publicou a versão corrigida para a release do ativo. O pacote fonte da instalação foi verificado. A Candidate observada é igual ou posterior à correção **e vem só de suítes autorizadas da release** (ver abaixo). Diagnóstico válido (não expirado, sem conflito). Evidências não conflitantes, nem antigas, nem expiradas. O comando vem de template. |
| Proposta que exige verificação ou revisão | Existe correção da distribuição, mas falta confirmar algo: Candidate não observada ou anterior à correção, associação binário→fonte não verificada, evidências divergentes ou antigas, ou a fonte diz que a release não é afetada. |
| Mitigação temporária | Não há correção para a release, mas há mitigação publicada pela fonte oficial. |
| Correção publicada pelo projeto original, sem confirmação para a distribuição | Correção upstream ou em outra release (ex.: sid/forky), sem pacote corrigido para a release do ativo. |
| Dados insuficientes | Release desconhecida, distribuição sem conector ou fontes indisponíveis. |
| Nenhuma correção encontrada nas fontes consultadas | As fontes responderam e nenhuma registra correção. **Não significa que ela não exista.** |

Correção publicada em sid/unstable ou forky **não** é tratada como adequada ao
Debian 13. Atualizar para a Candidate só é "correção validada" quando a Candidate
observada é comparada (regras dpkg: epoch, `~`, revisões) com a versão publicada
pela distribuição para a release.

## Fontes oficiais (coleta no backend)

| Fonte | Endpoint | Observações |
|---|---|---|
| Debian Security Tracker | `https://security-tracker.debian.org/tracker/<CVE>` | Página da CVE (~4 KB), com as tabelas de pacote fonte, release, versão e estado, as versões corrigidas e as notas. O feed JSON completo (~80 MB) **não** é baixado. |
| Ubuntu CVE tracker | `https://ubuntu.com/security/cves/<CVE>.json` | `packages[].statuses[]` por `release_codename` (released/needed/…); versão no campo `description`, mais `pocket`, `upstream` e `mitigation`. |
| Advisory do projeto original | `https://api.github.com/repos/<owner>/<repo>/security-advisories/<GHSA>` | Seguido apenas a partir de links GHSA citados pelas fontes oficiais, validados por padrão estrito; o host é fixo. Usa `vulnerabilities[].patched_versions`. |

Cada evidência registra:
- **origem:** `id`, publicador, URL e data da consulta (indicando se veio do cache e se era cache antigo);
- **conteúdo:** SHA-256 do conteúdo e trecho relevante;
- **escopo:** distribuição, release/pocket, pacote fonte e versão ou versão corrigida a que se aplica.

Novas fontes entram em `operations/research_sources.py` (`SOURCES` por
distribuição).

### Transporte, cache e conteúdo não confiável

- Hosts fixos em allowlist, HTTPS com TLS verificado, sem seguir redirecionamentos,
  sem variáveis de proxy do ambiente, timeout e orçamento total por pesquisa, e
  limite de tamanho por fonte.
- Cache em `/var/lib/eyemole/platform/research-cache`:
  - validade `cache_ttl_hours` (padrão 6 h), com revalidação condicional (`ETag`/`Last-Modified`);
  - após falha, usa cache antigo até `max_stale_hours` (padrão 72 h), sempre marcado como antigo; esse resultado nunca é classificado como validado;
  - falhas recentes ficam em cache negativo por 10 min.
- A API só registra o job; a pesquisa roda no worker e não bloqueia a API.
- O conteúdo externo é analisado em campos fixos. Ele não altera instruções nem
  executa ferramentas, e não define destinos: só pode indicar um advisory do
  GitHub, que passa pelo padrão estrito.

## Contexto do pacote

| Dado | Origem (registrada com data) |
|---|---|
| Release (ex.: trixie) | `/etc/os-release` importado, inventário Wazuh (`os.codename`) ou tabela de releases a partir da versão do sistema. |
| Pacote fonte (ex.: vim-tiny → vim) | `dpkg-query` importado (`${source:Package}`) ou inventário Wazuh (`syscollector`, campo `source`). **Nunca deduzido pelo nome.** |
| Candidate e suítes do repositório | `apt-cache policy` importado. As URLs dos repositórios (que podem ser mirrors internos) não são guardadas nos dados analisados; ficam só as suítes (`trixie-security/main`). |
| Origem do pacote | Suítes da versão instalada: distribuição, backports ou só `/var/lib/dpkg/status`. |

Ficam separadas a **versão corrigida upstream**, a **versão corrigida publicada
para a distribuição/release** e a **Candidate observada no ativo**.

### Diagnósticos importados

O EyeMole não executa shell nos agentes, e a IA nunca executa nada. Em **Ver
correção** aparecem os diagnósticos somente leitura (marcados como "não executado
pelo EyeMole"):
- `dpkg-query -W -f='${binary:Package} ${Version} ${source:Package} ${source:Version}\n' <pacote>`;
- `apt-cache policy <pacote>`;
- `grep -E '^(ID|VERSION_ID|VERSION_CODENAME)=' /etc/os-release`.

O analista cola a saída e informa a data da coleta. O backend:
- interpreta a saída com parsers estritos (apt em inglês ou português);
- **recusa** dados que não são desta instalação ou estão incompletos:
  - outro pacote, versão instalada ou arquitetura (no `dpkg-query` ou nas linhas de origem do `apt-cache policy`);
  - `Installed: (none)`;
  - campos Installed/Candidate ausentes;
  - versão marcada com `***` diferente de Installed;
  - Candidate fora da tabela de versões;
  - `/etc/os-release` sem `ID` e versão;
- **guarda como conflito**, sem usar para validar e mostrando na interface, um `/etc/os-release` de outra distribuição, release ou versão. Um conflito nunca redefine o contexto do ativo;
- grava o resultado vinculado à instalação, com quem importou, quando e a confiança `imported_by_analyst`. A saída bruta fica só no servidor;
- **expira** o diagnóstico após `diagnostics_max_age_hours` (padrão 72 h, contados de `collected_at`). Diagnósticos expirados ou em conflito são mantidos como histórico (`diagnostic_history` e auditoria `diagnostic.imported`), e a interface pede nova coleta.

### Origem da Candidate

A versão sozinha nunca valida a correção. **Todas** as suítes que oferecem a
Candidate precisam estar autorizadas para a release do ativo:

| Escopo | Suítes autorizadas |
|---|---|
| Release (padrão) | `<release>` + `authorized_pockets` (padrão: `""`, `-security`, `-updates`, ex.: `trixie`, `trixie-security`, `trixie-updates`) |
| Backports (pacote instalado de `<release>-backports` e correção publicada para o backports) | Somente `<release>-backports` |
| Explícitas do administrador | `extra_authorized_suites` (ex.: nome de suíte de um mirror interno) |

O resultado deixa de ser "correção validada" e o comando fixado não é gerado quando a Candidate vem de:
- sid/unstable ou forky/testing;
- outra release ou distribuição (ex.: `noble-security`);
- pocket não autorizado (ex.: `-proposed-updates`);
- backports fora do seu escopo;
- origem desconhecida (sem suíte).

Nesses casos o resultado é "proposta que exige verificação", e a pendência explica a origem. Repositórios configurados como `stable`/`testing`, sem o codinome, também não são autorizados, porque o nome muda com o tempo; use o codinome ou adicione a suíte em `extra_authorized_suites`.

### Validade da classificação

Cada resultado tem `valid_until`, que é o menor entre:
- a última confirmação de cada evidência (`checked_at`) + `evidence_max_age_hours` (padrão 24 h);
- a coleta do diagnóstico usado + `diagnostics_max_age_hours`.

Passado esse instante, a API (sem acessar a rede) mostra a pesquisa como desatualizada, sem classificação atual, proposta, comando ou selo, e os fatos deixam de alimentar a explicação. A atualização é feita pelo worker numa nova pesquisa.

O inventário Wazuh, quando a integração está habilitada, é atualizado (somente
leitura) no início da pesquisa e passa a guardar o pacote fonte de cada binário.

## Proposta da IA

Contrato próprio, separado da explicação:

```json
{"summary": "…", "recommended": 0,
 "alternatives": [{"kind": "update_package|mitigation|wait_for_distribution_fix|manual_build|release_change|remove_package|other_manual",
                   "package": "…", "target_version": "…", "evidence_ids": ["…"], "rationale": "…", "impact": "…",
                   "prerequisites": ["…"], "verification": ["…"], "rollback": "…", "manual_steps": ["…"]}],
 "open_questions": ["…"]}
```

O motor valida e descarta a proposta inteira se encontrar:
- evidência, pacote ou versão alvo ausentes das evidências e do contexto;
- versão, URL ou KB inventados no texto;
- promessa de garantia;
- comandos em `update_package`.

Se a proposta for descartada, o resultado do motor continua disponível.

Para alternativas aceitas:
- **`update_package`:** se a versão alvo for a correção publicada para a release, o comando vem do template do motor:
  - validado: `sudo apt-get install --only-upgrade -- <binário>=<Candidate observada>`, com simulação `-s`, verificação e recuperação;
  - a verificar: o mesmo comando sem fixar versão, com pré-requisito de conferir a Candidate.

  Versão de sid ou upstream não gera comando.
- **Mitigação, compilação manual, troca de release, remoção e outros:** aparecem como "proposta para revisão manual (sem validação)". Os `manual_steps` da IA são mostrados como não validados e não executados.
- **Recomendação:** o motor mantém a alternativa com melhor fundamento: atualização validada, depois atualização a verificar, mitigação, aguardar a distribuição e, por último, procedimentos manuais. Se a IA recomendar outra, a interface informa que o motor ajustou.

A IA recebe:
- **contexto mínimo:** CVE, pacotes, versões, release, arquitetura e suítes;
- **evidências públicas.**

Não recebe hostname, ID do agente, IP, URLs de repositório nem a saída bruta. A
chave NVIDIA continua só no worker.

## Fatos do motor e explicação

Quando há pesquisa atual, os fatos do motor usados pela explicação passam a incluir:
- a correção da distribuição, as versões upstream, o estado da release e a Candidate observada;
- a indicação de que houve diagnóstico coletado.

A validação de consistência compara a resposta com esse conjunto atualizado, sem
congelar o desconhecimento do snapshot. Diagnósticos apenas **permitem consultar**:
sem coleta importada, a prosa não pode dizer que eles confirmam ou mostram algo.
O contrato de fatos passou para a versão 3 e a identidade da explicação inclui a
revisão da pesquisa. Explicações antigas aparecem invalidadas, com registros e
auditoria preservados.

## Identidade e invalidação

- A pesquisa fica vinculada à instalação (agente + `finding_id`) e ao projeto.
- Ela fica **desatualizada** quando mudam:
  - o contexto (orientação/snapshot, inventário, diagnóstico importado);
  - o provedor ou modelo de IA;
  - o contrato da pesquisa;
  - o conteúdo das fontes em cache.

  Nesse caso a interface mostra os motivos e não exibe proposta nem comandos.
- O escopo de agentes do usuário vale para pesquisa, importação e jobs.
- Cada pesquisa gera evento de auditoria (`research.completed`, `diagnostic.imported`).

## Configuração

```bash
sudo eyemole update
sudo eyemole research configure --project hmg --enable
sudo eyemole research status --project hmg
sudo systemctl restart eyemole-platform-worker.service
sudo eyemole research check --project hmg --cve CVE-2026-73076 --distribution debian
```

O `check` executa como `eyemole-worker` (mesmo sandbox do worker, com escrita só em
`/var/lib/eyemole/platform`) e mostra quais fontes responderam. Requer saída HTTPS do
servidor para `security-tracker.debian.org`, `ubuntu.com` e `api.github.com`
(porta 443, sem proxy). A API do GitHub sem autenticação tem limite de 60
requisições/hora por IP; o cache reduz o consumo.

Bloco em `/etc/hmg-soar/platform.json`:

```json
"research": {"enabled": true, "sources": ["debian_security_tracker", "ubuntu_cve_tracker", "upstream_advisory"],
             "cache_ttl_hours": 6, "max_stale_hours": 72, "timeout_seconds": 20, "budget_seconds": 90,
             "refresh_inventory": true, "evidence_max_age_hours": 24, "diagnostics_max_age_hours": 72,
             "authorized_pockets": ["", "-security", "-updates"], "extra_authorized_suites": []}
```

O contrato da pesquisa está na versão 2: resultados classificados pelas regras
anteriores aparecem como desatualizados (registro e auditoria preservados) até nova
pesquisa. O contrato de fatos da explicação passou para a versão 4.

A proposta por IA usa o provedor de `integrations.ai` (NVIDIA). Sem IA, a pesquisa
entrega o resultado do motor e das fontes.

## Roteiro de homologação

1. `sudo eyemole research check --project hmg --cve CVE-2026-73076 --distribution debian`. Esperado: `ok: true`, com o tracker Debian e o advisory do projeto disponíveis.
2. **Ver correção** → vim-tiny (Debian 13, 2:9.1.1230-2, CVE-2026-73076) → **Pesquisar correção**. Pelos dados públicos de 13/10/2026, o esperado é "Correção publicada pelo projeto original, sem confirmação para a distribuição":
   - upstream 9.2.0847;
   - trixie listado como vulnerável;
   - sid/forky com correção, que não vale para trixie;
   - pacote fonte "não verificado".
3. Execute no ativo os diagnósticos exibidos (`dpkg-query`, `apt-cache policy`, `/etc/os-release`) e importe as saídas. Pesquise de novo e confira:
   - pacote fonte `vim` com origem "importado pelo analista";
   - Candidate observada.
4. Repita para vim (CVE-2026-73072). Esperado: upstream 9.2.0846, mesma situação para trixie.
5. Se o Debian publicar a correção para trixie, confira que a pesquisa passa a "proposta que exige verificação" e, depois do `apt-get update` e de uma nova importação da Candidate, a "correção validada", com o comando por template.
6. Confira que a explicação por IA da mesma instalação usa os novos fatos (versões upstream permitidas, sem "os diagnósticos confirmam").

## Limitações

- Conectores apenas para Debian e Ubuntu (e advisories do GitHub a partir dessas fontes). Outros sistemas: "Dados insuficientes", até um conector ser adicionado.
- A leitura do Debian depende do HTML da página por CVE (formato estável, mas não é API); mudança de formato resulta em fonte indisponível (`unexpected_format`), nunca em "sem correção".
- A Candidate só é conhecida por diagnóstico importado; o EyeMole não executa nada no ativo.
- A pesquisa real nas fontes e a proposta real da NVIDIA dependem da homologação no servidor; os testes usam respostas gravadas e sintéticas.
