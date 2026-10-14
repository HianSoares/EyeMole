# Remediação automática ("Ver correção")

Ao abrir **Ver correção** numa vulnerabilidade, o EyeMole inicia ou reutiliza a
análise daquela instalação. Não há botões "Pesquisar correção" nem "Explicar com
IA" no modal. A análise roda no worker e a interface mostra o progresso; o
resultado aparece sem novos cliques.

A primeira informação do modal é a **Correção recomendada**:
- ação e versão/KB alvo;
- comando com botão **Copiar**;
- terminal correto, privilégio e reinício;
- motivo e fontes.

Abaixo ficam:
- os detalhes: pré-requisitos, simulação, verificação, recuperação, requisitos de exploração, pendências, outras alternativas e fontes;
- a orientação do motor;
- a importação manual de diagnósticos, como alternativa.

Pesquisar não executa nada no ativo: o usuário copia e executa. A execução pela
plataforma continua no fluxo de aprovação da campanha.

## Fluxo

1. `POST /platform/findings/<id>/analysis` (abertura do modal) é idempotente.
   - Devolve a análise válida ou o job em andamento.
   - Só enfileira um novo job quando não há resultado atual. O job é identificado pelo contexto da instalação e pelo provedor/modelo, o que evita duplicação e chamadas externas repetidas.
   - Falha recente não é refeita automaticamente (`retry_after_failure_minutes`, padrão 10).
   - Papéis só de leitura veem o resultado, mas não iniciam a análise.
2. O worker executa, registrando o progresso (`inventory`, `sources`, `analysis`, `collection`, `ai`, `validation`):
   1. atualiza o inventário do Wazuh (somente leitura): sistema, build, arquitetura, pacotes com pacote fonte e hotfixes;
   2. consulta as fontes oficiais, com cache;
   3. avalia a aplicabilidade;
   4. pede coleta ao agente se faltar dado indispensável;
   5. obtém a proposta da IA;
   6. valida tudo no motor.
3. Quando o agente envia a coleta, o contexto muda. A análise fica desatualizada e a interface a reinicia automaticamente.
4. A análise deixa de ser atual quando mudam:
   - contexto ou inventário;
   - diagnóstico (revalidado a cada uso);
   - evidências, incluindo a expiração;
   - modelo;
   - contrato da pesquisa (v3).

## Sistemas suportados

| Sistema | Fonte oficial | Comando |
|---|---|---|
| Debian (bookworm, trixie, …) e Ubuntu (focal…questing), pacotes `apt` | Debian Security Tracker / Ubuntu CVE tracker, advisories do projeto (GitHub) | `sudo apt-get install --only-upgrade -- <pacote>=<Candidate>` (bash, root via sudo) |
| Windows (sistema operacional, atualizações publicadas pela MSRC) | Microsoft Security Update Guide API v2 (`api.msrc.microsoft.com/sug/v2.0/.../affectedProduct`) | PowerShell (Administrador) via Windows Update Agent API, instalando a KB somente se o canal do ativo (Windows Update/WSUS) a oferecer |

**Não suportados** (resultado "dados insuficientes" ou "nenhuma correção", sem
comando genérico):
- RHEL, SUSE e outras distribuições;
- aplicativos Windows de terceiros e produtos Microsoft fora das KBs de sistema;
- macOS.

## Linux

Mantém as regras dos PRs anteriores:
- pacote fonte verificado;
- versão corrigida da distribuição para a release (backports só no próprio escopo);
- Candidate observada vinda **somente** de suítes autorizadas da release;
- comparação dpkg;
- evidências e diagnóstico válidos.

Ficam separadas a versão upstream, a versão da distribuição e a Candidate do
ativo. Sem atualização da distribuição, a recomendação é a mitigação oficial
(se houver) ou aguardar a publicação, com o motivo e as fontes.

## Windows

- **Produto:** casado pelo ramo de build (`10.0.<build>`), servidor ou cliente, arquitetura e Server Core quando conhecido (coleta > inventário > snapshot). Se a Microsoft não lista o produto ou a arquitetura do ativo, nada é recomendado e as notas indicam a incompatibilidade.
- **KB:** a "Security Update" do produto, com build corrigida e reinício (`rebootRequired`).
  - Já instalada (hotfix) ou build igual/posterior: sem comando de instalação; a pendência indica que o achado pode estar desatualizado.
  - KB substituída instalada: informada; a correção está na atualização mais recente.
- **Selo "Validado":** exige build e arquitetura do inventário ou coleta (não só do snapshot), lista de hotfixes completa, KB oferecida pelo canal do ativo (coletado), evidências não expiradas e ausência de conflito.
- **Sem o selo:** o comando ainda é entregue, porque verifica a oferta antes de instalar. KB não oferecida aparece como pendência (aprovar no WSUS), com o pacote do Microsoft Update Catalog como alternativa manual sem selo.
- **Comando:** gerado por template com a KB validada (`KB\d{6,8}`, literal PowerShell com aspas simples escapadas). O modal indica PowerShell como Administrador e o reinício. Simulação (busca sem instalar), verificação (`Get-HotFix`, UBR) e recuperação (`wusa /uninstall`, com a ressalva de SSU+LCU) são incluídas.

## Requisitos de exploração

Vêm do catálogo oficial curado (`remediation/data/vendor_evidence.json`, campo
`requirements` com verificação fixa, ex.: papel WSUS `UpdateServices`) e da IA,
quando ela cita evidência (sempre "não verificado").

| Estado | Efeito |
|---|---|
| Presente | A exposição descrita se aplica. |
| Ausente | Exposição reduzida segundo a fonte. **Não** significa pacote atualizado nem encerra o achado; a correção continua recomendada. |
| Desconhecido | Pendência; quando há verificação fixa, a coleta é pedida ao agente. |

## Coleta automática pelo agente (somente leitura)

**Ações fixas** (parâmetros validados no servidor e no agente):

| Sistema | Ações |
|---|---|
| Linux | `os_release`, `dpkg_source <pacote>`, `apt_policy <pacote>` |
| Windows | `windows_build`, `windows_hotfixes`, `wu_search <KB>` (busca no Windows Update Agent, sem instalar), `windows_feature <nome>` |

**Pedido:** HMAC-SHA256 sobre o texto exato do payload, vinculado ao agente,
válido por `expiry_minutes` (padrão 10) e de uso único. É enviado pelo Wazuh
Active Response (`!eyemole-collect` ou `!eyemole-collect-win`). Pedidos
repetidos para a mesma instalação e as mesmas ações são reaproveitados.

**Retorno:** `POST /soar-api/agent-context/<agent_id>`, com o mesmo token do
agente usado no upload de SBOM e para o URL configurado no próprio agente. O
servidor confere:
- projeto, agente, pedido pendente, prazo e ações solicitadas;
- as saídas, com os parsers estritos;
- identidade e coerência: outro build, versão ou arquitetura é recusado.

O resultado vira um diagnóstico de origem "coletado pelo agente", revalidado a
cada uso como os importados.

**Indisponível** (desabilitada, sem Wazuh, sem chave, falha de envio ou agente
sem resposta): o modal mostra o dado ausente exato e o diagnóstico somente
leitura que o obtém, para executar e importar manualmente.

### Instalação no agente (manual)

**Linux:**
1. Copie `agents/eyemole-collect.py` para `/var/ossec/active-response/bin/eyemole-collect`, com `root:root 0750`.
2. Crie `/etc/eyemole/collector.json` (`root:root 0600`):
   ```json
   {"enabled": true, "agent_id": "007", "hmac_key": "<>=32 caracteres aleatórios>",
    "upload_url": "https://<servidor>/soar-api/agent-context/007", "token_file": "/etc/eyemole-agent/token",
    "ca_file": "/etc/eyemole-agent/ca.pem"}
   ```

**Windows:**
1. Copie `agents/eyemole-collect.cmd` e `agents/eyemole-collect.ps1` para `C:\Program Files (x86)\ossec-agent\active-response\bin\`.
2. Crie `%ProgramData%\EyeMole\collector.json` com os mesmos campos (`token_file` apontando para o token do agente). Restrinja a ACL a SYSTEM e Administrators.

**No manager Wazuh**, registre os comandos:
- `eyemole-collect` (executável `eyemole-collect`);
- `eyemole-collect-win` (executável `eyemole-collect.cmd`).

Em ambos, `timeout_allowed` = `no`. Garanta que o usuário da API possa acioná-los.

**No servidor EyeMole:**
1. Em `/etc/hmg-soar/integrations.env`, defina `EYEMOLE_COLLECTOR_KEYS={"007": "<mesma chave>", "012": "<chave>"}`, com chaves diferentes por agente.
2. O token do agente é o mesmo do upload de SBOM, provisionado como em [agent-sbom-setup.md](agent-sbom-setup.md)
   (o envio exige o token habilitado para o agente em `assets_context.json`).
3. Habilite a coleta: `sudo eyemole research configure --project hmg --enable --agent-collection on`.

O instalador já publica o `location /soar-api/agent-context/` no nginx, sem Basic
Auth e com autenticação própria por token.

## Segurança

- **Credenciais:** a IA não tem shell nem ferramentas, e a chave NVIDIA fica só no worker.
- **Dados mínimos:** a proposta recebe CVE, produto/pacote, build/versões, arquitetura, KBs instaladas e as evidências públicas. Hostname, ID do agente, IP e URLs de repositório não são enviados.
- **Comandos:** vêm só de templates. Código da IA aparece como "proposta para revisão manual", sem selo. Versões, KBs ou URLs inventados descartam a proposta.
- **Controles anteriores mantidos:** origem autorizada da Candidate, validade das evidências, revalidação dos diagnósticos contra o contexto atual, identidade por instalação, escopo por projeto e ativo, e auditoria (`research.completed`, `collection.requested/received/rejected`, `diagnostic.collected`).
- **Falhas:** IA ou fonte indisponível mantêm um resultado útil: classificação do motor, mitigação ou impedimento concreto.

## Configuração

```bash
sudo eyemole update
sudo eyemole research configure --project hmg --enable --agent-collection on
sudo systemctl restart eyemole-platform-worker.service
sudo eyemole research check --project hmg --cve CVE-2025-59287 --distribution windows
sudo eyemole research check --project hmg --cve CVE-2026-73076 --distribution debian
```

`research configure --enable` acrescenta a fonte da Microsoft às listas
existentes. A saída HTTPS do servidor precisa alcançar `api.msrc.microsoft.com`,
`security-tracker.debian.org`, `ubuntu.com` e `api.github.com`.

## Roteiro de homologação

1. Rode os `research check` acima. Esperado: `ok: true`.
2. **Windows Server 2019 com CVE-2025-59287:** abra Ver correção.
   - Esperado: progresso; KB5070883 (build 10.0.17763.7922, reinício "possível"); comando PowerShell; pedido de coleta ao agente.
   - Com o receptor instalado: a análise é refeita sozinha com build, hotfixes, oferta da KB e papel WSUS. O selo aparece se a KB for oferecida pelo WSUS/Windows Update.
3. **Execução no Windows:** "Simulação" no PowerShell como Administrador (lista a KB se oferecida). Execute o comando numa janela de manutenção e confira `Get-HotFix -Id KB5070883` e o UBR.
4. **Debian 13 (vim-tiny, CVE-2026-73076):** sem atualização da distribuição, a recomendação é aguardar, com fontes. Com o receptor Linux, o pacote fonte e a Candidate aparecem como "coletado pelo agente".
5. **Desligar a coleta** (`--agent-collection off`): o modal mostra o dado ausente e o diagnóstico manual.
6. **Agente parado:** após `expiry_minutes`, "o agente não respondeu".
7. **IA desabilitada ou com falha:** o resultado do motor continua com comando e fontes.

## O que depende de Windows real ou homologação

- **Execução do PowerShell:** Windows Update Agent, Get-HotFix e Get-WindowsFeature num servidor Windows real, e o protocolo de Active Response do Wazuh em Windows. Nos testes automatizados só a verificação de assinatura e parâmetros roda em PowerShell; as ações de sistema não.
- **Linux real:** o receptor Linux com `dpkg-query`/`apt-cache` reais e o comando de Active Response no manager.
- **Fontes e IA reais:** respostas reais da MSRC/Debian/Ubuntu a partir do servidor e a proposta real da NVIDIA. Os testes usam respostas gravadas (MSRC e Debian em 13–14/10/2026) e sintéticas.
