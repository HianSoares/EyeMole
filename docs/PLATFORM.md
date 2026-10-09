# Plataforma operacional do EyeMole

A área **Operações**, em `/soar/assets/operations.html`, organiza o tratamento de vulnerabilidades por campanha. Os módulos em `operations/` usam a mesma identidade de instância e o motor de remediação existente. O dashboard e a primeira instalação continuam disponíveis.

## O que está implementado

| Capacidade | Comportamento |
|---|---|
| Campanhas | Grupos candidatos por produto, pacote e arquitetura; até 500 instâncias por campanha; contagem por exposição |
| Tratamento | Responsável, prazo, janela de manutenção, justificativa e histórico de alterações |
| Aceitação de risco | Administrador registra motivo e vencimento; expiração fica visível |
| Validação | Exige coleta completa e posterior à aplicação, ativo incluído, agente ativo e inventário posterior com versão corrigida |
| Inventário | Importação via Wazuh ou observação manual identificada pelo usuário; dados desconhecidos permanecem explícitos |
| Explicação por IA | NVIDIA API Catalog (compatível com OpenAI) por padrão: explica a orientação de uma instalação ou os planos da campanha; resposta estruturada validada; comandos vêm do motor determinístico. Kiro mantido como provedor legado |
| Evidências | Material oficial Microsoft CVRF, Red Hat e Ubuntu; fonte, data e hash; aplicabilidade exige revisão |
| GLPI | Abertura de chamado com identificador da campanha e leitura do estado remoto |
| QRadar / Vision One | Consulta de offenses/alertas, paginação limitada e correlação por mapeamento explícito de ativos |
| Acesso | Papéis e escopo por ambiente e ativo; Basic Auth existente ou OIDC via OAuth2 Proxy local |
| Piloto | Active Response Wazuh 4.x em Linux apt/dnf/yum; ações assinadas, versões fixadas, aprovação e janela |
| Operação | Diagnóstico, retenção, snapshots comprimidos e recuperação automática de update com falha |
| Engenharia | Worker separado, SQLite com transações e jobs duráveis, CI Linux e publicação por tags |

## Habilitar após a atualização

A plataforma e todas as integrações são instaladas **desabilitadas**. A instalação existente permanece utilizável até configurar os acessos. O instalador preserva arquivos já existentes.

1. Atualize a instalação pelo fluxo documentado em [UPDATES.md](UPDATES.md), depois do merge.
2. Confira `/etc/hmg-soar/platform.json`. O projeto `hmg` aponta para o snapshot e as configurações existentes. Para outros ambientes, use snapshots e configurações separados; definir um projeto não conecta automaticamente outro Wazuh.
3. Cadastre primeiro o usuário administrador já existente no Basic Auth:

```bash
sudo eyemole access SEU_USUARIO --role admin --project '*' --enable
sudo eyemole access ANALISTA --role analyst --project hmg
sudo eyemole access RESPONSAVEL --role owner --project hmg --agent 001
sudo eyemole access AUDITOR --role auditor --project hmg
sudo eyemole doctor
```

O comando cadastra **autorização**; não cria senha no Nginx nem conta no IdP. Os usuários Basic Auth continuam sendo criados com `create-web-user.sh`. Para revogar um acesso, remova a entrada de `users` com `sudoedit /etc/hmg-soar/platform.json`. Alterações são lidas a cada requisição e antes de cada job.

| Papel | Ler | Tratar | Integrar | Aprovar / aceitar | Executar |
|---|---|---|---|---|---|
| admin | Sim | Sim | Sim | Sim | Sim |
| analyst | Sim | Sim | Sim | Não | Não |
| owner | Sim | Sim | Não | Não | Não |
| auditor | Sim | Não | Não | Não | Não |

`agent_ids` vazio significa todos os ativos dos projetos autorizados. Use uma lista explícita para limitar responsáveis. O dashboard antigo contém snapshots integrais: quando a plataforma está habilitada, ele e seus endpoints ficam restritos ao administrador global sem filtro de ativos. Os demais usuários acessam Operações. Auditoria integral exige escopo completo do projeto.

O Nginx valida a autenticação e consulta a política também para arquivos estáticos. A API continua em loopback; não a exponha diretamente. Não permita que proxies anteriores substituam a identidade de usuários por cabeçalhos não verificados.

## Fluxo de uma campanha

1. Abra **Ações sugeridas**, escolha o grupo e crie uma campanha. Para grupos grandes, selecione o início do lote: 1, 501, 1001 etc. A separação em lotes não decide automaticamente a aplicabilidade.
2. Passe para **Em análise**, gere planos e consulte evidências, contexto ausente e pré-requisitos.
3. Informe responsável e janela de manutenção e passe para **Planejada**. O prazo é separado da janela.
4. Execute o procedimento revisado pela sua ferramenta de manutenção ou habilite o piloto descrito abaixo.
5. Registre **Aplicação registrada** com a evidência da mudança. A ausência de uma CVE não basta para registrar sucesso.
6. Sincronize inventário e gere uma nova coleta completa após a aplicação. Clique em **Validar correção**.

A confirmação exige que a exposição desapareça da coleta, que o ativo tenha sido coletado e permaneça ativo e que as versões dos planos estejam corrigidas no inventário posterior. Coleta parcial, agente desconectado, inventário antigo, comparação de versão indeterminada ou instalação ambígua mantêm a campanha aguardando validação.

A contagem agregada é por agente + CVE + pacote. Cada instalação continua com seu `finding_id` próprio. O relógio de SLA não reinicia por mudança de severidade ou instalação adicional.

O snapshot tem limite de 128 MiB e 500 mil linhas. A idade máxima padrão é 24 horas, configurável por projeto. EPSS ausente é desconhecido, distinto de zero. Campos de arquitetura, versão corrigida e fontes ficam explícitos na qualidade da coleta.

## Jobs e auditoria

A API registra pedidos; `eyemole-platform-worker.service` os executa com um usuário Linux separado (`eyemole-worker`). O código e seus diretórios são administrados por root; configuração operacional, cache, saída, SBOMs e auditoria continuam graváveis pelo serviço. Banco e fila ficam em `/var/lib/eyemole/platform/operations.sqlite3`. Transações impedem perda silenciosa por alterações concorrentes. Jobs são revalidados contra papel, escopo e versão da campanha antes de executar.

Somente um worker é admitido por lock. Jobs interrompidos não são repetidos automaticamente. Chamados e execução de correção com resposta incerta precisam ser reconciliados no destino antes de outra tentativa. O desinstalador para e remove o worker; conserva a base operacional, inclusive no modo purge, para reconciliação administrativa. No modo preserve, também copia a base para o diretório privado de preservação. Jobs de leitura podem ser solicitados novamente explicitamente. Em caso de chamado criado sem confirmação local, procure o marcador `[EyeMole:projeto:id-da-campanha]` no GLPI; não abra outro sem conferir.

A auditoria registra ator, ação e alterações com encadeamento de hashes. Isso detecta alterações nos registros existentes; não é uma assinatura externa nem protege contra um administrador que reescreva toda a base. Exporte a base e a auditoria para retenção organizacional se precisar dessa garantia.

## Credenciais e múltiplos ambientes

Use `sudoedit /etc/hmg-soar/integrations.env` (root:root 0600). Esse arquivo é entregue **somente ao worker** pelo systemd. A API não recebe esses segredos no ambiente. Exemplos sem credenciais reais estão em `config/`.

Para credenciais distintas por ambiente, defina `secret_prefix`, por exemplo `HMG_`, no projeto e use `HMG_GLPI_APP_TOKEN`, `HMG_GLPI_USER_TOKEN`, `HMG_NVIDIA_API_KEY`, `HMG_KIRO_API_KEY`, `HMG_EYEMOLE_WAZUH_USER` etc. Quando o prefixo existe, não há fallback para credenciais sem prefixo. Reinicie o worker após editar o arquivo de ambiente:

```bash
sudo systemctl restart eyemole-platform-worker.service
sudo journalctl -u eyemole-platform-worker.service -n 30 --no-pager
```

Conectores exigem HTTPS validado. Para certificados internos, configure `ca` com o caminho de uma cadeia confiável legível pelo worker. Redirecionamentos são recusados, tokens não seguem paginação para outro domínio, e há limites de chamadas, tamanho de respostas e duração. QRadar/Vision One incompletos são registrados como incompletos, sem inferir ausência de incidentes.

GLPI usa a API V1 (`/apirest.php`). Configure `GLPI_APP_TOKEN` e `GLPI_USER_TOKEN`. O estado remoto é informativo: resolver um chamado não confirma a correção e confirmar uma campanha não fecha automaticamente o chamado.

QRadar usa `QRADAR_TOKEN` e uma versão da API compatível com seu servidor. Vision One usa `VISION_ONE_TOKEN` e a URL regional correta. Em `asset_map`, associe observáveis conhecidos ao ID Wazuh: use dados do seu ambiente apenas na configuração local. A correspondência exata de IP/nome identifica o ativo; não comprova exploração de uma CVE.

Wazuh usa `EYEMOLE_WAZUH_USER` e `EYEMOLE_WAZUH_PASSWORD`, com permissões mínimas para leitura de inventário. O instante de consulta não substitui a data do scan Syscollector. Instalações com versões conflitantes são marcadas como ambíguas.

## Explicação por IA

O provedor padrão é a NVIDIA API Catalog, via adaptador HTTP compatível com OpenAI executado pelo worker. Não é necessário instalar Kiro, fazer login ou fornecer `KIRO_API_KEY`. Habilitação, chave `NVIDIA_API_KEY`, validação (`sudo eyemole ai check`), troca de modelo, dados enviados, limites e estados exibidos estão em [AI_PROVIDER.md](AI_PROVIDER.md).

A IA explica a orientação da instalação aberta em **Ver correção** e os planos da campanha (**Explicar com IA**). O resultado fica associado à instância, à revisão do plano/evidências e ao provedor/modelo; é rejeitado se os dados mudarem durante a geração. A IA não executa, aprova, aceita risco nem confirma correções.

### Kiro Organization (legado)

Instalações com `integrations.kiro` habilitado e sem bloco `integrations.ai` continuam usando o Kiro. Instale uma versão do Kiro CLI compatível com `chat --v3 --no-interactive --agent`, em um caminho absoluto controlado por root e sem escrita por grupo/outros. Configure esse caminho em `integrations.kiro.binary`, habilite a integração e forneça `KIRO_API_KEY` emitida e permitida pela sua organização. A sessão do Kiro no Windows não é transferida ao servidor; esta integração usa autenticação própria do worker.

Referência do provedor: [Kiro headless](https://kiro.dev/docs/cli/headless/) e [autenticação](https://kiro.dev/docs/cli/authentication/).

Cada execução usa HOME privado, perfil temporário com `tools: []`, permissões negadas, sem MCPs, hooks ou recursos locais e limite de tempo/tamanho. O prompt inclui CVE, pacote, versões, contexto ausente e referências de evidências; não inclui nomes de hosts, IPs, senhas nem o ambiente completo do worker. Banners de terminal são separados dos dados; exatamente uma resposta JSON deve passar pelo contrato e pelos IDs permitidos. O resultado aceito é explicativo, ligado a IDs existentes. Campos de execução ou IDs inventados são rejeitados. Kiro não altera planos, aprova ações nem executa correções.

A implementação não depende de contas gratuitas ou sessões compartilhadas do freellmapi. Custo, retenção e disponibilidade do provedor seguem a política da sua organização. A conexão real precisa ser validada com a credencial organizacional antes de uso operacional.

## Evidências e Windows

Para Microsoft CVRF, configure `evidence_month`, por exemplo `2026-Oct`. O mês deve corresponder ao documento oficial que inclui a CVE. Red Hat e Ubuntu são consultados por CVE. O material é armazenado com hash e indicação `needs_review`; baixar um boletim não determina o KB aplicável.

A curadoria Windows continua usando o catálogo de evidências e contexto do motor de remediação. Produto, edição, build/UBR, arquitetura, função e supersedência precisam ser verificados. Dados de roles, hotfixes, reinício e canal de atualização podem ser registrados no inventário manual; a API Wazuh não fornece automaticamente todos esses campos. A execução piloto desta versão suporta Linux. Windows mantém orientação e procedimento manual revisado.

## SSO corporativo opcional

Basic Auth permanece o padrão. Para OIDC, configure um OAuth2 Proxy em `127.0.0.1:4180` com seu IdP, redirect URI HTTPS `/oauth2/callback`, cookies Secure/HttpOnly e `--set-xauthrequest`. Registre exatamente o identificador retornado por `X-Auth-Request-User` na política de usuários. Segredos OIDC pertencem à configuração privada do proxy.

Depois de validar o proxy, altere `authentication.mode` para `oidc` e regenere o snippet Nginx a partir do checkout revisado:

```bash
sudo bash -c 'source /EyeMole/install.sh; install_nginx_snippet; reload_nginx'
```

Faça isso em janela administrativa e preserve uma sessão SSH para recuperação. O modo da configuração e o snippet precisam corresponder. O instalador gera `/oauth2/` e troca Basic Auth pela verificação da sessão corporativa. A API verifica o cookie diretamente no endpoint local `/oauth2/auth`, sem seguir redirects; não confia em um nome de usuário enviado pelo cliente. Uma sessão expirada exige novo login. O IdP/proxy real e a autenticação ponta a ponta precisam ser validados na sua homologação.

## Execução piloto Linux

A execução fica desabilitada por padrão no servidor **e** no agente. Habilitar a integração de inventário não habilita execução. Não configure uma resposta automática a todas as CVEs.

No agente Wazuh **4.x Linux**, instale o receptor `agents/eyemole-remediate.py` como `/var/ossec/active-response/bin/eyemole-remediate`, root:root 0750. Configure `/etc/eyemole/execution.json`, root:root 0600, com `enabled`, `agent_id`, uma `hmac_key` aleatória de pelo menos 32 caracteres, `packages` e `package_managers` explicitamente autorizados. Chaves diferentes por agente; mantenha cópia correspondente em `EYEMOLE_AGENT_KEYS` no worker.

Registre um comando Wazuh com nome `eyemole-remediate`, executable `eyemole-remediate` e `timeout_allowed` `no`. Teste o protocolo de Active Response da sua versão 4.x e o acesso do usuário API ao comando. Esta integração não instala o receptor nem altera configurações do Wazuh automaticamente.

No projeto, habilite `execution.enabled`, enumere `execution.agent_ids` e limite `max_actions` (máximo 20). Gere os planos, confira o **comando exato do piloto**, passe a campanha para planejada e aprove os planos atuais. Mudanças em Grype, contexto, allowlist, templates, evidências ou políticas também invalidam o plano para aprovação/envio. Só então selecione até cinco ativos do piloto, dentro da janela.

O servidor valida todos os alvos antes do primeiro envio; só aceita planos de alta confiança para pacote único e apt/dnf/yum. Dependências agrupadas e ações conflitantes exigem tratamento manual. O receptor valida assinatura, validade de cinco minutos, ID de agente, pacote permitido, gerenciador e versão instalada exata. Usa argv sem shell e bloqueia replay pelo ID da ação. Não habilita repositórios nem usa `--allow-downgrades`/`--oldpackage`.

O ACK Wazuh confirma envio, não sucesso do gerenciador. Recibos são guardados em `/platform/executions`; logs e estados locais ficam em `/var/lib/eyemole-executor` no agente. Falha ou interrupção exige conferir o alvo. Registre a aplicação, importe o inventário posterior e valide a campanha; nenhuma resposta da IA confirma a correção.

## Validação antes de homologação

A suíte local cobre o motor existente, instalação/desinstalação Linux, fluxo operacional, acesso, transporte, inventário, execução assinada e recuperação em diretórios isolados. Não é uma execução de integração real com credenciais nem uma atualização no servidor Wazuh.

Antes de habilitar integrações, valide os endpoints e versões dos seus produtos, o RBAC, o SSO (se usado), o provedor de IA (`sudo eyemole ai check`) e um piloto em ativo descartável. A verificação visual em navegador não foi concluída nesta sessão por falha da ferramenta de navegação; confira desktop e mobile em homologação.

Consulte também [UPDATES.md](UPDATES.md) e [REMEDIATION_GUIDANCE.md](REMEDIATION_GUIDANCE.md).
