# Explicação por IA (NVIDIA)

A explicação por IA descreve, em linguagem natural, a orientação de correção que
o motor determinístico do EyeMole já produziu. O provedor padrão é a **NVIDIA
API Catalog** (endpoint compatível com OpenAI). A integração não depende do
Kiro: não exige CLI, login nem `KIRO_API_KEY`.

## O que a IA faz e o que não faz

| Faz | Não faz |
|---|---|
| Explica o plano de **uma instalação** ("Ver correção") ou os planos de uma campanha | Gerar, alterar ou substituir comandos — os comandos vêm só do motor |
| Aponta contexto ausente (distribuição, versão corrigida, evidência) | Apresentar comando genérico como correção confirmada |
| Cita apenas os IDs de instância e de evidência fornecidos pelo EyeMole | Executar comandos, aprovar planos/campanhas, aceitar risco |
| Indica provedor, modelo e data da geração | Encerrar vulnerabilidades ou marcar ativos como corrigidos |

A confirmação de uma correção continua exigindo a validação existente da campanha
(coleta completa posterior, inventário e versão corrigida).

## Arquitetura

1. O navegador pede a explicação (`POST /soar-api/platform/findings/<finding_id>/ai`
   ou o botão **Explicar com IA** da campanha). A API só registra um job.
2. O worker `eyemole-platform-worker.service` (usuário `eyemole-worker`) executa o job.
   Somente ele recebe `NVIDIA_API_KEY`, por `EnvironmentFile=/etc/hmg-soar/integrations.env`.
3. O worker gera a orientação determinística da instância, envia **fatos técnicos
   mínimos** ao provedor e valida a resposta.
4. Antes de gravar, o worker confere que snapshot, orientação, planos e evidências
   não mudaram durante a geração. Caso contrário, o job falha como desatualizado e
   nada é gravado como concluído.

O resultado fica associado a: instância (`finding_id`), revisão do snapshot,
revisão das fontes da orientação, provedor e modelo. Outra instalação com a mesma
CVE não reutiliza a explicação; trocar o modelo exige nova geração.

### Dados enviados ao provedor

Somente: `finding_id` (hash opaco), CVE, pacote, tipo de pacote, versão instalada,
versão corrigida, família/versão do sistema, arquitetura, gerenciador, estado do
plano, se existe comando validado (sim/não), confiança, reinício, justificativa,
pré-requisitos, avisos, contexto ausente e identificadores/URLs públicas das
evidências.

**Nunca enviados:** nome do ativo, hostname, ID do agente, IPs (removidos do texto
livre), e-mails, usuários, credenciais, texto dos comandos e diagnósticos, caminhos
de instalação, logs e snapshots.

### Validação da resposta

- Exatamente um objeto JSON `{"summary", "recommendations": [{"finding_id", "evidence_ids", "explanation"}]}`
  (tolera um bloco `<think>` inicial e uma cerca ```` ```json ````).
- Campos extras, IDs de instância ou evidência inexistentes, chamadas de ferramenta,
  respostas truncadas ou acima dos limites são rejeitados.
- Texto com comandos (linhas iniciadas por `sudo`, `apt-get`, `dnf`, `wusa`,
  `Install-*` etc., blocos de código ou `$(...)`) é rejeitado inteiro.

### Transporte

- Endpoint somente da configuração administrativa (`platform.json`), validado contra
  a allowlist do provedor (`https://integrate.api.nvidia.com/v1`). O navegador não
  escolhe provedor, URL nem modelo.
- TLS sempre validado (confiança do sistema ou `ca` administrativa).
- Redirecionamentos recusados: a chave nunca é enviada a outro host.
- Orçamento total de tempo (`timeout_seconds`, padrão 90 s, 15–300), até 3 tentativas
  para timeout, falha de conexão, HTTP 429 e 5xx, respeitando `Retry-After` dentro do
  orçamento. HTTP 401/403, 404 e 400/422 não são repetidos.
- Resposta limitada a 256 KiB; saída do modelo limitada por `max_output_tokens`.
- Erros exibidos e registrados sem chave, prompt nem corpo da resposta remota.

## Limites e condições do endpoint NVIDIA

O uso do NVIDIA API Catalog com chave de avaliação é regido pelos **NVIDIA API
Trial Terms of Service** e pela licença do modelo. Há limites de taxa e de uso
definidos pela NVIDIA para a sua conta, que podem mudar. **Não há garantia de
gratuidade ilimitada nem de disponibilidade para produção.** Para uso contínuo,
avalie o plano adequado com a NVIDIA e a política de dados da sua organização
(o provedor recebe os fatos técnicos listados acima).

Quando a NVIDIA estiver indisponível, sem cota (HTTP 429) ou recusar a chave, a
orientação determinística continua acessível e a interface mostra o estado da
explicação (não gerada, na fila, gerando, concluída, falhou, desatualizada).

## Configuração no servidor

Pré-requisitos: plataforma operacional habilitada (`docs/PLATFORM.md`), usuário com
papel `admin`, `analyst` ou `owner` no projeto e saída HTTPS do servidor para
`integrate.api.nvidia.com:443`.

1. Gere uma chave em <https://build.nvidia.com> com a conta autorizada pela sua
   organização. Não cole a chave em chats, tickets ou no Git.
2. Grave a chave somente no arquivo de segredos do worker:

   ```bash
   sudo sh -c 'umask 077; touch /etc/hmg-soar/integrations.env'
   sudo chown root:root /etc/hmg-soar/integrations.env
   sudo chmod 0600 /etc/hmg-soar/integrations.env
   sudoedit /etc/hmg-soar/integrations.env
   ```

   Adicione (ou preencha) a linha `NVIDIA_API_KEY=...`. Com `secret_prefix`
   no projeto (ex.: `HMG_`), use `HMG_NVIDIA_API_KEY` — não há fallback para o nome
   sem prefixo.
3. Habilite o provedor no projeto (o comando não grava segredos):

   ```bash
   sudo eyemole ai configure --project hmg --enable
   sudo eyemole ai status --project hmg
   ```

4. Reinicie o worker para carregar o arquivo de segredos e valide a conexão com
   dados sintéticos. O `check` executa via `systemd-run` como `eyemole-worker`,
   com os mesmos grupos (`eyemole-ops`, `www-data`), `EnvironmentFile` e
   restrições de sandbox do worker; o arquivo de segredos continua ilegível para
   o próprio usuário `eyemole-worker` (quem o lê é o systemd):

   ```bash
   sudo systemctl restart eyemole-platform-worker.service
   sudo eyemole ai check --project hmg
   ```

   Saída esperada: `{"ok": true, "provider": "nvidia", "model": "nvidia/nemotron-3-super-120b-a12b", "contract": "valid", ...}`.
   Em falha, o campo `code` indica a causa: `missing_credentials` (chave ausente
   no worker), `auth_failed`, `rate_limited`, `model_unavailable`, `timeout`,
   `connection_failed` (rede, DNS, proxy ou TLS), `redirect_refused`,
   `request_rejected`, `invalid_json`, `unknown_reference`, `command_in_text`, ...
   O adaptador ignora variáveis de proxy do ambiente: o servidor precisa de saída
   HTTPS direta para `integrate.api.nvidia.com:443`.

5. Teste pela interface: dashboard → **Ver correção** → **Explicar com IA**, e em
   Operações → campanha → **Gerar planos** → **Explicar com IA**. O dashboard
   precisa ser regenerado pela próxima coleta (`hmg-soar-report`) para exibir a
   seção de IA no modal.

### Trocar o modelo

```bash
sudo eyemole ai configure --project hmg --model nvidia/OUTRO-MODELO
sudo eyemole ai check --project hmg
```

Confirme no catálogo da NVIDIA que o modelo está disponível para a sua chave.
Explicações anteriores ficam associadas ao modelo que as gerou e deixam de ser
exibidas como atuais. Para modelos sem o parâmetro `chat_template_kwargs`, use
`"thinking": "provider_default"` no bloco `integrations.ai` (via `sudoedit
/etc/hmg-soar/platform.json`).

### Desabilitar

```bash
sudo eyemole ai configure --project hmg --disable
```

### Bloco de configuração (`/etc/hmg-soar/platform.json`)

```json
"integrations": {
  "ai": {
    "enabled": true,
    "provider": "nvidia",
    "base_url": "https://integrate.api.nvidia.com/v1",
    "model": "nvidia/nemotron-3-super-120b-a12b",
    "timeout_seconds": 90,
    "max_output_tokens": 2048,
    "thinking": "disabled"
  }
}
```

`sudo eyemole update` preserva `platform.json` e `integrations.env` existentes.

## Kiro (legado)

Instalações que já tinham `integrations.kiro.enabled = true` e **nenhum** bloco
`integrations.ai` continuam usando o Kiro CLI, com o mesmo contrato de resposta.
Para migrar, configure a NVIDIA como acima; o bloco `integrations.ai` passa a ter
precedência. O Kiro pode ser mantido explicitamente com `"provider": "kiro"` no
bloco `ai`. A rota antiga `/platform/campaigns/<id>/kiro` agora registra o mesmo job
de explicação por IA.

## Outros provedores compatíveis

O adaptador (`operations/llm.py`) aceita outros provedores compatíveis com a API
OpenAI por meio de uma nova entrada no registro `PROVIDERS` (endpoint, hosts
permitidos, nome do segredo, modelo padrão). Não há roteamento automático entre
empresas: cada projeto usa exatamente o provedor configurado.
