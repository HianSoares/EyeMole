# EyeMole SOAR — Hardening de Segurança e Modo de Produção

Este documento descreve a arquitetura segura do EyeMole SOAR, por que a
instalação padrão **não usa `sudoers`/`NOPASSWD`**, como funciona o modo seguro,
como (opcionalmente) habilitar a execução manual via web em ambiente controlado,
os riscos residuais, comandos de validação e o procedimento de rollback.

---

## 1. Arquitetura segura (visão geral)

| Componente | Função | Privilégio |
|---|---|---|
| `hmg-soar-api.service` | API local HTTP (status/auditoria) | Usuário `hmg-soar`, sem capabilities, escuta **somente** em `127.0.0.1:8765` |
| `hmg-soar-report.timer` | Agenda a geração de relatório (a cada 6h) | root (systemd) |
| `hmg-soar-report.service` | Gera o relatório (oneshot, `--mode audit`) | Usuário `hmg-soar` |
| Nginx `/soar/` e `/soar-api/` | Publica o dashboard e faz proxy da API | Basic Auth em todas as rotas |
| Usuário `hmg-soar` | Conta de serviço | `/usr/sbin/nologin`, sem sudo no modo padrão |

Fluxo de dados:

```
Navegador --HTTPS+BasicAuth--> Nginx --/soar/--> arquivos estáticos em /var/www/wazuh-soar
                                    \--/soar-api/--> 127.0.0.1:8765 (API local)

Geração do relatório:  systemd timer (root) -> hmg-soar-report.service (hmg-soar) -> /var/www/wazuh-soar
```

A API **lê** o status do serviço/timer diretamente via `systemctl show`
(consulta somente-leitura, **sem `sudo`**). Ela **não** dispara execução
privilegiada no modo padrão. A API também realiza **escrita restrita**:
contexto de ativos (`/opt/hmg-soar/config/assets_context.json`) e registros
de auditoria (`/opt/hmg-soar/audit/` e `/var/www/wazuh-soar/data/`).

---

## 2. Por que não usamos `sudoers` por padrão

A versão anterior criava `/etc/sudoers.d/hmg-soar-api` com regras `NOPASSWD`
para permitir que a conta de serviço `hmg-soar` executasse wrappers como root
(inclusive para disparar a análise via web). A equipe de segurança bloqueou esse
modelo porque:

- `NOPASSWD` amplia a superfície de ataque: o comprometimento da conta de
  serviço (ou da aplicação web) passa a permitir execução privilegiada.
- A geração do relatório **já é feita automaticamente** pelo timer do systemd
  (gerenciado pelo root durante a instalação), portanto a API **não precisa** de
  privilégio para cumprir sua função principal.
- O status do dashboard pode ser obtido **sem privilégio** via `systemctl show`.

Conclusão: no modo padrão removemos `sudoers`/`NOPASSWD` e a API opera somente
com leitura, mantendo a automação intacta.

---

## 3. Como funciona o modo seguro (padrão)

Instalação padrão:

```bash
git clone https://github.com/HianSoares/EyeMole.git
cd EyeMole
sudo ./install.sh
sudo ./create-web-user.sh <usuario>
```

No modo seguro o instalador:

- **NÃO** cria `/etc/sudoers.d/hmg-soar-api`.
- **NÃO** cria `NOPASSWD`.
- Se encontrar um `sudoers` de instalação anterior, faz **backup** e o **remove**,
  registrando: *"Modo seguro ativo: sudoers da API não será instalado. Execução
  manual via web ficará desabilitada."*
- Remove wrappers privilegiados antigos (`/usr/local/sbin/hmg-soar-*`).
- Habilita a automação: `systemctl enable --now hmg-soar-report.timer`.
- Sobe a API em `127.0.0.1:8765` (`systemctl enable --now hmg-soar-api.service`).

Comportamento da API no modo seguro:

- `GET /soar-api/status` → continua funcionando (leitura via `systemctl show`).
  Se `systemctl` não estiver disponível/sem permissão, responde **degradado e
  seguro** (HTTP 200), com `report_status_label: "Indisponível"`,
  `timer_status_label: "Indisponível"` e `action_mode: "safe_no_sudoers"`.
- `POST /soar-api/run-analysis` → **HTTP 403** com
  `{"status":"disabled","message":"Execução manual via web desabilitada em modo seguro."}`.
  Não tenta `sudo` nem `systemctl start`.

Comportamento do dashboard no modo seguro:

- O botão **"Executar análise agora"** fica **oculto/desabilitado** e é exibida a
  mensagem: *"Execução manual via web desabilitada em modo seguro. Use o timer
  automático ou execute manualmente via SSH com privilégio administrativo."*
- Os cartões de **API**, **Serviço de Relatório** e **Agendamento (Timer)**
  continuam exibindo o status corretamente.

Execução manual (quando necessária), feita por um administrador via SSH:

```bash
sudo systemctl start hmg-soar-report.service
```

---

## 4. Como habilitar o web-run opcional (HMG/lab)

Apenas em ambiente **controlado** (homologação/laboratório), é possível habilitar
a execução manual via web. Isso **não usa `sudoers`/`NOPASSWD`**: instala uma
regra **PolicyKit** de escopo mínimo. A API dispara a análise pedindo ao systemd
(`systemctl start --no-block hmg-soar-report.service`), e o PolicyKit autoriza
esse start. Como não há `sudo`/SUID envolvido, o hardening do serviço da API
(`NoNewPrivileges=yes`) **permanece ativo** — que é justamente o que bloqueava a
elevação via `sudo` do mecanismo antigo.

```bash
EYEMOLE_ENABLE_WEB_RUN=1 sudo ./install.sh
# ou
sudo ./install.sh --enable-web-run
```

Nesse modo:

- Valida que o PolicyKit está presente; se `polkitd`/`rules.d` faltarem, o
  instalador **falha com mensagem clara** em vez de configurar algo quebrado.
- Cria `/etc/polkit-1/rules.d/49-hmg-soar.rules` (root:root, 0644) com escopo
  **MÍNIMO**: só o usuário `hmg-soar`, só a unidade `hmg-soar-report.service`,
  só o verbo `start` (nunca `ALL`, nunca wildcard de unidade).
- Cria o marcador de estado único `/opt/hmg-soar/config/web_run.enabled`
  (root:www-data, 0644), lido pela API para expor `action_mode`.
- **Remove** (com backup) qualquer `sudoers`/wrapper de instalação anterior,
  para não deixar dois caminhos de privilégio ativos.
- `POST /soar-api/run-analysis` passa a responder **HTTP 202** e o botão do
  dashboard fica visível/habilitado (`action_mode: "web_run_enabled"`).

> Recomendação: **não** habilite web-run em produção.

---

## 5. Hardening dos serviços systemd

### 5.1 `hmg-soar-api.service`

Escuta **somente** em `127.0.0.1:8765` (definido em `soar_api.py`; nunca
`0.0.0.0`). Principais diretivas:

```
User=hmg-soar
Group=www-data
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictRealtime=true
RestrictSUIDSGID=true
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
SystemCallArchitectures=native
UMask=0027
CapabilityBoundingSet=        # nenhuma capability
AmbientCapabilities=          # nenhuma capability
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
ReadOnlyPaths=/opt/hmg-soar
ReadWritePaths=/var/www/wazuh-soar/data /opt/hmg-soar/audit /opt/hmg-soar/config
```

Notas de compatibilidade:

- `AF_UNIX` é mantido porque `systemctl show` fala com o systemd via socket
  D-Bus/unix; `AF_INET` é necessário para o bind local. Remover `AF_UNIX`
  quebraria a leitura de status (a API então degradaria para "Indisponível",
  sem 500).
- A API usa **somente a stdlib do Python**, compatível com
  `MemoryDenyWriteExecute=true`.

### 5.2 `hmg-soar-report.service`

Precisa de **rede** (Wazuh/Indexer) e de escrita em output/cache/web. Diretivas:

```
User=hmg-soar
Group=www-data
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
SystemCallArchitectures=native
UMask=0027
CapabilityBoundingSet=
AmbientCapabilities=
ReadWritePaths=/opt/hmg-soar/output /opt/hmg-soar/.hmg_cache /opt/hmg-soar/config \
              /var/www/wazuh-soar /var/www/wazuh-soar/data \
              /var/www/wazuh-soar/reports /var/www/wazuh-soar/assets
```

Notas de compatibilidade:

- **Não** aplicamos `MemoryDenyWriteExecute` aqui, pois a geração de
  PDF/CSV pode usar extensões nativas que conflitam com essa diretiva.
- A rede **não** é restringida (sem `PrivateNetwork`/`IPAddressDeny`), pois o
  serviço consulta o Wazuh/Indexer.
- `EnvironmentFile=/etc/hmg-soar/credentials.env` é lido pelo systemd como root
  antes de baixar privilégio, portanto o sandbox não impede a leitura.

---

## 6. Permissões esperadas

| Caminho | Owner:Group | Modo |
|---|---|---|
| `/etc/hmg-soar/credentials.env` | `root:hmg-soar` (ou `root:root`) | `0640` |
| `/etc/nginx/.htpasswd-wazuh-soar` | `root:www-data` | `0640` |
| `/etc/polkit-1/rules.d/49-hmg-soar.rules` (somente web-run) | `root:root` | `0644` |
| `/opt/hmg-soar/config/web_run.enabled` (marcador, somente web-run) | `root:www-data` | `0644` |
| `/opt/hmg-soar` | `hmg-soar:www-data` | `0755` |
| `/opt/hmg-soar/audit/actions.log` | `hmg-soar:www-data` | `0640` |
| `/var/www/wazuh-soar/data/audit_actions.jsonl` | `hmg-soar:www-data` | `0660` |

`credentials.env`: nunca deve ter os valores impressos em log. O instalador
ajusta as permissões mas **não** imprime o conteúdo. Como o `EnvironmentFile` é
lido pelo systemd como root, a conta de serviço não precisa de leitura direta;
por isso `root:root 0640` também é aceitável e evita expor segredos ao grupo
`www-data` (Nginx).

---

## 7. Hardening de Nginx

- **Basic Auth** em todas as rotas: `/soar/`, `/soar/data/`, `/soar/reports/`,
  `/soar/assets/` e `/soar-api/`.
- Headers de segurança: `X-Frame-Options`, `X-Content-Type-Options: nosniff`,
  `Referrer-Policy`.
- `Cache-Control: no-store` na API e `no-store/no-cache` nos dados/HTML.
- `autoindex off` em todas as locations estáticas (sem listagem de diretório).
- Proxy da API **somente** para `http://127.0.0.1:8765/`.
- Nenhuma porta nova é aberta; o **certificado TLS existente não é alterado**.
- O instalador procura o server block ativo priorizando
  `sites-enabled` → `sites-available` → `conf.d` → `nginx.conf`, evitando
  instalar o `include` no arquivo errado.

---

## 8. Comandos de validação

Validação estática (qualquer máquina):

```bash
git status --short
git diff --stat
git diff --check

bash -n install.sh
bash -n create-web-user.sh
bash -n set-asset-context.sh

python3 -m py_compile opt/hmg-soar/analyserV1.py
python3 -m py_compile opt/hmg-soar/soar_api.py
python3 -m py_compile opt/hmg-soar/context_bootstrap.py
```

Validação no servidor (com systemd):

```bash
sudo ./install.sh

systemctl status hmg-soar-api.service --no-pager
systemctl status hmg-soar-report.timer --no-pager
systemctl status hmg-soar-report.service --no-pager || true

# Não deve haver NOPASSWD por padrão:
sudo -l -U hmg-soar || true

# API somente em loopback:
ss -ltnp | grep 8765 || true

sudo nginx -t
curl -kfsS -u "<usuario>:<senha>" https://<servidor>/soar/ -o /dev/null && echo OK
curl -kfsS -u "<usuario>:<senha>" https://<servidor>/soar-api/status | python3 -m json.tool
```

Resultado esperado (produção, modo seguro):

- `sudo -l -U hmg-soar` **não** lista `NOPASSWD` para os wrappers.
- `/etc/sudoers.d/hmg-soar-api` **não** existe.
- API ativa em `127.0.0.1:8765`.
- `GET /soar-api/status` → `action_mode: "safe_no_sudoers"`, com labels de
  serviço/timer corretos (ou "Indisponível" se o systemd não puder ser lido).
- `POST /soar-api/run-analysis` → `403 {"status":"disabled", ...}`.
- Timer `hmg-soar-report.timer` ativo; relatório gerado automaticamente.

---

## 9. Riscos residuais

- **Basic Auth** protege as rotas, mas a robustez depende da força das senhas em
  `.htpasswd` e do TLS do Wazuh Dashboard (não gerenciado por este projeto).
- O modo **web-run** (opt-in) instala uma regra **PolicyKit** restrita (sem
  `sudoers`/`NOPASSWD`); use apenas em ambiente controlado. Mesmo restrita a um
  usuário/unidade/verbo, ela permite disparar a análise via web.
- `systemctl show` é leitura, mas expõe metadados de unidades a quem acessa a API
  (já protegida por Basic Auth e loopback).
- O hardening do `report.service` não usa `MemoryDenyWriteExecute` por
  compatibilidade com bibliotecas nativas de relatório.
- Caso o sandbox do systemd bloqueie `systemctl show` em algum ambiente, o status
  aparece como "Indisponível" (sem falha) — validar com os comandos da seção 8.

---

## 10. Rollback

A instalação cria um backup em `/opt/backup-eyemole-install-<timestamp>/` com os
artefatos substituídos (inclui o `sudoers` anterior, se havia).

Reverter para um estado anterior:

```bash
# 1) Restaurar o snippet/conf do Nginx anterior, se necessário:
sudo cp /opt/backup-eyemole-install-<timestamp>/<arquivo> /etc/nginx/...
sudo nginx -t && sudo systemctl reload nginx

# 2) Reverter o código (git):
git checkout -- install.sh systemd/ opt/hmg-soar/soar_api.py opt/hmg-soar/analyserV1.py
```

> **Restauração do sudoers legado**: procedimento legado e não recomendado.
> Reintroduz o modelo de privilégio removido pelo hardening e exige aprovação
> formal da equipe de segurança. O backup está disponível em
> `/opt/backup-eyemole-install-<timestamp>/hmg-soar-api`, mas sua restauração
> **não faz parte do fluxo normal de operação**.

Para simplesmente **desfazer o web-run** e voltar ao modo seguro:

```bash
sudo ./install.sh          # reexecuta no modo seguro: faz backup e remove a regra
                           # PolicyKit + o marcador web_run.enabled (e o sudoers legado)
```

---

## 11. Serviços e caminhos usados

- Serviços/timers: `hmg-soar-api.service`, `hmg-soar-report.service`,
  `hmg-soar-report.timer`.
- Aplicação: `/opt/hmg-soar` (somente leitura para a API).
- Dashboard: `/var/www/wazuh-soar` (`data/`, `reports/`, `assets/`).
- Config/segredos: `/etc/hmg-soar/credentials.env`.
- Nginx: snippet `/etc/nginx/snippets/eyemole-soar-locations.conf`;
  auth `/etc/nginx/.htpasswd-wazuh-soar`.
- API: `127.0.0.1:8765` (loopback apenas).

---

## 12. Classificação de ativos via web (sem privilégio)

A aba **Ativos & Exposição** permite classificar ativos pendentes diretamente
pela interface, **sem linha de comando**. Esta funcionalidade é segura por
construção:

- **Não usa** `sudo`, `sudoers`, `NOPASSWD`, `systemctl`, shell, `os.system`,
  `subprocess`, `eval` nem `shell=True`.
- **Apenas edita** o arquivo JSON local
  `/opt/hmg-soar/config/assets_context.json` (único caminho de escrita
  autorizado; o `agent_id` nunca é usado como caminho).
- **Não reativa** a execução manual via web: o botão "Executar análise agora"
  continua desabilitado em modo seguro e `/soar-api/run-analysis` continua `403`.

Endpoints (atrás de Basic Auth do Nginx, API em loopback):

- `GET /soar-api/assets-context` — lista o contexto de ativos (sanitizado).
- `POST /soar-api/assets-context/<agent_id>` — atualiza o contexto de um ativo.

Validações no servidor (defesa em profundidade):

- `agent_id`: somente `[A-Za-z0-9_-]`, até 64 caracteres (sem path traversal).
- `criticality` ∈ {critical, high, medium, low, unknown}.
- `environment` ∈ {prod, hmg, dev, test, unknown}.
- `exposure` ∈ {internal, dmz, internet, unknown}.
- `technical_owner`/`business_owner`: texto até 256 chars; `notes` até 1000;
  remoção de caracteres de controle.
- `Content-Type` deve ser `application/json`; payload máximo de 16 KB.
- Rejeita `Origin`/`Referer` de host diferente (proteção mínima de CSRF).
- Escrita **atômica**: backup `.bak`, arquivo temporário no mesmo diretório,
  validação do JSON e `os.replace`; permissões `0640` (owner `hmg-soar`,
  grupo `www-data`).

`classification_status` é definido como `classified` quando `criticality` for
diferente de `unknown`, ou `pending` caso contrário — então o ativo sai da lista
de pendentes.

A priorização completa só é aplicada no **próximo relatório automático** (timer)
ou após execução manual via SSH (`sudo systemctl start hmg-soar-report.service`).
A edição de contexto funciona normalmente em **modo seguro**, pois não exige
privilégio administrativo.

Auditoria: cada alteração gera um evento JSONL em
`/opt/hmg-soar/audit/audit_actions.jsonl` com `timestamp`, `remote_addr`,
`user` (Basic Auth via `X-Remote-User`), `action=update_asset_context`,
`agent_id`, `changed_fields`, `result` e `message` — **sem registrar valores
sensíveis** (apenas os nomes dos campos alterados).

Hardening do serviço da API para esta função: `ReadWritePaths` inclui
`/opt/hmg-soar/config` (além de `/opt/hmg-soar/audit`), mantendo o restante de
`/opt/hmg-soar` como somente leitura.

---

## 13. Hardening do módulo Remediation Guidance

### Interface copy-only (sem execução)

O módulo de orientação de correção opera exclusivamente em modo **copy-only**:

- O backend **nunca** executa comandos, scripts ou verificações de forma
  automatizada.
- O campo `execution_allowed` na resposta da API é **sempre `false`**, imposto
  pelo backend independentemente da configuração.
- O operador pode apenas visualizar e copiar o conteúdo apresentado.
- Nenhuma funcionalidade de "auto-remediation" ou "self-healing" está presente.

### Gating por nível de confiança

Orientações que incluem referência a comandos são apresentadas **somente**
quando o nível de confiança (`confidence`) da orientação é `high` ou `medium`.

- Achados com confiança `low` recebem apenas texto descritivo e referências.
- Isso reduz o risco de o operador aplicar procedimentos inadequados baseados
  em correspondências fracas.

### Confiança no header X-Remote-User

A identidade do operador nas ações de auditoria é extraída do header
`X-Remote-User`, injetado pelo proxy Nginx após autenticação Basic Auth.

**Risco residual:** qualquer processo local com acesso à porta `127.0.0.1:8765`
pode enviar requisições com um header `X-Remote-User` arbitrário, pois a API
não valida a origem da requisição além do loopback. Esse é um trust boundary
aceito dado que:

- A API escuta **somente** em loopback (`127.0.0.1:8765`).
- Em produção, apenas o Nginx tem acesso direto à porta.
- Processos locais executando como outro usuário precisariam de acesso à
  rede loopback, que é restrita ao próprio servidor.

### API vinculada somente ao loopback

A API de remediação está vinculada a `127.0.0.1:8765`, assim como todos os
demais endpoints. Não há bind em `0.0.0.0` ou em interfaces externas.

Validação:
```bash
ss -tlnp | grep 8765
```

Resultado esperado: `127.0.0.1:8765` apenas.

### Processos locais como fronteira de confiança residual

Processos executando no mesmo servidor com acesso à rede loopback podem:

- Consultar orientações de remediação sem autenticação Nginx.
- Registrar ações de auditoria com `X-Remote-User` arbitrário.

**Mitigação:** o hardening do servidor (conta de serviço dedicada, sandbox
systemd, `NoNewPrivileges=true`) limita quais processos podem explorar essa
fronteira. Em ambientes com requisitos mais rígidos, considere adição de
autenticação mTLS ou token na camada da API.

### Generic update policy desabilitada por padrão

O arquivo `generic_update_policy.json` é instalado com a política de
atualização genérica **desabilitada** (`"enabled": false`). A ativação
requer edição manual do arquivo pelo administrador.

### Logs nunca contêm conteúdo de comandos

O sistema de logging **não registra** o conteúdo dos campos `command` ou
`verification_command` presentes nas orientações de remediação.

Os logs registram apenas:
- `guidance_id`
- `finding_id`
- `action` (`view` / `copy`)
- `user`
- `timestamp`
- `confidence`

Isso garante que, mesmo em caso de vazamento de logs, nenhum procedimento
de correção específico é exposto.

### Campo execution_allowed

O campo `execution_allowed` é retornado como `false` em **toda** resposta
do endpoint de remediação. Esse valor é:

- Definido pelo backend de forma incondicional (hardcoded).
- Não configurável via arquivo de configuração.
- Não alterável por header, parâmetro ou body da requisição.

Clientes da API devem tratar esse campo como informativo (interface pode
exibir "somente cópia") e nunca condicionar execução local a esse valor.

---

## 14. Segurança do desinstalador

### Proteção contra path traversal

O desinstalador valida rigorosamente todos os caminhos antes de qualquer operação `rm`:
- Rejeita caminhos vazios
- Rejeita `/`, `/opt`, `/var`, `/etc`, `/etc/nginx`, `/usr`
- Rejeita caminhos relativos
- Rejeita caminhos contendo `..`
- Resolve caminhos canônicos quando possível

### Backup de credenciais

O backup pré-desinstalação pode conter `credentials.env`. O diretório de backup é criado com:
- Permissões: `0700`
- Ownership: `root:root`
- Manifesto SHA-256 para verificação de integridade

### Componentes compartilhados nunca removidos

O desinstalador NUNCA remove:
- Pacote Nginx ou sua configuração base
- Python ou módulos do sistema
- Grupo `www-data`
- Wazuh Manager/Indexer/Agent
- Backups de instalações anteriores

### Confirmação de purge

O modo `--purge` exige confirmação explícita digitando `PURGE EYEMOLE` (ou `--yes` para automação). Isso previne deleção acidental de dados em ambientes interativos.
