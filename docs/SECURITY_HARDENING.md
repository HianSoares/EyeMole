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
                                    \--/soar-api/--> 127.0.0.1:8765 (API local, somente leitura)

Geração do relatório:  systemd timer (root) -> hmg-soar-report.service (hmg-soar) -> /var/www/wazuh-soar
```

A API **lê** o status do serviço/timer diretamente via `systemctl show`
(consulta somente-leitura, **sem `sudo`**). Ela **não** dispara execução
privilegiada no modo padrão.

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
sudo ./create-web-user.sh
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
a execução manual via web. Isso instala um wrapper fixo e uma regra `sudoers`
**restrita** (apenas o disparo da análise; o status continua sem `sudo`):

```bash
EYEMOLE_ENABLE_WEB_RUN=1 sudo ./install.sh
# ou
sudo ./install.sh --enable-web-run
```

Nesse modo:

- Cria `/usr/local/sbin/hmg-soar-run-analysis` (root:root, 0700).
- Cria `/etc/sudoers.d/hmg-soar-api` (0440) contendo **somente**:
  `hmg-soar ALL=(ALL) NOPASSWD: /usr/local/sbin/hmg-soar-run-analysis`.
- Valida a sintaxe com `visudo -cf` (e remove o arquivo se reprovado).
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
ReadWritePaths=/var/www/wazuh-soar/data /opt/hmg-soar/audit
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
| `/etc/sudoers.d/hmg-soar-api` (somente web-run) | `root:root` | `0440` |
| `/usr/local/sbin/hmg-soar-run-analysis` (somente web-run) | `root:root` | `0700` |
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
curl -k -I https://127.0.0.1/soar/
curl -k -I https://127.0.0.1/soar-api/status
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
- O modo **web-run** (opt-in) reintroduz um `sudoers` restrito; use apenas em
  ambiente controlado. Mesmo restrito, permite disparar a análise via web.
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
# 1) Restaurar o sudoers anterior (se você precisa do comportamento antigo):
sudo cp /opt/backup-eyemole-install-<timestamp>/hmg-soar-api /etc/sudoers.d/hmg-soar-api
sudo chown root:root /etc/sudoers.d/hmg-soar-api
sudo chmod 0440 /etc/sudoers.d/hmg-soar-api
sudo visudo -cf /etc/sudoers.d/hmg-soar-api

# 2) Restaurar o snippet/conf do Nginx anterior, se necessário:
sudo cp /opt/backup-eyemole-install-<timestamp>/<arquivo> /etc/nginx/...
sudo nginx -t && sudo systemctl reload nginx

# 3) Reverter o código (git):
git checkout -- install.sh systemd/ opt/hmg-soar/soar_api.py opt/hmg-soar/analyserV1.py
```

Para simplesmente **desfazer o web-run** e voltar ao modo seguro:

```bash
sudo ./install.sh          # reexecuta no modo seguro: faz backup e remove o sudoers
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
