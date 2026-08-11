# EyeMole SOAR — Guia de Instalação

## 1. Objetivo

Este documento descreve o passo a passo para instalar o **EyeMole SOAR** em um servidor Linux com Wazuh/Nginx, publicar o dashboard em `/soar/`, habilitar a API auxiliar em `/soar-api/` e proteger o acesso com autenticação Basic Auth.

Ao final da instalação, o acesso será feito por:

```text
https://<servidor>/soar/
```

---

## 2. Pré-requisitos

Antes de iniciar, confirme que o servidor possui:

- Sistema Linux com `systemd`.
- Acesso `sudo`.
- `git` instalado.
- Nginx instalado ou disponível para instalação.
- Wazuh Dashboard já publicado via Nginx.
- Repositório EyeMole acessível pelo servidor.
- Arquivo de credenciais do ambiente, para publicação dos dados reais:

```text
/etc/hmg-soar/credentials.env
```

Observação: se o arquivo `credentials.env` não existir, o instalador criará automaticamente o modelo em `/etc/hmg-soar/credentials.env` com permissão 0640. O dashboard opera em modo bootstrap/offline até que as senhas obrigatórias `OPENSEARCH_PASS` e `WAZUH_API_PASS` sejam configuradas.

---

## 3. Clone do repositório

Em um diretório de trabalho do usuário administrador:

```bash
cd ~
git clone https://github.com/HianSoares/EyeMole.git
cd EyeMole
```

Caso o repositório esteja público, o clone não solicitará senha.

Caso o repositório esteja privado, o GitHub poderá solicitar autenticação. Use:

```text
Username: seu usuário do GitHub
Password: Personal Access Token do GitHub
```

Não use sua senha real do GitHub no terminal.

---

## 4. Instalação principal (modo seguro)

Dentro da pasta do projeto:

```bash
sudo ./install.sh
```

A instalação padrão opera em **modo seguro**:

- **Não** cria `/etc/sudoers.d/hmg-soar-api`.
- **Não** cria `NOPASSWD`.
- Se encontrar artefatos legados (`sudoers`, wrappers em `/usr/local/sbin/`), faz backup e os remove.
- Mantém a execução automática pelo timer `hmg-soar-report.timer`.
- Deixa o botão "Executar análise agora" do dashboard oculto/desabilitado.
- Permite execução manual administrativa via SSH:

```bash
sudo systemctl start hmg-soar-report.service
```

O instalador executa automaticamente:

- Instalação de dependências (`python3`, `rsync`, `nginx`).
- Criação do usuário de serviço `hmg-soar` e diretórios.
- Cópia dos arquivos para `/opt/hmg-soar`.
- Publicação do dashboard em `/var/www/wazuh-soar`.
- Criação dos diretórios de auditoria.
- Instalação das unidades `systemd`.
- Configuração do snippet Nginx para `/soar/` e `/soar-api/`.
- Recarga do Nginx.
- Execução inicial do relatório, quando possível.
- Habilitação automática de `hmg-soar-api.service` e `hmg-soar-report.timer`.

---

## 5. Habilitação do web-run opcional (somente HMG/lab)

Em ambientes controlados de homologação ou laboratório, a execução manual via web pode ser habilitada:

```bash
sudo ./install.sh --enable-web-run
```

Nesse modo:

- **Não** cria `sudoers` nem `NOPASSWD`.
- Utiliza uma regra PolicyKit restrita (`/etc/polkit-1/rules.d/49-hmg-soar.rules`).
- Autoriza somente o usuário `hmg-soar` a dar `start` somente na unidade `hmg-soar-report.service`.
- Cria o marcador de estado `/opt/hmg-soar/config/web_run.enabled`.
- O endpoint `POST /soar-api/run-analysis` responde HTTP 202.
- O botão do dashboard fica visível/habilitado.

Para retornar ao modo seguro, reexecute sem `--enable-web-run`:

```bash
sudo ./install.sh
```

---

## 6. Criação do usuário web

Após a instalação, crie o usuário de acesso ao painel:

```bash
sudo ./create-web-user.sh <usuario>
```

O script solicitará a senha de acesso.

Esse usuário é apenas para autenticação web via Nginx Basic Auth. Ele não precisa ser igual ao usuário Linux, SSH, Wazuh ou GitHub.

Para listar usuários web já cadastrados:

```bash
sudo cut -d: -f1 /etc/nginx/.htpasswd-wazuh-soar
```

---

## 7. Acesso ao painel

Após instalar e criar o usuário web, acesse:

```text
https://<servidor>/soar/
```

Informe o usuário e senha criados na etapa anterior.

---

## 8. Validação dos serviços

Após a instalação, valide os serviços principais:

```bash
systemctl status hmg-soar-api.service --no-pager
systemctl status hmg-soar-report.timer --no-pager
systemctl list-timers --all | grep hmg-soar || true
```

Esperado para a API:

```text
Active: active (running)
```

Esperado para o timer:

```text
Active: active (waiting)
Trigger: ...
```

---

## 9. Validação da API

As rotas estão protegidas por Basic Auth. Para testar sem expor a senha no histórico:

```bash
read -s -p "Senha web: " SOAR_PASS
echo

curl -kfsS \
  -u "admmaster:${SOAR_PASS}" \
  "https://<servidor>/soar-api/health" | python3 -m json.tool

curl -kfsS \
  -u "admmaster:${SOAR_PASS}" \
  "https://<servidor>/soar-api/status" | python3 -m json.tool

unset SOAR_PASS
```

Troque `admmaster` pelo usuário web criado e `<servidor>` pelo hostname real.

### Resposta de `GET /soar-api/health`

```json
{
  "status": "ok",
  "service": "hmg-soar-api",
  "version": "1.0.0",
  "timestamp": "2026-07-28T12:00:00+00:00"
}
```

### Resposta de `GET /soar-api/status` (modo seguro)

Campos principais:

```json
{
  "timestamp": "...",
  "action_mode": "safe_no_sudoers",
  "report_status_label": "Pronto (Ocioso)",
  "timer_status_label": "Ativo",
  "wrapper_exit_code": 0,
  "timer_info": {
    "active_state": "active",
    "sub_state": "waiting"
  }
}
```

### Resposta de `POST /soar-api/run-analysis` (modo seguro)

```json
HTTP 403
{
  "status": "disabled",
  "message": "Execução manual via web desabilitada em modo seguro."
}
```

---

## 10. Interpretação dos status

Na aba **Status & Auditoria**, o comportamento esperado é:

```text
API SOAR: Online
Serviço de relatório: Pronto (Ocioso)
Agendamento: Ativo
Último Exit Code: 0
```

O serviço `hmg-soar-report.service` é do tipo `oneshot`. Após concluir, ele aparece como:

```text
inactive (dead)
status=0/SUCCESS
```

Isso **não é erro**. Significa que o relatório foi gerado com sucesso e o serviço finalizou normalmente.

---

## 11. Execução manual

### Modo seguro (padrão)

A execução manual é feita por um administrador via SSH:

```bash
sudo systemctl start hmg-soar-report.service
```

O botão "Executar análise agora" do dashboard fica desabilitado neste modo.

### Web-run habilitado

Quando o modo web-run está ativo (`--enable-web-run`), a execução pode ser disparada pelo botão da aba **Status & Auditoria**.

---

## 12. Classificação de ativos pela interface web

Os ativos pendentes podem ser classificados diretamente pela aba **Ativos & Exposição**, sem linha de comando:

1. Abra a aba **Ativos & Exposição**.
2. Na tabela de ativos pendentes, clique em **Classificar**.
3. Preencha criticidade, ambiente, exposição, donos e observações.
4. Clique em **Salvar classificação**.

A classificação:

- **Não** usa `sudo`.
- **Não** executa shell.
- Apenas edita `/opt/hmg-soar/config/assets_context.json`.
- Registra a ação em `/opt/hmg-soar/audit/audit_actions.jsonl`.
- Funciona em modo seguro.

A priorização completa é aplicada no **próximo relatório automático** (timer) ou após execução manual via SSH.

O script `set-asset-context.sh` continua disponível para uso por CLI.

### Classificação via linha de comando

O script `set-asset-context.sh` permite classificar ativos sem a interface web. Requer `sudo`:

```bash
sudo ./set-asset-context.sh <agent_id> [opções]
```

Opções disponíveis:

| Opção | Descrição | Valores permitidos |
|---|---|---|
| `--technical-owner <dono>` | Responsável técnico | Texto livre |
| `--business-owner <dono>` | Área de negócio | Texto livre |
| `--criticality <nível>` | Criticidade do ativo | `critical`, `high`, `medium`, `low`, `unknown` |
| `--environment <env>` | Ambiente operacional | Texto livre (ex: `prod`, `hmg`, `dev`, `lab`) |

Exemplo:

```bash
sudo ./set-asset-context.sh 001 \
  --technical-owner "Equipe Windows" \
  --business-owner "Sistemas Corporativos" \
  --criticality critical \
  --environment hmg
```

O script edita `/opt/hmg-soar/config/assets_context.json` e ajusta permissões (`hmg-soar:www-data`, `0640`).

Após a classificação, a priorização será aplicada no próximo relatório automático (timer) ou após execução manual:

```bash
sudo systemctl start hmg-soar-report.service
```

Para exibir a ajuda: `sudo ./set-asset-context.sh --help`

---

### Consultar auditoria das ações

O endpoint `GET /soar-api/audit-actions` retorna os registros de auditoria das ações disparadas pela API (execuções manuais, classificações de ativos, etc.). Protegido por Basic Auth.

Parâmetro opcional: `limit` (padrão: 10, máximo: 50).

```bash
read -s -p "Senha web: " SOAR_PASS
echo

curl -kfsS \
  -u "admmaster:${SOAR_PASS}" \
  "https://<servidor>/soar-api/audit-actions?limit=10" | python3 -m json.tool

unset SOAR_PASS
```

Formato da resposta:

```json
{
  "timestamp": "2026-07-28T18:00:00Z",
  "source": "/var/www/wazuh-soar/data/audit_actions.jsonl",
  "limit": 10,
  "count": 0,
  "actions": []
}
```

O campo `actions` contém os registros encontrados no arquivo de auditoria. Os campos de cada registro variam conforme o tipo de ação, como execução manual ou atualização de contexto de ativo.

---

## 13. Atualização do EyeMole

Para atualizar uma instalação existente:

```bash
cd ~/EyeMole
git pull --ff-only origin main
sudo ./install.sh
```

Depois valide novamente:

```bash
systemctl status hmg-soar-api.service --no-pager
systemctl status hmg-soar-report.timer --no-pager
```

---

## 14. Troubleshooting

### 14.1 Erro 401 Unauthorized

Causa provável: usuário ou senha Basic Auth incorretos.

```bash
sudo cut -d: -f1 /etc/nginx/.htpasswd-wazuh-soar
sudo ./create-web-user.sh <usuario>
```

### 14.2 API retornando 502

Causa provável: serviço da API parado ou com erro.

```bash
systemctl status hmg-soar-api.service --no-pager
sudo journalctl -u hmg-soar-api.service -n 80 --no-pager
sudo systemctl restart hmg-soar-api.service
```

### 14.3 Agendamento aparece inativo

```bash
systemctl status hmg-soar-report.timer --no-pager
sudo systemctl enable --now hmg-soar-report.timer
```

### 14.4 Serviço de relatório aparece inactive/dead

Isso é normal quando o último exit code é `0`. Valide:

```bash
systemctl status hmg-soar-report.service --no-pager
```

Se aparecer `inactive (dead)` com `status=0/SUCCESS`, o serviço funcionou corretamente.

### 14.5 Configuração de credenciais (credentials.env)

Se `/etc/hmg-soar/credentials.env` não existir, o instalador cria automaticamente o arquivo a partir do modelo com permissão `0640`.

Para configurar o acesso real ao Wazuh/Indexer:

1. Edite o arquivo:
   ```bash
   sudo nano /etc/hmg-soar/credentials.env
   ```
2. Preencha as variáveis obrigatórias `OPENSEARCH_PASS` e `WAZUH_API_PASS`.
3. Variáveis com valores padrão (ex: `OPENSEARCH_HOST=127.0.0.1`) aparecem comentadas no modelo e podem ser descomentadas para personalização.
4. Após preencher, o próximo disparo do `hmg-soar-report.service` (manual ou via timer) detectará as credenciais e publicará os dados reais.

---

## 15. Caminhos importantes

| Recurso | Caminho |
|---|---|
| Aplicação | `/opt/hmg-soar` |
| Dashboard publicado | `/var/www/wazuh-soar` |
| Credenciais | `/etc/hmg-soar/credentials.env` |
| Usuários web | `/etc/nginx/.htpasswd-wazuh-soar` |
| Snippet Nginx | `/etc/nginx/snippets/eyemole-soar-locations.conf` |
| Contexto de ativos | `/opt/hmg-soar/config/assets_context.json` |
| Auditoria da API | `/opt/hmg-soar/audit/audit_actions.jsonl` |
| Auditoria publicada | `/var/www/wazuh-soar/data/audit_actions.jsonl` |
| Serviço da API | `hmg-soar-api.service` |
| Serviço de relatório | `hmg-soar-report.service` |
| Timer | `hmg-soar-report.timer` |

---

## 16. Fluxo resumido

```bash
git clone https://github.com/HianSoares/EyeMole.git
cd EyeMole
sudo ./install.sh
sudo ./create-web-user.sh <usuario>
```

Acesso final:

```text
https://<servidor>/soar/
```

---

## 17. Remediation Guidance — Instalação e Configuração

### Fresh install vs atualização

| Cenário | Comportamento |
|---|---|
| Fresh install (primeira instalação) | Arquivos de configuração padrão são copiados para `/opt/hmg-soar/config/` |
| Atualização (configs já existem) | Arquivos existentes são **preservados** — nunca sobrescritos |

O instalador usa a lógica **only-if-missing**: cada arquivo de configuração é copiado apenas se ainda não existir no destino.

### Arquivos de configuração instalados

| Arquivo | Finalidade |
|---|---|
| `generic_update_policy.json` | Política genérica de atualização (desabilitada por padrão) |
| `remediation_allowlist.json` | Lista de pacotes/ações permitidos nas orientações |
| `remediation_providers.json` | Provedores de orientação configurados |
| `remediation_templates.json` | Templates de orientação por tipo de achado |
| `risk_acceptance.json` | Registros de aceitação de risco |
| `sla_policy.json` | Política de SLA por severidade |
| `treatment_policy.json` | Política de tratamento de vulnerabilidades |

### Verificações fail-fast

O instalador executa verificações obrigatórias que interrompem a instalação em caso de falha:

1. **Validação JSON:** todos os arquivos `.json` em `/opt/hmg-soar/config/` são validados sintaticamente.
2. **Validação Python:** todos os módulos Python são compilados, incluindo `soar_api.py` e o pacote `remediation/`.
3. **Health check da API:** após iniciar o serviço, o instalador verifica se `GET /health` responde HTTP 200 em `127.0.0.1:8765`.

Se qualquer verificação falhar, a instalação é interrompida com mensagem de erro clara.

### Validação pós-instalação

Após a instalação, confirme que os arquivos de configuração de remediação existem:

```bash
ls -la /opt/hmg-soar/config/remediation_allowlist.json
ls -la /opt/hmg-soar/config/remediation_providers.json
ls -la /opt/hmg-soar/config/remediation_templates.json
ls -la /opt/hmg-soar/config/treatment_policy.json
ls -la /opt/hmg-soar/config/risk_acceptance.json
ls -la /opt/hmg-soar/config/sla_policy.json
ls -la /opt/hmg-soar/config/generic_update_policy.json
```

Valide o JSON de cada arquivo:

```bash
python3 -m json.tool /opt/hmg-soar/config/remediation_allowlist.json > /dev/null
python3 -m json.tool /opt/hmg-soar/config/treatment_policy.json > /dev/null
```

Confirme que a API responde e inclui o módulo de remediação:

```bash
curl -s http://127.0.0.1:8765/health | python3 -m json.tool
```

### Testando os endpoints de Remediation Guidance

Para verificar o endpoint sem incluir dados reais:

```bash
read -s -p "Senha web: " SOAR_PASS
echo

# Consultar orientação para um achado
curl -kfsS \
  -u "admmaster:${SOAR_PASS}" \
  "https://<servidor>/soar-api/remediation-guidance/<finding_id>" | python3 -m json.tool

# Registrar ação de auditoria
curl -kfsS -X POST \
  -u "admmaster:${SOAR_PASS}" \
  -H "Content-Type: application/json" \
  -d '{"action":"copy"}' \
  "https://<servidor>/soar-api/remediation-guidance/<guidance_id>/audit" | python3 -m json.tool

unset SOAR_PASS
```

Substitua `<finding_id>` e `<guidance_id>` pelos identificadores reais do ambiente.

---

## 18. Troubleshooting — Remediation Guidance

### 18.1 Arquivo de configuração ausente

**Sintoma:** API retorna erro ao consultar orientação de remediação.

**Diagnóstico:**
```bash
ls -la /opt/hmg-soar/config/remediation_*.json
ls -la /opt/hmg-soar/config/treatment_policy.json
```

**Solução:** reinstale no modo seguro para restaurar os arquivos padrão (configs existentes são preservadas):
```bash
sudo ./install.sh
```

### 18.2 API não responde ao endpoint de remediação

**Sintoma:** HTTP 502 ou timeout em `/soar-api/remediation-guidance/<finding_id>`.

**Diagnóstico:**
```bash
systemctl status hmg-soar-api.service --no-pager
journalctl -u hmg-soar-api.service -n 50 --no-pager
curl -s http://127.0.0.1:8765/health
```

**Solução:** reinicie a API e verifique se o módulo `remediation/` está acessível:
```bash
python3 -m py_compile /opt/hmg-soar/remediation/engine.py
sudo systemctl restart hmg-soar-api.service
```

---

## 19. Desinstalação segura

### Dry-run (sem alterações)

```bash
sudo ./uninstall.sh --dry-run
```

Mostra todas as ações planejadas sem executar nenhuma. Útil para revisão antes da remoção.

### Desinstalação com preservação de dados

```bash
sudo ./uninstall.sh
```

- Remove serviços systemd, integração Nginx e código da aplicação
- Preserva configurações, auditoria e relatórios em `/var/lib/eyemole-preserved/<timestamp>/`
- Cria backup completo antes de qualquer alteração
- Não remove o usuário de serviço

### Desinstalação completa (purge)

```bash
sudo ./uninstall.sh --purge
```

Exige confirmação digitando exatamente: `PURGE EYEMOLE`

Para scripts não-interativos: `sudo ./uninstall.sh --purge --yes`

### Verificação pós-desinstalação

```bash
# Confirmar que serviços foram removidos
systemctl status hmg-soar-api.service 2>&1 | grep -q "could not be found"

# Confirmar que Nginx está saudável
nginx -t

# Confirmar que a porta não está em uso
ss -tlnp | grep 8765

# Localizar backup
ls /opt/backup-eyemole-uninstall-*/MANIFEST.sha256
```

### Reinstalação posterior

Após uma desinstalação com `--purge`, o sistema pode ser reinstalado:

```bash
sudo ./install.sh
```

Configurações padrão serão restauradas e novos dados serão gerados.

---

## Segurança e modo de produção

Consulte [Hardening de segurança e modo de produção](SECURITY_HARDENING.md) para detalhes sobre:

- Diretivas de hardening do systemd.
- Permissões esperadas.
- PolicyKit e modo web-run.
- Rollback.
- Riscos residuais.
- Comandos de validação completos.
