---
title: Manual de Operações — EyeMole SOAR
version: 1.0.0
last_updated: 2026-07-29
audience:
  - administrador
---

# Operação do EyeMole SOAR

## Visão operacional

O EyeMole SOAR é composto por três serviços systemd, um proxy Nginx e arquivos estáticos publicados:

| Componente | Responsabilidade |
|---|---|
| `hmg-soar-api.service` | API HTTP local (127.0.0.1:8765) — serve dados ao Dashboard, aceita classificação de ativos, reporta status |
| `hmg-soar-report.service` | Oneshot — executa o Analyser que coleta, processa e publica snapshots |
| `hmg-soar-report.timer` | Agendamento automático do serviço de relatório a cada 6 horas |
| Nginx | Proxy reverso com Basic Auth — serve Dashboard em `/soar/` e proxy API em `/soar-api/` |
| `/var/www/wazuh-soar/` | Diretório web com HTML estático + JSONs publicados |
| `/opt/hmg-soar/config/` | Configurações JSON (ativos, SLA, exceções, tratamento) |

---

## Serviços

### hmg-soar-api.service

| Atributo | Valor |
|---|---|
| Tipo | `simple` (processo contínuo) |
| Usuário | `hmg-soar` |
| Grupo | `www-data` |
| Bind | `127.0.0.1:8765` (somente loopback) |
| Restart | `on-failure` (RestartSec=5) |
| Função | Serve JSONs publicados, aceita classificação de ativos, reporta status operacional |
| Estado esperado | `active (running)` |

**Comandos:**

```bash
# Status
sudo systemctl status hmg-soar-api.service

# Reiniciar
sudo systemctl restart hmg-soar-api.service

# Logs (últimas 50 linhas)
journalctl -u hmg-soar-api.service -n 50 --no-pager
```

**Comportamento em erro:** reinicia automaticamente após 5 segundos em caso de falha. Se não iniciar, verificar permissões em `/opt/hmg-soar/` e porta 8765 livre.

---

### hmg-soar-report.service

| Atributo | Valor |
|---|---|
| Tipo | `oneshot` (executa e termina) |
| Usuário | `hmg-soar` |
| Grupo | `www-data` |
| EnvironmentFile | `/etc/hmg-soar/credentials.env` |
| Modo fixo | `--mode audit` (nunca executa correção automática) |
| Função | Coleta vulnerabilidades do Wazuh Indexer, cruza com KEV/EPSS, calcula scores, publica HTML + JSONs |
| Estado esperado após conclusão | `inactive (dead)` com result=success |

**Comandos:**

```bash
# Status
sudo systemctl status hmg-soar-report.service

# Executar manualmente (via SSH)
sudo systemctl start hmg-soar-report.service

# Logs da última execução
journalctl -u hmg-soar-report.service -n 100 --no-pager

# Logs com timestamps (últimas 2 horas)
journalctl -u hmg-soar-report.service --since "2 hours ago" --no-pager
```

**Estado normal:** `inactive (dead)` após conclusão com sucesso é o comportamento **esperado** para um serviço oneshot. Não confundir com falha.

**Comportamento em erro:** se o exit code for diferente de 0, o estado será `failed`. Consultar logs para diagnóstico.

---

### hmg-soar-report.timer

| Atributo | Valor |
|---|---|
| Tipo | Timer systemd |
| Função | Dispara `hmg-soar-report.service` automaticamente |
| Estado esperado | `active (waiting)` |

**Comandos:**

```bash
# Status do timer
sudo systemctl status hmg-soar-report.timer

# Listar todos os timers e próxima execução
systemctl list-timers --all | grep hmg-soar

# Habilitar (se desabilitado)
sudo systemctl enable --now hmg-soar-report.timer
```

---

## Agendamento

### Configuração do timer

```ini
OnCalendar=*-*-* 00/6:00:00
Persistent=true
RandomizedDelaySec=300
```

### Horários aproximados de execução

| Horário base | Faixa real (com delay aleatório) |
|---|---|
| 00:00 | 00:00 – 00:05 |
| 06:00 | 06:00 – 06:05 |
| 12:00 | 12:00 – 12:05 |
| 18:00 | 18:00 – 18:05 |

### Persistent=true

Se o servidor estava desligado no horário agendado, o timer executa assim que possível após o boot.

### RandomizedDelaySec=300

Atraso aleatório de até 5 minutos para evitar pico de carga (útil em ambientes com múltiplas instâncias).

### Verificar timers

```bash
systemctl list-timers --all
```

Saída esperada para o timer ativo:

```
NEXT                         LEFT          LAST                         PASSED  UNIT                    ACTIVATES
<próxima execução>           <tempo>       <última execução>            <tempo> hmg-soar-report.timer   hmg-soar-report.service
```

---

## Modo seguro

### Instalação padrão

O modo seguro é o padrão após `install.sh` (sem flags especiais):

- **Sem sudoers** — nenhum arquivo em `/etc/sudoers.d/` para o EyeMole
- **Sem NOPASSWD** — a API não executa nada privilegiado
- **Sem wrappers SUID** — removidos na instalação
- **Botão de execução manual oculto** no Dashboard

### Geração de dados

- **Automática:** via timer (a cada 6 horas)
- **Manual (administrador via SSH):**

```bash
sudo systemctl start hmg-soar-report.service
```

### Status da API no modo seguro

O campo `action_mode` retornado por `/status` é `safe_no_sudoers`. O Dashboard oculta o botão de execução manual e exibe mensagem informativa.

---

## Web-run

### Ativação

```bash
sudo ./install.sh --enable-web-run
```

Ou via variável de ambiente:

```bash
EYEMOLE_ENABLE_WEB_RUN=1 sudo ./install.sh
```

### Quando usar

**Somente em ambientes controlados** (homologação, laboratório). Nunca em produção sem avaliação de risco.

### O que instala

- Regra PolicyKit restrita (`/etc/polkit-1/rules.d/49-hmg-soar.rules`)
- Marcador de estado (`/opt/hmg-soar/config/web_run.enabled`)

### Escopo da autorização PolicyKit

A regra autoriza **exclusivamente**:

| Atributo | Restrição |
|---|---|
| Action | `org.freedesktop.systemd1.manage-units` |
| Unit | `hmg-soar-report.service` |
| Verb | `start` |
| Subject user | `hmg-soar` |

Nenhuma outra unidade, verbo ou usuário é autorizado.

### Risco residual

Com web-run habilitado, qualquer usuário autenticado no Dashboard pode disparar uma nova análise. A análise em si é read-only (modo audit), mas consome recursos do Wazuh Indexer.

### Retorno ao modo seguro

```bash
sudo ./install.sh --safe
# ou simplesmente:
sudo ./install.sh
```

Isso remove a regra PolicyKit, o marcador de estado e eventuais sudoers legados.

---

## Atualização do código

### Verificar estado do repositório

```bash
cd /caminho/do/repositorio
git status
git log --oneline -5
```

### Atualizar código

```bash
git pull --ff-only
```

Se `--ff-only` falhar, **não force** — investigue divergências antes.

### Validar antes de instalar

Consulte a seção [Validações antes do deploy](#validações-antes-do-deploy).

### Instalar

```bash
sudo ./install.sh
```

### Verificar serviços após atualização

```bash
sudo systemctl status hmg-soar-api.service
sudo systemctl status hmg-soar-report.timer
systemctl list-timers --all | grep hmg-soar
```

### Smoke test

Consulte a seção [Deploy e smoke test](#deploy-e-smoke-test).

---

## Validações antes do deploy

### Checklist de validação

```bash
# 1. Verificar trailing whitespace / conflitos
git diff --check

# 2. Validar sintaxe Bash
bash -n install.sh
bash -n set-asset-context.sh
bash -n create-web-user.sh

# 3. Validar sintaxe Python
python3 -m py_compile opt/hmg-soar/analyserV1.py
python3 -m py_compile opt/hmg-soar/soar_api.py

# 4. Extrair e validar JavaScript embutido (opcional)
# Extraia o bloco <script> do HTML_TEMPLATE e valide com:
# node --check arquivo_extraido.js

# 5. Revisar diferenças
git diff --stat
git diff

# 6. Preview local (se disponível)
python3 opt/hmg-soar/preview_server.py
```

### O que verificar no diff

- Alterações em constantes de peso ou fórmulas
- Mudanças em endpoints da API
- Alterações em paths de arquivos
- Remoção de hardening do systemd
- Credenciais ou hostnames reais (não devem entrar no Git)

---

## Deploy e smoke test

### Checklist pós-deploy

| # | Verificação | Comando/Ação |
|---|---|---|
| 1 | API respondendo | `curl -s http://127.0.0.1:8765/health` |
| 2 | Timer ativo | `systemctl list-timers \| grep hmg-soar` |
| 3 | Relatório executou com sucesso | `journalctl -u hmg-soar-report.service -n 20 --no-pager` |
| 4 | Dashboard acessível (HTTP 200) | `curl -sku <usuario>:<senha> -o /dev/null -w '%{http_code}' https://<servidor>/soar/` |
| 5 | Filtros funcionando | No navegador: aplicar filtro, verificar cards e Sankey atualizando |
| 6 | Cards com valores | Verificar que cards de prioridade não estão todos zerados (se há dados) |
| 7 | Sankey renderizando | Diagrama visível na aba Vulnerabilidades |
| 8 | Console do navegador limpo | F12 → Console: sem erros JavaScript |
| 9 | Classificação de ativo | Abrir modal, salvar classificação, verificar auditoria |
| 10 | Auditoria registrada | Aba Status & Auditoria mostra a ação recente |

---

## Logs e diagnóstico

### API

```bash
# Logs recentes
journalctl -u hmg-soar-api.service -n 50 --no-pager

# Logs em tempo real
journalctl -u hmg-soar-api.service -f
```

### Relatório

```bash
# Logs da última execução
journalctl -u hmg-soar-report.service -n 100 --no-pager

# Logs com período específico
journalctl -u hmg-soar-report.service --since "2026-07-29 00:00:00" --no-pager
```

### Timer

```bash
# Próxima execução e última ativação
systemctl list-timers --all | grep hmg-soar

# Detalhes do timer
systemctl show hmg-soar-report.timer
```

### Nginx

```bash
# Testar configuração
sudo nginx -t

# Logs de acesso
tail -f /var/log/nginx/wazuh-dashboard-proxy-access.log

# Logs de erro
tail -f /var/log/nginx/wazuh-dashboard-proxy-error.log
```

### Portas

```bash
# Verificar se API está escutando
ss -tlnp | grep 8765
```

### API via loopback

```bash
# Health check
curl -s http://127.0.0.1:8765/health | python3 -m json.tool

# Status completo
curl -s http://127.0.0.1:8765/status | python3 -m json.tool
```

---

## Troubleshooting

### 401 Unauthorized no navegador

**Causa:** credenciais Basic Auth incorretas ou usuário não cadastrado.

**Solução:**
```bash
# Verificar se o arquivo htpasswd existe e contém o usuário
sudo cat /etc/nginx/.htpasswd-wazuh-soar

# Criar/atualizar usuário
sudo ./create-web-user.sh <usuario>
```

---

### 403 Forbidden em POST /run-analysis

**Causa:** modo seguro ativo — execução manual via web está desabilitada.

**Solução:** este é o comportamento esperado no modo seguro. Para executar análise manualmente:
```bash
sudo systemctl start hmg-soar-report.service
```

Se o modo web-run for necessário (apenas HMG/lab):
```bash
sudo ./install.sh --enable-web-run
```

---

### 502 Bad Gateway

**Causa:** API local não está respondendo na porta 8765.

**Solução:**
```bash
sudo systemctl status hmg-soar-api.service
sudo systemctl restart hmg-soar-api.service
ss -tlnp | grep 8765
```

---

### API offline (serviço não inicia)

**Causas possíveis:** erro de sintaxe Python, porta ocupada, permissões incorretas.

**Diagnóstico:**
```bash
journalctl -u hmg-soar-api.service -n 50 --no-pager
python3 -m py_compile /opt/hmg-soar/soar_api.py
ss -tlnp | grep 8765
ls -la /opt/hmg-soar/soar_api.py
```

---

### Timer inativo (não está agendando)

**Solução:**
```bash
sudo systemctl enable --now hmg-soar-report.timer
systemctl list-timers --all | grep hmg-soar
```

---

### Serviço de relatório em estado inactive (dead)

**Isso é NORMAL.** Para um serviço oneshot, `inactive (dead)` com `Result=success` significa que a última execução concluiu com sucesso.

**Verificar:**
```bash
systemctl show hmg-soar-report.service -p Result -p ExecMainStatus
```

Se `Result=success` e `ExecMainStatus=0`: tudo normal.

---

### Serviço de relatório em estado failed

**Diagnóstico:**
```bash
journalctl -u hmg-soar-report.service -n 100 --no-pager
systemctl show hmg-soar-report.service -p Result -p ExecMainStatus
```

**Causas comuns:**
- Wazuh Indexer inacessível (rede, credenciais)
- Credenciais expiradas em `/etc/hmg-soar/credentials.env`
- Permissão de escrita em `/var/www/wazuh-soar/`
- Timeout na consulta ao Indexer

---

### Dados obsoletos (stale)

**Sintoma:** timestamp de geração no Dashboard é antigo (> 6 horas).

**Diagnóstico:**
```bash
systemctl list-timers --all | grep hmg-soar
journalctl -u hmg-soar-report.service -n 20 --no-pager
stat /var/www/wazuh-soar/data/latest.json
```

**Solução:** verificar se o timer está ativo e se a última execução teve sucesso. Se necessário:
```bash
sudo systemctl start hmg-soar-report.service
```

---

### Botão "Executar análise agora" não aparece

**Causa:** modo seguro ativo (comportamento esperado).

**Verificar:**
```bash
curl -s http://127.0.0.1:8765/status | python3 -c "import sys,json; print(json.load(sys.stdin)['action_mode'])"
```

Se retornar `safe_no_sudoers`: o botão está corretamente oculto.

---

### Classificação de ativo não refletida no score

**Causa:** a classificação é salva imediatamente, mas o **Risk Score e SLAs só são recalculados na próxima execução do Analyser**.

**Solução:** aguardar o próximo ciclo do timer ou executar manualmente:
```bash
sudo systemctl start hmg-soar-report.service
```

---

### Filtros sem resultados

**Causa:** combinação de filtros AND que não corresponde a nenhum achado.

**Solução:** usar o botão "Reset Filters" no Dashboard para restaurar a visão completa.

---

### Configuração Nginx duplicada

**Sintoma:** `nginx -t` reporta conflito de locations.

**Diagnóstico:**
```bash
grep -r "soar" /etc/nginx/sites-enabled/ /etc/nginx/conf.d/ /etc/nginx/snippets/
```

**Solução:** garantir que o include do snippet existe em apenas um server block. Remover duplicatas e recarregar:
```bash
sudo nginx -t && sudo systemctl reload nginx
```

---

## Contexto de ativos

### Arquivo de contexto

- **Caminho:** `/opt/hmg-soar/config/assets_context.json`
- **Permissões:** `0640`, owner `hmg-soar:www-data`
- **Editável por:** API web (POST) ou CLI (`set-asset-context.sh`)

### Edição via web (modal)

Na aba "Ativos & Exposição", clicar em um ativo abre o modal de classificação. Campos: criticidade, ambiente, exposição, dono técnico, dono de negócio, serviço crítico, observações.

### Edição via CLI (set-asset-context.sh)

```bash
sudo ./set-asset-context.sh <agent_id> \
  --criticality <critical|high|medium|low|unknown> \
  --environment <prod|hmg|dev|test|unknown> \
  --technical-owner "Equipe de Infraestrutura" \
  --business-owner "Departamento Financeiro"
```

**Exemplos fictícios:**

```bash
# Classificar ativo como crítico em produção
sudo ./set-asset-context.sh 001 --criticality critical --environment prod

# Definir donos
sudo ./set-asset-context.sh 002 --technical-owner "Time Linux" --business-owner "RH"

# Classificação completa
sudo ./set-asset-context.sh 003 \
  --criticality high \
  --environment hmg \
  --technical-owner "Equipe de Banco de Dados" \
  --business-owner "Jurídico"
```

### Auditoria

- **Via web:** registrado em `/var/www/wazuh-soar/data/audit_actions.jsonl` e `/opt/hmg-soar/audit/audit_actions.jsonl`
- **Via CLI:** metadados `updated_by: set-asset-context-cli` gravados no próprio JSON

### Atualização no próximo relatório

A classificação tem efeito nos scores e SLAs **somente após a próxima execução** do Analyser (timer ou manual).

### Limitação conhecida — valores de ambiente

Os valores aceitos pela interface web e pela API (`prod`, `hmg`, `dev`, `test`, `unknown`) não correspondem integralmente às chaves do dicionário `WEIGHT_ENVIRONMENT` no Analyser (`production`, `hmg`, `development`, `lab`, `unknown`). Valores sem correspondência direta (`prod`, `dev`, `test`) recebem o peso de `unknown` (3 pontos).

**Como verificar o ambiente salvo:**

```bash
# Ver o ambiente de um ativo específico no JSON
python3 -c "
import json
with open('/opt/hmg-soar/config/assets_context.json') as f:
    data = json.load(f)
agent = data.get('agents', {}).get('<agent_id>', {})
print(f'environment: {agent.get(\"environment\", \"não definido\")}')
"
```

**Como verificar o peso aplicado:**

O peso efetivo é determinado por `WEIGHT_ENVIRONMENT.get(env, WEIGHT_ENVIRONMENT["unknown"])` em `calculate_agent_risk_modifiers`. Se o valor não estiver nas chaves `production`, `hmg`, `development`, `lab` ou `unknown`, o peso será 3 (fallback de `unknown`).

**Procedimento operacional (edição direta do JSON):**

Se for necessário utilizar o peso máximo de `production` (15 pontos):

1. Fazer backup do arquivo: `cp /opt/hmg-soar/config/assets_context.json /opt/hmg-soar/config/assets_context.json.bak`
2. Editar com usuário `hmg-soar` (ou root): alterar o campo `"environment"` do ativo de `"prod"` para `"production"`
3. Validar o JSON: `python3 -m json.tool /opt/hmg-soar/config/assets_context.json > /dev/null`
4. Verificar permissões: `ls -la /opt/hmg-soar/config/assets_context.json` — deve ser `0640 hmg-soar:www-data`
5. Aguardar a próxima análise ou executar manualmente: `sudo systemctl start hmg-soar-report.service`

> **Atenção:** edição manual do JSON não é auditada automaticamente (diferente da via web/CLI). Documente a alteração e valide o JSON antes de salvar.

---

## Backups, rollback e Git

### Checkpoints de instalação

Cada execução de `install.sh` cria backup em:

```
/opt/backup-eyemole-install-{timestamp}/
```

Exemplo: `/opt/backup-eyemole-install-20260729-143022/`

### Conteúdo do backup

- `/opt/hmg-soar/` (código anterior)
- `/var/www/wazuh-soar/` (web anterior)
- `/etc/nginx/.htpasswd-wazuh-soar` (credenciais web)
- Snippet Nginx
- Sudoers (se existia)
- Regra PolicyKit (se existia)

### Rollback de instalação

Para reverter para o estado anterior:

```bash
# Restaurar código
sudo cp -a /opt/backup-eyemole-install-{timestamp}/hmg-soar/* /opt/hmg-soar/

# Restaurar systemd units (se necessário)
sudo cp /opt/backup-eyemole-install-{timestamp}/*.service /etc/systemd/system/
sudo systemctl daemon-reload

# Reiniciar serviços
sudo systemctl restart hmg-soar-api.service
sudo systemctl restart hmg-soar-report.timer
```

### Git revert para commits publicados

```bash
git revert <hash-do-commit>
sudo ./install.sh
```

Prefira `git revert` a `git reset --hard` para commits já publicados.

### Cuidados

- **Não use** `git clean -fd` em diretórios que contenham backups ou dados locais
- **Não armazene** backups dentro do repositório Git
- **Cuidado** com sudoers legados em backups antigos — não restaure sem avaliação

---

## Remediation Guidance — Observabilidade e Operação

### Visão geral

O módulo de Remediation Guidance fornece orientações de correção para achados de vulnerabilidade. A interface é estritamente **copy-only**: o operador visualiza ou copia o conteúdo, mas o sistema nunca executa comandos.

### Auditoria (audit trail)

Toda interação com orientações de remediação é registrada:

| Ação | Descrição | Registro |
|---|---|---|
| `view` | Operador visualizou a orientação | Automático ao consultar o endpoint |
| `copy` | Operador copiou o conteúdo da orientação | Registrado via POST de auditoria |

O registro inclui: `timestamp`, `user` (via X-Remote-User), `guidance_id`, `finding_id`, `action` e `remote_addr`.

Log de auditoria: `/opt/hmg-soar/audit/audit_actions.jsonl`

### Códigos HTTP do endpoint de Remediation Guidance

| Código | Significado |
|---|---|
| 200 | Orientação retornada com sucesso / auditoria registrada |
| 400 | Requisição malformada (body inválido, action não reconhecida) |
| 401 | Autenticação ausente ou inválida (Basic Auth / X-Remote-User) |
| 404 | Finding ou guidance_id não encontrado |
| 429 | Rate limit excedido — respeitar header `Retry-After` |
| 500 | Erro interno do servidor |
| 503 | Serviço temporariamente indisponível (ex: cache em reconstrução) |

### Header Retry-After

Quando o endpoint retorna HTTP 429, o header `Retry-After` indica o número de segundos que o cliente deve aguardar antes de uma nova requisição.

Exemplo de resposta:
```
HTTP/1.1 429 Too Many Requests
Retry-After: 60
Content-Type: application/json

{"error": "rate_limit_exceeded", "retry_after": 60}
```

### Invalidação do guidance_id

O `guidance_id` é um identificador temporário mantido em cache. Ele pode ser invalidado nas seguintes situações:

- Reinício do serviço `hmg-soar-api.service`
- Limpeza manual ou expiração do cache
- Atualização da configuração de templates

Após invalidação, uma nova consulta com o `finding_id` gera um novo `guidance_id`. Tentativas de usar um `guidance_id` expirado retornam HTTP 404.

### Monitoramento

Verificar se o módulo de remediação está operacional:

```bash
# Health check geral da API
curl -s http://127.0.0.1:8765/health | python3 -m json.tool

# Logs da API (filtrar por remediation)
journalctl -u hmg-soar-api.service --no-pager | grep -i remediation | tail -20
```

---

## Dados que não devem entrar no Git

| Tipo | Exemplo | Motivo |
|---|---|---|
| Credenciais | `/etc/hmg-soar/credentials.env` | Segurança |
| Certificados privados | `*.key`, `*.pem` (chaves privadas) | Segurança |
| Contexto real de ativos | `assets_context.json` com dados reais | Privacidade |
| Relatórios gerados | `relatorio_wazuh.pdf`, `relatorio_wazuh.csv` | Volume, dados sensíveis |
| Logs de auditoria | `audit_actions.jsonl` | Dados operacionais sensíveis |
| Inventário real | Hostnames, IPs reais, agent_ids reais | Privacidade |
| Backups | `/opt/backup-eyemole-install-*` | Volume, dados sensíveis |
| Snapshots reais | `latest.json`, `risk_summary.json` com dados reais | Privacidade |
| Arquivo htpasswd | `/etc/nginx/.htpasswd-wazuh-soar` | Credenciais |

O `.gitignore` deve contemplar esses padrões. Em caso de dúvida, **não commite**.
