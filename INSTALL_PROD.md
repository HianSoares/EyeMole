# EyeMole SOAR — Instalação Limpa em Produção

Este guia descreve as etapas necessárias para realizar uma instalação profissional limpa do EyeMole SOAR em ambientes de produção.

## 📋 Fluxo de Instalação e Execução

1. **Clonar o repositório:**
   ```bash
   git clone https://github.com/HianSoares/EyeMole.git /opt/eyemole-repo
   ```

2. **Executar o instalador:**
   ```bash
   cd /opt/eyemole-repo
   sudo ./install.sh
   ```

3. **Criar usuário de acesso ao site:**
   ```bash
   sudo ./create-web-user.sh nome-do-usuario
   ```

4. **Acessar o dashboard:**
   ```text
   https://<seu-servidor>/soar/
   ```

---

## 🔒 Gerenciamento de Usuários Web

O acesso ao dashboard é protegido por autenticação básica do Nginx (Basic Auth). O arquivo de credenciais é mantido em:
`/etc/nginx/.htpasswd-wazuh-soar`

Para cadastrar novos usuários ou alterar a senha de usuários existentes manualmente:
```bash
sudo htpasswd /etc/nginx/.htpasswd-wazuh-soar usuario
sudo nginx -t
sudo systemctl reload nginx
```
*Nota: Este usuário é exclusivo para acesso ao portal web e não interfere em contas de sistema Linux, SSH ou APIs do Wazuh.*

---

## 🖥️ Configuração de Contexto de Ativos (CLI)

Após a instalação, todos os ativos detectados são provisionados automaticamente em estado pendente de classificação. Para designar criticidade, donos técnicos/operacionais e ambientes para um determinado ativo, utilize o script `set-asset-context.sh` localizado na raiz do repositório:

### Uso do Script:
```bash
sudo ./set-asset-context.sh <agent_id> [--technical-owner <owner>] [--business-owner <owner>] [--criticality <criticality>] [--environment <env>]
```

### Argumentos permitidos:
- `--criticality`: Nível de criticidade (`critical`, `high`, `medium`, `low`, `unknown`).
- `--technical-owner`: Nome ou equipe responsável pela administração técnica.
- `--business-owner`: Área de negócios dona do serviço/sistema.
- `--environment`: Ambiente operacional (ex: `prod`, `hmg`, `dev`, `lab`).

### Exemplo:
```bash
sudo ./set-asset-context.sh 001 --technical-owner "Equipe Windows" --business-owner "Sistemas Corporativos" --criticality critical --environment hmg
```

Após atualizar as definições de contexto de um ativo, execute ou reinicie o serviço do relatório para refletir os dados no painel:
```bash
sudo systemctl restart hmg-soar-report.service
```

---

## 📂 Estrutura de Arquivos de Contexto

Todos os JSONs de contexto e políticas operacionais são criados e mantidos no diretório de configuração do cérebro SOAR:

- **Localização:** `/opt/hmg-soar/config/`
- **Arquivos:**
  - `assets_context.json`: Mapeamento de criticidade, tags, e proprietários dos ativos.
  - `exposure_context.json`: Nível de exposição à internet, DMZ e portas críticas expostas.
  - `sla_policy.json`: Prazos de SLA operacionais com base no CVSS, KEV e criticidade do ativo.
  - `risk_acceptance.json`: Mapa declarativo de exceções aprovadas, aceites de risco e falsos positivos.

*Importante: O diretório `/opt/hmg-soar/config` e seus arquivos são gerados com permissões restritas `0640` e pertencem ao usuário `hmg-soar` e grupo `www-data`.*

---

## ⚙️ API de SOAR e Auditoria de Ações

O EyeMole SOAR possui uma API local executada via systemd para gerenciamento e auditoria sob demanda.

### Como validar a API:
A API escuta localmente na porta `8765` e está exposta de forma reversa e protegida atrás do Nginx em `/soar-api/`.

- **Validar status do serviço:**
  ```bash
  sudo systemctl status hmg-soar-api.service
  ```

- **Logs do serviço de API:**
  ```bash
  sudo journalctl -u hmg-soar-api.service -f
  ```

### Auditoria de Execuções:
Toda solicitação de execução de análise manual (POST `/soar-api/run-analysis`) gera um registro detalhado em formato JSONL contendo o operador autenticado, o IP de origem, o resultado, exit code da tarefa, timestamp e mensagem.

- **Arquivo de Auditoria:** `/var/www/wazuh-soar/data/audit_actions.jsonl`
- **Consultar via API (Últimos 10 registros):**
  ```bash
  curl -u nome-do-usuario https://<seu-servidor>/soar-api/audit-actions?limit=10
  ```
