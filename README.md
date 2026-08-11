<div align="center">

  <img
    src="opt/hmg-soar/assets/eyemole.png"
    alt="Logotipo do EyeMole"
    width="460"
  />

  # EyeMole SOAR

  **Gestão, contextualização e priorização de vulnerabilidades para ambientes Wazuh.**

  O EyeMole transforma achados técnicos do Wazuh em uma visão operacional de risco, combinando severidade, KEV, EPSS, exposição, criticidade dos ativos, SLA e contexto de tratamento.

</div>

---

## Visão geral

O EyeMole SOAR é uma aplicação web para gestão de vulnerabilidades integrada ao Wazuh.

O projeto coleta os achados do ambiente, aplica regras de priorização e publica um dashboard executivo com informações para apoiar decisões de correção.

Entre os principais recursos estão:

- Risk Command Center com score contextual;
- contagem de CVEs únicas e achados por severidade;
- priorização por CISA KEV e EPSS;
- sinais independentes de risco;
- Panorama de Risco integrado;
- fluxo Sankey por severidade, prioridade e agentes;
- contexto de ativos e exposição;
- controle de SLA e backlog;
- tendências históricas;
- classificação de ativos pela interface;
- API local protegida;
- auditoria das alterações de contexto;
- operação automática por `systemd timer`;
- modo seguro sem `sudoers` ou `NOPASSWD`.

---

## Arquitetura resumida

```text
Wazuh Indexer
      │
      ▼
analyserV1.py
      │
      ├── Relatórios CSV/HTML/JSON
      ├── Snapshot do dashboard
      └── Histórico operacional
      │
      ▼
/var/www/wazuh-soar
      │
      ├── Dashboard web
      └── Dados publicados
      │
      ▼
Nginx + autenticação HTTP
```

A API local do EyeMole fornece os dados dinâmicos usados pelas abas, gráficos, tabelas, contexto de ativos e indicadores operacionais.

---

## Funcionalidades

### Dashboard executivo

A aba Dashboard apresenta:

- Risk Score Contextual;
- CVEs únicas;
- vulnerabilidades críticas e altas;
- CISA KEV;
- EPSS acima do limiar configurado;
- ativos expostos;
- ativos sem classificação;
- backlog e SLA;
- Sinais de Risco e Priorização;
- Panorama de Risco integrado;
- Top 10 de prioridades de tratativa.

### Vulnerabilidades

A aba Vulnerabilidades oferece:

- filtros por agente, severidade, criticidade, exposição, ambiente e status;
- classificação por prioridade;
- busca por CVE, pacote ou agente;
- exportação CSV filtrada;
- diagrama Sankey por severidade, prioridade e agentes;
- lista detalhada de achados priorizados.

### Ativos e exposição

Permite acompanhar:

- criticidade dos ativos;
- nível de exposição;
- ambiente;
- serviço crítico;
- ativos pendentes de classificação;
- superfície de ataque;
- ativos externos autorizados sem agente Wazuh.

### Tratamento e SLA

Apresenta:

- itens vencidos;
- itens próximos do vencimento;
- backlog por ativo;
- backlog por responsável;
- aging;
- recorrência;
- ações recomendadas;
- plano de tratativa.

### Tendências e inteligência

Inclui:

- evolução do total de vulnerabilidades;
- críticas e altas;
- cumprimento de SLA;
- backlog acionável;
- ativos com melhora ou piora de risco;
- CVEs persistentes;
- histórico de risco aceito e exceções.

---

## Requisitos

- Linux com `systemd`;
- Python 3;
- Nginx;
- acesso ao Wazuh Indexer;
- certificados e credenciais válidos;
- privilégios administrativos para instalação;
- usuário web para acesso ao dashboard.

---

## Instalação

Clone o repositório:

```bash
git clone https://github.com/HianSoares/EyeMole.git
cd EyeMole
```

Instale no modo seguro padrão:

```bash
sudo ./install.sh
```

Configure as credenciais em `/etc/hmg-soar/credentials.env` (criado automaticamente):

```bash
sudo nano /etc/hmg-soar/credentials.env
```

Preencha as senhas `OPENSEARCH_PASS` e `WAZUH_API_PASS`.

Crie o usuário de acesso web:

```bash
sudo ./create-web-user.sh <usuario>
```

Após a instalação, acesse:

```text
https://<servidor>/soar/
```

Consulte o guia completo:

- [Instalação detalhada](docs/INSTALL_EYEMOLE.md)
- [Hardening e produção](docs/SECURITY_HARDENING.md)

---

## Modo seguro — padrão recomendado

Por padrão, o EyeMole opera sem execução manual pela interface web.

Nesse modo:

- não cria regras em `sudoers`;
- não utiliza `NOPASSWD`;
- não permite execução de comandos arbitrários;
- não permite execução manual da análise pela interface;
- mantém `NoNewPrivileges=yes`;
- executa os relatórios automaticamente pelo timer;
- permite execução administrativa via SSH.

Execução manual pelo servidor:

```bash
sudo systemctl start hmg-soar-report.service
```

Verificação do timer:

```bash
systemctl status hmg-soar-report.timer
```

Esse é o modo recomendado para produção.

---

## Execução manual via web — opt-in

Em ambientes controlados de homologação ou laboratório, a execução manual pela interface pode ser habilitada com:

```bash
sudo ./install.sh --enable-web-run
```

Esse modo:

- não cria `sudoers`;
- não utiliza `NOPASSWD`;
- usa uma regra PolicyKit restrita;
- autoriza somente o usuário de serviço do EyeMole;
- autoriza somente o início de `hmg-soar-report.service`;
- mantém o hardening da unidade `systemd`.

> A execução manual via web deve ser habilitada apenas após avaliação de segurança do ambiente.

Executar novamente o instalador sem `--enable-web-run` retorna a instalação ao modo seguro.

---

## Atualização dos dados

O botão **Recarregar Dados da API**:

- consulta novamente os endpoints locais;
- atualiza tabelas, indicadores e gráficos;
- não inicia uma nova análise;
- não executa shell;
- não chama `systemctl`;
- não utiliza `sudo`.

Uma nova coleta acontece:

- automaticamente pelo timer;
- manualmente por um administrador via SSH;
- pela interface apenas quando o modo web-run estiver habilitado.

---

## Classificação de ativos

A aba **Ativos & Exposição** permite classificar ativos pendentes diretamente pela interface.

A classificação pode registrar:

- criticidade;
- exposição;
- ambiente;
- responsável;
- serviço crítico;
- contexto operacional.

A operação:

- não usa `sudo`;
- não executa shell;
- não chama `systemctl`;
- altera apenas os arquivos JSON de contexto autorizados;
- registra a ação no log de auditoria.

Arquivo de contexto:

```text
/opt/hmg-soar/config/assets_context.json
```

Log de auditoria:

```text
/opt/hmg-soar/audit/audit_actions.jsonl
```

As alterações passam a influenciar integralmente a priorização no próximo relatório.

---

## Serviços

API local:

```bash
systemctl status hmg-soar-api.service
```

Timer de geração:

```bash
systemctl status hmg-soar-report.timer
```

Última execução:

```bash
systemctl status hmg-soar-report.service
```

Logs da API:

```bash
journalctl -u hmg-soar-api.service
```

Logs do relatório:

```bash
journalctl -u hmg-soar-report.service
```

O serviço de relatório é do tipo `oneshot`. Por isso, após concluir corretamente, ele pode aparecer como:

```text
inactive (dead)
```

com o resultado:

```text
status=0/SUCCESS
```

---

## Segurança

O EyeMole foi projetado para operar com privilégios mínimos.

Princípios aplicados:

- sem `sudoers` no modo padrão;
- sem `NOPASSWD`;
- PolicyKit restrito no modo web-run;
- API local;
- autenticação HTTP no Nginx;
- credenciais fora do diretório público;
- arquivos de contexto com permissões controladas;
- validação e escape de dados no frontend;
- auditoria das alterações;
- execução automática por unidades `systemd`;
- proteção contra execução arbitrária de comandos.

Nunca publique no Git:

- `credentials.env`;
- senhas;
- certificados privados;
- tokens;
- relatórios reais;
- inventários internos;
- dados de agentes;
- arquivos de contexto do ambiente;
- logs de auditoria reais.

Consulte:

- [Hardening de segurança](docs/SECURITY_HARDENING.md)

---

## Orientação de Correção (Remediation Guidance)

O EyeMole oferece orientação de correção para achados de vulnerabilidade, apresentando sugestões de comandos e procedimentos ao operador.

### Princípios de segurança

- **Interface somente cópia (copy-only):** o sistema nunca executa comandos automaticamente. O operador visualiza a orientação e pode copiar manualmente o conteúdo.
- **Sem execução pelo sistema:** nenhum comando é disparado pelo backend, pela API ou pela interface web. O campo `execution_allowed` é sempre `false`, imposto pelo backend.
- **Gating por confiança:** orientações com comandos são exibidas apenas quando o nível de confiança é `high` ou `medium`. Achados com confiança `low` recebem apenas texto descritivo.
- **Auditoria de ações:** toda visualização e cópia de orientação é registrada no log de auditoria com timestamp, usuário e ação realizada (`view` ou `copy`).

### Dependências de runtime

O serviço requer Python 3 com os módulos `requests` e `urllib3`. O instalador verifica e instala automaticamente os pacotes do sistema (`python3-requests`, `python3-urllib3`) em Debian/Ubuntu. Em outros sistemas, instale manualmente antes de executar `install.sh`.

Node.js **não** é necessário em produção — é usado apenas para validação de sintaxe JavaScript durante o desenvolvimento.

### Instalação de configurações padrão

- Em uma **instalação nova (fresh install)**, os arquivos de configuração padrão são instalados automaticamente em `/opt/hmg-soar/config/`:
  - `generic_update_policy.json`
  - `remediation_allowlist.json`
  - `remediation_providers.json`
  - `remediation_templates.json`
  - `risk_acceptance.json`
  - `sla_policy.json`
  - `treatment_policy.json`
- Em uma **atualização**, configurações existentes são preservadas (nunca sobrescritas).

### Endpoints da API

| Método | Rota | Descrição |
|---|---|---|
| GET | `/soar-api/remediation-guidance/<finding_id>` | Retorna a orientação de correção para um achado |
| POST | `/soar-api/remediation-guidance/<guidance_id>/audit` | Registra ação de auditoria (body: `{"action":"copy"}`) |

A API escuta somente em `127.0.0.1:8765` (loopback). O acesso externo é mediado pelo proxy Nginx com Basic Auth.

### Riscos residuais

- **Confiança no header X-Remote-User:** a identidade do operador é extraída do header injetado pelo Nginx. Processos locais com acesso à porta 8765 podem forjar esse header.
- **Sem autorização granular:** qualquer usuário autenticado no proxy pode consultar orientações e registrar ações de auditoria. Não há controle por papel (role) ou por escopo de ativos.

---

## Desinstalação

O EyeMole inclui um desinstalador oficial, seguro e idempotente:

```bash
# Visualizar ações sem executar
sudo ./uninstall.sh --dry-run

# Desinstalar preservando dados (configs, auditoria, relatórios)
sudo ./uninstall.sh

# Desinstalar removendo todos os dados (exige confirmação)
sudo ./uninstall.sh --purge

# Desinstalar e remover o usuário de serviço
sudo ./uninstall.sh --purge --yes --remove-user
```

Comportamento:
- **Modo padrão:** remove código, serviços e integração Nginx; preserva seletivamente dados de estado (configs, auditoria, relatórios, credentials, htpasswd) em `/var/lib/eyemole-preserved/`
- **Modo purge:** remove tudo após backup e confirmação explícita ("PURGE EYEMOLE")
- **Não remove:** Nginx, Python, Wazuh, www-data, pacotes do sistema, backups anteriores
- **Não preserva:** código Python, módulos de remediação, HTML publicado, assets estáticos
- **Backup:** criado automaticamente antes de qualquer alteração em `/opt/backup-eyemole-uninstall-<timestamp>/`
- **Rollback Nginx:** se `nginx -t` falhar após edição, a configuração é restaurada automaticamente

---

## Estrutura do projeto

```text
EyeMole/
├── docs/                  # Documentação
├── nginx/                 # Configurações do Nginx
├── opt/hmg-soar/          # Aplicação principal
├── systemd/               # Serviços e timers
├── create-web-user.sh     # Criação do usuário HTTP
├── install.sh             # Instalador
├── set-asset-context.sh   # Gestão de contexto
├── CHANGELOG.md           # Histórico de versões
└── README.md
```

---

## Desenvolvimento e preview

O projeto contém uma infraestrutura local de preview com dados fictícios.

Gerar o HTML:

```bash
python3 opt/hmg-soar/preview_dashboard.py
```

Iniciar o servidor mock:

```bash
python3 opt/hmg-soar/preview_server.py --port 8088
```

Abrir:

```text
http://127.0.0.1:8088/index.html
```

Os dados usados no preview são fictícios e não representam o ambiente real.

---

## Validação

Antes de enviar alterações:

```bash
python3 -m py_compile opt/hmg-soar/analyserV1.py
git diff --check
```

Também deve ser validada a sintaxe do JavaScript incorporado no `HTML_TEMPLATE`.

Nenhuma alteração deve ser implantada sem:

- revisão do diff;
- validação Python;
- validação JavaScript;
- teste do preview;
- smoke test no ambiente de homologação.

---

## Documentação

### Comece aqui

- [Guia do usuário](docs/USER_GUIDE.md)
- [Roteiro de demonstração](docs/DEMO_GUIDE.md)
- [Glossário](docs/GLOSSARY.md)

### Referência técnica

- [Referência do dashboard](docs/DASHBOARD_REFERENCE.md)
- [Métricas e fórmulas](docs/METRICS_AND_SCORING.md)
- [Arquitetura](docs/ARCHITECTURE.md)

### Administração e operação

- [Instalação](docs/INSTALL_EYEMOLE.md)
- [Operação](docs/OPERATIONS.md)
- [Segurança e hardening](docs/SECURITY_HARDENING.md)

### Histórico

- [Changelog](CHANGELOG.md)
- [Arquivo de documentos legados](docs/archive/README.md)

---

## Status do projeto

O EyeMole está em evolução ativa.

Mudanças relevantes devem ser registradas no `CHANGELOG.md` e publicadas por versão ou tag após validação em homologação.

---

<div align="center">

  **EyeMole SOAR**

  Priorização de risco, exposição e contexto de ativos para ambientes Wazuh.

</div>