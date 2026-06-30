\# EyeMole SOAR — Guia de Instalação



\## 1. Objetivo



Este documento descreve o passo a passo para instalar o \*\*EyeMole SOAR\*\* em um servidor Linux com Wazuh/Nginx, publicar o dashboard em `/soar/`, habilitar a API auxiliar em `/soar-api/` e proteger o acesso com autenticação Basic Auth.



Ao final da instalação, o acesso será feito por:



```text

https://<servidor>/soar/

```



\---



\## 2. Pré-requisitos



Antes de iniciar, confirme que o servidor possui:



\* Sistema Linux com `systemd`.

\* Acesso `sudo`.

\* `git` instalado.

\* Nginx instalado ou disponível para instalação.

\* Wazuh Dashboard já publicado via Nginx.

\* Repositório EyeMole acessível pelo servidor.

\* Arquivo de credenciais do ambiente, quando for usar dados reais:



```text

/etc/hmg-soar/credentials.env

```



Observação: caso o arquivo `credentials.env` não exista, o instalador consegue gerar uma estrutura inicial offline/bootstrap, mas a análise real depende das credenciais corretas do ambiente.



\---



\## 3. Clone do repositório



Em um diretório de trabalho do usuário administrador:



```bash

cd \~

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



\---



\## 4. Instalação principal



Dentro da pasta do projeto:



```bash

sudo ./install.sh

```



O instalador executa automaticamente as principais etapas:



\* Instala dependências necessárias, como `python3`, `rsync` e `nginx`, se necessário.

\* Cria usuário e diretórios da aplicação.

\* Copia os arquivos para:



```text

/opt/hmg-soar

```



\* Publica o dashboard em:



```text

/var/www/wazuh-soar

```



\* Cria diretórios de auditoria da API.

\* Instala wrappers seguros em:



```text

/usr/local/sbin/hmg-soar-run-analysis

/usr/local/sbin/hmg-soar-status

```



\* Instala unidades `systemd`.

\* Configura o snippet Nginx para `/soar/` e `/soar-api/`.

\* Recarrega o Nginx.

\* Executa uma primeira geração do relatório, quando possível.

\* Habilita automaticamente:



```text

hmg-soar-api.service

hmg-soar-report.timer

```



\---



\## 5. Criação do usuário web



Após a instalação, crie o usuário de acesso ao painel.



Exemplo com o usuário `admmaster`:



```bash

sudo ./create-web-user.sh admmaster

```



O script solicitará a senha de acesso.



Esse usuário é apenas para autenticação web via Nginx Basic Auth. Ele não precisa ser igual ao usuário Linux, SSH, Wazuh ou GitHub.



Para listar usuários web já cadastrados:



```bash

sudo cut -d: -f1 /etc/nginx/.htpasswd-wazuh-soar

```



\---



\## 6. Acesso ao painel



Após instalar e criar o usuário web, acesse:



```text

https://<servidor>/soar/

```



Exemplo:



```text

https://wazuh-manager-hmg/soar/

```



Informe o usuário e senha criados com:



```bash

sudo ./create-web-user.sh <usuario>

```



\---



\## 7. Validação dos serviços



Após a instalação, valide os serviços principais.



```bash

systemctl status hmg-soar-api.service --no-pager

systemctl status hmg-soar-report.timer --no-pager

systemctl list-timers --all | grep hmg-soar || true

```



O esperado para a API é algo como:



```text

Active: active (running)

```



O esperado para o timer é algo como:



```text

Active: active (waiting)

Trigger: ...

```



\---



\## 8. Validação da API de status



Teste o endpoint `/soar-api/status` sem expor a senha no histórico do terminal:



```bash

read -s -p "Senha web: " SOAR\_PASS

echo



curl -k -s -u "admmaster:${SOAR\_PASS}" https://127.0.0.1/soar-api/status | python3 -m json.tool



unset SOAR\_PASS

```



Troque `admmaster` pelo usuário web criado no ambiente.



Resultado esperado:



```json

{

&#x20; "report\_status\_label": "Pronto (Ocioso)",

&#x20; "timer\_status\_label": "Ativo",

&#x20; "wrapper\_exit\_code": 0

}

```



Também deve existir um bloco parecido com:



```json

"timer\_info": {

&#x20; "active\_state": "active",

&#x20; "sub\_state": "waiting"

}

```



\---



\## 9. Interpretação correta dos status



Na aba \*\*Status \& Auditoria\*\*, o comportamento esperado é:



```text

API SOAR: Online

Serviço de relatório: Pronto (Ocioso)

Agendamento: Ativo

Último Exit Code: 0

```



Observação importante:



O serviço `hmg-soar-report.service` é pontual. Ele executa, gera o relatório e finaliza. Por isso, no `systemctl`, ele pode aparecer como:



```text

inactive (dead)

status=0/SUCCESS

```



Isso não é erro.



A interpretação correta é:



```text

inactive/dead + wrapper\_exit\_code 0 = Pronto (Ocioso)

```



\---



\## 10. Executar análise manual



A análise pode ser executada diretamente pelo botão do painel:



```text

Status \& Auditoria > Executar análise agora

```



Após executar, clique em:



```text

Atualizar status

```



Também é possível validar pelo log de auditoria do painel, onde a execução deve aparecer como sucesso.



\---



\## 11. Definir responsáveis e criticidade dos ativos



Para enriquecer o dashboard com dono técnico, dono de negócio, criticidade e ambiente, use:



```bash

sudo ./set-asset-context.sh <agent\_id> \\

&#x20; --technical-owner "Equipe Técnica" \\

&#x20; --business-owner "Área de Negócio" \\

&#x20; --criticality critical \\

&#x20; --environment hmg

```



Exemplo:



```bash

sudo ./set-asset-context.sh 001 \\

&#x20; --technical-owner "Equipe Windows" \\

&#x20; --business-owner "Sistemas" \\

&#x20; --criticality critical \\

&#x20; --environment hmg

```



Depois gere novamente o relatório:



```bash

sudo systemctl restart hmg-soar-report.service

```



\---



\## 12. Atualização do EyeMole



Para atualizar uma instalação existente:



```bash

cd \~/EyeMole

git pull --ff-only origin main

sudo ./install.sh

```



Depois valide novamente:



```bash

systemctl status hmg-soar-api.service --no-pager

systemctl status hmg-soar-report.timer --no-pager

```



\---



\## 13. Troubleshooting



\### 13.1 Erro 401 Unauthorized



Causa provável: usuário ou senha Basic Auth incorretos.



Ver usuários cadastrados:



```bash

sudo cut -d: -f1 /etc/nginx/.htpasswd-wazuh-soar

```



Criar ou redefinir senha:



```bash

sudo ./create-web-user.sh <usuario>

```



\---



\### 13.2 API retornando 502



Causa provável: serviço da API parado ou com erro.



Valide:



```bash

systemctl status hmg-soar-api.service --no-pager

sudo journalctl -u hmg-soar-api.service -n 80 --no-pager

```



Tente reiniciar:



```bash

sudo systemctl restart hmg-soar-api.service

```



\---



\### 13.3 Agendamento aparece inativo



Valide o timer:



```bash

systemctl status hmg-soar-report.timer --no-pager

systemctl list-timers --all | grep hmg-soar || true

```



Ative novamente:



```bash

sudo systemctl enable --now hmg-soar-report.timer

```



O esperado é:



```text

Active: active (waiting)

```



\---



\### 13.4 Serviço de relatório aparece inactive/dead



Isso é normal quando o último exit code é `0`.



Valide:



```bash

systemctl status hmg-soar-report.service --no-pager

```



Se aparecer:



```text

inactive (dead)

status=0/SUCCESS

```



Então o serviço rodou corretamente e finalizou.



No painel, isso deve aparecer como:



```text

Pronto (Ocioso)

```



\---



\### 13.5 Arquivo credentials.env ausente



Se o arquivo abaixo não existir:



```text

/etc/hmg-soar/credentials.env

```



O instalador poderá gerar um bootstrap inicial, mas a análise real do ambiente dependerá da criação do arquivo de credenciais correto.



Após criar ou corrigir o arquivo, rode:



```bash

sudo ./install.sh

sudo systemctl restart hmg-soar-report.service

```



\---



\## 14. Caminhos importantes



Aplicação instalada:



```text

/opt/hmg-soar

```



Dashboard publicado:



```text

/var/www/wazuh-soar

```



Credenciais do ambiente:



```text

/etc/hmg-soar/credentials.env

```



Arquivo de usuários web:



```text

/etc/nginx/.htpasswd-wazuh-soar

```



Snippet Nginx:



```text

/etc/nginx/snippets/eyemole-soar-locations.conf

```



Serviço da API:



```text

hmg-soar-api.service

```



Serviço de relatório:



```text

hmg-soar-report.service

```



Timer de execução automática:



```text

hmg-soar-report.timer

```



\---



\## 15. Fluxo resumido de instalação



```bash

git clone https://github.com/HianSoares/EyeMole.git

cd EyeMole

sudo ./install.sh

sudo ./create-web-user.sh <usuario>

```



Exemplo:



```bash

git clone https://github.com/HianSoares/EyeMole.git

cd EyeMole

sudo ./install.sh

sudo ./create-web-user.sh admmaster

```



Acesso final:



```text

https://<servidor>/soar/

```



Resultado esperado no painel:



```text

API SOAR: Online

Serviço de relatório: Pronto (Ocioso)

Agendamento: Ativo

Último Exit Code: 0

```

---

## Segurança e modo de produção (importante)

A instalação **padrão é o modo seguro**: o `install.sh` **não cria**
`/etc/sudoers.d/hmg-soar-api` nem regras `NOPASSWD`. Consequências:

- A **execução automática** do relatório continua funcionando via
  `hmg-soar-report.timer` (habilitado pelo root durante a instalação).
- O botão **"Executar análise agora"** do dashboard pode aparecer
  **desabilitado/oculto** em produção (modo seguro).
- A **execução manual**, quando necessária, é feita por um administrador via SSH:
  `sudo systemctl start hmg-soar-report.service`.
- O endpoint `/soar-api/status` continua funcionando (status lido por
  `systemctl show`, sem `sudo`). O endpoint `/soar-api/run-analysis` responde
  `403` no modo seguro.

Habilitar a execução manual via web **apenas em ambiente controlado (HMG/lab)**:

```bash
EYEMOLE_ENABLE_WEB_RUN=1 sudo ./install.sh
# ou
sudo ./install.sh --enable-web-run
```

Detalhes completos (hardening systemd/Nginx, permissões, validação, riscos e
rollback) em [docs/SECURITY_HARDENING.md](SECURITY_HARDENING.md).

---

## Classificação de ativos pela interface web

Os ativos pendentes podem ser classificados **diretamente pela web**, sem a
linha de comando, na aba **Ativos & Exposição**:

1. abra a aba **Ativos & Exposição**;
2. na tabela **Ativos Pendentes de Classificação**, clique em **Classificar**;
3. preencha criticidade, ambiente, exposição, donos, serviço crítico e
   observações;
4. clique em **Salvar classificação**.

Após salvar, o ativo sai da lista de pendentes e aparece a mensagem:
*"Contexto salvo. A priorização completa será refletida no próximo relatório
automático ou após execução manual via SSH."*

Importante:

- A classificação via web **não usa sudo**, **não cria sudoers** e **apenas
  edita** o JSON local `/opt/hmg-soar/config/assets_context.json`.
- A **execução manual via web continua desabilitada** em produção (modo seguro).
- O **relatório automático** (timer `hmg-soar-report.timer`) aplica a
  priorização; se necessário antes disso, um administrador pode rodar via SSH:
  `sudo systemctl start hmg-soar-report.service`.
- Toda alteração de contexto é auditada em
  `/opt/hmg-soar/audit/audit_actions.jsonl`.

O script `set-asset-context.sh` continua disponível para uso por CLI. Ajuda:
`sudo ./set-asset-context.sh --help` (não cria nenhum ativo chamado `--help`).

