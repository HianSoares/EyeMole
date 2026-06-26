\# EyeMole SOAR — Instalação limpa em produção



\## Fluxo esperado



1\. Clonar o repositório:



```bash

git clone https://github.com/HianSoares/EyeMole.git /opt/eyemole-repo

```



2\. Executar o instalador:



```bash

cd /opt/eyemole-repo

sudo ./install.sh

```



3\. Criar usuário de acesso ao site:



```bash

sudo ./create-web-user.sh nome-do-usuario

```



4\. Acessar o dashboard:



```text

https://SERVIDOR/soar/

```



\## Usuário web



O acesso ao site é protegido por Basic Auth do Nginx.



O usuário é criado em:



```text

/etc/nginx/.htpasswd-wazuh-soar

```



Criar ou alterar senha de um usuário:



```bash

sudo htpasswd /etc/nginx/.htpasswd-wazuh-soar usuario

sudo nginx -t

sudo systemctl reload nginx

```



Esse usuário é apenas para acesso ao dashboard web. Ele não altera usuário Linux, SSH, Wazuh ou GitHub.



