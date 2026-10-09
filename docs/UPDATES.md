# Atualizações do EyeMole

## Primeira instalação e migração

Novas instalações continuam usando o passo a passo do README (`git clone`,
`sudo ./install.sh`, credenciais e usuário web). O instalador adiciona
`/usr/local/bin/eyemole`, controlado por root, sem mudar o processo inicial.

Uma instalação antiga ainda não possui esse comando: baixe esta versão e rode
o instalador **uma vez**, preservando os parâmetros usados na instalação
original. Após isso, as próximas atualizações usam apenas `sudo eyemole update`.
Não é necessário preencher novamente credenciais existentes.

A primeira atualização executada pela CLI anterior ainda usa o mecanismo de
recuperação dessa CLI: a recuperação automática descrita abaixo passa a valer
**depois** de instalada esta versão. O novo instalador cria o snapshot comprimido
mesmo nessa migração e inicia o worker ao concluir; consulte a localização real
do snapshot no log do instalador.

## Aviso e comandos

```bash
eyemole version       # SHA do código instalado
eyemole check-update  # consulta agora, sem instalar ou exigir sudo
sudo eyemole update   # aplica a atualização
```

O canal é a branch `main` de `HianSoares/EyeMole`: qualquer novo commit no
histórico da instalação conta como nova revisão. Não são versões semânticas
nem releases de teste. Um checkout divergente, modificado ou mais novo que a
`main` não é sobrescrito.

O timer `eyemole-update-check.timer` consulta o GitHub às 08h e 20h no fuso do
servidor, com até 15 minutos de atraso aleatório. Usa apenas metadados públicos
do repositório; não transmite credenciais, ativos, CVEs ou relatórios.
O resultado local fica em `/var/www/wazuh-soar/data/update_status.json` e é
lido por `GET /soar-api/update-status`. O painel consulta esse endpoint ao
abrir e a cada minuto; não contata o GitHub diretamente.

Resultados com mais de 48 horas, falta de rede, limite da API GitHub ou JSON
inválido não são apresentados como uma instalação atualizada. A consulta
**não instala** código, e a API não possui endpoint de instalação.

## O que o update faz

1. Exige root e bloqueia uma segunda atualização simultânea.
2. Consulta a `main` e confirma que ela descende da revisão instalada.
3. Verifica conectividade e confiança TLS do Indexer e da API Wazuh como o
   usuário do serviço, sem autenticar nem enviar senhas. CA personalizada é
   necessária apenas se os certificados não forem confiáveis pelo sistema;
   precisa ser legível pelo serviço e o nome/IP precisa corresponder ao SAN.
   Um opt-in de laboratório já configurado é preservado, nunca ativado sozinho.
4. Clona o repositório fixo com TLS normal e checkout do SHA verificado;
   valida a sintaxe Bash/Python antes da implantação.
5. Verifica espaço para backup e restauração; recusa jobs/coletas ativos; pausa
   timers e processos que alteram os dados.
6. Cria e verifica um snapshot comprimido privado; executa o instalador preservando
   configurações, dados, credenciais e web-run. A revisão é registrada ao final.
7. Em falha de instalação, restaura o snapshot e valida Nginx. Se a recuperação
   falhar, mantém a manutenção e bloqueia novas atualizações.
8. Em sucesso, retoma os serviços/timers, atualiza o aviso e aplica retenção aos
   snapshots bem-sucedidos e relatórios históricos conforme a política.

A atualização pode levar alguns minutos e reinicia a API. Os componentes
Wazuh e os agentes não são atualizados por esse comando.

A CLI atende o layout padrão documentado. Instalações com diretórios,
usuário, grupo ou diretório de unidades personalizados devem continuar
usando o instalador com seus parâmetros originais; a CLI recusa aplicá-las
no layout padrão por engano.

## Backup e falhas

No layout padrão, snapshots ficam em `/var/backups/eyemole/eyemole-snapshot-*`,
com `snapshot.tar.gz` e manifesto SHA-256 privados. O destino pode ser alterado
em `/etc/hmg-soar/update-policy.json`. O log do update permanece em
`/var/lib/eyemole/updates/update-*/install.log`. O checkout inicial pode continuar
em `/EyeMole`; o updater usa staging privado persistente, sem depender de `/tmp`.

O snapshot inclui aplicação, publicação web, configuração e credenciais,
CLI/helper anteriores, base da plataforma, unidades gerenciadas e `/etc/nginx`.
**A recuperação restaura também a configuração completa do Nginx** capturada
naquele instante. Não execute mudanças paralelas de outros sites durante o update.
ACLs e atributos estendidos são preservados; recuperação de ACL exige `setfacl`
(pacote `acl`, instalado como dependência). Links para fora dos caminhos gerenciados
ou arquivos especiais bloqueiam o snapshot antes de instalar.

Falha antes da instalação não altera o código. Falha durante a instalação tenta
recuperação automática. Falha da própria recuperação mantém
`/run/eyemole-recovery-required` e exige intervenção. Não remova esse marcador
para ignorar um estado parcial. A recuperação manual é:

```bash
sudo eyemole rollback /var/backups/eyemole/eyemole-snapshot-SEU_SNAPSHOT
sudo eyemole doctor
```

Verifique o log antes de repetir. O comando de rollback verifica o snapshot e
espaço para staging, restaura os caminhos gerenciados e recarrega o Nginx; não
atualiza Wazuh nem os agentes. Arquivos externos a esses caminhos não são
restaurados. A criação de contas Linux pelo instalador também não é revertida.

A retenção conserva pelo menos dois snapshots bem-sucedidos, além de snapshots
preparados, falhos/restaurados e backups antigos. Limites de tamanho são metas:
se os backups protegidos excederem o limite, eles permanecem e exigem análise
administrativa. Backups históricos `/opt/backup-eyemole-*` não são apagados
por essa política. Relatórios históricos conservam pelo menos dois arquivos;
`latest.json` e o relatório atual não são candidatos.

```bash
sudo eyemole doctor              # serviços, disco, coleta e TLS
sudo eyemole status --json       # diagnóstico estruturado
sudo eyemole cleanup             # mostra candidatos, sem apagar
sudo eyemole cleanup --apply     # aplica a política configurada
```

O instalador direto usa snapshot comprimido para atualização de layout padrão,
mas a recuperação automática e a pausa coordenada são funções do `eyemole update`.
Instalações personalizadas usam seus parâmetros e backup compatível; a CLI continua
recusando atualizar um layout diferente.

```bash
systemctl status eyemole-update-check.timer
journalctl -u eyemole-update-check.service -n 30 --no-pager
```

O desinstalador remove a CLI e as unidades de consulta. Os backups privados
da atualização permanecem para recuperação e podem ser removidos pelo
administrador após validação.
