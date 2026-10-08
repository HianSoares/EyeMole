# Atualizações do EyeMole

## Primeira instalação e migração

Novas instalações continuam usando o passo a passo do README (`git clone`,
`sudo ./install.sh`, credenciais e usuário web). O instalador adiciona
`/usr/local/bin/eyemole`, controlado por root, sem mudar o processo inicial.

Uma instalação antiga ainda não possui esse comando: baixe esta versão e rode
o instalador **uma vez**, preservando os parâmetros usados na instalação
original. Após isso, as próximas atualizações usam apenas `sudo eyemole update`.
Não é necessário preencher novamente credenciais existentes.

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
5. Pausa os timers de coleta e recusa a troca se uma coleta já estiver ativa.
6. Executa o instalador, preservando `config/`, `output/`, SBOMs, cache,
   credenciais e o marcador de web-run. O instalador verifica API, nginx e
   publicação dos relatórios. A revisão é registrada somente ao final.
7. Retoma os timers que estavam ativos e atualiza o status do painel.

A atualização pode levar alguns minutos e reinicia a API. Os componentes
Wazuh e os agentes não são atualizados por esse comando.

A CLI atende o layout padrão documentado. Instalações com diretórios,
usuário, grupo ou diretório de unidades personalizados devem continuar
usando o instalador com seus parâmetros originais; a CLI recusa aplicá-las
no layout padrão por engano.

## Backup e falhas

Cada aplicação cria um backup privado em
`/opt/backup-eyemole-update-{timestamp}-{id}/`, incluindo aplicação, publicação
web, credenciais, CLI anterior e unidades systemd existentes. O log fica em
`/var/lib/eyemole/updates/update-{id}/install.log`; esses diretórios são privados
do administrador. Backups e logs não são eliminados automaticamente.

Erro de rede, TLS ou validação antes da instalação não altera o código em uso.
Uma falha durante a instalação pode deixar mudanças parciais: **não há rollback
automático**. A CLI mostra backup/log e registra `install_failed`, bloqueando
novas tentativas até a recuperação. Consulte o procedimento em
[OPERATIONS.md](OPERATIONS.md#rollback-de-instalação), restaurando também a
CLI, as unidades e `/etc/hmg-soar/installed-version.json` (da pasta
`credentials/` no backup) conforme
necessário. Não trate o SHA anterior como prova de que o código foi restaurado.

Se a recuperação for feita por uma reinstalação bem-sucedida, o instalador
registra novamente a revisão e remove o estado de falha. Investigue o log
antes de repetir uma instalação com a mesma causa.

```bash
systemctl status eyemole-update-check.timer
journalctl -u eyemole-update-check.service -n 30 --no-pager
```

O desinstalador remove a CLI e as unidades de consulta. Os backups privados
da atualização permanecem para recuperação e podem ser removidos pelo
administrador após validação.
