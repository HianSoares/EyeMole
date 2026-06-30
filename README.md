## EyeMole SOAR

Instalação padrão (**modo seguro**, sem `sudoers`/`NOPASSWD`):

```bash
git clone https://github.com/HianSoares/EyeMole.git
cd EyeMole
sudo ./install.sh
sudo ./create-web-user.sh
```

No modo seguro:

- A instalação **não cria** `sudoers` nem `NOPASSWD`.
- A geração do relatório ocorre **automaticamente** via `hmg-soar-report.timer`.
- O botão **"Executar análise agora"** fica **desabilitado/oculto** em produção.
- Execução manual, quando necessária, é feita por um administrador via SSH:
  `sudo systemctl start hmg-soar-report.service`.
- Habilitar execução manual via web (apenas HMG/lab):
  `sudo ./install.sh --enable-web-run`.


## Dashboard corporativo

A interface web do EyeMole usa um layout de produto SaaS para gestão de vulnerabilidades: sidebar fixa, topbar executiva, filtros visuais, KPIs, gráficos SVG autocontidos, tabelas compactas e modal moderno de contexto de ativos. O botão **Recarregar Dados** apenas refaz leituras via API/JSON e atualiza a tela; ele não executa análise, não chama `systemctl`, não usa `sudo` e não dispara shell.

## Classificação de ativos via web

A aba **Ativos & Exposição** permite classificar ativos pendentes pela interface
(botão **Classificar**), **sem linha de comando** e **sem privilégio**:

- não usa `sudo`, não cria `sudoers`, não chama `systemctl` nem executa shell;
- apenas edita o JSON local `/opt/hmg-soar/config/assets_context.json`;
- a execução manual via web continua **desabilitada** em produção;
- a priorização é aplicada no próximo relatório automático (timer) ou via SSH:
  `sudo systemctl start hmg-soar-report.service`;
- toda alteração é auditada em `/opt/hmg-soar/audit/audit_actions.jsonl`.

## Documentação

- [Guia de Instalação do EyeMole SOAR](docs/INSTALL_EYEMOLE.md)
- [Hardening de Segurança e Modo de Produção](docs/SECURITY_HARDENING.md)
