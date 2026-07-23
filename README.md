<div align="center">
  <img src="opt/hmg-soar/assets/eyemole.png" alt="EyeMole Logo" width="280"/>

  # EyeMole SOAR

  **Dashboard de gestão de vulnerabilidades para Wazuh, com priorização de risco e contexto de exposição.**

</div>

---

## Índice

- [Instalação](#instalação)
- [Modo seguro (padrão)](#modo-seguro-padrão)
- [Execução manual via web (opt-in)](#execução-manual-via-web-opt-in)
- [Dashboard corporativo](#dashboard-corporativo)
- [Classificação de ativos via web](#classificação-de-ativos-via-web)
- [Documentação](#documentação)

---

## Instalação

```bash
git clone https://github.com/HianSoares/EyeMole.git
cd EyeMole
sudo ./install.sh
sudo ./create-web-user.sh
```

## Modo seguro (padrão)

Por padrão, a instalação roda em **modo seguro**, sem `sudoers` nem `NOPASSWD`:

- A instalação **não cria** `sudoers` nem `NOPASSWD`.
- A geração do relatório ocorre **automaticamente** via `hmg-soar-report.timer`.
- O botão **"Executar análise agora"** fica **desabilitado/oculto** em produção.
- Execução manual, quando necessária, é feita por um administrador via SSH:
```bash
  sudo systemctl start hmg-soar-report.service
```

## Execução manual via web (opt-in)

Para habilitar o botão de execução manual pela interface web (recomendado apenas em ambiente **HMG/lab**):

```bash
sudo ./install.sh --enable-web-run
```

Esse modo usa uma regra **PolicyKit restrita** — **sem** `sudoers`/`NOPASSWD`:

- autoriza apenas o usuário `hmg-soar` a dar `start`
- apenas na unidade `hmg-soar-report.service`
- a API dispara a análise pedindo ao `systemd` (`systemctl start`), então o hardening do serviço (`NoNewPrivileges=yes`) permanece **ativo**

## Dashboard corporativo

A interface web do EyeMole usa um layout de produto SaaS para gestão de vulnerabilidades: sidebar fixa, topbar executiva, filtros visuais, KPIs, gráficos SVG autocontidos, tabelas compactas e modal moderno de contexto de ativos.

O botão **Recarregar Dados** apenas refaz leituras via API/JSON e atualiza a tela — ele não executa análise, não chama `systemctl`, não usa `sudo` e não dispara shell.

## Classificação de ativos via web

A aba **Ativos & Exposição** permite classificar ativos pendentes diretamente pela interface (botão **Classificar**), **sem linha de comando** e **sem privilégio**:

- não usa `sudo`, não cria `sudoers`, não chama `systemctl` nem executa shell;
- apenas edita o JSON local `/opt/hmg-soar/config/assets_context.json`;
- a execução manual via web continua **desabilitada** em produção;
- a priorização é aplicada no próximo relatório automático (timer) ou via SSH:
```bash
  sudo systemctl start hmg-soar-report.service
```
- toda alteração é auditada em `/opt/hmg-soar/audit/audit_actions.jsonl`.

## Documentação

- [Guia de Instalação do EyeMole SOAR](docs/INSTALL_EYEMOLE.md)
- [Hardening de Segurança e Modo de Produção](docs/SECURITY_HARDENING.md)

---

<div align="center">
  <sub>EyeMole SOAR — priorização de risco e contexto de exposição para Wazuh.</sub>
</div>