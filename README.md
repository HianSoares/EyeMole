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

## Documentação

- [Guia de Instalação do EyeMole SOAR](docs/INSTALL_EYEMOLE.md)
- [Hardening de Segurança e Modo de Produção](docs/SECURITY_HARDENING.md)
