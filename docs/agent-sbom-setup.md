# EyeMole Agent SBOM Setup

This guide installs the agent-side SBOM push scripts for EyeMole SOAR. The values below that mention a concrete hostname are examples from one validation environment; replace them with the HTTPS hostname of your own Wazuh/EyeMole installation.

EyeMole does not execute remote commands on agents. Each agent runs Syft locally, generates a CycloneDX JSON SBOM, and uploads it to:

```text
https://<your-wazuh-hostname>/soar-api/sbom/<agent_id>
```

The SBOM filename contract on the server side is still exact: uploads are stored as `{agent_id}.json`, without suffixes.

## Server Preparation

Generate one token per Wazuh agent on the EyeMole server:

```bash
cd /opt/hmg-soar
sudo python3 generate_agent_token.py 001
sudo python3 generate_agent_token.py 003
sudo python3 generate_agent_token.py 004
sudo python3 generate_agent_token.py 005
```

Copy each cleartext token once to its matching agent. The token is not recoverable from `assets_context.json` because only the SHA-256 hash is stored.

For Linux installation, prefer `--token-file` over `--token`. Passing the token directly on the command line can expose it briefly through `ps aux` and may save it in shell history.

## TLS Certificate

Most Wazuh Dashboard installations use a self-signed certificate by default. If that is your case, copy the public certificate to each agent and configure the optional CA certificate path.

Example for one environment:

```text
https://wazuh-manager-hmg.tre-pr.jus.br
```

This hostname is illustrative only. Other EyeMole installations must use their own hostname.

If your Wazuh Dashboard already uses a certificate issued by a public CA trusted by the agent OS, leave `CA_CERT_PATH` or `CaCertPath` empty.

## Linux Agents

Use the Linux script on agents `003`, `004`, and `005`.

Install Syft using Anchore's official installer:

```bash
curl -sSfL https://get.anchore.io/syft | sudo sh -s -- -b /usr/local/bin
syft version
```

After copying this repository or the `agent-scripts/linux/` directory from a Windows workstation, restore executable bits before use:

```bash
chmod +x agent-scripts/linux/*.sh
```

Install the EyeMole SBOM task. Ubuntu and Debian default to `dir:/var/lib/dpkg`; Rocky/RHEL defaults to `dir:/var/lib/rpm`.

Example for agent `003`:

```bash
sudo install -m 0600 -o root -g root /tmp/eyemole-agent-003.token /etc/eyemole-agent-token-003
sudo ./agent-scripts/linux/install-agent-script.sh \
  --agent-id 003 \
  --server-url https://wazuh-manager-hmg.tre-pr.jus.br \
  --token-file /etc/eyemole-agent-token-003 \
  --ca-cert /etc/eyemole-agent/wazuh-dashboard.crt
rm /tmp/eyemole-agent-003.token
```

Example for Rocky/RHEL agent `005`:

```bash
sudo install -m 0600 -o root -g root /tmp/eyemole-agent-005.token /etc/eyemole-agent-token-005
sudo ./agent-scripts/linux/install-agent-script.sh \
  --agent-id 005 \
  --server-url https://wazuh-manager-hmg.tre-pr.jus.br \
  --token-file /etc/eyemole-agent-token-005 \
  --ca-cert /etc/eyemole-agent/wazuh-dashboard.crt \
  --scan-target dir:/var/lib/rpm
rm /tmp/eyemole-agent-005.token
```

The initial scan scope is intentionally reduced to package database directories. Expand to `dir:/` only after measuring runtime and CPU on at least one real agent.

Validate manually:

```bash
sudo systemctl status eyemole-sbom.timer
sudo systemctl start eyemole-sbom.service
sudo journalctl -u eyemole-sbom.service -n 100 --no-pager
sudo tail -n 100 /var/log/eyemole-agent/sbom-upload.log
```

## Windows Agent

Use the Windows scripts on agent `001`.

Windows Server 2019 includes `curl.exe` by default. Verify it first:

```powershell
curl.exe --version
```

Install Syft by downloading the Windows release archive directly from GitHub Releases:

```powershell
New-Item -ItemType Directory -Force -Path "C:\Program Files\EyeMoleAgent" | Out-Null
# Download the latest syft Windows amd64 zip from:
# https://github.com/anchore/syft/releases
# Extract syft.exe to:
# C:\Program Files\EyeMoleAgent\syft.exe
& "C:\Program Files\EyeMoleAgent\syft.exe" version
```

The definitive default Syft path used by the Windows installer is `C:\Program Files\EyeMoleAgent\syft.exe`.

Run the installer from an elevated PowerShell session:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\agent-scripts\windows\Install-EyeMoleSbomTask.ps1 `
  -AgentId "001" `
  -EyeMoleSoarUrl "https://wazuh-manager-hmg.tre-pr.jus.br" `
  -Token "<token-generated-for-agent-001>" `
  -CaCertPath "C:\ProgramData\EyeMoleAgent\wazuh-dashboard.crt"
```

The default Windows scan scope is:

```text
C:\Program Files
C:\Program Files (x86)
```

Expand to a full `C:\` scan only after measuring runtime and CPU on the real Windows Server.

Validate manually:

```powershell
Get-ScheduledTask -TaskName "EyeMole SBOM Upload"
Start-ScheduledTask -TaskName "EyeMole SBOM Upload"
Get-Content "C:\ProgramData\EyeMoleAgent\logs\sbom-upload.log" -Tail 100
```

## Server Validation

After an agent upload, verify the server queue and Grype output:

```bash
sudo ls -l /opt/hmg-soar/sbom/pending
sudo systemctl start hmg-soar-grype.service
sudo python3 -m json.tool /opt/hmg-soar/output/grype_latest.json | head -n 80
```

The Nginx route `/soar-api/sbom/<agent_id>` is intentionally unauthenticated at the HTTP Basic Auth layer. Authentication happens inside `soar_api.py` with the agent Bearer token.
