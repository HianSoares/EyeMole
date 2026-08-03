"""
Remediation Guidance Module — EyeMole SOAR (MVP)

Gera orientações de correção copiáveis a partir de templates locais controlados.
NUNCA executa comandos. Campo execution_allowed é constante False.

Invariantes de segurança:
- Nenhum subprocess, os.system, os.popen, eval, exec, shell=True
- Nenhuma escalação de privilégio ou gerenciamento de serviço
- Nenhuma chamada de rede
- Nenhuma criação de processo
- Nenhuma escrita no snapshot
- Nenhum endpoint de execução
- execution_allowed é constante False sem override possível
- Falha fechada: qualquer erro → sem comando
"""

__version__ = "0.1.0"
