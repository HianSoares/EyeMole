"""
Providers para o módulo de Remediation Guidance.

Cada provider é um módulo plugável que consulta uma fonte de dados
para enriquecer a orientação de correção. No MVP, apenas WazuhProvider
está implementado.

Invariantes:
- Nenhum provider executa subprocess, os.system, eval, exec
- Nenhum provider faz chamadas de rede
- Nenhum provider modifica o snapshot
- Nenhum provider inventa dados não existentes
"""
