# Testes de instalação/desinstalação no Windows (Git Bash)

As suítes `tests/test_installation.py` e `tests/test_uninstallation.py`
executam trechos reais de `install.sh` e `uninstall.sh` via Bash. No ambiente de
desenvolvimento Windows (Git Bash) parte delas falha por limitações do ambiente.
**Elas precisam passar em um host Linux de homologação antes de qualquer
implantação** — validação pendente.

## Método de classificação (08/10/2026)

1. Suíte completa no código da branch `fix/remediation-reliability` e, em
   paralelo, no commit de referência `42ac9e4` (worktree isolado, mesmo host).
2. Comparação teste a teste do conjunto de falhas e da assinatura de cada erro.
3. Toda divergência entre as duas árvores reexecutada isoladamente nas duas.

Resultado: 128/150 passaram na branch e 129/150 no `42ac9e4`. As 20 falhas
determinísticas são idênticas nas duas árvores, com a mesma assinatura. As
divergências são timeouts intermitentes que passam isoladamente nas duas
árvores. **Nenhuma regressão identificada.**

## Falhas determinísticas (iguais na branch e em `42ac9e4`)

| Teste | Causa | Evidência |
|---|---|---|
| `test_installation.py::TestOfflineDashboardAndWebValidation::test_32_offline_install_publishes_placeholder_and_succeeds` | Grupo do usuário Windows sem nome no Git Bash | `id: cannot find name for group ID 1049089` |
| `...::test_33_credentials_install_runs_service_and_preserves_real_dashboard` | Idem | Idem |
| `...::test_34_real_report_generation_without_index_html_fails` | Idem | Idem |
| `...::test_35_placeholder_creation_failure_causes_die` | Idem | Idem |
| `...::test_36_reinstall_upgrade_preserves_existing_index_html` | Idem | Idem |
| `...::test_39_heredoc_write_failure_cleans_up_tmp_and_dies` | Idem | Idem |
| `...::test_40_step_failures_clean_up_tmp_and_die[chmod]` | Idem: o script termina antes do passo injetado | `stderr='id: cannot find name for group ID 1049089'`, marcador de `chmod` não criado |
| `...::test_40_step_failures_clean_up_tmp_and_die[chown]` | Idem (mesma asserção de marcador) | Idem |
| `...::test_40_step_failures_clean_up_tmp_and_die[mv]` | Idem (mesma asserção de marcador) | Idem |
| `...::test_41_no_temporary_files_left_over_after_successful_publication` | Grupo sem nome | `id: cannot find name for group ID 1049089` |
| `...::test_45_target_as_directory_fails_and_cleans_up` | Idem | Idem |
| `...::test_46_cleanup_failure_emits_warning_and_preserves_original_error` | Idem | Idem |
| `...::test_37_symlink_index_html_rejected_by_validation_and_placeholder` | Sem privilégio para criar symlink | `OSError: [WinError 1314]` |
| `...::TestCredentialsEnvTemplateAndReadiness::test_49_credentials_env_symlink_fails_closed` | Idem | Idem |
| `test_uninstallation.py::TestSandboxAndInvariants::test_symlink_site_conf_protection_and_restoration` | Idem | Idem |
| `test_uninstallation.py::TestSandboxAndInvariants::test_symlink_site_conf_rollback_preserves_symlink_and_restores_content` | Idem | Idem |
| `test_installation.py::...::test_38_nginx_user_read_permission_failure_causes_die` | Usuário `www-data` inexistente / sem ACL POSIX | `Validação da publicação web falhou: o usuário Nginx 'www-data' não possui permissão de leitura` |
| `...::test_43_nginx_user_missing_causes_die` | Codificação: saída UTF-8 do Bash decodificada em cp1252 | A mensagem esperada é emitida; a comparação de string com acentos falha |
| `...::TestCredentialsEnvTemplateAndReadiness::test_47_credentials_env_auto_creation_when_missing` | NTFS não preserva modo POSIX | `assert '0o666' == '0o640'`; as asserções de conteúdo do `credentials.env` passam |
| `test_uninstallation.py::TestNginxTransaction::test_preserve_mode_htpasswd_validation_and_flow` | Desempenho: excede o limite de 30s do subprocesso também isolado | `subprocess.TimeoutExpired ... timed out after 30 seconds` |

## Timeouts intermitentes (passam isoladamente nas duas árvores)

| Teste | Observação |
|---|---|
| `test_installation.py::TestValidatePython::test_15_syntax_error_in_remediation_fails` | Falhou só na execução paralela da branch; passa isolado nas duas árvores |
| `test_uninstallation.py::TestNginxTransaction::test_final_validation_failure_exit_code` | Idem |
| `test_uninstallation.py::TestNginxTransaction::test_reload_failure_restores_and_aborts` | Falhou só na execução do `42ac9e4`; passa isolado nas duas árvores |
| `test_installation.py::TestValidatePython::test_13_valid_python_passes` e `test_17_import_smoke_test_passes` | Timeout em execução anterior; `test_17` usa módulos-stub sintéticos (não depende do código da aplicação) |

Cada caso de teste dispara vários processos `bash`/`python` com limite fixo de
30s; no Git Bash o custo de criação de processos varia com a carga do host.

## Validação pendente antes da implantação

Executar em host Linux de homologação (não no servidor Wazuh de produção):

```bash
cd opt/hmg-soar && python3 -m pytest -q tests/test_installation.py tests/test_uninstallation.py
```

Critério: 150/150. Qualquer falha em Linux deve ser tratada como possível
regressão, já que as causas acima não se aplicam a esse ambiente.
