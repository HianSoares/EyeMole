@echo off
rem Wazuh Active Response wrapper for the read-only EyeMole collector (see eyemole-collect.ps1).
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0eyemole-collect.ps1"
