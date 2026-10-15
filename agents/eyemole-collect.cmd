@echo off
rem Wazuh Active Response wrapper for the read-only EyeMole collector (see eyemole-collect.ps1).
rem The Wazuh agent may run as a 32-bit process on 64-bit Windows: %SystemRoot%\Sysnative reaches the native
rem (64-bit) PowerShell from WOW64; on 32-bit Windows (no Sysnative) System32 is already native.
setlocal
set "EYEMOLE_PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if exist "%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe" set "EYEMOLE_PS=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
"%EYEMOLE_PS%" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0eyemole-collect.ps1"
exit /b %ERRORLEVEL%
