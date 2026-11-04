@echo off
title CRIPTEX - Cofre Digital Windows
cd /d "%~dp0"

echo ============================================================================
echo  CRIPTEX - Cofre Digital Windows (Cifra de Vigenere + Pen USB + Biometria)
echo ============================================================================

if exist ".venv\Scripts\python.exe" goto RUN_APP

echo.
echo [1/2] Primeiro arranque detetado: A criar ambiente virtual Python (.venv)...
python -m venv .venv
if exist ".venv\Scripts\python.exe" goto INSTALL_DEPS

py -3 -m venv .venv
if exist ".venv\Scripts\python.exe" goto INSTALL_DEPS

echo.
echo [ERRO] Nao foi possivel localizar o Python 3 instalado no Windows.
echo Instale o Python 3.10+ em https://www.python.org/downloads/ marcando "Add Python to PATH".
pause
exit /b 1

:INSTALL_DEPS
echo [2/2] A instalar dependencias do Criptex (PyQt6, cryptography, qrcode, psutil)...
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 goto DEPS_ERROR
echo.
echo [OK] Ambiente configurado com sucesso!

:RUN_APP
echo A iniciar Criptex Security Suite...
".venv\Scripts\python.exe" "%~dp0main.py" --elevate
exit /b 0

:DEPS_ERROR
echo.
echo [ERRO] Falha ao instalar dependencias do ficheiro requirements.txt.
pause
exit /b 1
