@echo off
setlocal
chcp 65001 >nul
title CRIPTEX — Cofre Digital Windows
cd /d "%~dp0"

echo ============================================================================
echo  CRIPTEX — Cofre Digital Windows (Cifra de Vigenere + Pen USB + Biometria)
echo ============================================================================

if not exist ".venv\Scripts\python.exe" (
    echo.
    echo [1/2] Primeiro arranque detetado: A criar ambiente virtual Python ^(.venv^)...
    where py >nul 2>nul
    if %errorlevel% equ 0 (
        py -3 -m venv .venv
    ) else (
        python -m venv .venv
    )
    if not exist ".venv\Scripts\python.exe" (
        echo.
        echo [ERRO] Nao foi possivel localizar o Python 3 instalado no Windows.
        echo Instale o Python 3.10+ em https://www.python.org/downloads/ marcando "Add Python to PATH".
        pause
        exit /b 1
    )
    echo [2/2] A instalar dependencias do Criptex ^(PyQt6, cryptography, qrcode, psutil^)...
    ".venv\Scripts\python.exe" -m pip install --upgrade pip >nul 2>nul
    ".venv\Scripts\python.exe" -m pip install -r requirements.txt
    if %errorlevel% neq 0 (
        echo.
        echo [ERRO] Falha ao instalar dependencias do ficheiro requirements.txt.
        pause
        exit /b 1
    )
    echo.
    echo [OK] Ambiente configurado com sucesso!
)

echo A iniciar Criptex Security Suite...
".venv\Scripts\python.exe" "%~dp0main.py" --elevate
if %errorlevel% neq 0 (
    echo.
    echo [ERRO] O Criptex terminou com codigo de erro %errorlevel%.
    pause
)
endlocal
