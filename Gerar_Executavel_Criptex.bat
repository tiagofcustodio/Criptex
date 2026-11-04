@echo off
title CRIPTEX - Gerador de Executavel Autonomo (Criptex.exe)
cd /d "%~dp0"

echo ============================================================================
echo  CRIPTEX - Compilador de Executavel Autonomo Windows (PyInstaller)
echo ============================================================================

if not exist ".venv\Scripts\python.exe" (
    echo [1/3] A preparar ambiente virtual Python...
    python -m venv .venv
)

echo [2/3] A instalar dependencias e PyInstaller...
".venv\Scripts\python.exe" -m pip install -r requirements.txt pyinstaller
if errorlevel 1 goto BUILD_ERR

echo [3/3] A gerar executavel autonomo Criptex.exe (com Manifesto UAC Admin)...
".venv\Scripts\pyinstaller.exe" --noconfirm --clean --onefile --windowed --uac-admin --name "Criptex" --distpath "%~dp0" main.py
if errorlevel 1 goto BUILD_ERR

echo.
echo ============================================================================
echo  [OK] Criptex.exe gerado com sucesso em: %~dp0Criptex.exe
echo  Este executavel funciona em qualquer PC Windows SEM precisar de Python!
echo ============================================================================
pause
exit /b 0

:BUILD_ERR
echo.
echo [ERRO] Falha ao compilar o executavel Criptex.exe.
pause
exit /b 1
