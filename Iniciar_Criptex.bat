@echo off
title CRIPTEX - Cofre Digital Windows
cd /d "%~dp0"

echo ============================================================================
echo  CRIPTEX - Cofre Digital Windows (Cifra de Vigenere + Pen USB + Biometria)
echo ============================================================================

if exist "%~dp0Criptex.exe" goto RUN_STANDALONE_ROOT
if exist "%~dp0dist\Criptex.exe" goto RUN_STANDALONE_DIST
if exist ".venv\Scripts\python.exe" goto RUN_VENV

echo.
echo [1/3] A verificar instalacao do Python no Windows...
python --version >nul 2>nul
if not errorlevel 1 goto CREATE_VENV_PYTHON

py -3 --version >nul 2>nul
if not errorlevel 1 goto CREATE_VENV_PY

echo.
echo [!] Python nao detetado neste computador.
echo [!] A instalar automaticamente Python 3.12 via Windows Package Manager (winget)...
winget install -e --id Python.Python.3.12 --scope user --accept-package-agreements --accept-source-agreements
if errorlevel 1 goto PYTHON_MISSING_ERR

set "PATH=%LOCALAPPDATA%\Programs\Python\Python312;%LOCALAPPDATA%\Programs\Python\Python312\Scripts;%LOCALAPPDATA%\Programs\Python\Launcher;%ProgramFiles%\Python312;%ProgramFiles%\Python312\Scripts;%PATH%"

python --version >nul 2>nul
if not errorlevel 1 goto CREATE_VENV_PYTHON

py -3 --version >nul 2>nul
if not errorlevel 1 goto CREATE_VENV_PY

if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" (
    "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" -m venv .venv
    if exist ".venv\Scripts\python.exe" goto INSTALL_DEPS
)

:PYTHON_MISSING_ERR
echo.
echo [ERRO] Nao foi possivel instalar ou localizar o Python 3 automaticamente.
echo Instale o Python 3.12 em https://www.python.org/downloads/ marcando "Add Python to PATH"
echo ou execute diretamente o ficheiro Criptex.exe (que nao requer Python).
pause
exit /b 1

:CREATE_VENV_PYTHON
echo [2/3] A preparar ambiente virtual Python (.venv)...
python -m venv .venv
if exist ".venv\Scripts\python.exe" goto INSTALL_DEPS
goto PYTHON_MISSING_ERR

:CREATE_VENV_PY
echo [2/3] A preparar ambiente virtual Python (.venv)...
py -3 -m venv .venv
if exist ".venv\Scripts\python.exe" goto INSTALL_DEPS
goto PYTHON_MISSING_ERR

:INSTALL_DEPS
echo [3/3] A instalar dependencias do Criptex (PyQt6, cryptography, qrcode, psutil)...
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 goto DEPS_ERROR
echo.
echo [OK] Ambiente configurado com sucesso!

:RUN_VENV
echo A iniciar Criptex Security Suite...
".venv\Scripts\python.exe" "%~dp0main.py" --elevate
exit /b 0

:RUN_STANDALONE_ROOT
echo A iniciar executavel autonomo Criptex.exe...
start "" "%~dp0Criptex.exe" --elevate
exit /b 0

:RUN_STANDALONE_DIST
echo A iniciar executavel autonomo dist\Criptex.exe...
start "" "%~dp0dist\Criptex.exe" --elevate
exit /b 0

:DEPS_ERROR
echo.
echo [ERRO] Falha ao instalar dependencias do ficheiro requirements.txt.
pause
exit /b 1
