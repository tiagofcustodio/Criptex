@echo off
chcp 65001 >nul
title CRIPTEX — Cofre Digital Windows
cd /d "%~dp0"
echo ============================================================================
echo  CRIPTEX — Cofre Digital Windows (Cifra de Vigenere + Pen USB + Biometria)
echo ============================================================================
.\.venv\Scripts\python.exe main.py --elevate
