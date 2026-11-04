#!/usr/bin/env python3
# Criptex — Ponto de Entrada Principal (Windows Desktop Vault)

from __future__ import annotations

import argparse
import ctypes
import os
import subprocess
import sys
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent


def ensure_dependencies() -> None:
    """Garante que todas as dependências do requirements.txt estão instaladas."""
    try:
        import cryptography  # noqa: F401
        import PIL  # noqa: F401
        import psutil  # noqa: F401
        import PyQt6  # noqa: F401
        import qrcode  # noqa: F401
    except ImportError:
        req_file = PROJECT_DIR / "requirements.txt"
        print("[Criptex] A instalar dependências necessárias pela primeira vez...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", str(req_file)])


def request_admin_elevation() -> None:
    """Reinicia o processo pedindo elevação UAC de Administrador no Windows mantendo o diretório do projeto."""
    if os.name != "nt":
        return
    try:
        if not ctypes.windll.shell32.IsUserAnAdmin():
            script_path = str(Path(__file__).resolve())
            extra_args = [f'"{arg}"' for arg in sys.argv[1:] if arg != "--elevate"]
            params = " ".join([f'"{script_path}"'] + extra_args)
            ret = ctypes.windll.shell32.ShellExecuteW(
                None,
                "runas",
                sys.executable,
                params,
                str(PROJECT_DIR),
                1,
            )
            # ShellExecuteW retorna > 32 se a elevação foi aceite pelo utilizador
            if int(ret) > 32:
                sys.exit(0)
            else:
                print("[Criptex] Elevação UAC recusada ou cancelada; a iniciar em modo utilizador padrão.")
    except Exception as e:
        print(f"Aviso ao solicitar elevação de Administrador: {e}")


def main() -> int:
    os.chdir(PROJECT_DIR)
    if str(PROJECT_DIR) not in sys.path:
        sys.path.insert(0, str(PROJECT_DIR))

    parser = argparse.ArgumentParser(
        description="CRIPTEX — Cofre Digital Windows com Cifra de Vigenère, Pen USB Física e Desbloqueio Biométrico Smartphone"
    )
    parser.add_argument(
        "--elevate",
        action="store_true",
        help="Solicita privilégios de Administrador UAC ao iniciar para controlo físico dos adaptadores de rede.",
    )
    args = parser.parse_args()

    ensure_dependencies()

    if args.elevate:
        request_admin_elevation()

    from criptex.ui.main_window import run_app

    return run_app()


if __name__ == "__main__":
    raise SystemExit(main())
