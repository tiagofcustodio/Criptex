#!/usr/bin/env python3
# Criptex — Ponto de Entrada Principal (Windows Desktop Vault)

from __future__ import annotations

import argparse
import ctypes
import sys

from criptex.ui.main_window import run_app


def request_admin_elevation() -> None:
    """Reinicia o processo pedindo elevação UAC de Administrador no Windows."""
    try:
        if not ctypes.windll.shell32.IsUserAnAdmin():
            params = " ".join(f'"{arg}"' for arg in sys.argv if arg != "--elevate")
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, params, None, 1
            )
            sys.exit(0)
    except Exception as e:
        print(f"Aviso ao solicitar elevação de Administrador: {e}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="CRIPTEX — Cofre Digital Windows com Cifra de Vigenère, Pen USB Física e Desbloqueio Biométrico Smartphone"
    )
    parser.add_argument(
        "--elevate",
        action="store_true",
        help="Solicita privilégios de Administrador UAC ao iniciar para controlo físico dos adaptadores de rede.",
    )
    args = parser.parse_args()

    if args.elevate:
        request_admin_elevation()

    return run_app()


if __name__ == "__main__":
    raise SystemExit(main())
