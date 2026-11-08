# Criptex — Detetor e Gestor de Chave Física USB (Hardware Token)
# A palavra-chave da Cifra de Vigenère reside exclusivamente numa Pen USB física.
# Se o utilizador desbloquear o Criptex apenas com a biometria do smartphone (ex: telemóvel roubado)
# sem a Pen USB física ligada ao computador, o Criptex abre em Modo Cifrado (Locked Cipher Mode),
# onde todas as passwords e ficheiros permanecem estritamente encriptados pela Cifra de Vigenère!

from __future__ import annotations

import ctypes
from ctypes import wintypes
import hashlib
import json
import os
import secrets
import string
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple


DRIVE_UNKNOWN = 0
DRIVE_NO_ROOT_DIR = 1
DRIVE_REMOVABLE = 2
DRIVE_FIXED = 3
DRIVE_REMOTE = 4
DRIVE_CDROM = 5
DRIVE_RAMDISK = 6

USB_KEY_FILENAME = ".criptex_usb_key.crpxkey"


@dataclass
class UsbDriveInfo:
    mount_point: str          # Ex: "E:\\"
    volume_label: str         # Ex: "KINGSTON"
    serial_number: str        # Ex: "A8F3-91B2"
    filesystem: str           # Ex: "FAT32" / "exFAT" / "NTFS"
    drive_type: int           # 2 = DRIVE_REMOVABLE
    has_criptex_key: bool     # True se contiver .criptex_usb_key.crpxkey
    key_file_path: Path

    @property
    def display_name(self) -> str:
        label = self.volume_label or "PEN_USB"
        kind = "Unidade USB Removível" if self.drive_type == DRIVE_REMOVABLE else "Volume Externo"
        status = "[CHAVE CRIPTEX ATIVA]" if self.has_criptex_key else "[Sem Chave]"
        return f"{self.mount_point} ({label} | S/N: {self.serial_number} | {kind}) {status}"


class UsbKeyManager:
    """
    Gere a deteção de Pens USB físicas no Windows via Win32 APIs (`GetLogicalDriveStringsW`,
    `GetDriveTypeW`, `GetVolumeInformationW`) e lê/provisiona a palavra-chave da Cifra de Vigenère.
    
    Vincula criptograficamente a chave ao número de série físico do volume USB (`serial_number`)
    para que uma cópia simples do ficheiro para o disco local não funcione como chave válida.
    """

    def __init__(self, custom_mount_paths: Optional[List[Path]] = None) -> None:
        self.custom_mount_paths = custom_mount_paths or []

    @staticmethod
    def _get_volume_metadata(root_path: str) -> Tuple[str, str, str]:
        """Devolve (volume_label, serial_hex, filesystem_name) usando Win32 GetVolumeInformationW."""
        kernel32 = ctypes.windll.kernel32
        vol_name_buf = ctypes.create_unicode_buffer(261)
        fs_name_buf = ctypes.create_unicode_buffer(261)
        serial_num = wintypes.DWORD(0)
        max_comp_len = wintypes.DWORD(0)
        fs_flags = wintypes.DWORD(0)

        res = kernel32.GetVolumeInformationW(
            ctypes.c_wchar_p(root_path),
            vol_name_buf,
            ctypes.sizeof(vol_name_buf) // ctypes.sizeof(wintypes.WCHAR),
            ctypes.byref(serial_num),
            ctypes.byref(max_comp_len),
            ctypes.byref(fs_flags),
            fs_name_buf,
            ctypes.sizeof(fs_name_buf) // ctypes.sizeof(wintypes.WCHAR),
        )
        if not res:
            return ("USB_DRIVE", "0000-0000", "UNKNOWN")

        s_val = serial_num.value
        serial_str = f"{(s_val >> 16) & 0xFFFF:04X}-{s_val & 0xFFFF:04X}"
        return (vol_name_buf.value or "PEN_USB", serial_str, fs_name_buf.value or "FAT32")

    def scan_usb_drives(self, include_fixed_with_key: bool = True) -> List[UsbDriveInfo]:
        """
        Lista todas as Pens USB (DRIVE_REMOVABLE) ligadas ao computador Windows,
        bem como qualquer unidade externa que contenha um token `.criptex_usb_key.crpxkey`.
        """
        drives: List[UsbDriveInfo] = []
        kernel32 = ctypes.windll.kernel32

        if self.custom_mount_paths:
            for custom_mount in self.custom_mount_paths:
                if custom_mount.exists():
                    v_key = custom_mount / USB_KEY_FILENAME
                    drives.append(
                        UsbDriveInfo(
                            mount_point=str(custom_mount),
                            volume_label=custom_mount.name.upper(),
                            serial_number=hashlib.sha256(str(custom_mount).encode("utf-8")).hexdigest()[:8].upper(),
                            filesystem="FAT32",
                            drive_type=DRIVE_REMOVABLE,
                            has_criptex_key=v_key.exists(),
                            key_file_path=v_key,
                        )
                    )
            return drives

        buf_len = kernel32.GetLogicalDriveStringsW(0, None)
        if buf_len > 0:
            buf = ctypes.create_unicode_buffer(buf_len + 1)
            kernel32.GetLogicalDriveStringsW(buf_len, buf)
            raw_drives = [d for d in ctypes.wstring_at(buf, buf_len).split("\x00") if d]

            for root in raw_drives:
                is_system_drive = root.upper().startswith("C:")
                if is_system_drive:
                    continue
                dtype = kernel32.GetDriveTypeW(ctypes.c_wchar_p(root))
                # Ignorar unidades de rede (DRIVE_REMOTE) e CD-ROM para nunca bloquear quando a Internet é cortada
                if dtype not in (DRIVE_REMOVABLE, DRIVE_FIXED):
                    continue

                key_path = Path(root) / USB_KEY_FILENAME
                has_key = False
                try:
                    has_key = key_path.exists()
                except Exception:
                    has_key = False

                if dtype == DRIVE_REMOVABLE or (include_fixed_with_key and dtype == DRIVE_FIXED) or has_key:
                    label, serial_str, fs_name = self._get_volume_metadata(root)
                    drives.append(
                        UsbDriveInfo(
                            mount_point=root,
                            volume_label=label,
                            serial_number=serial_str,
                            filesystem=fs_name,
                            drive_type=dtype,
                            has_criptex_key=has_key,
                            key_file_path=key_path,
                        )
                    )

        for custom_mount in self.custom_mount_paths:
            if custom_mount.exists():
                v_key = custom_mount / USB_KEY_FILENAME
                drives.append(
                    UsbDriveInfo(
                        mount_point=str(custom_mount),
                        volume_label=custom_mount.name.upper(),
                        serial_number=hashlib.sha256(str(custom_mount).encode("utf-8")).hexdigest()[:8].upper(),
                        filesystem="FAT32",
                        drive_type=DRIVE_REMOVABLE,
                        has_criptex_key=v_key.exists(),
                        key_file_path=v_key,
                    )
                )

        return drives

    @staticmethod
    def generate_strong_vigenere_key(length: int = 48) -> str:
        """Gera uma palavra-chave polialfabética de Vigenère de alta entropia para gravar na Pen USB."""
        alphabet = string.ascii_uppercase + string.ascii_lowercase + string.digits + "!@#$%&*-_+=?"
        return "".join(secrets.choice(alphabet) for _ in range(length))

    def provision_usb_key(
        self,
        drive: UsbDriveInfo,
        vigenere_key: Optional[str] = None,
        vault_id: str = "CRIPTEX-MAIN",
    ) -> Tuple[str, Path]:
        """
        Grava a palavra-chave da Cifra de Vigenère na Pen USB física selecionada,
        vinculada ao número de série do volume USB.
        Devolve (vigenere_key, key_file_path).
        """
        if not vigenere_key or len(vigenere_key.strip()) < 4:
            vigenere_key = self.generate_strong_vigenere_key(48)
        else:
            vigenere_key = vigenere_key.strip()

        # Ofuscar a chave no ficheiro USB misturando-a com o Serial Number do hardware da Pen USB
        # para que o ficheiro só possa ser lido quando está presente nessa Pen USB específica!
        serial_mask = hashlib.sha256(f"CRIPTEX-USB-HW:{drive.serial_number}".encode("utf-8")).digest()
        raw_key_bytes = vigenere_key.encode("utf-8")
        masked_bytes = bytearray(len(raw_key_bytes))
        for i, b in enumerate(raw_key_bytes):
            masked_bytes[i] = (b + serial_mask[i % len(serial_mask)]) & 0xFF

        payload = {
            "header": "CRIPTEX_HARDWARE_USB_KEY_V1",
            "vault_id": vault_id,
            "usb_volume_label": drive.volume_label,
            "usb_serial_binding": hashlib.sha256(drive.serial_number.encode("utf-8")).hexdigest()[:24],
            "vigenere_key_masked_hex": bytes(masked_bytes).hex().upper(),
            "key_fingerprint": hashlib.sha256(raw_key_bytes).hexdigest()[:16].upper(),
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

        key_path = Path(drive.mount_point) / USB_KEY_FILENAME
        key_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        return vigenere_key, key_path

    def read_vigenere_key_from_usb(self, drive: UsbDriveInfo) -> Optional[str]:
        """
        Lê e reconstrói a palavra-chave da Cifra de Vigenère a partir da Pen USB física,
        validando o número de série do hardware USB.
        """
        key_path = Path(drive.mount_point) / USB_KEY_FILENAME
        if not key_path.exists():
            return None

        try:
            data = json.loads(key_path.read_text(encoding="utf-8"))
            if data.get("header") != "CRIPTEX_HARDWARE_USB_KEY_V1":
                return None

            expected_serial_hash = hashlib.sha256(drive.serial_number.encode("utf-8")).hexdigest()[:24]
            if data.get("usb_serial_binding") != expected_serial_hash:
                # Se alguém copiou o ficheiro .crpxkey para outra Pen ou disco com número de série diferente, falha!
                return None

            masked_bytes = bytes.fromhex(data["vigenere_key_masked_hex"])
            serial_mask = hashlib.sha256(f"CRIPTEX-USB-HW:{drive.serial_number}".encode("utf-8")).digest()
            raw_key_bytes = bytearray(len(masked_bytes))
            for i, b in enumerate(masked_bytes):
                raw_key_bytes[i] = (b - serial_mask[i % len(serial_mask)]) & 0xFF

            return bytes(raw_key_bytes).decode("utf-8")
        except Exception:
            return None

    def find_active_usb_key(self) -> Tuple[Optional[UsbDriveInfo], Optional[str]]:
        """
        Procura automaticamente em todas as unidades USB ligadas ao computador por uma
        chave `.criptex_usb_key.crpxkey` válida.
        Devolve (UsbDriveInfo, vigenere_key) ou (None, None) se a Pen USB não estiver inserida.
        """
        for d in self.scan_usb_drives():
            if d.has_criptex_key:
                key = self.read_vigenere_key_from_usb(d)
                if key:
                    return d, key
        return None, None
