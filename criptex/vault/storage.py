# Criptex — Armazenamento do Cofre Digital (Passwords & Ficheiros)
# Tanto as passwords como os ficheiros são guardados no interior do cofre
# modificados diretamente pela Cifra de Vigenère.
#
# ARQUITETURA DE DUPLO FATOR FÍSICO (SMARTPHONE BIOMÉTRICO + PEN USB FÍSICA):
#   - O acesso à aplicação é autorizado pela Biometria do Smartphone.
#   - A Palavra-Chave da Cifra de Vigenère reside exclusivamente na Pen USB física.
#   - Se alguém usar um smartphone roubado SEM a Pen USB física inserida no PC,
#     o Criptex abre, mas TODOS OS DADOS PERMANECEM ENCRIPTADOS (Modo Cifrado / Sem Chave USB).

from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple

from criptex.crypto.vigenere import VigenereCipher


@dataclass
class PasswordEntry:
    id: str
    # Mesmo o título, utilizador e URL têm versão cifrada com Vigenère para quando a Pen USB não está presente!
    title_vigenere_ascii: str
    username_vigenere_ascii: str
    url_vigenere_ascii: str
    title_cipher_token: str
    username_cipher_token: str
    url_cipher_token: str
    category: str
    # Password e notas cifradas com Vigenère (token VIG$...) e visualização ASCII Vigenère
    vigenere_cipher_token: str
    vigenere_ascii_preview: str
    notes_vigenere: str
    created_at: str
    updated_at: str

    # Campos desencriptados em memória apenas quando a Pen USB física está presente:
    decrypted_title: Optional[str] = None
    decrypted_username: Optional[str] = None
    decrypted_url: Optional[str] = None


@dataclass
class VaultFileEntry:
    id: str
    original_name_vigenere_ascii: str
    original_name_cipher_token: str
    vault_filename: str
    original_size: int
    encrypted_size: int
    sha256_original: str
    vigenere_header_hex: str
    vigenere_sample_hex: str
    added_at: str
    decrypted_original_name: Optional[str] = None


class CriptexVaultStorage:
    """
    Gere o diretório fortificado `.criptex_vault/`:
      - `vault_meta.json`: Configuração do cofre, canário da Chave USB Vigenère
        e registo biométrico do smartphone (WebAuthn).
      - `passwords_store.json`: Registos cujos campos sensíveis (incluindo título, utilizador,
        password e notas) estão todos transformados pela Cifra de Vigenère.
        Assim, se o cofre for aberto apenas com o smartphone (sem a Pen USB física),
        o cofre carrega a lista mas mostra apenas os criptogramas Vigenère indecifráveis!
      - `files/*.crpx`: Ficheiros importados para o interior do cofre, cujos bytes foram
        transformados in-place pela Cifra de Vigenère (`C[i] = (P[i] + K[i]) mod 256`).
    """

    def __init__(self, base_dir: Optional[Path] = None) -> None:
        if base_dir is None:
            base_dir = Path.cwd() / ".criptex_vault"
        self.base_dir = Path(base_dir)
        self.files_dir = self.base_dir / "files"
        self.meta_path = self.base_dir / "vault_meta.json"
        self.passwords_path = self.base_dir / "passwords.crpx"
        self.files_index_path = self.base_dir / "files_index.crpx"

        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.files_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Inicialização e Verificação da Chave Vigenère (Guardada na Pen USB)
    # ------------------------------------------------------------------
    def is_initialized(self) -> bool:
        if not self.meta_path.exists():
            return False
        meta = self.load_meta()
        return bool(meta.get("canary"))

    def load_meta(self) -> Dict[str, Any]:
        if not self.meta_path.exists():
            return {}
        try:
            return json.loads(self.meta_path.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def save_meta(self, meta: Dict[str, Any]) -> None:
        self.meta_path.write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")

    def initialize_vault(
        self,
        usb_master_key: str,
        usb_serial: str = "",
        usb_label: str = "PEN_USB",
        device_name: str = "Smartphone Biométrico",
    ) -> None:
        """
        Inicializa o cofre vinculando-o à Palavra-Chave da Cifra de Vigenère que está
        guardada na Pen USB física.
        """
        if len(usb_master_key.strip()) < 4:
            raise ValueError("A Chave Mestra de Vigenère na Pen USB deve ter pelo menos 4 caracteres.")

        # Preservar dispositivo biométrico já registado se o cofre estiver apenas a atualizar a chave USB
        existing_meta = self.load_meta()
        existing_bio = existing_meta.get("biometric_device", {})
        if existing_bio.get("paired") and existing_bio.get("credential_id"):
            bio_block = existing_bio
        else:
            bio_block = {
                "paired": False,
                "locked": False,
                "device_name": device_name,
                "credential_id": None,
                "public_key_spki_b64": None,
                "device_token_hash": None,
                "algorithm": None,
                "user_agent": "",
                "paired_at": None,
            }

        canary = VigenereCipher.encrypt_password_str("CRIPTEX_VAULT_VERIFIED_OK", usb_master_key)
        meta = {
            "version": "2.1.0-USB-BIO-LOCKED",
            "cipher": "Vigenere-Polyalphabetic-Mod256-HMAC-SHA256",
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "canary": canary,
            "usb_token": {
                "usb_label": usb_label,
                "usb_serial_hash": hashlib.sha256(usb_serial.encode("utf-8")).hexdigest()[:24] if usb_serial else "",
                "key_fingerprint": hashlib.sha256(usb_master_key.encode("utf-8")).hexdigest()[:16].upper(),
            },
            "biometric_device": bio_block,
        }
        self.save_meta(meta)
        if not self.passwords_path.exists():
            self._save_raw_passwords([])
        if not self.files_index_path.exists():
            self._save_raw_files_index([])

    def verify_master_key(self, usb_master_key: Optional[str]) -> bool:
        """
        Verifica se a chave Vigenère lida da Pen USB desencripta corretamente o canário do cofre.
        Se a Pen USB não estiver inserida (`None`) ou tiver outra chave, devolve `False`.
        """
        if not usb_master_key:
            return False
        meta = self.load_meta()
        canary = meta.get("canary")
        if not canary:
            return False
        try:
            plain = VigenereCipher.decrypt_password_str(canary, usb_master_key)
            return plain == "CRIPTEX_VAULT_VERIFIED_OK"
        except Exception:
            return False

    def register_biometric_credential(
        self,
        credential_id: str,
        public_key_spki_b64: str = "",
        algorithm: int = -7,
        device_name: str = "Smartphone WebAuthn",
        user_agent: str = "",
        device_token_hash: str = "",
        hw_signature_hash: str = "",
        paired_ip: str = "",
        allow_overwrite: bool = False,
    ) -> None:
        """
        Regista e tranca permanentemente o smartphone biométrico após o primeiro uso do QR Code.
        Se já existir um dispositivo biométrico registado e `allow_overwrite=False`, lança PermissionError
        para impedir que outro telemóvel substitua o dispositivo original fora das Definições do Cofre.
        """
        meta = self.load_meta()
        bio = meta.get("biometric_device", {})
        if bio.get("paired") and bio.get("credential_id") and not allow_overwrite:
            raise PermissionError(
                "Já existe um smartphone biométrico registado e bloqueado neste cofre! "
                "A alteração só é permitida nas Definições no interior do cofre com o desbloqueio original e a Pen USB física."
            )

        bio.update(
            {
                "paired": True,
                "locked": True,
                "device_name": device_name or "Smartphone WebAuthn",
                "credential_id": credential_id,
                "public_key_spki_b64": public_key_spki_b64,
                "device_token_hash": device_token_hash or bio.get("device_token_hash") or "",
                "hw_signature_hash": hw_signature_hash or bio.get("hw_signature_hash") or "",
                "paired_ip": paired_ip or bio.get("paired_ip") or "",
                "algorithm": algorithm,
                "user_agent": user_agent[:180],
                "paired_at": bio.get("paired_at") or time.strftime("%Y-%m-%d %H:%M:%S"),
            }
        )
        meta["biometric_device"] = bio
        self.save_meta(meta)

    def reset_biometric_pairing(
        self,
        usb_master_key: Optional[str],
        original_biometric_verified: bool,
    ) -> None:
        """
        Desvincula o smartphone biométrico atual para permitir emparelhar um novo telemóvel.
        SÓ PODE SER EXECUTADO DENTRO DO COFRE quando AMBOS os fatores originais estão presentes:
          1. Desbloqueio Biométrico Original (`original_biometric_verified=True`)
          2. Pen USB Física com a Chave de Vigenère válida (`verify_master_key(usb_master_key)=True`)
        """
        if not original_biometric_verified:
            raise PermissionError(
                "Acesso Negado: É obrigatório ter a sessão autenticada com o desbloqueio biométrico original."
            )
        if not usb_master_key or not self.verify_master_key(usb_master_key):
            raise PermissionError(
                "Acesso Negado: A Pen USB física original com a palavra-chave Vigenère tem de estar ligada ao computador "
                "para alterar ou revogar o dispositivo biométrico."
            )

        meta = self.load_meta()
        meta["biometric_device"] = {
            "paired": False,
            "locked": False,
            "device_name": "Aguardando Novo Registo Biométrico",
            "credential_id": None,
            "public_key_spki_b64": None,
            "device_token_hash": None,
            "hw_signature_hash": None,
            "paired_ip": None,
            "algorithm": None,
            "user_agent": "",
            "paired_at": None,
        }
        self.save_meta(meta)

    def get_biometric_device_info(self) -> Dict[str, Any]:
        meta = self.load_meta()
        return meta.get("biometric_device", {})

    def is_biometric_paired(self) -> bool:
        meta = self.load_meta()
        bio = meta.get("biometric_device", {})
        return bool(bio.get("paired") and bio.get("credential_id"))

    # ------------------------------------------------------------------
    # Gestão de Passwords (Se sem Pen USB -> tudo permanece cifrado!)
    # ------------------------------------------------------------------
    def _save_raw_passwords(self, entries: List[PasswordEntry]) -> None:
        clean_list = []
        for e in entries:
            d = asdict(e)
            d.pop("decrypted_title", None)
            d.pop("decrypted_username", None)
            d.pop("decrypted_url", None)
            clean_list.append(d)
        payload = json.dumps(clean_list, ensure_ascii=False, indent=2).encode("utf-8")
        self.passwords_path.write_bytes(payload)

    def _load_raw_passwords(self) -> List[PasswordEntry]:
        if not self.passwords_path.exists():
            return []
        try:
            raw_list = json.loads(self.passwords_path.read_bytes().decode("utf-8"))
            return [PasswordEntry(**item) for item in raw_list]
        except Exception:
            return []

    def list_passwords(self, usb_master_key: Optional[str] = None) -> List[PasswordEntry]:
        """
        Lista as entradas de passwords do cofre.
        - Se `usb_master_key` for válida (Pen USB física presente): desencripta o título,
          utilizador e URL em memória para visualização autorizada.
        - Se `usb_master_key` for `None` ou inválida (ex: smartphone roubado sem Pen USB):
          devolve os registos mas TODOS os campos permanecem cifrados com Vigenère!
        """
        entries = self._load_raw_passwords()
        has_valid_key = self.verify_master_key(usb_master_key)
        for e in entries:
            if has_valid_key and usb_master_key:
                try:
                    e.decrypted_title = VigenereCipher.decrypt_password_str(e.title_cipher_token, usb_master_key)
                    e.decrypted_username = VigenereCipher.decrypt_password_str(e.username_cipher_token, usb_master_key)
                    e.decrypted_url = VigenereCipher.decrypt_password_str(e.url_cipher_token, usb_master_key)
                except Exception:
                    e.decrypted_title = e.title_vigenere_ascii
                    e.decrypted_username = e.username_vigenere_ascii
                    e.decrypted_url = e.url_vigenere_ascii
            else:
                e.decrypted_title = None
                e.decrypted_username = None
                e.decrypted_url = None
        return entries

    def add_password(
        self,
        usb_master_key: str,
        title: str,
        username: str,
        plain_password: str,
        url: str = "",
        category: str = "Geral",
        notes: str = "",
    ) -> PasswordEntry:
        if not self.verify_master_key(usb_master_key):
            raise PermissionError("Pen USB física com a Chave de Vigenère é obrigatória para cifrar novas passwords.")

        entries = self._load_raw_passwords()
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        clean_title = title.strip() or "Sem Título"
        clean_user = username.strip()
        clean_url = url.strip()

        entry = PasswordEntry(
            id=str(uuid.uuid4())[:8],
            title_vigenere_ascii=VigenereCipher.classic_alphabetic_vigenere(clean_title, usb_master_key),
            username_vigenere_ascii=VigenereCipher.classic_alphabetic_vigenere(clean_user, usb_master_key),
            url_vigenere_ascii=VigenereCipher.classic_alphabetic_vigenere(clean_url, usb_master_key),
            title_cipher_token=VigenereCipher.encrypt_password_str(clean_title, usb_master_key),
            username_cipher_token=VigenereCipher.encrypt_password_str(clean_user, usb_master_key),
            url_cipher_token=VigenereCipher.encrypt_password_str(clean_url, usb_master_key),
            category=category.strip() or "Geral",
            vigenere_cipher_token=VigenereCipher.encrypt_password_str(plain_password, usb_master_key),
            vigenere_ascii_preview=VigenereCipher.classic_alphabetic_vigenere(
                plain_password, usb_master_key, decrypt=False
            ),
            notes_vigenere=VigenereCipher.encrypt_password_str(notes or "", usb_master_key),
            created_at=now,
            updated_at=now,
        )
        entries.append(entry)
        self._save_raw_passwords(entries)
        return entry

    def delete_password(self, usb_master_key: Optional[str], entry_id: str) -> bool:
        if not self.verify_master_key(usb_master_key):
            raise PermissionError("A Pen USB física tem de estar ligada para apagar dados do cofre.")
        entries = self._load_raw_passwords()
        new_entries = [e for e in entries if e.id != entry_id]
        if len(new_entries) == len(entries):
            return False
        self._save_raw_passwords(new_entries)
        return True

    def reveal_password(self, entry: PasswordEntry, usb_master_key: Optional[str]) -> Tuple[str, str]:
        """
        Desencripta (plain_password, plain_notes) usando a chave da Pen USB.
        Se a Pen USB não estiver inserida, lança PermissionError e mantém tudo encriptado.
        """
        if not usb_master_key or not self.verify_master_key(usb_master_key):
            raise PermissionError(
                "ACESSO NEGADO: A Pen USB física com a palavra-chave Vigenère não está ligada ao computador! "
                "Todos os dados permanecem encriptados."
            )
        plain_pw = VigenereCipher.decrypt_password_str(entry.vigenere_cipher_token, usb_master_key)
        plain_notes = ""
        if entry.notes_vigenere:
            try:
                plain_notes = VigenereCipher.decrypt_password_str(entry.notes_vigenere, usb_master_key)
            except Exception:
                plain_notes = ""
        return plain_pw, plain_notes

    # ------------------------------------------------------------------
    # Gestão de Ficheiros no Cofre (Modificados no interior com Vigenère)
    # ------------------------------------------------------------------
    def _save_raw_files_index(self, entries: List[VaultFileEntry]) -> None:
        clean_list = []
        for e in entries:
            d = asdict(e)
            d.pop("decrypted_original_name", None)
            clean_list.append(d)
        payload = json.dumps(clean_list, ensure_ascii=False, indent=2).encode("utf-8")
        self.files_index_path.write_bytes(payload)

    def _load_raw_files_index(self) -> List[VaultFileEntry]:
        if not self.files_index_path.exists():
            return []
        try:
            raw_list = json.loads(self.files_index_path.read_bytes().decode("utf-8"))
            return [VaultFileEntry(**item) for item in raw_list]
        except Exception:
            return []

    def list_files(self, usb_master_key: Optional[str] = None) -> List[VaultFileEntry]:
        """
        Lista os ficheiros guardados no interior do cofre.
        Sem a Pen USB física (`usb_master_key=None`), mesmo os nomes originais e os conteúdos
        permanecem cifrados com Vigenère!
        """
        entries = self._load_raw_files_index()
        has_valid_key = self.verify_master_key(usb_master_key)
        for e in entries:
            if has_valid_key and usb_master_key:
                try:
                    e.decrypted_original_name = VigenereCipher.decrypt_password_str(
                        e.original_name_cipher_token, usb_master_key
                    )
                except Exception:
                    e.decrypted_original_name = e.original_name_vigenere_ascii
            else:
                e.decrypted_original_name = None
        return entries

    def import_file(
        self,
        source_path: Path,
        usb_master_key: Optional[str],
        shred_original: bool = False,
    ) -> VaultFileEntry:
        if not usb_master_key or not self.verify_master_key(usb_master_key):
            raise PermissionError(
                "Pen USB física não detetada! É necessária a chave USB para cifrar ficheiros no cofre."
            )

        source_path = Path(source_path)
        if not source_path.exists() or not source_path.is_file():
            raise FileNotFoundError(f"Ficheiro não encontrado: {source_path}")

        raw_bytes = source_path.read_bytes()
        sha256_orig = hashlib.sha256(raw_bytes).hexdigest()

        encrypted_blob = VigenereCipher.encrypt_bytes(raw_bytes, usb_master_key)
        file_id = str(uuid.uuid4())[:8]
        name_vig = VigenereCipher.classic_alphabetic_vigenere(source_path.name, usb_master_key)
        vault_filename = f"{file_id}.crpx"
        dest_path = self.files_dir / vault_filename
        dest_path.write_bytes(encrypted_blob)

        header_len = 5 + 1 + 16 + 32
        header_hex = encrypted_blob[:22].hex().upper()
        sample_cipher = encrypted_blob[header_len : header_len + 32].hex().upper()

        entry = VaultFileEntry(
            id=file_id,
            original_name_vigenere_ascii=name_vig,
            original_name_cipher_token=VigenereCipher.encrypt_password_str(source_path.name, usb_master_key),
            vault_filename=vault_filename,
            original_size=len(raw_bytes),
            encrypted_size=len(encrypted_blob),
            sha256_original=sha256_orig,
            vigenere_header_hex=header_hex,
            vigenere_sample_hex=sample_cipher,
            added_at=time.strftime("%Y-%m-%d %H:%M:%S"),
            decrypted_original_name=source_path.name,
        )

        entries = self._load_raw_files_index()
        entries.append(entry)
        self._save_raw_files_index(entries)

        if shred_original:
            self._secure_shred_file(source_path)

        return entry

    def export_decrypted_file(
        self,
        file_id: str,
        dest_path: Path,
        usb_master_key: Optional[str],
    ) -> Path:
        if not usb_master_key or not self.verify_master_key(usb_master_key):
            raise PermissionError(
                "BLOQUEADO: Sem a Pen USB física ligada ao computador, os ficheiros não podem ser desencriptados!"
            )

        entries = self._load_raw_files_index()
        target = next((e for e in entries if e.id == file_id), None)
        if not target:
            raise ValueError(f"Ficheiro com ID {file_id} não encontrado no cofre.")

        vault_file = self.files_dir / target.vault_filename
        if not vault_file.exists():
            raise FileNotFoundError(f"Contentor cifrado ausente: {vault_file}")

        encrypted_blob = vault_file.read_bytes()
        decrypted_bytes = VigenereCipher.decrypt_bytes(encrypted_blob, usb_master_key)

        actual_sha = hashlib.sha256(decrypted_bytes).hexdigest()
        if actual_sha != target.sha256_original:
            raise ValueError("Falha de verificação SHA-256 após desencriptação Vigenère!")

        dest_path = Path(dest_path)
        dest_path.write_bytes(decrypted_bytes)
        return dest_path

    def inspect_vault_file_bytes(self, file_id: str, usb_master_key: Optional[str] = None) -> Dict[str, Any]:
        """
        Inspeciona os bytes do ficheiro dentro do cofre:
        - Se a Pen USB física estiver presente (`usb_master_key` válida): mostra a comparação
          lado-a-lado entre os bytes originais $P[i]$, o deslocamento $K[i]$ e os bytes cifrados $C[i]$.
        - Se a Pen USB física NÃO estiver presente (ex: smartphone roubado): mostra apenas
          os bytes encriptados $C[i]$ gravados em disco; o conteúdo original permanece 100% oculto e indecifrável!
        """
        entries = self._load_raw_files_index()
        target = next((e for e in entries if e.id == file_id), None)
        if not target:
            raise ValueError("Ficheiro não encontrado.")

        vault_file = self.files_dir / target.vault_filename
        blob = vault_file.read_bytes()
        header_len = 5 + 1 + 16 + 32
        cipher_body = blob[header_len:]

        has_valid_key = self.verify_master_key(usb_master_key)
        comparison = []

        if has_valid_key and usb_master_key:
            plain = VigenereCipher.decrypt_bytes(blob, usb_master_key)
            sample_len = min(24, len(plain))
            for i in range(sample_len):
                p_b = plain[i]
                c_b = cipher_body[i]
                k_b = (c_b - p_b) & 0xFF
                comparison.append(
                    {
                        "offset": f"0x{i:04X}",
                        "plain_hex": f"{p_b:02X}",
                        "plain_ascii": chr(p_b) if 32 <= p_b <= 126 else ".",
                        "key_shift": f"+{k_b:03d} (0x{k_b:02X})",
                        "cipher_hex": f"{c_b:02X}",
                        "cipher_ascii": chr(c_b) if 32 <= c_b <= 126 else ".",
                    }
                )
            plain_preview = plain[:256].decode("utf-8", errors="replace")
        else:
            sample_len = min(24, len(cipher_body))
            for i in range(sample_len):
                c_b = cipher_body[i]
                comparison.append(
                    {
                        "offset": f"0x{i:04X}",
                        "plain_hex": "🔒??",
                        "plain_ascii": "🔒",
                        "key_shift": "🔒 [FALTA PEN USB]",
                        "cipher_hex": f"{c_b:02X}",
                        "cipher_ascii": chr(c_b) if 32 <= c_b <= 126 else ".",
                    }
                )
            plain_preview = "🔒 [CONTEÚDO ENCRIPTADO COM VIGENÈRE — INSIRA A PEN USB FÍSICA PARA DESENCRIPTAR]"

        return {
            "entry": asdict(target),
            "usb_unlocked": has_valid_key,
            "vault_path": str(vault_file),
            "raw_header_magic": blob[:5].decode("ascii", errors="replace"),
            "salt_hex": blob[6:22].hex().upper(),
            "hmac_hex": blob[22:54].hex().upper(),
            "byte_comparison": comparison,
            "plain_text_preview": plain_preview,
        }

    def delete_vault_file(self, file_id: str, usb_master_key: Optional[str]) -> bool:
        if not usb_master_key or not self.verify_master_key(usb_master_key):
            raise PermissionError("A Pen USB física tem de estar ligada para eliminar ficheiros do cofre.")
        entries = self._load_raw_files_index()
        target = next((e for e in entries if e.id == file_id), None)
        if not target:
            return False

        vault_file = self.files_dir / target.vault_filename
        if vault_file.exists():
            self._secure_shred_file(vault_file)

        new_entries = [e for e in entries if e.id != file_id]
        self._save_raw_files_index(new_entries)
        return True

    @staticmethod
    def _secure_shred_file(path: Path) -> None:
        try:
            size = path.stat().st_size
            with open(path, "ba+", buffering=0) as f:
                f.seek(0)
                f.write(os.urandom(min(size, 1024 * 1024)))
                f.seek(0)
                f.write(b"\x00" * min(size, 1024 * 1024))
            path.unlink()
        except Exception:
            if path.exists():
                path.unlink()
