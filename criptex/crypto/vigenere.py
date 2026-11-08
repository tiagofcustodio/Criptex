# Criptex — Motor da Cifra de Vigenère Fortificada
# Suporta encriptação/desencriptação ao nível de bytes (Mod 256) e texto visível,
# com expansão determinística de chave e verificação de integridade HMAC-SHA256.

from __future__ import annotations

import base64
import functools
import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from typing import Dict, Any, Tuple


MAGIC_HEADER = b"CRPX1"  # 5 bytes


@dataclass
class VigenereInspection:
    """Detalhes pedagógicos e técnicos de uma operação Vigenère para exibição na UI."""
    plaintext_preview: str
    key_preview: str
    extended_key_hex: str
    ciphertext_hex: str
    ciphertext_b64: str
    byte_shifts: list[dict[str, Any]]
    mac_hex: str


class VigenereCipher:
    """
    Motor da Cifra de Vigenère Fortificada do Criptex.
    
    Aplica a transformação matemática clássica de Vigenère no corpo Z_256 (bytes):
      - Cifrar:    C[i] = (P[i] + K[i mod len(K)]) mod 256
      - Decifrar:  P[i] = (C[i] - K[i mod len(K)]) mod 256
    
    Para evitar ataques clássicos de Kasiski / Índice de Coincidência em ficheiros
    grandes ou passwords repetidas, a chave Vigenère do utilizador pode ser combinada
    com uma keystream derivada por PBKDF2-HMAC-SHA256 (ou usada em modo puro se a
    chave expandida tiver o tamanho exato da chave original). Aqui expandimos a
    chave Vigenère num bloco primo longo (ex: 4099 bytes) derivado da chave + salt,
    mantendo 100% a aritmética modular aditiva de Vigenère byte-a-byte!
    """

    KEY_RING_LENGTH = 1021  # Número primo para evitar periodicidade curta

    @staticmethod
    @functools.lru_cache(maxsize=2048)
    def derive_vigenere_key_ring(master_key: str, salt: bytes, pure_mode: bool = False) -> bytes:
        """
        Gera o anel de deslocamentos (key ring) da Cifra de Vigenère a partir da chave.
        Se pure_mode=True, usa diretamente os bytes UTF-8 da master_key repetidos.
        Caso contrário, deriva um anel de 1021 bytes via PBKDF2-HMAC-SHA256 combinando
        a chave UTF-8 clássica com o salt.
        """
        if not master_key:
            raise ValueError("A chave Vigenère não pode estar vazia.")
        raw_key = master_key.encode("utf-8")
        if pure_mode:
            return raw_key

        derived = hashlib.pbkdf2_hmac(
            "sha256",
            raw_key,
            salt + b":criptex-vigenere-ring",
            iterations=60_000,
            dklen=VigenereCipher.KEY_RING_LENGTH,
        )
        # Combina aditivamente (mod 256) os bytes originais da chave com a expansão
        ring = bytearray(VigenereCipher.KEY_RING_LENGTH)
        key_len = len(raw_key)
        for i in range(VigenereCipher.KEY_RING_LENGTH):
            ring[i] = (raw_key[i % key_len] + derived[i]) & 0xFF
        return bytes(ring)

    @staticmethod
    @functools.lru_cache(maxsize=2048)
    def derive_mac_key(master_key: str, salt: bytes) -> bytes:
        """Deriva uma sub-chave dedicada para autenticação de integridade HMAC-SHA256."""
        return hashlib.pbkdf2_hmac(
            "sha256",
            master_key.encode("utf-8"),
            salt + b":criptex-hmac-auth",
            iterations=60_000,
            dklen=32,
        )

    @staticmethod
    def vigenere_transform_bytes(data: bytes, key_ring: bytes, decrypt: bool = False) -> bytes:
        """
        Executa a adição/subtração polialfabética da Cifra de Vigenère (mod 256)
        sobre um buffer de bytes arbitrário.
        """
        if not key_ring:
            raise ValueError("O anel de chave Vigenère não pode estar vazio.")
        ring_len = len(key_ring)
        out = bytearray(len(data))
        if not decrypt:
            for i, b in enumerate(data):
                out[i] = (b + key_ring[i % ring_len]) & 0xFF
        else:
            for i, b in enumerate(data):
                out[i] = (b - key_ring[i % ring_len]) & 0xFF
        return bytes(out)

    @classmethod
    def encrypt_bytes(cls, data: bytes, master_key: str, pure_mode: bool = False) -> bytes:
        """
        Encripta bytes arbitrários com a Cifra de Vigenère e empacota com cabeçalho
        binário CRPX1 + flag + salt (16B) + HMAC-SHA256 (32B) + Ciphertext Vigenère.
        """
        salt = os.urandom(16)
        flags = 0x01 if pure_mode else 0x00
        key_ring = cls.derive_vigenere_key_ring(master_key, salt, pure_mode=pure_mode)
        ciphertext = cls.vigenere_transform_bytes(data, key_ring, decrypt=False)

        mac_key = cls.derive_mac_key(master_key, salt)
        header = MAGIC_HEADER + bytes([flags]) + salt
        mac = hmac.new(mac_key, header + ciphertext, hashlib.sha256).digest()
        return header + mac + ciphertext

    @classmethod
    def decrypt_bytes(cls, blob: bytes, master_key: str) -> bytes:
        """
        Verifica a autenticidade HMAC-SHA256 e reverte a Cifra de Vigenère (mod 256).
        Lança ValueError se a chave estiver incorreta ou os dados corrompidos.
        """
        min_len = len(MAGIC_HEADER) + 1 + 16 + 32
        if len(blob) < min_len or blob[: len(MAGIC_HEADER)] != MAGIC_HEADER:
            raise ValueError("Formato de contentor Criptex inválido ou corrompido.")

        flags = blob[len(MAGIC_HEADER)]
        pure_mode = bool(flags & 0x01)
        salt_start = len(MAGIC_HEADER) + 1
        salt = blob[salt_start : salt_start + 16]
        mac_start = salt_start + 16
        expected_mac = blob[mac_start : mac_start + 32]
        ciphertext = blob[mac_start + 32 :]

        header = blob[:mac_start]
        mac_key = cls.derive_mac_key(master_key, salt)
        actual_mac = hmac.new(mac_key, header + ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(expected_mac, actual_mac):
            raise ValueError("Chave Vigenère inválida ou integridade violada (HMAC falhou).")

        key_ring = cls.derive_vigenere_key_ring(master_key, salt, pure_mode=pure_mode)
        return cls.vigenere_transform_bytes(ciphertext, key_ring, decrypt=True)

    @classmethod
    def encrypt_password_str(cls, plaintext: str, master_key: str, pure_mode: bool = False) -> str:
        """
        Encripta uma password ou segredo textual usando a Cifra de Vigenère e devolve
        uma representação compacta prefixada com `VIG$` em Base64 URL-safe.
        """
        raw = plaintext.encode("utf-8")
        encrypted_blob = cls.encrypt_bytes(raw, master_key, pure_mode=pure_mode)
        return "VIG$" + base64.urlsafe_b64encode(encrypted_blob).decode("ascii")

    @classmethod
    def decrypt_password_str(cls, token: str, master_key: str) -> str:
        """
        Desencripta uma string prefixada com `VIG$` usando a Cifra de Vigenère.
        """
        if not token.startswith("VIG$"):
            raise ValueError("Token de password Vigenère inválido (falta prefixo VIG$).")
        b64_part = token[4:]
        blob = base64.urlsafe_b64decode(b64_part.encode("ascii"))
        decrypted = cls.decrypt_bytes(blob, master_key)
        return decrypted.decode("utf-8")

    @classmethod
    def inspect_transformation(cls, plaintext: str, master_key: str, max_steps: int = 32) -> VigenereInspection:
        """
        Gera uma análise passo-a-passo da transformação polialfabética de Vigenère
        para mostrar ao utilizador como cada byte/carácter foi deslocado no interior do cofre.
        """
        if not master_key:
            master_key = "CRIPTEX"
        data = plaintext.encode("utf-8")
        raw_key = master_key.encode("utf-8")
        salt = hashlib.sha256(b"criptex-preview-salt:" + raw_key).digest()[:16]
        key_ring = cls.derive_vigenere_key_ring(master_key, salt, pure_mode=False)
        cipher = cls.vigenere_transform_bytes(data, key_ring, decrypt=False)
        mac_key = cls.derive_mac_key(master_key, salt)
        mac_hex = hmac.new(mac_key, cipher, hashlib.sha256).hexdigest()

        steps = []
        for i in range(min(len(data), max_steps)):
            p_byte = data[i]
            k_raw_byte = raw_key[i % len(raw_key)]
            k_ring_byte = key_ring[i % len(key_ring)]
            c_byte = cipher[i]
            steps.append(
                {
                    "index": i,
                    "plain_char": chr(p_byte) if 32 <= p_byte <= 126 else f"0x{p_byte:02X}",
                    "plain_byte": p_byte,
                    "key_char": chr(k_raw_byte) if 32 <= k_raw_byte <= 126 else f"0x{k_raw_byte:02X}",
                    "shift_byte": k_ring_byte,
                    "cipher_byte": c_byte,
                    "cipher_hex": f"{c_byte:02X}",
                    "formula": f"({p_byte} + {k_ring_byte}) mod 256 = {c_byte}",
                }
            )

        return VigenereInspection(
            plaintext_preview=plaintext[:64],
            key_preview=master_key,
            extended_key_hex=key_ring[:32].hex().upper(),
            ciphertext_hex=cipher.hex().upper(),
            ciphertext_b64=base64.b64encode(cipher).decode("ascii"),
            byte_shifts=steps,
            mac_hex=mac_hex.upper(),
        )

    @staticmethod
    def classic_alphabetic_vigenere(text: str, key: str, decrypt: bool = False) -> str:
        """
        Aplica também a Cifra de Vigenère clássica ASCII imprimível (carácter a carácter,
        intervalo ASCII 32..126 = 95 caracteres) para visualização legível direta na tabela
        do cofre ou modo pedagógico.
        """
        if not key:
            return text
        out_chars = []
        key_len = len(key)
        for i, ch in enumerate(text):
            code = ord(ch)
            if 32 <= code <= 126:
                k_shift = (ord(key[i % key_len]) - 32) % 95
                if decrypt:
                    new_code = 32 + ((code - 32 - k_shift) % 95)
                else:
                    new_code = 32 + ((code - 32 + k_shift) % 95)
                out_chars.append(chr(new_code))
            else:
                out_chars.append(ch)
        return "".join(out_chars)
