# Testes Automatizados da Suite Criptex
# Verifica:
#  1. Motor da Cifra de Vigenère (Passwords UTF-8, Ficheiros Binários Mod 256, HMAC-SHA256)
#  2. Gestor de Chave Física USB (Provisionamento vinculado ao Serial Number e leitura)
#  3. Cenário de Smartphone Roubado SEM Pen USB Física: O Criptex abre mas TODOS os dados
#     (passwords e ficheiros) permanecem encriptados!
#  4. Servidor Biométrico WebAuthn + QR Code e Escudo de Fortificação Windows

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from criptex.crypto.vigenere import VigenereCipher
from criptex.vault.storage import CriptexVaultStorage
from criptex.security.fortress import FortressShield
from criptex.security.usb_key import UsbKeyManager
from criptex.biometrics.webauthn_server import SmartphoneBiometricServer
from criptex.biometrics.pc_biometrics import PcBiometricAuthenticator
from criptex.i18n import detect_computer_locale, get_detected_language_Summary, tr


class TestCriptexSuite(unittest.TestCase):
    def test_vigenere_bytes_and_passwords(self) -> None:
        key = "CHAVE-SECRETA-VIGENERE-2026"
        sample_pw = "MinhaPasswordSuperForte!@#99"

        token = VigenereCipher.encrypt_password_str(sample_pw, key)
        self.assertTrue(token.startswith("VIG$"))
        recovered = VigenereCipher.decrypt_password_str(token, key)
        self.assertEqual(recovered, sample_pw)

        with self.assertRaises(ValueError):
            VigenereCipher.decrypt_password_str(token, "CHAVE-ERRADA")

        ascii_cipher = VigenereCipher.classic_alphabetic_vigenere(sample_pw, key, decrypt=False)
        self.assertNotEqual(ascii_cipher, sample_pw)
        ascii_plain = VigenereCipher.classic_alphabetic_vigenere(ascii_cipher, key, decrypt=True)
        self.assertEqual(ascii_plain, sample_pw)

    def test_usb_hardware_key_and_stolen_smartphone_scenario(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            vault_dir = Path(tmpdir) / ".criptex_vault"
            usb_mount = Path(tmpdir) / "USB_DRIVE_E"
            usb_mount.mkdir(parents=True, exist_ok=True)

            usb_mgr = UsbKeyManager(custom_mount_paths=[usb_mount])
            drives = usb_mgr.scan_usb_drives()
            usb_drive = next(d for d in drives if d.mount_point == str(usb_mount))

            # 1. Provisionar a palavra-chave da Cifra de Vigenère na Pen USB
            usb_key, key_file = usb_mgr.provision_usb_key(usb_drive, vigenere_key="USB-VIGENERE-SECRET-KEY-99")
            self.assertTrue(key_file.exists())

            found_drive, read_key = usb_mgr.find_active_usb_key()
            self.assertIsNotNone(found_drive)
            self.assertEqual(read_key, "USB-VIGENERE-SECRET-KEY-99")

            # 2. Inicializar o cofre com a chave da Pen USB e guardar passwords e ficheiros
            storage = CriptexVaultStorage(base_dir=vault_dir)
            storage.initialize_vault(usb_master_key=read_key, usb_serial=usb_drive.serial_number)

            pw_entry = storage.add_password(
                usb_master_key=read_key,
                title="Banco Suíço",
                username="tiago_vip",
                plain_password="UltraSecretPassword#2026",
                url="https://swissbank.ch",
                notes="Chave cofre: 4411",
            )

            src_file = Path(tmpdir) / "relatorio_secreto.txt"
            original_bytes = b"CONTEUDO CONFIDENCIAL PROTEGIDO POR VIGENERE NA PEN USB!\n" * 3
            src_file.write_bytes(original_bytes)
            f_entry = storage.import_file(src_file, read_key, shred_original=False)

            # 3. CENÁRIO: Smartphone Roubado SEM a Pen USB ligada (usb_master_key = None)
            # O Criptex abre e lista os registos, mas todos os dados permanecem encriptados!
            locked_passwords = storage.list_passwords(usb_master_key=None)
            self.assertEqual(len(locked_passwords), 1)
            self.assertIsNone(locked_passwords[0].decrypted_title)
            self.assertIsNone(locked_passwords[0].decrypted_username)
            self.assertNotEqual(locked_passwords[0].title_vigenere_ascii, "Banco Suíço")

            # Tentar revelar a password sem a Pen USB lança PermissionError
            with self.assertRaises(PermissionError):
                storage.reveal_password(locked_passwords[0], usb_master_key=None)

            # Listar ficheiros sem a Pen USB mantém o nome original e os bytes encriptados
            locked_files = storage.list_files(usb_master_key=None)
            self.assertEqual(len(locked_files), 1)
            self.assertIsNone(locked_files[0].decrypted_original_name)

            locked_inspection = storage.inspect_vault_file_bytes(f_entry.id, usb_master_key=None)
            self.assertFalse(locked_inspection["usb_unlocked"])
            self.assertIn("CONTEÚDO ENCRIPTADO", locked_inspection["plain_text_preview"])

            with self.assertRaises(PermissionError):
                storage.export_decrypted_file(f_entry.id, Path(tmpdir) / "out.txt", usb_master_key=None)

            # 4. CENÁRIO: Pen USB Física Inserida + Biometria (usb_master_key = read_key)
            unlocked_passwords = storage.list_passwords(usb_master_key=read_key)
            self.assertEqual(unlocked_passwords[0].decrypted_title, "Banco Suíço")
            plain_pw, plain_notes = storage.reveal_password(unlocked_passwords[0], usb_master_key=read_key)
            self.assertEqual(plain_pw, "UltraSecretPassword#2026")

            exported = Path(tmpdir) / "restaurado.txt"
            storage.export_decrypted_file(f_entry.id, exported, usb_master_key=read_key)
            self.assertEqual(exported.read_bytes(), original_bytes)

    def test_fortress_shield_keyboard_masking_and_chaffing(self) -> None:
        shield = FortressShield()
        shield.start_keyboard_masking()
        self.assertTrue(shield.status.keyboard_shield_active)

        chaff = shield.inject_external_chaff_burst(count=5)
        self.assertEqual(len(chaff), 5)
        self.assertEqual(shield.status.masked_keystrokes_count, 1)
        self.assertEqual(shield.status.chaff_injected_count, 5)

        shield.stop_keyboard_masking()
        self.assertFalse(shield.status.keyboard_shield_active)

    def test_biometric_https_server_handshake_and_device_locking(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = CriptexVaultStorage(base_dir=Path(tmpdir) / ".criptex_vault")
            storage.initialize_vault("CHAVE-TESTE")
            auth_events = []

            server = SmartphoneBiometricServer(
                vault_storage=storage,
                on_authenticated=lambda res: auth_events.append(res),
            )
            url = server.start()
            self.assertTrue(url.startswith("https://"))
            self.assertFalse(storage.is_biometric_paired())

            # 1º Uso do QR Code: Smartphone A autentica e fica permanentemente registado
            ok_1, msg_1, res_1 = server.verify_mobile_payload(
                {
                    "mode": "mobile_signed_token",
                    "session_token": server.session_token,
                    "challenge_b64": server.challenge_b64,
                    "device_token_hash": "hash_smartphone_original_A",
                    "user_agent": "iPhone 16 Pro (Telemóvel Original)",
                },
                client_ip="192.168.1.50",
            )
            self.assertTrue(ok_1)
            self.assertIsNotNone(res_1)
            self.assertTrue(storage.is_biometric_paired())

            # 2º Uso: O mesmo Smartphone A volta a desbloquear -> ACEITE
            ok_2, msg_2, res_2 = server.verify_mobile_payload(
                {
                    "mode": "mobile_signed_token",
                    "session_token": server.session_token,
                    "challenge_b64": server.challenge_b64,
                    "device_token_hash": "hash_smartphone_original_A",
                    "user_agent": "iPhone 16 Pro (Telemóvel Original)",
                },
                client_ip="192.168.1.50",
            )
            self.assertTrue(ok_2)

            # Tentativa com um Smartphone B diferente -> REJEITADO!
            ok_bad, msg_bad, res_bad = server.verify_mobile_payload(
                {
                    "mode": "mobile_signed_token",
                    "session_token": server.session_token,
                    "challenge_b64": server.challenge_b64,
                    "device_token_hash": "hash_smartphone_intruso_B",
                    "user_agent": "Dispositivo Não Autorizado",
                },
                client_ip="192.168.1.99",
            )
            self.assertFalse(ok_bad)
            self.assertIsNone(res_bad)

            # Tentar alterar o telemóvel registado SEM a Pen USB física -> PermissionError
            with self.assertRaises(PermissionError):
                storage.reset_biometric_pairing(usb_master_key=None, original_biometric_verified=True)

            # Tentar alterar o telemóvel registado SEM o desbloqueio biométrico original -> PermissionError
            with self.assertRaises(PermissionError):
                storage.reset_biometric_pairing(usb_master_key="CHAVE-TESTE", original_biometric_verified=False)

            # Alterar nas Definições dentro do cofre COM o desbloqueio original + Pen USB -> SUCESSO
            storage.reset_biometric_pairing(usb_master_key="CHAVE-TESTE", original_biometric_verified=True)
            self.assertFalse(storage.is_biometric_paired())

            # Agora o novo Smartphone B pode ser registado no próximo 1º uso
            ok_new, msg_new, res_new = server.verify_mobile_payload(
                {
                    "mode": "mobile_signed_token",
                    "session_token": server.session_token,
                    "challenge_b64": server.challenge_b64,
                    "device_token_hash": "hash_smartphone_novo_B",
                    "user_agent": "Novo Smartphone Autorizado",
                },
                client_ip="192.168.1.60",
            )
            self.assertTrue(ok_new)
            self.assertTrue(storage.is_biometric_paired())
            server.stop()

    def test_os_language_detection_and_translations(self) -> None:
        lang_code, locale_tag = detect_computer_locale()
        self.assertIn(lang_code, ("pt", "en", "es", "fr", "de", "it"))
        self.assertTrue(len(locale_tag) >= 2)
        self.assertIn(locale_tag, get_detected_language_Summary())
        self.assertIsInstance(tr("Smartphone (Código QR)"), str)
        self.assertIsInstance(tr("Impressão Digital do PC"), str)

    def test_pc_biometrics_sensor_detection(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = CriptexVaultStorage(base_dir=Path(tmpdir) / ".criptex_vault")
            pc_bio = PcBiometricAuthenticator(vault_storage=storage)
            available, desc = pc_bio.check_sensor_status()
            self.assertIsInstance(available, bool)
            self.assertTrue(len(desc) > 0)


if __name__ == "__main__":
    unittest.main()
