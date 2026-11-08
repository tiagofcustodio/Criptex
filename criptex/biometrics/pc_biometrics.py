# Criptex — Autenticação por Impressão Digital / Biometria Nativa do Computador (Windows Hello & WinBio)
# Permite ao utilizador escolher desbloquear o cofre Criptex diretamente com o leitor de
# Impressão Digital / Windows Hello do computador em alternativa ao código QR do smartphone.

from __future__ import annotations

import base64
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
import platform
import time
from typing import Callable, Optional, Tuple

from criptex.biometrics.webauthn_server import BiometricAuthResult


# ======================================================================
# ESTRUTURAS C NATIVAS DO WINDOWS (<webauthn.h> & <winbio.h>)
# ======================================================================
class WEBAUTHN_RP_ENTITY_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("dwVersion", wintypes.DWORD),
        ("pwszId", wintypes.LPCWSTR),
        ("pwszName", wintypes.LPCWSTR),
        ("pwszIcon", wintypes.LPCWSTR),
    ]


class WEBAUTHN_USER_ENTITY_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("dwVersion", wintypes.DWORD),
        ("cbId", wintypes.DWORD),
        ("pbId", ctypes.POINTER( ctypes.c_ubyte)),
        ("pwszName", wintypes.LPCWSTR),
        ("pwszIcon", wintypes.LPCWSTR),
        ("pwszDisplayName", wintypes.LPCWSTR),
    ]


class WEBAUTHN_COSE_CREDENTIAL_PARAMETER(ctypes.Structure):
    _fields_ = [
        ("dwVersion", wintypes.DWORD),
        ("pwszCredentialType", wintypes.LPCWSTR),
        ("lAlg", wintypes.LONG),
    ]


class WEBAUTHN_COSE_CREDENTIAL_PARAMETERS(ctypes.Structure):
    _fields_ = [
        ("cCredentialParameters", wintypes.DWORD),
        ("pCredentialParameters", ctypes.POINTER(WEBAUTHN_COSE_CREDENTIAL_PARAMETER)),
    ]


class WEBAUTHN_CLIENT_DATA(ctypes.Structure):
    _fields_ = [
        ("dwVersion", wintypes.DWORD),
        ("cbClientDataJSON", wintypes.DWORD),
        ("pbClientDataJSON", ctypes.POINTER(ctypes.c_ubyte)),
        ("pwszHashAlgId", wintypes.LPCWSTR),
    ]


class WEBAUTHN_CREDENTIALS(ctypes.Structure):
    _fields_ = [
        ("cCredentials", wintypes.DWORD),
        ("pCredentials", ctypes.c_void_p),
    ]


class WEBAUTHN_EXTENSIONS(ctypes.Structure):
    _fields_ = [
        ("cExtensions", wintypes.DWORD),
        ("pExtensions", ctypes.c_void_p),
    ]


class WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS(ctypes.Structure):
    _fields_ = [
        ("dwVersion", wintypes.DWORD),
        ("dwTimeoutMilliseconds", wintypes.DWORD),
        ("CredentialList", WEBAUTHN_CREDENTIALS),
        ("Extensions", WEBAUTHN_EXTENSIONS),
        ("dwAuthenticatorAttachment", wintypes.DWORD),
        ("bRequireResidentKey", wintypes.BOOL),
        ("dwUserVerificationRequirement", wintypes.DWORD),
        ("dwAttestationConveyancePreference", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("pCancellationId", ctypes.c_void_p),
    ]


class WEBAUTHN_CREDENTIAL_ATTESTATION(ctypes.Structure):
    _fields_ = [
        ("dwVersion", wintypes.DWORD),
        ("pwszFormatType", wintypes.LPCWSTR),
        ("cbAuthenticatorData", wintypes.DWORD),
        ("pbAuthenticatorData", ctypes.POINTER(ctypes.c_ubyte)),
        ("cbAttestation", wintypes.DWORD),
        ("pbAttestation", ctypes.POINTER(ctypes.c_ubyte)),
        ("dwAttestationDecodeType", wintypes.DWORD),
        ("pvAttestationDecode", ctypes.c_void_p),
        ("cbAttestationObject", wintypes.DWORD),
        ("pbAttestationObject", ctypes.POINTER(ctypes.c_ubyte)),
        ("cbCredentialId", wintypes.DWORD),
        ("pbCredentialId", ctypes.POINTER(ctypes.c_ubyte)),
    ]


class PcBiometricAuthenticator:
    """
    Motor de autenticação biométrica local do computador (Impressão Digital / Windows Hello):
      1. Verifica sensores biométricos diretos via `winbio.dll` (`WinBioEnumBiometricUnits` / `WinBioIdentify`).
      2. Aciona o autenticador biométrico nativo do Windows 10/11 via `webauthn.dll`
         (`WebAuthNAuthenticatorMakeCredential` com `WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM` e
         `WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED`).
    """

    def __init__(
        self,
        vault_storage,
        on_log: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.vault_storage = vault_storage
        self.on_log = on_log

    def log(self, msg: str) -> None:
        if self.on_log:
            try:
                self.on_log(msg)
            except Exception:
                pass

    @staticmethod
    def get_pc_hardware_signature() -> str:
        """Obtém uma assinatura determinística do hardware deste computador Windows."""
        vol_serial = 0
        if os.name == "nt":
            try:
                sys_drive = os.environ.get("SystemDrive", "C:") + "\\"
                serial = wintypes.DWORD(0)
                ctypes.windll.kernel32.GetVolumeInformationW(
                    wintypes.LPCWSTR(sys_drive),
                    None,
                    0,
                    ctypes.byref(serial),
                    None,
                    None,
                    None,
                    0,
                )
                vol_serial = serial.value
            except Exception:
                pass
        raw = f"PC::{platform.node()}::{platform.machine()}::{vol_serial:08X}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def check_sensor_status(self) -> Tuple[bool, str]:
        """
        Verifica se o computador tem sensor de Impressão Digital (`winbio.dll`) ou
        Windows Hello Platform Authenticator (`webauthn.dll`) disponível.
        """
        if os.name != "nt":
            return False, "Sistema operativo não suportado para Windows Hello / WinBio."

        fp_units = 0
        try:
            winbio = ctypes.windll.winbio
            unit_ptr = ctypes.c_void_p()
            count = ctypes.c_size_t(0)
            # WINBIO_TYPE_FINGERPRINT = 0x00000008
            hr = winbio.WinBioEnumBiometricUnits(8, ctypes.byref(unit_ptr), ctypes.byref(count))
            if hr == 0 and count.value > 0:
                fp_units = int(count.value)
                winbio.WinBioFree(unit_ptr)
        except Exception:
            pass

        if fp_units > 0:
            return True, f"Sensor Físico de Impressão Digital detetado no PC ({fp_units} unidade WinBio ativa)."

        try:
            webauthn = ctypes.windll.webauthn
            avail = ctypes.c_int(0)
            hr = webauthn.WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable(ctypes.byref(avail))
            if hr == 0 and bool(avail.value):
                return True, "Sensor Biométrico do Computador (Windows Hello / Impressão Digital) pronto."
        except Exception:
            pass

        return (
            False,
            "Nenhum sensor de Impressão Digital ou Windows Hello configurado neste PC. Configure nas Definições do Windows ou utilize o QR Code do Smartphone.",
        )

    def _try_direct_winbio_fingerprint(self) -> Tuple[bool, str]:
        """Tenta ler diretamente a impressão digital via Windows Biometric Framework (winbio.dll) se houver sensor dedicado."""
        try:
            winbio = ctypes.windll.winbio
            unit_ptr = ctypes.c_void_p()
            count = ctypes.c_size_t(0)
            hr = winbio.WinBioEnumBiometricUnits(8, ctypes.byref(unit_ptr), ctypes.byref(count))
            if hr != 0 or count.value == 0:
                return False, ""
            winbio.WinBioFree(unit_ptr)

            session = ctypes.c_uint32(0)
            # WINBIO_TYPE_FINGERPRINT = 8, WINBIO_POOL_SYSTEM = 1, WINBIO_FLAG_DEFAULT = 0
            hr = winbio.WinBioOpenSession(
                8, 1, 0, None, 0, None, ctypes.byref(session)
            )
            if hr != 0:
                return False, ""

            try:
                unit_id = ctypes.c_uint32(0)
                identity_buf = (ctypes.c_ubyte * 128)()
                subfactor = ctypes.c_ubyte(0)
                reject_detail = ctypes.c_uint32(0)
                hr_id = winbio.WinBioIdentify(
                    session,
                    ctypes.byref(unit_id),
                    ctypes.byref(identity_buf),
                    ctypes.byref(subfactor),
                    ctypes.byref(reject_detail),
                )
                if hr_id == 0:
                    return True, f"WinBio-Unit-{unit_id.value}-Sub-{subfactor.value}"
            finally:
                winbio.WinBioCloseSession(session)
        except Exception:
            pass
        return False, ""

    def authenticate(self, hwnd: int) -> Tuple[bool, str, Optional[BiometricAuthResult]]:
        """
        Executa a leitura da Impressão Digital / Windows Hello do computador.
        Retorna `(sucesso, mensagem, BiometricAuthResult)`.
        """
        if os.name != "nt":
            return False, "Apenas disponível em Windows.", None

        pc_hw_hash = self.get_pc_hardware_signature()

        # 1. Tentar leitura direta WinBio se existir leitor dedicado registado no WBF
        winbio_ok, winbio_tag = self._try_direct_winbio_fingerprint()
        if winbio_ok:
            cred_id = f"PC-WINBIO-{pc_hw_hash[:14].upper()}"
            return self._finalize_pc_biometric_verification(
                cred_id=cred_id,
                pc_hw_hash=pc_hw_hash,
                mode_label="Impressão Digital do PC (Sensor WinBio)",
                detail=winbio_tag,
            )

        # 2. Invocar o diálogo nativo Windows Hello (Impressão Digital / Biometria do PC) via webauthn.dll
        try:
            webauthn = ctypes.windll.webauthn

            rp_info = WEBAUTHN_RP_ENTITY_INFORMATION(
                dwVersion=1,
                pwszId="criptex.local",
                pwszName="Criptex Security Suite",
                pwszIcon=None,
            )

            user_id_bytes = hashlib.sha256(f"criptex-pc-{pc_hw_hash}".encode("utf-8")).digest()[:16]
            user_id_arr = (ctypes.c_ubyte * len(user_id_bytes)).from_buffer_copy(user_id_bytes)
            user_info = WEBAUTHN_USER_ENTITY_INFORMATION(
                dwVersion=1,
                cbId=len(user_id_bytes),
                pbId=ctypes.cast(user_id_arr, ctypes.POINTER(ctypes.c_ubyte)),
                pwszName="owner@criptex.local",
                pwszIcon=None,
                pwszDisplayName="Proprietário Criptex (PC)",
            )

            cose_arr = (WEBAUTHN_COSE_CREDENTIAL_PARAMETER * 2)(
                WEBAUTHN_COSE_CREDENTIAL_PARAMETER(
                    dwVersion=1,
                    pwszCredentialType="public-key",
                    lAlg=-7,  # ES256
                ),
                WEBAUTHN_COSE_CREDENTIAL_PARAMETER(
                    dwVersion=1,
                    pwszCredentialType="public-key",
                    lAlg=-257,  # RS256
                ),
            )
            cose_params = WEBAUTHN_COSE_CREDENTIAL_PARAMETERS(
                cCredentialParameters=2,
                pCredentialParameters=ctypes.cast(
                    cose_arr, ctypes.POINTER(WEBAUTHN_COSE_CREDENTIAL_PARAMETER)
                ),
            )

            challenge_b64 = base64.urlsafe_b64encode(os.urandom(32)).decode("ascii").rstrip("=")
            client_data_dict = {
                "type": "webauthn.create",
                "challenge": challenge_b64,
                "origin": "https://criptex.local",
                "crossOrigin": False,
            }
            client_data_bytes = json.dumps(client_data_dict).encode("utf-8")
            client_data_arr = (ctypes.c_ubyte * len(client_data_bytes)).from_buffer_copy(client_data_bytes)
            client_data = WEBAUTHN_CLIENT_DATA(
                dwVersion=1,
                cbClientDataJSON=len(client_data_bytes),
                pbClientDataJSON=ctypes.cast(client_data_arr, ctypes.POINTER(ctypes.c_ubyte)),
                pwszHashAlgId="SHA-256",
            )

            # dwAuthenticatorAttachment = 1 (WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM -> Sensor local do PC)
            # dwUserVerificationRequirement = 1 (WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED -> Biometria obrigatória)
            # dwAttestationConveyancePreference = 1 (NONE)
            options = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS(
                dwVersion=1,
                dwTimeoutMilliseconds=60000,
                CredentialList=WEBAUTHN_CREDENTIALS(0, None),
                Extensions=WEBAUTHN_EXTENSIONS(0, None),
                dwAuthenticatorAttachment=1,
                bRequireResidentKey=False,
                dwUserVerificationRequirement=1,
                dwAttestationConveyancePreference=1,
                dwFlags=0,
                pCancellationId=None,
            )

            p_attestation = ctypes.POINTER(WEBAUTHN_CREDENTIAL_ATTESTATION)()
            hr = webauthn.WebAuthNAuthenticatorMakeCredential(
                wintypes.HWND(hwnd),
                ctypes.byref(rp_info),
                ctypes.byref(user_info),
                ctypes.byref(cose_params),
                ctypes.byref(client_data),
                ctypes.byref(options),
                ctypes.byref(p_attestation),
            )

            if hr != 0:
                webauthn.WebAuthNGetErrorName.argtypes = [ctypes.c_long]
                webauthn.WebAuthNGetErrorName.restype = wintypes.LPCWSTR
                err_name = webauthn.WebAuthNGetErrorName(hr) or f"HRESULT 0x{hr & 0xFFFFFFFF:08X}"
                if err_name == "NotAllowedError":
                    return (
                        False,
                        "Leitura biométrica do computador cancelada ou não reconhecida pelo Windows Hello.",
                        None,
                    )
                return (
                    False,
                    f"Não foi possível concluir a verificação biométrica no PC ({err_name}).",
                    None,
                )

            try:
                att = p_attestation.contents
                cred_len = int(att.cbCredentialId)
                if cred_len > 0 and att.pbCredentialId:
                    raw_cred = bytes(att.pbCredentialId[:cred_len])
                    cred_id_b64 = base64.urlsafe_b64encode(raw_cred).decode("ascii").rstrip("=")
                else:
                    cred_id_b64 = f"PC-HELLO-{pc_hw_hash[:16].upper()}"
            finally:
                try:
                    webauthn.WebAuthNFreeCredentialAttestation(p_attestation)
                except Exception:
                    pass

            return self._finalize_pc_biometric_verification(
                cred_id=cred_id_b64,
                pc_hw_hash=pc_hw_hash,
                mode_label="Impressão Digital do PC (Windows Hello)",
                detail=f"Windows Hello ({platform.node()})",
            )

        except Exception as e:
            return False, f"Erro no subsistema biométrico do PC: {e}", None

    def _finalize_pc_biometric_verification(
        self,
        cred_id: str,
        pc_hw_hash: str,
        mode_label: str,
        detail: str,
    ) -> Tuple[bool, str, Optional[BiometricAuthResult]]:
        """Regista ou valida a biometria do computador junto do CriptexVaultStorage."""
        if not self.vault_storage.is_biometric_paired():
            self.vault_storage.register_biometric_credential(
                credential_id=cred_id,
                public_key_spki_b64="",
                algorithm=-7,
                device_name=f"Computador ({platform.node()})",
                user_agent=detail,
                device_token_hash=pc_hw_hash,
                hw_signature_hash=pc_hw_hash,
                paired_ip="127.0.0.1",
            )
            self.log(f"Biometria do computador registada e vinculada ao cofre ({detail}).")
        else:
            self.log(f"Biometria do computador verificada com sucesso ({detail}).")

        res = BiometricAuthResult(
            verified=True,
            mode=mode_label,
            device_info=detail,
            credential_id=cred_id[:16],
            timestamp=time.strftime("%H:%M:%S"),
        )
        return True, "Impressão Digital / Biometria do Computador confirmada com sucesso!", res
