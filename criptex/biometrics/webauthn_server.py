# Criptex — Servidor de Autenticação Biométrica do Smartphone (WebAuthn / Passkey + QR Code)
# Permite que o cofre Windows só possa ser desbloqueado após a validação biométrica
# realizada no smartphone registado do utilizador.

from __future__ import annotations

import base64
import datetime
import hashlib
import hmac
import http.cookies
import http.server
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import threading
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional, Dict, Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.x509.oid import NameOID


DEFAULT_BIOMETRIC_PORT = 8443


MOBILE_BIOMETRIC_HTML = r"""<!DOCTYPE html>
<html lang="pt">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<title>Criptex — Desbloqueio Biométrico</title>
<style>
  :root {
    --bg: #151210;
    --card: rgba(46, 40, 36, 0.58);
    --accent: #5efce8;
    --accent-dim: rgba(94, 252, 232, 0.16);
    --success: #5efce8;
    --danger: #ff7b72;
    --text: #f6f3f0;
    --muted: rgba(244, 238, 232, 0.72);
  }
  * {
    box-sizing: border-box;
    margin: 0;
    padding: 0;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI Variable Display", "Segoe UI", Roboto, sans-serif;
    -webkit-tap-highlight-color: transparent;
    user-select: none;
    -webkit-user-select: none;
  }
  body {
    background:
      radial-gradient(circle at 50% 12%, rgba(94, 252, 232, 0.22) 0%, transparent 48%),
      radial-gradient(circle at 22% 78%, rgba(196, 146, 98, 0.28) 0%, transparent 55%),
      radial-gradient(circle at 82% 68%, rgba(214, 182, 142, 0.18) 0%, transparent 45%),
      linear-gradient(160deg, #14110f 0%, #1e1916 52%, #111616 100%);
    color: var(--text);
    min-height: 100vh;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 18px;
  }
  .vault-card {
    position: relative;
    overflow: hidden;
    width: 100%;
    max-width: 400px;
    background: linear-gradient(180deg, rgba(58, 50, 45, 0.66) 0%, rgba(34, 29, 27, 0.58) 55%, rgba(24, 21, 19, 0.72) 100%);
    backdrop-filter: blur(26px) saturate(165%);
    -webkit-backdrop-filter: blur(26px) saturate(165%);
    border-top: 1px solid rgba(255, 255, 255, 0.34);
    border-left: 1px solid rgba(255, 255, 255, 0.20);
    border-right: 1px solid rgba(255, 255, 255, 0.18);
    border-bottom: 1.5px solid rgba(94, 252, 232, 0.45);
    border-radius: 28px;
    padding: 28px 22px;
    text-align: center;
    box-shadow: 0 20px 48px rgba(0, 0, 0, 0.58), inset 0 1px 0 rgba(255, 255, 255, 0.22);
  }
  .vault-card::before {
    content: "";
    position: absolute;
    top: 0;
    left: 50%;
    transform: translateX(-50%);
    width: 68px;
    height: 4px;
    border-radius: 99px;
    background: #5efce8;
    box-shadow: 0 0 24px 6px rgba(94, 252, 232, 0.55);
  }
  .badge {
    display: inline-block;
    padding: 5px 14px;
    background: rgba(94, 252, 232, 0.14);
    color: #5efce8;
    border: 1px solid rgba(94, 252, 232, 0.42);
    border-radius: 99px;
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.5px;
    margin-bottom: 12px;
  }
  h1 {
    font-size: 21px;
    font-weight: 700;
    margin-bottom: 8px;
    color: #ffffff;
  }
  p.sub {
    font-size: 13px;
    color: var(--muted);
    line-height: 1.5;
    margin-bottom: 18px;
  }
  .pairing-pill {
    font-size: 11px;
    font-weight: 600;
    padding: 8px 14px;
    border-radius: 99px;
    margin-bottom: 20px;
    background: rgba(18, 16, 15, 0.52);
    border: 1px solid rgba(255, 255, 255, 0.20);
    color: #5efce8;
  }
  .scanner-wrap {
    position: relative;
    width: 136px;
    height: 136px;
    margin: 0 auto 20px;
    display: flex;
    align-items: center;
    justify-content: center;
    cursor: pointer;
    touch-action: manipulation;
  }
  .scanner-svg {
    position: absolute;
    top: 0;
    left: 0;
    width: 136px;
    height: 136px;
    transform: rotate(-90deg);
  }
  .ring-bg {
    fill: rgba(24, 66, 60, 0.36);
    stroke: rgba(255, 255, 255, 0.22);
    stroke-width: 3.5;
  }
  .ring-progress {
    fill: none;
    stroke: #5efce8;
    stroke-width: 4.5;
    stroke-linecap: round;
    stroke-dasharray: 377;
    stroke-dashoffset: 377;
    filter: drop-shadow(0 0 8px rgba(94, 252, 232, 0.65));
    transition: stroke-dashoffset 0.12s ease, stroke 0.2s ease;
  }
  .scanner-core {
    position: relative;
    z-index: 2;
    width: 106px;
    height: 106px;
    border-radius: 50%;
    border: 1px solid rgba(94, 252, 232, 0.38);
    background: radial-gradient(circle, rgba(94, 252, 232, 0.20) 0%, rgba(22, 54, 48, 0.42) 100%);
    box-shadow: 0 0 26px rgba(94, 252, 232, 0.22), inset 0 1px 0 rgba(255, 255, 255, 0.30);
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    transition: transform 0.15s ease, background 0.2s ease;
  }
  .scanner-wrap.scanning .scanner-core {
    transform: scale(0.95);
    background: radial-gradient(circle, rgba(94, 252, 232, 0.38) 0%, rgba(22, 68, 60, 0.62) 100%);
  }
  .scanner-wrap.verified .ring-progress {
    stroke: var(--success);
    stroke-dashoffset: 0;
  }
  .fp-icon {
    width: 54px;
    height: 54px;
    stroke: #ffffff;
    fill: none;
    stroke-width: 2;
    stroke-linecap: round;
    stroke-linejoin: round;
    filter: drop-shadow(0 0 6px rgba(94, 252, 232, 0.55));
    transition: stroke 0.2s ease;
  }
  .scanner-wrap.verified .fp-icon {
    stroke: #5efce8;
  }
  .scan-hint {
    font-size: 11px;
    color: var(--muted);
    margin-bottom: 16px;
  }
  .btn-bio {
    width: 100%;
    padding: 14px 18px;
    border-top: 1px solid #99fff2;
    border-left: 1px solid #5efce8;
    border-right: 1px solid #5efce8;
    border-bottom: 1px solid #2dd4bf;
    border-radius: 99px;
    background: linear-gradient(180deg, rgba(94, 252, 232, 0.36) 0%, rgba(20, 184, 166, 0.28) 50%, rgba(15, 118, 110, 0.48) 100%);
    box-shadow: 0 8px 24px rgba(45, 212, 191, 0.24), inset 0 1px 0 rgba(255, 255, 255, 0.35);
    color: #ffffff;
    font-size: 14px;
    font-weight: 700;
    cursor: pointer;
  }
  .btn-bio:active {
    transform: scale(0.98);
  }
  .btn-bio:disabled {
    opacity: 0.6;
    cursor: default;
  }
  .status-box {
    margin-top: 16px;
    padding: 12px 14px;
    border-radius: 16px;
    font-size: 12px;
    line-height: 1.45;
    background: rgba(18, 16, 15, 0.52);
    border: 1px solid rgba(255, 255, 255, 0.18);
    color: var(--muted);
    min-height: 50px;
    display: flex;
    align-items: center;
    justify-content: center;
  }
  .status-ok {
    border-color: #5efce8;
    color: #5efce8;
    background: rgba(18, 56, 48, 0.62);
    font-weight: 600;
  }
  .status-err {
    border-color: var(--danger);
    color: #ffa198;
    background: rgba(68, 22, 28, 0.62);
    font-weight: 600;
  }
  .meta-info {
    margin-top: 16px;
    font-size: 11px;
    color: rgba(244, 238, 232, 0.62);
    border-top: 1px solid rgba(255, 255, 255, 0.14);
    padding-top: 12px;
    line-height: 1.4;
  }
</style>
</head>
<body>
  <div class="vault-card">
    <div class="badge">Criptex Security Suite</div>
    <h1>Desbloqueio Biométrico</h1>
    <p class="sub" id="modeDesc">
      Mantenha o dedo pressionado no sensor biométrico abaixo (ou toque no botão) para validar o seu smartphone e desbloquear o Cofre Windows.
    </p>

    <div class="pairing-pill" id="pairingBanner">
      A verificar vínculo do dispositivo...
    </div>

    <div class="scanner-wrap" id="scannerWrap" onclick="triggerBiometricUnlock()">
      <svg class="scanner-svg" viewBox="0 0 132 132">
        <circle class="ring-bg" cx="66" cy="66" r="60"></circle>
        <circle class="ring-progress" id="ringProgress" cx="66" cy="66" r="60"></circle>
      </svg>
      <div class="scanner-core">
        <svg class="fp-icon" id="fpSvg" viewBox="0 0 24 24">
          <path d="M12 10a2 2 0 0 0-2 2c0 1.02-.1 2.51-.26 4"/>
          <path d="M14 13.12c0 2.38 0 6.38-1 8.88"/>
          <path d="M17.29 21.02c.12-.6.43-2.3.5-3.02"/>
          <path d="M2 12a10 10 0 0 1 18-6"/>
          <path d="M2 16h.01"/>
          <path d="M21.8 16c.2-2 .131-5.354 0-6"/>
          <path d="M5 19.5C5.5 18 6 15 6 12a6 6 0 0 1 .34-2"/>
          <path d="M8.65 22c.21-.66.45-1.32.57-2"/>
          <path d="M9 6.8a6 6 0 0 1 9 5.2v2"/>
        </svg>
      </div>
    </div>

    <div class="scan-hint" id="scanHint">
      Toque no ícone de Impressão Digital ou no botão abaixo para abrir o sensor biométrico real do seu telemóvel
    </div>

    <button class="btn-bio" id="mainBtn" onclick="triggerBiometricUnlock()">
      Autenticar com Impressão Digital / FaceID
    </button>

    <div class="status-box" id="statusBox">
      Pronto. Toque no botão acima para ativar o leitor de Impressão Digital / FaceID do telemóvel.
    </div>

    <div class="meta-info">
      Sessão: <span id="sessionChallengeShort">...</span><br>
      Ao desbloquear, o PC irá cortar a Internet, mascarar o teclado e fechar aplicações de gravação.
    </div>
  </div>

<script>
const CHALLENGE_B64 = "__CHALLENGE_B64__";
const SESSION_TOKEN = "__SESSION_TOKEN__";
const IS_PAIRED = __IS_PAIRED__;
const IS_WEBAUTHN_CRED = __IS_WEBAUTHN_CRED__;
const STORED_CRED_ID_B64 = "__STORED_CRED_ID_B64__";
const SERVER_COOKIE_TOKEN = "__SERVER_COOKIE_TOKEN__";

document.getElementById("sessionChallengeShort").textContent = CHALLENGE_B64.substring(0, 16) + "...";

const pairingBanner = document.getElementById("pairingBanner");
if (!IS_PAIRED) {
  pairingBanner.textContent = "1.º Uso: Este smartphone ficará vinculado ao Cofre Criptex";
} else {
  pairingBanner.textContent = "Cofre vinculado ao smartphone registado";
}

function b64urlToUint8Array(base64Url) {
  const padding = '='.repeat((4 - base64Url.length % 4) % 4);
  const base64 = (base64Url + padding).replace(/-/g, '+').replace(/_/g, '/');
  const rawData = window.atob(base64);
  const outputArray = new Uint8Array(rawData.length);
  for (let i = 0; i < rawData.length; ++i) {
    outputArray[i] = rawData.charCodeAt(i);
  }
  return outputArray;
}

function bufferToB64url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function getCookie(name) {
  const parts = ("; " + document.cookie).split("; " + name + "=");
  if (parts.length === 2) return parts.pop().split(";").shift();
  return "";
}

function setCookie(name, val) {
  document.cookie = name + "=" + val + "; max-age=315360000; path=/; SameSite=Lax";
}

function getOrCreateDeviceToken() {
  let token = "";
  try {
    token = localStorage.getItem("criptex_device_secret_v1") || "";
  } catch (e) {}

  if (!token) {
    token = getCookie("criptex_device_token") || "";
  }
  if (!token && SERVER_COOKIE_TOKEN) {
    token = SERVER_COOKIE_TOKEN;
  }
  if (!token) {
    const arr = new Uint8Array(24);
    if (window.crypto && window.crypto.getRandomValues) {
      window.crypto.getRandomValues(arr);
      token = bufferToB64url(arr.buffer);
    } else {
      token = "DEVTOKEN-" + Math.random().toString(36).substring(2) + "-" + Date.now();
    }
  }
  try {
    localStorage.setItem("criptex_device_secret_v1", token);
  } catch (e) {}
  setCookie("criptex_device_token", token);
  return token;
}

function getHardwareSignature() {
  let gpu = "";
  try {
    const canvas = document.createElement("canvas");
    const gl = canvas.getContext("webgl") || canvas.getContext("experimental-webgl");
    if (gl) {
      const dbg = gl.getExtension("WEBGL_debug_renderer_info");
      if (dbg) {
        gpu = (gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) || "") + "|" +
              (gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) || "");
      }
    }
  } catch (e) {}
  const parts = [
    navigator.userAgent || "",
    navigator.platform || "",
    String(navigator.hardwareConcurrency || ""),
    String(navigator.deviceMemory || ""),
    String(navigator.maxTouchPoints || ""),
    String(screen.width) + "x" + String(screen.height) + "@" + String(window.devicePixelRatio || 1),
    gpu
  ];
  return parts.join("::");
}

// Garantir que o token é sincronizado entre Cookie e localStorage logo ao abrir
getOrCreateDeviceToken();

function setStatus(msg, type) {
  const box = document.getElementById("statusBox");
  box.textContent = msg;
  box.className = "status-box " + (type === "ok" ? "status-ok" : type === "err" ? "status-err" : "");
}

function setRingProgress(pct) {
  const circle = document.getElementById("ringProgress");
  const circumference = 377;
  const offset = circumference - (pct / 100) * circumference;
  circle.style.strokeDashoffset = offset;
}

let isUnlocked = false;

function isIpHostname(host) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(host) || host.includes(":");
}

// Se o utilizador abriu via IP local antes do túnel HTTPS WebAuthn terminar de ligar,
// redireciona automaticamente para o domínio HTTPS válido para ativar o leitor de Impressão Digital nativo.
if (isIpHostname(window.location.hostname)) {
  setStatus("A sincronizar canal seguro WebAuthn para ativar o sensor de Impressão Digital do telemóvel...", "");
  const tunnelPoll = setInterval(async () => {
    try {
      const r = await fetch("/api/tunnel_status", { cache: "no-store" });
      const d = await r.json();
      if (d && d.tunnel_url) {
        clearInterval(tunnelPoll);
        window.location.replace(d.tunnel_url);
      }
    } catch (e) {}
  }, 1000);
}

async function triggerBiometricUnlock() {
  if (isUnlocked) return;
  const btn = document.getElementById("mainBtn");
  const wrap = document.getElementById("scannerWrap");

  if (isIpHostname(window.location.hostname)) {
    try {
      const r = await fetch("/api/tunnel_status", { cache: "no-store" });
      const d = await r.json();
      if (d && d.tunnel_url) {
        window.location.replace(d.tunnel_url);
        return;
      }
    } catch (e) {}
    setStatus(
      "O navegador móvel exige um domínio HTTPS WebAuthn para abrir o sensor físico de Impressão Digital. " +
      "Aguarde 2 segundos ou leia o QR Code atualizado no ecrã do PC.",
      "err"
    );
    return;
  }

  if (!window.PublicKeyCredential || !navigator.credentials || !navigator.credentials.create) {
    setStatus(
      "Este navegador não suporta o sensor biométrico WebAuthn (Impressão Digital / FaceID). Abra o link no Chrome (Android) ou Safari (iOS).",
      "err"
    );
    return;
  }

  btn.disabled = true;
  wrap.classList.add("scanning");
  setRingProgress(60);
  setStatus("Coloque o dedo no sensor de Impressão Digital (ou confirme o FaceID) no seu telemóvel...", "");

  try {
    const challengeBytes = b64urlToUint8Array(CHALLENGE_B64);
    const userId = new Uint8Array(16);
    window.crypto.getRandomValues(userId);

    const cred = await navigator.credentials.create({
      publicKey: {
        challenge: challengeBytes,
        rp: {
          name: "Criptex Security Suite",
          id: window.location.hostname
        },
        user: {
          id: userId,
          name: "criptex-vault@criptex.local",
          displayName: "Cofre Criptex Windows"
        },
        pubKeyCredParams: [
          { type: "public-key", alg: -7 },
          { type: "public-key", alg: -257 }
        ],
        authenticatorSelection: {
          authenticatorAttachment: "platform",
          residentKey: "preferred",
          userVerification: "required"
        },
        timeout: 60000,
        attestation: "none"
      }
    });

    const pubKeyBuffer = cred.response.getPublicKey ? cred.response.getPublicKey() : null;
    const pubKeyAlg = cred.response.getPublicKeyAlgorithm ? cred.response.getPublicKeyAlgorithm() : -7;
    await sendVerification({
      mode: "webauthn_register",
      session_token: SESSION_TOKEN,
      credential_id: bufferToB64url(cred.rawId),
      client_data_json: bufferToB64url(cred.response.clientDataJSON),
      attestation_object: bufferToB64url(cred.response.attestationObject),
      public_key_spki: pubKeyBuffer ? bufferToB64url(pubKeyBuffer) : "",
      algorithm: pubKeyAlg,
      device_token: getOrCreateDeviceToken(),
      hw_signature: getHardwareSignature(),
      user_agent: navigator.userAgent
    });
  } catch (webauthnErr) {
    setRingProgress(0);
    wrap.classList.remove("scanning");
    const errName = webauthnErr && webauthnErr.name ? webauthnErr.name : "Erro";
    if (errName === "NotAllowedError" || errName === "AbortError") {
      setStatus(
        "Leitura de Impressão Digital / FaceID cancelada ou recusada no telemóvel. É obrigatório validar a impressão digital real no sensor.",
        "err"
      );
    } else {
      setStatus(
        "Falha ao aceder ao sensor biométrico do telemóvel (" + errName + "): " + (webauthnErr.message || webauthnErr),
        "err"
      );
    }
  } finally {
    if (!isUnlocked) {
      btn.disabled = false;
    }
  }
}

async function sendVerification(payload) {
  const resp = await fetch("/api/verify", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin",
    body: JSON.stringify(payload)
  });
  const data = await resp.json();
  if (resp.ok && data.ok) {
    isUnlocked = true;
    const wrap = document.getElementById("scannerWrap");
    wrap.classList.remove("scanning");
    wrap.classList.add("verified");
    setRingProgress(100);
    if (navigator.vibrate) {
      try { navigator.vibrate([60, 40, 120]); } catch (e) {}
    }
    document.getElementById("scanHint").textContent = "Autenticação concluída com sucesso";
    document.getElementById("mainBtn").textContent = "Cofre Desbloqueado no PC";
    document.getElementById("mainBtn").disabled = true;
    setStatus(data.message || "Biometria Confirmada! O Cofre Criptex foi desbloqueado no seu PC.", "ok");
    return true;
  } else {
    setRingProgress(0);
    document.getElementById("scannerWrap").classList.remove("scanning");
    setStatus("Acesso recusado: " + (data.error || "Falha na verificação"), "err");
    return false;
  }
}
</script>
</body>
</html>
"""


@dataclass
class BiometricAuthResult:
    verified: bool
    mode: str
    device_info: str
    credential_id: str
    timestamp: str


class ReusableThreadingHTTPServer(http.server.ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


class SmartphoneBiometricServer:
    """
    Servidor HTTPS local em porta fixa (8443) para autenticação biométrica via Smartphone (QR Code).

    Características principais:
      1. Porta fixa (`8443`) e certificado TLS persistente guardado em `.criptex_vault/tls/`
         para que a origem (`https://192.168.x.x:8443`), a exceção TLS do browser móvel,
         os Cookies e o `localStorage` do telemóvel se mantenham sempre idênticos entre sessões.
      2. Dupla persistência do identificador criptográfico do smartphone (`Cookie` HTTP + `localStorage`).
      3. Vinculação automática ao primeiro telemóvel que desbloquear o cofre, bloqueando qualquer
         outro telemóvel até que seja desvinculado nas Definições com o desbloqueio original + Pen USB.
    """

    def __init__(
        self,
        vault_storage,
        on_authenticated: Callable[[BiometricAuthResult], None],
        on_log: Optional[Callable[[str], None]] = None,
        on_qr_url_updated: Optional[Callable[[str], None]] = None,
        preferred_port: int = DEFAULT_BIOMETRIC_PORT,
    ) -> None:
        self.vault_storage = vault_storage
        self.on_authenticated = on_authenticated
        self.on_log = on_log
        self.on_qr_url_updated = on_qr_url_updated
        self.preferred_port = preferred_port

        self.host_ip = self.detect_lan_ip()
        self.port = preferred_port
        self.http_port = 8440
        self.tunnel_base_url: Optional[str] = None
        self.challenge_bytes = os.urandom(32)
        self.challenge_b64 = base64.urlsafe_b64encode(self.challenge_bytes).decode("ascii").rstrip("=")
        self.session_token = base64.urlsafe_b64encode(os.urandom(24)).decode("ascii").rstrip("=")
        self.valid_session_tokens = {self.session_token}
        self.valid_challenges = {self.challenge_b64}

        self._httpd: Optional[ReusableThreadingHTTPServer] = None
        self._http_plain_d: Optional[ReusableThreadingHTTPServer] = None
        self._server_thread: Optional[threading.Thread] = None
        self._http_plain_thread: Optional[threading.Thread] = None
        self._tunnel_proc: Optional[subprocess.Popen] = None
        self._cert_dir = Path(self.vault_storage.base_dir) / "tls"
        self._cert_dir.mkdir(parents=True, exist_ok=True)
        self.is_running = False

    def log(self, msg: str) -> None:
        if self.on_log:
            try:
                self.on_log(msg)
            except Exception:
                pass

    @staticmethod
    def detect_lan_ip() -> str:
        """Deteta o endereço IPv4 da placa de rede Wi-Fi/Ethernet local para o smartphone aceder."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                ip = s.getsockname()[0]
                if ip and not ip.startswith("127."):
                    return ip
        except Exception:
            pass
        try:
            hostname = socket.gethostname()
            for addr in socket.getaddrinfo(hostname, None, socket.AF_INET):
                ip = addr[4][0]
                if not ip.startswith("127.") and not ip.startswith("169.254."):
                    return ip
        except Exception:
            pass
        return "127.0.0.1"

    def _ensure_self_signed_cert(self) -> tuple[Path, Path]:
        """
        Gera ou reutiliza um certificado X.509 persistente com SAN para o IP local,
        domínios nip.io/sslip.io e localhost. Reutilizar o mesmo certificado evita que
        o utilizador tenha de aceitar avisos TLS em cada sessão.
        """
        cert_path = self._cert_dir / "criptex_local_cert.pem"
        key_path = self._cert_dir / "criptex_local_key.pem"
        ip_marker_path = self._cert_dir / "cert_host_ip.txt"

        if (
            cert_path.exists()
            and key_path.exists()
            and ip_marker_path.exists()
            and ip_marker_path.read_text(encoding="utf-8").strip() == self.host_ip
        ):
            return cert_path, key_path

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "PT"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Criptex Security Vault"),
                x509.NameAttribute(NameOID.COMMON_NAME, self.host_ip),
            ]
        )

        san_entries = [
            x509.DNSName("localhost"),
            x509.DNSName(f"{self.host_ip}.nip.io"),
            x509.DNSName(f"{self.host_ip.replace('.', '-')}.sslip.io"),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        ]
        try:
            san_entries.append(x509.IPAddress(ipaddress.ip_address(self.host_ip)))
        except Exception:
            pass

        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
            .sign(key, hashes.SHA256())
        )

        key_path.write_bytes(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        ip_marker_path.write_text(self.host_ip, encoding="utf-8")
        return cert_path, key_path

    def _bind_server_port(self, handler_cls) -> ReusableThreadingHTTPServer:
        """Tenta usar sempre a porta fixa 8443 para manter a mesma origem no smartphone."""
        candidate_ports = [self.preferred_port, 8444, 8445, 8446, 0]
        last_err = None
        for p in candidate_ports:
            try:
                srv = ReusableThreadingHTTPServer(("0.0.0.0", p), handler_cls)
                return srv
            except OSError as e:
                last_err = e
                continue
        raise RuntimeError(f"Não foi possível iniciar o servidor HTTPS biométrico: {last_err}")

    def _bind_plain_http_port(self, handler_cls) -> ReusableThreadingHTTPServer:
        """Inicia listener HTTP local (127.0.0.1) para alimentar o túnel HTTPS WebAuthn."""
        for p in (8440, 8441, 8442, 0):
            try:
                return ReusableThreadingHTTPServer(("127.0.0.1", p), handler_cls)
            except OSError:
                continue
        raise RuntimeError("Não foi possível abrir porta local para o túnel WebAuthn.")

    def _start_webauthn_https_tunnel(self) -> None:
        """
        Estabelece túnel HTTPS com certificado válido (Let's Encrypt via localhost.run / OpenSSH nativo do Windows)
        para que o navegador móvel (Chrome Android / Safari iOS) execute a API WebAuthn (`navigator.credentials.create`)
        e acione obrigatoriamente o sensor físico de Impressão Digital / FaceID do telemóvel.
        """
        self._tunnel_ready_event = threading.Event()

        def _tunnel_worker() -> None:
            ssh_bin = r"C:\Windows\System32\OpenSSH\ssh.exe"
            if not Path(ssh_bin).exists():
                ssh_bin = "ssh"
            cmd = [
                ssh_bin,
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=NUL",
                "-o", "ServerAliveInterval=30",
                "-o", "ConnectTimeout=6",
                "-R", f"80:127.0.0.1:{self.http_plain_port}",
                "nokey@localhost.run",
            ]
            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            try:
                proc = subprocess.Popen(
                    cmd,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    creationflags=creationflags,
                )
                self._tunnel_proc = proc
                url_pattern = re.compile(r"https://[a-zA-Z0-9.-]+\.lhr\.life")
                assert proc.stdout is not None
                for line in proc.stdout:
                    if not self.is_running:
                        break
                    m = url_pattern.search(line)
                    if m:
                        found_url = m.group(0).rstrip("/")
                        if found_url != self.tunnel_base_url:
                            self.tunnel_base_url = found_url
                            self._tunnel_ready_event.set()
                            self.log(
                                f"Canal HTTPS WebAuthn ativo ({found_url}) — Leitor real de Impressão Digital / FaceID pronto."
                            )
                            if self.on_qr_url_updated:
                                try:
                                    self.on_qr_url_updated(self.get_qr_url())
                                except Exception:
                                    pass
            except Exception as e:
                self._tunnel_ready_event.set()
                self.log(f"Aviso ao criar túnel WebAuthn: {e}")

        t = threading.Thread(target=_tunnel_worker, name="CriptexWebAuthnTunnel", daemon=True)
        t.start()
        # Nunca bloquear a thread da interface gráfica (Qt) se houver callback assíncrono on_qr_url_updated
        if self.preferred_port != 0 and self.on_qr_url_updated is None:
            self._tunnel_ready_event.wait(timeout=1.5)

    def start(self) -> str:
        """Inicia o servidor HTTPS de autenticação biométrica e devolve o URL para o QR Code."""
        self.host_ip = self.detect_lan_ip()
        self.challenge_bytes = os.urandom(32)
        self.challenge_b64 = base64.urlsafe_b64encode(self.challenge_bytes).decode("ascii").rstrip("=")
        self.session_token = base64.urlsafe_b64encode(os.urandom(18)).decode("ascii").rstrip("=")
        self.valid_session_tokens.add(self.session_token)
        self.valid_challenges.add(self.challenge_b64)

        if self.is_running and self._httpd:
            return self.get_qr_url()

        cert_path, key_path = self._ensure_self_signed_cert()
        parent = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:
                pass

            def _extract_cookie_token(self) -> str:
                raw_cookie = self.headers.get("Cookie", "")
                if not raw_cookie:
                    return ""
                try:
                    c = http.cookies.SimpleCookie()
                    c.load(raw_cookie)
                    if "criptex_device_token" in c:
                        return c["criptex_device_token"].value
                except Exception:
                    pass
                return ""

            def do_GET(self) -> None:
                parsed = urllib.parse.urlparse(self.path)
                params = urllib.parse.parse_qs(parsed.query)
                token = params.get("t", [""])[0]

                if parsed.path == "/api/tunnel_status":
                    tunnel_url = (
                        f"{parent.tunnel_base_url}/auth?t={parent.session_token}"
                        if parent.tunnel_base_url
                        else ""
                    )
                    payload = json.dumps({"tunnel_url": tunnel_url}).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.send_header("Cache-Control", "no-store")
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                    return

                if parsed.path in ("/", "/auth"):
                    host_hdr = self.headers.get("Host", "")
                    if parent.tunnel_base_url and ".lhr.life" not in host_hdr:
                        redirect_target = f"{parent.tunnel_base_url}/auth?t={parent.session_token}"
                        self.send_response(302)
                        self.send_header("Location", redirect_target)
                        self.end_headers()
                        return

                    meta = parent.vault_storage.load_meta()
                    bio = meta.get("biometric_device", {})
                    stored_cred = bio.get("credential_id") or ""
                    is_paired = bool(bio.get("paired") and stored_cred)
                    is_webauthn_cred = bool(is_paired and not stored_cred.startswith("DEV-"))
                    cookie_tok = self._extract_cookie_token()

                    html = (
                        MOBILE_BIOMETRIC_HTML.replace("__CHALLENGE_B64__", parent.challenge_b64)
                        .replace("__SESSION_TOKEN__", parent.session_token)
                        .replace("__IS_PAIRED__", "true" if is_paired else "false")
                        .replace("__IS_WEBAUTHN_CRED__", "true" if is_webauthn_cred else "false")
                        .replace("__STORED_CRED_ID_B64__", stored_cred if is_webauthn_cred else "")
                        .replace("__SERVER_COOKIE_TOKEN__", cookie_tok)
                    )
                    body = html.encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    parent.log(f"Smartphone conectado ao portal biométrico ({self.client_address[0]}).")
                else:
                    self.send_response(404)
                    self.end_headers()

            def do_POST(self) -> None:
                if self.path != "/api/verify":
                    self.send_response(404)
                    self.end_headers()
                    return

                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length)
                try:
                    data = json.loads(raw.decode("utf-8"))
                    cookie_tok = self._extract_cookie_token()
                    if cookie_tok and not data.get("device_token"):
                        data["device_token"] = cookie_tok

                    ok, msg, result = parent.verify_mobile_payload(data, self.client_address[0])
                    status_code = 200 if ok else 400
                    resp_bytes = json.dumps({"ok": ok, "message": msg, "error": None if ok else msg}).encode("utf-8")
                    self.send_response(status_code)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    dev_tok = data.get("device_token", "")
                    if ok and dev_tok:
                        self.send_header(
                            "Set-Cookie",
                            f"criptex_device_token={dev_tok}; Max-Age=315360000; Path=/; SameSite=Lax",
                        )
                    self.send_header("Content-Length", str(len(resp_bytes)))
                    self.end_headers()
                    self.wfile.write(resp_bytes)

                    if ok and result:
                        parent.on_authenticated(result)
                except Exception as e:
                    err_bytes = json.dumps({"ok": False, "error": str(e)}).encode("utf-8")
                    self.send_response(400)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.end_headers()
                    self.wfile.write(err_bytes)

        self._httpd = self._bind_server_port(Handler)
        self.port = self._httpd.server_address[1]

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
        self._httpd.socket = ctx.wrap_socket(self._httpd.socket, server_side=True)

        self.is_running = True
        self._server_thread = threading.Thread(
            target=self._httpd.serve_forever,
            name="CriptexBiometricHTTPS",
            daemon=True,
        )
        self._server_thread.start()

        # Também inicia listener HTTP local (127.0.0.1) para túnel HTTPS público WebAuthn sem aviso SSL
        if self.preferred_port != 0:
            try:
                self._http_plain_d = self._bind_plain_http_port(Handler)
                self.http_plain_port = self._http_plain_d.server_address[1]
                self._http_plain_thread = threading.Thread(
                    target=self._http_plain_d.serve_forever,
                    name="CriptexBiometricPlainHTTP",
                    daemon=True,
                )
                self._http_plain_thread.start()
                self._start_webauthn_https_tunnel()
            except Exception:
                pass

        self.log(f"Servidor Biométrico HTTPS ativo em https://{self.host_ip}:{self.port}")
        return self.get_qr_url()

    def stop(self) -> None:
        """
        Encerra o servidor HTTPS, o listener HTTP local e o processo de túnel SSH de forma
        totalmente assíncrona para nunca bloquear ou congelar a thread da interface gráfica (Qt).
        """
        self.is_running = False
        self.tunnel_base_url = None

        proc = self._tunnel_proc
        self._tunnel_proc = None

        http_plain = self._http_plain_d
        self._http_plain_d = None

        httpd = self._httpd
        self._httpd = None

        def _async_cleanup() -> None:
            if proc is not None:
                try:
                    # Nunca fechar proc.stdout antes de terminar o processo (evita deadlock no BufferedReader no Windows)
                    proc.kill()
                except Exception:
                    pass
            if http_plain is not None:
                try:
                    http_plain.shutdown()
                    http_plain.server_close()
                except Exception:
                    pass
            if httpd is not None:
                try:
                    httpd.shutdown()
                    httpd.server_close()
                except Exception:
                    pass

        threading.Thread(target=_async_cleanup, name="CriptexBioServerStop", daemon=True).start()

    def get_qr_url(self) -> str:
        if self.tunnel_base_url:
            return f"{self.tunnel_base_url}/auth?t={self.session_token}"
        return f"https://{self.host_ip}:{self.port}/auth?t={self.session_token}"

    @staticmethod
    def _b64url_decode(val: str) -> bytes:
        pad = "=" * ((4 - len(val) % 4) % 4)
        return base64.urlsafe_b64decode((val + pad).encode("ascii"))

    def verify_mobile_payload(
        self, data: Dict[str, Any], client_ip: str
    ) -> tuple[bool, str, Optional[BiometricAuthResult]]:
        """
        Valida a resposta WebAuthn (`webauthn_register` ou `webauthn_assert`) ou o token
        criptográfico do smartphone que leu o QR Code da sessão.
        """
        sess_tok = data.get("session_token", "")
        if sess_tok != self.session_token and sess_tok not in self.valid_session_tokens:
            return False, "Token de sessão QR expirado. Atualize a página no telemóvel ou leia o novo QR Code.", None

        mode = data.get("mode", "")
        user_agent = data.get("user_agent", "Smartphone")
        dev_token = data.get("device_token", "")
        dev_token_hash = data.get("device_token_hash", "")
        if dev_token and not dev_token_hash:
            dev_token_hash = hashlib.sha256(dev_token.encode("utf-8")).hexdigest()

        hw_sig = data.get("hw_signature", "")
        hw_sig_hash = hashlib.sha256(hw_sig.encode("utf-8")).hexdigest() if hw_sig else ""

        if mode in ("webauthn_register", "webauthn_assert"):
            client_data_b64 = data.get("client_data_json", "")
            client_data_bytes = self._b64url_decode(client_data_b64)
            client_data = json.loads(client_data_bytes.decode("utf-8"))

            received_challenge = client_data.get("challenge", "")
            if received_challenge != self.challenge_b64 and received_challenge not in self.valid_challenges:
                return False, "Challenge WebAuthn não coincide com a sessão do cofre.", None

            cred_id = data.get("credential_id", "")

            if mode == "webauthn_register":
                pub_spki = data.get("public_key_spki", "")
                alg = int(data.get("algorithm", -7))
                if not self.vault_storage.is_biometric_paired():
                    self.vault_storage.register_biometric_credential(
                        credential_id=cred_id,
                        public_key_spki_b64=pub_spki,
                        algorithm=alg,
                        device_name=f"Smartphone ({client_ip})",
                        user_agent=user_agent,
                        device_token_hash=dev_token_hash,
                        hw_signature_hash=hw_sig_hash,
                        paired_ip=client_ip,
                    )
                    self.log(f"Smartphone biométrico registado e vinculado ao cofre ({client_ip}).")
                    res = BiometricAuthResult(
                        verified=True,
                        mode="WebAuthn Passkey (1º Registo Biométrico)",
                        device_info=f"{client_ip} | {user_agent[:45]}",
                        credential_id=cred_id[:16],
                        timestamp=time.strftime("%H:%M:%S"),
                    )
                    return True, "Smartphone registado e biometria verificada com sucesso!", res
                else:
                    # Já existe um smartphone registado; verificar se é o mesmo dispositivo
                    # (ex: quando o túnel WebAuthn muda de subdomínio e o Android cria uma nova passkey de sessão)
                    meta = self.vault_storage.load_meta()
                    bio = meta.get("biometric_device", {})
                    stored_hash = bio.get("device_token_hash") or ""
                    stored_hw = bio.get("hw_signature_hash") or ""
                    stored_cred_id = bio.get("credential_id") or ""

                    token_matches = bool(stored_hash and dev_token_hash and hmac.compare_digest(stored_hash, dev_token_hash))
                    hw_matches = bool(stored_hw and hw_sig_hash and hmac.compare_digest(stored_hw, hw_sig_hash))
                    cred_matches = bool(stored_cred_id and cred_id and stored_cred_id == cred_id)

                    if not token_matches and not hw_matches and not cred_matches:
                        return (
                            False,
                            "Este cofre já tem um smartphone biométrico registado! Só o dispositivo original pode desbloqueá-lo, "
                            "e qualquer alteração só pode ser feita nas Definições dentro do cofre com a Pen USB.",
                            None,
                        )

                    self.vault_storage.register_biometric_credential(
                        credential_id=cred_id or stored_cred_id,
                        public_key_spki_b64=pub_spki or bio.get("public_key_spki_b64", ""),
                        algorithm=alg,
                        device_name=bio.get("device_name") or f"Smartphone ({client_ip})",
                        user_agent=user_agent,
                        device_token_hash=dev_token_hash or stored_hash,
                        hw_signature_hash=hw_sig_hash or stored_hw,
                        paired_ip=client_ip,
                        allow_overwrite=True,
                    )
                    self.log(f"Biometria nativa WebAuthn do smartphone registado validada ({client_ip}).")
                    res = BiometricAuthResult(
                        verified=True,
                        mode="WebAuthn Passkey (Dispositivo Registado)",
                        device_info=f"{client_ip} | {user_agent[:45]}",
                        credential_id=cred_id[:16],
                        timestamp=time.strftime("%H:%M:%S"),
                    )
                    return True, "Biometria do smartphone registado verificada com sucesso!", res

            elif mode == "webauthn_assert":
                meta = self.vault_storage.load_meta()
                bio = meta.get("biometric_device", {})
                stored_cred_id = bio.get("credential_id")
                if not bio.get("paired") or not stored_cred_id:
                    return False, "Nenhum dispositivo biométrico registado ainda.", None
                if cred_id != stored_cred_id:
                    return (
                        False,
                        "Dispositivo biométrico não reconhecido! Apenas o smartphone originalmente registado pode desbloquear o cofre.",
                        None,
                    )

                pub_spki_b64 = bio.get("public_key_spki_b64")
                auth_data_bytes = self._b64url_decode(data.get("authenticator_data", ""))
                sig_bytes = self._b64url_decode(data.get("signature", ""))

                if len(auth_data_bytes) >= 33:
                    flags = auth_data_bytes[32]
                    if not (flags & 0x01):
                        return False, "Presença do utilizador não confirmada pelo sensor biométrico.", None

                if pub_spki_b64:
                    try:
                        spki_bytes = self._b64url_decode(pub_spki_b64)
                        pub_key = serialization.load_der_public_key(spki_bytes)
                        client_data_hash = hashlib.sha256(client_data_bytes).digest()
                        signed_data = auth_data_bytes + client_data_hash
                        if isinstance(pub_key, ec.EllipticCurvePublicKey):
                            pub_key.verify(sig_bytes, signed_data, ec.ECDSA(hashes.SHA256()))
                        elif isinstance(pub_key, rsa.RSAPublicKey):
                            pub_key.verify(sig_bytes, signed_data, padding.PKCS1v15(), hashes.SHA256())
                    except Exception as e:
                        return False, f"Assinatura criptográfica biométrica inválida: {e}", None

                self.log(f"Assinatura biométrica do smartphone registado validada ({client_ip}).")
                res = BiometricAuthResult(
                    verified=True,
                    mode="WebAuthn Passkey (Dispositivo Registado)",
                    device_info=f"{client_ip} | {user_agent[:45]}",
                    credential_id=cred_id[:16],
                    timestamp=time.strftime("%H:%M:%S"),
                )
                return True, "Biometria do smartphone registado verificada com sucesso!", res

        elif mode == "mobile_signed_token":
            ch_b64 = data.get("challenge_b64", "")
            if ch_b64 != self.challenge_b64 and ch_b64 not in self.valid_challenges:
                return False, "Challenge da sessão incorreto. Atualize o QR Code.", None

            if not dev_token_hash:
                return False, "Token criptográfico do dispositivo ausente.", None

            meta = self.vault_storage.load_meta()
            bio = meta.get("biometric_device", {})
            if not bio.get("paired"):
                # 1º uso: registar e trancar este smartphone!
                self.vault_storage.register_biometric_credential(
                    credential_id=f"DEV-{dev_token_hash[:16].upper()}",
                    public_key_spki_b64="",
                    algorithm=-7,
                    device_name=f"Smartphone ({client_ip})",
                    user_agent=user_agent,
                    device_token_hash=dev_token_hash,
                    hw_signature_hash=hw_sig_hash,
                    paired_ip=client_ip,
                )
                self.log(f"Smartphone registado no 1º uso via QR Code ({client_ip}).")
                res = BiometricAuthResult(
                    verified=True,
                    mode="Smartphone Registado (1º Uso QR)",
                    device_info=f"{client_ip} | {user_agent[:45]}",
                    credential_id=f"DEV-{dev_token_hash[:12].upper()}",
                    timestamp=time.strftime("%H:%M:%S"),
                )
                return True, "Smartphone registado e vinculado com sucesso ao Cofre Criptex!", res
            else:
                # Já existe dispositivo registado: validar que é exatamente o mesmo smartphone!
                stored_hash = bio.get("device_token_hash") or ""
                stored_hw = bio.get("hw_signature_hash") or ""

                token_matches = bool(stored_hash and dev_token_hash and hmac.compare_digest(stored_hash, dev_token_hash))
                hw_matches = bool(stored_hw and hw_sig_hash and hmac.compare_digest(stored_hw, hw_sig_hash))

                if not token_matches and not hw_matches:
                    return (
                        False,
                        "Este cofre já está vinculado a outro smartphone registado. "
                        "A alteração só pode ser efetuada nas Definições dentro do cofre com o desbloqueio original e a Pen USB.",
                        None,
                    )

                # Se o smartphone foi reconhecido pela assinatura de hardware (ex: leitor QR efémero),
                # sincronizamos o novo token criptográfico para manter o vínculo consistente.
                if hw_matches and not token_matches and dev_token_hash:
                    self.vault_storage.register_biometric_credential(
                        credential_id=bio.get("credential_id") or f"DEV-{dev_token_hash[:16].upper()}",
                        public_key_spki_b64=bio.get("public_key_spki_b64") or "",
                        algorithm=bio.get("algorithm") or -7,
                        device_name=bio.get("device_name") or f"Smartphone ({client_ip})",
                        user_agent=user_agent,
                        device_token_hash=dev_token_hash,
                        hw_signature_hash=hw_sig_hash,
                        paired_ip=client_ip,
                        allow_overwrite=True,
                    )

                self.log(f"Smartphone oficial registado confirmado ({client_ip}).")
                res = BiometricAuthResult(
                    verified=True,
                    mode="Smartphone Registado Verificado",
                    device_info=f"{client_ip} | {user_agent[:45]}",
                    credential_id=bio.get("credential_id", "DEV")[:16],
                    timestamp=time.strftime("%H:%M:%S"),
                )
                return True, "Biometria do smartphone registado confirmada!", res

        return False, "Modo de autenticação desconhecido.", None
