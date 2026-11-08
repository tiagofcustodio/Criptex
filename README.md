# CRIPTEX — Fortified Windows Digital Vault

**Author:** Tiago Custodio  
**Platform:** Windows 10 / 11 (`Python` + `PyQt6` + `Win32 Native APIs`)  
**UI Theme:** Liquid Frosted Glass & Mint Spotlight Edition

---

## Overview

**Criptex** is a fortified Windows desktop digital vault designed by **Tiago Custodio** to protect sensitive **passwords** and **files** using a multi-layered hardware and biometric security architecture:

1. **Polyalphabetic Vigenère Cipher Engine (`Mod 256` + `ASCII Mod 95` + `HMAC-SHA256`)** for both passwords and binary files (`.crpx`).
2. **Physical USB Hardware Key (`.criptex_usb_key.crpxkey`)** bound to the USB drive's hardware volume serial number.
3. **Dual-Option Biometric Authentication** — users can freely choose between:
   - **Smartphone Biometrics (QR Code / WebAuthn)** over a secure tunnel, or
   - **PC Fingerprint Sensor (Windows Hello / Windows Biometric Framework)**.
4. **Active Windows Fortress Countermeasures** while the vault is open (temporary Internet cut-off, anti-keylogger keyboard masking + scrambled virtual keypad, automatic termination of screen recording/streaming apps, and `WDA_EXCLUDEFROMCAPTURE` window protection).
5. **Automatic OS Language Detection (`i18n`)** — automatically detects the computer's native operating system language (`Português`, `English`, `Español`, `Français`, `Deutsch`, `Italiano`) via `kernel32.dll` and adapts the entire interface.

---

## Core Security Architecture

### 1. Polyalphabetic Vigenère Cipher (Passwords & Files) — [`vigenere.py`](criptex/crypto/vigenere.py)
- **Passwords**: Every password, title, username, and note stored in the vault is encrypted using the Vigenère Cipher (`Mod 256` byte-level stream + printable ASCII `Mod 95` representation), with keys expanded into a 1021-byte prime ring via `PBKDF2-HMAC-SHA256` and authenticated with `HMAC-SHA256`.
- **Files (`.crpx`)**: Every file imported into the vault is transformed byte-by-byte inside `.criptex_vault/files/` using the Vigenère Cipher formula:
  $$C_i = (P_i + K_{i \bmod L} + S_{i \bmod 32} + (i \bmod 251)) \bmod 256$$
- **Interactive Vigenère Inspector**: Includes a dedicated mathematical inspector tab that displays step-by-step byte shifts ($P_i$, $K_i$, formula, and resulting $C_i$) and side-by-side binary hex comparisons.

### 2. Physical USB Hardware Key — [`usb_key.py`](criptex/security/usb_key.py)
- The Vigenère master key is never stored on the PC's hard drive. Instead, it is stored exclusively on a **physical USB flash drive** (`.criptex_usb_key.crpxkey`) and cryptographically bound to the drive's **Hardware Volume Serial Number** (`Win32 GetVolumeInformationW`).
- **Stolen Biometric Device Protection**:
  - **Biometrics + Physical USB Drive Inserted**: The vault opens and decrypts all passwords and files in real time.
  - **Biometrics WITHOUT Physical USB Drive**: Even if someone unlocks the biometric step without the physical USB drive plugged into the PC, Criptex opens in **Restricted Encrypted Mode** — **all passwords and files remain strictly encrypted** and cannot be revealed or exported.

### 3. Biometric Unlock: Smartphone QR Code OR PC Fingerprint
Users can select their preferred biometric authentication method directly on the Lock Screen:
- **Option A — Smartphone Biometrics via QR Code ([`webauthn_server.py`](criptex/biometrics/webauthn_server.py))**:
  - Starts a local server and HTTPS WebAuthn tunnel, displaying a session-unique QR Code to scan with a smartphone (TouchID / FaceID / Android Fingerprint via `navigator.credentials.create` with `authenticatorAttachment: "platform"`).
  - **First-Use Device Binding**: The first smartphone to complete biometric verification is permanently paired with the vault. Subsequent attempts from any other phone are rejected.
- **Option B — PC Fingerprint Sensor ([`pc_biometrics.py`](criptex/biometrics/pc_biometrics.py))**:
  - Allows unlocking the vault directly using the computer's built-in fingerprint reader via native Windows APIs (`winbio.dll` Windows Biometric Framework and `webauthn.dll` Windows Hello Platform Authenticator) bound to the PC's hardware signature.
- **Protected Device Reset**: Changing or unlinking the registered biometric device in the **Settings & Devices** tab requires **both** the original biometric unlock and the physical USB key inserted simultaneously.

### 4. Active Windows Fortress Countermeasures — [`fortress.py`](criptex/security/fortress.py)
While the vault is unlocked, Criptex actively engages four system-level defenses:
- **Temporary Internet Cut-Off**: Temporarily disables network interfaces (`netsh interface set interface` / `ipconfig /release`) while inside the vault and automatically restores connectivity as soon as the vault is locked or closed.
- **Anti-Keylogger Keyboard Masking & Chaff Injection**: Installs a low-level Windows keyboard hook (`WH_KEYBOARD_LL`) that injects synthetic random noise keystrokes (`SendInput` chaff) to confuse external keyloggers, paired with a **Scrambled Virtual Keypad**.
- **Anti-Screen Recording & Anti-Streaming Shield**: Continuously scans for and terminates recording/streaming processes (`OBS Studio`, `Discord`, `ShareX`, `Bandicam`, `Xbox Game Bar`, `Zoom`, `Teams`, `Snipping Tool`, etc.) and applies `SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE)` so screen-capture APIs only see a black window.

### 5. Automatic Computer Language Detection — [`i18n.py`](criptex/i18n.py)
- Queries `GetUserDefaultLocaleName` and `GetUserDefaultUILanguage` (`kernel32.dll`) on startup to detect the operating system's language and automatically translates the UI (`Portuguese`, `English`, `Spanish`, `French`, `German`, and `Italian`).

---

## Getting Started

### Option 1: Standalone Executable (`Criptex.exe` — Recommended)
Simply double-click **`Criptex.exe`** (or run [`Iniciar_Criptex.bat`](Iniciar_Criptex.bat)).
- **No Python installation required**: `Criptex.exe` bundles the Python runtime, `PyQt6`, `cryptography`, `qrcode`, `psutil`, and the Windows UAC Administrator manifest into a single portable executable.

### Option 2: Running from Source ([`Iniciar_Criptex.bat`](Iniciar_Criptex.bat))
```bat
Iniciar_Criptex.bat
```
- If `Criptex.exe` is present in the root folder, it launches immediately.
- If running from source on a PC without Python installed, `Iniciar_Criptex.bat` automatically installs **Python 3.12** via Windows `winget` (`winget install -e --id Python.Python.3.12`), creates `.venv`, and installs all dependencies from [`requirements.txt`](requirements.txt).

### Building `Criptex.exe` from Source
To recompile the standalone `Criptex.exe` executable using PyInstaller:
```bat
Gerar_Executavel_Criptex.bat
```

---

## Running Automated Tests

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

---

## Author & Credits

Designed and developed by **Tiago Custodio**.
