# CRIPTEX — Cofre Digital Windows

Aplicação nativa para Windows (**Python + PyQt6 + Win32 APIs**) concebida como um cofre digital de alta segurança com **Cifra de Vigenère** (para **Passwords** e **Ficheiros**), **Chave Física em Pen USB**, **Desbloqueio Biométrico via Smartphone (WebAuthn / QR Code)** com vinculação ao primeiro telemóvel utilizado, e **Isolamento Ativo de Sistema**.

---

## Arquitetura de Segurança

1. **Cifra de Vigenère Polialfabética (Passwords e Ficheiros)**
   - **Passwords**: Cada password, título, utilizador e nota é transformado através da Cifra de Vigenère (`Mod 256` ao nível de bytes + representação Vigenère ASCII imprimível `Mod 95`), com chave expandida num anel primo de 1021 bytes via `PBKDF2-HMAC-SHA256` e assinatura `HMAC-SHA256` ([`vigenere.py`](criptex/crypto/vigenere.py)).
   - **Ficheiros (`.crpx`)**: Todos os ficheiros importados para o cofre são modificados byte-a-byte no interior de `.criptex_vault/files/` utilizando a Cifra de Vigenère:
     $$C_i = (P_i + K_{i \bmod L} + S_{i \bmod 32} + (i \bmod 251)) \bmod 256$$

2. **Chave da Cifra Guardada numa Pen USB Física ([`usb_key.py`](criptex/security/usb_key.py))**
   - A palavra-chave da Cifra de Vigenère é armazenada exclusivamente numa **Pen USB física** (`.criptex_usb_key.crpxkey`) e vinculada ao **Número de Série de Hardware do Volume USB** (`Win32 GetVolumeInformationW`).
   - **Proteção contra Roubo de Smartphone**: Caso alguém utilize o telemóvel sem a Pen USB física ligada ao computador, o Criptex abre mas **todos os dados (passwords e ficheiros) permanecem encriptados**.

3. **Desbloqueio Biométrico via Smartphone com Vinculação no 1.º Uso ([`webauthn_server.py`](criptex/biometrics/webauthn_server.py))**
   - Servidor HTTPS local que apresenta um código QR exclusivo por sessão para leitura com o telemóvel na rede local (TouchID / FaceID / Impressão Digital Android via WebAuthn).
   - **Vinculação Permanente após o 1.º Uso**: O primeiro telemóvel a ler o código QR e validar a biometria fica registado no cofre. Qualquer outro telemóvel é rejeitado.
   - **Alteração Protegida nas Definições**: O telemóvel registado só pode ser alterado na aba **Definições & Dispositivos** no interior do cofre quando **ambos** os fatores estão presentes (desbloqueio biométrico original + Pen USB física inserida).

4. **Proteções Ativas no Interior do Cofre ([`fortress.py`](criptex/security/fortress.py))**
   - **Corte Momentâneo da Internet**: Desativa temporariamente os adaptadores de rede (`netsh interface set interface ... admin=DISABLED` / `ipconfig /release`) ao entrar no cofre e restaura a ligação ao trancar ou sair.
   - **Mascaramento de Teclado Anti-Keylogger**: Hook `WH_KEYBOARD_LL` ao nível do sistema operativo que injeta eventos de ruído sintético (`SendInput`) para mascarar a digitação para o exterior do cofre, complementado por um **Teclado Virtual Baralhado**.
   - **Bloqueio de Aplicações de Stream e Gravação**: Termina automaticamente processos de gravação/captura (`OBS Studio`, `Discord`, `ShareX`, `Bandicam`, `Xbox Game Bar`, `Zoom`, `Teams`, etc.) e aplica `SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE)` na janela do cofre.

---

## Como Executar (Após Download / Clone do GitHub)

1. Certifique-se de que tem o **Python 3.10+** instalado no Windows.
2. Execute o lançador principal [Iniciar_Criptex.bat](Iniciar_Criptex.bat):

```bat
Iniciar_Criptex.bat
```

> No **primeiro arranque** após extrair do GitHub, o `Iniciar_Criptex.bat` cria automaticamente o ambiente virtual `.venv`, instala todas as dependências de `requirements.txt` e inicia o Criptex solicitando elevação UAC de Administrador.

Ou diretamente via terminal:

```powershell
python main.py --elevate
```
