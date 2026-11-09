# Criptex — Deteção Automática do Idioma do Computador e Internacionalização (i18n)
# Deteta automaticamente a língua nativa do sistema operativo Windows (GetUserDefaultLocaleName /
# GetUserDefaultUILanguage) e traduz dinamicamente a interface do Criptex.

from __future__ import annotations

import ctypes
import locale
import os
from typing import Dict

# Mapa de LCIDs primários do Windows caso GetUserDefaultLocaleName não esteja disponível
_LCID_PRIMARY_MAP: Dict[int, str] = {
    0x16: "pt",  # Português (pt-PT, pt-BR)
    0x09: "en",  # English (en-US, en-GB, etc.)
    0x0A: "es",  # Español
    0x0C: "fr",  # Français
    0x07: "de",  # Deutsch
    0x10: "it",  # Italiano
}

LANGUAGE_DISPLAY_NAMES: Dict[str, str] = {
    "pt": "Português",
    "en": "English",
    "es": "Español",
    "fr": "Français",
    "de": "Deutsch",
    "it": "Italiano",
}


def detect_computer_locale() -> tuple[str, str]:
    """
    Deteta o idioma configurado no computador (Windows Kernel32 / Locale do Sistema).
    Devolve `(lang_code, full_locale)` — ex: `('pt', 'pt-PT')` ou `('en', 'en-US')`.
    """
    full_tag = ""
    if os.name == "nt":
        try:
            k32 = ctypes.windll.kernel32
            buf = ctypes.create_unicode_buffer(85)
            if k32.GetUserDefaultLocaleName(buf, 85) > 0 and buf.value:
                full_tag = buf.value.strip()
            if not full_tag:
                lcid = int(k32.GetUserDefaultUILanguage()) & 0xFFFF
                primary = lcid & 0x3FF
                lang = _LCID_PRIMARY_MAP.get(primary, "pt")
                return lang, f"{lang}-{lang.upper()}"
        except Exception:
            pass

    if not full_tag:
        try:
            loc, _ = locale.getlocale()
            if loc:
                full_tag = loc.replace("_", "-")
        except Exception:
            pass

    if not full_tag:
        full_tag = os.environ.get("LANG", "pt-PT").split(".")[0].replace("_", "-")

    short = full_tag.split("-")[0].lower() if full_tag else "pt"
    if short not in LANGUAGE_DISPLAY_NAMES:
        short = "en"
    return short, (full_tag or short)


CURRENT_LANG, CURRENT_LOCALE_TAG = detect_computer_locale()


def set_language_override(lang_code: str) -> None:
    """Permite atualizar o idioma ativo em tempo de execução se desejado."""
    global CURRENT_LANG
    code = lang_code.split("-")[0].lower()
    if code in LANGUAGE_DISPLAY_NAMES:
        CURRENT_LANG = code


def get_detected_language_Summary() -> str:
    name = LANGUAGE_DISPLAY_NAMES.get(CURRENT_LANG, CURRENT_LANG.upper())
    return f"{name} ({CURRENT_LOCALE_TAG})"


# Dicionário de traduções indexado pelo texto base em Português -> {idioma: tradução}
_TRANSLATIONS: Dict[str, Dict[str, str]] = {
    "Criptex Security Suite  •  Liquid Glass Edition": {
        "en": "Criptex Security Suite  •  Liquid Glass Edition",
        "es": "Criptex Security Suite  •  Edición Liquid Glass",
        "fr": "Criptex Security Suite  •  Édition Liquid Glass",
        "de": "Criptex Security Suite  •  Liquid Glass Edition",
        "it": "Criptex Security Suite  •  Edizione Liquid Glass",
    },
    "Estado: Aguardando Autenticação  •  Motor: Vigenère Mod-256 + HMAC-SHA256": {
        "en": "Status: Awaiting Authentication  •  Engine: Vigenère Mod-256 + HMAC-SHA256",
        "es": "Estado: Esperando Autenticación  •  Motor: Vigenère Mod-256 + HMAC-SHA256",
        "fr": "État : En attente d'authentification  •  Moteur : Vigenère Mod-256 + HMAC-SHA256",
        "de": "Status: Warte auf Authentifizierung  •  Engine: Vigenère Mod-256 + HMAC-SHA256",
        "it": "Stato: In attesa di autenticazione  •  Motore: Vigenère Mod-256 + HMAC-SHA256",
    },
    "1. Verificação Biométrica (Smartphone ou Computador)": {
        "en": "1. Biometric Verification (Smartphone or Computer)",
        "es": "1. Verificación Biométrica (Smartphone u Ordenador)",
        "fr": "1. Vérification Biométrique (Smartphone ou Ordinateur)",
        "de": "1. Biometrische Verifizierung (Smartphone oder Computer)",
        "it": "1. Verifica Biometrica (Smartphone o Computer)",
    },
    "Escolha o método biométrico para desbloquear o cofre: leitura do código QR no telemóvel ou sensor de Impressão Digital do próprio computador (Windows Hello).": {
        "en": "Choose the biometric method to unlock the vault: scan the QR code on your phone or use this computer's Fingerprint sensor (Windows Hello).",
        "es": "Elija el método biométrico para desbloquear la bóveda: código QR en el móvil o lector de Huella Digital del ordenador (Windows Hello).",
        "fr": "Choisissez la méthode biométrique pour déverrouiller le coffre : QR code sur mobile ou lecteur d'empreintes digitales de l'ordinateur (Windows Hello).",
        "de": "Wählen Sie die biometrische Methode zum Entsperren: QR-Code auf dem Smartphone oder Fingerabdrucksensor des Computers (Windows Hello).",
        "it": "Scegli il metodo biometrico per sbloccare la cassaforte: codice QR sullo smartphone o lettore di impronte digitali del PC (Windows Hello).",
    },
    "Smartphone (Código QR)": {
        "en": "Smartphone (QR Code)",
        "es": "Smartphone (Código QR)",
        "fr": "Smartphone (Code QR)",
        "de": "Smartphone (QR-Code)",
        "it": "Smartphone (Codice QR)",
    },
    "Impressão Digital do PC": {
        "en": "PC Fingerprint (Windows Hello)",
        "es": "Huella Digital del PC",
        "fr": "Empreinte Digitale PC",
        "de": "PC-Fingerabdruck",
        "it": "Impronta Digitale PC",
    },
    "Gerar Novo QR Code": {
        "en": "Generate New QR Code",
        "es": "Generar Nuevo Código QR",
        "fr": "Générer un nouveau QR Code",
        "de": "Neuen QR-Code generieren",
        "it": "Genera Nuovo Codice QR",
    },
    "Copiar Endereço HTTPS": {
        "en": "Copy HTTPS Address",
        "es": "Copiar Dirección HTTPS",
        "fr": "Copier l'adresse HTTPS",
        "de": "HTTPS-Adresse kopieren",
        "it": "Copia Indirizzo HTTPS",
    },
    "Sensor Biométrico Nativo do Computador (Windows Hello / WinBio)": {
        "en": "Computer Native Biometric Sensor (Windows Hello / WinBio)",
        "es": "Sensor Biométrico Nativo del Ordenador (Windows Hello / WinBio)",
        "fr": "Capteur Biométrique Natif de l'Ordinateur (Windows Hello / WinBio)",
        "de": "Nativer Biometriesensor des Computers (Windows Hello / WinBio)",
        "it": "Sensore Biometrico Nativo del Computer (Windows Hello / WinBio)",
    },
    "Utilize o leitor de Impressão Digital ou reconhecimento biométrico Windows Hello integrado no seu computador para autenticar sem precisar do telemóvel.": {
        "en": "Use the Fingerprint reader or Windows Hello biometric sensor built into your computer to authenticate without needing your phone.",
        "es": "Utilice el lector de Huella Digital o biometría Windows Hello integrada en su ordenador para autenticar sin necesitar el móvil.",
        "fr": "Utilisez le lecteur d'empreintes digitales ou Windows Hello intégré à votre ordinateur pour vous authentifier sans téléphone.",
        "de": "Verwenden Sie den integrierten Fingerabdruckleser oder Windows Hello Ihres Computers zur Authentifizierung ohne Smartphone.",
        "it": "Usa il lettore di impronte digitali o Windows Hello integrato nel tuo computer per autenticarti senza smartphone.",
    },
    "Autenticar com Impressão Digital do Computador": {
        "en": "Authenticate with Computer Fingerprint",
        "es": "Autenticar con Huella Digital del Ordenador",
        "fr": "Authentifier avec l'Empreinte de l'Ordinateur",
        "de": "Mit Computer-Fingerabdruck authentifizieren",
        "it": "Autentica con Impronta Digitale del PC",
    },
    "Aguardando leitura biométrica (Smartphone QR ou Impressão Digital do PC)...": {
        "en": "Awaiting biometric verification (Smartphone QR or PC Fingerprint)...",
        "es": "Esperando lectura biométrica (QR del Smartphone o Huella del PC)...",
        "fr": "En attente de lecture biométrique (QR Smartphone ou Empreinte PC)...",
        "de": "Warte auf biometrische Prüfung (Smartphone-QR oder PC-Fingerabdruck)...",
        "it": "In attesa di verifica biometrica (QR Smartphone o Impronta PC)...",
    },
    "A aguardar que coloque o dedo no sensor de Impressão Digital do computador (Windows Hello)...": {
        "en": "Waiting for you to place your finger on the computer's Fingerprint sensor (Windows Hello)...",
        "es": "Esperando que coloque el dedo en el lector de Huella Digital del ordenador (Windows Hello)...",
        "fr": "Veuillez placer votre doigt sur le capteur d'empreintes digitales de l'ordinateur (Windows Hello)...",
        "de": "Bitte legen Sie Ihren Finger auf den Fingerabdrucksensor des Computers (Windows Hello)...",
        "it": "Posiziona il dito sul sensore di impronte digitali del computer (Windows Hello)...",
    },
    "2. Chave da Cifra de Vigenère (Pen USB Física)": {
        "en": "2. Vigenère Cipher Key (Physical USB Drive)",
        "es": "2. Clave del Cifrado de Vigenère (Memoria USB Física)",
        "fr": "2. Clé du Chiffre de Vigenère (Clé USB Physique)",
        "de": "2. Vigenère-Chiffrierschlüssel (Physischer USB-Stick)",
        "it": "2. Chiave Cifrario di Vigenère (Chiavetta USB Fisica)",
    },
    "A palavra-chave da Cifra de Vigenère é armazenada exclusivamente numa Pen USB física.\n• Com Biometria + Pen USB Física: O cofre abre e desencripta as passwords e ficheiros.\n• Sem Pen USB Física (ex: smartphone roubado): O Criptex abre, mas todos os dados permanecem encriptados.": {
        "en": "The Vigenère Cipher master key is stored exclusively on a physical USB drive.\n• With Biometrics + Physical USB Drive: Vault opens and decrypts passwords and files.\n• Without Physical USB Drive: Criptex opens, but all data remains strictly encrypted.",
        "es": "La clave del Cifrado de Vigenère se guarda exclusivamente en una memoria USB física.\n• Con Biometría + USB Físico: La bóveda se abre y desencripta contraseñas y archivos.\n• Sin USB Físico: Criptex se abre, pero todos los datos permanecen encriptados.",
        "fr": "La clé du chiffre de Vigenère est stockée exclusivement sur une clé USB physique.\n• Avec Biométrie + Clé USB : Le coffre s'ouvre et déchiffre les mots de passe et fichiers.\n• Sans Clé USB : Criptex s'ouvre, mais toutes les données restent chiffrées.",
        "de": "Der Vigenère-Schlüssel wird ausschließlich auf einem physischen USB-Stick gespeichert.\n• Mit Biometrie + USB-Stick: Tresor öffnet und entschlüsselt Passwörter und Dateien.\n• Ohne USB-Stick: Criptex öffnet sich, aber alle Daten bleiben verschlüsselt.",
        "it": "La chiave del Cifrario di Vigenère è salvata esclusivamente su una chiavetta USB fisica.\n• Con Biometria + USB Fisica: La cassaforte si apre e decrittografa password e file.\n• Senza USB Fisica: Criptex si apre, ma tutti i dati restano crittografati.",
    },
    "Atualizar Lista USB": {
        "en": "Refresh USB List",
        "es": "Actualizar Lista USB",
        "fr": "Actualiser la liste USB",
        "de": "USB-Liste aktualisieren",
        "it": "Aggiorna Lista USB",
    },
    "Configurar ou Gravar Chave Vigenère na Pen USB:": {
        "en": "Configure or Write Vigenère Key to USB Drive:",
        "es": "Configurar o Grabar Clave Vigenère en Memoria USB:",
        "fr": "Configurer ou écrire la clé Vigenère sur la clé USB :",
        "de": "Vigenère-Schlüssel auf USB-Stick konfigurieren oder schreiben:",
        "it": "Configura o Scrivi Chiave Vigenère sulla Chiavetta USB:",
    },
    "Teclado Virtual": {
        "en": "Virtual Keypad",
        "es": "Teclado Virtual",
        "fr": "Clavier Virtuel",
        "de": "Virtuelle Tastatur",
        "it": "Tastiera Virtuale",
    },
    "Gravar Chave na Pen USB Selecionada": {
        "en": "Write Key to Selected USB Drive",
        "es": "Grabar Clave en la Memoria USB Seleccionada",
        "fr": "Écrire la clé sur la clé USB sélectionnée",
        "de": "Schlüssel auf gewählten USB-Stick schreiben",
        "it": "Scrivi Chiave sulla Chiavetta USB Selezionata",
    },
    "Aguardando Confirmação Biométrica...": {
        "en": "Awaiting Biometric Confirmation...",
        "es": "Esperando Confirmación Biométrica...",
        "fr": "En attente de confirmation biométrique...",
        "de": "Warte auf biometrische Bestätigung...",
        "it": "In attesa di conferma biometrica...",
    },
    "Registo de Eventos e Auditoria:": {
        "en": "Security Audit & Event Log:",
        "es": "Registro de Eventos y Auditoría:",
        "fr": "Journal des événements et d'audit :",
        "de": "Sicherheits- und Ereignisprotokoll:",
        "it": "Registro Eventi e Audit:",
    },
    "Proteção Ativa": {
        "en": "Active Protection",
        "es": "Protección Activa",
        "fr": "Protection Active",
        "de": "Aktiver Schutz",
        "it": "Protezione Attiva",
    },
    "Internet: Cortada": {
        "en": "Internet: Cut Off",
        "es": "Internet: Cortada",
        "fr": "Internet : Coupé",
        "de": "Internet: Getrennt",
        "it": "Internet: Disconnessa",
    },
    "Teclado: Mascarado": {
        "en": "Keyboard: Masked",
        "es": "Teclado: Enmascarado",
        "fr": "Clavier : Masqué",
        "de": "Tastatur: Maskiert",
        "it": "Tastiera: Mascherata",
    },
    "Anti-Gravação: Ativo": {
        "en": "Anti-Recording: Active",
        "es": "Anti-Grabación: Activo",
        "fr": "Anti-Capture : Actif",
        "de": "Aufnahmeschutz: Aktiv",
        "it": "Anti-Registrazione: Attivo",
    },
    "Trancar Cofre e Restaurar Internet": {
        "en": "Lock Vault & Restore Internet",
        "es": "Bloquear Bóveda y Restaurar Internet",
        "fr": "Verrouiller le coffre et rétablir Internet",
        "de": "Tresor sperren & Internet wiederherstellen",
        "it": "Blocca Cassaforte e Ripristina Internet",
    },
    "Passwords": {
        "en": "Passwords",
        "es": "Contraseñas",
        "fr": "Mots de passe",
        "de": "Passwörter",
        "it": "Password",
    },
    "Ficheiros (.crpx)": {
        "en": "Files (.crpx)",
        "es": "Archivos (.crpx)",
        "fr": "Fichiers (.crpx)",
        "de": "Dateien (.crpx)",
        "it": "File (.crpx)",
    },
    "Matriz Vigenère": {
        "en": "Vigenère Matrix",
        "es": "Matriz Vigenère",
        "fr": "Matrice Vigenère",
        "de": "Vigenère-Matrix",
        "it": "Matrice Vigenère",
    },
    "Escudo & Sistema": {
        "en": "Shield & System",
        "es": "Escudo y Sistema",
        "fr": "Bouclier & Système",
        "de": "Schutzschild & System",
        "it": "Scudo e Sistema",
    },
    "Dispositivos": {
        "en": "Devices",
        "es": "Dispositivos",
        "fr": "Appareils",
        "de": "Geräte",
        "it": "Dispositivi",
    },
    "Desencriptar e Mostrar Password": {
        "en": "Decrypt & Reveal Password",
        "es": "Desencriptar y Mostrar Contraseña",
        "fr": "Déchiffrer et afficher le mot de passe",
        "de": "Passwort entschlüsseln & anzeigen",
        "it": "Decrittografa e Mostra Password",
    },
    "Inspecionar na Matriz Vigenère": {
        "en": "Inspect in Vigenère Matrix",
        "es": "Inspeccionar en Matriz Vigenère",
        "fr": "Inspecter dans la matrice Vigenère",
        "de": "In Vigenère-Matrix prüfen",
        "it": "Ispeziona nella Matrice Vigenère",
    },
    "Eliminar Registo": {
        "en": "Delete Entry",
        "es": "Eliminar Registro",
        "fr": "Supprimer l'entrée",
        "de": "Eintrag löschen",
        "it": "Elimina Voce",
    },
    "Adicionar Nova Password": {
        "en": "Add New Password",
        "es": "Añadir Nueva Contraseña",
        "fr": "Ajouter un nouveau mot de passe",
        "de": "Neues Passwort hinzufügen",
        "it": "Aggiungi Nuova Password",
    },
    "Gerar Password Segura": {
        "en": "Generate Secure Password",
        "es": "Generar Contraseña Segura",
        "fr": "Générer un mot de passe sécurisé",
        "de": "Sicheres Passwort generieren",
        "it": "Genera Password Sicura",
    },
    "Gerar uma password criptograficamente segura (20 caracteres) e preencher automaticamente": {
        "en": "Generate a cryptographically secure password (20 chars) and auto-fill",
        "es": "Generar una contraseña criptográficamente segura (20 caracteres) y rellenar automáticamente",
        "fr": "Générer un mot de passe cryptographiquement sûr (20 caractères) et remplir automatiquement",
        "de": "Kryptografisch sicheres Passwort (20 Zeichen) generieren und automatisch ausfüllen",
        "it": "Genera una password crittograficamente sicura (20 caratteri) e compila automaticamente",
    },
    "Password Segura Gerada (20 caracteres • Copiada para a Área de Transferência):": {
        "en": "Secure Password Generated (20 chars • Copied to Clipboard):",
        "es": "Contraseña Segura Generada (20 caracteres • Copiada al Portapapeles):",
        "fr": "Mot de passe sécurisé généré (20 caractères • Copié dans le presse-papiers) :",
        "de": "Sicheres Passwort generiert (20 Zeichen • In Zwischenablage kopiert):",
        "it": "Password Sicura Generata (20 caratteri • Copiata negli Appunti):",
    },
    "Password segura de 20 caracteres (CSPRNG) gerada e preenchida no formulário.": {
        "en": "20-character secure password (CSPRNG) generated and filled in the form.",
        "es": "Contraseña segura de 20 caracteres (CSPRNG) generada y rellenada en el formulario.",
        "fr": "Mot de passe sécurisé de 20 caractères (CSPRNG) généré et rempli dans le formulaire.",
        "de": "Sicheres 20-Zeichen-Passwort (CSPRNG) generiert und im Formular ausgefüllt.",
        "it": "Password sicura di 20 caratteri (CSPRNG) generata e inserita nel modulo.",
    },
    "Passwords Guardadas (Encriptadas com Cifra de Vigenère)": {
        "en": "Saved Passwords (Encrypted with Vigenère Cipher)",
        "es": "Contraseñas Guardadas (Cifradas con Cifrado Vigenère)",
        "fr": "Mots de passe enregistrés (Chiffrés avec le chiffre de Vigenère)",
        "de": "Gespeicherte Passwörter (Verschlüsselt mit Vigenère-Chiffre)",
        "it": "Password Salvate (Cifrate con Cifrario di Vigenère)",
    },
    "Serviço / Título": {
        "en": "Service / Title",
        "es": "Servicio / Título",
        "fr": "Service / Titre",
        "de": "Dienst / Titel",
        "it": "Servizio / Titolo",
    },
    "Utilizador": {
        "en": "Username",
        "es": "Usuario",
        "fr": "Utilisateur",
        "de": "Benutzername",
        "it": "Utente",
    },
    "Password Cifrada (Vigenère)": {
        "en": "Encrypted Password (Vigenère)",
        "es": "Contraseña Cifrada (Vigenère)",
        "fr": "Mot de passe chiffré (Vigenère)",
        "de": "Verschlüsseltes Passwort (Vigenère)",
        "it": "Password Cifrata (Vigenère)",
    },
    "Token Criptográfico": {
        "en": "Cryptographic Token",
        "es": "Token Criptográfico",
        "fr": "Jeton cryptographique",
        "de": "Kryptografisches Token",
        "it": "Token Crittografico",
    },
    "Ex: Banco, Email, Servidor": {
        "en": "E.g., Bank, Email, Server",
        "es": "Ej: Banco, Correo, Servidor",
        "fr": "Ex : Banque, Email, Serveur",
        "de": "Z. B. Bank, E-Mail, Server",
        "it": "Es: Banca, Email, Server",
    },
    "Utilizador ou Email": {
        "en": "Username or Email",
        "es": "Usuario o Correo",
        "fr": "Nom d'utilisateur ou Email",
        "de": "Benutzername oder E-Mail",
        "it": "Nome utente o Email",
    },
    "URL (ex: https://...)": {
        "en": "URL (e.g., https://...)",
        "es": "URL (ej: https://...)",
        "fr": "URL (ex : https://...)",
        "de": "URL (z. B. https://...)",
        "it": "URL (es: https://...)",
    },
    "Password secreta (cifrada com a chave da Pen USB)": {
        "en": "Secret password (encrypted with USB drive key)",
        "es": "Contraseña secreta (cifrada con la clave de la memoria USB)",
        "fr": "Mot de passe secret (chiffré avec la clé USB)",
        "de": "Geheimes Passwort (mit USB-Schlüssel verschlüsselt)",
        "it": "Password segreta (cifrata con la chiave USB)",
    },
    "Notas adicionais": {
        "en": "Additional notes",
        "es": "Notas adicionales",
        "fr": "Notes supplémentaires",
        "de": "Zusätzliche Notizen",
        "it": "Note aggiuntive",
    },
    "Título / Serviço:": {
        "en": "Title / Service:",
        "es": "Título / Servicio:",
        "fr": "Titre / Service :",
        "de": "Titel / Dienst:",
        "it": "Titolo / Servizio:",
    },
    "Utilizador:": {
        "en": "Username:",
        "es": "Usuario:",
        "fr": "Utilisateur :",
        "de": "Benutzername:",
        "it": "Utente:",
    },
    "URL / Endereço:": {
        "en": "URL / Address:",
        "es": "URL / Dirección:",
        "fr": "URL / Adresse :",
        "de": "URL / Adresse:",
        "it": "URL / Indirizzo:",
    },
    "Password (Input Protegido):": {
        "en": "Password (Protected Input):",
        "es": "Contraseña (Entrada Protegida):",
        "fr": "Mot de passe (Saisie protégée) :",
        "de": "Passwort (Geschützte Eingabe):",
        "it": "Password (Input Protetto):",
    },
    "Teclado": {
        "en": "Keypad",
        "es": "Teclado",
        "fr": "Clavier",
        "de": "Tastatur",
        "it": "Tastiera",
    },
    "Abrir Teclado Virtual Seguro": {
        "en": "Open Secure Virtual Keypad",
        "es": "Abrir Teclado Virtual Seguro",
        "fr": "Ouvrir le clavier virtuel sécurisé",
        "de": "Sichere virtuelle Tastatur öffnen",
        "it": "Apri Tastiera Virtuale Sicura",
    },
    "Pré-visualização da Cifra de Vigenère:": {
        "en": "Vigenère Cipher Live Preview:",
        "es": "Vista Previa del Cifrado Vigenère:",
        "fr": "Aperçu en direct du chiffre de Vigenère :",
        "de": "Vigenère-Chiffre Live-Vorschau:",
        "it": "Anteprima Cifrario di Vigenère:",
    },
    "A aguardar introdução...": {
        "en": "Waiting for input...",
        "es": "Esperando entrada...",
        "fr": "En attente de saisie...",
        "de": "Warte auf Eingabe...",
        "it": "In attesa di inserimento...",
    },
    "Insira a Pen USB física para cifrar com a sua chave Vigenère.": {
        "en": "Insert the physical USB drive to encrypt with your Vigenère key.",
        "es": "Inserte la memoria USB física para cifrar con su clave Vigenère.",
        "fr": "Insérez la clé USB physique pour chiffrer avec votre clé Vigenère.",
        "de": "Stecken Sie den physischen USB-Stick ein, um mit Ihrem Vigenère-Schlüssel zu verschlüsseln.",
        "it": "Inserisci la chiavetta USB fisica per cifrare con la tua chiave Vigenère.",
    },
    "Notas:": {
        "en": "Notes:",
        "es": "Notas:",
        "fr": "Notes :",
        "de": "Notizen:",
        "it": "Note:",
    },
    "Selecione um registo na tabela e clique em 'Desencriptar e Mostrar Password'.": {
        "en": "Select an entry in the table and click 'Decrypt & Reveal Password'.",
        "es": "Seleccione un registro en la tabla y haga clic en 'Desencriptar y Mostrar Contraseña'.",
        "fr": "Sélectionnez une entrée dans le tableau et cliquez sur 'Déchiffrer et afficher le mot de passe'.",
        "de": "Wählen Sie einen Eintrag in der Tabelle und klicken Sie auf 'Passwort entschlüsseln & anzeigen'.",
        "it": "Seleziona una voce nella tabella e clicca su 'Decrittografa e Mostra Password'.",
    },
    "Pen USB Necessária": {
        "en": "USB Drive Required",
        "es": "Memoria USB Necesaria",
        "fr": "Clé USB requise",
        "de": "USB-Stick erforderlich",
        "it": "Chiavetta USB Necessaria",
    },
    "Não é possível cifrar novas passwords sem a Pen USB física ligada ao computador.": {
        "en": "Cannot encrypt new passwords without the physical USB drive plugged into the computer.",
        "es": "No es posible cifrar nuevas contraseñas sin la memoria USB física conectada al ordenador.",
        "fr": "Impossible de chiffrer de nouveaux mots de passe sans la clé USB physique branchée à l'ordinateur.",
        "de": "Neue Passwörter können nicht ohne angeschlossenen physischen USB-Stick verschlüsselt werden.",
        "it": "Impossibile cifrare nuove password senza la chiavetta USB fisica collegata al computer.",
    },
    "Campos Obrigatórios": {
        "en": "Required Fields",
        "es": "Campos Obligatorios",
        "fr": "Champs obligatoires",
        "de": "Pflichtfelder",
        "it": "Campi Obbligatori",
    },
    "Preencha pelo menos o Título e a Password.": {
        "en": "Please fill in at least the Title and Password.",
        "es": "Rellene al menos el Título y la Contraseña.",
        "fr": "Veuillez remplir au moins le Titre et le Mot de passe.",
        "de": "Bitte füllen Sie mindestens Titel und Passwort aus.",
        "it": "Compila almeno il Titolo e la Password.",
    },
    "Cifrar com Chave USB e Guardar": {
        "en": "Encrypt with USB Key & Save",
        "es": "Cifrar con Clave USB y Guardar",
        "fr": "Chiffrer avec la clé USB et enregistrer",
        "de": "Mit USB-Schlüssel verschlüsseln & speichern",
        "it": "Cifra con Chiave USB e Salva",
    },
    "Importar e Cifrar Ficheiro": {
        "en": "Import & Encrypt File",
        "es": "Importar y Cifrar Archivo",
        "fr": "Importer et chiffrer un fichier",
        "de": "Datei importieren & verschlüsseln",
        "it": "Importa e Cifra File",
    },
    "Desencriptar e Exportar Ficheiro": {
        "en": "Decrypt & Export File",
        "es": "Desencriptar y Exportar Archivo",
        "fr": "Déchiffrer et exporter le fichier",
        "de": "Datei entschlüsseln & exportieren",
        "it": "Decrittografa ed Esporta File",
    },
    "Eliminar do Cofre": {
        "en": "Delete from Vault",
        "es": "Eliminar de la Bóveda",
        "fr": "Supprimer du coffre",
        "de": "Aus Tresor löschen",
        "it": "Elimina dalla Cassaforte",
    },
}


def tr(text: str) -> str:
    """Traduz `text` para o idioma detetado no computador (ou devolve o original em Português se `pt`)."""
    if CURRENT_LANG == "pt":
        return text
    entry = _TRANSLATIONS.get(text)
    if entry and CURRENT_LANG in entry:
        return entry[CURRENT_LANG]
    return text
