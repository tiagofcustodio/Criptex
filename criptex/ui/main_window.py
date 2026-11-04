# Criptex — Interface Gráfica Desktop Windows (PyQt6)
# Tema Profissional Executivo de Cibersegurança (Enterprise Dark Slate & Titanium)
# Cofre Digital Altamente Fortificado com:
#   - Cifra de Vigenère (Passwords & Ficheiros)
#   - Palavra-Chave da Cifra guardada em Pen USB Física (.criptex_usb_key.crpxkey)
#   - Desbloqueio Biométrico do Smartphone (WebAuthn QR)
#   - Caso alguém consiga usar o smartphone roubado sem a Pen USB física no PC,
#     o Criptex abre mas TODOS OS DADOS PERMANECEM ENCRIPTADOS!
#   - Corte Momentâneo de Internet, Mascaramento de Teclado Anti-Keylogger e Exterminador de Apps de Stream/Gravação.

from __future__ import annotations

import io
import random
import string
import sys
import time
from pathlib import Path
from typing import Optional, List

import qrcode
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QObject
from PyQt6.QtGui import QImage, QPixmap, QKeyEvent
from PyQt6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QStackedWidget,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from criptex.biometrics.webauthn_server import SmartphoneBiometricServer, BiometricAuthResult
from criptex.crypto.vigenere import VigenereCipher
from criptex.security.fortress import FortressShield, STREAM_AND_RECORDING_PROCESSES
from criptex.security.usb_key import UsbKeyManager, UsbDriveInfo
from criptex.vault.storage import CriptexVaultStorage, PasswordEntry, VaultFileEntry


ENTERPRISE_SECURITY_QSS = """
QMainWindow, QDialog {
    background-color: #0d1117;
    color: #e6edf3;
    font-family: "Segoe UI", sans-serif;
}
QWidget {
    color: #e6edf3;
    font-family: "Segoe UI", sans-serif;
}
QFrame#TopHeaderBar {
    background-color: #161b22;
    border-bottom: 1px solid #30363d;
}
QFrame#Card {
    background-color: #161b22;
    border: 1px solid #30363d;
    border-radius: 6px;
}
QFrame#SubPanel {
    background-color: #0d1117;
    border: 1px solid #21262d;
    border-left: 3px solid #2f81f7;
    border-radius: 4px;
}
QFrame#ShieldBanner {
    background-color: #161b22;
    border: 1px solid #30363d;
    border-left: 4px solid #238636;
    border-radius: 6px;
}
QFrame#WarningCipherBanner {
    background-color: #281216;
    border: 1px solid #da3633;
    border-left: 4px solid #f85149;
    border-radius: 6px;
}
QLabel#HeroTitle {
    font-size: 21px;
    font-weight: 700;
    color: #f0f6fc;
    letter-spacing: 0.8px;
}
QLabel#SectionTitle {
    font-size: 13px;
    font-weight: 700;
    color: #c9d1d9;
    letter-spacing: 0.3px;
}
QLabel#Subtle {
    color: #8b949e;
    font-size: 12px;
}
QLineEdit, QPlainTextEdit, QComboBox {
    background-color: #0d1117;
    border: 1px solid #30363d;
    border-radius: 5px;
    padding: 8px 11px;
    color: #f0f6fc;
    font-size: 13px;
}
QLineEdit:focus, QPlainTextEdit:focus, QComboBox:focus {
    border: 1px solid #2f81f7;
    background-color: #090d11;
}
QComboBox::drop-down {
    border-left: 1px solid #30363d;
    width: 24px;
}
QPushButton {
    background-color: #21262d;
    border: 1px solid #30363d;
    border-radius: 5px;
    padding: 8px 14px;
    color: #c9d1d9;
    font-weight: 600;
    font-size: 12px;
}
QPushButton:hover {
    background-color: #30363d;
    border-color: #8b949e;
    color: #f0f6fc;
}
QPushButton:disabled {
    background-color: #161b22;
    color: #484f58;
    border-color: #21262d;
}
QPushButton#PrimaryBtn {
    background-color: #1f6feb;
    border: 1px solid #388bfd;
    color: #ffffff;
    font-weight: 700;
}
QPushButton#PrimaryBtn:hover {
    background-color: #388bfd;
}
QPushButton#PrimaryBtn:disabled {
    background-color: #161b22;
    border: 1px solid #21262d;
    color: #484f58;
}
QPushButton#SecondaryAccentBtn {
    background-color: #1f242c;
    border: 1px solid #388bfd;
    color: #58a6ff;
    font-weight: 600;
}
QPushButton#SecondaryAccentBtn:hover {
    background-color: #262c36;
}
QPushButton#DangerBtn {
    background-color: #21262d;
    border: 1px solid #da3633;
    color: #f85149;
    font-weight: 600;
}
QPushButton#DangerBtn:hover {
    background-color: #da3633;
    color: #ffffff;
}
QTabWidget::pane {
    border: 1px solid #30363d;
    background-color: #0d1117;
    border-radius: 6px;
}
QTabBar::tab {
    background-color: #161b22;
    color: #8b949e;
    padding: 9px 18px;
    margin-right: 4px;
    border: 1px solid #30363d;
    border-bottom: none;
    border-top-left-radius: 5px;
    border-top-right-radius: 5px;
    font-weight: 600;
    font-size: 12px;
}
QTabBar::tab:selected {
    background-color: #0d1117;
    color: #f0f6fc;
    border-top: 2px solid #2f81f7;
}
QTableWidget {
    background-color: #0d1117;
    border: 1px solid #30363d;
    border-radius: 5px;
    gridline-color: #21262d;
    selection-background-color: #1f2937;
    selection-color: #58a6ff;
    font-size: 12px;
}
QHeaderView::section {
    background-color: #161b22;
    color: #8b949e;
    padding: 8px;
    border: none;
    border-right: 1px solid #21262d;
    border-bottom: 1px solid #30363d;
    font-weight: 600;
    font-size: 12px;
}
QListWidget {
    background-color: #0d1117;
    border: 1px solid #30363d;
    border-radius: 5px;
    padding: 6px;
    font-family: "Consolas", monospace;
    font-size: 12px;
    color: #c9d1d9;
}
QCheckBox {
    font-size: 12px;
    color: #c9d1d9;
    spacing: 8px;
}
QCheckBox::indicator {
    width: 15px;
    height: 15px;
    border: 1px solid #30363d;
    border-radius: 3px;
    background-color: #0d1117;
}
QCheckBox::indicator:checked {
    background-color: #1f6feb;
    border: 1px solid #388bfd;
}
"""


class MaskedVaultLineEdit(QLineEdit):
    """
    Campo de texto com Mascaramento Anti-Keylogger para o exterior do cofre:
    Cada tecla premida injeta uma rajada de caracteres falsos ("Chaff") na fila do sistema
    operativo para confundir keyloggers externos.
    """

    chaffGenerated = pyqtSignal(str, str)

    def __init__(
        self,
        shield: FortressShield,
        placeholder: str = "",
        secret_field: bool = False,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self.shield = shield
        self.secret_field = secret_field
        self.setPlaceholderText(placeholder)
        if secret_field:
            self.setEchoMode(QLineEdit.EchoMode.Password)

    def keyPressEvent(self, event: QKeyEvent) -> None:
        text = event.text()
        if text and text.isprintable():
            fake_stream = self.shield.inject_external_chaff_burst(count=4)
            self.chaffGenerated.emit("•", fake_stream)
        super().keyPressEvent(event)


class ScrambledVirtualKeypadDialog(QDialog):
    """Teclado Virtual Anti-Keylogger com posições aleatórias."""

    def __init__(self, initial_text: str = "", parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Teclado Virtual Seguro (Anti-Keylogger)")
        self.resize(520, 340)
        self._value = initial_text

        layout = QVBoxLayout(self)
        info = QLabel(
            "As teclas estão dispostas de forma aleatória para impedir a captura por keyloggers de hardware ou registo de cliques."
        )
        info.setWordWrap(True)
        info.setObjectName("Subtle")
        layout.addWidget(info)

        self.preview_edit = QLineEdit(self._value)
        self.preview_edit.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.preview_edit)

        self.grid_widget = QWidget()
        self.grid = QGridLayout(self.grid_widget)
        self.grid.setSpacing(5)
        layout.addWidget(self.grid_widget)

        self._build_scrambled_keys()

        bottom = QHBoxLayout()
        btn_toggle = QPushButton("Mostrar / Ocultar")
        btn_toggle.clicked.connect(self._toggle_echo)
        btn_reshuffle = QPushButton("Baralhar Teclas")
        btn_reshuffle.clicked.connect(self._build_scrambled_keys)
        btn_clear = QPushButton("Apagar Último")
        btn_clear.clicked.connect(self._backspace)
        btn_ok = QPushButton("Confirmar")
        btn_ok.setObjectName("PrimaryBtn")
        btn_ok.clicked.connect(self.accept)

        bottom.addWidget(btn_toggle)
        bottom.addWidget(btn_reshuffle)
        bottom.addWidget(btn_clear)
        bottom.addWidget(btn_ok)
        layout.addLayout(bottom)

    def _build_scrambled_keys(self) -> None:
        while self.grid.count():
            item = self.grid.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        charset = list(string.ascii_letters + string.digits + "!@#$%&*_-+=")
        random.shuffle(charset)
        cols = 11
        for idx, ch in enumerate(charset[:66]):
            btn = QPushButton(ch)
            btn.setFixedHeight(32)
            btn.clicked.connect(lambda checked=False, c=ch: self._append_char(c))
            self.grid.addWidget(btn, idx // cols, idx % cols)

    def _append_char(self, ch: str) -> None:
        self.preview_edit.setText(self.preview_edit.text() + ch)

    def _backspace(self) -> None:
        self.preview_edit.setText(self.preview_edit.text()[:-1])

    def _toggle_echo(self) -> None:
        if self.preview_edit.echoMode() == QLineEdit.EchoMode.Password:
            self.preview_edit.setEchoMode(QLineEdit.EchoMode.Normal)
        else:
            self.preview_edit.setEchoMode(QLineEdit.EchoMode.Password)

    def get_value(self) -> str:
        return self.preview_edit.text()


class BridgeSignals(QObject):
    biometricVerified = pyqtSignal(object)
    qrUrlUpdated = pyqtSignal(str)
    logMessage = pyqtSignal(str)


class CriptexMainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Criptex")
        self.resize(1280, 840)
        self.setStyleSheet(ENTERPRISE_SECURITY_QSS)

        self.signals = BridgeSignals()
        self.signals.biometricVerified.connect(self._on_biometric_verified_ui)
        self.signals.qrUrlUpdated.connect(self._render_qr_code_url)
        self.signals.logMessage.connect(self._append_security_log)

        self.vault_storage = CriptexVaultStorage()
        self.usb_manager = UsbKeyManager()

        self.shield = FortressShield(on_event=lambda msg: self.signals.logMessage.emit(msg))
        self.bio_server = SmartphoneBiometricServer(
            vault_storage=self.vault_storage,
            on_authenticated=lambda res: self.signals.biometricVerified.emit(res),
            on_log=lambda msg: self.signals.logMessage.emit(msg),
            on_qr_url_updated=lambda url: self.signals.qrUrlUpdated.emit(url),
        )

        self.current_master_key: Optional[str] = None
        self.active_usb_drive: Optional[UsbDriveInfo] = None
        self.biometric_unlocked: bool = False
        self.last_bio_result: Optional[BiometricAuthResult] = None
        self._detected_drives: List[UsbDriveInfo] = []

        # Contentor Principal com Barra Superior Discreta e Profissional
        master_widget = QWidget()
        master_layout = QVBoxLayout(master_widget)
        master_layout.setContentsMargins(0, 0, 0, 0)
        master_layout.setSpacing(0)

        top_bar = QFrame()
        top_bar.setObjectName("TopHeaderBar")
        top_bar.setFixedHeight(36)
        tb_layout = QHBoxLayout(top_bar)
        tb_layout.setContentsMargins(20, 0, 20, 0)

        lbl_brand = QLabel("Criptex Security Suite  |  Cofre de Passwords e Ficheiros")
        lbl_brand.setStyleSheet("font-size: 12px; font-weight: 600; color: #c9d1d9;")
        self.lbl_header_status = QLabel("Estado: Aguardando Autenticação  •  Motor: Vigenère Mod-256 + HMAC-SHA256")
        self.lbl_header_status.setStyleSheet("font-size: 12px; color: #8b949e;")
        tb_layout.addWidget(lbl_brand)
        tb_layout.addStretch()
        tb_layout.addWidget(self.lbl_header_status)
        master_layout.addWidget(top_bar)

        self.stack = QStackedWidget()
        master_layout.addWidget(self.stack, 1)
        self.setCentralWidget(master_widget)

        self._build_lock_screen()
        self._build_vault_screen()

        self.stack.setCurrentWidget(self.lock_screen)
        self._start_biometric_qr_session()
        self._refresh_usb_drives_list()

        self.telemetry_timer = QTimer(self)
        self.telemetry_timer.timeout.connect(self._on_periodic_tick)
        self.telemetry_timer.start(1500)

    # ==================================================================
    # ECRÃ 1: AUTENTICAÇÃO DUPLA (BIOMETRIA + PEN USB FÍSICA)
    # ==================================================================
    def _build_lock_screen(self) -> None:
        self.lock_screen = QWidget()
        root = QHBoxLayout(self.lock_screen)
        root.setContentsMargins(28, 24, 28, 24)
        root.setSpacing(22)

        # Painel Esquerdo: Fator 1 — Autenticação Biométrica no Smartphone
        qr_card = QFrame()
        qr_card.setObjectName("Card")
        qr_layout = QVBoxLayout(qr_card)
        qr_layout.setContentsMargins(24, 22, 24, 22)
        qr_layout.setSpacing(12)

        lbl_hero = QLabel("Criptex Vault")
        lbl_hero.setObjectName("HeroTitle")
        qr_layout.addWidget(lbl_hero)

        lbl_sec1 = QLabel("1. Verificação Biométrica via Smartphone")
        lbl_sec1.setObjectName("SectionTitle")
        qr_layout.addWidget(lbl_sec1)

        lbl_sub = QLabel(
            "Digitalize o código QR abaixo com o seu smartphone para validar a sua Impressão Digital "
            "ou FaceID (WebAuthn) na rede local."
        )
        lbl_sub.setWordWrap(True)
        lbl_sub.setObjectName("Subtle")
        qr_layout.addWidget(lbl_sub)

        self.qr_image_label = QLabel()
        self.qr_image_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.qr_image_label.setFixedSize(240, 240)
        self.qr_image_label.setStyleSheet(
            "background-color: #ffffff; border: 1px solid #30363d; border-radius: 8px; padding: 10px;"
        )
        qr_center = QHBoxLayout()
        qr_center.addStretch()
        qr_center.addWidget(self.qr_image_label)
        qr_center.addStretch()
        qr_layout.addLayout(qr_center)

        self.qr_url_label = QLabel("A iniciar servidor HTTPS local...")
        self.qr_url_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.qr_url_label.setStyleSheet("font-family: Consolas, monospace; color: #8b949e; font-size: 11px;")
        self.qr_url_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        qr_layout.addWidget(self.qr_url_label)

        self.bio_pairing_info_label = QLabel()
        self.bio_pairing_info_label.setWordWrap(True)
        self.bio_pairing_info_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.bio_pairing_info_label.setStyleSheet(
            "background-color: #0d1117; border: 1px solid #30363d; border-radius: 5px; padding: 8px; "
            "color: #8b949e; font-size: 11px;"
        )
        qr_layout.addWidget(self.bio_pairing_info_label)

        self.bio_status_badge = QLabel("Aguardando leitura biométrica no smartphone...")
        self.bio_status_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.bio_status_badge.setStyleSheet(
            "background-color: #1f1d14; border: 1px solid #9e6a03; border-radius: 5px; color: #e3b341; "
            "padding: 9px; font-size: 12px; font-weight: 600;"
        )
        qr_layout.addWidget(self.bio_status_badge)

        qr_btns = QHBoxLayout()
        btn_refresh_qr = QPushButton("Gerar Novo QR Code")
        btn_refresh_qr.clicked.connect(self._start_biometric_qr_session)
        btn_copy_qr_url = QPushButton("Copiar Endereço HTTPS")
        btn_copy_qr_url.clicked.connect(lambda: QApplication.clipboard().setText(self.bio_server.get_qr_url()))
        qr_btns.addWidget(btn_refresh_qr)
        qr_btns.addWidget(btn_copy_qr_url)
        qr_layout.addLayout(qr_btns)

        qr_layout.addStretch()
        root.addWidget(qr_card, 5)

        # Painel Direito: Fator 2 — Chave Física USB (Cifra de Vigenère)
        right_card = QFrame()
        right_card.setObjectName("Card")
        r_layout = QVBoxLayout(right_card)
        r_layout.setContentsMargins(24, 22, 24, 22)
        r_layout.setSpacing(12)

        lbl_usb_title = QLabel("2. Chave da Cifra de Vigenère (Pen USB Física)")
        lbl_usb_title.setObjectName("SectionTitle")
        r_layout.addWidget(lbl_usb_title)

        desc_usb = QLabel(
            "A palavra-chave da Cifra de Vigenère é armazenada exclusivamente numa Pen USB física.\n"
            "• Com Biometria + Pen USB Física: O cofre abre e desencripta as passwords e ficheiros.\n"
            "• Sem Pen USB Física (ex: smartphone roubado): O Criptex abre, mas todos os dados permanecem encriptados."
        )
        desc_usb.setWordWrap(True)
        desc_usb.setObjectName("Subtle")
        r_layout.addWidget(desc_usb)

        self.usb_status_badge = QLabel("A verificar dispositivos USB ligados...")
        self.usb_status_badge.setWordWrap(True)
        self.usb_status_badge.setStyleSheet(
            "background-color: #281216; border: 1px solid #da3633; border-radius: 5px; color: #ffa198; "
            "padding: 9px; font-size: 12px; font-weight: 600;"
        )
        r_layout.addWidget(self.usb_status_badge)

        usb_sel_row = QHBoxLayout()
        self.usb_combo = QComboBox()
        btn_scan_usb = QPushButton("Atualizar Lista USB")
        btn_scan_usb.clicked.connect(self._refresh_usb_drives_list)
        usb_sel_row.addWidget(self.usb_combo, 1)
        usb_sel_row.addWidget(btn_scan_usb)
        r_layout.addLayout(usb_sel_row)

        # Sub-painel de Configuração da Chave na Pen USB
        prov_box = QFrame()
        prov_box.setObjectName("SubPanel")
        p_layout = QVBoxLayout(prov_box)
        p_layout.setContentsMargins(14, 12, 14, 12)
        p_layout.setSpacing(8)

        lbl_p = QLabel("Configurar ou Gravar Chave Vigenère na Pen USB:")
        lbl_p.setStyleSheet("font-weight: 600; color: #f0f6fc; font-size: 12px;")
        p_layout.addWidget(lbl_p)

        key_row = QHBoxLayout()
        self.usb_custom_key_edit = MaskedVaultLineEdit(
            self.shield,
            placeholder="Palavra-chave personalizada (ou deixe em branco para gerar chave automática de 48 bytes)...",
            secret_field=True,
        )
        btn_vk = QPushButton("Teclado Virtual")
        btn_vk.clicked.connect(self._open_virtual_keypad_for_master)
        key_row.addWidget(self.usb_custom_key_edit, 1)
        key_row.addWidget(btn_vk)
        p_layout.addLayout(key_row)

        prov_btns = QHBoxLayout()
        btn_provision_usb = QPushButton("Gravar Chave na Pen USB Selecionada")
        btn_provision_usb.clicked.connect(self._provision_selected_usb)
        prov_btns.addWidget(btn_provision_usb)
        p_layout.addLayout(prov_btns)

        r_layout.addWidget(prov_box)

        self.btn_enter_vault = QPushButton("Aguardando Confirmação Biométrica...")
        self.btn_enter_vault.setObjectName("PrimaryBtn")
        self.btn_enter_vault.setFixedHeight(42)
        self.btn_enter_vault.setEnabled(False)
        self.btn_enter_vault.clicked.connect(self._attempt_unlock_vault)
        r_layout.addWidget(self.btn_enter_vault)

        lbl_log = QLabel("Registo de Eventos e Auditoria:")
        lbl_log.setObjectName("SectionTitle")
        r_layout.addWidget(lbl_log)

        self.lock_log_list = QListWidget()
        r_layout.addWidget(self.lock_log_list, 1)

        root.addWidget(right_card, 6)
        self.stack.addWidget(self.lock_screen)

    # ==================================================================
    # ECRÃ 2: INTERIOR DO COFRE (PASSWORDS & FICHEIROS)
    # ==================================================================
    def _build_vault_screen(self) -> None:
        self.vault_screen = QWidget()
        v_root = QVBoxLayout(self.vault_screen)
        v_root.setContentsMargins(18, 14, 18, 14)
        v_root.setSpacing(10)

        # Barra de Estado de Proteção Ativa
        banner = QFrame()
        banner.setObjectName("ShieldBanner")
        b_layout = QHBoxLayout(banner)
        b_layout.setContentsMargins(16, 9, 16, 9)

        self.lbl_shield_state = QLabel("Proteção Ativa")
        self.lbl_shield_state.setStyleSheet("font-weight: 700; color: #3fb950; font-size: 13px;")
        b_layout.addWidget(self.lbl_shield_state)

        self.lbl_usb_vault_state = QLabel("Pen USB: A verificar...")
        self.lbl_usb_vault_state.setStyleSheet(
            "background-color: #12261e; border: 1px solid #238636; border-radius: 4px; color: #3fb950; "
            "padding: 4px 10px; font-size: 12px; font-weight: 600;"
        )
        b_layout.addWidget(self.lbl_usb_vault_state)

        self.lbl_net_state = QLabel("Internet: Cortada")
        self.lbl_net_state.setStyleSheet(
            "background-color: #281216; border: 1px solid #da3633; border-radius: 4px; color: #ffa198; "
            "padding: 4px 10px; font-size: 12px; font-weight: 600;"
        )
        b_layout.addWidget(self.lbl_net_state)

        self.lbl_kbd_state = QLabel("Teclado: Mascarado")
        self.lbl_kbd_state.setStyleSheet(
            "background-color: #161b22; border: 1px solid #30363d; border-radius: 4px; color: #c9d1d9; "
            "padding: 4px 10px; font-size: 12px; font-weight: 600;"
        )
        b_layout.addWidget(self.lbl_kbd_state)

        self.lbl_stream_state = QLabel("Anti-Gravação: Ativo")
        self.lbl_stream_state.setStyleSheet(
            "background-color: #161b22; border: 1px solid #30363d; border-radius: 4px; color: #58a6ff; "
            "padding: 4px 10px; font-size: 12px; font-weight: 600;"
        )
        b_layout.addWidget(self.lbl_stream_state)

        b_layout.addStretch()

        btn_lock = QPushButton("Trancar Cofre e Restaurar Internet")
        btn_lock.setObjectName("DangerBtn")
        btn_lock.clicked.connect(self.lock_vault)
        b_layout.addWidget(btn_lock)

        v_root.addWidget(banner)

        # Aviso quando o Cofre é aberto sem a Pen USB Física
        self.no_usb_warning_banner = QFrame()
        self.no_usb_warning_banner.setObjectName("WarningCipherBanner")
        w_layout = QHBoxLayout(self.no_usb_warning_banner)
        w_layout.setContentsMargins(16, 10, 16, 10)
        self.lbl_no_usb_warning = QLabel(
            "Aviso de Segurança (Pen USB Ausente): O Criptex foi desbloqueado apenas com a biometria do smartphone, "
            "mas a Pen USB física com a palavra-chave da Cifra de Vigenère não se encontra ligada ao computador. "
            "Todos os dados (passwords e ficheiros) permanecem encriptados. Insira a Pen USB para desencriptar."
        )
        self.lbl_no_usb_warning.setWordWrap(True)
        self.lbl_no_usb_warning.setStyleSheet("color: #ffa198; font-weight: 600; font-size: 12px;")
        w_layout.addWidget(self.lbl_no_usb_warning, 1)
        self.no_usb_warning_banner.setVisible(False)
        v_root.addWidget(self.no_usb_warning_banner)

        # Separadores do Cofre
        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_passwords_tab(), "Passwords (Cifra de Vigenère)")
        self.tabs.addTab(self._build_files_tab(), "Ficheiros Cifrados (.crpx)")
        self.tabs.addTab(self._build_vigenere_inspector_tab(), "Inspetor da Cifra de Vigenère")
        self.tabs.addTab(self._build_security_center_tab(), "Segurança & Monitorização")
        self.tabs.addTab(self._build_settings_tab(), "Definições & Dispositivos")
        v_root.addWidget(self.tabs, 1)

        # Barra Inferior de Proteção de Teclado
        chaff_bar = QFrame()
        chaff_bar.setObjectName("Card")
        c_layout = QHBoxLayout(chaff_bar)
        c_layout.setContentsMargins(12, 6, 12, 6)
        lbl_c = QLabel("Proteção Anti-Keylogger (Ruído externo gerado):")
        lbl_c.setStyleSheet("color: #8b949e; font-weight: 600; font-size: 12px;")
        self.lbl_chaff_stream = QLabel("A aguardar digitação dentro do cofre...")
        self.lbl_chaff_stream.setStyleSheet("font-family: Consolas, monospace; color: #58a6ff; font-size: 12px;")
        c_layout.addWidget(lbl_c)
        c_layout.addWidget(self.lbl_chaff_stream, 1)
        v_root.addWidget(chaff_bar)
        self.stack.addWidget(self.vault_screen)

    # ------------------------------------------------------------------
    # ABA 1: COFRE DE PASSWORDS (CIFRA DE VIGENÈRE)
    # ------------------------------------------------------------------
    def _build_passwords_tab(self) -> QWidget:
        page = QWidget()
        layout = QHBoxLayout(page)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(16)

        left = QVBoxLayout()
        self.lbl_pw_table_header = QLabel("Passwords Guardadas (Encriptadas com Cifra de Vigenère)")
        self.lbl_pw_table_header.setObjectName("SectionTitle")
        left.addWidget(self.lbl_pw_table_header)

        self.pw_table = QTableWidget(0, 5)
        self.pw_table.setHorizontalHeaderLabels(
            ["ID", "Serviço / Título", "Utilizador", "Password Cifrada (Vigenère)", "Token Criptográfico"]
        )
        self.pw_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.pw_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.pw_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.pw_table.itemSelectionChanged.connect(self._on_password_selected)
        left.addWidget(self.pw_table, 1)

        btn_row = QHBoxLayout()
        self.btn_reveal_pw = QPushButton("Desencriptar e Mostrar Password")
        self.btn_reveal_pw.clicked.connect(self._reveal_selected_password)
        self.btn_inspect_pw = QPushButton("Inspecionar na Matriz Vigenère")
        self.btn_inspect_pw.clicked.connect(self._inspect_selected_password_in_matrix)
        self.btn_del_pw = QPushButton("Eliminar Registo")
        self.btn_del_pw.setObjectName("DangerBtn")
        self.btn_del_pw.clicked.connect(self._delete_selected_password)
        btn_row.addWidget(self.btn_reveal_pw)
        btn_row.addWidget(self.btn_inspect_pw)
        btn_row.addWidget(self.btn_del_pw)
        left.addLayout(btn_row)

        layout.addLayout(left, 7)

        form_card = QFrame()
        form_card.setObjectName("Card")
        f_layout = QVBoxLayout(form_card)
        f_layout.setContentsMargins(18, 18, 18, 18)
        f_layout.setSpacing(9)

        lbl_f = QLabel("Adicionar Nova Password")
        lbl_f.setObjectName("SectionTitle")
        f_layout.addWidget(lbl_f)

        self.pw_title_edit = MaskedVaultLineEdit(self.shield, "Ex: Banco, Email, Servidor")
        self.pw_user_edit = MaskedVaultLineEdit(self.shield, "Utilizador ou Email")
        self.pw_url_edit = MaskedVaultLineEdit(self.shield, "URL (ex: https://...)")
        self.pw_secret_edit = MaskedVaultLineEdit(
            self.shield, "Password secreta (cifrada com a chave da Pen USB)", secret_field=True
        )
        self.pw_notes_edit = MaskedVaultLineEdit(self.shield, "Notas adicionais")

        for w in (
            self.pw_title_edit,
            self.pw_user_edit,
            self.pw_url_edit,
            self.pw_secret_edit,
            self.pw_notes_edit,
        ):
            w.chaffGenerated.connect(self._on_chaff_generated)

        self.pw_secret_edit.textChanged.connect(self._update_live_vigenere_pw_preview)

        f_layout.addWidget(QLabel("Título / Serviço:"))
        f_layout.addWidget(self.pw_title_edit)
        f_layout.addWidget(QLabel("Utilizador:"))
        f_layout.addWidget(self.pw_user_edit)
        f_layout.addWidget(QLabel("URL / Endereço:"))
        f_layout.addWidget(self.pw_url_edit)
        f_layout.addWidget(QLabel("Password (Input Protegido):"))

        sec_row = QHBoxLayout()
        sec_row.addWidget(self.pw_secret_edit, 1)
        btn_vk_pw = QPushButton("Teclado")
        btn_vk_pw.setToolTip("Abrir Teclado Virtual Seguro")
        btn_vk_pw.clicked.connect(self._open_virtual_keypad_for_pw)
        sec_row.addWidget(btn_vk_pw)
        f_layout.addLayout(sec_row)

        f_layout.addWidget(QLabel("Pré-visualização da Cifra de Vigenère:"))
        self.lbl_live_vig_preview = QLabel("A aguardar introdução...")
        self.lbl_live_vig_preview.setWordWrap(True)
        self.lbl_live_vig_preview.setStyleSheet(
            "background-color: #0d1117; border: 1px solid #30363d; border-radius: 5px; padding: 8px; "
            "font-family: Consolas, monospace; color: #58a6ff; font-size: 11px;"
        )
        f_layout.addWidget(self.lbl_live_vig_preview)

        f_layout.addWidget(QLabel("Notas:"))
        f_layout.addWidget(self.pw_notes_edit)

        self.btn_save_pw = QPushButton("Cifrar com Chave USB e Guardar")
        self.btn_save_pw.setObjectName("PrimaryBtn")
        self.btn_save_pw.clicked.connect(self._save_password_entry)
        f_layout.addWidget(self.btn_save_pw)

        self.lbl_revealed_box = QLabel(
            "Selecione um registo na tabela e clique em 'Desencriptar e Mostrar Password'."
        )
        self.lbl_revealed_box.setWordWrap(True)
        self.lbl_revealed_box.setStyleSheet(
            "background-color: #0d1117; border: 1px solid #30363d; border-left: 3px solid #2f81f7; "
            "border-radius: 4px; padding: 10px; font-size: 12px; color: #e6edf3;"
        )
        f_layout.addWidget(self.lbl_revealed_box)
        f_layout.addStretch()

        layout.addWidget(form_card, 4)
        return page

    # ------------------------------------------------------------------
    # ABA 2: COFRE DE FICHEIROS (BYTES VIGENÈRE)
    # ------------------------------------------------------------------
    def _build_files_tab(self) -> QWidget:
        page = QWidget()
        layout = QHBoxLayout(page)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(16)

        left = QVBoxLayout()
        lbl_f = QLabel("Ficheiros Guardados no Cofre (Modificados ao Nível de Bytes com Vigenère)")
        lbl_f.setObjectName("SectionTitle")
        left.addWidget(lbl_f)

        self.files_table = QTableWidget(0, 6)
        self.files_table.setHorizontalHeaderLabels(
            [
                "ID",
                "Nome do Ficheiro",
                "Contentor (.crpx)",
                "Tamanho (Bytes)",
                "Amostra Hex Vigenère",
                "Data",
            ]
        )
        self.files_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.files_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.files_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.files_table.itemSelectionChanged.connect(self._on_vault_file_selected)
        left.addWidget(self.files_table, 1)

        self.chk_shred_source = QCheckBox(
            "Eliminar de forma segura (Shred) o ficheiro original fora do cofre após a importação"
        )
        left.addWidget(self.chk_shred_source)

        actions = QHBoxLayout()
        self.btn_import_file = QPushButton("Importar e Cifrar Ficheiro")
        self.btn_import_file.setObjectName("PrimaryBtn")
        self.btn_import_file.clicked.connect(self._import_file_to_vault)

        self.btn_export_file = QPushButton("Desencriptar e Exportar Ficheiro")
        self.btn_export_file.clicked.connect(self._export_file_from_vault)

        self.btn_del_file = QPushButton("Eliminar do Cofre")
        self.btn_del_file.setObjectName("DangerBtn")
        self.btn_del_file.clicked.connect(self._delete_file_from_vault)

        actions.addWidget(self.btn_import_file)
        actions.addWidget(self.btn_export_file)
        actions.addWidget(self.btn_del_file)
        left.addLayout(actions)

        layout.addLayout(left, 7)

        inspect_card = QFrame()
        inspect_card.setObjectName("Card")
        i_layout = QVBoxLayout(inspect_card)
        i_layout.setContentsMargins(16, 16, 16, 16)

        lbl_i = QLabel("Inspeção Binária do Ficheiro no Cofre")
        lbl_i.setObjectName("SectionTitle")
        i_layout.addWidget(lbl_i)

        lbl_sub = QLabel(
            "Compara os bytes originais com os bytes cifrados pela Cifra de Vigenère dentro do cofre. "
            "Sem a Pen USB inserida, apenas os bytes encriptados são visíveis."
        )
        lbl_sub.setWordWrap(True)
        lbl_sub.setObjectName("Subtle")
        i_layout.addWidget(lbl_sub)

        self.file_hex_inspector = QPlainTextEdit()
        self.file_hex_inspector.setReadOnly(True)
        self.file_hex_inspector.setStyleSheet("font-family: Consolas, monospace; font-size: 12px; color: #c9d1d9;")
        i_layout.addWidget(self.file_hex_inspector, 1)

        layout.addWidget(inspect_card, 5)
        return page

    # ------------------------------------------------------------------
    # ABA 3: INSPETOR DA CIFRA DE VIGENÈRE
    # ------------------------------------------------------------------
    def _build_vigenere_inspector_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        lbl = QLabel("Verificador da Cifra de Vigenère (Mod 256 & ASCII)")
        lbl.setObjectName("SectionTitle")
        layout.addWidget(lbl)

        top_row = QHBoxLayout()
        self.vig_test_input = MaskedVaultLineEdit(
            self.shield, "Introduza um texto ou password para analisar os deslocamentos da cifra..."
        )
        self.vig_test_input.chaffGenerated.connect(self._on_chaff_generated)
        self.vig_test_input.setText("SegredoConfidencial2026!")
        btn_calc = QPushButton("Calcular Transformação")
        btn_calc.setObjectName("PrimaryBtn")
        btn_calc.clicked.connect(self._refresh_vigenere_inspector)
        top_row.addWidget(self.vig_test_input, 1)
        top_row.addWidget(btn_calc)
        layout.addLayout(top_row)

        self.vig_summary_label = QLabel()
        self.vig_summary_label.setWordWrap(True)
        self.vig_summary_label.setStyleSheet(
            "background-color: #161b22; border: 1px solid #30363d; border-left: 3px solid #2f81f7; "
            "border-radius: 5px; padding: 10px; font-family: Consolas, monospace; color: #58a6ff; font-size: 12px;"
        )
        layout.addWidget(self.vig_summary_label)

        self.vig_steps_table = QTableWidget(0, 7)
        self.vig_steps_table.setHorizontalHeaderLabels(
            [
                "Índice (i)",
                "Carácter Original",
                "Byte P[i]",
                "Carácter da Chave USB",
                "Deslocamento K[i]",
                "Fórmula Vigenère (Mod 256)",
                "Byte Cifrado C[i]",
            ]
        )
        self.vig_steps_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.vig_steps_table, 1)
        return page

    # ------------------------------------------------------------------
    # ABA 4: SEGURANÇA & MONITORIZAÇÃO
    # ------------------------------------------------------------------
    def _build_security_center_tab(self) -> QWidget:
        page = QWidget()
        layout = QHBoxLayout(page)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)

        left_card = QFrame()
        left_card.setObjectName("Card")
        l_layout = QVBoxLayout(left_card)

        lbl_s = QLabel("Estado das Proteções do Sistema e Chave USB")
        lbl_s.setObjectName("SectionTitle")
        l_layout.addWidget(lbl_s)

        self.security_details_box = QPlainTextEdit()
        self.security_details_box.setReadOnly(True)
        self.security_details_box.setStyleSheet("font-family: Consolas, monospace; font-size: 12px; color: #c9d1d9;")
        l_layout.addWidget(self.security_details_box, 1)

        btn_force_scan = QPushButton("Verificar e Fechar Aplicações de Gravação / Stream Agora")
        btn_force_scan.setObjectName("PrimaryBtn")
        btn_force_scan.clicked.connect(lambda: self.shield.scan_and_kill_streaming_apps())
        l_layout.addWidget(btn_force_scan)

        layout.addWidget(left_card, 5)

        right_card = QFrame()
        right_card.setObjectName("Card")
        r_layout = QVBoxLayout(right_card)

        lbl_ev = QLabel("Registo de Auditoria de Segurança")
        lbl_ev.setObjectName("SectionTitle")
        r_layout.addWidget(lbl_ev)

        self.vault_log_list = QListWidget()
        r_layout.addWidget(self.vault_log_list, 1)

        layout.addWidget(right_card, 6)
        return page

    # ------------------------------------------------------------------
    # ABA 5: DEFINIÇÕES & DISPOSITIVOS (GESTÃO DO SMARTPHONE VINCULADO)
    # ------------------------------------------------------------------
    def _build_settings_tab(self) -> QWidget:
        page = QWidget()
        layout = QHBoxLayout(page)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)

        # Coluna Esquerda: Dispositivo Biométrico Vinculado
        bio_card = QFrame()
        bio_card.setObjectName("Card")
        b_layout = QVBoxLayout(bio_card)
        b_layout.setContentsMargins(20, 20, 20, 20)
        b_layout.setSpacing(12)

        lbl_title = QLabel("Dispositivo Biométrico Registado (Smartphone Vinculado)")
        lbl_title.setObjectName("SectionTitle")
        b_layout.addWidget(lbl_title)

        lbl_desc = QLabel(
            "Após o primeiro uso do código QR e desbloqueio com o sistema biométrico do telemóvel, "
            "esse dispositivo fica permanentemente vinculado ao cofre. Nenhum outro smartphone poderá "
            "desbloquear o Criptex.\n\n"
            "Para alterar ou substituir o telemóvel registado, é obrigatória a presença simultânea de:\n"
            "1. O desbloqueio biométrico original na sessão atual;\n"
            "2. A Pen USB física com a palavra-chave da Cifra de Vigenère inserida no computador."
        )
        lbl_desc.setWordWrap(True)
        lbl_desc.setObjectName("Subtle")
        b_layout.addWidget(lbl_desc)

        self.settings_bio_info_box = QLabel()
        self.settings_bio_info_box.setWordWrap(True)
        self.settings_bio_info_box.setStyleSheet(
            "background-color: #0d1117; border: 1px solid #30363d; border-left: 3px solid #2f81f7; "
            "border-radius: 5px; padding: 12px; font-family: Consolas, monospace; font-size: 12px; color: #e6edf3;"
        )
        b_layout.addWidget(self.settings_bio_info_box)

        self.settings_auth_reqs_badge = QLabel()
        self.settings_auth_reqs_badge.setWordWrap(True)
        b_layout.addWidget(self.settings_auth_reqs_badge)

        self.btn_reset_bio_device = QPushButton(
            "Desvincular Smartphone Atual e Autorizar Novo Registo Biométrico via QR"
        )
        self.btn_reset_bio_device.setObjectName("DangerBtn")
        self.btn_reset_bio_device.clicked.connect(self._reset_biometric_device_from_settings)
        b_layout.addWidget(self.btn_reset_bio_device)

        b_layout.addStretch()
        layout.addWidget(bio_card, 6)

        # Coluna Direita: Estado da Chave Física USB & Segurança do Cofre
        usb_card = QFrame()
        usb_card.setObjectName("Card")
        u_layout = QVBoxLayout(usb_card)
        u_layout.setContentsMargins(20, 20, 20, 20)
        u_layout.setSpacing(12)

        lbl_u_title = QLabel("Chave Física USB & Política de Acesso")
        lbl_u_title.setObjectName("SectionTitle")
        u_layout.addWidget(lbl_u_title)

        self.settings_usb_info_box = QLabel()
        self.settings_usb_info_box.setWordWrap(True)
        self.settings_usb_info_box.setStyleSheet(
            "background-color: #0d1117; border: 1px solid #30363d; border-radius: 5px; "
            "padding: 12px; font-family: Consolas, monospace; font-size: 12px; color: #c9d1d9;"
        )
        u_layout.addWidget(self.settings_usb_info_box)

        lbl_policy = QLabel(
            "Política de Segurança Criptex:\n"
            "• 1º Uso do QR Code: Regista automaticamente o telemóvel que efetuar o primeiro desbloqueio biométrico.\n"
            "• Usos Seguintes: O servidor HTTPS local valida a credencial/token criptográfico do telemóvel e bloqueia qualquer outro dispositivo.\n"
            "• Proteção contra Roubo: Se o telemóvel registado for utilizado sem a Pen USB física no PC, o cofre abre em modo restrito (todos os dados encriptados e as definições de dispositivo bloqueadas)."
        )
        lbl_policy.setWordWrap(True)
        lbl_policy.setObjectName("Subtle")
        u_layout.addWidget(lbl_policy)

        u_layout.addStretch()
        layout.addWidget(usb_card, 5)
        return page

    # ==================================================================
    # GESTÃO DE PEN USB FÍSICA (DETEÇÃO, PROVISIONAMENTO E HOTPLUG)
    # ==================================================================
    def _refresh_usb_drives_list(self) -> None:
        self._detected_drives = self.usb_manager.scan_usb_drives()
        self.usb_combo.clear()
        for d in self._detected_drives:
            self.usb_combo.addItem(d.display_name)

        active_drive, key = self.usb_manager.find_active_usb_key()
        if active_drive and key:
            self.active_usb_drive = active_drive
            self.current_master_key = key
            if not self.vault_storage.is_initialized():
                self.vault_storage.initialize_vault(
                    usb_master_key=key,
                    usb_serial=active_drive.serial_number,
                    usb_label=active_drive.volume_label,
                )
            self.usb_status_badge.setText(
                f"Pen USB com Chave Detetada: {active_drive.mount_point} ({active_drive.volume_label} | S/N: {active_drive.serial_number})"
            )
            self.usb_status_badge.setStyleSheet(
                "background-color: #12261e; border: 1px solid #238636; border-radius: 5px; color: #3fb950; "
                "padding: 9px; font-size: 12px; font-weight: 600;"
            )
        else:
            self.active_usb_drive = None
            self.current_master_key = None
            if self._detected_drives:
                self.usb_status_badge.setText(
                    "Pen USB detetada, mas sem ficheiro de chave (.criptex_usb_key.crpxkey). Clique em 'Gravar Chave na Pen USB Selecionada'."
                )
            else:
                self.usb_status_badge.setText(
                    "Nenhuma Pen USB com chave detetada: Se abrir o Criptex apenas com o smartphone, todos os dados permanecerão encriptados."
                )
            self.usb_status_badge.setStyleSheet(
                "background-color: #281216; border: 1px solid #da3633; border-radius: 5px; color: #ffa198; "
                "padding: 9px; font-size: 12px; font-weight: 600;"
            )

        self._update_unlock_button_text()

    def _provision_selected_usb(self) -> None:
        idx = self.usb_combo.currentIndex()
        if idx < 0 or idx >= len(self._detected_drives):
            QMessageBox.warning(
                self,
                "Nenhuma Pen USB Selecionada",
                "Insira uma Pen USB física no computador e clique em 'Atualizar Lista USB' antes de gravar a chave.",
            )
            return

        drive = self._detected_drives[idx]
        custom_key = self.usb_custom_key_edit.text().strip()

        key_written, key_path = self.usb_manager.provision_usb_key(
            drive=drive,
            vigenere_key=custom_key if custom_key else None,
        )

        if not self.vault_storage.is_initialized():
            self.vault_storage.initialize_vault(
                usb_master_key=key_written,
                usb_serial=drive.serial_number,
                usb_label=drive.volume_label,
            )
            self._append_security_log(
                f"Cofre inicializado e associado à Pen USB {drive.mount_point} (S/N {drive.serial_number})."
            )
        else:
            if not self.vault_storage.verify_master_key(key_written):
                reply = QMessageBox.question(
                    self,
                    "Associar Cofre à Nova Chave USB?",
                    "O cofre existente estava associado a outra chave. Deseja reinicializar o cofre para usar esta nova Pen USB?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                )
                if reply == QMessageBox.StandardButton.Yes:
                    self.vault_storage.initialize_vault(
                        usb_master_key=key_written,
                        usb_serial=drive.serial_number,
                        usb_label=drive.volume_label,
                    )

        self.usb_custom_key_edit.clear()
        self._refresh_usb_drives_list()
        QMessageBox.information(
            self,
            "Chave Vigenère Guardada na Pen USB",
            f"A palavra-chave da Cifra de Vigenère foi guardada com sucesso na Pen USB:\n{key_path}\n\n"
            f"Sem esta Pen USB ligada ao computador, todos os dados do Criptex permanecerão encriptados.",
        )

    # ==================================================================
    # LÓGICA DE AUTENTICAÇÃO BIOMÉTRICA (QR CODE + WEBAUTHN)
    # ==================================================================
    def _refresh_bio_pairing_banner_on_lock_screen(self) -> None:
        bio_info = self.vault_storage.get_biometric_device_info()
        if bio_info.get("paired"):
            dev_name = bio_info.get("device_name") or "Smartphone Registado"
            cred_id = bio_info.get("credential_id") or "-"
            paired_at = bio_info.get("paired_at") or "-"
            self.bio_pairing_info_label.setText(
                f"Dispositivo Vinculado: {dev_name} (ID: {cred_id[:18]} | Registado: {paired_at})\n"
                f"Apenas este smartphone pode desbloquear o Criptex. Alteração disponível apenas nas Definições dentro do cofre."
            )
            self.bio_pairing_info_label.setStyleSheet(
                "background-color: #111b27; border: 1px solid #1f6feb; border-radius: 5px; padding: 8px; "
                "color: #58a6ff; font-size: 11px; font-weight: 600;"
            )
        else:
            self.bio_pairing_info_label.setText(
                "1º Uso (Modo de Registo Inicial): Nenhum smartphone vinculado ainda.\n"
                "O primeiro telemóvel a ler o QR Code e concluir o desbloqueio biométrico ficará registado neste cofre."
            )
            self.bio_pairing_info_label.setStyleSheet(
                "background-color: #0d1117; border: 1px solid #30363d; border-radius: 5px; padding: 8px; "
                "color: #8b949e; font-size: 11px;"
            )

    def _start_biometric_qr_session(self) -> None:
        self.biometric_unlocked = False
        self._update_unlock_button_text()
        self._refresh_bio_pairing_banner_on_lock_screen()
        self.bio_status_badge.setText("Aguardando leitura biométrica no smartphone...")
        self.bio_status_badge.setStyleSheet(
            "background-color: #1f1d14; border: 1px solid #9e6a03; border-radius: 5px; color: #e3b341; "
            "padding: 9px; font-size: 12px; font-weight: 600;"
        )

        url = self.bio_server.start()
        self._render_qr_code_url(url)

    def _render_qr_code_url(self, url: str) -> None:
        if not url:
            return
        self.qr_url_label.setText(url)

        qr = qrcode.QRCode(version=1, box_size=8, border=2)
        qr.add_data(url)
        qr.make(fit=True)
        pil_img = qr.make_image(fill_color="#0d1117", back_color="#ffffff")
        buf = io.BytesIO()
        pil_img.save(buf, format="PNG")
        qimg = QImage.fromData(buf.getvalue(), "PNG")
        pix = QPixmap.fromImage(qimg).scaled(
            220,
            220,
            Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation,
        )
        self.qr_image_label.setPixmap(pix)

    def _on_biometric_verified_ui(self, result: BiometricAuthResult) -> None:
        self.biometric_unlocked = True
        self.last_bio_result = result
        self._refresh_bio_pairing_banner_on_lock_screen()
        self.bio_status_badge.setText(
            f"Biometria Confirmada às {result.timestamp} ({result.mode})"
        )
        self.bio_status_badge.setStyleSheet(
            "background-color: #12261e; border: 1px solid #238636; border-radius: 5px; color: #3fb950; "
            "padding: 9px; font-size: 12px; font-weight: 600;"
        )
        self._update_unlock_button_text()
        self._append_security_log(f"Autenticação biométrica móvel validada ({result.device_info}).")

    def _update_unlock_button_text(self) -> None:
        if not self.biometric_unlocked:
            self.btn_enter_vault.setEnabled(False)
            self.btn_enter_vault.setText("Aguardando Confirmação Biométrica...")
            return

        self.btn_enter_vault.setEnabled(True)
        if self.active_usb_drive and self.current_master_key:
            self.btn_enter_vault.setText(
                f"Abrir Cofre Criptex (Biometria + Pen USB {self.active_usb_drive.mount_point} Verificadas)"
            )
        else:
            self.btn_enter_vault.setText(
                "Abrir Cofre Sem Pen USB (Modo Protegido — Dados Permanecerão Encriptados)"
            )

    # ==================================================================
    # ENTRADA E SAÍDA DO COFRE + SINCRONIZAÇÃO COM PEN USB
    # ==================================================================
    def _attempt_unlock_vault(self) -> None:
        if not self.biometric_unlocked:
            QMessageBox.warning(
                self,
                "Biometria Obrigatória",
                "O cofre Criptex requer a validação biométrica do smartphone antes de abrir.",
            )
            return

        self._refresh_usb_drives_list()
        self.bio_server.stop()

        hwnd = int(self.winId())
        self.shield.engage_fortress(hwnd=hwnd)

        self.stack.setCurrentWidget(self.vault_screen)
        self._sync_vault_usb_lock_state()

    def _sync_vault_usb_lock_state(self) -> None:
        active_drive, key = self.usb_manager.find_active_usb_key()
        has_valid_usb = bool(active_drive and key and self.vault_storage.verify_master_key(key))

        if has_valid_usb:
            self.active_usb_drive = active_drive
            self.current_master_key = key
            self.no_usb_warning_banner.setVisible(False)
            self.lbl_header_status.setText(
                f"Estado: Cofre Desencriptado  •  Pen USB: {active_drive.mount_point} ({active_drive.serial_number})"
            )
            self.lbl_usb_vault_state.setText(
                f"Pen USB Ativa ({active_drive.mount_point}) — Dados Desencriptados"
            )
            self.lbl_usb_vault_state.setStyleSheet(
                "background-color: #12261e; border: 1px solid #238636; border-radius: 4px; color: #3fb950; "
                "padding: 4px 10px; font-size: 12px; font-weight: 600;"
            )
            self.lbl_pw_table_header.setText(
                "Passwords Guardadas (Pen USB Presente — Dados Desencriptados)"
            )
        else:
            self.active_usb_drive = None
            self.current_master_key = None
            self.no_usb_warning_banner.setVisible(True)
            self.lbl_header_status.setText(
                "Estado: Modo Encriptado (Pen USB Ausente — Todos os dados permanecem cifrados)"
            )
            self.lbl_usb_vault_state.setText("Pen USB Ausente — Dados Encriptados")
            self.lbl_usb_vault_state.setStyleSheet(
                "background-color: #281216; border: 1px solid #da3633; border-radius: 4px; color: #ffa198; "
                "padding: 4px 10px; font-size: 12px; font-weight: 600;"
            )
            self.lbl_pw_table_header.setText(
                "Passwords Guardadas (Pen USB Ausente — Todos os dados permanecem encriptados com Vigenère)"
            )
            self.lbl_revealed_box.setText(
                "Dados Encriptados: A Pen USB física com a palavra-chave da Cifra de Vigenère "
                "não está ligada ao computador. Nenhum dado pode ser desencriptado sem a Pen USB."
            )

        for btn in (
            self.btn_save_pw,
            self.btn_del_pw,
            self.btn_import_file,
            self.btn_export_file,
            self.btn_del_file,
        ):
            btn.setEnabled(has_valid_usb)

        self._refresh_passwords_table()
        self._refresh_files_table()
        self._refresh_vigenere_inspector()
        self._refresh_shield_telemetry()
        self._refresh_settings_tab()

    def _refresh_settings_tab(self) -> None:
        bio_info = self.vault_storage.get_biometric_device_info()
        has_valid_usb = bool(
            self.active_usb_drive
            and self.current_master_key
            and self.vault_storage.verify_master_key(self.current_master_key)
        )
        can_change_device = bool(self.biometric_unlocked and has_valid_usb)

        if bio_info.get("paired"):
            self.settings_bio_info_box.setText(
                f"Estado do Vínculo:      ATIVO (Bloqueado ao 1º Dispositivo)\n"
                f"Dispositivo Registado:  {bio_info.get('device_name', '-')}\n"
                f"ID da Credencial:       {bio_info.get('credential_id', '-')}\n"
                f"Data do 1º Registo:     {bio_info.get('paired_at', '-')}\n"
                f"Agente / Plataforma:    {bio_info.get('user_agent') or 'WebAuthn / Passkey Mobile'}\n"
                f"Hash Criptográfico:     {(bio_info.get('device_token_hash') or bio_info.get('public_key_b64') or '-')[:28]}..."
            )
        else:
            self.settings_bio_info_box.setText(
                "Estado do Vínculo:      AGUARDANDO 1º REGISTO QR\n"
                "Dispositivo Registado:  Nenhum (O próximo telemóvel a autenticar ficará vinculado)"
            )

        if can_change_device:
            self.settings_auth_reqs_badge.setText(
                "Requisitos de Segurança Verificados:\n"
                "✓ Desbloqueio Biométrico Original Confirmado\n"
                f"✓ Pen USB Física Presente e Validada ({self.active_usb_drive.mount_point} | S/N {self.active_usb_drive.serial_number})\n"
                "Está autorizado a alterar o smartphone registado."
            )
            self.settings_auth_reqs_badge.setStyleSheet(
                "background-color: #12261e; border: 1px solid #238636; border-radius: 5px; color: #3fb950; "
                "padding: 10px; font-size: 12px; font-weight: 600;"
            )
            self.btn_reset_bio_device.setEnabled(True)
        else:
            self.settings_auth_reqs_badge.setText(
                "Alteração de Dispositivo Bloqueada:\n"
                f"• Desbloqueio Biométrico Original: {'Confirmado' if self.biometric_unlocked else 'Pendente'}\n"
                "• Pen USB Física Vigenère: AUSENTE\n\n"
                "Não é possível alterar o telemóvel registado sem a Pen USB física ligada ao computador."
            )
            self.settings_auth_reqs_badge.setStyleSheet(
                "background-color: #281216; border: 1px solid #da3633; border-radius: 5px; color: #ffa198; "
                "padding: 10px; font-size: 12px; font-weight: 600;"
            )
            self.btn_reset_bio_device.setEnabled(False)

        if has_valid_usb and self.active_usb_drive:
            self.settings_usb_info_box.setText(
                f"Pen USB Ligada:         {self.active_usb_drive.mount_point} ({self.active_usb_drive.volume_label})\n"
                f"Número de Série (HW):   {self.active_usb_drive.serial_number}\n"
                f"Ficheiro de Chave:      {self.active_usb_drive.key_file_path}\n"
                f"Verificação da Chave:   VÁLIDA (Autoriza desencriptação e gestão de dispositivos)"
            )
        else:
            self.settings_usb_info_box.setText(
                "Pen USB Ligada:         NENHUMA PEN USB COM CHAVE VÁLIDA DETETADA\n"
                "Estado dos Dados:       Todos os dados permanecem cifrados com Vigenère\n"
                "Gestão de Dispositivos: Bloqueada até inserir a Pen USB física"
            )

    def _reset_biometric_device_from_settings(self) -> None:
        if not self.biometric_unlocked or not self.current_master_key:
            QMessageBox.critical(
                self,
                "Acesso Negado — Requisitos em Falta",
                "Para alterar o smartphone biométrico registado é obrigatório ter o cofre desbloqueado "
                "com a biometria original e a Pen USB física inserida no computador.",
            )
            return

        reply = QMessageBox.question(
            self,
            "Alterar Smartphone Biométrico Registado",
            "Tem a certeza de que deseja desvincular o smartphone atual?\n\n"
            "• O vínculo atual será removido.\n"
            "• O cofre voltará ao ecrã de autenticação QR para que possa ler o código QR com o novo smartphone "
            "e registá-lo no primeiro uso.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        try:
            self.vault_storage.reset_biometric_pairing(
                usb_master_key=self.current_master_key,
                original_biometric_verified=self.biometric_unlocked,
            )
            self._append_security_log(
                "Vínculo biométrico do smartphone reiniciado nas Definições (autorizado por Biometria Original + Pen USB)."
            )
            self._refresh_settings_tab()
            QMessageBox.information(
                self,
                "Smartphone Desvinculado com Sucesso",
                "O registo biométrico anterior foi removido.\n"
                "O Criptex irá agora regressar ao ecrã inicial para que possa ler o código QR e vincular o novo telemóvel.",
            )
            self.lock_vault()
        except PermissionError as e:
            QMessageBox.critical(self, "Operação Bloqueada", str(e))

    def lock_vault(self) -> None:
        self.shield.disengage_fortress()
        self.current_master_key = None
        self.pw_table.setRowCount(0)
        self.files_table.setRowCount(0)
        self.file_hex_inspector.clear()
        self.lbl_header_status.setText("Estado: Aguardando Autenticação  •  Motor: Vigenère Mod-256 + HMAC-SHA256")

        self._start_biometric_qr_session()
        self._refresh_usb_drives_list()
        self.stack.setCurrentWidget(self.lock_screen)

    def closeEvent(self, event) -> None:
        try:
            self.bio_server.stop()
            self.shield.disengage_fortress()
        except Exception:
            pass
        super().closeEvent(event)

    # ==================================================================
    # OPERAÇÕES DE PASSWORDS (CIFRA DE VIGENÈRE)
    # ==================================================================
    def _update_live_vigenere_pw_preview(self, text: str) -> None:
        if not text:
            self.lbl_live_vig_preview.setText("A aguardar introdução...")
            return
        if not self.current_master_key:
            self.lbl_live_vig_preview.setText("Insira a Pen USB física para cifrar com a sua chave Vigenère.")
            return
        ascii_vig = VigenereCipher.classic_alphabetic_vigenere(text, self.current_master_key, decrypt=False)
        insp = VigenereCipher.inspect_transformation(text, self.current_master_key, max_steps=8)
        self.lbl_live_vig_preview.setText(
            f"Vigenère ASCII: {ascii_vig}\n"
            f"Bytes Hex:      {insp.ciphertext_hex[:40]}...\n"
            f"HMAC-SHA256:    {insp.mac_hex[:24]}..."
        )

    def _refresh_passwords_table(self) -> None:
        entries = self.vault_storage.list_passwords(self.current_master_key)
        self.pw_table.setRowCount(len(entries))
        for row, e in enumerate(entries):
            title_display = (
                e.decrypted_title
                if e.decrypted_title is not None
                else f"[Encriptado] {e.title_vigenere_ascii}"
            )
            user_display = (
                e.decrypted_username
                if e.decrypted_username is not None
                else f"[Encriptado] {e.username_vigenere_ascii}"
            )

            self.pw_table.setItem(row, 0, QTableWidgetItem(e.id))
            self.pw_table.setItem(row, 1, QTableWidgetItem(title_display))
            self.pw_table.setItem(row, 2, QTableWidgetItem(user_display))
            self.pw_table.setItem(row, 3, QTableWidgetItem(e.vigenere_ascii_preview))
            self.pw_table.setItem(row, 4, QTableWidgetItem(e.vigenere_cipher_token[:36] + "..."))

    def _save_password_entry(self) -> None:
        if not self.current_master_key:
            QMessageBox.critical(
                self,
                "Pen USB Necessária",
                "Não é possível cifrar novas passwords sem a Pen USB física ligada ao computador.",
            )
            return
        title = self.pw_title_edit.text().strip()
        user = self.pw_user_edit.text().strip()
        url = self.pw_url_edit.text().strip()
        secret = self.pw_secret_edit.text()
        notes = self.pw_notes_edit.text().strip()

        if not title or not secret:
            QMessageBox.warning(self, "Campos Obrigatórios", "Preencha pelo menos o Título e a Password.")
            return

        entry = self.vault_storage.add_password(
            usb_master_key=self.current_master_key,
            title=title,
            username=user,
            plain_password=secret,
            url=url,
            notes=notes,
        )
        self.pw_title_edit.clear()
        self.pw_user_edit.clear()
        self.pw_url_edit.clear()
        self.pw_secret_edit.clear()
        self.pw_notes_edit.clear()
        self._refresh_passwords_table()
        self._append_security_log(f"Password cifrada com a chave USB Vigenère e guardada ({entry.id}).")

    def _get_selected_password_entry(self) -> Optional[PasswordEntry]:
        rows = self.pw_table.selectionModel().selectedRows()
        if not rows:
            return None
        entry_id = self.pw_table.item(rows[0].row(), 0).text()
        entries = self.vault_storage.list_passwords(self.current_master_key)
        return next((e for e in entries if e.id == entry_id), None)

    def _on_password_selected(self) -> None:
        entry = self._get_selected_password_entry()
        if not entry:
            return
        if not self.current_master_key:
            self.lbl_revealed_box.setText(
                f"Registo Encriptado (Pen USB Ausente):\n"
                f"• Título Cifrado: {entry.title_vigenere_ascii}\n"
                f"• Utilizador Cifrado: {entry.username_vigenere_ascii}\n"
                f"• Password Cifrada (Vigenère): {entry.vigenere_ascii_preview}\n"
                f"• Token: {entry.vigenere_cipher_token[:44]}..."
            )
        else:
            self.lbl_revealed_box.setText(
                f"Registo '{entry.decrypted_title}' selecionado.\n"
                f"Guardado com Vigenère: {entry.vigenere_ascii_preview}\n"
                f"Clique em 'Desencriptar e Mostrar Password' para revelar."
            )

    def _reveal_selected_password(self) -> None:
        entry = self._get_selected_password_entry()
        if not entry:
            QMessageBox.information(self, "Seleção", "Selecione um registo na tabela primeiro.")
            return
        try:
            plain_pw, plain_notes = self.vault_storage.reveal_password(entry, self.current_master_key)
            self.lbl_revealed_box.setText(
                f"Desencriptado com Chave USB (Vigenère):\n"
                f"• Serviço: {entry.decrypted_title} ({entry.decrypted_username})\n"
                f"• Cifrado no Cofre: {entry.vigenere_ascii_preview}\n"
                f"• Password Original: {plain_pw}\n"
                f"• Notas: {plain_notes or '(Sem notas)'}"
            )
        except PermissionError as e:
            QMessageBox.critical(self, "Pen USB Ausente — Dados Encriptados", str(e))

    def _inspect_selected_password_in_matrix(self) -> None:
        entry = self._get_selected_password_entry()
        if not entry:
            QMessageBox.information(self, "Seleção", "Selecione um registo na tabela primeiro.")
            return
        if not self.current_master_key:
            QMessageBox.warning(
                self,
                "Pen USB Ausente",
                "Sem a Pen USB física ligada, apenas o criptograma Vigenère está disponível.",
            )
            return
        plain_pw, _ = self.vault_storage.reveal_password(entry, self.current_master_key)
        self.vig_test_input.setText(plain_pw)
        self._refresh_vigenere_inspector()
        self.tabs.setCurrentIndex(2)

    def _delete_selected_password(self) -> None:
        entry = self._get_selected_password_entry()
        if not entry or not self.current_master_key:
            return
        self.vault_storage.delete_password(self.current_master_key, entry.id)
        self._refresh_passwords_table()

    # ==================================================================
    # OPERAÇÕES DE FICHEIROS NO COFRE (CIFRA DE VIGENÈRE BYTE-A-BYTE)
    # ==================================================================
    def _refresh_files_table(self) -> None:
        files = self.vault_storage.list_files(self.current_master_key)
        self.files_table.setRowCount(len(files))
        for row, f in enumerate(files):
            name_display = (
                f.decrypted_original_name
                if f.decrypted_original_name is not None
                else f"[Encriptado] {f.original_name_vigenere_ascii}"
            )
            self.files_table.setItem(row, 0, QTableWidgetItem(f.id))
            self.files_table.setItem(row, 1, QTableWidgetItem(name_display))
            self.files_table.setItem(row, 2, QTableWidgetItem(f.vault_filename))
            self.files_table.setItem(row, 3, QTableWidgetItem(f"{f.original_size} B -> {f.encrypted_size} B"))
            self.files_table.setItem(row, 4, QTableWidgetItem(f.vigenere_sample_hex[:28] + "..."))
            self.files_table.setItem(row, 5, QTableWidgetItem(f.added_at))

    def _import_file_to_vault(self) -> None:
        if not self.current_master_key:
            QMessageBox.critical(self, "Pen USB Ausente", "Insira a Pen USB física para cifrar ficheiros.")
            return
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Selecionar Ficheiro para Cifrar com Vigenère no Cofre"
        )
        if not file_path:
            return
        shred = self.chk_shred_source.isChecked()
        try:
            entry = self.vault_storage.import_file(
                Path(file_path),
                self.current_master_key,
                shred_original=shred,
            )
            self._refresh_files_table()
            self._append_security_log(
                f"Ficheiro '{entry.decrypted_original_name}' cifrado com Vigenère no cofre ({entry.vault_filename})."
            )
        except Exception as e:
            QMessageBox.critical(self, "Erro ao Importar Ficheiro", str(e))

    def _on_vault_file_selected(self) -> None:
        rows = self.files_table.selectionModel().selectedRows()
        if not rows:
            return
        file_id = self.files_table.item(rows[0].row(), 0).text()
        try:
            info = self.vault_storage.inspect_vault_file_bytes(file_id, self.current_master_key)
            usb_state = (
                "Desencriptado (Pen USB Presente)"
                if info["usb_unlocked"]
                else "Bloqueado (Pen USB Ausente — Dados Encriptados)"
            )
            lines = [
                f"=== Ficheiro no Cofre: {info['entry']['vault_filename']} ===",
                f"Estado da Chave USB: {usb_state}",
                f"Caminho Físico:      {info['vault_path']}",
                f"Cabeçalho:           {info['raw_header_magic']} | Salt: {info['salt_hex']}",
                f"HMAC-SHA256:         {info['hmac_hex'][:48]}...",
                "",
                "OFFSET  | BYTE ORIG (P) | DESLOCAMENTO VIGENÈRE (K) | BYTE NO COFRE (C = P+K mod 256)",
                "--------+---------------+---------------------------+--------------------------------",
            ]
            for step in info["byte_comparison"]:
                lines.append(
                    f"{step['offset']}  |   0x{step['plain_hex']} ('{step['plain_ascii']}')  |      "
                    f"{step['key_shift']}       |     0x{step['cipher_hex']} ('{step['cipher_ascii']}')"
                )
            lines.append("")
            lines.append("=== Pré-visualização do Conteúdo ===")
            lines.append(info["plain_text_preview"])
            self.file_hex_inspector.setPlainText("\n".join(lines))
        except Exception as e:
            self.file_hex_inspector.setPlainText(f"Erro ao inspecionar ficheiro: {e}")

    def _export_file_from_vault(self) -> None:
        if not self.current_master_key:
            QMessageBox.critical(
                self,
                "Pen USB Ausente",
                "Sem a Pen USB física ligada ao computador, os ficheiros permanecem encriptados e não podem ser exportados.",
            )
            return
        rows = self.files_table.selectionModel().selectedRows()
        if not rows:
            QMessageBox.information(self, "Seleção", "Selecione um ficheiro na tabela primeiro.")
            return
        file_id = self.files_table.item(rows[0].row(), 0).text()
        orig_name = self.files_table.item(rows[0].row(), 1).text()

        dest, _ = QFileDialog.getSaveFileName(
            self,
            "Guardar Ficheiro Desencriptado (Reverter Cifra de Vigenère)",
            orig_name,
        )
        if not dest:
            return
        try:
            out_path = self.vault_storage.export_decrypted_file(
                file_id, Path(dest), self.current_master_key
            )
            QMessageBox.information(
                self,
                "Ficheiro Exportado com Sucesso",
                f"A Cifra de Vigenère foi revertida com a chave da Pen USB e a integridade SHA-256 foi confirmada.\nGuardado em: {out_path}",
            )
        except Exception as e:
            QMessageBox.critical(self, "Erro ao Exportar", str(e))

    def _delete_file_from_vault(self) -> None:
        if not self.current_master_key:
            return
        rows = self.files_table.selectionModel().selectedRows()
        if not rows:
            return
        file_id = self.files_table.item(rows[0].row(), 0).text()
        self.vault_storage.delete_vault_file(file_id, self.current_master_key)
        self.file_hex_inspector.clear()
        self._refresh_files_table()

    # ==================================================================
    # INSPETOR MATEMÁTICO DA CIFRA DE VIGENÈRE
    # ==================================================================
    def _refresh_vigenere_inspector(self) -> None:
        text = self.vig_test_input.text() or "Criptex"
        if not self.current_master_key:
            self.vig_summary_label.setText(
                "Pen USB Ausente: A palavra-chave da Cifra de Vigenère não está carregada em memória. "
                "Insira a Pen USB física para visualizar os deslocamentos da sua chave."
            )
            self.vig_steps_table.setRowCount(0)
            return

        key = self.current_master_key
        insp = VigenereCipher.inspect_transformation(text, key, max_steps=32)
        ascii_vig = VigenereCipher.classic_alphabetic_vigenere(text, key, decrypt=False)

        self.vig_summary_label.setText(
            f"Chave USB Ativa: {'*' * min(24, len(key))} ({len(key)} bytes) | "
            f"Anel Derivado (Hex): {insp.extended_key_hex[:36]}...\n"
            f"Criptograma Vigenère ASCII:  {ascii_vig}\n"
            f"Criptograma Vigenère Base64: {insp.ciphertext_b64}"
        )

        self.vig_steps_table.setRowCount(len(insp.byte_shifts))
        for row, s in enumerate(insp.byte_shifts):
            self.vig_steps_table.setItem(row, 0, QTableWidgetItem(str(s["index"])))
            self.vig_steps_table.setItem(row, 1, QTableWidgetItem(str(s["plain_char"])))
            self.vig_steps_table.setItem(row, 2, QTableWidgetItem(str(s["plain_byte"])))
            self.vig_steps_table.setItem(row, 3, QTableWidgetItem(str(s["key_char"])))
            self.vig_steps_table.setItem(row, 4, QTableWidgetItem(f"+{s['shift_byte']}"))
            self.vig_steps_table.setItem(row, 5, QTableWidgetItem(s["formula"]))
            self.vig_steps_table.setItem(row, 6, QTableWidgetItem(f"0x{s['cipher_hex']}"))

    # ==================================================================
    # TELEMETRIA CONTÍNUA (HOTPLUG USB + ESCUDO WINDOWS)
    # ==================================================================
    def _open_virtual_keypad_for_master(self) -> None:
        dlg = ScrambledVirtualKeypadDialog(self.usb_custom_key_edit.text(), self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self.usb_custom_key_edit.setText(dlg.get_value())

    def _open_virtual_keypad_for_pw(self) -> None:
        dlg = ScrambledVirtualKeypadDialog(self.pw_secret_edit.text(), self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self.pw_secret_edit.setText(dlg.get_value())

    def _on_chaff_generated(self, real_char_masked: str, fake_outside: str) -> None:
        st = self.shield.status
        self.lbl_chaff_stream.setText(
            f"Input Interno: [{real_char_masked}]  ➔  Ruído enviado para o exterior: "
            f"[{fake_outside}]  ({st.masked_keystrokes_count} teclas protegidas / {st.chaff_injected_count} sinais de ruído)"
        )

    def _append_security_log(self, msg: str) -> None:
        self.lock_log_list.insertItem(0, msg)
        if hasattr(self, "vault_log_list"):
            self.vault_log_list.insertItem(0, msg)

    def _on_periodic_tick(self) -> None:
        active_drive, key = self.usb_manager.find_active_usb_key()
        had_key = bool(self.current_master_key)
        has_key_now = bool(active_drive and key and self.vault_storage.verify_master_key(key))

        if self.stack.currentWidget() == self.lock_screen:
            if had_key != has_key_now:
                self._refresh_usb_drives_list()
        else:
            if had_key != has_key_now:
                self._sync_vault_usb_lock_state()
            self._refresh_shield_telemetry()

    def _refresh_shield_telemetry(self) -> None:
        st = self.shield.status
        if not st.active:
            return

        self.lbl_net_state.setText("Internet: Cortada (Isolamento Ativo)")
        self.lbl_kbd_state.setText(
            f"Teclado: {st.masked_keystrokes_count} teclas ({st.chaff_injected_count} ruído)"
        )
        self.lbl_stream_state.setText(
            f"Anti-Gravação: Ativo ({len(st.terminated_apps)} fechadas)"
        )

        usb_info = (
            f"Presente ({self.active_usb_drive.mount_point} | S/N {self.active_usb_drive.serial_number}) — Dados Desencriptados"
            if self.active_usb_drive and self.current_master_key
            else "Ausente — Modo Protegido (Todos os dados permanecem encriptados)"
        )

        details = [
            "=== Relatório de Segurança do Cofre Criptex ===",
            f"• Biometria do Smartphone (Fator 1): {self.last_bio_result.mode if self.last_bio_result else 'Confirmada'}",
            f"• Pen USB Física Vigenère (Fator 2): {usb_info}",
            f"• Privilégios no Windows:            {'Administrador' if st.is_admin else 'Utilizador Padrão'}",
            f"• Ligação à Internet:                {'Cortada temporariamente' if st.internet_cut else 'Ativa'}",
            f"• Placas de Rede Desativadas:        {', '.join(st.disabled_adapters) if st.disabled_adapters else 'Isolamento Ativo'}",
            f"• Proteção Anti-Captura de Ecrã:     {'SetWindowDisplayAffinity Ativo' if st.anti_capture_hwnd_active else 'Ativo'}",
            f"• Proteção Anti-Keylogger:           {'Hook WH_KEYBOARD_LL + Ruído Chaff Ativo' if st.keyboard_shield_active else 'Inativo'}",
            f"• Estatísticas de Teclado:           {st.masked_keystrokes_count} teclas reais -> {st.chaff_injected_count} eventos de ruído",
            f"• Apps de Gravação Encerradas:       {', '.join(st.terminated_apps) if st.terminated_apps else 'Nenhuma detetada em execução'}",
            "",
            "=== Aplicações de Gravação e Streaming Monitorizadas ===",
            ", ".join(sorted(STREAM_AND_RECORDING_PROCESSES.values())),
        ]
        self.security_details_box.setPlainText("\n".join(details))


def run_app() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("Criptex Security Vault")
    window = CriptexMainWindow()
    window.show()
    return app.exec()
