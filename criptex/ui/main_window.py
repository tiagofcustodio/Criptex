# Criptex — Interface Gráfica Desktop Windows (PyQt6)
# Tema Liquid Frosted Glass & Mint Spotlight (Smoky Translucent Glassmorphism)
# Cofre Digital Altamente Fortificado com:
#   - Cifra de Vigenère (Passwords & Ficheiros)
#   - Palavra-Chave da Cifra guardada em Pen USB Física (.criptex_usb_key.crpxkey)
#   - Desbloqueio Biométrico do Smartphone (WebAuthn QR)
#   - Caso alguém consiga usar o smartphone roubado sem a Pen USB física no PC,
#     o Criptex abre mas TODOS OS DADOS PERMANECEM ENCRIPTADOS!
#   - Corte Momentâneo de Internet, Mascaramento de Teclado Anti-Keylogger e Exterminador de Apps de Stream/Gravação.

from __future__ import annotations

import ctypes
import io
import random
import string
import sys
import threading
import time
from pathlib import Path
from typing import Optional, List, Tuple

import qrcode
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QObject, QRectF, QPointF
from PyQt6.QtGui import (
    QImage,
    QPixmap,
    QKeyEvent,
    QPainter,
    QPainterPath,
    QColor,
    QLinearGradient,
    QRadialGradient,
    QPen,
    QFont,
    QPolygonF,
)
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

from criptex.biometrics.pc_biometrics import PcBiometricAuthenticator
from criptex.biometrics.webauthn_server import SmartphoneBiometricServer, BiometricAuthResult
from criptex.crypto.vigenere import VigenereCipher
from criptex.i18n import tr, get_detected_language_Summary
from criptex.security.fortress import FortressShield, STREAM_AND_RECORDING_PROCESSES
from criptex.security.usb_key import UsbKeyManager, UsbDriveInfo
from criptex.vault.storage import CriptexVaultStorage, PasswordEntry, VaultFileEntry


ENTERPRISE_SECURITY_QSS = """
QMainWindow, QDialog {
    background-color: #161311;
    color: #f4f1ee;
    font-family: "Segoe UI Variable Display", "Segoe UI", sans-serif;
}
QWidget {
    color: #f4f1ee;
    font-family: "Segoe UI Variable Display", "Segoe UI", sans-serif;
}
QFrame#TopHeaderBar {
    background-color: qlineargradient(
        x1:0, y1:0, x2:1, y2:0,
        stop:0 rgba(48, 42, 38, 0.72),
        stop:0.5 rgba(34, 30, 28, 0.66),
        stop:1 rgba(48, 42, 38, 0.72)
    );
    border-bottom: 1px solid rgba(255, 255, 255, 0.18);
}
QFrame#Card {
    background-color: qlineargradient(
        x1:0, y1:0, x2:0, y2:1,
        stop:0 rgba(56, 49, 45, 0.64),
        stop:0.5 rgba(36, 32, 30, 0.56),
        stop:1 rgba(26, 23, 22, 0.68)
    );
    border-top: 1px solid rgba(255, 255, 255, 0.28);
    border-left: 1px solid rgba(255, 255, 255, 0.18);
    border-right: 1px solid rgba(255, 255, 255, 0.14);
    border-bottom: 1px solid rgba(94, 252, 232, 0.20);
    border-radius: 22px;
}
QFrame#SubPanel {
    background-color: rgba(20, 18, 17, 0.52);
    border: 1px solid rgba(255, 255, 255, 0.15);
    border-left: 3px solid #5efce8;
    border-radius: 14px;
}
QFrame#ShieldBanner {
    background-color: qlineargradient(
        x1:0, y1:0, x2:1, y2:0,
        stop:0 rgba(46, 41, 38, 0.72),
        stop:0.5 rgba(32, 38, 37, 0.66),
        stop:1 rgba(44, 39, 36, 0.72)
    );
    border-top: 1px solid rgba(255, 255, 255, 0.26);
    border-bottom: 1px solid rgba(94, 252, 232, 0.32);
    border-left: 1px solid rgba(255, 255, 255, 0.20);
    border-right: 1px solid rgba(255, 255, 255, 0.20);
    border-radius: 22px;
}
QFrame#WarningCipherBanner {
    background-color: rgba(68, 22, 28, 0.68);
    border: 1px solid rgba(255, 123, 114, 0.45);
    border-left: 4px solid #ff7b72;
    border-radius: 18px;
}
QLabel#HeroTitle {
    font-size: 23px;
    font-weight: 700;
    color: #ffffff;
    letter-spacing: 0.9px;
}
QLabel#SectionTitle {
    font-size: 13px;
    font-weight: 700;
    color: #f3efeb;
    letter-spacing: 0.4px;
}
QLabel#Subtle {
    color: rgba(235, 228, 220, 0.72);
    font-size: 12px;
}
QLineEdit, QPlainTextEdit, QComboBox {
    background-color: rgba(18, 16, 15, 0.58);
    border: 1px solid rgba(255, 255, 255, 0.18);
    border-radius: 13px;
    padding: 8px 13px;
    color: #ffffff;
    font-size: 13px;
}
QLineEdit:focus, QPlainTextEdit:focus, QComboBox:focus {
    border: 1px solid #5efce8;
    background-color: rgba(14, 24, 23, 0.72);
}
QComboBox::drop-down {
    border-left: 1px solid rgba(255, 255, 255, 0.14);
    width: 26px;
}
QComboBox QAbstractItemView {
    background-color: #221e1c;
    border: 1px solid rgba(94, 252, 232, 0.35);
    selection-background-color: rgba(94, 252, 232, 0.22);
    selection-color: #5efce8;
    color: #f4f1ee;
}
QPushButton {
    background-color: qlineargradient(
        x1:0, y1:0, x2:0, y2:1,
        stop:0 rgba(255, 255, 255, 0.13),
        stop:1 rgba(255, 255, 255, 0.05)
    );
    border-top: 1px solid rgba(255, 255, 255, 0.28);
    border-left: 1px solid rgba(255, 255, 255, 0.18);
    border-right: 1px solid rgba(255, 255, 255, 0.18);
    border-bottom: 1px solid rgba(255, 255, 255, 0.12);
    border-radius: 15px;
    padding: 8px 16px;
    color: #f4f1ee;
    font-weight: 600;
    font-size: 12px;
}
QPushButton:hover {
    background-color: qlineargradient(
        x1:0, y1:0, x2:0, y2:1,
        stop:0 rgba(94, 252, 232, 0.24),
        stop:1 rgba(45, 212, 191, 0.10)
    );
    border: 1px solid #5efce8;
    color: #ffffff;
}
QPushButton:disabled {
    background-color: rgba(255, 255, 255, 0.04);
    color: rgba(255, 255, 255, 0.30);
    border: 1px solid rgba(255, 255, 255, 0.08);
}
QPushButton#PrimaryBtn {
    background-color: qlineargradient(
        x1:0, y1:0, x2:0, y2:1,
        stop:0 rgba(94, 252, 232, 0.36),
        stop:0.5 rgba(20, 184, 166, 0.28),
        stop:1 rgba(15, 118, 110, 0.44)
    );
    border-top: 1px solid #86ffef;
    border-left: 1px solid #5efce8;
    border-right: 1px solid #5efce8;
    border-bottom: 1px solid #2dd4bf;
    border-radius: 17px;
    color: #ffffff;
    font-weight: 700;
}
QPushButton#PrimaryBtn:hover {
    background-color: qlineargradient(
        x1:0, y1:0, x2:0, y2:1,
        stop:0 rgba(94, 252, 232, 0.50),
        stop:1 rgba(20, 184, 166, 0.38)
    );
    border: 1px solid #a7fff4;
}
QPushButton#PrimaryBtn:disabled {
    background-color: rgba(255, 255, 255, 0.05);
    border: 1px solid rgba(255, 255, 255, 0.10);
    color: rgba(255, 255, 255, 0.32);
}
QPushButton#SecondaryAccentBtn {
    background-color: rgba(94, 252, 232, 0.12);
    border: 1px solid rgba(94, 252, 232, 0.45);
    border-radius: 15px;
    color: #5efce8;
    font-weight: 600;
}
QPushButton#SecondaryAccentBtn:hover {
    background-color: rgba(94, 252, 232, 0.22);
}
QPushButton#DangerBtn {
    background-color: rgba(248, 81, 73, 0.14);
    border: 1px solid rgba(255, 123, 114, 0.45);
    border-radius: 15px;
    color: #ffa198;
    font-weight: 600;
}
QPushButton#DangerBtn:hover {
    background-color: rgba(218, 54, 51, 0.48);
    border: 1px solid #ff7b72;
    color: #ffffff;
}
QTabWidget::pane {
    border: 1px solid rgba(255, 255, 255, 0.20);
    background-color: rgba(30, 27, 25, 0.54);
    border-radius: 22px;
}
QTabBar::tab {
    background-color: rgba(42, 37, 34, 0.62);
    color: rgba(244, 241, 238, 0.68);
    padding: 10px 20px;
    margin-right: 6px;
    border: 1px solid rgba(255, 255, 255, 0.16);
    border-radius: 16px;
    font-weight: 600;
    font-size: 12px;
}
QTabBar::tab:selected {
    background-color: qlineargradient(
        x1:0, y1:0, x2:0, y2:1,
        stop:0 rgba(94, 252, 232, 0.34),
        stop:1 rgba(38, 34, 32, 0.72)
    );
    color: #ffffff;
    border-top: 2px solid #5efce8;
    border-bottom: 1px solid #5efce8;
}
QTableWidget {
    background-color: rgba(18, 16, 15, 0.52);
    border: 1px solid rgba(255, 255, 255, 0.16);
    border-radius: 16px;
    gridline-color: rgba(255, 255, 255, 0.08);
    selection-background-color: rgba(94, 252, 232, 0.20);
    selection-color: #5efce8;
    font-size: 12px;
}
QHeaderView::section {
    background-color: rgba(46, 40, 37, 0.72);
    color: rgba(244, 241, 238, 0.80);
    padding: 8px;
    border: none;
    border-right: 1px solid rgba(255, 255, 255, 0.08);
    border-bottom: 1px solid rgba(255, 255, 255, 0.18);
    font-weight: 600;
    font-size: 12px;
}
QListWidget {
    background-color: rgba(18, 16, 15, 0.52);
    border: 1px solid rgba(255, 255, 255, 0.16);
    border-radius: 16px;
    padding: 8px;
    font-family: "Consolas", monospace;
    font-size: 12px;
    color: #e8e2dc;
}
QCheckBox {
    font-size: 12px;
    color: #e8e2dc;
    spacing: 8px;
}
QCheckBox::indicator {
    width: 16px;
    height: 16px;
    border: 1px solid rgba(255, 255, 255, 0.28);
    border-radius: 5px;
    background-color: rgba(18, 16, 15, 0.60);
}
QCheckBox::indicator:checked {
    background-color: #2dd4bf;
    border: 1px solid #5efce8;
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


class GlassSpotlightNavBar(QWidget):
    """
    Barra de navegação flutuante em vidro fumado ('Smoky Liquid Glass') inspirada no design de referência:
      - Cápsula translúcida com borda especular de vidro ('specular rim light')
      - Feixe de luz cónico superior ('Mint-Cyan Spotlight Cone' #5efce8) sobre o separador ativo
      - Halo circular esmeralda-menta e contorno néon suave
    """

    tabSelected = pyqtSignal(int)

    def __init__(self, items: List[Tuple[str, str]], parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._items = items  # [(icon_kind, label), ...]
        self._active_index = 0
        self._hover_index = -1
        self.setFixedHeight(74)
        self.setMouseTracking(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

    def set_active_index(self, index: int) -> None:
        if 0 <= index < len(self._items) and index != self._active_index:
            self._active_index = index
            self.update()

    def _index_at_pos(self, x: float) -> int:
        w = max(1.0, float(self.width() - 32))
        rel_x = x - 16.0
        if rel_x < 0 or rel_x > w or not self._items:
            return -1
        slot_w = w / len(self._items)
        idx = int(rel_x // slot_w)
        return max(0, min(len(self._items) - 1, idx))

    def mouseMoveEvent(self, event) -> None:
        idx = self._index_at_pos(event.position().x())
        if idx != self._hover_index:
            self._hover_index = idx
            self.update()
        super().mouseMoveEvent(event)

    def leaveEvent(self, event) -> None:
        self._hover_index = -1
        self.update()
        super().leaveEvent(event)

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            idx = self._index_at_pos(event.position().x())
            if idx >= 0:
                self._active_index = idx
                self.tabSelected.emit(idx)
                self.update()
        super().mousePressEvent(event)

    def _draw_vector_icon(
        self, painter: QPainter, kind: str, cx: float, cy: float, color: QColor
    ) -> None:
        pen = QPen(color, 1.8, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin)
        painter.setPen(pen)
        painter.setBrush(Qt.BrushStyle.NoBrush)

        if kind == "passwords":
            # Ícone de Cadeado / Cofre
            body = QRectF(cx - 7.5, cy - 1.0, 15.0, 11.0)
            painter.drawRoundedRect(body, 3.0, 3.0)
            shackle = QPainterPath()
            shackle.moveTo(cx - 4.5, cy - 1.0)
            shackle.lineTo(cx - 4.5, cy - 4.5)
            shackle.arcTo(QRectF(cx - 4.5, cy - 9.0, 9.0, 9.0), 180, -180)
            shackle.lineTo(cx + 4.5, cy - 1.0)
            painter.drawPath(shackle)
            painter.drawEllipse(QPointF(cx, cy + 4.2), 1.3, 1.3)
        elif kind == "files":
            # Ícone de Pasta Cifrada
            path = QPainterPath()
            path.moveTo(cx - 8.5, cy - 5.5)
            path.lineTo(cx - 2.5, cy - 5.5)
            path.lineTo(cx - 0.5, cy - 3.0)
            path.lineTo(cx + 8.5, cy - 3.0)
            path.lineTo(cx + 8.5, cy + 7.5)
            path.lineTo(cx - 8.5, cy + 7.5)
            path.closeSubpath()
            painter.drawPath(path)
            painter.drawLine(QPointF(cx - 4.0, cy + 2.5), QPointF(cx + 4.0, cy + 2.5))
        elif kind == "matrix":
            # Ícone de Símbolo (+) / Matriz Vigenère em círculo luminoso
            painter.drawEllipse(QPointF(cx, cy + 1.0), 8.2, 8.2)
            painter.drawLine(QPointF(cx, cy - 3.2), QPointF(cx, cy + 5.2))
            painter.drawLine(QPointF(cx - 4.2, cy + 1.0), QPointF(cx + 4.2, cy + 1.0))
        elif kind == "shield":
            # Ícone de Escudo de Isolamento
            path = QPainterPath()
            path.moveTo(cx, cy - 7.5)
            path.lineTo(cx + 7.5, cy - 4.5)
            path.quadTo(cx + 7.5, cy + 4.0, cx, cy + 8.5)
            path.quadTo(cx - 7.5, cy + 4.0, cx - 7.5, cy - 4.5)
            path.closeSubpath()
            painter.drawPath(path)
        elif kind == "qr":
            # Ícone de Código QR
            painter.drawRect(QRectF(cx - 7.0, cy - 6.0, 5.2, 5.2))
            painter.drawRect(QRectF(cx + 1.8, cy - 6.0, 5.2, 5.2))
            painter.drawRect(QRectF(cx - 7.0, cy + 2.8, 5.2, 5.2))
            painter.drawPoint(QPointF(cx + 3.0, cy + 4.0))
            painter.drawRect(QRectF(cx + 3.2, cy + 4.2, 3.6, 3.6))
        elif kind == "fingerprint":
            # Ícone de Impressão Digital do PC
            arc1 = QPainterPath()
            arc1.arcMoveTo(QRectF(cx - 7.5, cy - 6.5, 15.0, 15.0), 30)
            arc1.arcTo(QRectF(cx - 7.5, cy - 6.5, 15.0, 15.0), 30, 120)
            painter.drawPath(arc1)
            arc2 = QPainterPath()
            arc2.arcMoveTo(QRectF(cx - 4.8, cy - 3.8, 9.6, 11.5), 15)
            arc2.arcTo(QRectF(cx - 4.8, cy - 3.8, 9.6, 11.5), 15, 150)
            painter.drawPath(arc2)
            painter.drawLine(QPointF(cx, cy - 1.2), QPointF(cx, cy + 7.0))
            painter.drawLine(QPointF(cx - 3.5, cy + 2.0), QPointF(cx - 3.5, cy + 6.8))
            painter.drawLine(QPointF(cx + 3.5, cy + 2.0), QPointF(cx + 3.5, cy + 6.8))
        else:
            # Ícone de Dispositivo / Utilizador Biométrico
            painter.drawEllipse(QPointF(cx, cy - 3.5), 3.6, 3.6)
            arc = QPainterPath()
            arc.moveTo(cx - 7.2, cy + 7.5)
            arc.quadTo(cx, cy + 1.2, cx + 7.2, cy + 7.5)
            painter.drawPath(arc)

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        rect = QRectF(14.0, 5.0, float(self.width() - 28), float(self.height() - 10))
        radius = rect.height() / 2.0

        # 1. Corpo da cápsula em vidro fumado ('Smoky Frosted Glass')
        pill_path = QPainterPath()
        pill_path.addRoundedRect(rect, radius, radius)

        bg_grad = QLinearGradient(rect.topLeft(), rect.bottomLeft())
        bg_grad.setColorAt(0.0, QColor(62, 54, 49, 198))
        bg_grad.setColorAt(0.48, QColor(38, 33, 30, 182))
        bg_grad.setColorAt(1.0, QColor(24, 21, 19, 212))
        painter.fillPath(pill_path, bg_grad)

        # Brilho especular superior interno ('Top Glass Specular Highlight')
        top_shine = QLinearGradient(rect.topLeft(), QPointF(rect.left(), rect.top() + 18.0))
        top_shine.setColorAt(0.0, QColor(255, 255, 255, 42))
        top_shine.setColorAt(1.0, QColor(255, 255, 255, 0))
        painter.save()
        painter.setClipPath(pill_path)
        painter.fillRect(QRectF(rect.left(), rect.top(), rect.width(), 18.0), top_shine)

        n = max(1, len(self._items))
        slot_w = rect.width() / n

        # 2. Feixe de Luz Cónico ('Mint-Cyan Spotlight Cone') + Halo sobre o item ativo
        active_cx = rect.left() + (self._active_index + 0.5) * slot_w
        cone_poly = QPolygonF(
            [
                QPointF(active_cx - 19.0, rect.top() + 1.0),
                QPointF(active_cx + 19.0, rect.top() + 1.0),
                QPointF(active_cx + slot_w * 0.42, rect.bottom() - 1.0),
                QPointF(active_cx - slot_w * 0.42, rect.bottom() - 1.0),
            ]
        )
        cone_grad = QLinearGradient(QPointF(active_cx, rect.top()), QPointF(active_cx, rect.bottom()))
        cone_grad.setColorAt(0.0, QColor(94, 252, 232, 92))
        cone_grad.setColorAt(0.55, QColor(45, 212, 191, 34))
        cone_grad.setColorAt(1.0, QColor(45, 212, 191, 0))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(cone_grad)
        painter.drawPolygon(cone_poly)

        # Halo circular esmeralda-menta atrás do ícone ativo
        orb_grad = QRadialGradient(QPointF(active_cx, rect.top() + 24.0), 26.0)
        orb_grad.setColorAt(0.0, QColor(94, 252, 232, 76))
        orb_grad.setColorAt(0.65, QColor(20, 184, 166, 26))
        orb_grad.setColorAt(1.0, QColor(20, 184, 166, 0))
        painter.setBrush(orb_grad)
        painter.drawEllipse(QPointF(active_cx, rect.top() + 24.0), 26.0, 26.0)

        # Emissor luminoso superior ('Mint Spotlight Emitter Bar')
        emitter_rect = QRectF(active_cx - 20.0, rect.top() + 0.5, 40.0, 3.6)
        painter.setBrush(QColor(94, 252, 232, 245))
        painter.drawRoundedRect(emitter_rect, 1.8, 1.8)

        # Contorno néon inferior sob o item ativo
        bottom_glow_rect = QRectF(active_cx - slot_w * 0.30, rect.bottom() - 2.6, slot_w * 0.60, 2.4)
        painter.setBrush(QColor(94, 252, 232, 215))
        painter.drawRoundedRect(bottom_glow_rect, 1.2, 1.2)
        painter.restore()

        # 3. Borda especular de vidro em redor da cápsula
        rim_grad = QLinearGradient(rect.topLeft(), rect.bottomRight())
        rim_grad.setColorAt(0.0, QColor(255, 255, 255, 95))
        rim_grad.setColorAt(0.5, QColor(255, 255, 255, 42))
        rim_grad.setColorAt(1.0, QColor(94, 252, 232, 88))
        painter.setPen(QPen(rim_grad, 1.3))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawPath(pill_path)

        # 4. Desenhar ícones e legendas de cada separador
        font = QFont("Segoe UI Variable Display", 9)
        for idx, (icon_kind, label) in enumerate(self._items):
            cx = rect.left() + (idx + 0.5) * slot_w
            icon_cy = rect.top() + 22.0
            is_active = idx == self._active_index
            is_hover = idx == self._hover_index

            if is_active:
                # Círculo de vidro esmeralda no ícone ativo
                painter.setPen(QPen(QColor(94, 252, 232, 185), 1.2))
                painter.setBrush(QColor(22, 66, 60, 145))
                painter.drawEllipse(QPointF(cx, icon_cy + 1.0), 14.5, 14.5)
                icon_color = QColor(255, 255, 255, 255)
                text_color = QColor(255, 255, 255, 255)
                font.setWeight(QFont.Weight.Bold)
            elif is_hover:
                painter.setPen(QPen(QColor(255, 255, 255, 60), 1.0))
                painter.setBrush(QColor(255, 255, 255, 22))
                painter.drawEllipse(QPointF(cx, icon_cy + 1.0), 13.5, 13.5)
                icon_color = QColor(94, 252, 232, 235)
                text_color = QColor(244, 241, 238, 235)
                font.setWeight(QFont.Weight.DemiBold)
            else:
                icon_color = QColor(240, 235, 230, 185)
                text_color = QColor(235, 228, 220, 175)
                font.setWeight(QFont.Weight.Medium)

            self._draw_vector_icon(painter, icon_kind, cx, icon_cy, icon_color)

            painter.setFont(font)
            painter.setPen(text_color)
            lbl_rect = QRectF(cx - slot_w * 0.48, rect.top() + 39.0, slot_w * 0.96, 20.0)
            painter.drawText(lbl_rect, int(Qt.AlignmentFlag.AlignCenter), label)


class PcFingerprintOrbWidget(QWidget):
    """
    Orbe de Leitura de Impressão Digital em Vidro Fumado & Luz Menta ('Liquid Glass Fingerprint Scanner Orb').
    Permite clicar diretamente no sensor para acionar o leitor biométrico do PC (Windows Hello / WinBio).
    """

    clicked = pyqtSignal()

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setFixedSize(184, 184)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._verified = False
        self._scanning = False

    def set_state(self, verified: bool = False, scanning: bool = False) -> None:
        self._verified = verified
        self._scanning = scanning
        self.update()

    def mousePressEvent(self, event) -> None:
        self.clicked.emit()
        super().mousePressEvent(event)

    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        cx = self.width() / 2.0
        cy = self.height() / 2.0

        # Halo exterior difuso
        accent = QColor(94, 252, 232) if not self._scanning else QColor(247, 208, 112)
        halo = QRadialGradient(QPointF(cx, cy), 88.0)
        halo.setColorAt(0.0, QColor(accent.red(), accent.green(), accent.blue(), 86 if self._verified else 54))
        halo.setColorAt(0.65, QColor(20, 184, 166, 22))
        halo.setColorAt(1.0, QColor(20, 184, 166, 0))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(halo)
        painter.drawEllipse(QPointF(cx, cy), 88.0, 88.0)

        # Círculo de vidro fumado ('Smoky Glass Sensor Pad')
        pad_grad = QLinearGradient(0.0, cy - 68.0, 0.0, cy + 68.0)
        pad_grad.setColorAt(0.0, QColor(58, 50, 46, 215))
        pad_grad.setColorAt(0.5, QColor(34, 30, 27, 198))
        pad_grad.setColorAt(1.0, QColor(20, 18, 17, 228))
        painter.setBrush(pad_grad)
        painter.setPen(QPen(QColor(accent.red(), accent.green(), accent.blue(), 195), 2.0))
        painter.drawEllipse(QPointF(cx, cy), 68.0, 68.0)

        # Anel concêntrico interior
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.setPen(QPen(QColor(255, 255, 255, 45), 1.1))
        painter.drawEllipse(QPointF(cx, cy), 56.0, 56.0)

        # Desenho vetorial das cristas de Impressão Digital
        pen = QPen(accent if (self._verified or self._scanning) else QColor(94, 252, 232, 230), 2.5)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(pen)

        for r_w, r_h, start_deg, span_deg in (
            (36.0, 42.0, 22, 136),
            (27.0, 33.0, 15, 150),
            (18.0, 24.0, 8, 164),
            (9.5, 14.5, 0, 180),
        ):
            arc = QPainterPath()
            rect = QRectF(cx - r_w, cy - r_h * 0.85, r_w * 2.0, r_h * 1.75)
            arc.arcMoveTo(rect, start_deg)
            arc.arcTo(rect, start_deg, span_deg)
            painter.drawPath(arc)

        # Linhas inferiores da impressão digital
        painter.drawLine(QPointF(cx, cy - 5.0), QPointF(cx, cy + 29.0))
        painter.drawLine(QPointF(cx - 9.5, cy + 2.0), QPointF(cx - 12.0, cy + 26.0))
        painter.drawLine(QPointF(cx + 9.5, cy + 2.0), QPointF(cx + 12.0, cy + 26.0))
        painter.drawLine(QPointF(cx - 18.5, cy + 7.0), QPointF(cx - 22.0, cy + 21.0))
        painter.drawLine(QPointF(cx + 18.5, cy + 7.0), QPointF(cx + 22.0, cy + 21.0))


class BridgeSignals(QObject):
    biometricVerified = pyqtSignal(object)
    pcBiometricFailed = pyqtSignal(str)
    qrUrlUpdated = pyqtSignal(str)
    logMessage = pyqtSignal(str)


class CriptexMainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Criptex")
        self.resize(1280, 840)
        self.setStyleSheet(ENTERPRISE_SECURITY_QSS)
        self._apply_windows_dwm_glass()

        self.signals = BridgeSignals()
        self.signals.biometricVerified.connect(self._on_biometric_verified_ui)
        self.signals.pcBiometricFailed.connect(self._on_pc_biometric_failed_ui)
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
        self.pc_bio_auth = PcBiometricAuthenticator(
            vault_storage=self.vault_storage,
            on_log=lambda msg: self.signals.logMessage.emit(msg),
        )

        self.current_master_key: Optional[str] = None
        self.active_usb_drive: Optional[UsbDriveInfo] = None
        self.biometric_unlocked: bool = False
        self.last_bio_result: Optional[BiometricAuthResult] = None
        self._detected_drives: List[UsbDriveInfo] = []
        self._pc_bio_scanning: bool = False

        # Contentor Principal com Barra Superior em Vidro Fumado
        master_widget = QWidget()
        master_layout = QVBoxLayout(master_widget)
        master_layout.setContentsMargins(0, 0, 0, 0)
        master_layout.setSpacing(0)

        top_bar = QFrame()
        top_bar.setObjectName("TopHeaderBar")
        top_bar.setFixedHeight(38)
        tb_layout = QHBoxLayout(top_bar)
        tb_layout.setContentsMargins(22, 0, 22, 0)

        lbl_brand = QLabel(
            f"{tr('Criptex Security Suite  •  Liquid Glass Edition')}   •   by Tiago Custodio   •   {tr('Idioma do Sistema')}: {get_detected_language_Summary()}"
        )
        lbl_brand.setStyleSheet("font-size: 12px; font-weight: 600; color: #f4f1ee; letter-spacing: 0.4px;")
        self.lbl_header_status = QLabel(tr("Estado: Aguardando Autenticação  •  Motor: Vigenère Mod-256 + HMAC-SHA256"))
        self.lbl_header_status.setStyleSheet("font-size: 12px; color: #5efce8;")
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

    def _apply_windows_dwm_glass(self) -> None:
        """Ativa barra de título escura imersiva e efeito Acrylic/Mica do Windows 11 DWM."""
        if sys.platform != "win32":
            return
        try:
            hwnd = int(self.winId())
            dwmapi = ctypes.windll.dwmapi
            dark_mode = ctypes.c_int(1)
            # DWMWA_USE_IMMERSIVE_DARK_MODE = 20
            dwmapi.DwmSetWindowAttribute(hwnd, 20, ctypes.byref(dark_mode), ctypes.sizeof(dark_mode))
            # DWMWA_SYSTEMBACKDROP_TYPE = 38 (3 = DWMSBT_TRANSIENTWINDOW Acrylic, 2 = Mica)
            backdrop_type = ctypes.c_int(3)
            dwmapi.DwmSetWindowAttribute(hwnd, 38, ctypes.byref(backdrop_type), ctypes.sizeof(backdrop_type))
        except Exception:
            pass

    def paintEvent(self, event) -> None:
        """
        Desenha o fundo arquitetónico difuso ('Warm Espresso & Mint Bokeh Backdrop')
        para que os cartões e cápsulas de vidro fumado translúcido tenham profundidade real.
        """
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        w = float(self.width())
        h = float(self.height())

        base_grad = QLinearGradient(0.0, 0.0, w, h)
        base_grad.setColorAt(0.0, QColor(20, 17, 15))
        base_grad.setColorAt(0.45, QColor(28, 23, 20))
        base_grad.setColorAt(1.0, QColor(15, 19, 19))
        painter.fillRect(self.rect(), base_grad)

        # Esfera difusa quente âmbar/madeira (como o ambiente da imagem de referência)
        warm_orb = QRadialGradient(QPointF(w * 0.22, h * 0.72), max(w, h) * 0.55)
        warm_orb.setColorAt(0.0, QColor(186, 138, 92, 64))
        warm_orb.setColorAt(0.5, QColor(122, 86, 56, 28))
        warm_orb.setColorAt(1.0, QColor(28, 23, 20, 0))
        painter.fillRect(self.rect(), warm_orb)

        # Esfera difusa esmeralda-menta superior ('Mint Spotlight Aura')
        mint_orb = QRadialGradient(QPointF(w * 0.52, h * 0.16), max(w, h) * 0.46)
        mint_orb.setColorAt(0.0, QColor(94, 252, 232, 48))
        mint_orb.setColorAt(0.5, QColor(20, 184, 166, 18))
        mint_orb.setColorAt(1.0, QColor(15, 19, 19, 0))
        painter.fillRect(self.rect(), mint_orb)

        # Luz ambiente suave no canto direito
        champagne_orb = QRadialGradient(QPointF(w * 0.84, h * 0.65), max(w, h) * 0.42)
        champagne_orb.setColorAt(0.0, QColor(214, 182, 142, 42))
        champagne_orb.setColorAt(1.0, QColor(20, 17, 15, 0))
        painter.fillRect(self.rect(), champagne_orb)

    # ==================================================================
    # ECRÃ 1: AUTENTICAÇÃO DUPLA (BIOMETRIA + PEN USB FÍSICA)
    # ==================================================================
    def _build_lock_screen(self) -> None:
        self.lock_screen = QWidget()
        root = QHBoxLayout(self.lock_screen)
        root.setContentsMargins(28, 24, 28, 24)
        root.setSpacing(22)

        # Painel Esquerdo: Fator 1 — Autenticação Biométrica (Escolha entre QR Code ou Impressão Digital do PC)
        qr_card = QFrame()
        qr_card.setObjectName("Card")
        qr_layout = QVBoxLayout(qr_card)
        qr_layout.setContentsMargins(24, 20, 24, 20)
        qr_layout.setSpacing(10)

        lbl_hero = QLabel(tr("Criptex Vault"))
        lbl_hero.setObjectName("HeroTitle")
        qr_layout.addWidget(lbl_hero)

        lbl_sec1 = QLabel(tr("1. Verificação Biométrica (Smartphone QR ou Impressão Digital do PC)"))
        lbl_sec1.setObjectName("SectionTitle")
        qr_layout.addWidget(lbl_sec1)

        # Seletor em Vidro Fumado & Spotlight: Smartphone QR vs Impressão Digital do PC
        self.bio_method_nav = GlassSpotlightNavBar(
            [
                ("qr", tr("Smartphone (Código QR)")),
                ("fingerprint", tr("Impressão Digital do PC")),
            ]
        )
        qr_layout.addWidget(self.bio_method_nav)

        self.bio_method_stack = QStackedWidget()

        # --- Página 0: Smartphone (Código QR) ---
        qr_page = QWidget()
        qr_page_layout = QVBoxLayout(qr_page)
        qr_page_layout.setContentsMargins(0, 4, 0, 0)
        qr_page_layout.setSpacing(8)

        lbl_sub = QLabel(
            tr(
                "Digitalize o código QR abaixo com o seu smartphone para validar a sua Impressão Digital "
                "ou FaceID (WebAuthn) na rede local."
            )
        )
        lbl_sub.setWordWrap(True)
        lbl_sub.setObjectName("Subtle")
        qr_page_layout.addWidget(lbl_sub)

        self.qr_image_label = QLabel()
        self.qr_image_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.qr_image_label.setFixedSize(210, 210)
        self.qr_image_label.setStyleSheet(
            "background-color: #ffffff; border: 2px solid rgba(94, 252, 232, 0.55); border-radius: 20px; padding: 8px;"
        )
        qr_center = QHBoxLayout()
        qr_center.addStretch()
        qr_center.addWidget(self.qr_image_label)
        qr_center.addStretch()
        qr_page_layout.addLayout(qr_center)

        self.qr_url_label = QLabel(tr("A iniciar servidor HTTPS local..."))
        self.qr_url_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.qr_url_label.setStyleSheet("font-family: Consolas, monospace; color: #5efce8; font-size: 11px;")
        self.qr_url_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        qr_page_layout.addWidget(self.qr_url_label)

        qr_btns = QHBoxLayout()
        btn_refresh_qr = QPushButton(tr("Gerar Novo QR Code"))
        btn_refresh_qr.clicked.connect(self._start_biometric_qr_session)
        btn_copy_qr_url = QPushButton(tr("Copiar Endereço HTTPS"))
        btn_copy_qr_url.clicked.connect(lambda: QApplication.clipboard().setText(self.bio_server.get_qr_url()))
        qr_btns.addWidget(btn_refresh_qr)
        qr_btns.addWidget(btn_copy_qr_url)
        qr_page_layout.addLayout(qr_btns)
        self.bio_method_stack.addWidget(qr_page)

        # --- Página 1: Impressão Digital do PC (Windows Hello / Sensor Biométrico) ---
        pc_page = QWidget()
        pc_page_layout = QVBoxLayout(pc_page)
        pc_page_layout.setContentsMargins(0, 4, 0, 0)
        pc_page_layout.setSpacing(10)

        lbl_pc_sub = QLabel(
            tr(
                "Utilize o leitor de Impressão Digital integrado no seu computador (Windows Hello / WinBio) "
                "para desbloquear o Criptex sem precisar do smartphone."
            )
        )
        lbl_pc_sub.setWordWrap(True)
        lbl_pc_sub.setObjectName("Subtle")
        pc_page_layout.addWidget(lbl_pc_sub)

        self.pc_fingerprint_orb = PcFingerprintOrbWidget()
        self.pc_fingerprint_orb.clicked.connect(self._trigger_pc_fingerprint_scan)
        orb_center = QHBoxLayout()
        orb_center.addStretch()
        orb_center.addWidget(self.pc_fingerprint_orb)
        orb_center.addStretch()
        pc_page_layout.addLayout(orb_center)

        avail, avail_desc = self.pc_bio_auth.check_sensor_status()
        self.pc_sensor_info_label = QLabel(f"{tr('Estado do Sensor Biométrico do PC:')}\n{avail_desc}")
        self.pc_sensor_info_label.setWordWrap(True)
        self.pc_sensor_info_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.pc_sensor_info_label.setStyleSheet(
            "font-family: Consolas, monospace; color: #5efce8; font-size: 11px;"
            if avail
            else "font-family: Consolas, monospace; color: #f7d070; font-size: 11px;"
        )
        pc_page_layout.addWidget(self.pc_sensor_info_label)

        self.btn_scan_pc_fingerprint = QPushButton(tr("Validar Impressão Digital no Computador"))
        self.btn_scan_pc_fingerprint.setObjectName("PrimaryBtn")
        self.btn_scan_pc_fingerprint.setFixedHeight(40)
        self.btn_scan_pc_fingerprint.clicked.connect(self._trigger_pc_fingerprint_scan)
        pc_page_layout.addWidget(self.btn_scan_pc_fingerprint)
        self.bio_method_stack.addWidget(pc_page)

        self.bio_method_nav.tabSelected.connect(self.bio_method_stack.setCurrentIndex)
        qr_layout.addWidget(self.bio_method_stack)

        self.bio_pairing_info_label = QLabel()
        self.bio_pairing_info_label.setWordWrap(True)
        self.bio_pairing_info_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.bio_pairing_info_label.setStyleSheet(
            "background-color: rgba(20, 18, 17, 0.58); border: 1px solid rgba(255, 255, 255, 0.16); "
            "border-radius: 14px; padding: 9px; color: rgba(244, 241, 238, 0.78); font-size: 11px;"
        )
        qr_layout.addWidget(self.bio_pairing_info_label)

        self.bio_status_badge = QLabel(tr("Aguardando leitura biométrica no smartphone..."))
        self.bio_status_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.bio_status_badge.setStyleSheet(
            "background-color: rgba(54, 42, 22, 0.62); border: 1px solid rgba(245, 194, 87, 0.48); "
            "border-radius: 14px; color: #f7d070; padding: 9px; font-size: 12px; font-weight: 600;"
        )
        qr_layout.addWidget(self.bio_status_badge)

        qr_layout.addStretch()
        root.addWidget(qr_card, 5)

        # Painel Direito: Fator 2 — Chave Física USB (Cifra de Vigenère)
        right_card = QFrame()
        right_card.setObjectName("Card")
        r_layout = QVBoxLayout(right_card)
        r_layout.setContentsMargins(24, 22, 24, 22)
        r_layout.setSpacing(12)

        lbl_usb_title = QLabel(tr("2. Chave da Cifra de Vigenère (Pen USB Física)"))
        lbl_usb_title.setObjectName("SectionTitle")
        r_layout.addWidget(lbl_usb_title)

        desc_usb = QLabel(
            tr(
                "A palavra-chave da Cifra de Vigenère é armazenada exclusivamente numa Pen USB física.\n"
                "• Com Biometria + Pen USB Física: O cofre abre e desencripta as passwords e ficheiros.\n"
                "• Sem Pen USB Física (ex: smartphone roubado): O Criptex abre, mas todos os dados permanecem encriptados."
            )
        )
        desc_usb.setWordWrap(True)
        desc_usb.setObjectName("Subtle")
        r_layout.addWidget(desc_usb)

        self.usb_status_badge = QLabel(tr("A verificar dispositivos USB ligados..."))
        self.usb_status_badge.setWordWrap(True)
        self.usb_status_badge.setStyleSheet(
            "background-color: #281216; border: 1px solid #da3633; border-radius: 5px; color: #ffa198; "
            "padding: 9px; font-size: 12px; font-weight: 600;"
        )
        r_layout.addWidget(self.usb_status_badge)

        usb_sel_row = QHBoxLayout()
        self.usb_combo = QComboBox()
        btn_scan_usb = QPushButton(tr("Atualizar Lista USB"))
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

        lbl_p = QLabel(tr("Configurar ou Gravar Chave Vigenère na Pen USB:"))
        lbl_p.setStyleSheet("font-weight: 600; color: #f0f6fc; font-size: 12px;")
        p_layout.addWidget(lbl_p)

        key_row = QHBoxLayout()
        self.usb_custom_key_edit = MaskedVaultLineEdit(
            self.shield,
            placeholder=tr("Palavra-chave personalizada (ou deixe em branco para gerar chave automática de 48 bytes)..."),
            secret_field=True,
        )
        btn_vk = QPushButton(tr("Teclado Virtual"))
        btn_vk.clicked.connect(self._open_virtual_keypad_for_master)
        key_row.addWidget(self.usb_custom_key_edit, 1)
        key_row.addWidget(btn_vk)
        p_layout.addLayout(key_row)

        prov_btns = QHBoxLayout()
        btn_provision_usb = QPushButton(tr("Gravar Chave na Pen USB Selecionada"))
        btn_provision_usb.clicked.connect(self._provision_selected_usb)
        prov_btns.addWidget(btn_provision_usb)
        p_layout.addLayout(prov_btns)

        r_layout.addWidget(prov_box)

        self.btn_enter_vault = QPushButton(tr("Aguardando Confirmação Biométrica..."))
        self.btn_enter_vault.setObjectName("PrimaryBtn")
        self.btn_enter_vault.setFixedHeight(42)
        self.btn_enter_vault.setEnabled(False)
        self.btn_enter_vault.clicked.connect(self._attempt_unlock_vault)
        r_layout.addWidget(self.btn_enter_vault)

        lbl_log = QLabel(tr("Registo de Eventos e Auditoria:"))
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

        self.lbl_shield_state = QLabel(tr("Proteção Ativa"))
        self.lbl_shield_state.setStyleSheet("font-weight: 700; color: #5efce8; font-size: 13px;")
        b_layout.addWidget(self.lbl_shield_state)

        self.lbl_usb_vault_state = QLabel(tr("Pen USB: A verificar..."))
        self.lbl_usb_vault_state.setStyleSheet(
            "background-color: rgba(18, 56, 48, 0.65); border: 1px solid #5efce8; border-radius: 12px; color: #5efce8; "
            "padding: 5px 12px; font-size: 12px; font-weight: 600;"
        )
        b_layout.addWidget(self.lbl_usb_vault_state)

        self.lbl_net_state = QLabel(tr("Internet: Cortada"))
        self.lbl_net_state.setStyleSheet(
            "background-color: rgba(68, 22, 28, 0.62); border: 1px solid rgba(255, 123, 114, 0.50); border-radius: 12px; color: #ffa198; "
            "padding: 5px 12px; font-size: 12px; font-weight: 600;"
        )
        b_layout.addWidget(self.lbl_net_state)

        self.lbl_kbd_state = QLabel(tr("Teclado: Mascarado"))
        self.lbl_kbd_state.setStyleSheet(
            "background-color: rgba(255, 255, 255, 0.08); border: 1px solid rgba(255, 255, 255, 0.22); border-radius: 12px; color: #f4f1ee; "
            "padding: 5px 12px; font-size: 12px; font-weight: 600;"
        )
        b_layout.addWidget(self.lbl_kbd_state)

        self.lbl_stream_state = QLabel(tr("Anti-Gravação: Ativo"))
        self.lbl_stream_state.setStyleSheet(
            "background-color: rgba(20, 62, 58, 0.58); border: 1px solid rgba(94, 252, 232, 0.45); border-radius: 12px; color: #5efce8; "
            "padding: 5px 12px; font-size: 12px; font-weight: 600;"
        )
        b_layout.addWidget(self.lbl_stream_state)

        b_layout.addStretch()

        btn_lock = QPushButton(tr("Trancar Cofre e Restaurar Internet"))
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
            tr(
                "Aviso de Segurança (Pen USB Ausente): O Criptex foi desbloqueado apenas com a biometria do smartphone, "
                "mas a Pen USB física com a palavra-chave da Cifra de Vigenère não se encontra ligada ao computador. "
                "Todos os dados (passwords e ficheiros) permanecem encriptados. Insira a Pen USB para desencriptar."
            )
        )
        self.lbl_no_usb_warning.setWordWrap(True)
        self.lbl_no_usb_warning.setStyleSheet("color: #ffa198; font-weight: 600; font-size: 12px;")
        w_layout.addWidget(self.lbl_no_usb_warning, 1)
        self.no_usb_warning_banner.setVisible(False)
        v_root.addWidget(self.no_usb_warning_banner)

        # Barra de Navegação Cápsula em Vidro Fumado com Spotlight ('Liquid Glass Nav Bar')
        self.glass_nav = GlassSpotlightNavBar(
            [
                ("passwords", tr("Passwords")),
                ("files", tr("Ficheiros (.crpx)")),
                ("matrix", tr("Matriz Vigenère")),
                ("shield", tr("Escudo & Sistema")),
                ("settings", tr("Dispositivos")),
            ]
        )
        v_root.addWidget(self.glass_nav)

        # Separadores do Cofre
        self.tabs = QTabWidget()
        self.tabs.tabBar().setVisible(False)
        self.tabs.addTab(self._build_passwords_tab(), tr("Passwords (Cifra de Vigenère)"))
        self.tabs.addTab(self._build_files_tab(), tr("Ficheiros Cifrados (.crpx)"))
        self.tabs.addTab(self._build_vigenere_inspector_tab(), tr("Inspetor da Cifra de Vigenère"))
        self.tabs.addTab(self._build_security_center_tab(), tr("Segurança & Monitorização"))
        self.tabs.addTab(self._build_settings_tab(), tr("Definições & Dispositivos"))
        self.glass_nav.tabSelected.connect(self.tabs.setCurrentIndex)
        self.tabs.currentChanged.connect(self.glass_nav.set_active_index)
        v_root.addWidget(self.tabs, 1)

        # Barra Inferior de Proteção de Teclado
        chaff_bar = QFrame()
        chaff_bar.setObjectName("Card")
        c_layout = QHBoxLayout(chaff_bar)
        c_layout.setContentsMargins(16, 8, 16, 8)
        lbl_c = QLabel(tr("Proteção Anti-Keylogger (Ruído externo gerado):"))
        lbl_c.setStyleSheet("color: rgba(244, 241, 238, 0.72); font-weight: 600; font-size: 12px;")
        self.lbl_chaff_stream = QLabel(tr("A aguardar digitação dentro do cofre..."))
        self.lbl_chaff_stream.setStyleSheet("font-family: Consolas, monospace; color: #5efce8; font-size: 12px;")
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
        self.lbl_pw_table_header = QLabel(tr("Passwords Guardadas (Encriptadas com Cifra de Vigenère)"))
        self.lbl_pw_table_header.setObjectName("SectionTitle")
        left.addWidget(self.lbl_pw_table_header)

        self.pw_table = QTableWidget(0, 5)
        self.pw_table.setHorizontalHeaderLabels(
            ["ID", tr("Serviço / Título"), tr("Utilizador"), tr("Password Cifrada (Vigenère)"), tr("Token Criptográfico")]
        )
        self.pw_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.pw_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.pw_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.pw_table.itemSelectionChanged.connect(self._on_password_selected)
        left.addWidget(self.pw_table, 1)

        btn_row = QHBoxLayout()
        self.btn_reveal_pw = QPushButton(tr("Desencriptar e Mostrar Password"))
        self.btn_reveal_pw.clicked.connect(self._reveal_selected_password)
        self.btn_inspect_pw = QPushButton(tr("Inspecionar na Matriz Vigenère"))
        self.btn_inspect_pw.clicked.connect(self._inspect_selected_password_in_matrix)
        self.btn_del_pw = QPushButton(tr("Eliminar Registo"))
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

        lbl_f = QLabel(tr("Adicionar Nova Password"))
        lbl_f.setObjectName("SectionTitle")
        f_layout.addWidget(lbl_f)

        self.pw_title_edit = MaskedVaultLineEdit(self.shield, tr("Ex: Banco, Email, Servidor"))
        self.pw_user_edit = MaskedVaultLineEdit(self.shield, tr("Utilizador ou Email"))
        self.pw_url_edit = MaskedVaultLineEdit(self.shield, tr("URL (ex: https://...)"))
        self.pw_secret_edit = MaskedVaultLineEdit(
            self.shield, tr("Password secreta (cifrada com a chave da Pen USB)"), secret_field=True
        )
        self.pw_notes_edit = MaskedVaultLineEdit(self.shield, tr("Notas adicionais"))

        for w in (
            self.pw_title_edit,
            self.pw_user_edit,
            self.pw_url_edit,
            self.pw_secret_edit,
            self.pw_notes_edit,
        ):
            w.chaffGenerated.connect(self._on_chaff_generated)

        self.pw_secret_edit.textChanged.connect(self._update_live_vigenere_pw_preview)

        f_layout.addWidget(QLabel(tr("Título / Serviço:")))
        f_layout.addWidget(self.pw_title_edit)
        f_layout.addWidget(QLabel(tr("Utilizador:")))
        f_layout.addWidget(self.pw_user_edit)
        f_layout.addWidget(QLabel(tr("URL / Endereço:")))
        f_layout.addWidget(self.pw_url_edit)
        f_layout.addWidget(QLabel(tr("Password (Input Protegido):")))

        sec_row = QHBoxLayout()
        sec_row.addWidget(self.pw_secret_edit, 1)
        btn_vk_pw = QPushButton(tr("Teclado"))
        btn_vk_pw.setToolTip(tr("Abrir Teclado Virtual Seguro"))
        btn_vk_pw.clicked.connect(self._open_virtual_keypad_for_pw)
        sec_row.addWidget(btn_vk_pw)
        f_layout.addLayout(sec_row)

        f_layout.addWidget(QLabel(tr("Pré-visualização da Cifra de Vigenère:")))
        self.lbl_live_vig_preview = QLabel(tr("A aguardar introdução..."))
        self.lbl_live_vig_preview.setWordWrap(True)
        self.lbl_live_vig_preview.setStyleSheet(
            "background-color: rgba(18, 16, 15, 0.58); border: 1px solid rgba(94, 252, 232, 0.35); border-radius: 13px; padding: 9px; "
            "font-family: Consolas, monospace; color: #5efce8; font-size: 11px;"
        )
        f_layout.addWidget(self.lbl_live_vig_preview)

        f_layout.addWidget(QLabel(tr("Notas:")))
        f_layout.addWidget(self.pw_notes_edit)

        self.btn_save_pw = QPushButton(tr("Cifrar com Chave USB e Guardar"))
        self.btn_save_pw.setObjectName("PrimaryBtn")
        self.btn_save_pw.clicked.connect(self._save_password_entry)
        f_layout.addWidget(self.btn_save_pw)

        self.lbl_revealed_box = QLabel(
            tr("Selecione um registo na tabela e clique em 'Desencriptar e Mostrar Password'.")
        )
        self.lbl_revealed_box.setWordWrap(True)
        self.lbl_revealed_box.setStyleSheet(
            "background-color: rgba(18, 16, 15, 0.58); border: 1px solid rgba(255, 255, 255, 0.18); border-left: 3px solid #5efce8; "
            "border-radius: 13px; padding: 10px; font-size: 12px; color: #f4f1ee;"
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
        lbl_f = QLabel(tr("Ficheiros Guardados no Cofre (Modificados ao Nível de Bytes com Vigenère)"))
        lbl_f.setObjectName("SectionTitle")
        left.addWidget(lbl_f)

        self.files_table = QTableWidget(0, 6)
        self.files_table.setHorizontalHeaderLabels(
            [
                "ID",
                tr("Nome do Ficheiro"),
                tr("Contentor (.crpx)"),
                tr("Tamanho (Bytes)"),
                tr("Amostra Hex Vigenère"),
                tr("Data"),
            ]
        )
        self.files_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.files_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.files_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.files_table.itemSelectionChanged.connect(self._on_vault_file_selected)
        left.addWidget(self.files_table, 1)

        self.chk_shred_source = QCheckBox(
            tr("Eliminar de forma segura (Shred) o ficheiro original fora do cofre após a importação")
        )
        left.addWidget(self.chk_shred_source)

        actions = QHBoxLayout()
        self.btn_import_file = QPushButton(tr("Importar e Cifrar Ficheiro"))
        self.btn_import_file.setObjectName("PrimaryBtn")
        self.btn_import_file.clicked.connect(self._import_file_to_vault)

        self.btn_export_file = QPushButton(tr("Desencriptar e Exportar Ficheiro"))
        self.btn_export_file.clicked.connect(self._export_file_from_vault)

        self.btn_del_file = QPushButton(tr("Eliminar do Cofre"))
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

        lbl_i = QLabel(tr("Inspeção Binária do Ficheiro no Cofre"))
        lbl_i.setObjectName("SectionTitle")
        i_layout.addWidget(lbl_i)

        lbl_sub = QLabel(
            tr(
                "Compara os bytes originais com os bytes cifrados pela Cifra de Vigenère dentro do cofre. "
                "Sem a Pen USB inserida, apenas os bytes encriptados são visíveis."
            )
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

        lbl = QLabel(tr("Verificador da Cifra de Vigenère (Mod 256 & ASCII)"))
        lbl.setObjectName("SectionTitle")
        layout.addWidget(lbl)

        top_row = QHBoxLayout()
        self.vig_test_input = MaskedVaultLineEdit(
            self.shield, tr("Introduza um texto ou password para analisar os deslocamentos da cifra...")
        )
        self.vig_test_input.chaffGenerated.connect(self._on_chaff_generated)
        self.vig_test_input.setText("SegredoConfidencial2026!")
        btn_calc = QPushButton(tr("Calcular Transformação"))
        btn_calc.setObjectName("PrimaryBtn")
        btn_calc.clicked.connect(self._refresh_vigenere_inspector)
        top_row.addWidget(self.vig_test_input, 1)
        top_row.addWidget(btn_calc)
        layout.addLayout(top_row)

        self.vig_summary_label = QLabel()
        self.vig_summary_label.setWordWrap(True)
        self.vig_summary_label.setStyleSheet(
            "background-color: rgba(20, 18, 17, 0.58); border: 1px solid rgba(94, 252, 232, 0.35); border-left: 3px solid #5efce8; "
            "border-radius: 14px; padding: 10px; font-family: Consolas, monospace; color: #5efce8; font-size: 12px;"
        )
        layout.addWidget(self.vig_summary_label)

        self.vig_steps_table = QTableWidget(0, 7)
        self.vig_steps_table.setHorizontalHeaderLabels(
            [
                tr("Índice (i)"),
                tr("Carácter Original"),
                tr("Byte P[i]"),
                tr("Carácter da Chave USB"),
                tr("Deslocamento K[i]"),
                tr("Fórmula Vigenère (Mod 256)"),
                tr("Byte Cifrado C[i]"),
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

        lbl_s = QLabel(tr("Estado das Proteções do Sistema e Chave USB"))
        lbl_s.setObjectName("SectionTitle")
        l_layout.addWidget(lbl_s)

        self.security_details_box = QPlainTextEdit()
        self.security_details_box.setReadOnly(True)
        self.security_details_box.setStyleSheet("font-family: Consolas, monospace; font-size: 12px; color: #c9d1d9;")
        l_layout.addWidget(self.security_details_box, 1)

        btn_force_scan = QPushButton(tr("Verificar e Fechar Aplicações de Gravação / Stream Agora"))
        btn_force_scan.setObjectName("PrimaryBtn")
        btn_force_scan.clicked.connect(
            lambda: threading.Thread(
                target=self.shield.scan_and_kill_streaming_apps,
                name="CriptexManualStreamScan",
                daemon=True,
            ).start()
        )
        l_layout.addWidget(btn_force_scan)

        layout.addWidget(left_card, 5)

        right_card = QFrame()
        right_card.setObjectName("Card")
        r_layout = QVBoxLayout(right_card)

        lbl_ev = QLabel(tr("Registo de Auditoria de Segurança"))
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

        lbl_title = QLabel(tr("Dispositivo Biométrico Registado (Smartphone Vinculado)"))
        lbl_title.setObjectName("SectionTitle")
        b_layout.addWidget(lbl_title)

        lbl_desc = QLabel(
            "Após o primeiro uso do código QR ou da Impressão Digital do PC, "
            "esse método biométrico fica vinculado ao cofre.\n\n"
            "Para alterar ou substituir o registo biométrico, é obrigatória a presença simultânea de:\n"
            "1. O desbloqueio biométrico original na sessão atual;\n"
            "2. A Pen USB física com a palavra-chave da Cifra de Vigenère inserida no computador."
        )
        lbl_desc.setWordWrap(True)
        lbl_desc.setObjectName("Subtle")
        b_layout.addWidget(lbl_desc)

        self.settings_bio_info_box = QLabel()
        self.settings_bio_info_box.setWordWrap(True)
        self.settings_bio_info_box.setStyleSheet(
            "background-color: rgba(18, 16, 15, 0.58); border: 1px solid rgba(255, 255, 255, 0.18); border-left: 3px solid #5efce8; "
            "border-radius: 14px; padding: 12px; font-family: Consolas, monospace; font-size: 12px; color: #f4f1ee;"
        )
        b_layout.addWidget(self.settings_bio_info_box)

        self.settings_auth_reqs_badge = QLabel()
        self.settings_auth_reqs_badge.setWordWrap(True)
        b_layout.addWidget(self.settings_auth_reqs_badge)

        self.btn_reset_bio_device = QPushButton(
            tr("Desvincular Smartphone Atual e Autorizar Novo Registo Biométrico via QR")
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

        lbl_u_title = QLabel(tr("Chave Física USB & Política de Acesso"))
        lbl_u_title.setObjectName("SectionTitle")
        u_layout.addWidget(lbl_u_title)

        self.settings_usb_info_box = QLabel()
        self.settings_usb_info_box.setWordWrap(True)
        self.settings_usb_info_box.setStyleSheet(
            "background-color: rgba(18, 16, 15, 0.58); border: 1px solid rgba(255, 255, 255, 0.18); border-radius: 14px; "
            "padding: 12px; font-family: Consolas, monospace; font-size: 12px; color: #f4f1ee;"
        )
        u_layout.addWidget(self.settings_usb_info_box)

        lbl_policy = QLabel(
            "Política de Segurança Criptex:\n"
            "• Escolha Biométrica: Pode desbloquear o cofre através da Impressão Digital do PC (Windows Hello / WinBio) ou do Smartphone (Código QR).\n"
            "• 1º Uso Biométrico: Regista automaticamente o dispositivo que efetuar o primeiro desbloqueio biométrico.\n"
            "• Proteção contra Roubo: Se o desbloqueio biométrico for efetuado sem a Pen USB física no PC, o cofre abre em modo restrito (todos os dados encriptados)."
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
                "background-color: rgba(18, 56, 48, 0.65); border: 1px solid #5efce8; border-radius: 14px; color: #5efce8; "
                "padding: 9px; font-size: 12px; font-weight: 600;"
            )
        else:
            self.active_usb_drive = None
            self.current_master_key = None
            if self._detected_drives:
                self.usb_status_badge.setText(
                    tr("Pen USB detetada, mas sem ficheiro de chave (.criptex_usb_key.crpxkey). Clique em 'Gravar Chave na Pen USB Selecionada'.")
                )
            else:
                self.usb_status_badge.setText(
                    tr("Nenhuma Pen USB com chave detetada: Se abrir o Criptex apenas com o smartphone, todos os dados permanecerão encriptados.")
                )
            self.usb_status_badge.setStyleSheet(
                "background-color: rgba(68, 22, 28, 0.62); border: 1px solid rgba(255, 123, 114, 0.50); border-radius: 14px; color: #ffa198; "
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
    # LÓGICA DE AUTENTICAÇÃO BIOMÉTRICA (QR CODE + IMPRESSÃO DIGITAL PC)
    # ==================================================================
    def _trigger_pc_fingerprint_scan(self) -> None:
        """
        Inicia a leitura da Impressão Digital / Biometria do próprio computador
        (Windows Hello / Windows Biometric Framework) numa thread em segundo plano.
        """
        if self._pc_bio_scanning:
            return
        self._pc_bio_scanning = True
        self.pc_fingerprint_orb.set_state(verified=False, scanning=True)
        self.btn_scan_pc_fingerprint.setEnabled(False)
        self.btn_scan_pc_fingerprint.setText(tr("A aguardar leitura da Impressão Digital no sensor do PC..."))
        self.bio_status_badge.setText(tr("A aguardar leitura da Impressão Digital no sensor do PC..."))
        self.bio_status_badge.setStyleSheet(
            "background-color: rgba(54, 42, 22, 0.62); border: 1px solid rgba(245, 194, 87, 0.48); border-radius: 14px; color: #f7d070; "
            "padding: 9px; font-size: 12px; font-weight: 600;"
        )

        hwnd = int(self.winId())

        def _worker() -> None:
            ok, msg, result = self.pc_bio_auth.authenticate(hwnd=hwnd)
            if ok and result is not None:
                self.signals.biometricVerified.emit(result)
            else:
                self.signals.pcBiometricFailed.emit(
                    msg or tr("Leitura biométrica cancelada ou não concluída no computador. Tente novamente ou use o Código QR.")
                )

        threading.Thread(target=_worker, daemon=True, name="CriptexPcBioWorker").start()

    def _on_pc_biometric_failed_ui(self, err_msg: str) -> None:
        self._pc_bio_scanning = False
        self.pc_fingerprint_orb.set_state(verified=False, scanning=False)
        self.btn_scan_pc_fingerprint.setEnabled(True)
        self.btn_scan_pc_fingerprint.setText(tr("Validar Impressão Digital no Computador"))
        self.bio_status_badge.setText(err_msg)
        self.bio_status_badge.setStyleSheet(
            "background-color: rgba(68, 22, 28, 0.62); border: 1px solid rgba(255, 123, 114, 0.50); border-radius: 14px; color: #ffa198; "
            "padding: 9px; font-size: 12px; font-weight: 600;"
        )

    def _refresh_bio_pairing_banner_on_lock_screen(self) -> None:
        bio_info = self.vault_storage.get_biometric_device_info()
        if bio_info.get("paired"):
            dev_name = bio_info.get("device_name") or "Dispositivo Registado"
            cred_id = bio_info.get("credential_id") or "-"
            paired_at = bio_info.get("paired_at") or "-"
            self.bio_pairing_info_label.setText(
                f"Dispositivo Vinculado: {dev_name} (ID: {cred_id[:18]} | Registado: {paired_at})\n"
                f"Apenas este dispositivo biométrico pode desbloquear o Criptex. Alteração disponível apenas nas Definições dentro do cofre."
            )
            self.bio_pairing_info_label.setStyleSheet(
                "background-color: rgba(18, 56, 48, 0.55); border: 1px solid rgba(94, 252, 232, 0.48); border-radius: 14px; padding: 9px; "
                "color: #5efce8; font-size: 11px; font-weight: 600;"
            )
        else:
            self.bio_pairing_info_label.setText(
                tr(
                    "1º Uso (Modo de Registo Inicial): Nenhum smartphone vinculado ainda.\n"
                    "O primeiro telemóvel a ler o QR Code e concluir o desbloqueio biométrico ficará registado neste cofre."
                )
            )
            self.bio_pairing_info_label.setStyleSheet(
                "background-color: rgba(20, 18, 17, 0.58); border: 1px solid rgba(255, 255, 255, 0.16); border-radius: 14px; padding: 9px; "
                "color: rgba(244, 241, 238, 0.78); font-size: 11px;"
            )

    def _start_biometric_qr_session(self) -> None:
        self.biometric_unlocked = False
        self._pc_bio_scanning = False
        if hasattr(self, "pc_fingerprint_orb"):
            self.pc_fingerprint_orb.set_state(verified=False, scanning=False)
            self.btn_scan_pc_fingerprint.setEnabled(True)
            self.btn_scan_pc_fingerprint.setText(tr("Validar Impressão Digital no Computador"))
        self._update_unlock_button_text()
        self._refresh_bio_pairing_banner_on_lock_screen()
        self.bio_status_badge.setText(tr("Aguardando leitura biométrica no smartphone..."))
        self.bio_status_badge.setStyleSheet(
            "background-color: rgba(54, 42, 22, 0.62); border: 1px solid rgba(245, 194, 87, 0.48); border-radius: 14px; color: #f7d070; "
            "padding: 9px; font-size: 12px; font-weight: 600;"
        )

        def _start_server_bg() -> None:
            try:
                url = self.bio_server.start()
                if url:
                    self.signals.qrUrlUpdated.emit(url)
            except Exception as e:
                self.signals.logMessage.emit(f"Aviso ao iniciar servidor QR: {e}")

        threading.Thread(target=_start_server_bg, name="CriptexQrStartWorker", daemon=True).start()

    def _render_qr_code_url(self, url: str) -> None:
        if not url:
            return
        self.qr_url_label.setText(url)

        qr = qrcode.QRCode(version=1, box_size=8, border=2)
        qr.add_data(url)
        qr.make(fit=True)
        pil_img = qr.make_image(fill_color="#161311", back_color="#ffffff")
        buf = io.BytesIO()
        pil_img.save(buf, format="PNG")
        qimg = QImage.fromData(buf.getvalue(), "PNG")
        pix = QPixmap.fromImage(qimg).scaled(
            194,
            194,
            Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation,
        )
        self.qr_image_label.setPixmap(pix)

    def _on_biometric_verified_ui(self, result: BiometricAuthResult) -> None:
        self._pc_bio_scanning = False
        self.biometric_unlocked = True
        self.last_bio_result = result
        if hasattr(self, "pc_fingerprint_orb"):
            self.pc_fingerprint_orb.set_state(verified=True, scanning=False)
            self.btn_scan_pc_fingerprint.setEnabled(True)
            self.btn_scan_pc_fingerprint.setText(tr("Validar Impressão Digital no Computador"))
        self._refresh_bio_pairing_banner_on_lock_screen()
        self.bio_status_badge.setText(
            f"Biometria Confirmada às {result.timestamp} ({result.mode})"
        )
        self.bio_status_badge.setStyleSheet(
            "background-color: rgba(18, 56, 48, 0.68); border: 1px solid #5efce8; border-radius: 14px; color: #5efce8; "
            "padding: 9px; font-size: 12px; font-weight: 600;"
        )
        self._update_unlock_button_text()
        self._append_security_log(f"Autenticação biométrica validada ({result.device_info}).")

    def _update_unlock_button_text(self) -> None:
        if not self.biometric_unlocked:
            self.btn_enter_vault.setEnabled(False)
            self.btn_enter_vault.setText(tr("Aguardando Confirmação Biométrica..."))
            return

        self.btn_enter_vault.setEnabled(True)
        if self.active_usb_drive and self.current_master_key:
            self.btn_enter_vault.setText(
                f"Abrir Cofre Criptex (Biometria + Pen USB {self.active_usb_drive.mount_point} Verificadas)"
            )
        else:
            self.btn_enter_vault.setText(
                tr("Abrir Cofre Sem Pen USB (Modo Protegido — Dados Permanecerão Encriptados)")
            )

    # ==================================================================
    # ENTRADA E SAÍDA DO COFRE + SINCRONIZAÇÃO COM PEN USB
    # ==================================================================
    def _attempt_unlock_vault(self) -> None:
        if not self.biometric_unlocked:
            QMessageBox.warning(
                self,
                tr("Biometria Obrigatória"),
                tr("O cofre Criptex requer a validação biométrica do smartphone antes de abrir."),
            )
            return

        # Mudar imediatamente para o ecrã do cofre sem bloquear a thread gráfica
        self.stack.setCurrentWidget(self.vault_screen)
        self.bio_server.stop()

        hwnd = int(self.winId())
        self.shield.engage_fortress(hwnd=hwnd, async_mode=True)

        self._refresh_usb_drives_list()
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
                "background-color: rgba(18, 56, 48, 0.65); border: 1px solid #5efce8; border-radius: 12px; color: #5efce8; "
                "padding: 5px 12px; font-size: 12px; font-weight: 600;"
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
                "background-color: rgba(68, 22, 28, 0.62); border: 1px solid rgba(255, 123, 114, 0.50); border-radius: 12px; color: #ffa198; "
                "padding: 5px 12px; font-size: 12px; font-weight: 600;"
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
        self.stack.setCurrentWidget(self.lock_screen)
        self.shield.disengage_fortress(async_mode=True)
        self.current_master_key = None
        self.pw_table.setRowCount(0)
        self.files_table.setRowCount(0)
        self.file_hex_inspector.clear()
        self.lbl_header_status.setText(tr("Estado: Aguardando Autenticação  •  Motor: Vigenère Mod-256 + HMAC-SHA256"))

        self._start_biometric_qr_session()
        self._refresh_usb_drives_list()

    def closeEvent(self, event) -> None:
        try:
            if hasattr(self, "telemetry_timer"):
                self.telemetry_timer.stop()
            self.bio_server.stop()
            self.shield.disengage_fortress(async_mode=True)
        except Exception:
            pass
        event.accept()

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
    app.setOrganizationName("Tiago Custodio")
    window = CriptexMainWindow()
    window.show()
    return app.exec()
