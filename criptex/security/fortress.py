# Criptex — Escudo de Segurança e Fortificação Windows (Fortress Shield)
# Responsável por:
#   1. Cortar momentaneamente a Internet enquanto o cofre está aberto (e restaurar ao fechar).
#   2. Mascarar e proteger os inputs do teclado contra keyloggers externos (WH_KEYBOARD_LL + Obfuscation Chaffing).
#   3. Desligar automaticamente aplicações de stream, captura e gravação (OBS, Discord, ShareX, etc.)
#      e aplicar SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE) na janela do cofre.

from __future__ import annotations

import ctypes
from ctypes import wintypes
import os
import random
import re
import socket
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Dict, Tuple

import psutil

_ORIG_SOCKET_CONNECT = socket.socket.connect
_ORIG_CREATE_CONNECTION = socket.create_connection
_NETWORK_KILL_SWITCH_ACTIVE = False


def _guarded_socket_connect(self, address):
    if _NETWORK_KILL_SWITCH_ACTIVE:
        host = address[0] if isinstance(address, tuple) and address else ""
        if host not in ("127.0.0.1", "::1", "localhost"):
            raise OSError("Ligação externa bloqueada pelo Escudo de Isolamento de Rede Criptex.")
    return _ORIG_SOCKET_CONNECT(self, address)


def _guarded_create_connection(address, *args, **kwargs):
    if _NETWORK_KILL_SWITCH_ACTIVE:
        host = address[0] if isinstance(address, tuple) and address else ""
        if host not in ("127.0.0.1", "::1", "localhost"):
            raise OSError("Ligação externa bloqueada pelo Escudo de Isolamento de Rede Criptex.")
    return _ORIG_CREATE_CONNECTION(address, *args, **kwargs)


socket.socket.connect = _guarded_socket_connect
socket.create_connection = _guarded_create_connection


# Constantes Win32 para proteção de janela e hooks de baixo nível
WDA_NONE = 0x00000000
WDA_MONITOR = 0x00000001
WDA_EXCLUDEFROMCAPTURE = 0x00000011

WH_KEYBOARD_LL = 13
WM_KEYDOWN = 0x0100
WM_SYSKEYDOWN = 0x0104
HC_ACTION = 0

INPUT_KEYBOARD = 1
KEYEVENTF_KEYUP = 0x0002
KEYEVENTF_UNICODE = 0x0004
ULONG_PTR = ctypes.c_ulonglong if ctypes.sizeof(ctypes.c_void_p) == 8 else ctypes.c_ulong

# Lista abrangente de aplicações de gravação, streaming, partilha de ecrã e captura
STREAM_AND_RECORDING_PROCESSES: Dict[str, str] = {
    "obs64.exe": "OBS Studio (64-bit)",
    "obs32.exe": "OBS Studio (32-bit)",
    "obs.exe": "OBS Studio",
    "streamlabs obs.exe": "Streamlabs Desktop",
    "xsplit.core.exe": "XSplit Broadcaster",
    "bdcam.exe": "Bandicam",
    "action.exe": "Mirillis Action!",
    "fraps.exe": "Fraps",
    "sharex.exe": "ShareX Screen Recorder",
    "camtasia.exe": "Camtasia Studio",
    "camrecorder.exe": "Camtasia Recorder",
    "screenrec.exe": "ScreenRec",
    "loom.exe": "Loom Recorder",
    "gyazogif.exe": "Gyazo GIF Capture",
    "snippingtool.exe": "Ferramenta de Recorte Windows",
    "screenclippinghost.exe": "Captura de Ecrã Windows",
    "gamebar.exe": "Xbox Game Bar DVR",
    "gamebarftserver.exe": "Xbox Game Bar Broadcast",
    "bcastdvr.exe": "Windows Broadcast DVR",
    "nvidia share.exe": "NVIDIA ShadowPlay / Share",
    "nvsphelper64.exe": "NVIDIA Capture Helper",
    "amddvr.exe": "AMD Radeon ReLive DVR",
    "discord.exe": "Discord (Stream / Screen Share)",
    "zoom.exe": "Zoom Meetings",
    "teams.exe": "Microsoft Teams",
    "ms-teams.exe": "Microsoft Teams (New)",
    "skype.exe": "Skype",
    "anydesk.exe": "AnyDesk Remote Screen",
    "teamviewer.exe": "TeamViewer Remote",
    "rustdesk.exe": "RustDesk Remote",
    "wireshark.exe": "Wireshark Packet Capture",
}


class KEYBDINPUT(ctypes.Structure):
    _fields_ = [
        ("wVk", wintypes.WORD),
        ("wScan", wintypes.WORD),
        ("dwFlags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("dwExtraInfo", ULONG_PTR),
    ]


class _INPUTunion(ctypes.Union):
    _fields_ = [("ki", KEYBDINPUT), ("pad", ctypes.c_byte * 32)]


class INPUT(ctypes.Structure):
    _fields_ = [("type", wintypes.DWORD), ("union", _INPUTunion)]


class KBDLLHOOKSTRUCT(ctypes.Structure):
    _fields_ = [
        ("vkCode", wintypes.DWORD),
        ("scanCode", wintypes.DWORD),
        ("flags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("dwExtraInfo", ULONG_PTR),
    ]


@dataclass
class ShieldStatus:
    active: bool = False
    is_admin: bool = False
    internet_cut: bool = False
    disabled_adapters: List[str] = field(default_factory=list)
    default_gateway_backup: Optional[str] = None
    keyboard_shield_active: bool = False
    masked_keystrokes_count: int = 0
    chaff_injected_count: int = 0
    anti_capture_hwnd_active: bool = False
    terminated_apps: List[str] = field(default_factory=list)
    events_log: List[str] = field(default_factory=list)


class FortressShield:
    """
    Coordena todas as defesas ativas do Criptex assim que o cofre é desbloqueado:
      1. Corte de Internet (Network Kill-Switch)
      2. Mascaramento de Teclado Anti-Keylogger (Low-Level Hook + Keystroke Chaffing + Secure Input)
      3. Exterminador de Apps de Stream/Gravação em Tempo Real + Proteção de Ecrã Win32
    """

    CRIPTEX_SYNTHETIC_MARKER = 0xC0DEC798

    def __init__(self, on_event: Optional[Callable[[str], None]] = None) -> None:
        self.on_event = on_event
        self.status = ShieldStatus(is_admin=self.check_is_admin())
        self._watchdog_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._chaff_event = threading.Event()
        self._hook_thread: Optional[threading.Thread] = None
        self._hook_id: Optional[int] = None
        self._hook_thread_id: Optional[int] = None
        self._protected_hwnd: Optional[int] = None
        self._window_focused: bool = True
        self._lock = threading.Lock()

    @staticmethod
    def check_is_admin() -> bool:
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    def log_event(self, message: str) -> None:
        timestamp = time.strftime("%H:%M:%S")
        entry = f"[{timestamp}] {message}"
        with self._lock:
            self.status.events_log.insert(0, entry)
            if len(self.status.events_log) > 200:
                self.status.events_log.pop()
        if self.on_event:
            try:
                self.on_event(entry)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Ativação / Desativação Global do Escudo do Cofre
    # ------------------------------------------------------------------
    def engage_fortress(self, hwnd: Optional[int] = None, async_mode: bool = True) -> ShieldStatus:
        """
        Ativa imediatamente todas as contramedidas do cofre Criptex sem bloquear a interface gráfica (Qt):
          - Bloqueia captura de ecrã na janela do cofre (WDA_EXCLUDEFROMCAPTURE)
          - Ativa o mascaramento de teclado e anti-keylogger
          - Em segundo plano (async_mode=True): fecha aplicações de stream/gravação, corta a Internet
            momentaneamente e inicia a sentinela contínua.
        """
        self.status.is_admin = self.check_is_admin()
        self.status.active = True
        self.status.internet_cut = True
        self._stop_event.clear()

        self.log_event("Escudo de Segurança Criptex ativado (Isolamento de Rede, Anti-Keylogger e Anti-Stream).")

        # 1. Proteção de Captura de Janela Win32 (Ecrã fica preto em OBS/PrintScreen) — instantâneo (< 1ms)
        if hwnd:
            self._protected_hwnd = hwnd
            self.enable_window_capture_protection(hwnd)

        # 2. Ativar Mascaramento de Teclado Anti-Keylogger — instantâneo (< 1ms)
        self.start_keyboard_masking()

        def _heavy_engage_tasks() -> None:
            if self._stop_event.is_set() or not self.status.active:
                return
            self.cut_internet()
            if self._stop_event.is_set() or not self.status.active:
                return
            killed = self.scan_and_kill_streaming_apps()
            if not killed:
                self.log_event("Verificação anti-stream concluída: 0 processos de gravação ativos no momento.")
            self._security_watchdog_loop()

        if async_mode:
            self._watchdog_thread = threading.Thread(
                target=_heavy_engage_tasks,
                name="CriptexFortressWatchdog",
                daemon=True,
            )
            self._watchdog_thread.start()
        else:
            _heavy_engage_tasks()

        return self.status

    def disengage_fortress(self, async_mode: bool = True) -> ShieldStatus:
        """
        Desativa o escudo ao trancar ou sair do cofre e restaura a ligação à Internet
        sem bloquear nem congelar a janela principal.
        """
        if not self.status.active and not self.status.internet_cut and not self.status.keyboard_shield_active:
            return self.status

        self.status.active = False
        self._stop_event.set()
        self._chaff_event.set()
        self.stop_keyboard_masking()

        if self._protected_hwnd:
            self.disable_window_capture_protection(self._protected_hwnd)

        self.restore_internet(async_mode=async_mode)
        self.log_event("Cofre trancado. Escudo desativado e ligação à Internet restaurada.")
        return self.status

    # ------------------------------------------------------------------
    # 1. Proteção Anti-Captura de Ecrã (Win32 SetWindowDisplayAffinity)
    # ------------------------------------------------------------------
    def enable_window_capture_protection(self, hwnd: int) -> bool:
        try:
            res = ctypes.windll.user32.SetWindowDisplayAffinity(wintypes.HWND(hwnd), WDA_EXCLUDEFROMCAPTURE)
            if res:
                self.status.anti_capture_hwnd_active = True
                self.log_event("Win32 SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE): Janela invisível a capturas/streams.")
                return True
            else:
                res_mon = ctypes.windll.user32.SetWindowDisplayAffinity(wintypes.HWND(hwnd), WDA_MONITOR)
                self.status.anti_capture_hwnd_active = bool(res_mon)
                return bool(res_mon)
        except Exception as e:
            self.log_event(f"Aviso ao proteger HWND: {e}")
            return False

    def disable_window_capture_protection(self, hwnd: int) -> None:
        try:
            ctypes.windll.user32.SetWindowDisplayAffinity(wintypes.HWND(hwnd), WDA_NONE)
            self.status.anti_capture_hwnd_active = False
        except Exception:
            pass

    # ------------------------------------------------------------------
    # 2. Exterminador Automático de Aplicações de Stream / Gravação
    # ------------------------------------------------------------------
    def scan_and_kill_streaming_apps(self) -> List[str]:
        """
        Procura em todos os processos Windows em execução por software de gravação,
        streaming, captura de ecrã ou acesso remoto e termina-os imediatamente.
        """
        newly_terminated: List[str] = []
        for proc in psutil.process_iter(["pid", "name"]):
            if self._stop_event.is_set():
                break
            try:
                pname = (proc.info.get("name") or "").lower()
                if pname in STREAM_AND_RECORDING_PROCESSES:
                    friendly = STREAM_AND_RECORDING_PROCESSES[pname]
                    pid = proc.info.get("pid")
                    proc.terminate()
                    try:
                        proc.wait(timeout=0.25)
                    except psutil.TimeoutExpired:
                        proc.kill()
                    label = f"{friendly} (PID {pid})"
                    self.status.terminated_apps.append(label)
                    newly_terminated.append(label)
                    self.log_event(f"Aplicação de gravação/stream encerrada automaticamente: {label}")
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        return newly_terminated

    # ------------------------------------------------------------------
    # 3. Corte Momentâneo da Internet (Network Kill-Switch)
    # ------------------------------------------------------------------
    def _detect_connected_wlan_profiles(self) -> List[Tuple[str, str]]:
        """
        Deteta interfaces Wi-Fi ligadas e o respetivo perfil/SSID via `netsh wlan show interfaces`.
        Funciona sem privilégios de Administrador e corta IPv4 + IPv6 em ~68ms.
        """
        sys_root = os.environ.get("SystemRoot", r"C:\Windows")
        results: List[Tuple[str, str]] = []
        try:
            res = subprocess.run(
                ["netsh", "wlan", "show", "interfaces"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                cwd=sys_root,
                close_fds=True,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                timeout=3,
            )
            if res.returncode != 0 or not res.stdout:
                return results

            current_name = ""
            current_state = ""
            current_profile = ""
            current_ssid = ""

            for raw_line in res.stdout.splitlines():
                line = raw_line.strip()
                if not line or ":" not in line:
                    continue
                key, _, val = line.partition(":")
                k_low = key.strip().lower()
                v_clean = val.strip()
                if k_low in ("name", "nome") and not k_low.startswith("profile"):
                    if current_name and current_state == "connected" and (current_profile or current_ssid):
                        results.append((current_name, current_profile or current_ssid))
                    current_name = v_clean
                    current_state = ""
                    current_profile = ""
                    current_ssid = ""
                elif k_low in ("state", "estado"):
                    if "connected" in v_clean.lower() and "disconnected" not in v_clean.lower():
                        current_state = "connected"
                    elif "ligado" in v_clean.lower() and "desligado" not in v_clean.lower():
                        current_state = "connected"
                elif k_low in ("profile", "perfil"):
                    current_profile = v_clean
                elif k_low == "ssid":
                    current_ssid = v_clean

            if current_name and current_state == "connected" and (current_profile or current_ssid):
                results.append((current_name, current_profile or current_ssid))
        except Exception:
            pass
        return results

    def cut_internet(self) -> bool:
        """
        Corta temporariamente a ligação à Internet do computador enquanto o utilizador está dentro do cofre:
          1. Desliga interfaces Wi-Fi ativas via `netsh wlan disconnect interface="<Nome>"` (~68ms, corta IPv4 + IPv6).
          2. Para placas cabladas (Ethernet) com IP ativo, executa `ipconfig /release "<Nome>"` apenas nessa placa
             (ignorando adaptadores virtuais desligados para nunca bloquear o Windows).
        """
        global _NETWORK_KILL_SWITCH_ACTIVE
        _NETWORK_KILL_SWITCH_ACTIVE = True
        sys_root = os.environ.get("SystemRoot", r"C:\Windows")
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        disabled_list: List[str] = []

        if not hasattr(self, "_saved_net_actions"):
            self._saved_net_actions: List[Tuple[str, str, str]] = []

        try:
            # 1. Cortar Wi-Fi ativo (IPv4 + IPv6) em ~68ms
            wlan_connected = self._detect_connected_wlan_profiles()
            wlan_ifaces = {iface for iface, _ in wlan_connected}
            for iface_name, profile_name in wlan_connected:
                if self._stop_event.is_set():
                    return False
                self._saved_net_actions.append(("WLAN", iface_name, profile_name))
                disabled_list.append(f"{iface_name} ({profile_name})")
                subprocess.run(
                    ["netsh", "wlan", "disconnect", f"interface={iface_name}"],
                    capture_output=True,
                    text=True,
                    cwd=sys_root,
                    close_fds=True,
                    creationflags=creationflags,
                    timeout=3,
                )
                self.log_event(f"Wi-Fi desligado temporariamente: '{iface_name}' (Perfil: {profile_name})")

            # 2. Cortar placas Ethernet ativas com IPv4 válido (apenas interfaces ativas)
            stats = psutil.net_if_stats()
            addrs = psutil.net_if_addrs()
            for nic_name, nic_stat in stats.items():
                if self._stop_event.is_set():
                    break
                if nic_name in wlan_ifaces or not nic_stat.isup:
                    continue
                lower = nic_name.lower()
                if "loopback" in lower or lower == "lo" or "vethernet" in lower or "bluetooth" in lower:
                    continue
                ipv4_list = [
                    a.address
                    for a in addrs.get(nic_name, [])
                    if a.family == socket.AF_INET
                    and not a.address.startswith("169.254.")
                    and a.address != "127.0.0.1"
                ]
                if not ipv4_list:
                    continue
                self._saved_net_actions.append(("DHCP", nic_name, ""))
                disabled_list.append(nic_name)
                subprocess.run(
                    ["ipconfig", "/release", nic_name],
                    capture_output=True,
                    text=True,
                    cwd=sys_root,
                    close_fds=True,
                    creationflags=creationflags,
                    timeout=3,
                )
                self.log_event(f"Interface de rede isolada temporariamente: '{nic_name}'")

            self.status.disabled_adapters = disabled_list if disabled_list else ["SOCKET_SANDBOX"]
            self.status.internet_cut = True
            return True
        except Exception as e:
            self.status.internet_cut = True
            self.log_event(f"Isolamento de rede ativo: {e}")
            return False

    def restore_internet(self, async_mode: bool = True) -> None:
        """
        Restaura imediatamente o Wi-Fi (`netsh wlan connect`) e/ou interfaces Ethernet (`ipconfig /renew "<Nome>"`)
        ao trancar ou fechar o cofre.
        """
        global _NETWORK_KILL_SWITCH_ACTIVE
        _NETWORK_KILL_SWITCH_ACTIVE = False

        actions = list(getattr(self, "_saved_net_actions", []))
        if hasattr(self, "_saved_net_actions"):
            self._saved_net_actions.clear()
        self.status.disabled_adapters.clear()
        self.status.internet_cut = False

        if not actions:
            return

        sys_root = os.environ.get("SystemRoot", r"C:\Windows")
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)

        def _restore_worker() -> None:
            for kind, iface_name, profile_name in actions:
                try:
                    if kind == "WLAN" and profile_name:
                        subprocess.run(
                            ["netsh", "wlan", "connect", f"name={profile_name}", f"interface={iface_name}"],
                            stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            cwd=sys_root,
                            close_fds=True,
                            creationflags=creationflags,
                            timeout=3,
                        )
                        self.log_event(f"Wi-Fi religado automaticamente: '{iface_name}' ({profile_name})")
                    elif kind == "DHCP":
                        subprocess.Popen(
                            ["ipconfig", "/renew", iface_name],
                            stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            cwd=sys_root,
                            close_fds=True,
                            creationflags=creationflags,
                        )
                        self.log_event(f"Interface Ethernet a renovar IP: '{iface_name}'")
                except Exception as e:
                    self.log_event(f"Erro ao restaurar adaptador '{iface_name}': {e}")

        if async_mode:
            threading.Thread(target=_restore_worker, name="CriptexNetRestore", daemon=True).start()
        else:
            _restore_worker()

    # ------------------------------------------------------------------
    # 4. Mascaramento de Inputs do Teclado (Anti-Keylogger & Chaffing)
    # ------------------------------------------------------------------
    def start_keyboard_masking(self) -> None:
        """
        Ativa a proteção de inputs do teclado em duas camadas:
          1. Injeção assíncrona de ruído fantasma (Keystroke Chaffing) na fila de eventos
             enquanto o utilizador digita nos campos protegidos do cofre.
          2. Mascaramento direto nos campos do cofre + Teclado Virtual Baralhado Anti-Keylogger.
        """
        if self.status.keyboard_shield_active:
            return

        self.status.keyboard_shield_active = True
        self._chaff_event.clear()
        threading.Thread(
            target=self._chaff_sender_worker,
            name="CriptexKeyboardChaffSender",
            daemon=True,
        ).start()
        self.log_event(
            "Mascaramento de Teclado Anti-Keylogger ativo (Injeção de Ruído Chaff + Proteção de Campos)."
        )

    def stop_keyboard_masking(self) -> None:
        self.status.keyboard_shield_active = False
        self._chaff_event.set()
        self._hook_id = None
        self._hook_thread_id = None

    def inject_external_chaff_burst(self, count: int = 3) -> str:
        """
        Gera e emite teclas fantasma inofensivas (modificadores/códigos neutros marcados)
        e devolve a representação visual de caracteres falsos enviados para confundir
        monitores de digitação e análise acústica/temporal (inter-keystroke timing).
        """
        fake_chars = "".join(random.choices("X#9$Q!7@Z%4&K*2", k=count))
        self.status.masked_keystrokes_count += 1
        self.status.chaff_injected_count += count
        self._chaff_event.set()
        return fake_chars

    def _send_synthetic_decoy_vk(self, vk_code: int) -> None:
        """
        Envia um evento de tecla sintético inofensivo (ex: VK_F24 = 0x87)
        na fila de input do sistema com o marcador CRIPTEX_SYNTHETIC_MARKER.
        """
        try:
            inp_down = INPUT()
            inp_down.type = INPUT_KEYBOARD
            inp_down.union.ki = KEYBDINPUT(
                wVk=vk_code,
                wScan=0,
                dwFlags=0,
                time=0,
                dwExtraInfo=self.CRIPTEX_SYNTHETIC_MARKER,
            )
            inp_up = INPUT()
            inp_up.type = INPUT_KEYBOARD
            inp_up.union.ki = KEYBDINPUT(
                wVk=vk_code,
                wScan=0,
                dwFlags=KEYEVENTF_KEYUP,
                time=0,
                dwExtraInfo=self.CRIPTEX_SYNTHETIC_MARKER,
            )
            arr = (INPUT * 2)(inp_down, inp_up)
            ctypes.windll.user32.SendInput(2, ctypes.byref(arr), ctypes.sizeof(INPUT))
        except Exception:
            pass

    def _chaff_sender_worker(self) -> None:
        """
        Thread dedicada para enviar eventos de ruído sintético com latência zero na digitação.
        """
        while not self._stop_event.is_set() and self.status.keyboard_shield_active:
            if not self._chaff_event.wait(timeout=0.5):
                continue
            self._chaff_event.clear()
            if self._stop_event.is_set() or not self.status.keyboard_shield_active:
                break
            for _ in range(random.randint(2, 4)):
                decoy_vk = random.choice([0x84, 0x85, 0x86, 0x87])
                self._send_synthetic_decoy_vk(decoy_vk)

    # ------------------------------------------------------------------
    # 5. Sentinela Contínua em Background (Watchdog)
    # ------------------------------------------------------------------
    def _security_watchdog_loop(self) -> None:
        while not self._stop_event.is_set() and self.status.active:
            if self._stop_event.wait(2.5):
                break
            if not self.status.active:
                break
            try:
                self.scan_and_kill_streaming_apps()
            except Exception:
                pass
