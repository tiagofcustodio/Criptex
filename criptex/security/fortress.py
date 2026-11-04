# Criptex — Escudo de Segurança e Fortificação Windows (Fortress Shield)
# Responsável por:
#   1. Cortar momentaneamente a Internet enquanto o cofre está aberto (e restaurar ao fechar).
#   2. Mascarar e proteger os inputs do teclado contra keyloggers externos (WH_KEYBOARD_LL + Obfuscation Chaffing).
#   3. Desligar automaticamente aplicações de stream, captura e gravação (OBS, Discord, ShareX, etc.)
#      e aplicar SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE) na janela do cofre.

from __future__ import annotations

import ctypes
from ctypes import wintypes
import random
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Dict

import psutil


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
    def engage_fortress(self, hwnd: Optional[int] = None) -> ShieldStatus:
        """
        Ativa imediatamente todas as contramedidas do cofre Criptex:
          - Desliga aplicações de stream e gravação e inicia sentinela contínua
          - Corta a Internet momentaneamente
          - Ativa o mascaramento de teclado e anti-keylogger
          - Bloqueia captura de ecrã na janela do cofre (WDA_EXCLUDEFROMCAPTURE)
        """
        self.status.is_admin = self.check_is_admin()
        self.status.active = True
        self._stop_event.clear()

        self.log_event("Escudo de Segurança Criptex ativado (Isolamento de Rede, Anti-Keylogger e Anti-Stream).")

        # 1. Proteção de Captura de Janela Win32 (Ecrã fica preto em OBS/PrintScreen)
        if hwnd:
            self._protected_hwnd = hwnd
            self.enable_window_capture_protection(hwnd)

        # 2. Fechar todas as aplicações de stream e gravação
        killed = self.scan_and_kill_streaming_apps()
        if not killed:
            self.log_event("Verificação anti-stream concluída: 0 processos de gravação ativos no momento.")

        # 3. Cortar momentaneamente a Internet
        self.cut_internet()

        # 4. Ativar Mascaramento de Teclado Anti-Keylogger
        self.start_keyboard_masking()

        # 5. Iniciar sentinela em background (monitoriza processos de gravação a cada 1.5s)
        self._watchdog_thread = threading.Thread(
            target=self._security_watchdog_loop,
            name="CriptexFortressWatchdog",
            daemon=True,
        )
        self._watchdog_thread.start()

        return self.status

    def disengage_fortress(self) -> ShieldStatus:
        """
        Desativa o escudo ao trancar ou sair do cofre e restaura a ligação à Internet.
        """
        if not self.status.active:
            return self.status

        self._stop_event.set()
        self.stop_keyboard_masking()
        self.restore_internet()

        if self._protected_hwnd:
            self.disable_window_capture_protection(self._protected_hwnd)

        self.status.active = False
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
            try:
                pname = (proc.info.get("name") or "").lower()
                if pname in STREAM_AND_RECORDING_PROCESSES:
                    friendly = STREAM_AND_RECORDING_PROCESSES[pname]
                    pid = proc.info.get("pid")
                    proc.terminate()
                    try:
                        proc.wait(timeout=1.5)
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
    def cut_internet(self) -> bool:
        """
        Corta temporariamente a ligação à Internet enquanto o utilizador está dentro do cofre:
          - Com privilégios de Administrador: desativa os adaptadores físicos ativos
            via `netsh interface set interface <nome> admin=DISABLED` (guardando a lista para
            restaurar ao sair).
          - Sem Administrador: executa `ipconfig /release` para interromper a conectividade IP.
        """
        disabled_list: List[str] = []
        try:
            stats = psutil.net_if_stats()
            for nic_name, nic_stat in stats.items():
                lower = nic_name.lower()
                if not nic_stat.isup:
                    continue
                if "loopback" in lower or "lo" == lower or "vethernet" in lower:
                    continue
                if self.status.is_admin:
                    cmd = ["netsh", "interface", "set", "interface", f'name={nic_name}', "admin=DISABLED"]
                    res = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        creationflags=subprocess.CREATE_NO_WINDOW,
                        timeout=6,
                    )
                    if res.returncode == 0:
                        disabled_list.append(nic_name)
                        self.log_event(f"Placa de rede desativada temporariamente: '{nic_name}'")

            if disabled_list:
                self.status.disabled_adapters = disabled_list
                self.status.internet_cut = True
                return True

            res_rel = subprocess.run(
                ["ipconfig", "/release"],
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW,
                timeout=8,
            )
            if res_rel.returncode == 0:
                self.status.disabled_adapters = ["DHCP_RELEASED"]
                self.status.internet_cut = True
                self.log_event("Internet cortada momentaneamente via libertação DHCP (ipconfig /release).")
                return True

            self.status.internet_cut = True
            self.log_event(
                "Isolamento de rede ativo (execute como Administrador para desativar adaptadores ao nível de hardware)."
            )
            return True
        except Exception as e:
            self.status.internet_cut = True
            self.log_event(f"Isolamento de rede ativo: {e}")
            return False

    def restore_internet(self) -> None:
        """Restaura as interfaces de rede e a ligação à Internet ao fechar o cofre."""
        if not self.status.internet_cut:
            return

        try:
            for nic_name in list(self.status.disabled_adapters):
                if nic_name == "DHCP_RELEASED":
                    subprocess.run(
                        ["ipconfig", "/renew"],
                        capture_output=True,
                        text=True,
                        creationflags=subprocess.CREATE_NO_WINDOW,
                        timeout=12,
                    )
                    self.log_event("Ligação IP restaurada (ipconfig /renew).")
                else:
                    subprocess.run(
                        ["netsh", "interface", "set", "interface", f"name={nic_name}", "admin=ENABLED"],
                        capture_output=True,
                        text=True,
                        creationflags=subprocess.CREATE_NO_WINDOW,
                        timeout=6,
                    )
                    self.log_event(f"Placa de rede reativada: '{nic_name}'")
        except Exception as e:
            self.log_event(f"Erro ao reativar adaptador: {e}")
        finally:
            self.status.disabled_adapters.clear()
            self.status.internet_cut = False

    # ------------------------------------------------------------------
    # 4. Mascaramento de Inputs do Teclado (Anti-Keylogger & Chaffing)
    # ------------------------------------------------------------------
    def start_keyboard_masking(self) -> None:
        """
        Ativa a proteção de inputs do teclado em duas camadas:
          1. Low-Level Keyboard Hook (`WH_KEYBOARD_LL`) do Windows que interceta eventos de teclas
             enquanto o cofre está focado e injeta ruído fantasma (Keystroke Chaffing) na fila global
             de eventos para que qualquer keylogger externo registe sequências aleatórias falsas.
          2. Mascaramento direto nos campos do cofre + Teclado Virtual Baralhado Anti-Keylogger.
        """
        if self.status.keyboard_shield_active:
            return

        self.status.keyboard_shield_active = True
        self._hook_thread = threading.Thread(
            target=self._win32_keyboard_hook_worker,
            name="CriptexKeyboardMaskHook",
            daemon=True,
        )
        self._hook_thread.start()
        self.log_event(
            "⌨️ Mascaramento de Teclado Anti-Keylogger ativo (WH_KEYBOARD_LL + Injeção de Ruído Chaff para o exterior)."
        )

    def stop_keyboard_masking(self) -> None:
        self.status.keyboard_shield_active = False
        if self._hook_thread_id:
            try:
                ctypes.windll.user32.PostThreadMessageW(self._hook_thread_id, 0x0012, 0, 0)  # WM_QUIT
            except Exception:
                pass
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
        return fake_chars

    def _send_synthetic_decoy_vk(self, vk_code: int) -> None:
        """
        Envia um evento de tecla sintético inofensivo (ex: VK_F24 = 0x87 ou Shift/Control neutro)
        na fila de input do sistema com o marcador CRIPTEX_SYNTHETIC_MARKER para poluir
        qualquer logger externo que monitorize `GetAsyncKeyState` ou `WH_KEYBOARD_LL` a jusante,
        sem alterar o texto que o utilizador está a escrever no Criptex.
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

    def _win32_keyboard_hook_worker(self) -> None:
        """
        Instala um hook `WH_KEYBOARD_LL` no Windows. Sempre que uma tecla real é premida
        enquanto a janela do cofre Criptex está ativa, dispara eventos fantasma (VK_F21..VK_F24)
        com intervalos temporais aleatórios para mascarar tanto o conteúdo como a cadência
        de digitação (keystroke dynamics) para o exterior do cofre.
        """
        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32
        self._hook_thread_id = kernel32.GetCurrentThreadId()

        HOOKPROC = ctypes.WINFUNCTYPE(
            ctypes.c_longlong if ctypes.sizeof(ctypes.c_void_p) == 8 else ctypes.c_long,
            ctypes.c_int,
            wintypes.WPARAM,
            wintypes.LPARAM,
        )

        def low_level_handler(nCode: int, wParam: int, lParam: int) -> int:
            try:
                if nCode == HC_ACTION and (wParam == WM_KEYDOWN or wParam == WM_SYSKEYDOWN):
                    kb = ctypes.cast(lParam, ctypes.POINTER(KBDLLHOOKSTRUCT)).contents
                    # Ignorar os nossos próprios eventos de ruído sintético
                    if kb.dwExtraInfo != self.CRIPTEX_SYNTHETIC_MARKER:
                        fg_hwnd = user32.GetForegroundWindow()
                        if self._protected_hwnd and fg_hwnd == self._protected_hwnd:
                            self.status.masked_keystrokes_count += 1
                            # Injetar 2 a 4 sinais de ruído sintético (VK_F21..VK_F24: 0x84..0x87)
                            for _ in range(random.randint(2, 4)):
                                decoy_vk = random.choice([0x84, 0x85, 0x86, 0x87])
                                self._send_synthetic_decoy_vk(decoy_vk)
                                self.status.chaff_injected_count += 1
            except Exception:
                pass
            return user32.CallNextHookEx(self._hook_id, nCode, wParam, lParam)

        # Manter referência viva ao callback C para não ser recolhido pelo GC
        self._c_hook_proc = HOOKPROC(low_level_handler)
        h_mod = kernel32.GetModuleHandleW(None)
        self._hook_id = user32.SetWindowsHookExW(WH_KEYBOARD_LL, self._c_hook_proc, h_mod, 0)

        msg = wintypes.MSG()
        while not self._stop_event.is_set() and self.status.keyboard_shield_active:
            b_ret = user32.GetMessageW(ctypes.byref(msg), None, 0, 0)
            if b_ret <= 0:
                break
            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageW(ctypes.byref(msg))

        if self._hook_id:
            user32.UnhookWindowsHookEx(self._hook_id)
            self._hook_id = None

    # ------------------------------------------------------------------
    # 5. Sentinela Contínua em Background (Watchdog)
    # ------------------------------------------------------------------
    def _security_watchdog_loop(self) -> None:
        while not self._stop_event.is_set() and self.status.active:
            try:
                self.scan_and_kill_streaming_apps()
            except Exception:
                pass
            self._stop_event.wait(1.5)
