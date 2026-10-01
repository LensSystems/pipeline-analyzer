"""Compatibilidad entre plataformas e instalaciones de Python.

- Versión mínima de Python (3.8).
- Consola: salida sin errores de codificación (Windows cp1252/cp437), colores ANSI en Windows 10+,
  caracteres Unicode solo donde la terminal los muestra bien.
- Ventanas (tkinter): detecta si están disponibles y, si no, explica cómo habilitarlas según la
  instalación: Homebrew, Python de Apple (Tk 8.5 obsoleto), python.org, Linux (apt/dnf/pacman/zypper/apk),
  pyenv, WSL y Windows.
"""

import os
import platform
import shutil
import sys
from typing import Dict, Optional, Tuple

MIN_PYTHON = (3, 8)

IS_WINDOWS = sys.platform.startswith("win")
IS_MAC = sys.platform == "darwin"
IS_LINUX = sys.platform.startswith("linux")

_ANSI_OK: Optional[bool] = None


# ====================================================================== Python


def python_ok() -> bool:
    return sys.version_info[:2] >= MIN_PYTHON


def python_error() -> str:
    return ("Se requiere Python %d.%d o superior (tienes %s en %s).\n%s"
            % (MIN_PYTHON + (platform.python_version(), sys.executable, python_install_hint())))


def python_install_hint() -> str:
    if IS_WINDOWS:
        return "Instala Python desde https://www.python.org/downloads/ (marca 'Add python.exe to PATH') o con: winget install Python.Python.3.12"
    if IS_MAC:
        return "Instala Python desde https://www.python.org/downloads/macos/ o con Homebrew: brew install python python-tk"
    distro = linux_distro()
    return {
        "debian": "sudo apt install python3 python3-tk",
        "fedora": "sudo dnf install python3 python3-tkinter",
        "rhel": "sudo dnf install python3.11 python3.11-tkinter",
        "arch": "sudo pacman -S python tk",
        "suse": "sudo zypper install python3 python3-tk",
        "alpine": "sudo apk add python3 python3-tkinter",
    }.get(distro, "Instala Python 3.8+ con el gestor de paquetes de tu distribución")


# ====================================================================== instalación / sistema


def install_kind() -> str:
    """homebrew | apple | python.org | pyenv | conda | windows-store | windows | linux-system | otro"""
    exe = os.path.realpath(sys.executable or "")
    prefix = sys.prefix
    if "conda" in prefix.lower() or os.path.exists(os.path.join(prefix, "conda-meta")):
        return "conda"
    if ".pyenv" in exe or "pyenv" in prefix:
        return "pyenv"
    if IS_MAC:
        if "/opt/homebrew/" in exe or "/usr/local/Cellar/" in exe or "/Homebrew/" in exe or "/homebrew/" in prefix.lower():
            return "homebrew"
        if exe.startswith(("/Library/Developer/CommandLineTools", "/Applications/Xcode")) or exe.startswith("/System/"):
            return "apple"
        if "/Library/Frameworks/Python.framework" in exe:
            return "python.org"
        return "otro"
    if IS_WINDOWS:
        return "windows-store" if "WindowsApps" in exe else "windows"
    if IS_LINUX:
        if "linuxbrew" in exe:
            return "homebrew"
        return "linux-system" if exe.startswith(("/usr/bin", "/bin")) else "otro"
    return "otro"


def linux_distro(os_release: Optional[str] = None) -> str:
    """debian | fedora | rhel | arch | suse | alpine | desconocida (lee /etc/os-release)."""
    if os_release is None:
        try:
            with open("/etc/os-release", encoding="utf-8") as fh:
                os_release = fh.read()
        except OSError:
            return "desconocida"
    info: Dict[str, str] = {}
    for line in os_release.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            info[k.strip()] = v.strip().strip('"').lower()
    families = (("debian", ("debian", "ubuntu", "linuxmint", "pop")), ("fedora", ("fedora",)),
                ("rhel", ("rhel", "centos", "rocky", "almalinux", "ol", "amzn")), ("arch", ("arch", "manjaro")),
                ("suse", ("suse", "opensuse", "sles", "opensuse-leap", "opensuse-tumbleweed")), ("alpine", ("alpine",)))
    # Primero el ID exacto y luego ID_LIKE en su orden (Rocky: ID_LIKE="rhel centos fedora" → rhel).
    for ident in [info.get("ID", "")] + info.get("ID_LIKE", "").split():
        for key, names in families:
            if ident in names:
                return key
    return "desconocida"


def is_wsl() -> bool:
    if not IS_LINUX:
        return False
    try:
        with open("/proc/version", encoding="utf-8") as fh:
            return "microsoft" in fh.read().lower()
    except OSError:
        return False


# ====================================================================== tkinter


def tk_install_hint(kind: Optional[str] = None, distro: Optional[str] = None) -> str:
    kind = kind or install_kind()
    ver = "%d.%d" % sys.version_info[:2]
    if kind == "homebrew":
        return "brew install python-tk@%s" % ver
    if kind == "apple":
        return ("El Python de Apple usa Tk 8.5 (obsoleto). Usa Python de https://www.python.org/downloads/macos/ "
                "o de Homebrew: brew install python python-tk")
    if kind == "python.org":
        return "Reinstala Python desde https://www.python.org/downloads/ (incluye tkinter)"
    if kind == "conda":
        return "conda install tk"
    if kind == "pyenv":
        if IS_MAC:
            return "brew install tcl-tk y reinstala la versión: pyenv uninstall %s && pyenv install %s" % (platform.python_version(), platform.python_version())
        return "Instala tk-dev (Debian/Ubuntu) o tk-devel (Fedora/RHEL) y reinstala la versión con pyenv install"
    if kind in ("windows", "windows-store"):
        return ("Ejecuta el instalador de Python → Modify → marca 'tcl/tk and IDLE' "
                "(o reinstala desde https://www.python.org/downloads/windows/)")
    if IS_LINUX:
        d = distro or linux_distro()
        return {
            "debian": "sudo apt install python3-tk",
            "fedora": "sudo dnf install python3-tkinter",
            "rhel": "sudo dnf install python%s-tkinter  (o python3-tkinter)" % ver,
            "arch": "sudo pacman -S tk",
            "suse": "sudo zypper install python3-tk",
            "alpine": "sudo apk add python3-tkinter",
        }.get(d, "Instala el paquete de tkinter de tu distribución (python3-tk / python3-tkinter)")
    return "Instala tkinter para tu versión de Python"


def tk_status() -> Tuple[bool, str, str]:
    """(disponible, motivo si no lo está, cómo habilitarlo)."""
    try:
        import tkinter
    except ImportError:
        return False, "tkinter no está instalado en este Python (%s)" % sys.executable, tk_install_hint()
    if IS_MAC and float(getattr(tkinter, "TkVersion", 8.6)) < 8.6:
        return False, "Tk %s de este Python está obsoleto en macOS (las ventanas pueden fallar)" % tkinter.TkVersion, tk_install_hint("apple")
    if IS_LINUX and not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        hint = "Usa WSLg (Windows 11) o un servidor X" if is_wsl() else "Conéctate con 'ssh -X' o ejecútalo en un escritorio"
        return False, "no hay entorno gráfico (DISPLAY/WAYLAND_DISPLAY vacíos)", hint
    try:
        root = tkinter.Tk()
        root.withdraw()
        root.destroy()
    except Exception as exc:  # TclError: no display, Tk roto, etc.
        return False, "no se pudo abrir una ventana (%s)" % str(exc).splitlines()[0][:120], tk_install_hint()
    return True, "", ""


# ====================================================================== consola


def enable_windows_ansi() -> bool:
    """Activa secuencias ANSI (colores, \\r) en la consola de Windows 10+."""
    if not IS_WINDOWS:
        return True
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        ok = True
        for handle_id in (-11, -12):  # STD_OUTPUT_HANDLE, STD_ERROR_HANDLE
            h = kernel32.GetStdHandle(handle_id)
            mode = ctypes.c_uint32()
            if not kernel32.GetConsoleMode(h, ctypes.byref(mode)):
                ok = False
                continue
            if not kernel32.SetConsoleMode(h, mode.value | 0x0004):  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
                ok = False
        return ok
    except Exception:
        return False


def setup_console() -> None:
    """Llamar al iniciar: evita UnicodeEncodeError y prepara colores."""
    global _ANSI_OK
    if IS_MAC:
        os.environ.setdefault("TK_SILENCE_DEPRECATION", "1")
    for stream in (sys.stdout, sys.stderr):
        if stream is None or not hasattr(stream, "reconfigure"):
            continue
        try:
            if not stream.isatty():
                stream.reconfigure(encoding="utf-8", errors="replace")  # archivos/tuberías: UTF-8 siempre
            else:
                stream.reconfigure(errors="replace")
        except Exception:
            pass
    _ANSI_OK = enable_windows_ansi()


def ansi_supported(stream=None) -> bool:
    stream = stream or sys.stdout
    if stream is None or not hasattr(stream, "isatty") or not stream.isatty():
        return False
    if os.environ.get("NO_COLOR") is not None or os.environ.get("TERM") == "dumb":
        return False
    if IS_WINDOWS:
        return bool(_ANSI_OK if _ANSI_OK is not None else enable_windows_ansi())
    return True


def fancy_unicode(stream=None) -> bool:
    """True si la terminal muestra bien ✔ █ ⠋ ↑ (UTF-8 y, en Windows, una terminal moderna)."""
    stream = stream or sys.stdout
    enc = (getattr(stream, "encoding", "") or "").lower().replace("-", "")
    if "utf8" not in enc:
        return False
    if IS_WINDOWS:
        # La consola clásica (conhost) con fuentes raster no muestra braille ni bloques.
        return bool(os.environ.get("WT_SESSION") or os.environ.get("TERM_PROGRAM") or os.environ.get("ConEmuANSI") == "ON")
    return True


def doctor() -> str:
    ok_tk, why, fix = tk_status()
    rows = [
        ("Python", "%s (%s) %s" % (platform.python_version(), platform.python_implementation(),
                                   "OK" if python_ok() else "NO SOPORTADO: mínimo %d.%d" % MIN_PYTHON)),
        ("Ejecutable", sys.executable or "?"),
        ("Instalación", install_kind()),
        ("Sistema", "%s %s (%s)%s" % (platform.system(), platform.release(), platform.machine(),
                                     " · WSL" if is_wsl() else "")),
    ]
    if IS_LINUX:
        rows.append(("Distribución", linux_distro()))
    rows += [
        ("Ventanas (tkinter)", "OK" if ok_tk else "NO DISPONIBLES: " + why),
    ]
    if not ok_tk:
        rows.append(("  Para habilitarlas", fix))
        rows.append(("  Mientras tanto", "el modo interactivo pregunta por consola (o usa --no-gui)"))
    rows += [
        ("Codificación consola", "stdout=%s stderr=%s" % (getattr(sys.stdout, "encoding", None), getattr(sys.stderr, "encoding", None))),
        ("Colores ANSI", "sí" if ansi_supported() else "no"),
        ("Símbolos Unicode", "sí" if fancy_unicode() else "no (se usan ASCII)"),
        ("Ancho de terminal", str(shutil.get_terminal_size((80, 20)).columns)),
    ]
    width = max(len(k) for k, _ in rows)
    return "Diagnóstico del entorno\n" + "\n".join("  %s : %s" % (k.ljust(width), v) for k, v in rows)


def notify(title: str, message: str) -> None:
    """Mensaje para el usuario aunque no haya consola (doble clic con pythonw)."""
    try:
        import tkinter
        from tkinter import messagebox
        root = tkinter.Tk()
        root.withdraw()
        messagebox.showwarning(title, message, parent=root)
        root.destroy()
        return
    except Exception:
        pass
    if IS_WINDOWS:
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(0, message, title, 0x30)  # MB_ICONWARNING
            return
        except Exception:
            pass
    if sys.stderr is not None:
        print("%s: %s" % (title, message), file=sys.stderr)


_TRANSLIT = {"→": "->", "←": "<-", "↑": "^", "↓": "v", "✔": "OK", "✅": "OK", "❌": "X", "⚠": "!", "•": "*",
             "…": "...", "—": "-", "–": "-", "│": "|", "█": "#", "░": ".", "»": ">", "·": ".", "≥": ">=", "≤": "<="}


def console_safe(text: str, stream=None) -> str:
    """Adapta el texto a la codificación de la consola (p. ej. cp1252/cp437 en Windows) sin perder legibilidad."""
    stream = stream or sys.stdout
    enc = getattr(stream, "encoding", None) or "utf-8"
    try:
        text.encode(enc)
        return text
    except (UnicodeEncodeError, LookupError):
        pass
    out = []
    for ch in text:
        try:
            ch.encode(enc)
            out.append(ch)
        except (UnicodeEncodeError, LookupError):
            out.append(_TRANSLIT.get(ch, "?"))
    return "".join(out)
