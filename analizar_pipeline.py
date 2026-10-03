#!/usr/bin/env python3
"""Lanzador único del analizador de pipelines (Windows, macOS y Linux).

    python analizar_pipeline.py                      # elige solo el mejor modo para este equipo
    python analizar_pipeline.py logs_123456 --pom pom.xml

Sin rutas, prueba de mejor a peor:
  1. Ventanas (tkinter). En Windows se abre sin consola (pythonw).
  2. Preguntas en la consola, si no hay ventanas pero sí una terminal.
  3. Aviso con el motivo y cómo habilitar las ventanas, si no hay ninguna de las dos.
Si las ventanas fallan a mitad de camino, continúa en el siguiente modo en vez de cerrarse.
Con rutas como argumentos se ejecuta directamente en la consola.
"""
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pipeline_analyzer import compat  # noqa: E402
from pipeline_analyzer.cli import gui_main, main  # noqa: E402


def _relaunch_without_console() -> bool:
    """Windows: reabre este mismo script con pythonw.exe (sin ventana de consola). True si lo logró."""
    exe = sys.executable or ""
    if not (sys.platform.startswith("win") and os.path.basename(exe).lower() == "python.exe"):
        return False
    pyw = os.path.join(os.path.dirname(exe), "pythonw.exe")
    if not os.path.exists(pyw):
        return False
    flags = getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    try:
        subprocess.Popen([pyw, os.path.abspath(__file__)], creationflags=flags, close_fds=True)
    except OSError:
        return False
    return True


def run() -> int:
    argv = sys.argv[1:]
    if argv:
        return main(argv)                          # con rutas u opciones: consola, sin elegir nada
    if sys.stdin is None:                          # pythonw / doble clic sin consola: solo ventanas
        return gui_main()
    console = sys.stdin.isatty()
    if compat.tk_status()[0]:
        if _relaunch_without_console():            # 1) ventanas sin consola
            return 0
        try:
            return main(["--gui"])                 # 1) ventanas con consola
        except Exception as exc:                   # las ventanas fallaron: se sigue con el siguiente modo
            print("Las ventanas fallaron (%s). Continuando en la consola…" % exc, file=sys.stderr)
            if not console:
                compat.notify("Analizador de pipelines", "Las ventanas fallaron: %s" % exc)
                return 1
    return main(["--no-gui"] if console else [])   # 2) preguntas en consola · 3) aviso con el motivo


if __name__ == "__main__":
    sys.exit(run())
