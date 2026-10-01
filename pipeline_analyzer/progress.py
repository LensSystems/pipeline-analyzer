"""Indicador de avance en consola (stderr), sin dependencias externas.

En una terminal interactiva muestra una barra animada que se redibuja en la misma línea:

    ⠹ [██████████░░░░░░░░░░]  52% │ Leyendo logs_123456 │ 23/44 · 1.8s

Fuera de una terminal (CI, redirección a archivo) solo imprime una línea por etapa.
"""

import shutil
import sys
import threading
import time
from typing import Callable, Optional, TextIO


class Progress:
    def __init__(self, total: int, enabled: bool = True, stream: Optional[TextIO] = None,
                 listener: Optional[Callable[..., None]] = None):
        # listener(pct, stage, detail, message): p. ej. la ventana de avance. Se llama solo desde el hilo principal.
        self.listener = listener
        self.stream = stream or sys.stderr
        self.total = max(1, total)
        self.done_units = 0
        self.stage_msg = ""
        self.detail = ""
        self.enabled = enabled
        self.tty = enabled and self.stream is not None and hasattr(self.stream, "isatty") and self.stream.isatty()
        from .compat import fancy_unicode
        self.unicode = self.stream is not None and fancy_unicode(self.stream)
        self.frames = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏" if self.unicode else "|/-\\"
        self.full, self.empty = ("█", "░") if self.unicode else ("#", ".")
        self.ok_mark = "✔" if self.unicode else "OK"
        self.t0 = time.monotonic()
        self._frame = 0
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None
        if self.tty:
            self._thread = threading.Thread(target=self._spin, daemon=True)
            self._thread.start()

    # ---------------------------------------------------------------- API

    def stage(self, msg: str) -> None:
        """Cambia la etapa actual (se imprime también fuera de una terminal)."""
        with self._lock:
            self.stage_msg = msg
            self.detail = ""
            if self.enabled and not self.tty and self.stream is not None:
                self.stream.write("%s %s\n" % ("»" if self.unicode else ">", msg))
                self.stream.flush()
            self._draw()
        self._notify()

    def advance(self, detail: str = "", units: int = 1) -> None:
        with self._lock:
            self.done_units = min(self.total, self.done_units + units)
            self.detail = detail
            self._draw()
        self._notify()

    def log(self, msg: str) -> None:
        """Mensaje permanente encima de la barra."""
        self._notify(msg)
        with self._lock:
            if not self.enabled or self.stream is None:
                return
            if self.tty:
                self._clear()
            self.stream.write("  %s %s\n" % (self.ok_mark, msg))
            self.stream.flush()
            self._draw()

    def close(self, msg: Optional[str] = None) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=1)
        if self.listener and msg:
            self._notify(msg, done=True)
        with self._lock:
            if not self.enabled or self.stream is None:
                return
            if self.tty:
                self._clear()
            if msg:
                self.stream.write("%s %s (%.1fs)\n" % (self.ok_mark, msg, time.monotonic() - self.t0))
            self.stream.flush()
            self.enabled = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close(None if exc_type else None)
        return False

    def _notify(self, message: Optional[str] = None, done: bool = False) -> None:
        if self.listener:
            pct = 1.0 if done else self.done_units / self.total
            self.listener(pct, self.stage_msg, self.detail, message)

    # ---------------------------------------------------------------- dibujo

    def _spin(self) -> None:
        while not self._stop.wait(0.1):
            with self._lock:
                self._frame = (self._frame + 1) % len(self.frames)
                self._draw()

    def _clear(self) -> None:
        width = shutil.get_terminal_size((100, 20)).columns
        self.stream.write("\r" + " " * (width - 1) + "\r")

    def _draw(self) -> None:
        if not (self.enabled and self.tty):
            return
        width = shutil.get_terminal_size((100, 20)).columns
        pct = self.done_units / self.total
        bar_w = 20
        filled = int(round(bar_w * pct))
        bar = self.full * filled + self.empty * (bar_w - filled)
        elapsed = time.monotonic() - self.t0
        sep = "│" if self.unicode else "|"
        parts = ["%s [%s] %3d%%" % (self.frames[self._frame], bar, pct * 100)]
        if self.stage_msg:
            parts.append(self.stage_msg)
        if self.detail:
            parts.append(self.detail)
        parts.append("%.1fs" % elapsed)
        line = (" %s " % sep).join(parts)
        if len(line) > width - 1:
            line = line[: width - 2] + "…"
        self.stream.write("\r" + line.ljust(width - 1))
        self.stream.flush()
