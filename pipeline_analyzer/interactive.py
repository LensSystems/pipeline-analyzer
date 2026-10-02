"""Modo interactivo: se usa cuando el programa se ejecuta sin rutas.

- Con entorno gráfico: un asistente en una sola ventana centrada (tkinter, biblioteca estándar) con
  los diálogos nativos "Seleccionar carpeta" / "Abrir archivo", el avance y el resultado final.
- Sin entorno gráfico (servidor, SSH, tkinter no instalado): las mismas preguntas en la consola.

Orden de las preguntas:
  1. Log principal (ejecución a analizar): carpeta de descarga, .zip o archivo de log.
  2. ¿Agregar log(s) de comparación? (ejecuciones anteriores; se pueden agregar varios).
  3. ¿Agregar pom.xml?
  4. ¿Agregar reportes de las herramientas? (PDF/JSON/XML de Checkmarx, PMD, Checkstyle, SpotBugs…), por si no venían
     incluidos en la carpeta o el .zip de logs. Se pueden agregar varios, en archivos o carpetas.
"""

import os
import re
import sys
from pathlib import Path
from typing import Callable, Dict, List, Optional

LOG_TYPES = [("Logs de pipeline", "*.txt *.log *.zip *.out"), ("Todos los archivos", "*.*")]
POM_TYPES = [("pom.xml", "*.xml"), ("Todos los archivos", "*.*")]
REPORT_TYPES = [("Reportes de herramientas", "*.pdf *.json *.xml *.md"), ("Todos los archivos", "*.*")]


class Cancelled(Exception):
    """El usuario canceló la selección del log principal o cerró la ventana."""


# ====================================================================== consola


def _clean_path(value: str, windows: Optional[bool] = None) -> str:
    """Normaliza una ruta escrita o arrastrada a la terminal.

    - macOS/Linux: quita comillas y espacios escapados (``/Mis\\ logs``).
    - Windows (cmd/PowerShell): quita comillas y el ``& '...'`` que agrega PowerShell; la barra invertida
      es el separador, así que no se toca.
    """
    windows = sys.platform.startswith("win") if windows is None else windows
    v = value.strip()
    if v.startswith("& "):
        v = v[2:].strip()
    v = v.strip('"').strip("'")
    if not windows:
        v = v.replace("\\ ", " ")
    return os.path.expanduser(v)


def _ask_path(prompt: str, required: bool, input_fn: Callable[[str], str], out) -> Optional[str]:
    while True:
        try:
            raw = input_fn(prompt)
        except EOFError:
            raise Cancelled()
        value = _clean_path(raw)
        if not value:
            if required:
                out.write("  Es obligatorio. Escribe o arrastra la ruta (Ctrl+C para salir).\n")
                continue
            return None
        if Path(value).exists():
            return value
        out.write("  No existe: %s\n" % value)


def _ask_yes(prompt: str, input_fn: Callable[[str], str]) -> bool:
    try:
        return input_fn(prompt).strip().lower() in ("s", "si", "sí", "y", "yes")
    except EOFError:
        return False


def gather_console(input_fn: Optional[Callable[[str], str]] = None, out=None) -> Dict[str, object]:
    import builtins
    input_fn = input_fn or builtins.input  # se resuelve al llamar (permite reemplazarla en pruebas)
    out = out or sys.stdout
    out.write("\nAnalizador de pipelines — modo interactivo\n")
    out.write("Puedes escribir la ruta o arrastrar la carpeta/archivo a esta ventana.\n\n")
    main = _ask_path("1) Log principal (carpeta de descarga, .zip o archivo de log): ", True, input_fn, out)
    compare: List[str] = []
    while _ask_yes("2) ¿Agregar un log de comparación (ejecución anterior)? [s/N]: ", input_fn):
        p = _ask_path("   Ruta del log de comparación: ", False, input_fn, out)
        if p:
            compare.append(p)
    pom = None
    if _ask_yes("3) ¿Agregar el pom.xml para revisarlo? [s/N]: ", input_fn):
        pom = _ask_path("   Ruta del pom.xml: ", False, input_fn, out)
    reports: List[str] = []
    if _ask_yes("4) ¿Agregar reportes de las herramientas (PDF/JSON/XML de Checkmarx, PMD, SpotBugs…)? "
                "Úsalo si no venían en la carpeta o el .zip [s/N]: ", input_fn):
        while True:
            p = _ask_path("   Ruta del reporte o carpeta (Enter para terminar): ", False, input_fn, out)
            if not p:
                break
            reports.append(p)
            out.write("   Agregado (%d). \n" % len(reports))
    return {"logs": compare + [main], "pom": pom, "main": main, "reports": reports}


# ====================================================================== ventanas (tkinter)


def gui_status():
    """(disponible, motivo, cómo habilitarlo) según la plataforma y la instalación de Python."""
    from .compat import tk_status
    return tk_status()


def gui_available() -> bool:
    return gui_status()[0]


ACCENT = "#0a7aff"      # azul del sistema (macOS)
SEV_COLORS = {"CRITICAL": "#d92d20", "HIGH": "#d92d20", "MEDIUM": "#b7791f", "LOW": "#2f6fdb", "INFO": "#6e6e73"}
FILE_INFO = {"reporte_completo.html": "Reporte HTML completo (local)", "reporte.html": "Reporte HTML enmascarado",
             "reporte.pdf": "PDF para compartir", "reporte_completo.pdf": "PDF completo (confidencial)",
             "reporte.md": "Markdown", "reporte.json": "JSON"}


class Gui:
    """Asistente en UNA ventana principal, visible y centrada, con el aspecto nativo del sistema.

    Usa widgets ttk (en macOS son los controles Aqua reales: botón principal azul, barra de progreso, lista y
    separadores nativos, y siguen el modo claro/oscuro), botones alineados a la derecha como en los diálogos de macOS
    (el principal a la derecha, cancelar a su izquierda) y un indicador de pasos.

    Todo ocurre dentro de la ventana: pasos, preguntas, avance y resultado. Los diálogos nativos de archivo se abren con
    esa ventana como padre; en macOS aparecen como hoja (sheet) anclada a ella y en Windows/Linux encima de ella, así que
    siempre quedan centrados. (Con una ventana raíz oculta, macOS los mandaba a la parte inferior de la pantalla.)
    Los botones viven en una franja inferior fija, con columnas iguales: nunca se deforman aunque el contenido sea largo.
    Todo corre en el hilo principal.
    """

    WIDTH, HEIGHT = 640, 500

    def __init__(self):
        import tkinter as tk
        from tkinter import filedialog, font as tkfont, ttk
        self.tk, self.fd, self.ttk, self.tkfont = tk, filedialog, ttk, tkfont
        if sys.platform.startswith("win"):
            try:  # nitidez en pantallas con escalado (Windows 8.1+)
                import ctypes
                ctypes.windll.shcore.SetProcessDpiAwareness(1)
            except Exception:
                pass
        self.root = root = tk.Tk()
        root.title("Analizador de pipelines")
        root.minsize(self.WIDTH, self.HEIGHT)
        root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.closed = False
        self.busy = False
        self.last_dir = os.getcwd()
        self._var = tk.StringVar(root, "")
        self.buttons: Dict[str, object] = {}  # botones visibles por texto (usado por las pruebas)
        self._setup_style()

        header = ttk.Frame(root, padding=(28, 22, 28, 14))
        header.pack(fill="x")
        self._icon = tk.Canvas(header, width=46, height=46, highlightthickness=0, bd=0, bg=self._bg)
        self._icon.pack(side="left", padx=(0, 14))
        self._draw_icon()
        titles = ttk.Frame(header)
        titles.pack(side="left", fill="x", expand=True)
        ttk.Label(titles, text="Analizador de pipelines", font=self.f_title).pack(anchor="w")
        self._step = ttk.Label(titles, text="", font=self.f_small, foreground=self._secondary)
        self._step.pack(anchor="w", pady=(2, 0))
        self._dots = tk.Canvas(header, width=90, height=14, highlightthickness=0, bd=0, bg=self._bg)
        self._dots.pack(side="right")
        ttk.Separator(root).pack(fill="x")
        # Franja de botones fija, empaquetada ANTES que el cuerpo: el cuerpo cede espacio y los botones conservan su forma.
        self.footer = ttk.Frame(root, padding=(28, 14, 24, 18))  # 24 + 4 del botón = 28 de margen
        self.footer.pack(side="bottom", fill="x")
        ttk.Separator(root).pack(side="bottom", fill="x")
        self.body = ttk.Frame(root, padding=(28, 20, 28, 8))
        self.body.pack(fill="both", expand=True)

        self._center()
        self._bring_to_front()

    # ---------------------------------------------------------------- estilo

    def _setup_style(self) -> None:
        style = self.ttk.Style()
        if sys.platform not in ("darwin",) and not sys.platform.startswith("win"):
            try:
                style.theme_use("clam")  # más moderno que "default" en Linux
            except Exception:
                pass
        base = self.tkfont.nametofont("TkDefaultFont")
        size = int(base.cget("size"))

        def font(delta: int, bold: bool = False):
            f = base.copy()
            f.configure(size=size + delta if size > 0 else size - delta, weight="bold" if bold else "normal")
            return f

        self.f_title, self.f_head, self.f_small, self.f_body = font(6, True), font(3, True), font(-1), font(0)
        self.f_chip = font(-1, True)
        self._bg = style.lookup("TFrame", "background") or self.root.cget("bg")
        self._field_bg = style.lookup("TEntry", "fieldbackground") or "#ffffff"
        self._secondary = self._system_color("systemSecondaryLabelColor", "#6e6e73")
        style.configure("Treeview", rowheight=26)

    def _system_color(self, name: str, fallback: str) -> str:
        if sys.platform == "darwin":
            try:
                self.root.winfo_rgb(name)  # falla si esta versión de Tk no conoce el color del sistema
                return name
            except Exception:
                pass
        return fallback

    def _draw_icon(self) -> None:
        c = self._icon
        r, pts = 11, [(2, 2), (44, 2), (44, 44), (2, 44)]
        # cuadrado redondeado azul (estilo icono de app) con un "pipeline" de tres nodos
        c.create_polygon(2 + r, 2, 44 - r, 2, 44, 2, 44, 2 + r, 44, 44 - r, 44, 44, 44 - r, 44, 2 + r, 44, 2, 44, 2, 44 - r, 2, 2 + r, 2, 2,
                         smooth=True, fill=ACCENT, outline=ACCENT)
        c.create_line(12, 23, 34, 23, fill="white", width=3)
        for x in (12, 23, 34):
            c.create_oval(x - 4.5, 18.5, x + 4.5, 27.5, fill="white", outline="white")

    def _draw_steps(self, step: str) -> None:
        self._dots.delete("all")
        m = re.match(r"Paso (\d+) de (\d+)", step)
        if not m:
            return
        cur, total = int(m.group(1)), int(m.group(2))
        for i in range(total):
            x = 10 + i * 22
            on = i < cur
            self._dots.create_oval(x - 5, 2, x + 5, 12, fill=ACCENT if on else self._bg, outline=ACCENT if on else "#a1a1a6", width=1.5)

    # ---------------------------------------------------------------- ventana

    def _center(self) -> None:
        r = self.root
        r.update_idletasks()
        w, h = max(self.WIDTH, r.winfo_reqwidth()), max(self.HEIGHT, r.winfo_reqheight())
        x = max(0, (r.winfo_screenwidth() - w) // 2)
        y = max(0, (r.winfo_screenheight() - h) // 3)
        r.geometry("%dx%d+%d+%d" % (w, h, x, y))

    def _bring_to_front(self) -> None:
        r = self.root
        r.deiconify()
        r.lift()
        try:  # al frente solo un instante: "siempre encima" taparía los diálogos nativos en Windows
            r.attributes("-topmost", True)
            r.after(400, lambda: r.attributes("-topmost", False))
        except Exception:
            pass
        r.focus_force()
        r.update()

    def _on_close(self) -> None:
        if self.busy:  # durante el análisis no se cierra a medias
            return
        self.closed = True
        self._var.set("__close__")

    def _clear(self, step: str) -> None:
        for w in list(self.body.winfo_children()) + list(self.footer.winfo_children()):
            w.destroy()
        for i in range(8):  # restablece las columnas de la franja de botones
            self.footer.grid_columnconfigure(i, weight=0, uniform="", minsize=0)
        self.footer.grid_rowconfigure(0, minsize=30)  # misma altura de franja en todas las pantallas (con o sin botones)
        self.buttons = {}
        self._step["text"] = step
        self._draw_steps(step)
        from . import BRAND  # distintivo discreto, abajo a la izquierda (ocupa la columna elástica, no afecta a los botones)
        # En su propia fila (debajo de los botones): nunca lo recorta un botón, por anchos que sean
        self.ttk.Label(self.footer, text=BRAND, font=self.f_small, foreground=self._secondary).grid(
            row=1, column=0, columnspan=8, sticky="w", pady=(8, 0))

    def _text(self, text: str, bold: bool = False, color: Optional[str] = None, small: bool = False) -> None:
        kw = {"foreground": color} if color else ({"foreground": self._secondary} if small else {})
        font = self.f_head if bold else (self.f_small if small else self.f_body)
        self.ttk.Label(self.body, text=text, justify="left", anchor="w", wraplength=self.WIDTH - 84, font=font, **kw).pack(
            fill="x", pady=(0, 12 if not small else 6))

    def _choice(self, options: List[tuple]) -> str:
        """Muestra botones [(texto, valor)] y espera el clic. Cerrar la ventana cancela todo.

        Convención de macOS: la primera opción es la principal (azul, a la derecha, responde a Enter) y las demás quedan a
        su izquierda. Todas las columnas son iguales, así que los botones siempre tienen el mismo tamaño y forma.
        """
        self.footer.grid_columnconfigure(0, weight=1)  # empuja los botones a la derecha
        shown = list(reversed(options))
        for col, (label, value) in enumerate(shown, 1):
            self.footer.grid_columnconfigure(col, weight=0, uniform="botones", minsize=120)
            primary = value == options[0][1]
            b = self.ttk.Button(self.footer, text=label, command=lambda v=value: self._var.set(v),
                                default="active" if primary else "normal")
            b.grid(row=0, column=col, sticky="ew", padx=4)  # mismo margen en todos: mismo tamaño
            self.buttons[label] = b
            if primary:
                b.focus_set()
        first = options[0][1]
        self.root.bind("<Return>", lambda e: self._var.set(first))
        cancel = next((v for _l, v in options if v in ("skip", "close", "no")), None)
        if cancel:
            self.root.bind("<Escape>", lambda e: self._var.set(cancel))
        self._var.set("")
        self.root.wait_variable(self._var)
        self.root.unbind("<Return>")
        self.root.unbind("<Escape>")
        if self.closed:
            raise Cancelled()
        return self._var.get()

    # ---------------------------------------------------------------- selección

    def _open(self, kind: str, title: str, filetypes=None) -> Optional[str]:
        self.root.update()
        if kind == "dir":
            path = self.fd.askdirectory(parent=self.root, title=title, initialdir=self.last_dir, mustexist=True)
        else:
            path = self.fd.askopenfilename(parent=self.root, title=title, initialdir=self.last_dir,
                                           filetypes=filetypes or LOG_TYPES)
        self._bring_to_front()
        if path:
            self.last_dir = str(Path(path).parent)
        return path or None

    def ask_log(self, step: str, title: str, message: str, required: bool) -> Optional[str]:
        while True:
            self._clear(step)
            self._text(title, bold=True)
            self._text(message)
            kind = self._choice([("Seleccionar carpeta…", "dir"), ("Abrir archivo…", "file"),
                                 ("Cancelar" if required else "Omitir", "skip")])
            if kind == "skip":
                if required:
                    raise Cancelled()
                return None
            path = self._open(kind, title)
            if path:
                return path
            # Se cerró el diálogo sin elegir: volver a mostrar las opciones

    def ask_yes(self, step: str, question: str, detail: str = "") -> bool:
        self._clear(step)
        self._text(question, bold=True)
        if detail:
            self._text(detail, small=True)
        return self._choice([("Sí", "yes"), ("No", "no")]) == "yes"

    def _open_many(self, title: str) -> List[str]:
        self.root.update()
        paths = self.fd.askopenfilenames(parent=self.root, title=title, initialdir=self.last_dir, filetypes=REPORT_TYPES)
        self._bring_to_front()
        if paths:
            self.last_dir = str(Path(paths[0]).parent)
        return list(paths or [])

    def ask_reports(self, step: str, chosen: List[str]) -> List[str]:
        """Paso extra: reportes de las herramientas que no venían en la carpeta o el .zip (varios, archivos o carpetas)."""
        reports: List[str] = []
        while True:
            self._clear(step)
            self._text("¿Quieres agregar reportes de las herramientas?", bold=True)
            self._text("Si el PDF de Checkmarx (o los XML/JSON de PMD, Checkstyle y SpotBugs) no venían en la carpeta o el .zip, "
                       "agrégalos aquí para ver el archivo, la línea y la solución de cada hallazgo y compararlos con el log.\n"
                       "Formatos: PDF, JSON, XML y Markdown. Puedes elegir varios archivos o una carpeta completa.", small=True)
            if reports:
                self._text("Agregados (%d):\n%s" % (len(reports), "\n".join("• " + Path(r).name for r in reports[-6:])
                                                   + ("\n• …" if len(reports) > 6 else "")))
            else:
                self._text("\n".join(chosen), small=True)
            action = self._choice([("Continuar" if reports else "Omitir", "done"), ("Agregar archivos…", "files"),
                                   ("Agregar carpeta…", "dir")])
            if action == "done":
                return reports
            if action == "files":
                reports += [p for p in self._open_many("Selecciona los reportes") if p not in reports]
            else:
                p = self._open("dir", "Selecciona la carpeta con los reportes")
                if p and p not in reports:
                    reports.append(p)

    def ask_pom(self) -> Optional[str]:
        return self._open("file", "Selecciona el pom.xml", POM_TYPES)

    def gather(self) -> Dict[str, object]:
        main = self.ask_log("Paso 1 de 4 · Log principal", "Selecciona la ejecución a analizar",
                            "• Carpeta de descarga de logs (p. ej. logs_123456)\n"
                            "• Archivo .zip de la descarga\n"
                            "• Archivo de log (.txt / .log)", required=True)
        chosen = ["Principal: " + main]
        compare: List[str] = []
        question = "¿Quieres agregar un log de comparación?"
        while self.ask_yes("Paso 2 de 4 · Comparación", question,
                           "Una ejecución anterior del mismo pipeline, para ver qué mejoró o empeoró.\n\n"
                           + "\n".join(chosen)):
            p = self.ask_log("Paso 2 de 4 · Comparación", "Selecciona la ejecución anterior",
                             "Carpeta, .zip o archivo de log.", required=False)
            if p:
                compare.append(p)
                chosen.append("Comparación: " + p)
            question = "¿Quieres agregar otro log de comparación?"
        pom = None
        if self.ask_yes("Paso 3 de 4 · pom.xml", "¿Quieres agregar el pom.xml?",
                        "Se revisan su configuración de build, calidad y dependencias.\n\n" + "\n".join(chosen)):
            pom = self.ask_pom()
            if pom:
                chosen.append("pom.xml: " + pom)
        reports = self.ask_reports("Paso 4 de 4 · Reportes", chosen)
        return {"logs": compare + [main], "pom": pom, "main": main, "reports": reports}

    # ---------------------------------------------------------------- avance

    def open_progress(self) -> Callable[..., None]:
        tk, ttk = self.tk, self.ttk
        self.busy = True
        self._clear("Analizando…")
        self._stage = ttk.Label(self.body, text="Preparando…", anchor="w", font=self.f_head)
        self._stage.pack(fill="x")
        self._bar = ttk.Progressbar(self.body, mode="determinate", maximum=100)
        self._bar.pack(fill="x", pady=(10, 8))
        self._detail = ttk.Label(self.body, text="", anchor="w", font=self.f_small, foreground=self._secondary)
        self._detail.pack(fill="x")
        holder = tk.Frame(self.body, bd=1, relief="solid", highlightthickness=0)
        holder.pack(fill="both", expand=True, pady=(12, 0))
        self._log = tk.Text(holder, height=7, state="disabled", relief="flat", wrap="word", font=self.f_small, bg=self._field_bg,
                            padx=8, pady=6)
        self._log.pack(fill="both", expand=True)
        self.root.update()

        def listener(pct: float, stage: str = "", detail: str = "", message: Optional[str] = None) -> None:
            if not self.busy:
                return
            self._bar["value"] = pct * 100
            self._stage["text"] = stage[:80]
            self._detail["text"] = detail[:90]
            if message:
                self._log.configure(state="normal")
                self._log.insert("end", "• " + message + "\n")
                self._log.see("end")
                self._log.configure(state="disabled")
            self.root.update()

        return listener

    def close_progress(self) -> None:
        self.busy = False

    # ---------------------------------------------------------------- resultado

    def _file_list(self, paths: List[str]) -> None:
        """Lista nativa y desplazable de los archivos generados; la carpeta se muestra una vez. Nunca empuja los botones."""
        ttk = self.ttk
        if paths:  # se empaqueta primero (abajo): su espacio queda reservado y la lista cede altura, nunca se recorta
            ttk.Label(self.body, text="Carpeta: " + str(Path(paths[0]).parent), font=self.f_small, foreground=self._secondary,
                      wraplength=self.WIDTH - 84, justify="left").pack(side="bottom", fill="x", pady=(8, 0))
        frame = ttk.Frame(self.body)
        frame.pack(fill="both", expand=True)
        sb = ttk.Scrollbar(frame, orient="vertical")
        tree = ttk.Treeview(frame, columns=("desc",), height=6, yscrollcommand=sb.set, selectmode="browse")
        tree.heading("#0", text="Archivo", anchor="w")
        tree.heading("desc", text="Descripción", anchor="w")
        tree.column("#0", width=230, stretch=False)
        tree.column("desc", width=300, stretch=True)
        for p in paths:
            name = Path(p).name
            tree.insert("", "end", text=name, values=(FILE_INFO.get(name, ""),))
        sb.configure(command=tree.yview)
        tree.pack(side="left", fill="both", expand=True)
        if len(paths) > 6:
            sb.pack(side="right", fill="y")


    def show_result(self, verdict: str, counts: Dict[str, int], written: List[str]) -> None:
        self.busy = False
        self._clear("Análisis completado")
        ok = verdict.startswith("Todos")
        self._text(("✓  " if ok else "⚠  ") + verdict, bold=True, color="#1f9d55" if ok else "#d93025")
        row = self.tk.Frame(self.body, bg=self._bg)
        row.pack(fill="x", pady=(0, 12))
        chips = [(k, v) for k, v in counts.items() if v]
        for k, v in chips:
            self.tk.Label(row, text="%s  %d" % (k, v), bg=SEV_COLORS.get(k, "#6e6e73"), fg="white", font=self.f_chip,
                          padx=9, pady=2).pack(side="left", padx=(0, 6))
        if not chips:
            self.ttk.Label(row, text="Sin hallazgos", font=self.f_small, foreground=self._secondary).pack(side="left")
        self._file_list(written)
        html = next((w for w in written if w.endswith("reporte_completo.html")), None) or next(
            (w for w in written if w.endswith(".html")), None)
        options = ([("Abrir reporte HTML", "open")] if html else []) + [("Cerrar", "close")]
        try:
            choice = self._choice(options)
        except Cancelled:
            return
        if choice == "open" and html:
            import webbrowser  # abre un archivo local con el navegador predeterminado
            webbrowser.open(Path(html).resolve().as_uri())

    def show_error(self, text: str) -> None:
        self.busy = False
        self._clear("Error")
        self._text("⚠  No se pudo completar", bold=True, color="#d93025")
        self._text(text)
        try:
            self._choice([("Cerrar", "close")])
        except Cancelled:
            pass

    def destroy(self) -> None:
        try:
            self.root.destroy()
        except Exception:
            pass
