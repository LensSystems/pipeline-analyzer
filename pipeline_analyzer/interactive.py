"""Modo interactivo: se usa cuando el programa se ejecuta sin rutas.

- Con entorno gráfico: un asistente en una sola ventana centrada (tkinter, biblioteca estándar) con
  los diálogos nativos "Seleccionar carpeta" / "Abrir archivo", el avance y el resultado final.
- Sin entorno gráfico (servidor, SSH, tkinter no instalado): las mismas preguntas en la consola.

Entradas (una sola pantalla, igual en macOS, Windows y Linux):
  - Log principal (obligatorio): carpeta de descarga, .zip o archivo de log.
  - Comparación (opcional): una o varias ejecuciones anteriores.
  - pom.xml (opcional).
  - Reportes de las herramientas (opcional): PDF/JSON/XML/Markdown de Checkmarx, PMD, Checkstyle, SpotBugs…, por si no venían
    incluidos en la carpeta o el .zip de logs; archivos o carpetas.
En la consola, las mismas preguntas una por una.
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


def _same(a: str, b: str) -> bool:
    return os.path.normcase(os.path.abspath(a)) == os.path.normcase(os.path.abspath(b))


def find_duplicate(path: str, st: Dict[str, object], skip: tuple = ()) -> Optional[str]:
    """Apartado ("main", "compare", "pom", "reports") donde ya está la misma ruta, o None. Mismo nombre en otra carpeta no cuenta.

    ``skip``: apartados de un solo valor que se están reemplazando (cambiar el log principal por sí mismo es válido).
    """
    for key in ("main", "compare", "pom", "reports"):
        if key in skip:
            continue
        value = st.get(key)
        for existing in ([value] if isinstance(value, str) else (value or [])):
            if existing and _same(path, existing):
                return key
    return None


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


def _ask_unique(prompt: str, required: bool, st: Dict[str, object], input_fn, out) -> Optional[str]:
    """Como ``_ask_path`` pero rechaza un archivo ya indicado en otro apartado (misma ruta)."""
    labels = {"main": "el log principal", "compare": "la comparación", "pom": "el pom.xml", "reports": "los reportes"}
    while True:
        p = _ask_path(prompt, required, input_fn, out)
        where = find_duplicate(p, st) if p else None
        if where is None:
            return p
        out.write("  Archivo no válido: ya está en %s. No se puede usar el mismo archivo en más de un apartado "
                  "(el mismo nombre en otra carpeta sí es válido).\n" % labels[where])


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
    st: Dict[str, object] = {"main": None, "compare": [], "pom": None, "reports": []}
    main = st["main"] = _ask_path("1) Log principal (carpeta de descarga, .zip o archivo de log): ", True, input_fn, out)
    compare: List[str] = st["compare"]
    while _ask_yes("2) ¿Agregar un log de comparación (ejecución anterior)? [s/N]: ", input_fn):
        p = _ask_unique("   Ruta del log de comparación: ", False, st, input_fn, out)
        if p:
            compare.append(p)
    pom = None
    if _ask_yes("3) ¿Agregar el pom.xml para revisarlo? [s/N]: ", input_fn):
        pom = st["pom"] = _ask_unique("   Ruta del pom.xml: ", False, st, input_fn, out)
    reports: List[str] = st["reports"]
    if _ask_yes("4) ¿Agregar reportes de las herramientas (PDF/JSON/XML de Checkmarx, PMD, SpotBugs…)? "
                "Úsalo si no venían en la carpeta o el .zip [s/N]: ", input_fn):
        while True:
            p = _ask_unique("   Ruta del reporte o carpeta (Enter para terminar): ", False, st, input_fn, out)
            if not p:
                break
            reports.append(p)
            out.write("   Agregado (%d).\n" % len(reports))
    return {"logs": compare + [main], "pom": pom, "main": main, "reports": reports}


# ====================================================================== ventanas (tkinter)


def gui_status():
    """(disponible, motivo, cómo habilitarlo) según la plataforma y la instalación de Python."""
    from .compat import tk_status
    return tk_status()


def gui_available() -> bool:
    return gui_status()[0]


ACCENT = "#0a7aff"      # azul del sistema (macOS)


def platform_style() -> Dict[str, object]:
    """Apariencia nativa según el sistema y su versión.

    ``mac``: tema Aqua (controles reales de macOS, modo claro/oscuro automático). ``win11`` / ``win10``: tema ``vista`` de
    Windows, con Segoe UI Variable en Windows 11 (compilación 22000 o posterior) y Segoe UI en Windows 10. En Linux, ``clam``.
    Tkinter (biblioteca estándar) no puede aplicar Mica ni el modo oscuro de Windows: se mantiene el aspecto claro nativo.
    """
    if sys.platform == "darwin":
        return {"os": "mac", "theme": "aqua", "families": (), "pad": 28, "radius": 8, "primary_right": True}
    if sys.platform.startswith("win"):
        wv = getattr(sys, "getwindowsversion", None)
        build = getattr(wv(), "build", 0) if callable(wv) else 0
        if build >= 22000:
            return {"os": "win11", "theme": "vista", "families": ("Segoe UI Variable Text", "Segoe UI Variable", "Segoe UI"),
                    "pad": 28, "radius": 4, "primary_right": False}
        return {"os": "win10", "theme": "vista", "families": ("Segoe UI",), "pad": 22, "radius": 0, "primary_right": False}
    return {"os": "linux", "theme": "clam", "families": (), "pad": 26, "radius": 6, "primary_right": True}
SEV_COLORS = {"CRITICAL": "#d92d20", "HIGH": "#d92d20", "MEDIUM": "#b7791f", "LOW": "#2f6fdb", "INFO": "#6e6e73"}
FILE_INFO = {"reporte_completo.html": "Reporte HTML completo (local)", "reporte.html": "Reporte HTML enmascarado",
             "reporte.pdf": "PDF para compartir", "reporte_completo.pdf": "PDF completo (confidencial)",
             "reporte.md": "Markdown", "reporte.json": "JSON"}


# Colores de estado accesibles para macOS (4.5:1 o más sobre el fondo de ventana, en claro y oscuro). Tk no conoce
# systemRedColor/systemGreenColor, y los colores de sistema verde/rojo no llegan a 3:1 como texto sobre el fondo claro.
MAC_LIGHT = {"ok": "#16794a", "bad": "#c1281b", "on": "#ffffff"}
MAC_DARK = {"ok": "#4cc38a", "bad": "#ff8a77", "on": "#1c1c1e"}
MAC_CHIPS = {"CRITICAL": "#c1281b", "HIGH": "#c1281b", "MEDIUM": "#9a5b00", "LOW": "#2f6fdb", "INFO": "#6e6e73"}  # texto blanco: 3.6 a 5.9:1


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
        self.style_info = platform_style()
        self.mac = self.style_info["os"] == "mac"       # solo para lo propio de macOS: atajos ⌘ y colores dinámicos del sistema
        self.WIDTH, self.HEIGHT = 760, 500              # misma pantalla en todos los sistemas; el alto crece con el contenido
        root.minsize(self.WIDTH, self.HEIGHT)
        self.cancel_requested = False
        self.new_requested = False     # el usuario pidió «Nuevo análisis» en la pantalla de resultado
        self._wrapped: List[tuple] = []
        self._setup_style()
        pad = self.style_info["pad"]

        # Sin franja de color ni icono propio: el título de la ventana lo pone el sistema; aquí solo el nombre y el paso actual.
        header = ttk.Frame(root, padding=(pad, 22, pad, 6))
        header.pack(fill="x")
        # El nombre de la app ya está en la barra de título: aquí solo el título de la pantalla actual
        self._step = ttk.Label(header, text="", font=self.f_title)
        self._step.pack(anchor="w")
        # Franja de botones fija, empaquetada ANTES que el cuerpo: el cuerpo cede espacio y los botones conservan su forma.
        self.footer = ttk.Frame(root, padding=(pad, 14, pad - 4, 18))  # el botón aporta 4 px de margen
        self.footer.pack(side="bottom", fill="x")
        ttk.Separator(root).pack(side="bottom", fill="x")
        self.body = ttk.Frame(root, padding=(pad, 18, pad, 8))
        self.body.pack(fill="both", expand=True)
        self.body.bind("<Configure>", self._rewrap)
        if self.mac:
            for seq in ("<Command-w>", "<Command-q>"):  # atajos estándar de macOS
                root.bind(seq, lambda e: self._on_close())

        self._center()
        self._bring_to_front()

    # ---------------------------------------------------------------- estilo

    def _setup_style(self) -> None:
        style = self.ttk.Style()
        info = self.style_info
        if info["theme"] in style.theme_names():
            try:
                style.theme_use(info["theme"])
            except Exception:
                pass
        base = self.tkfont.nametofont("TkDefaultFont")
        size = int(base.cget("size"))
        family = next((f for f in info["families"] if f in set(self.tkfont.families())), None)  # Segoe UI Variable → Segoe UI

        def font(delta: int, bold: bool = False):
            f = base.copy()
            f.configure(size=size + delta if size > 0 else size - delta, weight="bold" if bold else "normal")
            if family:
                f.configure(family=family)
            return f

        win = info["os"] != "mac" and info["os"] != "linux"
        self.f_title, self.f_head, self.f_small, self.f_body = font(5 if win else 7, True), font(2 if win else 3, True), font(-1), font(0)
        self.f_chip = font(-1, True)
        self._bg = style.lookup("TFrame", "background") or self.root.cget("bg")
        self._field_bg = style.lookup("TEntry", "fieldbackground") or "#ffffff"
        self._secondary = self._system_color("systemSecondaryLabelColor", "#6e6e73")
        # Colores de las listas agrupadas: en macOS siguen el modo claro/oscuro; en Windows y Linux, valores nativos claros
        self._card_bg = self._system_color("systemTextBackgroundColor", self._field_bg)
        self._card_border = self._system_color("systemSeparatorColor", "#d0d0d0")
        self._text_fg = self._system_color("systemTextColor", style.lookup("TLabel", "foreground") or "#1d1d1f")
        style.configure("Treeview", rowheight=26 if info["os"] != "win10" else 22)

    def _pal(self) -> Dict[str, str]:
        """Colores de estado. En macOS cambian con el modo claro/oscuro del sistema (se detecta por el color del texto)."""
        if not self.mac:
            return MAC_LIGHT   # Windows y Linux: apariencia clara, con los mismos colores accesibles
        try:
            dark = sum(self.root.winfo_rgb("systemTextColor")) / 3 > 32768
        except Exception:
            dark = False
        return MAC_DARK if dark else MAC_LIGHT

    def _system_color(self, name: str, fallback: str) -> str:
        if sys.platform == "darwin":
            try:
                self.root.winfo_rgb(name)  # falla si esta versión de Tk no conoce el color del sistema
                return name
            except Exception:
                pass
        return fallback

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

    def _request_cancel(self) -> None:
        """Cancelar el análisis en curso (botón, ⌘. en macOS o cerrar la ventana), con confirmación porque se pierde el avance."""
        if self.cancel_requested:
            return
        try:
            sure = self.root.tk.call("tk_messageBox", "-parent", ".", "-type", "yesno", "-icon", "warning", "-default", "no",
                                     "-message", "¿Cancelar el análisis?",
                                     "-detail", "Se perderá el avance y no se generará ningún reporte.") == "yes"
        except Exception:
            sure = True
        if sure:
            self.cancel_requested = True
            try:
                self._stage["text"] = "Cancelando…"
            except Exception:
                pass

    def _on_close(self) -> None:
        if self.busy:
            self._request_cancel()   # cerrar la ventana durante el análisis pide confirmación; no se cierra a medias
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
        self._wrapped = []
        self._step["text"] = step
        if not step.startswith("Análisis completado"):
            return  # la marca aparece una sola vez, en el resultado
        from . import BRAND  # distintivo discreto, abajo a la izquierda (ocupa la columna elástica, no afecta a los botones)
        # En su propia fila (debajo de los botones): nunca lo recorta un botón, por anchos que sean
        self.ttk.Label(self.footer, text=BRAND, font=self.f_small, foreground=self._secondary).grid(
            row=1, column=0, columnspan=8, sticky="w", pady=(8, 0))

    def _text(self, text: str, bold: bool = False, color: Optional[str] = None, small: bool = False) -> None:
        kw = {"foreground": color} if color else ({"foreground": self._secondary} if small else {})
        font = self.f_head if bold else (self.f_small if small else self.f_body)
        lbl = self.ttk.Label(self.body, text=text, justify="left", anchor="w", wraplength=self.WIDTH - 84, font=font, **kw)
        # La descripción pega con su título (4 pt) y se separa del siguiente bloque (16 pt): lo relacionado queda junto
        lbl.pack(fill="x", pady=(0, 4 if bold else (16 if small else 10)))
        self._wrapped.append((lbl, 0))

    def _rewrap(self, _event=None) -> None:
        """Reacomoda el texto al ancho real del cuerpo (la ventana se puede redimensionar)."""
        width = self.body.winfo_width() - 2 * self.style_info["pad"]
        if width > 100:
            for lbl, extra in self._wrapped:
                try:
                    lbl.configure(wraplength=width - extra)
                except Exception:
                    pass

    def _card(self, pady=(0, 14)):
        """Contenedor «agrupado» (borde fino, esquinas según el sistema) para listas de lo elegido."""
        card = self.tk.Frame(self.body, bg=self._card_bg, highlightthickness=1, bd=0,
                             highlightbackground=self._card_border, highlightcolor=self._card_border)
        card.pack(fill="x", pady=pady)
        return card

    def _fit(self) -> None:
        """Si el contenido de la pantalla pide más alto que la ventana, la agranda (sin achicarla) para no recortar botones."""
        r = self.root
        r.update_idletasks()
        need = sum(w.winfo_reqheight() for w in r.pack_slaves())
        cap = r.winfo_screenheight() - 120
        target = min(max(self.HEIGHT, need + 8), cap)   # sigue al contenido: se alarga al agregar archivos y vuelve a su alto base al quitarlos
        if target != r.winfo_height():
            r.geometry("%dx%d" % (r.winfo_width(), target))

    def _choice(self, options: List[tuple], cancel: Optional[str] = None, disabled: tuple = ()) -> str:
        """Muestra botones [(texto, valor)] y espera el clic. Cerrar la ventana cancela todo.

        Convención de macOS: la primera opción es la principal (azul, a la derecha, responde a Enter) y las demás quedan a
        su izquierda. Todas las columnas son iguales, así que los botones siempre tienen el mismo tamaño y forma.
        """
        for old in list(self.buttons.values()):  # varias llamadas seguidas en la misma pantalla (p. ej. «Abrir reporte»)
            try:
                old.destroy()
            except Exception:
                pass
        self.buttons = {}
        self.footer.grid_columnconfigure(0, weight=1)  # empuja los botones a la derecha
        # macOS/Linux: principal a la derecha y el resto a su izquierda. Windows: el principal va primero (a la izquierda del grupo).
        shown = list(reversed(options)) if self.style_info["primary_right"] else list(options)
        for col, (label, value) in enumerate(shown, 1):
            self.footer.grid_columnconfigure(col, weight=0, uniform="botones", minsize=120)
            primary = value == options[0][1]
            b = self.ttk.Button(self.footer, text=label, command=lambda v=value: self._var.set(v),
                                default="active" if primary else "normal")
            b.grid(row=0, column=col, sticky="ew", padx=6)  # mismo margen en todos: mismo tamaño
            self.buttons[label] = b
            if value in disabled:
                b.state(["disabled"])
            elif primary:
                b.focus_set()
        self._fit()
        first = options[0][1]
        if first not in disabled:
            self.root.bind("<Return>", lambda e: self._var.set(first))
        cancel = cancel or next((v for _l, v in options if v in ("skip", "close", "no")), None)
        if cancel:
            # Esc NO cierra ni cancela nada (se cerraba la aplicación sin querer). En macOS queda ⌘. como atajo estándar.
            if self.mac:
                self.root.bind("<Command-period>", lambda e: self._var.set(cancel))
        self._var.set("")
        self.root.wait_variable(self._var)
        self.root.unbind("<Return>")
        self.root.unbind("<Command-period>")
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

    def _open_many(self, title: str) -> List[str]:
        self.root.update()
        paths = self.fd.askopenfilenames(parent=self.root, title=title, initialdir=self.last_dir, filetypes=REPORT_TYPES)
        self._bring_to_front()
        if paths:
            self.last_dir = str(Path(paths[0]).parent)
        return list(paths or [])

    def ask_pom(self) -> Optional[str]:
        return self._open("file", "Selecciona el pom.xml", POM_TYPES)

    def gather(self) -> Dict[str, object]:
        return self._gather_form()

    # ---- macOS: una sola pantalla con todas las entradas (en una Mac hay espacio de sobra: menos pasos y menos modalidad)

    REMOVE_BG, REMOVE_BG_HOVER = "#c2410c", "#9a3412"   # naranja con texto blanco: 5.2:1 y 7.3:1

    def _remove_button(self, parent, command) -> object:
        """Botón «Quitar» naranja con las esquinas redondeadas de los botones de Aqua (los ttk nativos no admiten color).

        Se dibuja en un Canvas del mismo alto que un botón pequeño de macOS; admite foco (Tab), Espacio/Enter y estado al pasar el ratón.
        """
        tk = self.tk
        w, h, r = 66, 26, 7
        c = tk.Canvas(parent, width=w, height=h, bg=self._card_bg, highlightthickness=0, bd=0, takefocus=1,
                      cursor="pointinghand" if self.mac else "hand2")   # «pointinghand» solo existe en macOS: en Windows cerraba la ventana

        def draw(fill: str, ring: Optional[str] = None) -> None:
            c.delete("all")
            pts = [r, 1, w - r, 1, w - 1, 1, w - 1, r, w - 1, h - r, w - 1, h - 1, w - r, h - 1, r, h - 1, 1, h - 1, 1, h - r, 1, r, 1, 1]
            c.create_polygon(pts, smooth=True, fill=fill, outline=ring or fill, width=2 if ring else 1)
            c.create_text(w / 2, h / 2, text="Quitar", fill="#ffffff", font=self.f_small)

        draw(self.REMOVE_BG)
        c.bind("<Button-1>", lambda e: command())
        for key in ("<space>", "<Return>"):
            c.bind(key, lambda e: command())
        c.bind("<Enter>", lambda e: draw(self.REMOVE_BG_HOVER, "#0a7aff" if c.focus_get() is c else None))
        c.bind("<Leave>", lambda e: draw(self.REMOVE_BG, "#0a7aff" if c.focus_get() is c else None))
        c.bind("<FocusIn>", lambda e: draw(self.REMOVE_BG, "#0a7aff"))
        c.bind("<FocusOut>", lambda e: draw(self.REMOVE_BG))
        return c

    FORM_LIMIT = 2     # filas visibles por lista; el resto se resume en «… y n más»

    def _form_row(self, card, label: str, entries: List[tuple], actions: List[tuple], empty: str, last: bool = False) -> None:
        """Fila del formulario: etiqueta, lo elegido (nombre y carpeta; «Quitar» por elemento) y las acciones a la derecha."""
        tk, ttk = self.tk, self.ttk
        row = tk.Frame(card, bg=self._card_bg)
        row.pack(fill="x", padx=16, pady=10)
        tk.Label(row, text=label, bg=self._card_bg, fg=self._text_fg, font=self.f_body, anchor="nw", width=13, justify="left").pack(
            side="left", anchor="n")
        act = tk.Frame(row, bg=self._card_bg)
        act.pack(side="right", anchor="n", padx=(10, 0))
        for text, value in actions:
            ttk.Button(act, text=text, command=lambda v=value: self._var.set(v)).pack(side="left", padx=(6, 0))
        col = tk.Frame(row, bg=self._card_bg)
        col.pack(side="left", fill="x", expand=True)
        if not entries:
            tk.Label(col, text=empty, bg=self._card_bg, fg=self._secondary, font=self.f_body, anchor="w").pack(fill="x", pady=(3, 0))
        for path, remove in entries[:self.FORM_LIMIT]:
            line = tk.Frame(col, bg=self._card_bg)
            line.pack(fill="x", pady=(0, 4))
            self._remove_button(line, lambda v=remove: self._var.set(v)).pack(side="right", padx=(8, 0))
            txt = tk.Frame(line, bg=self._card_bg)
            txt.pack(side="left", fill="x", expand=True)
            p = Path(path)
            tk.Label(txt, text=p.name or str(path), bg=self._card_bg, fg=self._text_fg, font=self.f_body, anchor="w").pack(fill="x")
            parent = str(p.parent)
            if parent not in (".", ""):
                tk.Label(txt, text=parent if len(parent) <= 64 else "…" + parent[-63:], bg=self._card_bg, fg=self._secondary,
                         font=self.f_small, anchor="w").pack(fill="x")
        if len(entries) > self.FORM_LIMIT:
            tk.Label(col, text="… y %d más" % (len(entries) - self.FORM_LIMIT), bg=self._card_bg, fg=self._secondary,
                     font=self.f_small, anchor="w").pack(fill="x")
        if not last:
            tk.Frame(card, height=1, bg=self._card_border).pack(fill="x", padx=16)

    def _gather_form(self) -> Dict[str, object]:
        st: Dict[str, object] = {"main": None, "compare": [], "pom": None, "reports": []}
        self.root.geometry("%dx%d" % (self.WIDTH, self.HEIGHT))   # vuelve al tamaño base (p. ej. tras «Nuevo análisis»)
        while True:
            self._clear("Nuevo análisis")
            self._text("¿Qué quieres analizar?", bold=True)
            self._text("Elige el log de la ejecución. El resto es opcional: una ejecución anterior para comparar, el pom.xml "
                       "y los reportes de las herramientas que no venían en la carpeta o el .zip.", small=True)
            card = self._card(pady=(0, 6))
            main, compare, pom, reports = st["main"], st["compare"], st["pom"], st["reports"]
            self._form_row(card, "Log principal", [(main, "rm:main")] if main else [],
                           [("Carpeta…", "main:dir"), ("Archivo…", "main:file")], "Obligatorio: carpeta, .zip o archivo de log")
            self._form_row(card, "Comparación", [(c, "rm:cmp:%d" % i) for i, c in enumerate(compare)],
                           [("Carpeta…", "cmp:dir"), ("Archivo…", "cmp:file")], "Una ejecución anterior, para ver qué mejoró")
            self._form_row(card, "pom.xml", [(pom, "rm:pom")] if pom else [], [("Elegir…", "pom")], "Revisa build, calidad y dependencias")
            self._form_row(card, "Reportes", [(r, "rm:rep:%d" % i) for i, r in enumerate(reports)],
                           [("Archivos…", "rep:files"), ("Carpeta…", "rep:dir")], "PDF, JSON, XML o Markdown de las herramientas", last=True)
            action = self._choice([("Analizar", "go"), ("Cancelar", "skip")], disabled=() if main else ("go",))
            kind, _, arg = action.partition(":")
            if action == "go":
                return {"logs": list(compare) + [main], "pom": pom, "main": main, "reports": list(reports)}
            if action == "skip":
                raise Cancelled()
            if kind == "rm":
                what, _, idx = arg.partition(":")
                if what == "main":
                    st["main"] = None
                elif what == "pom":
                    st["pom"] = None
                else:
                    del st["compare" if what == "cmp" else "reports"][int(idx)]
            elif kind == "main":
                p = self._open(arg, "Selecciona la ejecución a analizar")
                if p and self._accept(p, st, "main"):
                    st["main"] = p
            elif kind == "cmp":
                p = self._open(arg, "Selecciona la ejecución anterior")
                if p and self._accept(p, st, "compare"):
                    compare.append(p)
            elif action == "pom":
                p = self.ask_pom()
                if p and self._accept(p, st, "pom"):
                    st["pom"] = p
            elif action == "rep:files":
                for p in self._open_many("Selecciona los reportes"):
                    if self._accept(p, st, "reports"):
                        reports.append(p)
            elif action == "rep:dir":
                p = self._open("dir", "Selecciona la carpeta con los reportes")
                if p and self._accept(p, st, "reports"):
                    reports.append(p)

    SECTIONS = {"main": "Log principal", "compare": "Comparación", "pom": "pom.xml", "reports": "Reportes"}

    def _accept(self, path: str, st: Dict[str, object], section: str) -> bool:
        """Rechaza (con aviso) un archivo ya elegido en cualquiera de los 4 apartados: misma ruta, no solo el mismo nombre."""
        where = find_duplicate(path, st, skip=(section,) if section in ("main", "pom") else ())
        if where is None:
            return True
        self._warn("Archivo no válido", "«%s» ya está en «%s».\nNo se puede usar el mismo archivo en más de un apartado "
                   "(ni repetirlo). Elige otro; un archivo con el mismo nombre pero en otra carpeta sí es válido."
                   % (Path(path).name, self.SECTIONS[where]))
        return False

    def _warn(self, title: str, detail: str) -> None:
        try:
            self.root.tk.call("tk_messageBox", "-parent", ".", "-type", "ok", "-icon", "warning", "-message", title, "-detail", detail)
        except Exception:
            pass

    # ---------------------------------------------------------------- avance

    def open_progress(self) -> Callable[..., None]:
        tk, ttk = self.tk, self.ttk
        self.busy = True
        self.cancel_requested = False
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
        self.footer.grid_columnconfigure(0, weight=1)
        self.footer.grid_columnconfigure(1, weight=0, minsize=120)
        cancel = ttk.Button(self.footer, text="Cancelar", command=self._request_cancel)
        cancel.grid(row=0, column=1, sticky="ew", padx=6)
        self.buttons["Cancelar"] = cancel
        if self.mac:
            self.root.bind("<Command-period>", lambda e: self._request_cancel())
        self.root.update()

        def listener(pct: float, stage: str = "", detail: str = "", message: Optional[str] = None) -> None:
            if not self.busy:
                return
            if self.cancel_requested:
                raise Cancelled()
            self._bar["value"] = pct * 100
            self._stage["text"] = stage[:80]
            self._detail["text"] = detail[:90]
            if message:
                self._log.configure(state="normal")
                self._log.insert("end", "• " + message + "\n")
                self._log.see("end")
                self._log.configure(state="disabled")
            self.root.update()
            if self.cancel_requested:  # se pidió cancelar durante este ciclo de eventos
                raise Cancelled()

        return listener

    def close_progress(self) -> None:
        self.busy = False
        for seq in ("<Command-period>",):
            self.root.unbind(seq)

    # ---------------------------------------------------------------- resultado

    def _file_list(self, paths: List[str]) -> None:
        """Lista nativa y desplazable de los archivos generados; la carpeta se muestra una vez. Nunca empuja los botones."""
        ttk = self.ttk
        if paths:  # se empaqueta primero (abajo): su espacio queda reservado y la lista cede altura, nunca se recorta
            ttk.Label(self.body, text="Carpeta: " + str(Path(paths[0]).parent) + "\nDoble clic en un archivo para abrirlo",
                      font=self.f_small, foreground=self._secondary,
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
        # el doble clic (o Enter) abre el elemento
        by_name = {Path(p).name: p for p in paths}

        def open_row(_event=None):
            sel = tree.selection()
            if sel and tree.item(sel[0], "text") in by_name:
                self._open_local(by_name[tree.item(sel[0], "text")])
        tree.bind("<Double-1>", open_row)
        tree.bind("<Return>", open_row)


    def show_result(self, verdict: str, counts: Dict[str, int], written: List[str]) -> None:
        self.busy = False
        self._clear("Análisis completado")
        ok = verdict.startswith("Todos")
        pal = self._pal()
        color = pal["ok"] if ok else pal["bad"]
        top = self.tk.Frame(self.body, bg=self._bg)
        top.pack(fill="x", pady=(0, 14))
        badge = self.tk.Canvas(top, width=32, height=32, highlightthickness=0, bd=0, bg=self._bg)
        badge.pack(side="left", padx=(0, 12), anchor="n")
        badge.create_oval(2, 2, 30, 30, fill=color, outline=color)
        badge.create_text(16, 16, text="✓" if ok else "!", fill=pal["on"], font=self.f_head)
        vlabel = self.ttk.Label(top, text=verdict, font=self.f_head, justify="left", anchor="w", wraplength=self.WIDTH - 130,
                                foreground=color)
        vlabel.pack(side="left", fill="x", expand=True)
        self._wrapped.append((vlabel, 44))
        row = self.tk.Frame(self.body, bg=self._bg)
        row.pack(fill="x", pady=(0, 12))
        chips = [(k, v) for k, v in counts.items() if v]
        for k, v in chips:
            self.tk.Label(row, text="%s  %d" % (k, v), bg=MAC_CHIPS.get(k, "#6e6e73"), fg="white", font=self.f_chip,
                          padx=9, pady=2).pack(side="left", padx=(0, 6))
        if not chips:
            self.ttk.Label(row, text="Sin hallazgos", font=self.f_small, foreground=self._secondary).pack(side="left")
        self._file_list(written)
        html = next((w for w in written if w.endswith("reporte_completo.html")), None) or next(
            (w for w in written if w.endswith(".html")), None)
        options = ([("Abrir reporte", "open")] if html else []) + [("Nuevo análisis", "new"), ("Cerrar", "close")]
        self.new_requested = False
        while True:
            try:
                choice = self._choice(options, cancel="close")
            except Cancelled:
                return
            if choice == "open" and html:
                self._open_local(html)      # abrir el reporte no cierra la ventana
                continue
            self.new_requested = choice == "new"
            return

    @staticmethod
    def _open_local(html: str) -> None:
        """Abre un archivo LOCAL (file://) con la aplicación predeterminada. Es el único punto que usa webbrowser."""
        import webbrowser
        webbrowser.open(Path(html).resolve().as_uri())

    def show_error(self, text: str) -> None:
        self.busy = False
        self._clear("Error")
        self._text("⚠  No se pudo completar", bold=True, color=self._pal()["bad"])
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
