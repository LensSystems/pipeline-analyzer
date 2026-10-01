"""Generador de PDF (solo biblioteca estándar) para los reportes.

Usa las fuentes estándar Helvetica y Courier (no hay que incrustar fuentes) con codificación WinAnsi (cp1252), así que
conserva acentos y eñes. El ajuste de línea usa las métricas reales de Helvetica; el código va en Courier. Soporta
tablas con celdas ajustadas, tarjetas, etiquetas de color, enlaces internos, marcadores (outline) y paginación.
"""

import unicodedata
from . import BRAND
from typing import Callable, Dict, List, Optional, Sequence, Tuple

Color = Tuple[float, float, float]

INK: Color = (0.11, 0.11, 0.10)
MUTED: Color = (0.42, 0.42, 0.40)
RED: Color = (0.71, 0.14, 0.09)
AMBER: Color = (0.60, 0.40, 0.0)
BLUE: Color = (0.18, 0.37, 0.65)
GREEN: Color = (0.12, 0.48, 0.30)
BAND: Color = (0.13, 0.17, 0.25)
RULE: Color = (0.82, 0.81, 0.78)
ZEBRA: Color = (0.972, 0.970, 0.962)
HEAD: Color = (0.92, 0.91, 0.88)
CODE: Color = (0.945, 0.945, 0.93)
WHITE: Color = (1, 1, 1)

# Anchos de Helvetica / Helvetica-Bold (AFM estándar), caracteres 32..126, en milésimas de em
_REG = [278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278] + [556] * 10 + \
    [278, 278, 584, 584, 584, 556, 1015] + \
    [667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611] + \
    [278, 278, 278, 469, 556, 333] + \
    [556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556, 556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500] + \
    [334, 260, 334, 584]
_BOLD = [278, 333, 474, 556, 556, 889, 722, 238, 333, 333, 389, 584, 278, 333, 278, 278] + [556] * 10 + \
    [333, 333, 584, 584, 584, 611, 975] + \
    [722, 722, 722, 722, 667, 611, 778, 722, 278, 556, 722, 611, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611] + \
    [333, 278, 333, 584, 556, 333] + \
    [556, 611, 556, 611, 556, 333, 611, 611, 278, 278, 556, 278, 889, 611, 611, 611, 611, 389, 556, 333, 611, 556, 778, 556, 556, 500] + \
    [389, 280, 389, 584]
_EXTRA = {"¿": 611, "¡": 333, "°": 400, "·": 278, "–": 556, "—": 1000, "•": 350, "…": 1000, "«": 556, "»": 556, "©": 737,
          "×": 584, "€": 556, "ß": 611, "º": 365, "ª": 370}

_TRANSLIT = {"→": "->", "←": "<-", "↑": "^", "↓": "v", "✔": "OK", "✅": "OK", "❌": "X", "⚠": "!", "⚙": "*", "▲": "^", "▼": "v",
             "│": "|", "█": "#", "░": ".", "≥": ">=", "≤": "<=", "\t": "    ", "\r": "", " ": " ", "’": "'", "‘": "'"}


def _latin(s: str) -> str:
    out = []
    for ch in s:
        try:
            ch.encode("cp1252")
            out.append(ch)
        except UnicodeEncodeError:
            out.append(_TRANSLIT.get(ch, "?"))
    return "".join(out)


def _pdf_str(s: str) -> str:
    out = []
    for b in _latin(s).encode("cp1252", "replace"):
        c = chr(b)
        if c in "\\()":
            out.append("\\" + c)
        elif 32 <= b < 127:
            out.append(c)
        else:
            out.append("\\%03o" % b)
    return "".join(out)


def _f(x: float) -> str:
    return ("%.2f" % x).rstrip("0").rstrip(".") or "0"


def _char_w(ch: str, bold: bool) -> int:
    o = ord(ch)
    table = _BOLD if bold else _REG
    if 32 <= o < 127:
        return table[o - 32]
    if ch in _EXTRA:
        return _EXTRA[ch]
    base = unicodedata.normalize("NFD", ch)[0]
    if base != ch and 32 <= ord(base) < 127:
        return table[ord(base) - 32]
    return 556


def text_width(s: str, size: float, bold: bool = False) -> float:
    return sum(_char_w(c, bold) for c in s) * size / 1000.0


def tint(c: Color, k: float = 0.88) -> Color:
    """Versión clara de un color (fondo de etiquetas y tarjetas)."""
    return tuple(1 - (1 - v) * (1 - k) for v in c)  # type: ignore[return-value]


class PdfDoc:
    W, H, M = 595.28, 841.89, 42.0  # A4 vertical
    BODY, LEAD = 9.0, 12.5

    def __init__(self, title: str, footer: str = "", footer_color: Color = MUTED,
                 scrub: Optional[Callable[[str], str]] = None):
        self.title, self.footer, self.footer_color = title, footer, footer_color
        self.scrub = scrub or (lambda s: s)
        self.pages: List[List[str]] = []
        self.links: List[List[Tuple[float, float, float, float, str]]] = []
        self.dests: Dict[str, Tuple[int, float]] = {}
        self.outline: List[Tuple[str, str]] = []  # (título, ancla) de los encabezados de nivel 1
        self.y = 0.0
        self._new_page()

    # ------------------------------------------------------------ geometría
    @property
    def cw(self) -> float:
        return self.W - 2 * self.M

    def _new_page(self) -> None:
        self.pages.append([])
        self.links.append([])
        self.y = self.H - self.M

    def _ensure(self, h: float) -> None:
        if self.y - h < self.M + 16:
            self._new_page()

    def _s(self, text) -> str:
        return _latin(self.scrub(str(text)))

    def space(self, h: float = 6) -> None:
        self.y -= h

    def anchor(self, name: str) -> None:
        self.dests[name] = (len(self.pages) - 1, self.y + 14)

    # ------------------------------------------------------------ primitivas
    def _text(self, x: float, y: float, s: str, size: Optional[float] = None, bold: bool = False, color: Color = INK,
              mono: bool = False) -> None:
        if not s:
            return
        font = "F3" if mono else ("F2" if bold else "F1")
        self.pages[-1].append("BT /%s %s Tf %s %s %s rg %s %s Td (%s) Tj ET"
                              % (font, _f(size or self.BODY), _f(color[0]), _f(color[1]), _f(color[2]), _f(x), _f(y), _pdf_str(s)))

    def _rect(self, x: float, y: float, w: float, h: float, fill: Optional[Color] = None, stroke: Optional[Color] = None) -> None:
        ops = []
        if fill:
            ops.append("%s %s %s rg" % tuple(_f(v) for v in fill))
        if stroke:
            ops.append("%s %s %s RG 0.6 w" % tuple(_f(v) for v in stroke))
        ops.append("%s %s %s %s re %s" % (_f(x), _f(y), _f(w), _f(h), "B" if fill and stroke else ("f" if fill else "S")))
        self.pages[-1].append(" ".join(ops))

    def _hline(self, x0: float, x1: float, y: float, color: Color = RULE) -> None:
        self.pages[-1].append("%s %s %s RG 0.5 w %s %s m %s %s l S" % (_f(color[0]), _f(color[1]), _f(color[2]), _f(x0), _f(y), _f(x1), _f(y)))

    def _link(self, x0: float, y0: float, x1: float, y1: float, name: Optional[str]) -> None:
        if name:
            self.links[-1].append((x0, y0, x1, y1, name))

    @staticmethod
    def _wrap(text: str, width: float, size: float, bold: bool = False) -> List[str]:
        """Ajuste de línea con métricas reales; parte las palabras más largas que el ancho (rutas, hashes)."""
        out: List[str] = []
        for raw in text.split("\n"):
            if not raw.strip():
                out.append("")
                continue
            line, w = "", 0.0
            space = text_width(" ", size, bold)
            for word in raw.split(" "):
                ww = text_width(word, size, bold)
                if ww > width:  # palabra más larga que la línea: corte por caracteres
                    if line:
                        out.append(line)
                        line, w = "", 0.0
                    chunk, cwid = "", 0.0
                    for ch in word:
                        chw = _char_w(ch, bold) * size / 1000.0
                        if cwid + chw > width and chunk:
                            out.append(chunk)
                            chunk, cwid = "", 0.0
                        chunk += ch
                        cwid += chw
                    line, w = chunk, cwid
                    continue
                add = ww if not line else ww + space
                if line and w + add > width:
                    out.append(line)
                    line, w = word, ww
                else:
                    line += (" " if line else "") + word
                    w += add
            out.append(line)
        return out

    # ------------------------------------------------------------ bloques
    def header_band(self, title: str, subtitle: str, color: Color = BAND) -> None:
        """Banda de portada en la primera página."""
        h = 84.0
        self._rect(0, self.H - h, self.W, h, fill=color)
        self._text(self.M, self.H - 40, self._s(title), 21, True, WHITE)
        self._text(self.M, self.H - 62, self._s(subtitle), 9, False, (0.80, 0.83, 0.90))
        self.y = self.H - h - 16

    def banner(self, text: str, color: Color = RED) -> None:
        lines = self._wrap(self._s(text), self.cw - 20, 8.5, True)
        h = len(lines) * 11 + 10
        self._ensure(h + 6)
        self._rect(self.M, self.y - h, self.cw, h, fill=tint(color, 0.9), stroke=color)
        for i, ln in enumerate(lines):
            self._text(self.M + 10, self.y - 14 - i * 11, ln, 8.5, True, color)
        self.y -= h + 8

    def verdict(self, text: str, ok: bool) -> None:
        col = GREEN if ok else RED
        lines = self._wrap(self._s(text), self.cw - 28, 11.5, True)
        h = len(lines) * 15 + 14
        self._ensure(h + 8)
        self._rect(self.M, self.y - h, self.cw, h, fill=tint(col, 0.9))
        self._rect(self.M, self.y - h, 4, h, fill=col)
        for i, ln in enumerate(lines):
            self._text(self.M + 16, self.y - 19 - i * 15, ln, 11.5, True, col)
        self.y -= h + 10

    def cards(self, items: Sequence[Tuple[str, str, str, Color, Optional[str]]], per_row: int = 3) -> None:
        """Tarjetas de estado: (nombre, estado, detalle, color, ancla opcional)."""
        gap = 8.0
        w = (self.cw - gap * (per_row - 1)) / per_row
        for i in range(0, len(items), per_row):
            row = items[i:i + per_row]
            prepared = []
            for name, status, detail, col, link in row:
                dl = self._wrap(self._s(detail), w - 16, 7.8)
                nl = self._wrap(self._s(name), w - 16, 7.8, True)
                prepared.append((nl, self._s(status), dl, col, link))
            h = max(len(nl) * 10 + 14 + len(dl) * 10 + 14 for nl, _st, dl, _c, _l in prepared)
            self._ensure(h + 8)
            for j, (nl, st, dl, col, link) in enumerate(prepared):
                x = self.M + j * (w + gap)
                self._rect(x, self.y - h, w, h, fill=(0.985, 0.985, 0.975), stroke=RULE)
                self._rect(x, self.y - h, 3, h, fill=col)
                yy = self.y - 12
                for ln in nl:
                    self._text(x + 10, yy, ln, 7.8, True, MUTED)
                    yy -= 10
                self._text(x + 10, yy - 4, st, 11, True, col)
                yy -= 18
                for ln in dl:
                    self._text(x + 10, yy, ln, 7.8, False, MUTED)
                    yy -= 10
                self._link(x, self.y - h, x + w, self.y, link)
            self.y -= h + 8

    def chips(self, items: Sequence[Tuple[str, Color]]) -> None:
        x, size = self.M, 7.8
        self._ensure(20)
        for text, col in items:
            text = self._s(text)
            w = text_width(text, size, True) + 12
            if x + w > self.W - self.M:
                x = self.M
                self.y -= 17
                self._ensure(20)
            self._rect(x, self.y - 13, w, 14, fill=tint(col, 0.86))
            self._text(x + 6, self.y - 9.5, text, size, True, col)
            x += w + 5
        self.y -= 22

    def heading(self, text: str, level: int = 1, anchor: Optional[str] = None) -> None:
        size = {1: 14.5, 2: 11.0}.get(level, 10.0)
        if level == 1:
            self._ensure(60)
            self.space(14)
            if anchor:
                self.outline.append((self._s(text), anchor))
        else:
            self._ensure(44)
            self.space(8)
        if anchor:
            self.anchor(anchor)
        lines = self._wrap(self._s(text), self.cw - (10 if level == 1 else 0), size, True)
        top = self.y
        for ln in lines:
            self.y -= size + 3.5
            self._text(self.M + (10 if level == 1 else 0), self.y, ln, size, True, INK)
        if level == 1:
            self._rect(self.M, self.y - 3, 4, top - self.y + 3 + size * 0.6, fill=BLUE)
            self.y -= 6
            self._hline(self.M, self.W - self.M, self.y)
        self.y -= 5

    def para(self, text: str, color: Color = INK, bold: bool = False, indent: float = 0, link: Optional[str] = None,
             prefix: str = "", size: Optional[float] = None) -> None:
        size = size or self.BODY
        lead = size * 1.4
        pw = text_width(prefix, size, bold) if prefix else 0.0
        width = self.cw - indent - pw
        for i, ln in enumerate(self._wrap(self._s(text), width, size, bold)):
            self._ensure(lead)
            self.y -= lead
            x = self.M + indent
            if prefix and i == 0:
                self._text(x, self.y, prefix, size, bold, color)
            self._text(x + pw, self.y, ln, size, bold, color)
            if link and ln:
                self._link(x + pw, self.y - 3, x + pw + text_width(ln, size, bold), self.y + size, link)

    def bullet(self, text: str, indent: float = 10, color: Color = INK) -> None:
        self.para(text, color, indent=indent, prefix="•  ")

    def code(self, text: str, indent: float = 12) -> None:
        size = 7.4
        cwid = 0.6 * size
        n = max(10, int((self.cw - indent - 10) / cwid))
        lines: List[str] = []
        for raw in self._s(text).split("\n"):
            raw = raw.rstrip()
            lines += [raw[i:i + n] for i in range(0, len(raw), n)] or [""]
        lead = 9.6
        for ln in lines:
            self._ensure(lead)
            self.y -= lead
            self._rect(self.M + indent, self.y - 2.4, self.cw - indent, lead, fill=CODE)
            self._text(self.M + indent + 4, self.y, ln, size, False, INK, mono=True)
        self.y -= 4

    def badge_line(self, badge: str, color: Color, title: str, size: float = 10.0, anchor: Optional[str] = None) -> None:
        """Encabezado de hallazgo: etiqueta de severidad + título en negrita."""
        bsize = 6.8
        badge = self._s(badge)
        bw = text_width(badge, bsize, True) + 10
        self._ensure(48)
        self.space(8)
        if anchor:
            self.anchor(anchor)
        lines = self._wrap(self._s(title), self.cw - bw - 8, size, True)
        self.y -= size + 3
        self._rect(self.M, self.y - 2.6, bw, 11.5, fill=color)
        self._text(self.M + 5, self.y + 0.6, badge, bsize, True, WHITE)
        for i, ln in enumerate(lines):
            self._text(self.M + bw + 8, self.y, ln, size, True, INK)
            if i < len(lines) - 1:
                self._ensure(size + 3)
                self.y -= size + 3
        self.y -= 2

    def toc(self, entries: Sequence[Tuple[str, str, int]]) -> None:
        self.heading("Contenido", 2)
        for title, anchor, page in entries:
            self._ensure(14)
            self.y -= 14
            t = self._s(title)
            self._text(self.M + 4, self.y, t, 9.5, False, BLUE)
            pg = str(page)
            pw = text_width(pg, 9.5)
            self._text(self.W - self.M - pw, self.y, pg, 9.5, False, MUTED)
            tw = text_width(t, 9.5)
            dots_x0, dots_x1 = self.M + 4 + tw + 6, self.W - self.M - pw - 6
            if dots_x1 > dots_x0:
                self.pages[-1].append("[1 3] 0 d %s %s %s RG 0.5 w %s %s m %s %s l S [] 0 d"
                                      % (_f(RULE[0]), _f(RULE[1]), _f(RULE[2]), _f(dots_x0), _f(self.y + 2.5), _f(dots_x1), _f(self.y + 2.5)))
            self._link(self.M, self.y - 3, self.W - self.M, self.y + 10, anchor)
        self.y -= 4

    def table(self, headers: Sequence[str], rows: Sequence[Sequence[str]],
              color_of: Optional[Callable[[int, str], Optional[Color]]] = None, links: Optional[Sequence[Optional[str]]] = None,
              size: float = 8.0) -> None:
        """Tabla a todo el ancho con celdas ajustadas y encabezado repetido al cambiar de página."""
        headers = [self._s(h) for h in headers]
        rows = [[self._s(c) for c in r] for r in rows]
        n = len(headers)
        pad = 4.5
        avail = self.cw - 2 * pad * n
        nat = [max([text_width(headers[i], size, True)] +
                   [max((text_width(l, size) for l in r[i].split("\n")), default=0) for r in rows]) for i in range(n)]
        mn = [min(nat[i], max(text_width(headers[i], size, True),
                              max((text_width(w, size) for r in rows for w in r[i].split()), default=0) if rows else 0, 26))
              for i in range(n)]
        mn = [min(m, nat[i]) for i, m in enumerate(mn)]
        if sum(nat) <= avail:  # reparte el sobrante proporcionalmente
            extra = avail - sum(nat)
            widths = [nat[i] + extra * (nat[i] / (sum(nat) or 1)) for i in range(n)]
        elif sum(mn) >= avail:
            widths = [avail * m / (sum(mn) or 1) for m in mn]
        else:
            k = (avail - sum(mn)) / ((sum(nat) - sum(mn)) or 1)
            widths = [mn[i] + (nat[i] - mn[i]) * k for i in range(n)]
        lead = size * 1.32

        def draw_row(cells: Sequence[str], head: bool, zebra: bool, link: Optional[str]) -> None:
            wrapped = [self._wrap(cells[i], widths[i], size, head) or [""] for i in range(n)]
            h = max(len(w) for w in wrapped) * lead + 7
            if self.y - h < self.M + 16:
                self._new_page()
                draw_row(headers_cells, True, False, None)
            top = self.y
            if head:
                self._rect(self.M, top - h, self.cw, h, fill=HEAD)
            elif zebra:
                self._rect(self.M, top - h, self.cw, h, fill=ZEBRA)
            x = self.M + pad
            for i in range(n):
                col = color_of(i, cells[i]) if (color_of and not head) else None
                for j, ln in enumerate(wrapped[i]):
                    self._text(x, top - 3.5 - (j + 1) * lead + 2.4, ln, size, head or bool(col), col or INK)
                x += widths[i] + 2 * pad
            self._hline(self.M, self.W - self.M, top - h)
            self._link(self.M, top - h, self.W - self.M, top, link)
            self.y = top - h

        headers_cells = headers
        self.space(2)
        self._hline(self.M, self.W - self.M, self.y)
        self._ensure(40)
        draw_row(headers, True, False, None)
        for k, r in enumerate(rows):
            draw_row(r, False, k % 2 == 1, links[k] if links else None)
        self.space(8)

    # ------------------------------------------------------------ salida
    def render(self) -> bytes:
        total = len(self.pages)
        corner = 14.0  # mismo espacio hasta el borde derecho y hasta el borde inferior: distintivo uniforme en la esquina
        for i in range(total):
            # Pie en tres zonas (izquierda: documento · centro: aviso · derecha: página) y, aparte y más abajo, el distintivo.
            self.pages[i].append("%s %s %s RG 0.5 w %s 44 m %s 44 l S" % (_f(RULE[0]), _f(RULE[1]), _f(RULE[2]), _f(self.M), _f(self.W - self.M)))
            left = "pipeline-analyzer  ·  %s" % self.title
            self.pages[i].append("BT /F1 7.2 Tf %s %s %s rg %s 32 Td (%s) Tj ET" % (
                _f(MUTED[0]), _f(MUTED[1]), _f(MUTED[2]), _f(self.M), _pdf_str(left)))
            label = "Página %d de %d" % (i + 1, total)
            self.pages[i].append("BT /F1 7.2 Tf %s %s %s rg %s 32 Td (%s) Tj ET" % (
                _f(MUTED[0]), _f(MUTED[1]), _f(MUTED[2]), _f(self.W - self.M - text_width(label, 7.2)), _pdf_str(label)))
            if self.footer:
                c = self.footer_color
                self.pages[i].append("BT /F2 7.2 Tf %s %s %s rg %s 32 Td (%s) Tj ET" % (
                    _f(c[0]), _f(c[1]), _f(c[2]), _f((self.W - text_width(self.footer, 7.2, True)) / 2), _pdf_str(self.footer)))
            # distintivo en la esquina inferior derecha, discreto y separado del pie
            self.pages[i].append("BT /F2 8 Tf 0.6 0.6 0.58 rg %s %s Td (%s) Tj ET" % (
                _f(self.W - corner - text_width(BRAND, 8, True)), _f(corner + 1.5), _pdf_str(BRAND)))

        objs: List[bytes] = []

        def add(body: str) -> int:
            objs.append(body.encode("latin-1"))
            return len(objs)

        add("CATALOG")  # 1
        add("PAGES")  # 2
        add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")  # 3
        add("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>")  # 4
        add("<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>")  # 5
        add("<< /Title (%s) /Producer (pipeline-analyzer) >>" % _pdf_str(self.title))  # 6
        first = 7
        page_ids = [first + 2 * i for i in range(total)]
        next_id = first + 2 * total
        annots_by_page: List[List[int]] = []
        annot_bodies: List[Tuple[int, str]] = []
        for i in range(total):
            ids = []
            for (x0, y0, x1, y1, name) in self.links[i]:
                if name not in self.dests:
                    continue
                pg, dy = self.dests[name]
                annot_bodies.append((next_id, "<< /Type /Annot /Subtype /Link /Rect [%s %s %s %s] /Border [0 0 0] /Dest [%d 0 R /XYZ 0 %s 0] >>"
                                     % (_f(x0), _f(y0), _f(x1), _f(y1), page_ids[pg], _f(dy))))
                ids.append(next_id)
                next_id += 1
            annots_by_page.append(ids)
        objs = objs[:6]
        for i in range(total):
            ann = (" /Annots [%s]" % " ".join("%d 0 R" % a for a in annots_by_page[i])) if annots_by_page[i] else ""
            add("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %s %s] /Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> >> /Contents %d 0 R%s >>"
                % (_f(self.W), _f(self.H), page_ids[i] + 1, ann))
            data = "\n".join(self.pages[i]).encode("latin-1", "replace")
            objs.append(b"<< /Length %d >>\nstream\n" % len(data) + data + b"\nendstream")
        for _id, body in annot_bodies:
            add(body)

        # marcadores (panel de navegación del visor)
        marks = [(t, a) for t, a in self.outline if a in self.dests]
        outlines_ref = ""
        if marks:
            root_id = len(objs) + 1
            item_ids = [root_id + 1 + k for k in range(len(marks))]
            add("<< /Type /Outlines /First %d 0 R /Last %d 0 R /Count %d >>" % (item_ids[0], item_ids[-1], len(marks)))
            for k, (t, a) in enumerate(marks):
                pg, dy = self.dests[a]
                links = (" /Prev %d 0 R" % item_ids[k - 1] if k else "") + (" /Next %d 0 R" % item_ids[k + 1] if k < len(marks) - 1 else "")
                add("<< /Title (%s) /Parent %d 0 R%s /Dest [%d 0 R /XYZ 0 %s 0] >>" % (_pdf_str(t), root_id, links, page_ids[pg], _f(dy)))
            outlines_ref = " /Outlines %d 0 R /PageMode /UseOutlines" % root_id
        objs[0] = ("<< /Type /Catalog /Pages 2 0 R%s >>" % outlines_ref).encode("latin-1")
        objs[1] = ("<< /Type /Pages /Kids [%s] /Count %d >>" % (" ".join("%d 0 R" % p for p in page_ids), total)).encode("latin-1")

        out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = []
        for n, body in enumerate(objs, 1):
            offsets.append(len(out))
            out += b"%d 0 obj\n" % n + body + b"\nendobj\n"
        xref = len(out)
        out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
        for off in offsets:
            out += b"%010d 00000 n \n" % off
        out += b"trailer\n<< /Size %d /Root 1 0 R /Info 6 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, xref)
        return bytes(out)
