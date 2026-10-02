"""Extracción de texto de PDF con solo la biblioteca estándar (zlib + un tokenizador mínimo de objetos PDF).

Cubre lo habitual en reportes generados por herramientas (Chromium/Skia, iText, wkhtmltopdf, ReportLab): objetos en flujos
comprimidos (ObjStm), filtros Flate/ASCIIHex/ASCII85, fuentes simples y Type0 con ``ToUnicode``, y posicionamiento del
texto (matrices Tm/cm) para reconstruir las líneas y las columnas de las tablas. No soporta PDF cifrados ni escaneados
(sin capa de texto): en esos casos ``extract_text`` lanza ``PdfError`` con el motivo.
"""

import re
import zlib
from typing import Any, Dict, List, Optional, Tuple

__all__ = ["PdfError", "extract_text"]


class PdfError(Exception):
    pass


class Name(str):
    """Nombre PDF (``/Algo``) para distinguirlo de una cadena."""


class Ref(tuple):
    """Referencia indirecta ``n g R``."""


_WS = b" \t\r\n\f\x00"
_DELIM = b"()<>[]{}/%"
_NUM = re.compile(rb"[+-]?(?:\d+\.?\d*|\.\d+)")


# ------------------------------------------------------------------------ tokenizador / parser de objetos

class _Lexer:
    def __init__(self, data: bytes, pos: int = 0):
        self.d = data
        self.p = pos

    def _skip(self) -> None:
        d, n = self.d, len(self.d)
        while self.p < n:
            c = d[self.p:self.p + 1]
            if c in (b" ", b"\t", b"\r", b"\n", b"\f", b"\x00"):
                self.p += 1
            elif c == b"%":
                while self.p < n and d[self.p:self.p + 1] not in (b"\r", b"\n"):
                    self.p += 1
            else:
                break

    def token(self) -> Any:
        """Siguiente token: número, Name, bytes (cadena), palabra clave (``bytes`` en un ``_Kw``) o delimitador."""
        self._skip()
        d, n = self.d, len(self.d)
        if self.p >= n:
            return None
        c = d[self.p:self.p + 1]
        if c == b"/":
            self.p += 1
            s = self.p
            while self.p < n and d[self.p:self.p + 1] not in _WS and d[self.p:self.p + 1] not in _DELIM:
                self.p += 1
            raw = d[s:self.p]
            raw = re.sub(rb"#([0-9A-Fa-f]{2})", lambda m: bytes([int(m.group(1), 16)]), raw)
            return Name("/" + raw.decode("latin-1"))
        if c == b"(":
            return self._string()
        if c == b"<":
            if d[self.p:self.p + 2] == b"<<":
                self.p += 2
                return _Kw("<<")
            e = d.find(b">", self.p)
            e = n if e < 0 else e
            hx = re.sub(rb"[^0-9A-Fa-f]", b"", d[self.p + 1:e])
            if len(hx) % 2:
                hx += b"0"
            self.p = e + 1
            return bytes.fromhex(hx.decode("ascii"))
        if c == b">":
            if d[self.p:self.p + 2] == b">>":
                self.p += 2
                return _Kw(">>")
            self.p += 1
            return _Kw(">")
        if c in (b"[", b"]", b"{", b"}"):
            self.p += 1
            return _Kw(c.decode())
        m = _NUM.match(d, self.p)
        if m and (m.end() >= n or d[m.end():m.end() + 1] in _WS or d[m.end():m.end() + 1] in _DELIM):
            self.p = m.end()
            t = m.group(0)
            return float(t) if b"." in t else int(t)
        s = self.p
        while self.p < n and d[self.p:self.p + 1] not in _WS and d[self.p:self.p + 1] not in _DELIM:
            self.p += 1
        if self.p == s:
            self.p += 1
        return _Kw(d[s:self.p].decode("latin-1"))

    def _string(self) -> bytes:
        d, n = self.d, len(self.d)
        self.p += 1
        depth = 1
        out = bytearray()
        while self.p < n:
            c = d[self.p]
            self.p += 1
            if c == 0x5C:  # barra invertida
                if self.p >= n:
                    break
                e = d[self.p]
                self.p += 1
                esc = {0x6E: 10, 0x72: 13, 0x74: 9, 0x62: 8, 0x66: 12}
                if e in esc:
                    out.append(esc[e])
                elif 0x30 <= e <= 0x37:
                    v = e - 0x30
                    for _ in range(2):
                        if self.p < n and 0x30 <= d[self.p] <= 0x37:
                            v = v * 8 + d[self.p] - 0x30
                            self.p += 1
                    out.append(v & 0xFF)
                elif e == 0x0D:
                    if self.p < n and d[self.p] == 0x0A:
                        self.p += 1
                elif e != 0x0A:
                    out.append(e)
            elif c == 0x28:
                depth += 1
                out.append(c)
            elif c == 0x29:
                depth -= 1
                if depth == 0:
                    break
                out.append(c)
            else:
                out.append(c)
        return bytes(out)


class _Kw(str):
    pass


def _parse_value(lx: _Lexer, tok: Any = None, allow_ref: bool = True) -> Any:
    t = lx.token() if tok is None else tok
    if isinstance(t, _Kw):
        if t == "<<":
            out: Dict[str, Any] = {}
            while True:
                k = lx.token()
                if k is None or (isinstance(k, _Kw) and k == ">>"):
                    return out
                if not isinstance(k, Name):
                    continue
                out[str(k)] = _parse_value(lx)
        if t == "[":
            arr: List[Any] = []
            while True:
                x = lx.token()
                if x is None or (isinstance(x, _Kw) and x == "]"):
                    return arr
                arr.append(_parse_value(lx, x))
        if t in ("true", "false"):
            return t == "true"
        return None
    if isinstance(t, int) and not isinstance(t, bool) and allow_ref:
        save = lx.p
        g = lx.token()
        if isinstance(g, int) and not isinstance(g, bool):
            r = lx.token()
            if isinstance(r, _Kw) and r == "R":
                return Ref((t, g))
        lx.p = save
    return t


# ------------------------------------------------------------------------ filtros de flujo

def _ascii85(b: bytes) -> bytes:
    import base64
    b = b.strip()
    if b.startswith(b"<~"):
        b = b[2:]
    if b.endswith(b"~>"):
        b = b[:-2]
    return base64.a85decode(b)


def _decode_stream(raw: bytes, d: Dict[str, Any], resolve) -> bytes:
    filters = resolve(d.get("/Filter"))
    if filters is None:
        return raw
    if not isinstance(filters, list):
        filters = [filters]
    for f in filters:
        f = str(resolve(f))
        if f in ("/FlateDecode", "/Fl"):
            try:
                raw = zlib.decompress(raw)
            except zlib.error:
                dec = zlib.decompressobj()
                try:
                    raw = dec.decompress(raw)
                except zlib.error:
                    raw = b""
            parms = resolve(d.get("/DecodeParms"))
            if isinstance(parms, list):
                parms = resolve(parms[0]) if parms else None
            if isinstance(parms, dict) and (resolve(parms.get("/Predictor")) or 1) >= 10:
                raw = _png_predictor(raw, int(resolve(parms.get("/Columns")) or 1), int(resolve(parms.get("/Colors")) or 1),
                                     int(resolve(parms.get("/BitsPerComponent")) or 8))
        elif f in ("/ASCIIHexDecode", "/AHx"):
            hx = re.sub(rb"[^0-9A-Fa-f]", b"", raw.split(b">")[0])
            raw = bytes.fromhex((hx + (b"0" if len(hx) % 2 else b"")).decode())
        elif f in ("/ASCII85Decode", "/A85"):
            try:
                raw = _ascii85(raw)
            except ValueError:
                raw = b""
        else:
            raise PdfError("filtro de flujo no soportado: %s" % f)
    return raw


def _png_predictor(data: bytes, columns: int, colors: int, bpc: int) -> bytes:
    bpp = max(1, colors * bpc // 8)
    row = (columns * colors * bpc + 7) // 8
    out = bytearray()
    prev = bytearray(row)
    for i in range(0, len(data) - row, row + 1):
        ft = data[i]
        cur = bytearray(data[i + 1:i + 1 + row])
        for j in range(row):
            a = cur[j - bpp] if j >= bpp else 0
            b = prev[j]
            c = prev[j - bpp] if j >= bpp else 0
            if ft == 1:
                cur[j] = (cur[j] + a) & 0xFF
            elif ft == 2:
                cur[j] = (cur[j] + b) & 0xFF
            elif ft == 3:
                cur[j] = (cur[j] + (a + b) // 2) & 0xFF
            elif ft == 4:
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                cur[j] = (cur[j] + (a if pa <= pb and pa <= pc else (b if pb <= pc else c))) & 0xFF
        out += cur
        prev = cur
    return bytes(out)


# ------------------------------------------------------------------------ documento

_OBJ_RE = re.compile(rb"(?<![0-9])(\d+)\s+(\d+)\s+obj\b")


class _Doc:
    def __init__(self, data: bytes):
        self.data = data
        self.objs: Dict[int, Any] = {}          # número -> valor (dict/lista/...) ya parseado
        self.streams: Dict[int, bytes] = {}     # número -> datos crudos del flujo
        self.trailer: Dict[str, Any] = {}
        self._cache: Dict[int, bytes] = {}
        self._scan()
        if "/Encrypt" in self.trailer:
            raise PdfError("el PDF está cifrado")
        self._load_objstm()

    def _scan(self) -> None:
        d = self.data
        for m in _OBJ_RE.finditer(d):
            num = int(m.group(1))
            lx = _Lexer(d, m.end())
            val = _parse_value(lx)
            self.objs[num] = val
            if isinstance(val, dict):
                lx._skip()
                if d[lx.p:lx.p + 6] == b"stream":
                    s = lx.p + 6
                    if d[s:s + 2] == b"\r\n":
                        s += 2
                    elif d[s:s + 1] in (b"\n", b"\r"):
                        s += 1
                    ln = self.resolve(val.get("/Length")) if isinstance(val.get("/Length"), int) else None
                    e = -1
                    if isinstance(ln, int) and d[s + ln:s + ln + 20].lstrip(_WS).startswith(b"endstream"):
                        e = s + ln
                    if e < 0:
                        e = d.find(b"endstream", s)
                        if e < 0:
                            e = len(d)
                        while e > s and d[e - 1:e] in (b"\n", b"\r"):
                            e -= 1
                    self.streams[num] = d[s:e]
        for m in re.finditer(rb"trailer\s*", d):
            t = _parse_value(_Lexer(d, m.end()))
            if isinstance(t, dict):
                self.trailer.update(t)
        for num, v in list(self.objs.items()):  # PDF 1.5: el trailer vive en el flujo XRef
            if isinstance(v, dict) and v.get("/Type") == "/XRef":
                for k in ("/Root", "/Encrypt"):
                    if k in v:
                        self.trailer.setdefault(k, v[k])

    def _load_objstm(self) -> None:
        for num, v in list(self.objs.items()):
            if not (isinstance(v, dict) and v.get("/Type") == "/ObjStm" and num in self.streams):
                continue
            data = self.stream(num)
            n, first = self.resolve(v.get("/N")) or 0, self.resolve(v.get("/First")) or 0
            lx = _Lexer(data[:first])
            pairs = []
            for _ in range(int(n)):
                a, b = lx.token(), lx.token()
                if isinstance(a, int) and isinstance(b, int):
                    pairs.append((a, b))
            for onum, off in pairs:
                if onum not in self.objs:
                    self.objs[onum] = _parse_value(_Lexer(data, first + off))

    def resolve(self, v: Any) -> Any:
        seen = 0
        while isinstance(v, Ref) and seen < 20:
            v = self.objs.get(v[0])
            seen += 1
        return v

    def stream(self, num_or_ref: Any) -> bytes:
        num = num_or_ref[0] if isinstance(num_or_ref, Ref) else num_or_ref
        if num not in self._cache:
            d = self.objs.get(num)
            if not isinstance(d, dict) or num not in self.streams:
                return b""
            self._cache[num] = _decode_stream(self.streams[num], d, self.resolve)
        return self._cache[num]

    # --- páginas
    def pages(self) -> List[Dict[str, Any]]:
        root = self.resolve(self.trailer.get("/Root"))
        out: List[Dict[str, Any]] = []

        def walk(node: Any, inherited: Dict[str, Any], depth: int = 0) -> None:
            node = self.resolve(node)
            if not isinstance(node, dict) or depth > 30:
                return
            inh = dict(inherited)
            if "/Resources" in node:
                inh["/Resources"] = node["/Resources"]
            kids = self.resolve(node.get("/Kids"))
            if isinstance(kids, list):
                for k in kids:
                    walk(k, inh, depth + 1)
            elif node.get("/Type") == "/Page" or "/Contents" in node:
                page = dict(node)
                page.setdefault("/Resources", inh.get("/Resources"))
                out.append(page)

        if isinstance(root, dict):
            walk(root.get("/Pages"), {})
        if not out:  # sin árbol válido: todas las páginas por número de objeto
            out = [v for _, v in sorted(self.objs.items()) if isinstance(v, dict) and v.get("/Type") == "/Page"]
        return out


# ------------------------------------------------------------------------ fuentes

class _Font:
    def __init__(self, doc: _Doc, fd: Any):
        fd = doc.resolve(fd) or {}
        self.two_byte = False
        self.map: Dict[int, str] = {}
        self.ok = False
        sub = str(doc.resolve(fd.get("/Subtype")) or "")
        tu = fd.get("/ToUnicode")
        if tu is not None and isinstance(tu, Ref):
            self.map = _parse_cmap(doc.stream(tu), self)
            self.ok = bool(self.map)
        if sub == "/Type0":
            self.two_byte = True
            if not self.ok:
                enc = str(doc.resolve(fd.get("/Encoding")) or "")
                if enc not in ("/Identity-H", "/Identity-V"):
                    pass  # CMap predefinido sin ToUnicode: no se puede decodificar
        else:
            self.two_byte = False
            if not self.ok:
                self.ok = True  # fuente simple: se interpreta el código como Latin-1/cp1252
            enc = doc.resolve(fd.get("/Encoding"))
            diffs = doc.resolve(enc.get("/Differences")) if isinstance(enc, dict) else None
            if isinstance(diffs, list):
                code = 0
                for x in diffs:
                    x = doc.resolve(x)
                    if isinstance(x, int):
                        code = x
                    elif isinstance(x, Name):
                        ch = _glyph(str(x)[1:])
                        if ch and code not in self.map:
                            self.map[code] = ch
                        code += 1

    def decode(self, b: bytes) -> str:
        out = []
        if self.two_byte:
            for i in range(0, len(b) - 1, 2):
                code = (b[i] << 8) | b[i + 1]
                out.append(self.map.get(code, ""))
            return "".join(out)
        for c in b:
            ch = self.map.get(c)
            if ch is None:
                try:
                    ch = bytes([c]).decode("cp1252")
                except UnicodeDecodeError:
                    ch = bytes([c]).decode("latin-1")
            out.append(ch)
        return "".join(out)


_GLYPHS = {"space": " ", "hyphen": "-", "period": ".", "comma": ",", "colon": ":", "semicolon": ";", "underscore": "_", "slash": "/",
           "backslash": "\\", "parenleft": "(", "parenright": ")", "bracketleft": "[", "bracketright": "]", "braceleft": "{",
           "braceright": "}", "quotesingle": "'", "quotedbl": '"', "at": "@", "numbersign": "#", "percent": "%", "ampersand": "&",
           "asterisk": "*", "plus": "+", "equal": "=", "less": "<", "greater": ">", "question": "?", "exclam": "!", "bar": "|",
           "dollar": "$", "asciitilde": "~", "asciicircum": "^", "grave": "`", "bullet": "•", "endash": "–", "emdash": "—",
           "zero": "0", "one": "1", "two": "2", "three": "3", "four": "4", "five": "5", "six": "6", "seven": "7", "eight": "8",
           "nine": "9", "aacute": "á", "eacute": "é", "iacute": "í", "oacute": "ó", "uacute": "ú", "ntilde": "ñ", "Ntilde": "Ñ",
           "adieresis": "ä", "odieresis": "ö", "udieresis": "ü"}


def _glyph(name: str) -> Optional[str]:
    if name in _GLYPHS:
        return _GLYPHS[name]
    if len(name) == 1:
        return name
    m = re.fullmatch(r"uni([0-9A-Fa-f]{4})", name)
    if m:
        return chr(int(m.group(1), 16))
    return None


def _parse_cmap(data: bytes, font: "_Font") -> Dict[int, str]:
    out: Dict[int, str] = {}

    def u(b: bytes) -> str:
        return b.decode("utf-16-be", "replace") if b else ""

    for blk in re.findall(rb"begincodespacerange(.*?)endcodespacerange", data, re.S):
        m = re.search(rb"<([0-9A-Fa-f]+)>", blk)
        if m:
            font.two_byte = len(m.group(1)) >= 4
    for blk in re.findall(rb"beginbfchar(.*?)endbfchar", data, re.S):
        for a, b in re.findall(rb"<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]*)>", blk):
            out[int(a, 16)] = u(bytes.fromhex(b.decode() + ("0" if len(b) % 2 else "")))
    for blk in re.findall(rb"beginbfrange(.*?)endbfrange", data, re.S):
        for m in re.finditer(rb"<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>\s*(<[0-9A-Fa-f]*>|\[[^\]]*\])", blk):
            lo, hi = int(m.group(1), 16), int(m.group(2), 16)
            if hi - lo > 0xFFFF:
                continue
            dst = m.group(3)
            if dst.startswith(b"["):
                for k, h in enumerate(re.findall(rb"<([0-9A-Fa-f]*)>", dst)):
                    out[lo + k] = u(bytes.fromhex(h.decode()))
            else:
                base = bytes.fromhex(dst[1:-1].decode())
                for k in range(hi - lo + 1):
                    if len(base) >= 2:
                        out[lo + k] = u(base[:-2] + ((int.from_bytes(base[-2:], "big") + k) & 0xFFFF).to_bytes(2, "big"))
                    elif base:
                        out[lo + k] = chr(base[0] + k)
    return out


# ------------------------------------------------------------------------ intérprete de contenido

Matrix = Tuple[float, float, float, float, float, float]
_ID: Matrix = (1, 0, 0, 1, 0, 0)


def _mul(m: Matrix, n: Matrix) -> Matrix:
    """``m × n`` (se aplica primero m): convención de fila de PDF."""
    return (m[0] * n[0] + m[1] * n[2], m[0] * n[1] + m[1] * n[3],
            m[2] * n[0] + m[3] * n[2], m[2] * n[1] + m[3] * n[3],
            m[4] * n[0] + m[5] * n[2] + n[4], m[4] * n[1] + m[5] * n[3] + n[5])


def _page_fragments(doc: _Doc, page: Dict[str, Any]) -> List[Tuple[float, float, float, str]]:
    """Fragmentos de texto de una página como (y, x, tamaño_aprox, texto) en coordenadas de página."""
    res = doc.resolve(page.get("/Resources")) or {}
    contents = page.get("/Contents")
    if isinstance(contents, Ref) and isinstance(doc.objs.get(contents[0]), list):
        contents = doc.objs[contents[0]]
    parts = contents if isinstance(contents, list) else [contents]
    data = b"\n".join(doc.stream(p) for p in parts if isinstance(p, Ref))
    fonts_dict = doc.resolve(res.get("/Font")) or {}
    fonts: Dict[str, _Font] = {}

    def font(name: str) -> Optional[_Font]:
        if name not in fonts:
            fd = fonts_dict.get(name)
            fonts[name] = _Font(doc, fd) if fd is not None else None  # type: ignore[assignment]
        return fonts[name]

    out: List[Tuple[float, float, float, str]] = []
    ctm = _ID
    stack: List[Matrix] = []
    tm = tlm = _ID
    cur: Optional[_Font] = None
    size = 10.0
    leading = 0.0
    operands: List[Any] = []
    lx = _Lexer(data)

    def emit(raw_text: str) -> None:
        if not raw_text:
            return
        m = _mul(tm, ctm)
        out.append((m[5], m[4], abs(size * (m[3] if m[3] else m[1] or 1)), raw_text))

    def advance(text_len: int) -> None:  # avance horizontal aproximado para varios Tj seguidos en la misma línea
        nonlocal tm
        tm = _mul((1, 0, 0, 1, text_len * size * 0.5, 0), tm)

    while True:
        t = lx.token()
        if t is None:
            break
        if not isinstance(t, _Kw) or t in ("[", "<<"):
            operands.append(_parse_value(lx, t, allow_ref=False) if isinstance(t, _Kw) else t)
            continue
        op = str(t)
        a = operands
        try:
            if op == "q":
                stack.append(ctm)
            elif op == "Q":
                ctm = stack.pop() if stack else _ID
            elif op == "cm" and len(a) >= 6:
                ctm = _mul(tuple(float(x) for x in a[-6:]), ctm)  # type: ignore[arg-type]
            elif op == "BT":
                tm = tlm = _ID
            elif op == "Tf" and len(a) >= 2:
                cur = font(str(a[-2]))
                size = float(a[-1])
            elif op == "TL" and a:
                leading = float(a[-1])
            elif op in ("Td", "TD") and len(a) >= 2:
                if op == "TD":
                    leading = -float(a[-1])
                tlm = _mul((1, 0, 0, 1, float(a[-2]), float(a[-1])), tlm)
                tm = tlm
            elif op == "Tm" and len(a) >= 6:
                tm = tlm = tuple(float(x) for x in a[-6:])  # type: ignore[assignment]
            elif op == "T*":
                tlm = _mul((1, 0, 0, 1, 0, -leading), tlm)
                tm = tlm
            elif op in ("Tj", "'", '"') and a and cur is not None:
                if op != "Tj":
                    tlm = _mul((1, 0, 0, 1, 0, -leading), tlm)
                    tm = tlm
                if isinstance(a[-1], bytes):
                    s = cur.decode(a[-1])
                    emit(s)
                    advance(len(s))
            elif op == "TJ" and a and isinstance(a[-1], list) and cur is not None:
                buf = []
                for x in a[-1]:
                    if isinstance(x, bytes):
                        buf.append(cur.decode(x))
                    elif isinstance(x, (int, float)) and x < -250:  # hueco grande = separación de palabra
                        buf.append(" ")
                s = "".join(buf)
                emit(s)
                advance(len(s))
        except (ValueError, TypeError, IndexError):
            pass
        operands = []
    return out


def _page_text(doc: _Doc, page: Dict[str, Any]) -> str:
    frags = _page_fragments(doc, page)
    if not frags:
        return ""
    # Agrupa por línea: misma y (con tolerancia relativa al tamaño de letra), de izquierda a derecha.
    frags.sort(key=lambda f: -f[0])
    lines: List[List[Tuple[float, float, float, str]]] = []
    for f in frags:
        if lines and abs(lines[-1][0][0] - f[0]) <= max(1.5, f[2] * 0.35):
            lines[-1].append(f)
        else:
            lines.append([f])
    out = []
    for ln in lines:
        ln.sort(key=lambda f: f[1])
        s = ""
        for f in ln:
            txt = f[3]
            if s and not s.endswith(" ") and not txt.startswith(" "):
                s += "  "
            s += txt
        if s.strip():
            out.append(s.rstrip())
    return "\n".join(out)


# ------------------------------------------------------------------------ API

def extract_text(path: Any, max_pages: int = 2000) -> List[str]:
    """Texto de cada página del PDF (una cadena por página, con una línea de texto por renglón visual).

    Lanza ``PdfError`` si el archivo no es un PDF, está cifrado o no tiene texto extraíble.
    """
    path = str(path)
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        raise PdfError("no se pudo leer el archivo: %s" % exc)
    if b"%PDF-" not in data[:1024]:
        raise PdfError("no es un PDF")
    pages: List[str] = []
    err: Optional[Exception] = None
    try:
        doc = _Doc(data)
        for pg in doc.pages()[:max_pages]:
            pages.append(_page_text(doc, pg))
    except PdfError as exc:
        err = exc
    except (RecursionError, ValueError, KeyError, IndexError, TypeError, zlib.error) as exc:
        err = PdfError("estructura del PDF no soportada (%s)" % exc.__class__.__name__)
    if not any(p.strip() for p in pages):
        if err:
            raise err
        raise PdfError("el PDF no tiene texto extraíble (¿está escaneado o usa fuentes sin ToUnicode?)")
    return pages
