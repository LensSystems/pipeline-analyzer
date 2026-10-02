"""Lectura de los PDF que se descargan de Checkmarx (CxOne) y cruce con los resultados del log y del JSON.

El PDF trae el detalle de los hallazgos SAST, SCA y SCS (consulta o CVE, severidad, estado, archivo y línea); el log del
pipeline solo trae conteos. ``parse_cxone_pdf`` convierte el texto del PDF en hallazgos con el mismo formato que usa
``tool_reports`` y ``reconcile`` los compara con lo que reportó el pipeline. Es tolerante: el diseño del PDF cambia entre
versiones y plantillas, así que se apoya en patrones (CVE, nombres de consulta, ``archivo:línea``, palabras de severidad)
y no en posiciones fijas.
"""

import re
from collections import Counter
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .cxone_scanreport import parse_scan_report
from .pdf_reader import PdfError, extract_text

SEVS = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
_SEV_WORD = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "info": "INFO", "informational": "INFO"}
_SEV_RE = re.compile(r"\b(critical|high|medium|low|informational|info)\b", re.I)
_SEV_ONLY_RE = re.compile(r"^\W*(critical|high|medium|low|informational|info)\b(?:\s+(?:severity|risk|vulnerabilities|results))?\W*(?:\(?\d+\)?)?\W*$", re.I)
_CVE_RE = re.compile(r"\b(CVE-\d{4}-\d{4,7}|GHSA(?:-[0-9a-z]{4}){3}|Cx[0-9A-Fa-f]{6,}-[0-9A-Za-z]+)\b")
_QUERY_RE = re.compile(r"^[A-Z][A-Za-z0-9]*(?:_[A-Za-z0-9]+)+$")
_QUERY_LABEL_RE = re.compile(r"^(?:vulnerability|query|name|rule|finding|issue)\s*[:\-]\s*(.+)$", re.I)
_EXT = r"(?:java|kt|kts|scala|groovy|js|jsx|mjs|cjs|ts|tsx|py|cs|vb|go|rb|php|c|cc|cpp|h|hpp|swift|m|sql|xml|ya?ml|json|gradle|properties|html?|jsp|tf|tfvars|dockerfile|sh|ps1|pom|config|conf|env|ini|toml)"
_LOC_RE = re.compile(r"((?:[A-Za-z]:)?[\w@$.\-/\\]*[\w\-]\.%s)\s*(?:[:#(]|\bline\b\s*[:#]?\s*|\s{1,3}(?=\d))\s*(\d+)\)?" % _EXT, re.I)
_FILE_ONLY_RE = re.compile(r"((?:[A-Za-z]:)?[\w@$.\-]+(?:[/\\][\w@$.\-]+)+\.%s)\b" % _EXT, re.I)
_PKG_RE = re.compile(r"\b([\w.\-]+:[\w.\-]+(?::|-)\d[\w.\-+]*|(?:npm|pypi|nuget|maven|go|gem|composer)[\-:/][\w.@/\-]+(?:[@\-:]\d[\w.\-+]*)?)\b", re.I)
_STATE_RE = re.compile(r"\b(proposed not exploitable|not exploitable|to verify|confirmed|urgent|ignored|not ignored)\b", re.I)
_STATUS_RE = re.compile(r"\b(?:status)\s*[:\-]?\s*(new|recurrent|fixed)\b|\b(new|recurrent|fixed)\b", re.I)
_CWE_RE = re.compile(r"\bCWE[\s\-:]*(\d+)\b", re.I)
_REC_RE = re.compile(r"recommended(?:\s+version)?\s*[:\-]?\s*([\w.\-+]+)|(?:upgrade|update|actualiz\w+)\s+to\s+([\w.\-+]+)", re.I)
_SUMMARY_ROW_RE = re.compile(r"^\s*(SAST|SCA|SCS|IAC|APIS?|CONTAINERS|SECRET DETECTION)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\b", re.I)
_ENGINE_HEAD = (
    (re.compile(r"\bSAST\b|static application security|static analysis", re.I), "SAST"),
    (re.compile(r"\bSCA\b|software composition|open source|dependenc", re.I), "SCA"),
    (re.compile(r"\bSCS\b|supply chain|secret detection|\bscorecard\b", re.I), "SCS"),
    (re.compile(r"\bIaC\b|infrastructure as code|kics", re.I), "IAC"),
    (re.compile(r"\bcontainers?\b", re.I), "CONTAINERS"),
)
_STATE_NORM = {"to verify": "TO_VERIFY", "not exploitable": "NOT_EXPLOITABLE", "proposed not exploitable": "PROPOSED_NOT_EXPLOITABLE",
               "confirmed": "CONFIRMED", "urgent": "URGENT", "ignored": "IGNORED", "not ignored": "NOT_IGNORED"}
_SKIP_STATES = {"NOT_EXPLOITABLE", "IGNORED"}


def _is_heading(line: str) -> bool:
    return len(line) < 70 and not _LOC_RE.search(line) and not _CVE_RE.search(line)


def _engine_of(line: str) -> Optional[str]:
    if not _is_heading(line):
        return None
    for rx, name in _ENGINE_HEAD:
        if rx.search(line):
            return name
    return None


def _norm(page_lines: Iterable[str]) -> List[str]:
    out = []
    for ln in page_lines:
        ln = ln.replace(" ", " ").strip()
        if ln:
            out.append(ln)
    return out


# ------------------------------------------------------------------------ interpretación del texto

def _meta(lines: List[str]) -> Dict[str, str]:
    meta: Dict[str, str] = {}
    pats = {"project": r"project(?:\s+name)?\s*[:\-]\s*(.+)", "branch": r"branch\s*[:\-]\s*(.+)", "scan_id": r"scan\s*id\s*[:\-]\s*([0-9a-f\-]{8,})",
            "risk_level": r"risk level\s*[:\-]\s*(.+)", "created": r"(?:scan\s+)?(?:created|date|finished)\s*[:\-]\s*(.+)"}
    for ln in lines[:200]:
        for k, rx in pats.items():
            if k not in meta:
                m = re.search(rx, ln, re.I)
                if m:
                    meta[k] = re.split(r"\s{2,}", m.group(1).strip())[0][:80]
    return meta


def _starts(line: str, engine: Optional[str]) -> Optional[str]:
    """Si la línea abre un hallazgo devuelve su identificador (consulta o CVE)."""
    m = _CVE_RE.search(line)
    if m:
        return m.group(1)
    m = _QUERY_LABEL_RE.match(line)
    if m:
        name = m.group(1).split("  ")[0].strip()
        if re.fullmatch(r"[\w .\-]{3,80}", name):
            return name.replace(" ", "_") if _QUERY_RE.match(name.replace(" ", "_")) else name
    first = re.split(r"\s{2,}|\s\|\s", line)[0].strip()
    if _QUERY_RE.match(first) and engine in (None, "SAST", "IAC", "SCS"):
        return first
    return None


def _block_item(block: List[str], ident: str, engine: Optional[str], default_sev: Optional[str]) -> Optional[Dict[str, Any]]:
    text = "\n".join(block)
    sev = None
    for ln in block:
        m = re.search(r"severity\s*[:\-]?\s*(critical|high|medium|low|informational|info)\b", ln, re.I)
        if m:
            sev = _SEV_WORD[m.group(1).lower()]
            break
    if not sev:
        for ln in block:
            m = _SEV_RE.search(re.sub(_STATE_RE, " ", ln))
            if m and not re.search(r"risk level|high-risk|high_risk", ln, re.I):
                sev = _SEV_WORD[m.group(1).lower()]
                break
    sev = sev or default_sev or "INFO"
    st = _STATE_RE.search(text)
    state = _STATE_NORM[st.group(1).lower()] if st else ""
    sm = None
    for ln in block:
        sm = re.search(r"status\s*[:\-]?\s*(new|recurrent|fixed)\b", ln, re.I)
        if sm:
            break
    status = sm.group(1).upper() if sm else ""
    if not status:  # celda suelta de una tabla: «New», «Recurrent»
        for ln in block[:3]:
            for cell in re.split(r"\s{2,}|\s\|\s", ln):
                if cell.strip().lower() in ("new", "recurrent", "fixed"):
                    status = cell.strip().upper()
    loc = _LOC_RE.search(text)
    file = line = None
    if loc:
        file, line = loc.group(1), int(loc.group(2))
    else:
        fo = _FILE_ONLY_RE.search(text)
        file = fo.group(1) if fo else None
    is_cve = bool(_CVE_RE.fullmatch(ident))
    eng = engine
    if is_cve or (eng is None and not loc):
        eng = "SCA" if is_cve else eng
    eng = eng or ("SAST" if loc else "SCA" if is_cve else "SAST")
    msg = ""
    if eng == "SCA":
        pk = _PKG_RE.search(re.sub(_CVE_RE, " ", text))
        if pk:
            file = pk.group(1)
        rec = _REC_RE.search(text)
        if rec:
            msg = "actualiza a %s" % (rec.group(1) or rec.group(2))
    cwe = _CWE_RE.search(text)
    if cwe:
        msg = (msg + " · " if msg else "") + "CWE-%s" % cwe.group(1)
    it = {"file": file or "", "line": line, "rule": ident, "severity": sev, "message": msg, "category": eng,
          "state": state, "status": status}
    return it


def parse_text(pages: List[str]) -> Dict[str, Any]:
    """Convierte el texto de las páginas en ``{items, summary, meta}``."""
    lines = _norm(ln for p in pages for ln in p.splitlines())
    if any("Similarity Id:" in ln for ln in lines):  # «Scan Report» de Checkmarx One: formato conocido y mucho más completo
        rep = parse_scan_report(lines)
        info = rep["info"]
        rep["summary"] = {}
        rep["meta"] = {k: info[k] for k in ("project", "branch", "scan_id", "created") if info.get(k)}
        if info.get("last_scanned"):
            rep["meta"]["created"] = info["last_scanned"]
        return rep
    meta = _meta(lines)
    summary: Dict[str, Dict[str, int]] = {}
    items: List[Dict[str, Any]] = []
    engine: Optional[str] = None
    heading_sev: Optional[str] = None
    cur: Optional[Tuple[str, Optional[str], Optional[str], List[str]]] = None

    def flush() -> None:
        nonlocal cur
        if cur:
            it = _block_item(cur[3], cur[0], cur[1], cur[2])
            if it:
                items.append(it)
        cur = None

    for ln in lines:
        m = _SUMMARY_ROW_RE.match(ln)
        if m:
            eng = {"APIS": "APIS", "API": "APIS", "SECRET DETECTION": "SECRETS"}.get(m.group(1).upper(), m.group(1).upper())
            summary[eng] = dict(zip(("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"), (int(x) for x in m.groups()[1:6])))
            continue
        e = _engine_of(ln)
        if e and not _starts(ln, engine):
            flush()
            engine = e
            heading_sev = None
            continue
        sv = _SEV_ONLY_RE.match(ln)
        if sv:
            flush()
            heading_sev = _SEV_WORD[sv.group(1).lower()]
            continue
        ident = _starts(ln, engine)
        if ident:
            flush()
            cur = (ident, engine, heading_sev, [ln])
        elif cur is not None:
            if len(cur[3]) < 40:
                cur[3].append(ln)
    flush()

    seen = set()
    uniq = []
    for it in items:  # los nodos del flujo de datos o encabezados repetidos duplican el mismo hallazgo
        k = (it["category"], it["rule"], it["file"], it["line"], it["severity"])
        if k not in seen:
            seen.add(k)
            uniq.append(it)
    return {"items": uniq, "summary": summary, "meta": meta}


def looks_like_checkmarx(pages: List[str]) -> bool:
    head = "\n".join(pages[:3]).lower()
    if "pipeline-analyzer" in head:  # PDF generado por esta misma herramienta
        return False
    if "similarity id:" in "\n".join(pages).lower() or ("scan results overview" in head and "results summary" in head):
        return True
    return "checkmarx" in head or "cxone" in head or "cx one" in head or ("sast" in head and "severity" in head)


def parse_cxone_pdf(path: Any) -> Optional[Dict[str, Any]]:
    """Lee un PDF de Checkmarx. Devuelve ``{"tool": "cxone_pdf", "items", "summary", "meta"}`` o ``None`` si no lo es."""
    if str(path).lower().endswith((".md", ".txt")):  # el mismo informe ya convertido a texto/Markdown
        try:
            pages = [Path(path).read_text(encoding="utf-8", errors="replace")]
        except OSError:
            return None
    else:
        try:
            pages = extract_text(path)
        except PdfError:
            return None
    if not looks_like_checkmarx(pages):
        return None
    rep = parse_text(pages)
    if not rep["items"] and not rep["summary"] and not rep.get("totals"):
        return None
    rep["tool"] = "cxone_pdf"
    rep["pages"] = len(pages)
    return rep


# ------------------------------------------------------------------------ cruce

def _key(it: Dict[str, Any]) -> Tuple[str, str]:
    if (it.get("category") or "").upper() == "SCA":  # el paquete se escribe distinto en el PDF y en el JSON: basta el CVE
        return (str(it.get("rule") or "").lower(), "")
    base = PurePosixPath(str(it.get("file") or "").replace("\\", "/")).name.lower()
    return (str(it.get("rule") or "").lower(), base)


def _count(items: List[Dict[str, Any]], include_resolved: bool = True) -> Dict[str, Dict[str, int]]:
    out: Dict[str, Dict[str, int]] = {}
    for it in items:
        if not include_resolved and it.get("state") in _SKIP_STATES:
            continue
        eng = (it.get("category") or "SAST").upper()
        sev = it["severity"]
        out.setdefault(eng, Counter())[sev] += 1  # type: ignore[assignment]
    return {e: dict(c) for e, c in out.items()}


def _identity(pdf: Dict[str, Any], log: Dict[str, Any]) -> List[Dict[str, str]]:
    """¿El PDF y el log son del mismo escaneo? Compara ID, rama, hora y estado de cada motor."""
    info = pdf.get("info") or {}
    out: List[Dict[str, str]] = []
    if not info or not log:
        return out

    def add(field: str, a: Any, b: Any, ok: Any) -> None:
        out.append({"field": field, "log": str(a), "pdf": str(b), "state": ok})

    if info.get("scan_id") and log.get("scan_id"):
        masked = "<" in info["scan_id"] or "<" in log["scan_id"]
        add("Scan ID", log["scan_id"], info["scan_id"], "n/c" if masked else ("igual" if info["scan_id"].lower() == log["scan_id"].lower() else "distinto"))
    if info.get("branch") and log.get("branch"):
        add("Rama", log["branch"], info["branch"], "igual" if info["branch"] == log["branch"] else "distinto")
    if info.get("last_scanned_dt") and log.get("created_at"):
        try:
            lt = datetime.strptime(log["created_at"], "%Y-%m-%d, %H:%M:%S")
            near = abs((lt - info["last_scanned_dt"]).total_seconds()) <= 120
            add("Hora del escaneo", log["created_at"], info["last_scanned"], "igual" if near else "distinto")
        except ValueError:
            pass
    pst = info.get("scanner_status") or {}
    for eng, st in ((e, (log.get("engines") or {}).get(e, {}).get("status")) for e in ("SAST", "SCA", "SCS")):
        if st and st != "-" and eng in pst:
            add("Estado %s" % eng, st, pst[eng], "igual" if st.lower() == pst[eng].lower() else "distinto")
    return out


def reconcile(pdf: Dict[str, Any], log_cxone: Optional[Dict[str, Any]] = None,
              json_items: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Compara el PDF con el log (conteos por motor y severidad) y con el JSON de CxOne (hallazgo por hallazgo).

    Devuelve ``{"counts": [...], "items": {...} | None, "verdict": "ok"|"differences"|"nolog", "notes": [...]}``.
    El conteo del PDF excluye los hallazgos «Not Exploitable»; el log, según la configuración del escaneo, puede incluirlos.
    """
    notes: List[str] = []
    pdf_open = _count(pdf["items"], include_resolved=False)
    pdf_all = _count(pdf["items"], include_resolved=True)
    for eng, row in (pdf.get("summary") or {}).items():  # el PDF declara su propio resumen: se usa si no hay detalle
        if eng not in pdf_all:
            pdf_open[eng] = {k: v for k, v in row.items() if v}
            pdf_all[eng] = pdf_open[eng]
    log = (log_cxone or {}).get("engines") or {}
    counts = []
    differs = False
    for eng in [e for e in ("SAST", "SCA", "SCS", "IAC", "CONTAINERS", "APIS", "SECRETS") if e in pdf_open or e in log] or []:
        lg = log.get(eng if eng != "IAC" else "IAC") or {}
        for sev in SEVS:
            p = pdf_open.get(eng, {}).get(sev, 0)
            p_all = pdf_all.get(eng, {}).get(sev, 0)
            l = lg.get(sev.lower()) if lg else None
            if l is None and not p:
                continue
            if l is None:
                state = "solo_pdf"
            elif l == p:
                state = "coincide"
            elif l == p_all:
                state = "coincide_con_resueltos"
            else:
                state = "difiere"
            differs = differs or state in ("difiere", "solo_pdf")
            counts.append({"engine": eng, "severity": sev, "log": l, "pdf": p, "pdf_all": p_all, "state": state})
    identity = _identity(pdf, log_cxone or {})
    if pdf.get("format") == "scan_report":
        t = pdf.get("totals") or {}
        n = Counter(i["severity"] for i in pdf["items"] if i["severity"] != "INFO")
        if t and any(t.get(k, 0) != n.get(k, 0) for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW")):
            notes.append("El resumen del PDF (%s) no coincide con los hallazgos que se leyeron (%s): puede haber resultados que no se interpretaron."
                         % ("/".join(str(t.get(k, 0)) for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW")),
                            "/".join(str(n.get(k, 0)) for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW"))))
        flt = " ".join(pdf.get("filters") or [])
        if "Excluded: Not Exploitable" in flt or "Not Exploitable" in flt:
            notes.append("El PDF está filtrado: no incluye hallazgos Not Exploitable ni Information. Es el mismo criterio con el que el breaker cuenta los activos.")
    for x in identity:
        if x["state"] == "distinto":
            differs = True
            notes.append("%s distinto entre el log (%s) y el PDF (%s)%s." % (x["field"], x["log"], x["pdf"],
                         ": el log marca Partial; revisa en CxOne si el escaneo SCS realmente terminó" if x["field"] == "Estado SCS" and x["log"] == "Partial" else ""))
    verdict = "nolog" if not log else ("differences" if differs else "ok")
    if not log:
        notes.append("El log no trae la tabla «Scan Summary» de CxOne: no hay conteos contra los que comparar.")
    elif any(c["state"] in ("difiere", "solo_pdf") for c in counts):
        notes.append("Los conteos del log y del PDF no coinciden. Revisa que sean del mismo escaneo (ID, rama y fecha) y "
                     "si el PDF incluye hallazgos en estado Not Exploitable que el breaker no cuenta.")

    items = None
    if json_items is not None:
        pk = {_key(i): i for i in pdf["items"]}
        jk = {_key(i): i for i in json_items}
        both = [k for k in pk if k in jk]
        items = {"coinciden": len(both), "solo_pdf": [pk[k] for k in pk if k not in jk],
                 "solo_json": [jk[k] for k in jk if k not in pk]}
        if items["solo_pdf"] or items["solo_json"]:
            notes.append("El PDF y el JSON de CxOne no listan los mismos hallazgos.")
    return {"counts": counts, "items": items, "verdict": verdict, "notes": notes, "meta": pdf.get("meta") or {}, "identity": identity}


def dump_text(path: Any) -> str:
    """Texto que ve el analizador al leer el PDF (para diagnosticar un PDF que no se interpreta bien)."""
    pages = extract_text(path)
    return "\n".join("===== página %d =====\n%s" % (i + 1, p) for i, p in enumerate(pages))
