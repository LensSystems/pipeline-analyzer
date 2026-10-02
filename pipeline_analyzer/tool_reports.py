"""Lectura de los reportes de las herramientas de análisis para dar reglas, archivos y líneas exactas.

Los logs del pipeline solo traen conteos. Si el usuario dispone de los reportes (``target/pmd.xml``,
``checkstyle-result.xml``, ``spotbugsXml.xml``, JSON de resultados de CxOne), este módulo los lee. Todo local,
solo biblioteca estándar. Tolera formatos parciales: lo que no entiende lo ignora.
"""

import json
import os
import tempfile
import zipfile
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .cxone_pdf import parse_cxone_pdf

MAX_FILES = 4000          # archivos revisados como máximo al recorrer carpetas
MAX_BYTES = 80 * 1024 * 1024
SKIP_DIRS = {".git", "node_modules", ".idea", "__pycache__"}
TOOL_LABEL = {"pmd": "PMD", "checkstyle": "Checkstyle", "spotbugs": "SpotBugs", "cxone": "CxOne", "cxone_pdf": "CxOne (PDF)"}
ORDER = ("pmd", "checkstyle", "spotbugs", "cxone", "cxone_pdf")
MAX_PDFS = 20             # PDF revisados como máximo por ejecución (los de carpetas de logs suelen ser ajenos)
MAX_PDF_BYTES = 40 * 1024 * 1024
_SNIFF = {b"<pmd": "pmd", b"<checkstyle": "checkstyle", b"<BugCollection": "spotbugs"}
_SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _int(v: Any) -> Optional[int]:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _item(file: str, line: Any, rule: str, severity: str, message: str, category: str = "") -> Dict[str, Any]:
    return {"file": file or "", "line": _int(line), "rule": rule or "?", "severity": severity, "message": (message or "").strip(),
            "category": category or ""}


# ------------------------------------------------------------------------ XML

def _pmd(root) -> List[Dict[str, Any]]:
    items = []
    for f in root:
        if _local(f.tag) != "file":
            continue
        for v in f:
            if _local(v.tag) != "violation":
                continue
            pr = _int(v.get("priority")) or 3
            items.append(_item(f.get("name", ""), v.get("beginline"), v.get("rule", ""),
                               "HIGH" if pr <= 2 else ("MEDIUM" if pr == 3 else "LOW"), " ".join((v.text or "").split()),
                               v.get("ruleset", "")))
    return items


def _checkstyle(root) -> List[Dict[str, Any]]:
    items = []
    for f in root:
        if _local(f.tag) != "file":
            continue
        for e in f:
            if _local(e.tag) != "error":
                continue
            sev = {"error": "HIGH", "warning": "MEDIUM"}.get((e.get("severity") or "").lower(), "LOW")
            rule = (e.get("source") or "").rsplit(".", 1)[-1]
            rule = rule[:-5] if rule.endswith("Check") else rule
            items.append(_item(f.get("name", ""), e.get("line"), rule, sev, e.get("message", "")))
    return items


def _spotbugs(root) -> List[Dict[str, Any]]:
    items = []
    for b in root:
        if _local(b.tag) != "BugInstance":
            continue
        pr = _int(b.get("priority")) or 2
        src = None
        for c in b:
            if _local(c.tag) == "SourceLine":
                src = c
                break
        if src is None:
            for c in b.iter():
                if _local(c.tag) == "SourceLine":
                    src = c
                    break
        msg = ""
        for c in b:
            if _local(c.tag) in ("LongMessage", "ShortMessage") and (c.text or "").strip():
                msg = c.text
                break
        file = ""
        line = None
        if src is not None:
            file = src.get("sourcepath") or src.get("classname") or ""
            line = src.get("start")
        items.append(_item(file, line, b.get("type", ""), "HIGH" if pr == 1 else ("MEDIUM" if pr == 2 else "LOW"), msg,
                           b.get("category", "")))
    return items


def parse_xml_report(path) -> Optional[Dict[str, Any]]:
    try:
        root = ET.parse(str(path)).getroot()
    except (ET.ParseError, OSError):
        return None
    tool = {"pmd": "pmd", "checkstyle": "checkstyle", "BugCollection": "spotbugs"}.get(_local(root.tag))
    if not tool:
        return None
    parse = {"pmd": _pmd, "checkstyle": _checkstyle, "spotbugs": _spotbugs}[tool]
    return {"tool": tool, "items": parse(root)}


# ------------------------------------------------------------------------ JSON (CxOne)

def parse_cxone_json(path) -> Optional[Dict[str, Any]]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    except (ValueError, OSError):
        return None
    results = data.get("results") if isinstance(data, dict) else data
    if not isinstance(results, list):
        return None
    items = []
    for r in results:
        if not isinstance(r, dict) or not r.get("severity") or not r.get("type"):
            continue
        d = r.get("data") or {}
        typ = str(r["type"]).lower()
        engine = "SCA" if typ.startswith("sca") else typ.upper()
        sev = str(r["severity"]).upper()
        nodes = d.get("nodes") or []
        first = nodes[0] if nodes and isinstance(nodes[0], dict) else {}
        vd = r.get("vulnerabilityDetails") or {}
        rule = d.get("queryName") or vd.get("cveName") or r.get("id") or "?"
        file = first.get("fileName") or d.get("fileName") or d.get("filename") or d.get("packageIdentifier") or ""
        line = first.get("line") or d.get("line")
        msg = d.get("description") or ""
        if engine == "SCA" and d.get("recommendedVersion"):
            msg = "actualiza a %s" % d["recommendedVersion"] + (" · " + msg if msg else "")
        it = _item(file, line, str(rule), sev if sev in _SEV_RANK else "INFO", msg, engine)
        it["state"] = r.get("state") or ""
        it["status"] = r.get("status") or ""
        items.append(it)
    if not items:
        return None
    return {"tool": "cxone", "items": items}


# ------------------------------------------------------------------------ descubrimiento

def _sniff(path: Path) -> Optional[str]:
    try:
        with open(str(path), "rb") as fh:
            head = fh.read(4096)
    except OSError:
        return None
    if path.suffix.lower() == ".xml":
        return next((t for k, t in _SNIFF.items() if k in head), None)
    if path.suffix.lower() == ".md":  # reporte de Checkmarx convertido a Markdown
        return "cxone_pdf"
    if path.suffix.lower() == ".pdf":
        return "cxone_pdf" if head.startswith(b"%PDF-") else None
    if path.suffix.lower() == ".json" and (b'"results"' in head or head.lstrip()[:1] == b"["):
        return "cxone"
    return None


def _candidates(paths: Iterable[Path]) -> Iterable[Path]:
    seen = 0
    for base in paths:
        base = Path(base)
        if base.is_file():
            yield base
            continue
        for root, dirs, files in os.walk(str(base)):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for name in files:
                seen += 1
                if seen > MAX_FILES:
                    return
                if name.lower().endswith((".xml", ".json", ".pdf", ".md")):
                    yield Path(root, name)


def _unzip_reports(zpath: Path, dest: str, audit: Optional[List[Dict[str, str]]]) -> List[Path]:
    """Extrae del .zip solo los archivos que pueden ser reportes (xml/json/pdf), con nombres seguros y tamaño acotado."""
    out: List[Path] = []
    try:
        zf = zipfile.ZipFile(str(zpath))
    except (zipfile.BadZipFile, OSError):
        return out
    with zf:
        for i, info in enumerate(zf.infolist()):
            name = info.filename
            if info.is_dir() or not name.lower().endswith((".xml", ".json", ".pdf", ".md")):
                continue
            if info.file_size > (MAX_PDF_BYTES if name.lower().endswith((".pdf", ".md")) else MAX_BYTES):
                if audit is not None:
                    audit.append({"file": "%s!%s" % (zpath.name, name), "status": "omitido: archivo muy grande"})
                continue
            target = Path(dest, "%d_%s" % (i, Path(name).name))  # nunca se usa la ruta del zip: evita escribir fuera de dest
            target.write_bytes(zf.read(info))
            out.append(target)
            _ZIP_ORIGIN[str(target)] = "%s!%s" % (zpath.name, name)
    return out


_ZIP_ORIGIN: Dict[str, str] = {}


def discover_reports(paths: Iterable[Path], audit: Optional[List[Dict[str, str]]] = None) -> Dict[str, Dict[str, Any]]:
    """Busca reportes de PMD, Checkstyle, SpotBugs y CxOne en archivos o carpetas.

    Devuelve ``{herramienta: {"items": [...], "sources": [nombres], "total": n}}``; varios módulos se combinan.
    """
    with tempfile.TemporaryDirectory() as tmp:
        expanded: List[Path] = []
        for p in paths:
            p = Path(p)
            if p.is_file() and p.suffix.lower() == ".zip":
                expanded += _unzip_reports(p, tmp, audit)
            else:
                expanded.append(p)
                if p.is_dir():  # .zip dentro de la carpeta compartida
                    for zf in p.rglob("*.zip"):
                        expanded += _unzip_reports(zf, tmp, audit)
        return _discover(expanded, audit)


def _discover(paths: List[Path], audit: Optional[List[Dict[str, str]]]) -> Dict[str, Dict[str, Any]]:
    found: Dict[str, Dict[str, Any]] = {}
    pdfs = 0

    def note(f: Path, status: str) -> None:
        if audit is not None:
            audit.append({"file": _ZIP_ORIGIN.get(str(f), str(f)), "status": status})

    for f in _candidates(paths):
        try:
            if f.stat().st_size > (MAX_PDF_BYTES if f.suffix.lower() in (".pdf", ".md") else MAX_BYTES):
                continue
        except OSError:
            continue
        kind = _sniff(f)
        if not kind:
            if f.suffix.lower() in (".xml", ".json", ".pdf", ".md"):
                note(f, "sin formato de herramienta conocido")
            continue
        if kind == "cxone_pdf":
            pdfs += 1
            if pdfs > MAX_PDFS:
                note(f, "omitido: más de %d PDF" % MAX_PDFS)
                continue
            rep = parse_cxone_pdf(f)
        else:
            rep = parse_cxone_json(f) if kind == "cxone" else parse_xml_report(f)
        if not rep:
            note(f, "no es un reporte reconocido" if kind != "cxone_pdf" else "PDF que no es de Checkmarx (o sin hallazgos legibles)")
            continue
        note(f, "leído: %s (%d hallazgos)" % (TOOL_LABEL.get(rep["tool"], rep["tool"]), len(rep["items"])))
        slot = found.setdefault(rep["tool"], {"items": [], "sources": []})
        slot["items"] += rep["items"]
        slot["sources"].append(_ZIP_ORIGIN.get(str(f), f.name).rsplit("!", 1)[-1].rsplit("/", 1)[-1])
        if rep["tool"] == "cxone_pdf":
            slot.setdefault("summary", {}).update(rep.get("summary") or {})
            slot.setdefault("meta", {}).update(rep.get("meta") or {})
            for k in ("format", "info", "filters", "queries", "totals", "notes"):
                if k in rep:
                    slot[k] = rep[k]
    for slot in found.values():
        seen = set()
        uniq = []
        for it in slot["items"]:  # módulos que repiten el mismo reporte
            k = (it["file"], it["line"], it["rule"], it["message"], it.get("index"))
            if k not in seen:
                seen.add(k)
                uniq.append(it)
        uniq.sort(key=lambda i: (_SEV_RANK.get(i["severity"], 9), i["rule"], i["file"], i["line"] or 0))
        slot["items"] = uniq
        slot["total"] = len(uniq)
        slot["sources"] = sorted(set(slot["sources"]))
    return {t: found[t] for t in ORDER if t in found}


def by_rule(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Resumen por regla: cantidad, severidad más alta y un ejemplo de ubicación."""
    groups: Dict[str, List[Dict[str, Any]]] = {}
    for it in items:
        groups.setdefault(it["rule"], []).append(it)
    out = []
    for rule, its in groups.items():
        sev = min((i["severity"] for i in its), key=lambda s: _SEV_RANK.get(s, 9))
        out.append({"rule": rule, "count": len(its), "severity": sev, "files": len({i["file"] for i in its}),
                    "example": its[0], "message": its[0]["message"]})
    out.sort(key=lambda g: (-g["count"], g["rule"]))
    return out


def short_file(path: str, keep_full: bool = False) -> str:
    """Ruta de código legible: completa en la versión local; si no, desde ``src/`` o las últimas carpetas (sin /Users/…)."""
    if keep_full or not path:
        return path
    p = path.replace("\\", "/")
    if "/src/" in p:
        return "src/" + p.split("/src/", 1)[1]
    parts = [x for x in p.split("/") if x]
    return "/".join(parts[-4:]) if len(parts) > 4 else p.lstrip("/")


def label(tool: str) -> str:
    return TOOL_LABEL.get(tool, tool)


def summarize(report: Dict[str, Any]) -> Dict[str, Any]:
    items = report["items"]
    sev = Counter(i["severity"] for i in items)
    return {"total": len(items), "files": len({i["file"] for i in items}), "severities": dict(sev)}
