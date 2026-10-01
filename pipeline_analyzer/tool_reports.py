"""Lectura de los reportes de las herramientas de análisis para dar reglas, archivos y líneas exactas.

Los logs del pipeline solo traen conteos. Si el usuario dispone de los reportes (``target/pmd.xml``,
``checkstyle-result.xml``, ``spotbugsXml.xml``, JSON de resultados de CxOne), este módulo los lee. Todo local,
solo biblioteca estándar. Tolera formatos parciales: lo que no entiende lo ignora.
"""

import json
import os
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

MAX_FILES = 4000          # archivos revisados como máximo al recorrer carpetas
MAX_BYTES = 80 * 1024 * 1024
SKIP_DIRS = {".git", "node_modules", ".idea", "__pycache__"}
TOOL_LABEL = {"pmd": "PMD", "checkstyle": "Checkstyle", "spotbugs": "SpotBugs", "cxone": "CxOne"}
ORDER = ("pmd", "checkstyle", "spotbugs", "cxone")
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
                if name.lower().endswith((".xml", ".json")):
                    yield Path(root, name)


def discover_reports(paths: Iterable[Path]) -> Dict[str, Dict[str, Any]]:
    """Busca reportes de PMD, Checkstyle, SpotBugs y CxOne en archivos o carpetas.

    Devuelve ``{herramienta: {"items": [...], "sources": [nombres], "total": n}}``; varios módulos se combinan.
    """
    found: Dict[str, Dict[str, Any]] = {}
    for f in _candidates(paths):
        try:
            if f.stat().st_size > MAX_BYTES:
                continue
        except OSError:
            continue
        kind = _sniff(f)
        if not kind:
            continue
        rep = parse_cxone_json(f) if kind == "cxone" else parse_xml_report(f)
        if not rep:
            continue
        slot = found.setdefault(rep["tool"], {"items": [], "sources": []})
        slot["items"] += rep["items"]
        slot["sources"].append(f.name)
    for slot in found.values():
        seen = set()
        uniq = []
        for it in slot["items"]:  # módulos que repiten el mismo reporte
            k = (it["file"], it["line"], it["rule"], it["message"])
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
