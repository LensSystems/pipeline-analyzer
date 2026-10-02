"""Parser del «Scan Report» que genera Checkmarx One (PDF de resultados, o su conversión a texto/Markdown).

El informe trae, en este orden: portada y resumen, filtros aplicados, información del escaneo, distribución de resultados,
el detalle de cada consulta SAST (con ``Result i of n``, severidad, estado, origen/destino y fragmento de código), el
detalle SCA (paquete, versión, CVE), las categorías de cumplimiento y, al final, «Vulnerability Details» con el riesgo y las
recomendaciones de cada consulta. Aquí se lee todo eso en una estructura única; ``cxone_pdf`` la cruza con el log.
"""

import re
from datetime import datetime
from typing import Any, Dict, List, Optional

_SEV = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "information": "INFO", "info": "INFO"}
_STATE = {"to verify": "TO_VERIFY", "confirmed": "CONFIRMED", "urgent": "URGENT", "not exploitable": "NOT_EXPLOITABLE",
          "proposed not exploitable": "PROPOSED_NOT_EXPLOITABLE"}
_PAGE_RE = re.compile(r"^Page \d+ of \d+$", re.I)
_RES_HEAD = re.compile(r"^(Critical|High|Medium|Low|Information|Info)\s+(?:Link\s+)?(New|Recurrent|Fixed)\s+(.+?)\s+Similarity Id:\s*(-?\d+)"
                       r"\s+Found First:\s*(.+?)\s+Found Last:\s*(.+)$", re.I)
_SCA_HEAD = re.compile(r"^(Critical|High|Medium|Low|Information|Info)\s+(?:Link\s+)?(New|Recurrent|Fixed)\s+(.+?)\s+Outdated:\s*(\w+)\s+"
                       r"Found First:\s*(.+)$", re.I)
_TWO = r"\s*(.*?)\s*%s:\s*(.*)$"
_STATUS_RE = re.compile(r"\b(SAST|SCA|SCS|IAC|APIS|CONTAINERS):\s*(Completed|Partial|Failed|Running|Canceled|Cancelled)\b", re.I)
_DATE_FMT = "%d %b, %Y"


def _date(s: str) -> Optional[datetime]:
    try:
        return datetime.strptime(s.strip(), _DATE_FMT)
    except ValueError:
        return None


def _stamp(s: str) -> Optional[datetime]:
    """«29 Sep, 2026 | 5:52 PM» → datetime (hora local del reporte)."""
    try:
        return datetime.strptime(re.sub(r"\s*\|\s*", " ", s.strip()), "%d %b, %Y %I:%M %p")
    except ValueError:
        return None


def _header_info(lines: List[str]) -> Dict[str, Any]:
    info: Dict[str, Any] = {}
    head = "\n".join(lines[:140])
    pats = (("project", r"Project Name:\s*(.+)"), ("scan_id", r"Scan Id:\s*(\S+)"), ("main_branch", r"Main Branch:\s*(\S+)"),
            ("duration", r"Scan Duration:\s*(.+?)(?:\s+Scan Type:|$)"), ("scan_type", r"Scan Type:\s*(.+)"),
            ("preset", r"Preset:\s*(.+?)(?:\s+Scanned Branch Name:|$)"), ("branch", r"Scanned Branch Name:\s*(\S+)"),
            ("loc", r"LOC Scanned:\s*(\d+)"), ("files", r"Files Scanned:\s*(\d+)"), ("initiator", r"Initiator:\s*(\S+)"),
            ("last_scanned", r"Last Scanned:\s*(.+)"), ("created", r"^Created:\s*(.+)"), ("timezone", r"Timezone:\s*(\S+)"),
            ("scanners", r"^Scanners:\s*(.+)"), ("density", r"Density:\s*([\d.]+)"))
    for key, rx in pats:
        m = re.search(rx, head, re.M)
        if m:
            info[key] = m.group(1).strip()
    for m in re.finditer(r"^Scan Id:\s*(\S+)\s+Main Branch", head, re.M):
        info["scan_id"] = m.group(1)
    status = {m.group(1).upper(): m.group(2).capitalize() for m in _STATUS_RE.finditer(head)}
    if status:
        info["scanner_status"] = status
    for i, ln in enumerate(lines[:140]):
        if ln == "Scan Tags:":
            tags = []
            for t in lines[i + 1:i + 6]:
                if (_PAGE_RE.match(t) or t.endswith(":") or t.startswith(("|", "Scan Results", "SAST", "SCA", "SCS", "By ", "Results", "Project"))
                        or re.fullmatch(r"[\d\s]+", t)):
                    break
                tags.append(t)
            info["tags"] = [t for t in tags if t.lower() != "none"]
    if info.get("last_scanned"):
        st = _stamp(info["last_scanned"])
        if st:
            info["last_scanned_dt"] = st
    return info


def _filters(lines: List[str]) -> List[str]:
    for i, ln in enumerate(lines):
        if ln == "Filtered By":
            out = []
            for t in lines[i + 1:i + 40]:
                if t.startswith("Scan Information") or _PAGE_RE.match(t):
                    break
                out.append(t)
            joined: List[str] = []
            for t in out:  # «Severity:» + «Excluded: Information» → una línea por filtro
                if t.endswith(":") and not t.startswith("Excluded"):
                    joined.append(t)
                elif joined and (t.startswith("Excluded") or joined[-1].endswith(":")):
                    joined[-1] = (joined[-1] + " " + t).strip()
                else:
                    joined.append(t)
            return joined
    return []


def _sev(word: str) -> str:
    return _SEV.get(word.strip().lower(), "INFO")


def _split_pair(line: str, label: str):
    """«Label: a Label: b» → (a, b)."""
    m = re.match(r"^%s:\s*(.*?)\s*(?:%s:\s*(.*))?$" % (label, label), line)
    return (m.group(1), m.group(2) or "") if m else ("", "")


def _clean_lines(pages_lines: List[str]) -> List[str]:
    out = []
    for ln in pages_lines:
        ln = ln.strip()
        if not ln or _PAGE_RE.match(ln) or ln.startswith("| ---"):
            continue
        out.append(ln)
    return out


def _fix_version(desc: str, current: str) -> str:
    m = re.search(r"(?:upgrade|update)(?:d)?(?:\s+\w+)?\s+to\s+(?:versions?\s+)?([0-9][\w.\-, ]*(?:\s+or\s+[0-9][\w.\-]+)?)", desc, re.I)
    if not m:
        return ""
    vers = re.findall(r"\d+(?:\.\d+)+", m.group(1))
    major = current.split(".")[0] if current else ""
    return next((v for v in vers if v.split(".")[0] == major), vers[0] if vers else "")


def parse_scan_report(raw_lines: List[str]) -> Dict[str, Any]:
    lines = _clean_lines(raw_lines)
    info = _header_info(lines)
    rep: Dict[str, Any] = {"format": "scan_report", "info": info, "filters": _filters(lines), "items": [], "queries": {}, "totals": {},
                           "sca_packages": {}, "notes": []}
    for i, ln in enumerate(lines[:30]):
        if ln == "Results Summary" and i + 1 < len(lines):
            m = re.match(r"^(\d+) (\d+) (\d+) (\d+) (\d+)$", lines[i + 1])
            if m:
                rep["totals"] = dict(zip(("CRITICAL", "HIGH", "MEDIUM", "LOW", "TOTAL"), (int(x) for x in m.groups())))

    mode: Optional[str] = None
    q: Optional[Dict[str, Any]] = None
    res: Optional[Dict[str, Any]] = None
    sub = None           # subsección dentro de un resultado: desc | cat | file | snippets
    last_cat = None
    pkg: Dict[str, str] = {}
    det: Optional[Dict[str, Any]] = None
    det_sec: Optional[str] = None
    last_scanned = info.get("last_scanned_dt")

    def finish_res() -> None:
        nonlocal res
        if not res:
            return
        if res["engine"] == "SAST":
            sn = res.pop("snips", [])
            res["line"] = sn[0][0] if sn else None
            res["dest_line"] = sn[1][0] if len(sn) > 1 else res["line"]
            res["snippet"] = "\n".join("%d %s" % (n, t) for n, t in sn[:4])
            res["message"] = "CWE-%s" % res["cwe"] + (" · %s → %s" % (res["element"], res["dest_element"]) if res.get("element") and
                                                       res["element"] != res.get("dest_element") else
                                                       (" · %s" % res["element"] if res.get("element") else ""))
        fd, ff = _date(res.get("found_first", "")), None
        if fd and last_scanned:
            res["age_days"] = (last_scanned - fd).days
        rep["items"].append(res)
        res = None

    for ln in lines:
        if mode != "details" and ln == "Vulnerability Details":
            finish_res()
            mode, det, det_sec = "details", None, None
            continue
        m = re.match(r"^SAST Scan Results\s*\(", ln)
        if m:
            mode, q, res = "sast", None, None
            continue
        if re.match(r"^SCA Scan Results\s*\(", ln):
            finish_res()
            mode, pkg = "sca", {}
            continue
        if re.match(r"^(SAST Resolved Vulnerabilities|SCA Vulnerabilities)$", ln) or ln == "Categories":
            finish_res()
            mode = None
            continue
        if ln == "Supply Chain Security Vulnerabilities":
            finish_res()
            mode = "scs"
            continue
        if mode == "scs":
            if "no data" in ln.lower():
                rep["notes"].append("SCS: sin resultados en el reporte.")
            continue

        if mode == "sast":
            m = re.match(r"^(\S+?)\s*\(Type\)$", ln)
            if m:
                finish_res()
                q = {"name": m.group(1), "path": "", "cwe": "", "total": 0, "description": "", "categories": {}}
                rep["queries"][q["name"]] = q
                sub = None
                continue
            if q is None:
                continue
            m = re.match(r"^Result (\d+) of (\d+)$", ln)
            if m:
                finish_res()
                res = {"engine": "SAST", "rule": q["name"], "category": "SAST", "cwe": q["cwe"], "query_path": q["path"], "index": int(m.group(1)),
                       "file": "", "dest_file": "", "method": "", "element": "", "dest_element": "", "snips": []}
                sub = None
                continue
            if res is None:
                if ln.startswith("Query Path:"):
                    q["path"] = ln.split(":", 1)[1].strip()
                    sub = None
                elif ln.startswith("CWE Id:"):
                    q["cwe"] = ln.split(":", 1)[1].strip()
                    sub = None
                elif ln.startswith("Total results:"):
                    q["total"] = int(re.sub(r"\D", "", ln) or 0)
                    sub = None
                elif ln.startswith("Description:"):
                    q["description"] = ln.split(":", 1)[1].strip()
                    sub = "desc"
                elif ln.startswith("Category:"):
                    sub, last_cat = "cat", None
                elif sub == "desc":
                    q["description"] += " " + ln
                elif sub == "cat":
                    m = re.match(r"^([A-Za-z][\w ().+/\-]*?):\s*(.*)$", ln)
                    if m:
                        last_cat = m.group(1)
                        q["categories"][last_cat] = m.group(2)
                    elif last_cat:
                        q["categories"][last_cat] += " " + ln
                continue
            # dentro de un resultado
            m = _RES_HEAD.match(ln)
            if m:
                res["severity"] = _sev(m.group(1))
                res["status"] = m.group(2).upper()
                res["state"] = _STATE.get(m.group(3).strip().lower(), re.sub(r"\W+", "_", m.group(3).strip().upper()))
                res["similarity_id"] = m.group(4)
                res["found_first"], res["found_last"] = m.group(5).strip(), m.group(6).strip()
                continue
            if ln.startswith("First Scan ID:"):
                res["first_scan_id"] = ln.split(":", 1)[1].strip()
            elif ln.startswith("Source Destination"):
                sub = None
            elif ln.startswith("File Name:"):
                res["file"], res["dest_file"] = _split_pair(ln, "File Name")
                sub = "file"
            elif ln.startswith("Method:"):
                res["method"], res["dest_method"] = _split_pair(ln, "Method")
                sub = None
            elif ln.startswith("Element:"):
                res["element"], res["dest_element"] = _split_pair(ln, "Element")
                sub = None
            elif ln == "Code Snippets":
                sub = "snips"
            elif sub == "file":  # la ruta larga se parte en varias líneas: «continuación-origen continuación-destino»
                toks = ln.split()
                if len(toks) >= 2:
                    res["file"] += toks[0]
                    res["dest_file"] += toks[-1]
                elif toks:
                    res["file"] += toks[0]
            elif sub == "snips":
                m = re.match(r"^(\d+)\s+(.*)$", ln)
                if m and int(m.group(1)) > 0 and not re.fullmatch(r"[\d\s]+", m.group(2)):
                    res["snips"].append((int(m.group(1)), m.group(2)))
            continue

        if mode == "sca":
            if ln.startswith("Package Name:"):
                pkg = {"name": ln.split(":", 1)[1].strip()}
                continue
            if ln.startswith("Version:") and pkg is not None and "version" not in pkg:
                pkg["version"] = ln.split(":", 1)[1].strip()
                continue
            m = re.match(r"^Result (\d+) of (\d+) - ", ln)
            if m:
                finish_res()
                res = {"engine": "SCA", "category": "SCA", "package": pkg.get("name", ""), "version": pkg.get("version", ""),
                       "file": "%s:%s" % (pkg.get("name", ""), pkg.get("version", "")), "line": None, "index": int(m.group(1)), "description": ""}
                sub = None
                continue
            if res is None:
                continue
            m = _SCA_HEAD.match(ln)
            if m:
                res["severity"] = _sev(m.group(1))
                res["status"] = m.group(2).upper()
                res["state"] = _STATE.get(m.group(3).strip().lower(), re.sub(r"\W+", "_", m.group(3).strip().upper()))
                res["outdated"] = m.group(4).lower()
                res["found_first"] = m.group(5).strip()
                continue
            if ln.startswith("CVE:"):
                res["rule"] = res["cve"] = ln.split(":", 1)[1].strip()
            elif ln.startswith("Description:"):
                res["description"] = ln.split(":", 1)[1].strip()
                sub = "desc"
            elif ln.startswith(("References:", "Result ID:")):
                sub = None
            elif ln.startswith("First Scan ID:"):
                res["first_scan_id"] = ln.split(":", 1)[1].strip()
            elif sub == "desc":
                res["description"] += " " + ln
            if res.get("description") and "fix_version" not in res:
                fx = _fix_version(res["description"], res.get("version", ""))
                if fx:
                    res["fix_version"] = fx
                    res["message"] = "actualiza a %s" % fx
            continue

        if mode == "details":
            m = re.match(r"^(\S+?)\s*\(CWE\s*(\d+)\)$", ln)
            if m:
                det = rep["queries"].setdefault(m.group(1), {"name": m.group(1), "path": "", "cwe": m.group(2), "total": 0, "description": "",
                                                              "categories": {}})
                det.update({"risk": "", "cause": "", "recommendations": []})
                det_sec = None
                continue
            if det is None:
                continue
            if ln == "What Is The Risk":
                det_sec = "risk"
            elif ln == "What Can Cause It":
                det_sec = "cause"
            elif ln == "General Recommendations":
                det_sec = "rec"
            elif det_sec in ("risk", "cause"):
                det[det_sec] = (det[det_sec] + " " + ln).strip()
            elif det_sec == "rec":
                if re.match(r"^(\*|-|•|\d+\.)\s+", ln) or not det["recommendations"]:
                    det["recommendations"].append(re.sub(r"^(\*|-|•|\d+\.)\s+", "", ln))
                else:
                    det["recommendations"][-1] += " " + ln
    finish_res()
    for q in rep["queries"].values():
        q["description"] = q["description"].strip()
    return rep
