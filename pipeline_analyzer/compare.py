"""Comparativa entre ejecuciones: tabla de métricas con tendencia y diff de hallazgos."""

from typing import Any, Callable, Dict, List, Optional, Tuple

from .rules import RATING_LETTER, Finding

# Tendencias
IMPROVED, WORSE, SAME, NA = "mejoró", "empeoró", "igual", "n/d"


def _get(d: Dict[str, Any], *path, default=None):
    for p in path:
        if not isinstance(d, dict) or p not in d:
            return default
        d = d[p]
    return d


def _sonar(metric: str) -> Callable[[Dict[str, Any]], Any]:
    def f(m):
        v = _get(m, "sonar", "conditions", metric, "actual")
        if v is not None and metric.endswith("rating"):
            return RATING_LETTER.get(str(v), v)
        return v
    return f


def _static_value(tool: str) -> Callable[[Dict[str, Any]], Any]:
    def f(m):
        d = _get(m, "static", tool, default={}) or {}
        st = d.get("status")
        if st == "NO EJECUTADO":
            return "NO EJECUTADO"
        if tool == "spotbugs" and d.get("unsupported_class_versions"):
            return "FALLO (Java %d)" % (max(int(k) for k in d["unsupported_class_versions"]) - 44)
        if d.get("violations") is not None:
            return d["violations"]
        return st
    return f


def _sum_keys(m, engine, keys):
    row = _get(m, "cxone", "engines", engine)
    if not row or not row.get("ran", True):
        return None
    return sum((row.get(k) or 0) for k in keys)


def _tests_failed(m):
    t = m.get("tests") or {}
    if not t.get("total"):
        return None
    return t["failures"] + t["errors"]


def _breakers_failed(m):
    return sum(1 for s in m["steps"] if s["name"].startswith("Breaker") and s["failed"])


# (clave, etiqueta, getter, mejor) — mejor: "lower" | "higher" | "status" | "rating" | None
METRICS: List[Tuple[str, str, Callable[[Dict[str, Any]], Any], Optional[str]]] = [
    ("tests.total", "Tests ejecutados", lambda m: _get(m, "tests", "total"), None),
    ("tests.failed", "Tests fallidos", _tests_failed, "lower"),
    ("sonar.gate", "Sonar quality gate", lambda m: _get(m, "sonar", "breaker"), "status"),
    ("sonar.reliability", "Sonar reliability (general)", _sonar("reliability_rating"), "rating"),
    ("sonar.new_reliability", "Sonar reliability (nuevo)", _sonar("new_reliability_rating"), "rating"),
    ("sonar.security", "Sonar security (general)", _sonar("security_rating"), "rating"),
    ("sonar.maintainability", "Sonar maintainability", _sonar("sqale_rating"), "rating"),
    ("sonar.coverage", "Sonar cobertura general %", _sonar("coverage"), "higher"),
    ("sonar.new_coverage", "Sonar cobertura nuevo %", _sonar("new_coverage"), "higher"),
    ("sonar.test_success", "Sonar éxito de tests %", _sonar("test_success_density"), "higher"),
    ("sonar.duplication", "Sonar duplicación %", _sonar("duplicated_lines_density"), "lower"),
    ("cx.sast_high", "CxOne SAST Critical+High", lambda m: _sum(m, "cxone", "engines", "SAST"), "lower"),
    ("cx.sast_medium", "CxOne SAST Medium", lambda m: _get(m, "cxone", "engines", "SAST", "medium"), "lower"),
    ("cx.sca_high", "CxOne SCA Critical+High", lambda m: _sum(m, "cxone", "engines", "SCA"), "lower"),
    ("cx.sast_low", "CxOne SAST Low", lambda m: _get(m, "cxone", "engines", "SAST", "low"), "lower"),
    ("cx.sca_medium_low", "CxOne SCA Medium+Low", lambda m: _sum_keys(m, "SCA", ("medium", "low")), "lower"),
    ("cx.total", "CxOne resultados totales", lambda m: _get(m, "cxone", "total_results"), "lower"),
    ("cx.breaker", "Breaker CxOne", lambda m: _get(m, "cxone", "breaker"), "status"),
    ("tmas.high", "TMAS Critical+High", lambda m: _sum(m, "tmas"), "lower"),
    ("static.checkstyle", "Checkstyle (violaciones)", _static_value("checkstyle"), "lower"),
    ("static.pmd", "PMD (violaciones)", _static_value("pmd"), "lower"),
    ("static.spotbugs", "SpotBugs", _static_value("spotbugs"), "lower"),
    ("breakers.failed", "Breakers en FALLO", _breakers_failed, "lower"),
    ("scanners.high", "Otros escáneres Critical+High", lambda m: sum(((d.get("critical") or 0) + (d.get("high") or 0) + (d.get("leaks") or 0))
                                                                     for d in (m.get("scanners") or {}).values()) if m.get("scanners") else None, "lower"),
    ("sec.secrets", "Secretos en claro en el log", lambda m: len(_get(m, "security", "secrets_in_clear", default=[]) or []) if m.get("security") else None, "lower"),
    ("sec.alerts", "Validaciones de seguridad en ALERTA", lambda m: sum(1 for c in _get(m, "security", "checklist", default=[]) if c["status"] == "ALERTA") if m.get("security") else None, "lower"),
    ("sec.cves", "Dependencias con CVE (log)", lambda m: len(_get(m, "security", "vulnerable_dependencies", default=[]) or []) if m.get("security") else None, "lower"),
    ("duration", "Duración del pipeline (min)", lambda m: round(m["meta"]["duration_s"] / 60, 1) if m["meta"].get("duration_s") else None, None),
]


def _sum(m, *path):
    d = _get(m, *path)
    if not isinstance(d, dict):
        return None
    c, h = d.get("critical"), d.get("high")
    if c is None and h is None:
        return None
    return (c or 0) + (h or 0)


def _score(v: Any, better: str) -> Optional[float]:
    """Puntaje comparable: mayor = mejor. NO EJECUTADO = FALLO < cualquier resultado medido."""
    s = str(v).upper()
    if s.startswith(("NO EJECUTADO", "FALLO")) or s == "ERROR":   # para la comparativa, «no se ejecutó» y «falló» son lo mismo
        return -1e6
    if s in ("OK", "PASO"):
        return 0.0
    if better == "rating":
        return -float("ABCDE".index(s)) if s in ("A", "B", "C", "D", "E") else None
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    return -f if better == "lower" else f


def trend(old: Any, new: Any, better: Optional[str]) -> str:
    if better is None or old is None or new is None:
        return NA
    if str(old) == str(new):
        return SAME
    ro, rn = _score(old, better), _score(new, better)
    if ro is None or rn is None:
        return NA
    if rn > ro:
        return IMPROVED
    if rn < ro:
        return WORSE
    return SAME


def delta(old: Any, new: Any) -> str:
    """Diferencia numérica con signo («-9», «+2.5»); vacío si los valores no son números."""
    if isinstance(old, bool) or isinstance(new, bool):
        return ""
    try:
        d = float(new) - float(old)
    except (TypeError, ValueError):
        return ""
    if d == 0:
        return ""
    txt = ("%.1f" % abs(d)).rstrip("0").rstrip(".")
    return ("+" if d > 0 else "-") + txt


def kind(old: Any, new: Any, better: Optional[str]) -> str:
    """Qué pasó entre dos valores: improved | worse | changed (cambió, sin juicio de mejor/peor) | same."""
    if old is None and new is None:
        return "same"
    if str(old) == str(new):
        return "same"
    t = trend(old, new, better)
    if t == SAME:
        return "same"
    if t == IMPROVED:
        return "improved"
    if t == WORSE:
        return "worse"
    return "changed"


def comparison_table(runs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rows = []
    for key, label, getter, better in METRICS:
        values = []
        for r in runs:
            try:
                values.append(getter(r["metrics"]))
            except Exception:  # una métrica mal formada no debe romper el reporte
                values.append(None)
        if all(v is None for v in values):
            continue
        rows.append({
            "key": key,
            "label": label,
            "values": values,
            "trend_prev": trend(values[-2], values[-1], better) if len(values) > 1 else NA,
            "trend_first": trend(values[0], values[-1], better) if len(values) > 1 else NA,
            "kind": kind(values[-2], values[-1], better) if len(values) > 1 else "same",
            "delta": delta(values[-2], values[-1]) if len(values) > 1 else "",
            "kind_first": kind(values[0], values[-1], better) if len(values) > 1 else "same",
            "delta_first": delta(values[0], values[-1]) if len(values) > 1 else "",
        })
    return rows


def comparison_summary(rows: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Agrupa las métricas por lo que pasó entre la penúltima y la última ejecución (viejo → nuevo)."""
    out: Dict[str, List[Dict[str, Any]]] = {"worse": [], "improved": [], "changed": [], "same": []}
    for r in rows:
        out[r["kind"]].append(r)
    return out


def summary_text(groups: Dict[str, List[Any]]) -> str:
    """Una frase: «3 mejoraron · 1 empeoró · 2 cambiaron · 18 sin cambios»."""
    parts = []
    n = len(groups["improved"])
    if n:
        parts.append("%d %s" % (n, "mejoró" if n == 1 else "mejoraron"))
    n = len(groups["worse"])
    if n:
        parts.append("%d %s" % (n, "empeoró" if n == 1 else "empeoraron"))
    n = len(groups["changed"])
    if n:
        parts.append("%d %s" % (n, "cambió" if n == 1 else "cambiaron"))
    n = len(groups["same"])
    if n:
        parts.append("%d sin cambios" % n)
    return " · ".join(parts) or "Sin métricas para comparar"


# Hallazgos que solo pueden confirmarse como resueltos si su herramienta se ejecutó
FINDING_TOOL = {
    "SPOTBUGS_JAVA_UNSUPPORTED": "spotbugs",
    "PMD_VIOLATIONS": "pmd",
    "CHECKSTYLE_VIOLATIONS": "checkstyle",
    "STATIC_TOOL_FAILED:spotbugs": "spotbugs",
    "STATIC_TOOL_FAILED:pmd": "pmd",
    "STATIC_TOOL_FAILED:checkstyle": "checkstyle",
}


def findings_diff(first: List[Finding], last: List[Finding],
                  last_metrics: Optional[Dict[str, Any]] = None) -> Dict[str, List[Finding]]:
    a = {f.uid: f for f in first}
    b = {f.uid: f for f in last}
    resolved, unverified = [], []
    for k, f in a.items():
        if k in b:
            continue
        tool = FINDING_TOOL.get(k)
        status = _get(last_metrics or {}, "static", tool, "status") if tool else None
        (unverified if status == "NO EJECUTADO" else resolved).append(f)
    return {
        "resolved": resolved,
        "unverified": unverified,
        "new": [b[k] for k in b if k not in a],
        "persistent": [b[k] for k in b if k in a],
    }
