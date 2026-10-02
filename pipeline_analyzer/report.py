"""Generación de reportes: consola, Markdown, HTML y JSON."""

import html
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from . import BRAND, __version__
from .compare import IMPROVED, NA, SAME, WORSE, comparison_table, findings_diff
from .pdf import AMBER, BAND, BLUE, GREEN, MUTED, RED, PdfDoc
from . import tool_reports as TR
from .cxone_pdf import reconcile
from . import cxone_view as CV
from .plan import build_plan, validation_commands
from .rules import SEVERITIES, SEVERITY_RANK, Finding, finding_anchor, is_pipeline_owned, pipeline_anchor


def short_origin(path: Any) -> str:
    """Origen de una ejecución sin revelar rutas: solo la carpeta de los logs (o la del archivo de log)."""
    p = Path(str(path))
    if p.is_dir() or p.suffix.lower() == ".zip" or not p.parent.name:
        return p.name or str(path)
    return p.parent.name


def short_path(path: Any) -> str:
    return Path(str(path)).name if path else ""


@dataclass
class Run:
    label: str
    metrics: Dict[str, Any]
    findings: List[Finding]


@dataclass
class Analysis:
    runs: List[Run]
    pom_findings: List[Finding] = field(default_factory=list)
    pom_path: Optional[str] = None
    review: Dict[str, Any] = field(default_factory=dict)         # inventario de archivos revisados (carpetas/.zip compartidos)
    tool_reports: Dict[str, Any] = field(default_factory=dict)  # PMD/Checkstyle/SpotBugs/CxOne leídos de --reports

    def _cx_extra(self, mod: str) -> str:
        """« · 9 Medium · 2 Low» del motor, para que el resumen no oculte lo que el breaker no bloquea."""
        row = ((self.last.metrics.get("cxone") or {}).get("engines") or {}).get(mod) or {}
        return "".join(" · %d %s" % (row[k], k.capitalize()) for k in ("medium", "low") if row.get(k))

    def cxone_summary(self) -> Optional[Dict[str, Any]]:
        """Tabla «Scan Summary» de CxOne de la última ejecución: motores en orden fijo, totales, metadatos y notas."""
        c = self.last.metrics.get("cxone") or {}
        eng = c.get("engines")
        if not eng:
            return None
        rows = []
        for name in _CX_ORDER:
            r = eng.get(name)
            if r is None and name == "TOTAL":
                continue
            r = r or {"ran": False, "status": "-"}
            rows.append({"name": name, "ran": bool(r.get("ran")), "status": r.get("status") or "-",
                         "counts": [r.get(k) if r.get("ran") else None for k in _CX_SEVS]})
        for name, r in (c.get("supply_chain") or {}).items():
            rows.append({"name": name, "ran": bool(r.get("ran")), "status": r.get("status") or "-",
                         "counts": [r.get(k) if r.get("ran") else None for k in _CX_SEVS], "sub": True})
        total = (eng.get("TOTAL") or {})
        notes = []
        engine_sum = sum((eng[n].get(k) or 0) for n in eng if n != "TOTAL" for k in _CX_SEVS)
        if c.get("total_results") is not None and engine_sum != c["total_results"]:
            notes.append("«Total Results» del log (%d) no coincide con la suma de los motores (%d)." % (c["total_results"], engine_sum))
        nb = sum((total.get(k) or 0) for k in ("medium", "low", "info"))
        if nb:
            notes.append("El breaker solo evalúa Critical/High: los %d hallazgo(s) Medium/Low/Info no bloquean, pero siguen siendo deuda de seguridad." % nb)
        if c.get("scs_warning"):
            notes.append("SCS (Scorecard) no se ejecutó: " + c["scs_warning"])
        elif any(r["name"] == "SCS" and r["status"] == "Partial" for r in rows):
            notes.append("SCS con estado Partial: el análisis de supply chain quedó incompleto.")
        flt = c.get("sast_filter") or ""
        if "/test/" in flt:
            notes.append("El filtro SAST excluye **/test/**: el código de pruebas no se escanea.")
        meta = {k: c[k] for k in ("project", "scan_id", "branch", "created_at", "scan_types", "risk_level", "task_version", "cli_version") if c.get(k)}
        return {"rows": rows, "total_results": c.get("total_results"), "meta": meta, "notes": notes}

    def cxone_match(self) -> Optional[Dict[str, Any]]:
        """Cruce del PDF de Checkmarx con el log (conteos) y con el JSON de CxOne (hallazgos), si hay PDF."""
        pdf = self.tool_reports.get("cxone_pdf")
        if not pdf:
            return None
        js = self.tool_reports.get("cxone")
        return reconcile(pdf, self.last.metrics.get("cxone"), js["items"] if js else None)

    @property
    def last(self) -> Run:
        return self.runs[-1]

    def comparison(self) -> List[Dict[str, Any]]:
        return comparison_table([{"metrics": r.metrics} for r in self.runs])

    def diff(self) -> Optional[Dict[str, List[Finding]]]:
        if len(self.runs) < 2:
            return None
        return findings_diff(self.runs[-2].findings, self.runs[-1].findings, self.runs[-1].metrics)

    def gates(self) -> List[Dict[str, str]]:
        """Estado de cada breaker/verificación en la última ejecución."""
        m = self.last.metrics
        t = m["tests"]
        out = []
        if t.get("total"):
            failed = t["failures"] + t["errors"]
            out.append({"name": "Tests unitarios", "status": "OK" if not failed else "FALLO",
                        "detail": "%d/%d OK (%s)" % (t["total"] - failed, t["total"], t.get("framework", "?"))})
        s = m["sonar"]
        if s.get("executed"):
            out.append({"name": "SonarQube", "status": s.get("breaker") or s.get("gate_status") or "N/D",
                        "detail": "Quality gate " + (s.get("gate_status") or "?"),
                        "related": [f.uid for f in self.pipeline_findings() if f.id in ("SONAR_STALE_GATE", "SONAR_RACE")]})
        mods = m["cxone"].get("modules", {})
        for mod in ("SAST", "SCA"):
            if mod in mods:
                d = mods[mod]
                out.append({"name": "CxOne " + mod, "status": "OK" if d["status"] == "PASO" else "FALLO",
                            "detail": "%d Critical / %d High%s" % (d["critical"], d["high"], self._cx_extra(mod))})
        if m["tmas"].get("breaker"):
            out.append({"name": "TMAS", "status": m["tmas"]["breaker"],
                        "detail": "%s Critical / %s High" % (m["tmas"].get("critical"), m["tmas"].get("high"))})
        for tool, label in (("checkstyle", "Checkstyle"), ("pmd", "PMD"), ("spotbugs", "SpotBugs")):
            d = m["static"].get(tool, {})
            if not d.get("step_found"):
                continue
            if d.get("status") == "NO EJECUTADO":
                st, det = "NO EJECUTADO", "Bloqueado por infraestructura"
                related = [f.uid for f in self.pipeline_findings() if f.id == "DOCKER_CONTAINER_CONFLICT"]
            else:
                st = d.get("breaker") or d.get("status")
                if d.get("unsupported_class_versions"):
                    det = "No soporta Java %d" % (max(int(k) for k in d["unsupported_class_versions"]) - 44)
                elif d.get("violations") is not None:
                    det = "%d violaciones" % d["violations"]
                else:
                    det = d.get("status") or ""
            out.append({"name": label, "status": st, "detail": det, "related": related if d.get("status") == "NO EJECUTADO" else []})
        from .rules import SCANNER_LABEL
        for name, d in (m.get("scanners") or {}).items():
            if name == "gitleaks":
                out.append({"name": "Gitleaks", "status": "FALLO" if d["leaks"] else "OK", "detail": "%d secreto(s)" % d["leaks"]})
            elif "critical" in d or "high" in d:
                bad = (d.get("critical") or 0) + (d.get("high") or 0)
                out.append({"name": SCANNER_LABEL.get(name, name), "status": "FALLO" if bad else "OK",
                            "detail": "%s Critical / %s High" % (d.get("critical", 0), d.get("high", 0))})
        sec = m.get("security")
        if sec:
            n = len(sec["secrets_in_clear"])
            alerts = sum(1 for c in sec["checklist"] if c["status"] == "ALERTA")
            out.append({"name": "Secretos en el log", "status": "FALLO" if n else "OK",
                        "detail": "%d posible(s) secreto(s)" % n if n else "Sin secretos en claro"})
            out.append({"name": "Controles de seguridad", "status": "OK" if not alerts else "ALERTA",
                        "detail": "%d de %d en alerta" % (alerts, len(sec["checklist"]))})
        return out

    def checklist(self) -> List[Dict[str, str]]:
        return (self.last.metrics.get("security") or {}).get("checklist", [])

    # --- separación proyecto / pipeline: lo del pipeline lo administra otro equipo y va al final como recomendaciones
    def project_findings(self) -> List[Finding]:
        """Hallazgos que el equipo del proyecto puede corregir (logs + pom)."""
        return [f for f in self.last.findings if not is_pipeline_owned(f)] + self.pom_findings

    def pipeline_findings(self) -> List[Finding]:
        return [f for f in self.last.findings if is_pipeline_owned(f)]

    def pipeline_map(self) -> Dict[str, Finding]:
        return {f.uid: f for f in self.pipeline_findings()}

    def pipeline_groups(self) -> "tuple":
        """(afectan a que el proyecto pase, resto): los primeros bloquean o causan un síntoma visible en el proyecto."""
        referenced = {u for f in self.project_findings() for u in f.related}
        pl = self.pipeline_findings()
        return [f for f in pl if f.blocks or f.uid in referenced], [f for f in pl if not (f.blocks or f.uid in referenced)]

    def pass_plan(self) -> List[Dict[str, Any]]:
        """Ruta ordenada para pasar el pipeline (ver plan.py)."""
        return build_plan(self.project_findings(), self.pipeline_findings(), self.gates())

    def action_plan(self, limit: int = 12) -> List[Finding]:
        """Qué corregir para pasar: hallazgos del proyecto y, marcados, los del pipeline que bloquean."""
        items = [f for f in self.project_findings() + [f for f in self.pipeline_findings() if f.blocks]
                 if f.severity in ("CRITICAL", "HIGH", "MEDIUM")]
        items.sort(key=lambda f: SEVERITY_RANK[f.severity])
        return items[:limit]

    def verdict(self) -> str:
        gates = self.gates()
        bad = [g["name"] for g in gates if g["status"] not in ("OK", "PASO", "ALERTA")]
        if not bad:
            return "Todos los breakers pasaron: listo para aprobar."
        return "Bloqueado por: " + ", ".join(bad)


def _fmt(v: Any) -> str:
    if v is None:
        return "-"
    if isinstance(v, float) and v.is_integer():
        return str(int(v))
    return str(v)


def _sev_counts(findings: List[Finding]) -> Dict[str, int]:
    return {s: sum(1 for f in findings if f.severity == s) for s in SEVERITIES}


# ====================================================================== consola

_ANSI = {"CRITICAL": "\033[1;31m", "HIGH": "\033[31m", "MEDIUM": "\033[33m", "LOW": "\033[36m", "INFO": "\033[37m",
         "OK": "\033[32m", "FALLO": "\033[31m", "NO EJECUTADO": "\033[35m", "ALERTA": "\033[33m", IMPROVED: "\033[32m", WORSE: "\033[31m"}
_RESET = "\033[0m"
_TREND_TXT = {IMPROVED: "↑ mejoró", WORSE: "↓ empeoró", SAME: "= igual", NA: "·"}
_TREND_ASCII = {IMPROVED: "+ mejoró", WORSE: "- empeoró", SAME: "= igual", NA: "."}


def _table(headers: List[str], rows: List[List[str]], color: bool, color_cols=()) -> str:
    widths = [max(len(str(h)), *(len(str(r[i])) for r in rows)) if rows else len(h) for i, h in enumerate(headers)]
    sep = "+" + "+".join("-" * (w + 2) for w in widths) + "+"

    def line(cells, paint=False):
        parts = []
        for i, c in enumerate(cells):
            txt = str(c).ljust(widths[i])
            if paint and color and i in color_cols:
                key = next((k for k in _ANSI if str(c).startswith(k) or k in str(c)), None)
                if key:
                    txt = _ANSI[key] + txt + _RESET
            parts.append(" " + txt + " ")
        return "|" + "|".join(parts) + "|"

    out = [sep, line(headers), sep]
    out += [line(r, True) for r in rows]
    out.append(sep)
    return "\n".join(out)


def render_console(a: Analysis, color: bool = True, unicode: bool = True) -> str:
    trend_txt = _TREND_TXT if unicode else _TREND_ASCII
    L: List[str] = []
    L.append("=" * 78)
    L.append(" ANÁLISIS DE PIPELINE — %d ejecución(es)" % len(a.runs))
    L.append("=" * 78)
    for r in a.runs:
        meta = r.metrics["meta"]
        L.append(" %s %-16s %-14s %s  (%s min)  %s" % ("•" if unicode else "*", r.label, meta.get("provider_label", ""), meta.get("start") or "",
                                                 round((meta.get("duration_s") or 0) / 60, 1), short_origin(meta["file"])))
    L.append("")
    L.append(" VEREDICTO (última ejecución): " + a.verdict())
    L.append("")
    L.append(_table(["Verificación", "Estado", "Detalle"],
                    [[g["name"], g["status"], g["detail"]] for g in a.gates()], color, color_cols=(1,)))

    cx = a.cxone_summary()
    if cx:
        L.append("\n RESULTADOS DE CXONE" + (" · %d en total" % cx["total_results"] if cx["total_results"] is not None else ""))
        L.append(_table(["Motor", "Critical", "High", "Medium", "Low", "Info", "Estado"],
                        [[("  ↳ " if r.get("sub") else "") + r["name"]] + [_cx_cell(v, r["ran"]) for v in r["counts"]] +
                         [r["status"] if r["ran"] else "no ejecutado"] for r in cx["rows"]], color))
        L += [" · " + n for n in cx["notes"]]

    if len(a.runs) > 1:
        L.append("\n COMPARATIVA")
        rows = a.comparison()
        headers = ["Métrica"] + [r.label for r in a.runs] + ["vs anterior", "vs primera"]
        L.append(_table(headers, [[row["label"]] + [_fmt(v) for v in row["values"]] +
                                  [trend_txt[row["trend_prev"]], trend_txt[row["trend_first"]]] for row in rows],
                        color, color_cols=(len(headers) - 2, len(headers) - 1)))
        d = a.diff()
        if d:
            L.append("\n CAMBIOS EN HALLAZGOS (%s → %s)" % (a.runs[-2].label, a.runs[-1].label))
            for name, lab in (("resolved", "Resueltos"), ("unverified", "No verificables (herramienta no ejecutada)"),
                              ("new", "Nuevos"), ("persistent", "Persisten")):
                L.append("  %s (%d):" % (lab, len(d[name])))
                for f in d[name]:
                    L.append("    - [%s] %s" % (f.severity, f.title))

    pmap = a.pipeline_map()
    L.append("\n PLAN DE ACCIÓN: qué corregir para pasar (prioridad)")
    for i, f in enumerate(a.action_plan(), 1):
        L.append("  %2d. [%s] %s%s" % (i, f.severity, f.title, "  <- depende del pipeline" if is_pipeline_owned(f) else ""))
    L.append("\n" + ("%s · pipeline-analyzer %s" % (BRAND, __version__)).rjust(78))

    L.append("\n HALLAZGOS DEL PROYECTO — %s" % a.last.label)
    for f in a.last.findings:
        if not is_pipeline_owned(f):
            L.append(_finding_console(f, color, pmap))
    if a.pom_findings:
        L.append("\n HALLAZGOS DEL POM — %s" % short_path(a.pom_path))
        for f in a.pom_findings:
            L.append(_finding_console(f, color, pmap))

    affecting, others = a.pipeline_groups()
    if affecting or others:
        L.append("\n RECOMENDACIONES PARA QUIEN ADMINISTRA EL PIPELINE")
        L.append("  (no dependen de tu código; las del primer grupo sí afectan a que tu proyecto pase)")
        if affecting:
            L.append("\n  Afectan a que tu proyecto pase:")
            L += [_finding_console(f, color, pmap) for f in affecting]
        if others:
            L.append("\n  Otras mejoras de seguridad y mantenimiento:")
            L += [_finding_console(f, color, pmap) for f in others]
    if a.checklist():
        L.append("\n VALIDACIONES DE SEGURIDAD (referencia) — %s" % a.last.label)
        L.append(_table(["Área", "Validación", "Estado", "Detalle"],
                        [[c["area"], c["check"], c["status"], c["detail"][:70]] for c in a.checklist()],
                        color, color_cols=(2,)))
    return "\n".join(L)


def _finding_console(f: Finding, color: bool, pmap: Optional[Dict[str, Finding]] = None) -> str:
    sev = ("%s[%s]%s" % (_ANSI[f.severity], f.severity, _RESET)) if color else "[%s]" % f.severity
    out = ["", "  %s %s  (%s%s)" % (sev, f.title, f.category, ", " + f.where if f.where else "")]
    for u in f.related:
        if pmap and u in pmap:
            out.append("     Depende del pipeline: %s (ver recomendaciones del pipeline, al final)" % pmap[u].title)
    if f.why:
        out.append("     Por qué: " + f.why)
    for e in f.evidence[:6]:
        out.append("     Evidencia: " + e)
    for i, s in enumerate(f.steps, 1):
        out.append("     %d) %s" % (i, s))
    for c in f.commands:
        out.append("     $ " + c)
    return "\n".join(out)


# ====================================================================== Markdown

_SEV_MD = {"CRITICAL": "🔴 CRITICAL", "HIGH": "🟠 HIGH", "MEDIUM": "🟡 MEDIUM", "LOW": "🔵 LOW", "INFO": "⚪ INFO"}
_TREND_MD = {IMPROVED: "✅ mejoró", WORSE: "🔴 empeoró", SAME: "➖ igual", NA: "·"}
_CHECK_MD = {"OK": "✅ OK", "ALERTA": "⚠️ ALERTA", "N/D": "· N/D", "INFO": "ℹ️ INFO"}
_STATUS_MD = {"OK": "✅ OK", "PASO": "✅ OK", "FALLO": "❌ FALLO", "NO EJECUTADO": "⚠️ NO EJECUTADO", "ALERTA": "⚠️ ALERTA"}


def _md_escape(s: Any) -> str:
    return str(s).replace("|", "\\|").replace("<", "&lt;").replace(">", "&gt;")


def render_markdown(a: Analysis) -> str:
    L: List[str] = []
    L.append("# Reporte de análisis de pipeline")
    L.append("")
    L.append("_Generado el %s con pipeline-analyzer %s · %s_" % (datetime.now().strftime("%Y-%m-%d %H:%M"), __version__, BRAND))
    L.append("")
    L.append("## Ejecuciones analizadas")
    L.append("")
    L.append("| Etiqueta | Proveedor | Inicio | Duración (min) | PR | Archivos | Origen |")
    L.append("|---|---|---|---|---|---|---|")
    for r in a.runs:
        mt = r.metrics["meta"]
        att = " (intento %s/%s)" % (mt["attempt"], mt["attempts"]) if mt.get("attempts", 1) > 1 else ""
        L.append("| %s | %s | %s | %s | %s | %s | `%s` |" % (r.label, mt.get("provider_label", "-"), mt.get("start") or "-",
                                                          round((mt.get("duration_s") or 0) / 60, 1), mt.get("pull_request") or "-",
                                                          str(mt.get("sources", 1)) + att, short_origin(mt["file"])))
    L.append("")
    L.append("## Resumen — %s" % a.last.label)
    L.append("")
    L.append("**Veredicto:** " + a.verdict())
    L.append("")
    L.append("| Verificación | Estado | Detalle |")
    L.append("|---|---|---|")
    for g in a.gates():
        L.append("| %s | %s | %s |" % (g["name"], _STATUS_MD.get(g["status"], g["status"]), _md_escape(g["detail"])))
    counts = _sev_counts(a.project_findings())
    L.append("")
    L.append("Hallazgos: " + " · ".join("%s: **%d**" % (_SEV_MD[s], n) for s, n in counts.items() if n))
    L += _cxone_summary_md(a)
    if a.tool_reports.get("cxone_pdf"):
        L += CV.findings_md(a.tool_reports["cxone_pdf"], False)

    if len(a.runs) > 1:
        L.append("")
        L.append("## Comparativa entre ejecuciones")
        L.append("")
        L.append("| Métrica | " + " | ".join(r.label for r in a.runs) + " | vs anterior | vs primera |")
        L.append("|---|" + "---|" * (len(a.runs) + 2))
        for row in a.comparison():
            L.append("| %s | %s | %s | %s |" % (row["label"], " | ".join(_md_escape(_fmt(v)) for v in row["values"]),
                                              _TREND_MD[row["trend_prev"]], _TREND_MD[row["trend_first"]]))
        d = a.diff()
        if d:
            L.append("")
            L.append("### Cambios en hallazgos (%s → %s)" % (a.runs[-2].label, a.runs[-1].label))
            for name, lab in (("resolved", "✅ Resueltos"), ("unverified", "❔ No verificables (herramienta no ejecutada)"),
                              ("new", "🆕 Nuevos"), ("persistent", "⏳ Persisten")):
                L.append("")
                L.append("**%s (%d)**" % (lab, len(d[name])))
                L.append("")
                for f in d[name]:
                    L.append("- %s — %s" % (_SEV_MD[f.severity], _md_escape(f.title)))
                if not d[name]:
                    L.append("- _ninguno_")

    L.append("")
    L.append("## Plan de acción: qué corregir para pasar")
    L.append("")
    for i, f in enumerate(a.action_plan(), 1):
        L.append("%d. %s — %s _(%s)_%s" % (i, _SEV_MD[f.severity], _md_escape(f.title), f.category,
                                          " · ⚙ [depende del pipeline](#%s)" % pipeline_anchor(f) if is_pipeline_owned(f) else ""))

    pmap = a.pipeline_map()
    L.append("")
    L.append("## Hallazgos del proyecto — %s" % a.last.label)
    for f in a.last.findings:
        if not is_pipeline_owned(f):
            L.extend(_finding_md(f, pmap))
    if a.pom_findings:
        L.append("")
        L.append("## Hallazgos del pom.xml")
        L.append("")
        L.append("`%s`" % short_path(a.pom_path))
        for f in a.pom_findings:
            L.extend(_finding_md(f, pmap))

    affecting, others = a.pipeline_groups()
    if affecting or others:
        L.append("")
        L.append("## Recomendaciones para quien administra el pipeline")
        L.append("")
        L.append("_No dependen del código del proyecto. Las del primer grupo sí afectan a que el proyecto pase._")
        for title, group in (("Afectan a que el proyecto pase", affecting), ("Otras mejoras de seguridad y mantenimiento", others)):
            if group:
                L.append("")
                L.append("### %s" % title)
                for f in group:
                    L.extend(_finding_md(f, pmap, anchor=True))
    if a.checklist():
        L.append("")
        L.append("## Validaciones de seguridad (referencia) — %s" % a.last.label)
        L.append("")
        L.append("| Área | Validación | Estado | Detalle |")
        L.append("|---|---|---|---|")
        for c in a.checklist():
            L.append("| %s | %s | %s | %s |" % (c["area"], c["check"], _CHECK_MD.get(c["status"], c["status"]), _md_escape(c["detail"])))
    L.append("")
    return "\n".join(L)


def _finding_md(f: Finding, pmap: Optional[Dict[str, Finding]] = None, anchor: bool = False) -> List[str]:
    L = [""] + (["<a id='%s'></a>" % pipeline_anchor(f)] if anchor else [])
    L += ["%s %s %s" % ("####" if anchor else "###", _SEV_MD[f.severity], _md_escape(f.title)), ""]
    for u in f.related:
        if pmap and u in pmap:
            L += ["⚙ **Depende del pipeline:** [%s](#%s)" % (_md_escape(pmap[u].title), pipeline_anchor(pmap[u])), ""]
    meta = "**Categoría:** %s" % f.category
    if f.where:
        meta += " · **Ubicación en el log:** `%s`" % f.where
    L.append(meta)
    L.append("")
    if f.why:
        L.append(f.why)
        L.append("")
    if f.evidence:
        L.append("**Evidencia:**")
        L.append("")
        L += ["- `%s`" % e.replace("`", "'") for e in f.evidence[:10]]
        L.append("")
    if f.steps:
        L.append("**Remediación:**")
        L.append("")
        L += ["%d. %s" % (i, s) for i, s in enumerate(f.steps, 1)]
        L.append("")
    for c in f.commands:
        L += ["```bash", c, "```"]
    if f.snippet:
        lang = "xml" if f.snippet.lstrip().startswith("<") else ("yaml" if f.snippet.lstrip().startswith("#") else
                                                                 "bash" if f.snippet.lstrip().startswith("mvn") else "java")
        L += ["```" + lang, f.snippet, "```"]
    return L


# ====================================================================== HTML

_CSS = CV.CSS_VARS + CV.CSS + """
:root{--bg:#f7f7f5;--card:#fff;--fg:#1d1d1b;--muted:#6b6b66;--border:#e3e2dc;--ok:#1f7a4d;--okbg:#e3f3ea;
--bad:#b42318;--badbg:#fde8e6;--warn:#9a6700;--warnbg:#fff4d6;--info:#2f5fa7;--infobg:#e6eefb;--code:#f1f0ec}
@media (prefers-color-scheme:dark){:root{--bg:#161615;--card:#1f1f1d;--fg:#ecebe6;--muted:#a3a29b;--border:#34332f;
--ok:#5cc58f;--okbg:#17301f;--bad:#ff8a7a;--badbg:#3a1c18;--warn:#f2c14e;--warnbg:#342a10;--info:#8fb4f5;--infobg:#18243a;--code:#2a2926}}
*{box-sizing:border-box}html{-webkit-text-size-adjust:100%}body{overflow-wrap:anywhere;margin:0;background:var(--bg);color:var(--fg);font:15px/1.7 system-ui,-apple-system,"Segoe UI",sans-serif}
main{width:100%;max-width:none;margin:0 auto;padding:clamp(12px,2.5vw,40px) clamp(12px,3vw,48px) 60px}h1{font-size:26px;margin:0 0 4px}h2{font-size:20px;margin:56px 0 18px}
.sub{color:var(--muted);margin:0 0 24px}.card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:22px 26px;margin:0 0 8px}
.verdict{font-weight:600;margin-bottom:20px;font-size:16px}.gates{display:grid;grid-template-columns:repeat(auto-fill,minmax(min(100%,180px),1fr));gap:16px}
.gate{border:1px solid var(--border);border-radius:10px;padding:14px 16px;background:var(--card)}.gate b{display:block;font-size:13px;color:var(--muted);font-weight:500}
.gate .st{font-weight:700;font-size:15px}.gate .d{font-size:13px;color:var(--muted)}
.ok{color:var(--ok)}.bad{color:var(--bad)}.warn{color:var(--warn)}
.tbl{width:100%;overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:14px;table-layout:auto}td code{white-space:normal}th,td{padding:10px 14px;border-bottom:1px solid var(--border);text-align:left;vertical-align:top}td{overflow-wrap:anywhere;word-break:break-word}td:last-child{min-width:120px}
th{font-size:12px;text-transform:uppercase;letter-spacing:.03em;color:var(--muted);font-weight:600}td.num{font-variant-numeric:tabular-nums}
.pill{display:inline-block;padding:1px 8px;border-radius:99px;font-size:12px;font-weight:600;white-space:nowrap}
.p-ok{background:var(--okbg);color:var(--ok)}.p-bad{background:var(--badbg);color:var(--bad)}.p-warn{background:var(--warnbg);color:var(--warn)}.p-info{background:var(--infobg);color:var(--info)}.p-na{color:var(--muted)}
.sev-CRITICAL,.sev-HIGH{background:var(--badbg);color:var(--bad)}.sev-MEDIUM{background:var(--warnbg);color:var(--warn)}.sev-LOW,.sev-INFO{background:var(--infobg);color:var(--info)}
details{background:var(--card);border:1px solid var(--border);border-radius:10px;margin:14px 0}summary{cursor:pointer;padding:14px 18px;display:flex;gap:12px;align-items:center;flex-wrap:wrap}
summary .t{font-weight:600;flex:1;min-width:min(100%,220px)}summary .c{color:var(--muted);font-size:13px}.fb{padding:4px 22px 22px}.fb p{margin:12px 0}.fb b{display:block;margin:18px 0 6px}.fb ul,.fb ol{margin:8px 0 12px}.fb li{margin:6px 0}
.fb ol{padding-left:20px;margin:6px 0}code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px}
pre{background:var(--code);padding:10px 12px;border-radius:6px;overflow-x:auto;white-space:pre-wrap;overflow-wrap:anywhere;word-break:break-word;max-width:100%}.ev li{font-family:ui-monospace,Menlo,monospace;font-size:12.5px;overflow-wrap:anywhere;white-space:pre-wrap}
.counts{display:flex;gap:10px;flex-wrap:wrap;margin-top:20px}.diffcols{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,260px),1fr));gap:12px}.diffcols>*,.gates>*{min-width:0}
.diffcols ul{padding-left:18px;margin:6px 0}.dep{background:var(--infobg);border-radius:10px;padding:12px 16px;margin:20px 0 0}.chip{display:inline-block;background:var(--infobg);color:var(--info);border:1px solid var(--info);border-radius:8px;padding:1px 9px;font-size:12px;font-weight:600;text-decoration:none;margin:2px 4px 2px 0;line-height:1.35}.chip:hover{text-decoration:underline}
details:target{outline:2px solid var(--info)}details,h2{scroll-margin-top:12px}h3{font-size:16px;margin:32px 0 12px}a{color:var(--info)}
.nav{display:flex;flex-wrap:wrap;gap:10px;margin:0 0 28px}.nav a{background:var(--card);border:1px solid var(--border);border-radius:99px;padding:3px 12px;text-decoration:none;font-size:13px;color:var(--fg)}.nav a:hover{border-color:var(--info);color:var(--info)}
.step{display:flex;gap:18px;background:var(--card);border:1px solid var(--border);border-radius:12px;padding:22px 26px;margin:20px 0}.step .sn{flex:none;width:32px;height:32px;border-radius:50%;background:var(--info);color:#fff;display:grid;place-items:center;font-weight:700}
.step .sb{flex:1;min-width:0}.step h3{margin:0 0 10px;font-size:17px}.acts{padding-left:22px;margin:14px 0}.acts>li{margin:18px 0}.acts ul{margin:8px 0 0;padding-left:18px;color:var(--muted);font-size:14px}
.done{background:var(--okbg);color:var(--ok);border-radius:10px;padding:10px 14px;margin:20px 0 0}.hint{background:var(--infobg);border-radius:10px;padding:10px 14px;margin:14px 0;font-size:14px}
.tooldet{background:var(--bg);margin:16px 0}.tooldet .tbl{padding:0 12px 10px}.tooldet details{margin:6px 12px}
.warnbox{background:var(--warnbg);color:var(--warn);border:1px solid var(--warn);border-radius:8px;padding:10px 14px;margin:0 0 18px;font-weight:600}
.sec{background:none;border:0;border-top:1px solid var(--border);border-radius:0;margin:0}.sec>summary{padding:22px 4px;list-style:none;gap:14px}
.sec>summary::-webkit-details-marker{display:none}.sec>summary::before{content:'▸';color:var(--muted);font-size:15px;width:14px;transition:transform .15s}
.sec[open]>summary::before{transform:rotate(90deg)}.sec>summary:hover h2{color:var(--info)}.sec>summary h2{margin:0;flex:none;font-size:18px}
.sec .sc{color:var(--muted);font-size:13px;margin-left:auto}.secb{padding:0 4px 32px}.secb>details:first-child{margin-top:0}
footer{color:var(--muted);font-size:13px;margin-top:56px}
.brand{position:fixed;right:14px;bottom:8px;font-size:12px;font-weight:600;letter-spacing:.06em;color:var(--muted);opacity:.55;pointer-events:none}
@media print{.brand{position:static;text-align:right}}
"""

_TREND_HTML = {IMPROVED: ("p-ok", "▲ mejoró"), WORSE: ("p-bad", "▼ empeoró"), SAME: ("p-na", "= igual"), NA: ("p-na", "·")}


def _e(s: Any) -> str:
    return html.escape(str(s), quote=True)


def _status_cls(st: str) -> str:
    return {"OK": "ok", "PASO": "ok", "FALLO": "bad"}.get(st, "warn")


def render_html(a: Analysis, full: bool = False) -> str:
    """``full=True``: versión de uso local, con valores reales y evidencia completa (no compartir)."""
    H: List[str] = []
    H.append("<!doctype html><html lang='es'><head><meta charset='utf-8'>"
             "<meta name='viewport' content='width=device-width,initial-scale=1'>"
             "<title>Reporte de pipeline%s</title><style>%s</style></head><body><main>" % (" (completo)" if full else "", _CSS))
    H.append("<h1>Reporte de análisis de pipeline%s</h1>" % (" — versión completa" if full else ""))
    if full:
        H.append("<div class='warnbox'>⚠ PRECAUCIÓN - INFORMACIÓN CONFIDENCIAL. Este documento contiene valores reales (secretos, credenciales, hosts y correos) y evidencia sin enmascarar. Trátalo como material sensible: no lo compartas, reenvíes ni adjuntes a tickets o chats; si se expone por error, rota las credenciales que aparezcan en él.</div>")
    H.append("<p class='sub'>%d ejecución(es) · generado %s · pipeline-analyzer %s</p>"
             % (len(a.runs), datetime.now().strftime("%Y-%m-%d %H:%M"), __version__))
    H.append("<nav class='nav'><a href='#ruta'>Ruta para pasar</a>%s<a href='#plan'>Plan de acción</a><a href='#hallazgos'>Hallazgos del proyecto</a>%s%s</nav>"
             % ("<a href='#cxone'>Resultados de CxOne</a>" if a.cxone_summary() else "",
                "<a href='#pipeline-recs'>Recomendaciones del pipeline</a>" if a.pipeline_findings() else "",
                "<a href='#validaciones'>Validaciones</a>" if a.checklist() else ""))

    # Resumen
    H.append("<h2>Resumen — %s</h2><div class='card'>" % _e(a.last.label))
    ok = a.verdict().startswith("Todos")
    pmap = a.pipeline_map()
    H.append("<div class='verdict %s'>%s</div><div class='gates'>" % ("ok" if ok else "bad", _e(a.verdict())))
    for g in a.gates():
        H.append("<div class='gate'><b>%s</b><div class='st %s'>%s</div><div class='d'>%s</div>%s</div>"
                 % (_e(g["name"]), _status_cls(g["status"]), _e(g["status"]), _e(g["detail"]),
                    "".join(_chip(pmap[u]) for u in g.get("related", []) if u in pmap)))
    H.append("</div><div class='counts'>")
    for s, n in _sev_counts(a.project_findings()).items():
        if n:
            H.append("<span class='pill sev-%s'>%s: %d</span>" % (s, s, n))
    H.append("</div>")
    blockers = [f for f in a.pipeline_findings() if f.blocks]
    if blockers:
        H.append("<div class='dep'>⚙ <b>Depende del pipeline</b> (clic para ver la causa y qué pedir al equipo que lo administra): %s</div>"
                 % " ".join(_chip(f) for f in blockers))
    if pmap:
        H.append("<p class='sub'><a href='#pipeline-recs'>Ver las %d recomendaciones para quien administra el pipeline ↓</a></p>" % len(pmap))
    H.append("</div>")

    # ---- Lo principal, siempre visible: qué bloquea y qué puede resolver el equipo de desarrollo
    H.append(_plan_html(a, full, pmap))
    H.append(_cxone_summary_html(a))

    # ---- El resto, plegado: solo el título hasta que el usuario lo expande
    plan = a.action_plan()
    body = ["<div class='card tbl'><table><tr><th>#</th><th>Severidad</th><th>Hallazgo</th><th>Categoría</th></tr>"]
    for i, f in enumerate(plan, 1):
        tag = " " + _chip(f) if is_pipeline_owned(f) else ""
        body.append("<tr><td class='num'>%d</td><td><span class='pill sev-%s'>%s</span></td><td>%s%s</td><td>%s</td></tr>"
                    % (i, f.severity, f.severity, _e(f.title), tag, _e(f.category)))
    body.append("</table></div>")
    H.append(_sec("Plan de acción: qué corregir para pasar", "".join(body), "plan", "%d acción(es)" % len(plan)))

    mine = [f for f in a.last.findings if not is_pipeline_owned(f)]
    body = [_finding_html(f, full, pmap) for f in mine]
    if a.pom_findings:
        body.append("<h3>Hallazgos del pom.xml</h3><p class='sub'><code>%s</code></p>" % _e(a.pom_path if full else short_path(a.pom_path)))
        body += [_finding_html(f, full, pmap) for f in a.pom_findings]
    H.append(_sec("Hallazgos del proyecto — %s" % a.last.label, "".join(body) or "<p class='sub'>Sin hallazgos.</p>", "hallazgos",
                  "%d hallazgo(s)%s" % (len(mine), " + %d del pom" % len(a.pom_findings) if a.pom_findings else "")))

    if len(a.runs) > 1:
        body = ["<div class='card tbl'><table><tr><th>Métrica</th>"]
        body += ["<th>%s</th>" % _e(r.label) for r in a.runs]
        body.append("<th>vs anterior</th><th>vs primera</th></tr>")
        for row in a.comparison():
            body.append("<tr><td>%s</td>" % _e(row["label"]))
            body += ["<td class='num'>%s</td>" % _e(_fmt(v)) for v in row["values"]]
            for k in ("trend_prev", "trend_first"):
                cls, txt = _TREND_HTML[row[k]]
                body.append("<td><span class='pill %s'>%s</span></td>" % (cls, txt))
            body.append("</tr>")
        body.append("</table></div>")
        d = a.diff()
        if d:
            body.append("<h3>Cambios en hallazgos (%s → %s)</h3><div class='diffcols'>" % (_e(a.runs[-2].label), _e(a.runs[-1].label)))
            for name, lab, cls in (("resolved", "Resueltos", "ok"), ("unverified", "No verificables", "warn"),
                                   ("new", "Nuevos", "bad"), ("persistent", "Persisten", "warn")):
                body.append("<div class='card'><b class='%s'>%s (%d)</b><ul>" % (cls, lab, len(d[name])))
                body += ["<li><span class='pill sev-%s'>%s</span> %s</li>" % (f.severity, f.severity, _e(f.title)) for f in d[name]]
                if not d[name]:
                    body.append("<li class='p-na'>ninguno</li>")
                body.append("</ul></div>")
            body.append("</div>")
        H.append(_sec("Comparativa entre ejecuciones", "".join(body), "comparativa", "%d ejecuciones" % len(a.runs)))

    body = ["<div class='card tbl'><table><tr><th>Etiqueta</th><th>Proveedor</th><th>Inicio</th>"
            "<th>Duración</th><th>PR</th><th>Archivos</th><th>Origen</th></tr>"]
    for r in a.runs:
        mt = r.metrics["meta"]
        att = " · intento %s/%s" % (mt["attempt"], mt["attempts"]) if mt.get("attempts", 1) > 1 else ""
        body.append("<tr><td>%s</td><td>%s</td><td>%s</td><td class='num'>%s min</td><td>%s</td><td class='num'>%s%s</td><td><code>%s</code></td></tr>"
                    % (_e(r.label), _e(mt.get("provider_label", "-")), _e(mt.get("start") or "-"),
                       round((mt.get("duration_s") or 0) / 60, 1), _e(mt.get("pull_request") or "-"),
                       mt.get("sources", 1), _e(att), _e(mt["file"] if full else short_origin(mt["file"]))))
    body.append("</table></div>")
    H.append(_sec("Ejecuciones analizadas", "".join(body), "ejecuciones", "%d · %s" % (len(a.runs), a.last.metrics["meta"].get("provider_label", ""))))
    H.append(_review_html(a))

    # Recomendaciones para quien administra el pipeline: configuración del SCM, normalmente fuera del alcance del equipo de desarrollo
    affecting, others = a.pipeline_groups()
    if affecting or others:
        body = ["<p class='sub'>Configuración del pipeline y de la plataforma: por lo general solo el equipo SCM/plataforma tiene acceso. "
                "No dependen del código del proyecto; las del primer grupo sí afectan a que tu proyecto pase.</p>"]
        for title, group in (("Afectan a que tu proyecto pase", affecting), ("Otras mejoras de seguridad y mantenimiento", others)):
            if group:
                body.append("<h3>%s (%d)</h3>" % (title, len(group)))
                body += [_finding_html(f, full, pmap, anchor=True) for f in group]
        H.append(_sec("Recomendaciones para quien administra el pipeline", "".join(body), "pipeline-recs",
                      "%d en total%s" % (len(affecting) + len(others), " · %d afectan a que pase" % len(affecting) if affecting else "")))
    if a.checklist():
        body = ["<div class='card tbl'><table><tr><th>Área</th><th>Validación</th><th>Estado</th><th>Detalle</th></tr>"]
        for c in a.checklist():
            cls = {"OK": "p-ok", "ALERTA": "p-bad", "INFO": "p-info"}.get(c["status"], "p-na")
            body.append("<tr><td>%s</td><td>%s</td><td><span class='pill %s'>%s</span></td><td>%s</td></tr>"
                        % (_e(c["area"]), _e(c["check"]), cls, _e(c["status"]), _e(c["detail"])))
        body.append("</table></div>")
        alerts = sum(1 for c in a.checklist() if c["status"] == "ALERTA")
        H.append(_sec("Validaciones de seguridad (referencia) — %s" % a.last.label, "".join(body), "validaciones",
                      "%d de %d en alerta" % (alerts, len(a.checklist()))))

    H.append("<footer>Las causas probables son heurísticas basadas en el log: confírmalas en SonarQube, "
             "CxOne y los reportes de cada herramienta.<br>%s · pipeline-analyzer %s</footer></main>"
             "<div class='brand' aria-hidden='true'>%s</div><script>%s</script></body></html>" % (BRAND, __version__, BRAND, _JS))
    return "".join(H)


_CX_ORDER = ("APIs", "IAC", "SAST", "SCA", "SCS", "CONTAINERS", "TOTAL")
_CX_SEVS = ("critical", "high", "medium", "low", "info")
_CX_META_LABEL = {"project": "Proyecto", "scan_id": "Scan ID", "branch": "Rama", "created_at": "Creado", "scan_types": "Tipos de escaneo",
                  "risk_level": "Nivel de riesgo", "task_version": "Tarea AST", "cli_version": "AST-CLI"}


def _sec(title: str, body: str, anchor: str, hint: str = "", open_: bool = False) -> str:
    """Sección plegable: solo el título (y un dato breve) hasta que el usuario la expande."""
    return ("<details class='sec' id='%s'%s><summary><h2>%s</h2><span class='sc'>%s</span></summary><div class='secb'>%s</div></details>"
            % (anchor, " open" if open_ else "", _e(title), _e(hint), body))


def _cx_cell(v: Any, ran: bool) -> str:
    return "-" if v is None or not ran else str(v)


def _cxone_summary_html(a: Analysis) -> str:
    s = a.cxone_summary()
    if not s:
        return ""
    H = ["<h2 id='cxone'>Resultados de CxOne</h2><div class='card'>", CV.summary_html(s)]
    H += ["<p class='hint'>💡 %s</p>" % _e(n) for n in s["notes"]]
    H.append("</div>")
    return "".join(H)


def _review_html(a: Analysis) -> str:
    rv = a.review
    if not rv or not rv["files"]:
        return ""
    c = rv["counts"]
    H = ["<div class='card'><p>%d archivo(s): %d log(s), %d definición(es) de pipeline, %d reporte(s) de herramientas leídos, %d ignorado(s).</p>"
         % (c["total"], c["logs"], c["definiciones"], c["reportes"], c["ignorados"])]
    cap = 400
    H.append("<details><summary>Ver el detalle de cada archivo%s</summary><div class='tbl'><table><tr><th>Archivo</th><th>Tratamiento</th></tr>"
             % (" (primeros %d)" % cap if len(rv["files"]) > cap else ""))
    for f in rv["files"][:cap]:
        bad = f["status"].startswith(("ignorado", "no ", "sin ", "omitido", "reporte de herramienta"))
        H.append("<tr><td><code>%s</code></td><td class='%s'>%s</td></tr>" % (_e(f["file"]), "p-na" if bad else "", _e(f["status"])))
    H.append("</table></div></details></div>")
    return _sec("Archivos revisados", "".join(H), "archivos", "%d archivo(s)" % c["total"])


def _cxone_summary_md(a: Analysis) -> List[str]:
    s = a.cxone_summary()
    if not s:
        return []
    L = ["", "## Resultados de CxOne" + (" · %d en total" % s["total_results"] if s["total_results"] is not None else ""), ""]
    if s["meta"]:
        L += ["_%s_" % " · ".join("%s: %s" % (_CX_META_LABEL[k], v) for k, v in s["meta"].items()), ""]
    L += ["| Motor | Critical | High | Medium | Low | Info | Estado |", "|---|---|---|---|---|---|---|"]
    for r in s["rows"]:
        L.append("| %s | %s | %s |" % (("↳ " if r.get("sub") else "") + r["name"], " | ".join(_cx_cell(v, r["ran"]) for v in r["counts"]),
                                       r["status"] if r["ran"] else "no ejecutado"))
    L += [""] + ["- %s" % _md_escape(n) for n in s["notes"]]
    return L


_STATIC_TOOLS = ("pmd", "checkstyle", "spotbugs")


def _tools_html(a: Analysis, tools, full: bool) -> str:
    """Tablas por regla y lista de ubicaciones de los reportes de herramientas que se pasaron con --reports."""
    H: List[str] = []
    for tool in tools:
        rep = a.tool_reports.get(tool)
        if not rep:
            continue
        items = rep["items"]
        sm = TR.summarize(rep)
        H.append("<details class='tooldet'><summary><b>%s</b> · %d hallazgo(s) en %d archivo(s) <span class='c'>(reporte: %s)</span></summary>"
                 % (TR.label(tool), sm["total"], sm["files"], _e(", ".join(rep["sources"][:3]))))
        H.append("<div class='tbl'><table><tr><th>Regla</th><th>Sev.</th><th>Cant.</th><th>Archivos</th><th>Ejemplo</th></tr>")
        for g in TR.by_rule(items)[:30]:
            ex = g["example"]
            loc = "%s%s" % (TR.short_file(ex["file"], full), ":%d" % ex["line"] if ex["line"] else "")
            H.append("<tr><td><code>%s</code></td><td><span class='pill sev-%s'>%s</span></td><td class='num'>%d</td><td class='num'>%d</td>"
                     "<td><code>%s</code>%s</td></tr>"
                     % (_e(g["rule"]), g["severity"], g["severity"], g["count"], g["files"], _e(loc),
                        "<div class='sub'>%s</div>" % _e(g["message"][:200]) if g["message"] else ""))
        H.append("</table></div>")
        cap = 500
        H.append("<details><summary>Todas las ubicaciones%s</summary><div class='tbl'><table><tr><th>Archivo:línea</th><th>Regla</th>"
                 "<th>Sev.</th><th>Mensaje</th></tr>" % (" (primeras %d de %d)" % (cap, len(items)) if len(items) > cap else " (%d)" % len(items)))
        for it in items[:cap]:
            extra = " · %s" % it["state"] if it.get("state") else ""
            H.append("<tr><td><code>%s%s</code></td><td><code>%s</code></td><td><span class='pill sev-%s'>%s</span></td><td>%s%s</td></tr>"
                     % (_e(TR.short_file(it["file"], full)), ":%d" % it["line"] if it["line"] else "", _e(it["rule"]), it["severity"],
                        it["severity"], _e(it["message"][:240]), _e(extra)))
        H.append("</table></div></details></details>")
    return "".join(H)


_MATCH_TXT = {"coincide": ("coincide", "p-ok"), "coincide_con_resueltos": ("coincide si se cuentan los Not Exploitable", "p-info"),
              "difiere": ("difiere", "p-bad"), "solo_pdf": ("solo en el PDF", "p-bad")}


def _cxone_match_html(a: Analysis, full: bool) -> str:
    m = a.cxone_match()
    if not m:
        return ""
    verdict = {"ok": ("Coinciden con el log", "p-ok"), "differences": ("Hay diferencias", "p-bad"), "nolog": ("Sin conteos en el log", "p-info")}[m["verdict"]]
    H = ["<details class='tooldet' open><summary><b>PDF de Checkmarx ↔ resultados del pipeline</b> <span class='pill %s'>%s</span></summary>" % (verdict[1], verdict[0])]
    meta = m["meta"]
    if meta:
        H.append("<p class='sub'>%s</p>" % _e(" · ".join("%s: %s" % (k.replace("_", " "), v) for k, v in meta.items())))
    if m["counts"]:
        H.append("<div class='tbl'><table><tr><th>Motor</th><th>Severidad</th><th>Log</th><th>PDF</th><th>Resultado</th></tr>")
        for r in m["counts"]:
            txt, cls = _MATCH_TXT[r["state"]]
            H.append("<tr><td>%s</td><td><span class='pill sev-%s'>%s</span></td><td class='num'>%s</td><td class='num'>%d%s</td>"
                     "<td><span class='pill %s'>%s</span></td></tr>"
                     % (_e(r["engine"]), r["severity"], r["severity"], "-" if r["log"] is None else r["log"], r["pdf"],
                        " <span class='c'>(%d con Not Exploitable)</span>" % r["pdf_all"] if r["pdf_all"] != r["pdf"] else "", cls, txt))
        H.append("</table></div>")
    if m.get("identity"):
        H.append("<div class='tbl'><table><tr><th>¿Mismo escaneo?</th><th>Log</th><th>PDF</th><th></th></tr>")
        for r in m["identity"]:
            cls, txt = {"igual": ("p-ok", "coincide"), "distinto": ("p-bad", "distinto"), "n/c": ("p-na", "no comparable")}[r["state"]]
            H.append("<tr><td>%s</td><td><code>%s</code></td><td><code>%s</code></td><td><span class='pill %s'>%s</span></td></tr>"
                     % (_e(r["field"]), _e(r["log"]), _e(r["pdf"]), cls, txt))
        H.append("</table></div>")
    it = m["items"]
    if it is not None:
        H.append("<p><b>Contra el JSON de CxOne:</b> %d hallazgo(s) coinciden, %d solo en el PDF, %d solo en el JSON.</p>"
                 % (it["coinciden"], len(it["solo_pdf"]), len(it["solo_json"])))
        for title, rows in (("Solo en el PDF", it["solo_pdf"]), ("Solo en el JSON", it["solo_json"])):
            if rows:
                H.append("<details><summary>%s (%d)</summary><ul class='ev'>%s</ul></details>" % (title, len(rows), "".join(
                    "<li><code>%s</code> · %s%s</li>" % (_e(r["rule"]), _e(TR.short_file(r["file"], full)), ":%d" % r["line"] if r["line"] else "")
                    for r in rows[:100])))
    for n in m["notes"]:
        H.append("<p class='hint'>💡 %s</p>" % _e(n))
    H.append("</details>")
    return "".join(H)


def _plan_html(a: Analysis, full: bool, pmap: Dict[str, Finding]) -> str:
    steps = a.pass_plan()
    H = ["<h2 id='ruta'>Ruta para pasar el pipeline</h2>"]
    if not steps:
        return "".join(H) + "<div class='card'><b class='ok'>Nada bloquea.</b> No hay hallazgos que impidan pasar.</div>"
    nb = sum(1 for s in steps if s["blocks"])
    H.append("<p class='sub'>%d paso(s) en orden: %s. Haz primero los que bloquean; cada uno enlaza con el detalle completo del hallazgo.</p>"
             % (len(steps), "%d bloquea(n)" % nb if nb else "ninguno bloquea"))
    has_static_report = any(t in a.tool_reports for t in _STATIC_TOOLS)
    for s in steps:
        H.append("<section class='step' id='paso-%d'><div class='sn'>%d</div><div class='sb'><h3>%s <span class='pill %s'>%s</span></h3>"
                 "<p class='sub'>%s</p>" % (s["n"], s["n"], _e(s["title"]), "p-bad" if s["blocks"] else "p-info",
                                            "Bloquea" if s["blocks"] else "No bloquea", _e(s["why"])))
        if s["gates"]:
            H.append("<p>Verificaciones en rojo: %s</p>" % " ".join(
                "<span class='pill p-bad'>%s · %s</span>" % (_e(g["name"]), _e(g["status"])) for g in s["gates"]))
        H.append("<ol class='acts'>")
        for f in s["findings"]:
            tag = ""
            if is_pipeline_owned(f):
                tag = " <span class='pill p-info'>lo resuelve quien administra el pipeline</span>"
            ch = "".join(_chip(pmap[u]) for u in f.related if u in pmap)
            todo = "".join("<li>%s</li>" % _e(x) for x in f.steps[:3])
            more = " <a href='#%s'>ver detalle completo →</a>" % finding_anchor(f)
            H.append("<li><span class='pill sev-%s'>%s</span> <b>%s</b>%s%s%s<ul>%s</ul></li>"
                     % (f.severity, f.severity, _e(f.title), tag, (" " + ch) if ch else "", more, todo))
        H.append("</ol>")
        if s["key"] == "static":
            H.append(_tools_html(a, _STATIC_TOOLS, full))
            ids = {f.id for f in s["findings"]}
            if not has_static_report and ids & {"PMD_VIOLATIONS", "CHECKSTYLE_VIOLATIONS", "STATIC_TOOL_FAILED"}:
                H.append("<p class='hint'>💡 El log solo trae conteos. Pasa los reportes con <code>--reports ruta/del/proyecto/target</code> "
                         "para ver aquí la regla, el archivo y la línea de cada violación.</p>")
        if s["key"] == "security":
            H.append(_tools_html(a, ("cxone",), full))
            H.append(_cxone_match_html(a, full))
            pdf = a.tool_reports.get("cxone_pdf")
            if pdf:
                H.append(CV.findings_html(pdf, full))
                if pdf.get("format") != "scan_report":
                    H.append(_tools_html(a, ("cxone_pdf",), full))
            if "cxone" not in a.tool_reports and "cxone_pdf" not in a.tool_reports and any(f.id.startswith("CXONE_") for f in s["findings"]):
                H.append("<p class='hint'>💡 Con el JSON de resultados de CxOne (<code>--reports ruta/al/json</code>) verás el query, el archivo "
                         "y la línea exactos de cada hallazgo. También sirve el PDF que descargas de Checkmarx.</p>")
        H.append("<p class='done'>✔ <b>Listo cuando:</b> %s</p></div></section>" % _e(s["done"]))
    cmds = validation_commands(a.last.metrics["tests"].get("framework", ""), steps)
    if cmds:
        H.append("<div class='card'><b>Antes de subir, valida en local</b> <span class='sub'>(ajusta a la invocación de tu template)</span>%s</div>"
                 % "".join("<pre>%s</pre>" % _e(c) for c in cmds))
    return "".join(H)


def _chip(f: Finding) -> str:
    """Etiqueta que enlaza con la recomendación del pipeline que afecta el resultado."""
    return "<a class='chip' href='#%s' title='Ir a la recomendación'>⚙ pipeline: %s</a>" % (pipeline_anchor(f), _e(f.title))


_JS = ("function o(){var h=location.hash.slice(1),t=h&&document.getElementById(h),e=t;"
       "while(e){if(e.tagName=='DETAILS')e.open=true;e=e.parentElement}if(t&&t.scrollIntoView)t.scrollIntoView()}"
       "addEventListener('hashchange',o);o();"
       "addEventListener('beforeprint',function(){document.querySelectorAll('details.sec').forEach(function(d){d.open=true})})")


def _finding_html(f: Finding, full: bool = False, pmap: Optional[Dict[str, Finding]] = None, anchor: bool = False) -> str:
    H = ["<details%s%s><summary><span class='pill sev-%s'>%s</span><span class='t'>%s</span><span class='c'>%s%s</span></summary><div class='fb'>"
         % (" id='%s'" % finding_anchor(f), " open" if f.severity in ("CRITICAL", "HIGH") else "", f.severity, f.severity, _e(f.title), _e(f.category),
            " · " + f.where if f.where else "")]
    for u in f.related:
        if pmap and u in pmap:
            H.append("<p class='dep'>⚙ <b>Depende del pipeline:</b> %s</p>" % _chip(pmap[u]))
    if f.why:
        H.append("<p>%s</p>" % _e(f.why))
    ev = (f.evidence_full or f.evidence) if full else f.evidence[:10]
    if ev:
        H.append("<b>Evidencia%s</b><ul class='ev'>%s</ul>" % (" (%d)" % len(ev) if full else "", "".join("<li>%s</li>" % _e(e) for e in ev)))
    if f.steps:
        H.append("<b>Remediación</b><ol>%s</ol>" % "".join("<li>%s</li>" % _e(s) for s in f.steps))
    for c in f.commands:
        H.append("<pre>%s</pre>" % _e(c))
    if f.snippet:
        H.append("<pre>%s</pre>" % _e(f.snippet))
    H.append("</div></details>")
    return "".join(H)


# ====================================================================== PDF

_SEV_COLOR = {"CRITICAL": RED, "HIGH": RED, "MEDIUM": AMBER, "LOW": BLUE, "INFO": BLUE}
_STATE_COLOR = {"OK": GREEN, "PASO": GREEN, "FALLO": RED, "ALERTA": RED, "NO EJECUTADO": AMBER, "N/D": AMBER, "INFO": BLUE}
_TREND_TXT = {IMPROVED: "mejoró", WORSE: "empeoró", SAME: "igual", NA: "-"}


def _finding_pdf(d: PdfDoc, f: Finding, full: bool, pmap: Dict[str, Finding], anchor: bool = False) -> None:
    d.badge_line(f.severity, _SEV_COLOR[f.severity], f.title, anchor=pipeline_anchor(f) if anchor else None)
    d.para("%s%s" % (f.category, " · " + f.where if f.where else ""), MUTED, indent=6, size=8)
    for u in f.related:
        if u in pmap:
            d.para("Depende del pipeline: %s  (clic para ver la causa)" % pmap[u].title, BLUE, True, indent=6, link=pipeline_anchor(pmap[u]), size=8.5)
    if f.why:
        d.para(f.why, indent=6)
    ev = (f.evidence_full or f.evidence) if full else f.evidence[:10]
    if ev:
        d.para("Evidencia%s" % (" (%d)" % len(ev) if full else ""), bold=True, indent=6, size=8.5)
        for e in ev:
            d.code(e)
    if f.steps:
        d.para("Remediación", bold=True, indent=6, size=8.5)
        for i, st in enumerate(f.steps, 1):
            d.para(st, indent=14, prefix="%d.  " % i)
    for c in f.commands:
        d.code(c)
    if f.snippet:
        d.code(f.snippet)


def _build_pdf(a: Analysis, full: bool, scrub: Optional[Callable[[str], str]], toc: List[tuple]) -> PdfDoc:
    title = "Reporte de pipeline" + (" (completo)" if full else "")
    d = PdfDoc(title, footer="CONFIDENCIAL - NO COMPARTIR" if full else "", footer_color=RED, scrub=scrub)
    ok = a.verdict().startswith("Todos")
    d.header_band("Reporte de análisis de pipeline" + (" · versión completa" if full else ""),
                  "%d ejecución(es) analizadas · %s · pipeline-analyzer %s"
                  % (len(a.runs), datetime.now().strftime("%Y-%m-%d %H:%M"), __version__), RED if full else BAND)
    if full:
        d.banner("PRECAUCIÓN - INFORMACIÓN CONFIDENCIAL. Este documento contiene valores reales (secretos, credenciales, hosts y correos) y evidencia sin enmascarar. Trátalo como material sensible: no lo compartas, reenvíes ni adjuntes a tickets o chats; si se expone por error, rota las credenciales que aparezcan en él.")
    pmap = a.pipeline_map()

    d.heading("Resumen - %s" % a.last.label, 1, "sec-resumen")
    d.verdict(a.verdict(), ok)
    cards = []
    for g in a.gates():
        related = [u for u in g.get("related", []) if u in pmap]
        detail = g["detail"] + ("  ->  depende del pipeline (clic)" if related else "")
        cards.append((g["name"], g["status"], detail, _STATE_COLOR.get(g["status"], MUTED), pipeline_anchor(pmap[related[0]]) if related else None))
    d.cards(cards)
    counts = _sev_counts(a.project_findings())
    d.chips([("%s: %d" % (s, n), _SEV_COLOR[s]) for s, n in counts.items() if n] or [("Sin hallazgos del proyecto", GREEN)])
    for f in [x for x in a.pipeline_findings() if x.blocks]:
        d.para("Depende del pipeline: %s  (clic para ver la causa)" % f.title, BLUE, True, link=pipeline_anchor(f), size=8.5)
    if pmap:
        d.para("Las %d recomendaciones para quien administra el pipeline están al final del documento." % len(pmap), MUTED, size=8.5)

    if toc:
        d.toc(toc)

    d.heading("Ejecuciones analizadas", 1, "sec-ejecuciones")
    rows = []
    for r in a.runs:
        mt = r.metrics["meta"]
        att = " (intento %s/%s)" % (mt["attempt"], mt["attempts"]) if mt.get("attempts", 1) > 1 else ""
        rows.append([r.label, mt.get("provider_label", "-"), mt.get("start") or "-", "%s min" % round((mt.get("duration_s") or 0) / 60, 1),
                     mt.get("pull_request") or "-", "%s%s" % (mt.get("sources", 1), att), short_origin(mt["file"])])
    d.table(["Etiqueta", "Proveedor", "Inicio", "Duración", "PR", "Archivos", "Origen"], rows)

    cx = a.cxone_summary()
    if cx:
        d.heading("Resultados de CxOne" + (" - %d en total" % cx["total_results"] if cx["total_results"] is not None else ""), 1, "sec-cxone")
        if cx["meta"]:
            d.para(" · ".join("%s: %s" % (_CX_META_LABEL[k], v) for k, v in cx["meta"].items()), MUTED, size=8.5)
        d.table(["Motor", "Critical", "High", "Medium", "Low", "Info", "Estado"],
                [[("-> " if r.get("sub") else "") + r["name"]] + [_cx_cell(v, r["ran"]) for v in r["counts"]] + [r["status"] if r["ran"] else "no ejecutado"]
                 for r in cx["rows"]])
        for n in cx["notes"]:
            d.bullet(n)
    pdf = a.tool_reports.get("cxone_pdf")
    if pdf:
        rows = CV.findings_table(pdf)
        if rows:
            d.heading("Hallazgos de Checkmarx y su solucion", 2)
            d.table(["Severidad", "Consulta / CVE", "Result.", "Solucion propuesta"], rows, lambda i, t: _SEV_COLOR.get(t) if i == 0 else None)

    if len(a.runs) > 1:
        d.heading("Comparativa entre ejecuciones", 1, "sec-comparativa")
        heads = ["Métrica"] + [r.label for r in a.runs] + ["vs anterior", "vs primera"]
        trows = [[row["label"]] + [_fmt(v) for v in row["values"]] + [_TREND_TXT[row["trend_prev"]], _TREND_TXT[row["trend_first"]]]
                 for row in a.comparison()]
        tcol = {"mejoró": GREEN, "empeoró": RED}
        d.table(heads, trows, lambda i, t: tcol.get(t) if i >= len(heads) - 2 else None)
        diff = a.diff()
        if diff:
            d.heading("Cambios en hallazgos (%s -> %s)" % (a.runs[-2].label, a.runs[-1].label), 2)
            for name, lab, col in (("resolved", "Resueltos", GREEN), ("unverified", "No verificables", AMBER),
                                   ("new", "Nuevos", RED), ("persistent", "Persisten", AMBER)):
                d.para("%s (%d)" % (lab, len(diff[name])), col, True, size=9.5)
                for f in diff[name]:
                    d.bullet("[%s] %s" % (f.severity, f.title))

    d.heading("Plan de acción: qué corregir para pasar", 1, "sec-plan")
    plan = a.action_plan()
    d.table(["#", "Severidad", "Hallazgo", "Categoría"],
            [[str(i), f.severity, f.title + ("  [depende del pipeline]" if is_pipeline_owned(f) else ""), f.category]
             for i, f in enumerate(plan, 1)],
            lambda i, t: _SEV_COLOR.get(t) if i == 1 else None,
            links=[pipeline_anchor(f) if is_pipeline_owned(f) else None for f in plan])

    d.heading("Hallazgos del proyecto - %s" % a.last.label, 1, "sec-hallazgos")
    for f in a.last.findings:
        if not is_pipeline_owned(f):
            _finding_pdf(d, f, full, pmap)
    if a.pom_findings:
        d.heading("Hallazgos del pom.xml", 1, "sec-pom")
        d.para(short_path(a.pom_path), MUTED, size=8.5)
        for f in a.pom_findings:
            _finding_pdf(d, f, full, pmap)

    affecting, others = a.pipeline_groups()
    if affecting or others:
        d.heading("Recomendaciones para quien administra el pipeline", 1, "sec-pipeline")
        d.para("No dependen del código del proyecto. Las del primer grupo sí afectan a que tu proyecto pase; las demás son "
               "mejoras de seguridad y mantenimiento.", MUTED, size=8.5)
        for gtitle, group in (("Afectan a que tu proyecto pase", affecting), ("Otras mejoras de seguridad y mantenimiento", others)):
            if group:
                d.heading("%s (%d)" % (gtitle, len(group)), 2)
                for f in group:
                    _finding_pdf(d, f, full, pmap, anchor=True)
    if a.checklist():
        d.heading("Validaciones de seguridad (referencia) - %s" % a.last.label, 1, "sec-validaciones")
        d.table(["Área", "Validación", "Estado", "Detalle"],
                [[c["area"], c["check"], c["status"], c["detail"]] for c in a.checklist()],
                lambda i, t: _STATE_COLOR.get(t) if i == 2 else None)
    d.space(10)
    d.para("Las causas probables son heurísticas basadas en el log: confírmalas en SonarQube, CxOne y los reportes de cada herramienta.",
           MUTED, size=8)
    return d


def render_pdf(a: Analysis, full: bool = False, scrub: Optional[Callable[[str], str]] = None) -> bytes:
    """PDF del reporte. ``full=True``: valores reales y evidencia completa (solo uso local).

    ``scrub`` se aplica a todo el texto antes de dibujarlo (redacción de secretos en la versión para compartir).
    El índice necesita conocer las páginas finales, así que el documento se arma tres veces (la última es la definitiva).
    """
    outline = _build_pdf(a, full, scrub, []).outline
    probe = _build_pdf(a, full, scrub, [(t, an, 0) for t, an in outline])
    toc = [(t, an, probe.dests[an][0] + 1) for t, an in outline if an in probe.dests]
    return _build_pdf(a, full, scrub, toc).render()


# ====================================================================== JSON


_RAW_KEYS = ("raw", "context", "context_full")


def _strip_raw(o: Any) -> Any:
    """Quita de las métricas los valores reales de secretos (solo los usa el HTML completo)."""
    if isinstance(o, dict):
        return {k: _strip_raw(v) for k, v in o.items() if k not in _RAW_KEYS and k != "insecure_http_all"}
    if isinstance(o, list):
        return [_strip_raw(v) for v in o]
    return o


def _short_meta(metrics: Dict[str, Any]) -> Dict[str, Any]:
    if isinstance(metrics.get("meta"), dict) and metrics["meta"].get("file"):
        metrics["meta"]["file"] = short_origin(metrics["meta"]["file"])
    return metrics


def render_json(a: Analysis) -> str:
    data = {
        "generator": "pipeline-analyzer %s" % __version__,
        "author": BRAND,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "verdict": a.verdict(),
        "gates": a.gates(),
        "runs": [{"label": r.label, "metrics": _short_meta(_strip_raw(r.metrics)), "findings": [f.to_dict() for f in r.findings]} for r in a.runs],
        "comparison": a.comparison(),
        "pom": {"path": short_path(a.pom_path), "findings": [f.to_dict() for f in a.pom_findings]},
    }
    d = a.diff()
    if d:
        data["diff"] = {k: [f.uid for f in v] for k, v in d.items()}
    return json.dumps(data, ensure_ascii=False, indent=2, default=str)
