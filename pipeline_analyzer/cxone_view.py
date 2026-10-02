"""Presentación HTML de los resultados de CxOne: tabla de resumen y hallazgos del reporte de Checkmarx con su solución."""

import html
import re
from collections import OrderedDict
from typing import Any, Dict, List

from . import cxone_fixes as FX
from .tool_reports import short_file

SEVS = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
SEV_ES = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low", "INFO": "Info"}
ENGINE_DESC = {"SAST": "Código fuente", "SCA": "Dependencias", "SCS": "Supply chain", "IAC": "Infraestructura", "APIs": "Seguridad de APIs",
               "CONTAINERS": "Imágenes", "TOTAL": "Todos los motores", "Secret Detection": "Secretos en el repo", "Scorecard": "Prácticas del repo"}
_STATE_ES = {"TO_VERIFY": "Por verificar", "CONFIRMED": "Confirmado", "URGENT": "Urgente", "NOT_EXPLOITABLE": "No explotable",
             "PROPOSED_NOT_EXPLOITABLE": "Propuesto no explotable"}
_VERDICT = {"falso_positivo": ("probable falso positivo", "v-fp"), "real": ("problema real", "v-real"), "revisar": ("revisar", "v-rev")}

CSS = """
.cxk{display:flex;flex-wrap:wrap;align-items:center;gap:18px 28px;margin:0 0 20px}
.cxk .big{font-size:40px;font-weight:700;line-height:1;letter-spacing:-.02em}.cxk .big small{display:block;font-size:12px;font-weight:600;color:var(--muted);letter-spacing:.04em;text-transform:uppercase;margin-top:4px}
.cxk .chips{display:flex;flex-wrap:wrap;gap:8px}.kc{display:flex;align-items:center;gap:8px;border:1px solid var(--border);border-radius:10px;padding:6px 12px;background:var(--card)}
.kc b{font-size:20px;line-height:1}.kc span{font-size:12px;color:var(--muted);font-weight:600}.kc i{width:9px;height:9px;border-radius:50%;display:block}
.kc.z{opacity:.55}.kc.z b{font-weight:500}
.cxbar{display:flex;height:10px;border-radius:99px;overflow:hidden;background:var(--code);margin:0 0 24px}.cxbar>span{display:block;min-width:3px}
.s-CRITICAL{--c:var(--sevC)}.s-HIGH{--c:var(--sevH)}.s-MEDIUM{--c:var(--sevM)}.s-LOW{--c:var(--sevL)}.s-INFO{--c:var(--muted)}
.kc i,.cxbar>span{background:var(--c)}
.cxt{width:100%;border-collapse:separate;border-spacing:0;font-size:14px}.cxt th{font-size:13px;color:var(--muted);font-weight:600;
text-align:center;padding:8px 10px;border-bottom:2px solid var(--border)}.cxt th:first-child,.cxt td:first-child{text-align:left}
.cxt td{padding:13px 12px;border-bottom:1px solid var(--border);text-align:center;vertical-align:middle}.cxt tr:last-child td{border-bottom:0}
.cxt .eng b{display:block;font-size:14px}.cxt .eng small{color:var(--muted);font-size:12px}
.cxt .off td{color:var(--muted)}.cxt .off .eng b{font-weight:500}.cxt .dash{opacity:.45}
.cxt .tot td{font-weight:700;background:var(--code);border-top:2px solid var(--border)}.cxt .tot td:first-child{border-radius:0 0 0 8px}.cxt .tot td:last-child{border-radius:0 0 8px 0}
.cxt .sub td:first-child{padding-left:26px}.cxt .sub .eng b{font-weight:500}
.n{display:inline-block;min-width:28px;padding:2px 8px;border-radius:99px;font-weight:700;color:#fff;background:var(--c)}.n.z{background:none;color:var(--muted);font-weight:500}
.st{display:inline-block;padding:2px 10px;border-radius:99px;font-size:12px;font-weight:600}.st.ok{background:var(--okbg);color:var(--ok)}.st.warn{background:var(--warnbg);color:var(--warn)}.st.na{background:var(--code);color:var(--muted)}
.cxmeta{display:flex;flex-wrap:wrap;gap:8px 22px;font-size:13px;color:var(--muted);margin:0 0 22px}.cxmeta b{color:var(--fg);font-weight:600}
.cxg{background:var(--card);border:1px solid var(--border);border-left:4px solid var(--c);border-radius:10px;margin:18px 0}.cxg>summary{padding:16px 20px;cursor:pointer;display:flex;flex-wrap:wrap;gap:6px 12px;align-items:center}
.cxg .qn{font-weight:700}.cxg .cw{color:var(--muted);font-size:13px}.cxg .bd{padding:0 24px 24px}.cxg h4{margin:26px 0 10px;font-size:14px}.cxg p{margin:10px 0}.cxg li{margin:8px 0}
.cxg .tag{font-size:11px;font-weight:700;border-radius:6px;padding:1px 7px}.tag.blk{background:var(--badbg);color:var(--bad)}.tag.ef{background:var(--infobg);color:var(--info)}
.v-fp{background:var(--okbg);color:var(--ok)}.v-real{background:var(--badbg);color:var(--bad)}.v-rev{background:var(--warnbg);color:var(--warn)}
.cxg ol{margin:8px 0;padding-left:22px}.cxg .loc{width:100%}.cxg .loc td{font-size:13px;vertical-align:top}.cxg .loc td:nth-child(3),.cxg .loc td:nth-child(4){white-space:nowrap}.refs{display:flex;flex-wrap:wrap;gap:6px;margin:6px 0}
.refs span{background:var(--code);border-radius:6px;padding:1px 8px;font-size:12px}.cxg pre{margin:6px 0}
@media(max-width:640px){.cxk .big{font-size:32px}.cxt{font-size:13px}.cxt td,.cxt th{padding:7px 6px}}
"""
CSS_VARS = (":root{--sevC:#8c1d18;--sevH:#c4321f;--sevM:#b7791f;--sevL:#3b6fb6}"
            "@media (prefers-color-scheme:dark){:root{--sevC:#d9534f;--sevH:#ef7a63;--sevM:#d8a233;--sevL:#6f9be0}.n:not(.z){color:#161615}}")


def _e(s: Any) -> str:
    return html.escape(str(s), quote=True)


def _n(v: Any, sev: str, ran: bool) -> str:
    if not ran or v is None:
        return "<span class='dash'>–</span>"
    return "<span class='n s-%s%s'>%d</span>" % (sev, " z" if not v else "", v)


def _status(s: str, ran: bool) -> str:
    if not ran:
        return "<span class='st na'>no ejecutado</span>"
    return "<span class='st %s'>%s</span>" % ("ok" if s.lower() == "completed" else "warn", _e(s))


def summary_html(s: Dict[str, Any]) -> str:
    """Tarjeta «Resultados de CxOne»: total, chips por severidad, barra proporcional y tabla por motor."""
    tot = next((r for r in s["rows"] if r["name"] == "TOTAL"), None)
    counts = dict(zip(SEVS, tot["counts"])) if tot else {}
    total = s["total_results"] if s["total_results"] is not None else sum(v or 0 for v in counts.values())
    H = ["<div class='cxk'><div class='big'>%d<small>resultados</small></div><div class='chips'>" % total]
    for sev in SEVS[:4]:
        v = counts.get(sev) or 0
        H.append("<div class='kc s-%s%s'><i></i><b>%d</b><span>%s</span></div>" % (sev, "" if v else " z", v, SEV_ES[sev]))
    H.append("</div>")
    if s["meta"].get("risk_level"):
        H.append("<span class='st %s'>%s</span>" % ("warn" if "high" in s["meta"]["risk_level"].lower() else "ok", _e(s["meta"]["risk_level"])))
    H.append("</div>")
    if sum(counts.values()):
        H.append("<div class='cxbar' role='img' aria-label='Distribución por severidad'>%s</div>" % "".join(
            "<span class='s-%s' style='flex:%d' title='%s: %d'></span>" % (k, v, SEV_ES[k], v) for k, v in counts.items() if v))
    meta = [("project", "Proyecto"), ("branch", "Rama"), ("created_at", "Escaneo"), ("scan_types", "Tipos"), ("scan_id", "Scan ID"),
            ("task_version", "Tarea AST"), ("cli_version", "AST-CLI")]
    H.append("<div class='cxmeta'>%s</div>" % "".join("<span>%s <b>%s</b></span>" % (lab, _e(s["meta"][k])) for k, lab in meta if s["meta"].get(k)))
    H.append("<div class='tbl'><table class='cxt'><tr><th>Motor</th>%s<th>Total</th><th>Estado</th></tr>"
             % "".join("<th>%s</th>" % SEV_ES[k] for k in SEVS))
    for r in s["rows"]:
        ran = r["ran"]
        total_row = sum(v or 0 for v in r["counts"]) if ran else None
        H.append("<tr class='%s'><td class='eng'><b>%s</b><small>%s</small></td>%s<td>%s</td><td>%s</td></tr>" % (
            " ".join(x for x in ("tot" if r["name"] == "TOTAL" else "", "off" if not ran else "", "sub" if r.get("sub") else "") if x),
            _e(r["name"]), _e(ENGINE_DESC.get(r["name"], "")),
            "".join("<td>%s</td>" % _n(v, k, ran) for k, v in zip(SEVS, r["counts"])),
            "<b>%d</b>" % total_row if ran else "<span class='dash'>–</span>", _status(r["status"], ran)))
    H.append("</table></div>")
    return "".join(H)


# ---------------------------------------------------------------------------- hallazgos del reporte de Checkmarx

def _group(items: List[Dict[str, Any]]) -> "OrderedDict[str, List[Dict[str, Any]]]":
    order = {k: i for i, k in enumerate(SEVS)}
    groups: "OrderedDict[str, List[Dict[str, Any]]]" = OrderedDict()
    for it in sorted(items, key=lambda i: (order.get(i["severity"], 9), i["rule"], i.get("file", ""), i.get("line") or 0)):
        groups.setdefault(it["rule"], []).append(it)
    return OrderedDict(sorted(groups.items(), key=lambda kv: (order.get(kv[1][0]["severity"], 9), -len(kv[1]), kv[0])))


def _brief(text: str, n: int = 520) -> str:
    """Recorta en el último punto antes de ``n`` caracteres para no cortar una frase a la mitad."""
    if len(text) <= n:
        return text
    cut = text[:n]
    return cut[:cut.rfind(". ") + 1] if ". " in cut else cut.rstrip() + "…"


def _code(snippet: str) -> str:
    return "<pre>%s</pre>" % _e(snippet)


def findings_html(pdf: Dict[str, Any], full: bool) -> str:
    """Un bloque por consulta SAST / paquete SCA: qué es, qué hacer, ejemplo y ubicaciones con su veredicto."""
    items = [i for i in pdf["items"] if i.get("state") not in ("NOT_EXPLOITABLE",)]
    if not items:
        return ""
    info = pdf.get("info") or {}
    H = ["<h3 id='cx-hallazgos'>Hallazgos del reporte de Checkmarx y cómo resolverlos</h3>"]
    bits = [("Archivos", info.get("files")), ("LOC", info.get("loc")), ("Duración", info.get("duration")), ("Preset", info.get("preset")),
            ("Tipo", info.get("scan_type")), ("Rama principal", info.get("main_branch")), ("Iniciado por", info.get("initiator")),
            ("Etiquetas", ", ".join(info.get("tags") or []))]
    if any(v for _, v in bits):
        H.append("<div class='cxmeta'>%s</div>" % "".join("<span>%s <b>%s</b></span>" % (k, _e(v)) for k, v in bits if v))
    if pdf.get("filters"):
        H.append("<details><summary>Filtros con los que se generó el PDF</summary><ul class='ev'>%s</ul></details>"
                 % "".join("<li>%s</li>" % _e(f) for f in pdf["filters"]))
    queries = pdf.get("queries") or {}
    for rule, its in _group(items).items():
        sev = its[0]["severity"]
        q = queries.get(rule, {})
        sca = its[0]["engine"] == "SCA" if its[0].get("engine") else its[0].get("category") == "SCA"
        fx = FX.sca_fix(its[0]) if sca else FX.fix_for(rule, q.get("cwe") or its[0].get("cwe", ""))
        blocks = sev in ("CRITICAL", "HIGH")
        files = len({i["file"] for i in its})
        H.append("<details class='cxg s-%s'%s><summary><span class='pill sev-%s'>%s</span><span class='qn'>%s</span><span class='cw'>%s · %d resultado(s) en %d archivo(s)</span>%s%s</summary><div class='bd'>"
                 % (sev, " open" if blocks else "", sev, sev, _e(rule), "CWE-%s" % q["cwe"] if q.get("cwe") else ("SCA" if sca else ""),
                    len(its), files, "<span class='tag blk'>bloquea el breaker</span>" if blocks else "",
                    "<span class='tag ef'>esfuerzo %s</span>" % _e(fx["effort"]) if fx else ""))
        what = q.get("risk") or q.get("description") or ""
        if what and not what.lower().startswith("no query"):
            H.append("<h4>Qué significa</h4><p>%s</p>" % _e(_brief(what)))
        if sca and its[0].get("description"):
            H.append("<h4>Qué significa</h4><p>%s</p>" % _e(_brief(its[0]["description"])))
        if fx:
            H.append("<h4>Solución propuesta: %s</h4><ol>%s</ol>" % (_e(fx["title"]), "".join("<li>%s</li>" % _e(x) for x in fx["steps"])))
            if fx.get("code"):
                H.append(_code(fx["code"]))
        elif q.get("recommendations"):
            H.append("<h4>Recomendaciones de Checkmarx</h4><ul>%s</ul>" % "".join("<li>%s</li>" % _e(x) for x in q["recommendations"][:6]))
        if not sca:
            H.append("<p class='sub'>%s</p>" % _e(FX.triage_hint()))
        cats = q.get("categories") or {}
        refs = [("OWASP 2021", cats.get("OWASP Top 10 2021")), ("PCI DSS 4.0", cats.get("PCI DSS v4.0")), ("NIST 800-53", cats.get("NIST SP 800-53"))]
        if any(v for _, v in refs):
            H.append("<div class='refs'>%s</div>" % "".join("<span>%s: %s</span>" % (k, _e(v[:70])) for k, v in refs if v))
        H.append("<h4>Ubicaciones</h4><div class='tbl'><table class='loc'><tr><th>Archivo:línea</th><th>Detalle</th><th>Estado</th><th>Antigüedad</th>%s</tr>"
                 % ("" if sca else "<th>Veredicto</th>"))
        for it in its:
            loc = "%s%s" % (short_file(it["file"], full), ":%d" % it["line"] if it.get("line") else "")
            detail = (it.get("message") or "") if sca else "%s%s" % ((it.get("method") + " · ") if it.get("method") else "", it.get("message", ""))
            first = re.sub(r"^\d+\s+", "", (it.get("snippet") or "").split("\n")[0])
            snip = "<br><code>%s</code>" % _e(first[:110]) if first else ""
            age = "%d días" % it["age_days"] if it.get("age_days") is not None else "-"
            verdict = ""
            if not sca:
                v, why = FX.assess(it)
                label, cls = _VERDICT[v]
                verdict = "<td><span class='pill %s'>%s</span>%s</td>" % (cls, label, "<div class='sub'>%s</div>" % _e(why) if why else "")
            H.append("<tr><td><code>%s</code></td><td>%s%s</td><td>%s</td><td>%s</td>%s</tr>"
                     % (_e(loc), _e(detail), snip, _e(_STATE_ES.get(it.get("state", ""), it.get("state", ""))), age, verdict))
        H.append("</table></div></div></details>")
    return "".join(H)


def findings_table(pdf: Dict[str, Any]) -> List[List[str]]:
    """Filas (severidad, consulta, cantidad, solución) para el PDF."""
    rows = []
    queries = pdf.get("queries") or {}
    for rule, its in _group([i for i in pdf["items"] if i.get("state") != "NOT_EXPLOITABLE"]).items():
        sca = its[0].get("category") == "SCA"
        fx = FX.sca_fix(its[0]) if sca else FX.fix_for(rule, (queries.get(rule) or {}).get("cwe") or its[0].get("cwe", ""))
        rows.append([its[0]["severity"], rule, str(len(its)), fx["title"] if fx else "Revisar las recomendaciones de Checkmarx"])
    return rows


def findings_md(pdf: Dict[str, Any], full: bool) -> List[str]:
    items = [i for i in pdf["items"] if i.get("state") != "NOT_EXPLOITABLE"]
    if not items:
        return []
    L = ["", "## Hallazgos del reporte de Checkmarx y cómo resolverlos", ""]
    queries = pdf.get("queries") or {}
    for rule, its in _group(items).items():
        q = queries.get(rule, {})
        sca = its[0].get("category") == "SCA"
        fx = FX.sca_fix(its[0]) if sca else FX.fix_for(rule, q.get("cwe") or its[0].get("cwe", ""))
        L += ["### %s `%s` — %d resultado(s)%s" % (its[0]["severity"], rule, len(its), " · CWE-%s" % q["cwe"] if q.get("cwe") else ""), ""]
        if fx:
            L += ["**Solución:** %s" % fx["title"], ""] + ["%d. %s" % (i, s) for i, s in enumerate(fx["steps"], 1)]
            if fx.get("code"):
                L += ["", "```", fx["code"], "```"]
        L += ["", "| Archivo:línea | Estado | Veredicto |", "|---|---|---|"]
        for it in its:
            v = "" if sca else _VERDICT[FX.assess(it)[0]][0]
            L.append("| `%s%s` | %s | %s |" % (short_file(it["file"], full), ":%d" % it["line"] if it.get("line") else "",
                                              _STATE_ES.get(it.get("state", ""), it.get("state", "")), v))
        L.append("")
    return L
