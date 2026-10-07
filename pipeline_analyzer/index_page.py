"""Historial de análisis: ``resumen.json`` por carpeta y ``historial-reportes.html`` que los lista todos."""

import html
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from . import BRAND, __version__
from . import theme as TH

HISTORY_NAME = "historial-reportes.html"
FILE_LABELS = [("reporte.html", "HTML", False), ("reporte.pdf", "PDF", False), ("reporte.md", "Markdown", False),
               ("reporte.json", "JSON", False), ("reporte_completo.html", "HTML completo", True),
               ("reporte_completo.pdf", "PDF completo", True)]


def write_summary(run_dir: Path, analysis, version: str = __version__) -> None:
    """Guarda un resumen pequeño del análisis (sin rutas ni secretos) para el índice."""
    counts: Dict[str, int] = {}
    for f in analysis.project_findings():
        counts[f.severity] = counts.get(f.severity, 0) + 1
    data = {
        "folder": run_dir.name,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "version": version,
        "verdict": analysis.verdict(),
        "ok": analysis.is_ok(),
        "compare_only": analysis.compare_only,
        "labels": [r.label for r in analysis.runs],
        "provider": analysis.last.metrics["meta"].get("provider_label", ""),
        "counts": counts,
        "pipeline_recommendations": len(analysis.pipeline_findings()),
        "pipeline_blockers": sum(1 for f in analysis.pipeline_findings() if f.blocks),
        "steps_blocking": sum(1 for s in analysis.pass_plan() if s["blocks"]),
    }
    (run_dir / "resumen.json").write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _load(run: Path) -> Dict[str, Any]:
    m = re.match(r"(\d+)_(\d{4}-\d{2}-\d{2})", run.name)
    data: Dict[str, Any] = {"folder": run.name, "number": int(m.group(1)) if m else 0, "date": m.group(2) if m else ""}
    try:
        data.update(json.loads((run / "resumen.json").read_text(encoding="utf-8")))
    except (OSError, ValueError):
        pass
    data["files"] = [(n, label, local) for n, label, local in FILE_LABELS if (run / n).exists()]
    return data


def render_index(base: Path) -> str:
    runs = [_load(d) for d in base.iterdir() if d.is_dir() and re.match(r"\d+_", d.name)]
    runs.sort(key=lambda r: r["number"], reverse=True)
    e = html.escape
    rows: List[str] = []
    for i, r in enumerate(runs):
        ok = r.get("ok")
        verdict = r.get("verdict")
        pill = ("<span class='pill p-na'>sin resumen</span>" if verdict is None else
                "<span class='pill v %s'>%s</span>" % ("p-ok" if ok else "p-bad", e(verdict)))
        counts = " ".join("<span class='pill sev-%s'>%s %d</span>" % (k, k, v) for k, v in
                          sorted((r.get("counts") or {}).items(), key=lambda kv: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(kv[0]))
                          if k in ("CRITICAL", "HIGH", "MEDIUM", "LOW"))
        when = (r.get("generated_at") or r.get("date") or "").replace("T", " ")
        links = " ".join("<a class='file%s' href='%s/%s'%s>%s</a>" % (" local" if local else "", e(r["folder"], True), n,
                                                                      " title='Contiene valores reales: no compartir'" if local else "", e(label))
                         for n, label, local in r["files"])
        extra = "<div><span class='pill p-info'>Solo comparación</span></div>" if r.get("compare_only") else ""
        if r.get("pipeline_blockers"):
            extra += "<div class='sub'>⚙ %d bloqueo(s) dependen del pipeline</div>" % r["pipeline_blockers"]
        rows.append("<tr data-q='%s'><td class='num'><b>%03d</b>%s</td><td class='date'>%s</td><td>%s%s</td><td>%s</td><td>%s%s</td><td class='files'>%s</td></tr>"
                    % (e((r["folder"] + " " + " ".join(r.get("labels") or []) + " " + (verdict or "")).lower(), True), r["number"],
                       " <span class='pill p-info'>último</span>" if i == 0 else "", e(when), e(", ".join(r.get("labels") or []) or "-"),
                       "<div class='sub'>%s</div>" % e(r.get("provider") or "") if r.get("provider") else "", pill,
                       counts or "<span class='p-na'>-</span>", extra, links))
    body = ("<div class='card tbl'><table id='t'><tr><th>#</th><th>Fecha</th><th>Ejecuciones analizadas</th><th>Veredicto</th>"
            "<th>Hallazgos del proyecto</th><th>Archivos</th></tr>%s</table></div>" % "".join(rows)) if rows else \
        "<div class='card'>Aún no hay análisis en esta carpeta.</div>"
    return ("<!doctype html><html lang='es'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
            "<title>Historial de reportes</title><style>%s</style></head><body><main><h1>Historial de reportes</h1>"
            "<p class='sub'>%d análisis guardados en <code>%s</code> · actualizado %s · pipeline-analyzer %s</p>"
            "<input id='q' type='search' placeholder='Filtrar por número, fecha, etiqueta o veredicto…' aria-label='Filtrar'>%s"
            "<p class='sub'>Los archivos marcados como «completo» incluyen valores reales (secretos, hosts, correos): solo para uso local.</p>"
            "</main><div class='brand' aria-hidden='true'>%s</div><script>%s</script></body></html>"
            % (_CSS, len(runs), e(base.name), datetime.now().strftime("%Y-%m-%d %H:%M"), __version__, body, BRAND, _JS))


def write_index(base: Path) -> Path:
    path = base / HISTORY_NAME
    path.write_text(render_index(base), encoding="utf-8")
    return path


_JS = ("var q=document.getElementById('q');if(q){q.addEventListener('input',function(){var v=q.value.toLowerCase();"
       "document.querySelectorAll('#t tr[data-q]').forEach(function(r){r.style.display=r.dataset.q.indexOf(v)<0?'none':''})})}")

_CSS = TH.TOKENS + """

main{width:100%;max-width:1360px;margin:0 auto;padding:clamp(16px,3vw,44px) clamp(14px,3vw,48px) 60px}h1{font-size:clamp(26px,3.4vw,34px);letter-spacing:-.025em;font-weight:750;margin:0 0 6px}.sub{color:var(--muted);font-size:13px;margin:0 0 16px}
#q{width:100%;max-width:520px;padding:10px 14px;border:1px solid var(--border);border-radius:99px;background:var(--card);color:var(--fg);font:inherit;margin:6px 0 18px}#q:focus{border-color:var(--info)}#q::placeholder{color:var(--muted);opacity:1}
tr[data-q]:hover>td{background:color-mix(in srgb,var(--code) 55%,transparent)}
.card{background:var(--card);border:1px solid var(--border);border-radius:var(--r1);padding:8px 14px}.pill.v{white-space:normal;border-radius:12px;padding:3px 10px}.tbl{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:14px}
th,td{padding:8px 10px;border-bottom:1px solid var(--border);text-align:left;vertical-align:top}th{font-size:13px;color:var(--muted);font-weight:600}
th{overflow-wrap:normal;word-break:normal}td.num,td.date{white-space:nowrap}td.files{min-width:260px}.pill{display:inline-block;padding:1px 8px;border-radius:99px;font-size:12px;font-weight:600;margin:1px 2px 1px 0;white-space:nowrap}
.p-ok{background:var(--okbg);color:var(--ok)}.p-bad{background:var(--badbg);color:var(--bad)}.p-info{background:var(--infobg);color:var(--info)}.p-na{color:var(--muted)}
.sev-CRITICAL,.sev-HIGH{background:var(--badbg);color:var(--bad)}.sev-MEDIUM{background:var(--warnbg);color:var(--warn)}.sev-LOW{background:var(--infobg);color:var(--info)}
.file{display:inline-block;border:1px solid var(--border);border-radius:99px;padding:2px 11px;margin:2px 4px 2px 0;text-decoration:none;color:var(--info);font-size:13px;font-weight:500}
.brand{position:fixed;right:14px;bottom:8px;font-size:12px;font-weight:600;letter-spacing:.06em;color:var(--muted);opacity:.55;pointer-events:none}
.file:hover{border-color:var(--info)}.file.local{color:var(--warn);border-color:var(--warn)}code{font-family:ui-monospace,Menlo,monospace}
"""
