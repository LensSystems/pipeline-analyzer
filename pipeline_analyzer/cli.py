"""Línea de comandos.

Sin rutas, el programa pregunta qué analizar (ventanas "Seleccionar carpeta"/"Abrir archivo" o, sin
entorno gráfico, en la consola).

Ejemplos:
    python -m pipeline_analyzer                                   # modo interactivo
    python -m pipeline_analyzer logs_123456                       # carpeta descargada de Azure DevOps
    python -m pipeline_analyzer logs_123400.zip logs_123456 --pom pom.xml
    python -m pipeline_analyzer descargas/                        # carpeta con varias logs_* → una corrida cada una
    python -m pipeline_analyzer log_anterior.txt log_actual.txt   # logs combinados de un job
    python -m pipeline_analyzer logs_123456 --fail-on HIGH        # como breaker en CI
"""

import argparse
import glob
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import List

from . import __version__
from .extractors import extract
from .logparser import STEP_FILE_RE, build_id_from_path, discover, is_multi_file, parse_attempts
from .index_page import write_index, write_summary
from .pom_checks import check_pom
from . import inventory
from .tool_reports import discover_reports
from . import compat
from .interactive import Cancelled, Gui, gather_console, gui_status
from .progress import Progress
from .report import Analysis, Run, render_console, render_html, render_json, render_markdown, render_pdf
from .rules import SEVERITIES, SEVERITY_RANK, evaluate
from .security import mask_infra, redact

RENDERERS = {"md": ("reporte.md", render_markdown), "html": ("reporte.html", render_html), "json": ("reporte.json", render_json),
             "full": ("reporte_completo.html", lambda a: render_html(a, full=True))}
PDF_FORMATS = {"pdf": ("reporte.pdf", False), "pdf-full": ("reporte_completo.pdf", True)}


def _is_run_dir(d: Path) -> bool:
    """Carpeta de descarga de Azure DevOps: contiene archivos de paso '<n>_<paso>.txt'."""
    return any(STEP_FILE_RE.match(f.name) for f in d.rglob("*.txt"))


def _expand(patterns: List[str]) -> List[Path]:
    """Convierte los argumentos en una lista de ejecuciones (archivo, carpeta logs_<id> o .zip)."""
    runs: List[Path] = []
    for p in patterns:
        for m in sorted(glob.glob(p)) or [p]:
            path = Path(m)
            if not path.is_dir():
                runs.append(path)
                continue
            children = sorted(c for c in path.iterdir()
                              if (c.is_dir() and build_id_from_path(c)) or c.suffix.lower() == ".zip")
            own_steps = any(STEP_FILE_RE.match(f.name) for f in path.glob("*.txt"))
            if children and not own_steps and not build_id_from_path(path):
                runs += children                      # carpeta que agrupa varias descargas logs_*
            elif build_id_from_path(path) or _is_run_dir(path):
                runs.append(path)                     # una descarga logs_<id>
            else:
                runs += sorted(x for x in path.iterdir() if x.suffix.lower() in (".txt", ".log"))  # varios logs combinados
    return runs


def new_run_dir(base: Path) -> Path:
    """Crea una carpeta nueva por análisis (``001_2026-09-30``) para no sobrescribir los anteriores."""
    base.mkdir(parents=True, exist_ok=True)
    used = [int(m.group(1)) for d in base.iterdir() if d.is_dir() for m in [re.match(r"(\d+)_", d.name)] if m]
    n = max(used, default=0) + 1
    stamp = datetime.now().strftime("%Y-%m-%d")
    while True:
        run = base / ("%03d_%s" % (n, stamp))
        try:
            run.mkdir()
            return run
        except FileExistsError:
            n += 1


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="pipeline_analyzer",
        description="Analiza logs de pipelines de Azure DevOps (Maven, Sonar, CxOne, TMAS, Checkstyle/PMD/SpotBugs), "
                    "propone remediaciones y genera un reporte comparativo.",
    )
    ap.add_argument("logs", nargs="*",
                    help="Ejecuciones a analizar: carpetas logs_<id> descargadas de Azure DevOps, sus .zip, logs combinados "
                         "(.txt/.log) o una carpeta que agrupe varias. Con varias, se comparan en orden cronológico. "
                         "Si no se indica ninguna, el programa las pide (ventanas o consola).")
    ap.add_argument("--pom", help="pom.xml a revisar (opcional)")
    ap.add_argument("--reports", action="append", metavar="RUTA",
                    help="Carpeta o archivo con los reportes de las herramientas (PMD/Checkstyle/SpotBugs XML, JSON o PDF de Checkmarx/CxOne) para mostrar "
                         "reglas, archivos y líneas en el HTML. Se puede repetir. También se busca en la carpeta de logs y en el target/ del pom")
    ap.add_argument("--dump-pdf", metavar="PDF", help="Muestra el texto que se lee de un PDF de Checkmarx y los hallazgos que se interpretan "
                    "(para diagnosticar un PDF que no se reconoce) y termina")
    ap.add_argument("--labels", help="Etiquetas separadas por coma, una por ejecución y en el mismo orden")
    ap.add_argument("--keep-order", action="store_true", help="No reordenar las ejecuciones por fecha de inicio")
    ap.add_argument("--out-dir", help="Carpeta base de los reportes (default: reporte_pipeline; en modo interactivo, junto al log principal). "
                         "Cada análisis se guarda en una subcarpeta nueva numerada, con fecha y hora; nunca se sobrescribe")
    ap.add_argument("--gui", action="store_true", help="Elegir los archivos con ventanas aunque se indiquen rutas")
    ap.add_argument("--no-gui", action="store_true", help="En modo interactivo, preguntar por consola en lugar de abrir ventanas")
    ap.add_argument("--formats", default="full,pdf,pdf-full,md,json",
                    help="Formatos a generar: full (HTML completo, sin enmascarar, solo uso local), pdf (para compartir, con secretos "
                         "enmascarados), pdf-full (PDF completo, sin enmascarar), md, json, html (HTML enmascarado, opcional) o 'none'")
    ap.add_argument("--no-console", action="store_true", help="No imprimir el reporte en consola")
    ap.add_argument("--no-color", action="store_true", help="Consola sin colores ANSI")
    ap.add_argument("--no-progress", action="store_true", help="No mostrar el indicador de avance")
    ap.add_argument("--all-attempts", action="store_true",
                    help="Si una descarga contiene varios intentos (re-runs), analizar cada uno como una ejecución")
    ap.add_argument("--no-redact", action="store_true",
                    help="No enmascarar secretos en los reportes (por defecto se enmascaran)")
    ap.add_argument("--mask-infra", action="store_true",
                    help="Enmascarar también correos, IPs y hosts (útil para compartir el reporte fuera del equipo)")
    ap.add_argument("--fail-on", choices=SEVERITIES, help="Código de salida 1 si la última ejecución tiene hallazgos de esta severidad o mayor")
    ap.add_argument("--doctor", action="store_true",
                    help="Diagnóstico del entorno: versión de Python, ventanas (tkinter), consola; con la solución si algo falta")
    ap.add_argument("--version", action="version", version="%(prog)s " + __version__)
    return ap


def _dump_pdf(path: str) -> int:
    from .cxone_pdf import dump_text, parse_text
    from .pdf_reader import PdfError, extract_text
    try:
        if path.lower().endswith((".md", ".txt")):
            pages = [Path(path).read_text(encoding="utf-8", errors="replace")]
            print(pages[0])
        else:
            print(dump_text(path))
            pages = extract_text(path)
        rep = parse_text(pages)
    except PdfError as exc:
        print("No se pudo leer %s: %s" % (path, exc), file=sys.stderr)
        return 2
    print("\n===== hallazgos interpretados: %d =====" % len(rep["items"]))
    for it in rep["items"]:
        print("%-9s %-5s %-34s %s%s %s" % (it["severity"], it["category"], it["rule"][:34], it["file"], ":%d" % it["line"] if it["line"] else "",
                                          it["state"]))
    return 0


def main(argv=None) -> int:
    if not compat.python_ok():
        print(compat.python_error(), file=sys.stderr)
        return 3
    compat.setup_console()
    args = build_parser().parse_args(argv)
    if args.doctor:
        print(compat.doctor())
        return 0
    if args.dump_pdf:
        return _dump_pdf(args.dump_pdf)
    gui = None
    use_gui = False
    interactive_tty = sys.stdin is not None and sys.stdin.isatty()
    if (not args.logs or args.gui) and not args.no_gui:
        ok, why, fix = gui_status()
        use_gui = ok
        if not ok and (args.gui or interactive_tty):
            print("Ventanas no disponibles: %s.\nPara habilitarlas: %s\n%s\n"
                  % (why, fix, "Se usarán las rutas indicadas." if args.logs else "Continuando con preguntas en la consola…"),
                  file=sys.stderr)
    if (not args.logs or args.gui) and not (args.logs and not use_gui):
        if not use_gui and not (interactive_tty or args.no_gui):
            build_parser().print_usage(sys.stderr)
            print("Indica al menos un log, o ejecútalo en una terminal/escritorio para elegirlos.", file=sys.stderr)
            return 2
        try:
            if use_gui:
                gui = Gui()
                sel = gui.gather()
            else:
                sel = gather_console()
        except (Cancelled, KeyboardInterrupt):
            if gui:
                gui.destroy()
            print("\nCancelado.", file=sys.stderr)
            return 130
        args.logs = sel["logs"]
        args.pom = args.pom or sel["pom"]
        args.reports = list(args.reports or []) + list(sel.get("reports") or [])
        if args.out_dir is None:
            args.out_dir = str(Path(sel["main"]).resolve().parent / "reporte_pipeline")
    if args.out_dir is None:
        args.out_dir = "reporte_pipeline"
    try:
        rc = _run(args, gui)
        if gui:
            gui.destroy()
        return rc
    except Exception as exc:
        if gui:
            gui.close_progress()
            gui.show_error("No se pudo completar el análisis:\n\n%s" % exc)
            gui.destroy()
            return 1
        raise


def gui_main() -> int:
    """Entrada para doble clic (analizar_pipeline.pyw / pipeline-analyzer-gui): abre las ventanas.

    Sin consola (pythonw) y sin ventanas disponibles, avisa con un cuadro de diálogo del sistema.
    """
    has_console = sys.stdin is not None and sys.stdin.isatty()
    if not has_console:
        ok, why, fix = gui_status()
        if not ok:
            compat.notify("Analizador de pipelines", "Las ventanas no están disponibles: %s.\n\nPara habilitarlas: %s" % (why, fix))
            return 2
    return main(sys.argv[1:] or ["--gui"])


def _run(args, gui) -> int:
    paths = _expand(args.logs)
    missing = [str(f) for f in paths if not f.exists()]
    if missing:
        print("No se encontraron: " + ", ".join(missing), file=sys.stderr)
        return 2
    if not paths:
        print("No se encontraron logs en: " + ", ".join(args.logs), file=sys.stderr)
        return 2

    labels = [x.strip() for x in args.labels.split(",")] if args.labels else []
    if labels and len(labels) != len(paths):
        print("--labels debe tener %d etiquetas (una por ejecución): %s" % (len(paths), ", ".join(p.name for p in paths)),
              file=sys.stderr)
        return 2

    formats = [] if args.formats == "none" else [x.strip() for x in args.formats.split(",") if x.strip()]
    file_counts = [len(discover(p)) if is_multi_file(p) else 1 for p in paths]
    total = sum(file_counts) + 2 * len(paths) + (1 if args.pom else 0) + len(formats)
    prog = Progress(total, enabled=not args.no_progress, listener=gui.open_progress() if gui else None)

    hosts: dict = {}  # numeración de hosts enmascarados compartida por todo el PDF

    def _out(text: str) -> str:
        if not args.no_redact:
            text = redact(text)
        return mask_infra(text, hosts) if args.mask_infra else text

    written: List[str] = []
    try:
        runs: List[Run] = []
        for i, path in enumerate(paths):
            name = path.name
            prog.stage("Leyendo %s (%d/%d)" % (name, i + 1, len(paths)))
            n = [0]

            def on_file(rel, n=n, total_files=file_counts[i]):
                n[0] += 1
                prog.advance("%d/%d %s" % (n[0], total_files, rel.rsplit("/", 1)[-1]))

            attempts = parse_attempts(path, on_file)
            if not args.all_attempts:
                attempts = attempts[-1:]
            prog.stage("Extrayendo métricas y evaluando reglas de %s" % name)
            for log in attempts:
                metrics = extract(log)
                findings = evaluate(metrics)
                for f in findings:
                    f.location = log.locate(f.line)
                label = labels[i] if labels else (metrics["meta"].get("build_number") or build_id_from_path(path) or path.stem)
                if log.attempts > 1 and args.all_attempts:
                    label = "%s #%d" % (label, log.attempt)
                runs.append(Run(label, metrics, findings))
                crit = sum(1 for f in findings if f.severity in ("CRITICAL", "HIGH"))
                extra = " · intento %d de %d" % (log.attempt, log.attempts) if log.attempts > 1 else ""
                prog.log("%s [%s]: %d archivo(s), %d pasos, %d líneas → %d hallazgos (%d críticos/altos)%s"
                         % (label, metrics["meta"]["provider_label"], len(log.sources), len(log.steps), len(log.lines),
                            len(findings), crit, extra))
            prog.advance(units=2)

        if not args.keep_order and not labels:
            runs.sort(key=lambda r: r.metrics["meta"].get("start") or "")
        seen = {}
        for r in runs:  # etiquetas repetidas (p. ej. mismo build relanzado): hacerlas únicas
            if r.label in seen:
                seen[r.label] += 1
                r.label = "%s (%d)" % (r.label, seen[r.label])
            else:
                seen[r.label] = 1

        analysis = Analysis(runs)
        if args.pom:
            prog.stage("Revisando %s" % Path(args.pom).name)
            try:
                analysis.pom_findings = check_pom(args.pom)
                analysis.pom_path = args.pom
                prog.log("pom.xml: %d hallazgos" % len(analysis.pom_findings))
            except Exception as exc:  # un pom inválido no debe impedir el reporte de logs
                prog.log("Aviso: no se pudo analizar el pom (%s)" % exc)
            prog.advance()

        report_dirs = [Path(r) for r in (args.reports or [])]
        report_dirs += [p for p in paths if p.is_dir() or p.suffix.lower() == ".zip"]
        if args.pom and (Path(args.pom).parent / "target").is_dir():
            report_dirs.append(Path(args.pom).parent / "target")
        audit: List[dict] = []
        analysis.tool_reports = discover_reports([d for d in report_dirs if d.exists()], audit)
        analysis.review = inventory.build(list(paths) + [d for d in report_dirs if d not in paths and d.exists()], audit)
        c = analysis.review["counts"]
        prog.log("Archivos revisados: %d (%d logs, %d definiciones, %d reportes de herramientas, %d ignorados)"
                 % (c["total"], c["logs"], c["definiciones"], c["reportes"], c["ignorados"]))
        if analysis.tool_reports:
            prog.log("Reportes de herramientas: " + ", ".join("%s (%d)" % (t, r["total"]) for t, r in analysis.tool_reports.items()))

        if formats:
            out = new_run_dir(Path(args.out_dir))
            for fmt in formats:
                prog.stage("Generando reporte %s" % fmt.upper())
                if fmt in PDF_FORMATS:
                    name, is_full = PDF_FORMATS[fmt]
                    (out / name).write_bytes(render_pdf(analysis, full=is_full, scrub=None if is_full else _out))
                    written.append(str(out / name))
                    prog.advance()
                    continue
                if fmt not in RENDERERS:
                    prog.log("Formato desconocido: %s" % fmt)
                    prog.advance()
                    continue
                name, fn = RENDERERS[fmt]
                text = fn(analysis)
                if fmt != "full":  # el reporte completo es la única salida sin enmascarar (uso local)
                    text = _out(text)
                (out / name).write_text(text, encoding="utf-8")
                written.append(str(out / name))
                prog.advance()
            write_summary(out, analysis)
            write_index(Path(args.out_dir))
    except BaseException:
        prog.close()
        raise
    prog.close("Análisis completado: %d ejecución(es)" % len(paths))
    if gui:
        gui.close_progress()

    if not args.no_console and sys.stdout is not None:
        color = not args.no_color and compat.ansi_supported(sys.stdout)
        print(compat.console_safe(_out(render_console(analysis, color, compat.fancy_unicode(sys.stdout)))))
        if written:
            print("\nReportes generados:\n  " + "\n  ".join(written))

    if gui:
        counts = {s: sum(1 for f in analysis.last.findings + analysis.pom_findings if f.severity == s) for s in SEVERITIES}
        gui.show_result(analysis.verdict(), counts, [str(Path(w).resolve()) for w in written])

    if args.fail_on:
        limit = SEVERITY_RANK[args.fail_on]
        if any(SEVERITY_RANK[f.severity] <= limit for f in analysis.last.findings):
            return 1
    return 0
