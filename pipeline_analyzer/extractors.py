"""Extrae métricas estructuradas de un PipelineLog, independiente del proveedor de CI.

Los pasos se buscan primero por nombre (plantillas conocidas) y, si no existen, por su contenido
(salida de Maven/Gradle/Jest/pytest, SonarScanner, CxOne, TMAS, Trivy, Snyk...).

Secciones del resultado: meta, env, tests, jacoco, sonar, cxone, tmas, static, scanners, infra,
warnings, security, steps.
"""

import json
import re
from collections import Counter
from typing import Any, Dict, Iterator, List, Optional

from .logparser import PROVIDER_LABEL, PipelineLog, Step, build_id_from_path
from .security import extract_security, security_checklist

# ---------------------------------------------------------------- utilidades


def _json_blocks(step: Optional[Step], marker: Optional[str] = None) -> Iterator[Any]:
    """Bloques JSON (líneas que empiezan con ``{``) del paso, opcionalmente después de ``marker``."""
    if step is None:
        return
    started = marker is None
    buf: List[str] = []
    depth = 0
    for line in step.lines:
        t = line.text
        if not started:
            started = marker in t
            continue
        if not buf and not t.lstrip().startswith("{"):
            continue
        buf.append(t)
        depth += t.count("{") - t.count("}")
        if depth <= 0:
            try:
                yield json.loads("\n".join(buf))
            except ValueError:
                pass
            buf, depth = [], 0


def _json_with(step: Optional[Step], key: str) -> Optional[Dict[str, Any]]:
    return next((b for b in _json_blocks(step) if isinstance(b, dict) and key in b), None)


def _int(v: Optional[str]) -> Optional[int]:
    if v is None:
        return None
    v = v.strip()
    return int(v) if v.isdigit() else None


def _secs(a, b) -> Optional[float]:
    if a and b:
        return round((b - a).total_seconds(), 3)
    return None


# ---------------------------------------------------------------- meta / env


def _result(log: PipelineLog, text: str) -> Optional[str]:
    m = re.search(r"^Finished: (SUCCESS|FAILURE|UNSTABLE|ABORTED)", text, re.M)
    if m:
        return m.group(1)
    if re.search(r"^ERROR: Job failed", text, re.M):
        return "FAILURE"
    if re.search(r"^Job succeeded", text, re.M):
        return "SUCCESS"
    failed = [s for s in log.steps if s.failed]
    return "FAILURE" if failed else ("SUCCESS" if log.steps else None)


def _meta(log: PipelineLog) -> Dict[str, Any]:
    text = log.full_text()
    build = None
    m = re.search(r"-(?:sonarqube|checkstyle|pmd)-analysis-(\d{8}\.\d+)", text)
    if m:
        build = m.group(1)
    else:
        m = re.search(r'container name "/(\d{8}\.\d+)"', text)
        build = m.group(1) if m else None
    build_id = build_id_from_path(log.path)
    m = re.search(r"Added analysis for \S+ build (\d+)", text)
    if m:
        build_id = m.group(1)
    pr = None
    # En descargas multi-archivo el nombre del paso de checkout llega con '/' reemplazadas por '_'
    names = "\n".join(st.name for st in log.steps)
    m = re.search(r"refs[/_]pull[/_](\d+)[/_](?:merge|head)|merge_requests?[/_](\d+)|\bPR[-_ #](\d+)\b", text + "\n" + names)
    if m:
        pr = next(g for g in m.groups() if g)
    return {
        "file": str(log.path),
        "sources": len(log.sources),
        "provider": log.provider,
        "provider_label": PROVIDER_LABEL.get(log.provider, log.provider),
        "job": log.job,
        "attempt": log.attempt,
        "attempts": log.attempts,
        "result": _result(log, text),
        "build_number": build,
        "build_id": build_id,
        "pull_request": pr,
        "start": log.start.isoformat(sep=" ", timespec="seconds") if log.start else None,
        "end": log.end.isoformat(sep=" ", timespec="seconds") if log.end else None,
        "duration_s": _secs(log.start, log.end),
        "definitions": [rel for rel, _ in log.definitions],
        "aux_files": len({l.src for l in log.aux_lines}),
    }


def _env(log: PipelineLog) -> Dict[str, Any]:
    step = log.find_step(("Maven - Verify", "Build", "Test"), r"Apache Maven|openjdk version|javac \[|Gradle \d|Compiling \d+ source")
    text = step.text() if step else log.full_text()
    java = None
    m = re.search(r'openjdk version "([^"]+)"', text)
    if m:
        java = m.group(1)
    release = None
    m = re.search(r"javac \[.*?release (\d+)\]", text)
    if m:
        release = int(m.group(1))
    elif java:
        release = _int(java.split(".")[0])
    m = re.search(r"Apache Maven ([\d.]+)", text)
    maven = m.group(1) if m else None
    m = re.search(r"^Gradle (\d[\d.]*)", text, re.M)
    gradle = m.group(1) if m else None
    m = re.search(r"Running on \.\.\. (\S+)", text)
    image = m.group(1) if m else None
    main_src = test_src = None
    m = re.search(r"Compiling (\d+) source files .* to target/classes", text)
    if m:
        main_src = int(m.group(1))
    m = re.search(r"Compiling (\d+) source files .* to target/test-classes", text)
    if m:
        test_src = int(m.group(1))
    return {"java": java, "java_release": release, "maven": maven, "gradle": gradle, "build_image": image,
            "main_sources": main_src, "test_sources": test_src}


# ---------------------------------------------------------------- tests

SUMMARY_RE = re.compile(r"^\[(?:INFO|ERROR|WARNING)\] Tests run: (\d+), Failures: (\d+), Errors: (\d+), Skipped: (\d+)\s*$")
FAIL_RE = re.compile(r"^\[ERROR\]\s{2,}(\S+?)\.([\w$]+):(\d+)\s*(.*)$")


def _surefire(step: Step) -> Optional[Dict[str, Any]]:
    summary = None
    failing: List[Dict[str, Any]] = []
    seen = set()
    build = None
    in_tests = False
    test_lines = 0
    error_logs = 0
    summary_line = None
    for l in step.lines:
        t = l.text
        if "T E S T S" in t:
            in_tests = True
        elif in_tests and re.match(r"^\[\w+\] Results:", t):
            in_tests = False
        elif in_tests:
            test_lines += 1
            if re.search(r"\s(?:ERROR)\s[\w.$<>]+ -- ", t):
                error_logs += 1
        m = SUMMARY_RE.match(t)
        if m:
            summary = tuple(int(x) for x in m.groups())
            summary_line = l.no
        m = FAIL_RE.match(t)
        if m and (m.group(1), m.group(2)) not in seen:
            seen.add((m.group(1), m.group(2)))
            failing.append({"class": m.group(1), "method": m.group(2), "line": int(m.group(3)),
                            "message": m.group(4).strip(), "log_line": l.no, "where": l.where})
        if "BUILD SUCCESS" in t:
            build = "SUCCESS"
        elif "BUILD FAILURE" in t:
            build = "FAILURE"
    if summary is None:
        return None
    total, failures, errors, skipped = summary
    return {"framework": "maven-surefire", "step": step.name, "total": total, "failures": failures, "errors": errors,
            "skipped": skipped, "passed": total - failures - errors - skipped, "failing": failing,
            "build_result": build, "test_output_lines": test_lines, "error_log_lines": error_logs,
            "log_line": summary_line}


def _counts(words: str) -> Dict[str, int]:
    c: Dict[str, int] = {}
    for n, w in re.findall(r"(\d+) (failed|passed|skipped|errors?|error|pending|todo|xfailed|xpassed)", words):
        key = "errors" if w.startswith("error") else w
        c[key] = c.get(key, 0) + int(n)
    return c


def _generic_tests(step: Step) -> Optional[Dict[str, Any]]:
    """Gradle, Jest/Vitest, pytest, .NET (dotnet test) y Go."""
    t = step.text()
    failing: List[Dict[str, Any]] = []
    res = None
    # Gradle
    m = re.search(r"(\d+) tests? completed, (\d+) failed(?:, (\d+) skipped)?", t)
    if m:
        total, failed, skipped = int(m.group(1)), int(m.group(2)), int(m.group(3) or 0)
        res = ("gradle", total, failed, 0, skipped)
        for fm in re.finditer(r"^(\S+) > (.+?) FAILED$", t, re.M):
            failing.append({"class": fm.group(1), "method": fm.group(2), "line": None, "message": ""})
    # Jest / Vitest
    m = re.search(r"^Tests:\s+(.*\d+ total)", t, re.M) or re.search(r"^\s*Tests\s+(.*\(\d+\))", t, re.M)
    if not res and m:
        c = _counts(m.group(1))
        tm = re.search(r"(\d+) total|\((\d+)\)", m.group(1))
        total = int(next(g for g in tm.groups() if g)) if tm else sum(c.values())
        res = ("jest", total, c.get("failed", 0), 0, c.get("skipped", 0) + c.get("todo", 0))
        for fm in re.finditer(r"^\s*●\s+(.+?) › (.+)$", t, re.M):
            failing.append({"class": fm.group(1), "method": fm.group(2), "line": None, "message": ""})
    # pytest
    m = re.search(r"^=+ (.*\d+ (?:passed|failed|errors?|skipped).*?) in [\d.]+s(?: \([^)]*\))? =+$", t, re.M)
    if not res and m:
        c = _counts(m.group(1))
        failed = c.get("failed", 0)
        errors = c.get("errors", 0)
        skipped = c.get("skipped", 0) + c.get("xfailed", 0)
        res = ("pytest", failed + errors + skipped + c.get("passed", 0) + c.get("xpassed", 0), failed, errors, skipped)
        for fm in re.finditer(r"^(?:FAILED|ERROR) (\S+?)::(\S+)(?: - (.*))?$", t, re.M):
            failing.append({"class": fm.group(1), "method": fm.group(2), "line": None, "message": (fm.group(3) or "")[:200]})
    # .NET
    m = re.search(r"(?:Failed|Passed)!\s+-\s+Failed:\s+(\d+), Passed:\s+(\d+), Skipped:\s+(\d+), Total:\s+(\d+)", t)
    if not res and m:
        res = ("dotnet", int(m.group(4)), int(m.group(1)), 0, int(m.group(3)))
    # Go
    if not res and re.search(r"^(?:ok|FAIL|---) ", t, re.M) and re.search(r"^--- (?:PASS|FAIL):", t, re.M):
        passed = len(re.findall(r"^\s*--- PASS:", t, re.M))
        fails = re.findall(r"^\s*--- FAIL: (\S+)", t, re.M)
        res = ("go", passed + len(fails), len(fails), 0, len(re.findall(r"^\s*--- SKIP:", t, re.M)))
        failing = [{"class": "", "method": f, "line": None, "message": ""} for f in fails]
    if not res:
        return None
    fw, total, failures, errors, skipped = res
    build = "SUCCESS" if re.search(r"BUILD SUCCESS(?:FUL)?\b", t) else ("FAILURE" if re.search(r"BUILD FAIL(?:URE|ED)\b", t) else None)
    first = step.lines[0] if step.lines else None
    for f in failing:
        f.setdefault("log_line", first.no if first else None)
        f.setdefault("where", first.where if first else None)
    return {"framework": fw, "step": step.name, "total": total, "failures": failures, "errors": errors,
            "skipped": skipped, "passed": max(0, total - failures - errors - skipped), "failing": failing[:50],
            "build_result": build, "test_output_lines": len(step.lines), "error_log_lines": 0,
            "log_line": first.no if first else None}


def _tests(log: PipelineLog) -> Dict[str, Any]:
    runs = [r for r in ((_surefire(s) or _generic_tests(s)) for s in log.steps) if r]
    runs = [r for r in runs if r["total"]]
    primary = next((r for r in runs if re.match(r"(?i)maven - verify|.*\btest", r["step"])), None)
    if primary is None and runs:
        primary = max(runs, key=lambda r: r["total"])
    out: Dict[str, Any] = {"executions": len(runs), "executed_in": [r["step"] for r in runs]}
    if primary:
        out.update(primary)
    return out


def _jacoco(log: PipelineLog) -> Dict[str, Any]:
    step = log.find_step(("Maven - Verify",), r"Analyzed bundle|coverage checks")
    text = step.text() if step else ""
    m = re.search(r"Analyzed bundle '.*?' with (\d+) classes", text)
    checks = None
    if "All coverage checks have been met" in text:
        checks = "OK"
    elif re.search(r"Coverage checks have not been met", text):
        checks = "FALLO"
    return {"classes": int(m.group(1)) if m else None, "check": checks}


# ---------------------------------------------------------------- sonar

SONAR_RUN = r"ANALYSIS SUCCESSFUL|Communicating with SonarQube|SonarScanner|sonar-scanner|--- sonar:"


def _sonar(log: PipelineLog) -> Dict[str, Any]:
    run = log.find_step(("Sonarqube - Run", "Sonar"), SONAR_RUN)
    report = log.find_step(("Sonarqube - Get report",), r'"projectStatus"')
    breaker = log.step("Breaker - Sonarqube")
    out: Dict[str, Any] = {"executed": run is not None}
    if run:
        t = run.text()
        m = re.search(r"Communicating with SonarQube Server ([\d.]+)|SonarQube server ([\d.]+)", t)
        out["server_version"] = next((g for g in m.groups() if g), None) if m else None
        m = re.search(r"^(?:\[INFO\]|INFO:?) Java (\d+)[\d.]*", t, re.M)
        out["scanner_java"] = int(m.group(1)) if m else None
        m = re.search(r"Running on \.\.\. (\S+)", t)
        out["scanner_image"] = m.group(1) if m else None
        out["properties"] = dict(re.findall(r"^(?:-D)?(sonar\.[\w.]+)=(\S*)", t, re.M))
        m = re.search(r"sonar\.java\.source\): (\d+)", t)
        out["java_source"] = int(m.group(1)) if m else None
        m = re.search(r"(\d+) files indexed", t)
        out["files_indexed"] = int(m.group(1)) if m else None
        m = re.search(r"Quality profile for java: (\S+)", t)
        out["java_profile"] = m.group(1) if m else None
        qg = re.search(r"QUALITY GATE STATUS: (PASSED|FAILED)", t)
        out["qualitygate_wait"] = bool(re.search(r"sonar\.qualitygate\.wait=true", t)) or bool(qg)
        if qg:
            out["gate_status"] = "OK" if qg.group(1) == "PASSED" else "ERROR"
        succ = run.find_line("ANALYSIS SUCCESSFUL")
        out["analysis_ok"] = succ is not None
        out["warnings"] = sorted({
            re.sub(r"^(?:\[WARNING\]|WARN:?)\s*", "", l.text).strip()
            for l in run.lines
            if re.match(r"^(?:\[WARNING\] |WARN:? )", l.text) and not l.text.startswith("[WARNING]   *")
        })
        if succ and report and report is not run:
            out["report_delay_s"] = _secs(succ.ts, report.start)
    data = _json_with(report, "projectStatus")
    if data:
        ps = data["projectStatus"]
        out["gate_status"] = ps.get("status")
        out["period"] = ps.get("period")
        out["conditions"] = {
            c.get("metricKey"): {"status": c.get("status"), "comparator": c.get("comparator"),
                                 "threshold": c.get("errorThreshold"), "actual": c.get("actualValue")}
            for c in ps.get("conditions", [])
        }
        out["report_line"] = report.first_line if report else None
        out["executed"] = True
    if breaker:
        bt = breaker.text()
        if "Bad Quality Gate" in bt or breaker.failed:
            out["breaker"] = "FALLO"
        elif re.search(r"^OK\s*$", bt, re.M):
            out["breaker"] = "OK"
        else:
            out["breaker"] = "N/D"
    elif out.get("gate_status"):
        out["breaker"] = "OK" if out["gate_status"] == "OK" else "FALLO"
    return out


# ---------------------------------------------------------------- CxOne

CX_ROW_RE = re.compile(
    r"\|\s*(SAST|SCA|SCS|IAC|APIs|CONTAINERS|TOTAL)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*\|"
)
CX_SECRET_ROW_RE = re.compile(r"\|\s*(Secret Detection|Scorecard)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*\|")
CX_BREAKER_RE = re.compile(r"\|\s*(SAST|SCA)\s*\|\s*(FALLO|PASO)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*(.*?)\s*\|")


def _cxone(log: PipelineLog) -> Dict[str, Any]:
    scan = log.find_step(("CxOne Scan",), r"Scan Summary|\|\s*SAST\s+\S+\s+\S+")
    breaker = log.find_step(("Breaker - CxOne",), r"REPORTE FINAL DE CUMPLIMIENTO")
    sast_json = log.find_step(("Get JSON SAST",), r'"state":\s*"\w+"')
    out: Dict[str, Any] = {"executed": scan is not None or breaker is not None}
    if scan:
        t = scan.text()
        engines = {}
        for m in CX_ROW_RE.finditer(t):
            vals = [_int(x) for x in m.groups()[1:6]]
            status = m.group(7)
            row = dict(zip(["critical", "high", "medium", "low", "info"], vals), status=status)
            row["ran"] = status != "-" and any(v is not None for v in vals)  # «-» = motor no ejecutado en este escaneo
            engines[m.group(1).upper() if m.group(1) != "APIs" else "APIs"] = row
        out["engines"] = engines
        m = re.search(r"Risk Level: ([^\t\n]+)", t)
        out["risk_level"] = m.group(1).strip() if m else None
        m = re.search(r"Total Results:\s*(\d+)", t)
        if m:
            out["total_results"] = int(m.group(1))
        for key, rx in (("project", r"Project Name:\s*(\S+)"), ("scan_id", r"Scan ID:\s*(\S+)"),
                        ("created_at", r"Created At:\s*([0-9\-]+,\s*[0-9:]+)"), ("branch", r"Branch name:\s*(\S+)"),
                        ("scan_types", r"--scan-types[ ,]+([a-z,]+)"), ("task_version", r"Version\s*:\s*(\d+\.\d+\.\d+)"),
                        ("cli_version", r"Version file content:\s*(\S+)")):
            m = re.search(rx, t)
            if m:
                out[key] = m.group(1).strip()
        sup = {}
        for m in CX_SECRET_ROW_RE.finditer(t):
            vals = [_int(x) for x in m.groups()[1:6]]
            sup[m.group(1)] = dict(zip(["critical", "high", "medium", "low", "info"], vals), status=m.group(7),
                                   ran=m.group(7) != "-" and any(v is not None for v in vals))
        if sup:
            out["supply_chain"] = sup
        if "Secret Detection" in sup:
            sd = sup["Secret Detection"]
            out["secrets"] = {"critical": sd["critical"], "high": sd["high"], "status": sd["status"]}
        m = re.search(r"SCS scan warning:\s*(.+)", t)
        if m:
            out["scs_warning"] = m.group(1).strip()[:220]
        m = re.search(r"Additional parameter: --sast-filter\s+Additional parameter:\s*\"([^\"]+)\"", t)
        if m:
            out["sast_filter"] = m.group(1)
        out["scan_line"] = scan.first_line
    if breaker:
        t = breaker.text()
        out["breaker"] = "FALLO" if breaker.failed or "FALLO DE SEGURIDAD" in t else "OK"
        out["modules"] = {
            m.group(1): {"status": m.group(2), "critical": int(m.group(3)), "high": int(m.group(4)), "info": m.group(5)}
            for m in CX_BREAKER_RE.finditer(t)
        }
        out["baseline"] = not bool(re.search(r"No se encontr[oó] l[ií]nea base", t, re.I))
        out["breaker_line"] = breaker.first_line
    if sast_json:
        states = Counter()
        for st, cnt in re.findall(r'"state":\s*"(\w+)",\s*"count":\s*(\d+)', sast_json.text()):
            states[st] += int(cnt)
        out["sast_states"] = dict(states)
    return out


# ---------------------------------------------------------------- TMAS


def _tmas(log: PipelineLog) -> Dict[str, Any]:
    run = log.find_step(("TMAS - Run",), r"tmas version")
    show = log.find_step(("TMAS - Show",), r'"totalVulnCount"')
    breaker = log.step("Breaker - TMAS")
    out: Dict[str, Any] = {"executed": run is not None or show is not None}
    if run:
        m = run.search(r"tmas version (\S+)")
        out["version"] = m.group(1) if m else None
    data = _json_with(show, "vulnerabilities")
    if data and isinstance(data.get("vulnerabilities"), dict):
        v = data["vulnerabilities"]
        out.update({"total": v.get("totalVulnCount"), "critical": v.get("criticalCount"), "high": v.get("highCount"),
                    "medium": v.get("mediumCount"), "low": v.get("lowCount")})
    if breaker:
        out["breaker"] = "FALLO" if breaker.failed else "OK"
    return out


# ---------------------------------------------------------------- Checkstyle / PMD / SpotBugs

STATIC_TOOLS = {
    "checkstyle": ("ReportBugs - Checkstyle", "Breaker - CheckStyle", "checkstyle",
                   r"You have (\d+) Checkstyle violations?|Checkstyle rule violations were found.*?(\d+) violations?"),
    "pmd": ("ReportBugs - PMD", "Breaker - PMD", "pmd",
            r"You have (\d+) PMD violations?|(\d+) PMD rule violations? were found"),
    "spotbugs": ("ReportBugs - Spotbugs", "Breaker - SpotBugs", "spotbugs",
                 r"Total bugs: (\d+)|BugInstance size is (\d+)"),
}

INFRA_PATTERNS = (
    "is already in use by container",
    "OCI runtime exec failed",
    "outside of container mount namespace",
)


def _static_tool(log: PipelineLog, report_name: str, breaker_name: str, goal: str, violations_re: str) -> Dict[str, Any]:
    # Goal de Maven ("--- pmd:3.28.0:pmd") o tarea de Gradle ("> Task :pmdMain")
    report = log.find_step((report_name,), r"--- %s:|> Task :%s" % (goal, goal))
    breaker = log.step(breaker_name)
    out: Dict[str, Any] = {"step_found": report is not None}
    if report:
        t = report.text()
        m = re.search(r"--- %s:(\S+):\w+ \(" % goal, t)
        out["plugin_version"] = m.group(1) if m else None
        blocked = any(p in t for p in INFRA_PATTERNS)
        ran = m is not None or bool(re.search(r"> Task :%s" % goal, t, re.I))
        if not ran and (blocked or ".ok not found" in t):
            status = "NO EJECUTADO"
        elif "BUILD FAILURE" in t or "encontró errores" in t or "encontro errores" in t or re.search(r"BUILD FAILED", t):
            status = "FALLO"
        elif report.failed:
            status = "FALLO"
        else:
            status = "OK"
        out["status"] = status
        out["blocked_by_infra"] = blocked and not ran
        out["report_line"] = report.first_line
        m = re.search(r"PMD version: (\S+)", t)
        if m:
            out["engine_version"] = m.group(1)
        vm = re.search(violations_re, t)
        if vm:
            out["violations"] = int(next(g for g in vm.groups() if g))
        if goal == "spotbugs":
            majors = Counter(int(x) for x in re.findall(r"Unsupported class file major version (\d+)", t))
            out["unsupported_class_versions"] = dict(majors)
            out["no_classes"] = "NoClassesFoundToAnalyzeException" in t
    if breaker:
        t = breaker.text()
        m = re.search(r"Se tienen (\d+) errores", t)
        out["violations"] = int(m.group(1)) if m else (0 if re.search(r"Sin errores", t, re.I) else out.get("violations"))
        out["report_missing"] = "FileNotFoundException" in t
        out["breaker"] = "FALLO" if breaker.failed else "OK"
        out["breaker_line"] = breaker.first_line
    elif report and out.get("status") != "NO EJECUTADO":
        out["breaker"] = "FALLO" if (out.get("violations") or out.get("status") == "FALLO") else "OK"
    return out


def _static(log: PipelineLog) -> Dict[str, Any]:
    return {name: _static_tool(log, *cfg) for name, cfg in STATIC_TOOLS.items()}


# ---------------------------------------------------------------- otros escáneres de seguridad


def _scanners(log: PipelineLog) -> Dict[str, Dict[str, Any]]:
    """Resúmenes de escáneres comunes en pipelines de cualquier proveedor."""
    text = log.full_text()
    out: Dict[str, Dict[str, Any]] = {}

    trivy = re.findall(r"Total: (\d+) \(UNKNOWN: (\d+), LOW: (\d+), MEDIUM: (\d+), HIGH: (\d+), CRITICAL: (\d+)\)", text)
    if trivy:
        s = [sum(int(r[i]) for r in trivy) for i in range(6)]
        out["trivy"] = {"total": s[0], "low": s[2], "medium": s[3], "high": s[4], "critical": s[5], "targets": len(trivy)}

    m = re.search(r"found (\d+) vulnerabilit(?:y|ies)(?: \(([^)]*)\))?", text) or \
        re.search(r"^(\d+) vulnerabilit(?:y|ies) \(([^)]*)\)", text, re.M)
    if m:
        sev = dict((w, int(n)) for n, w in re.findall(r"(\d+) (low|moderate|high|critical)", m.group(2) or ""))
        out["npm_audit"] = {"total": int(m.group(1)), "critical": sev.get("critical", 0), "high": sev.get("high", 0),
                            "medium": sev.get("moderate", 0), "low": sev.get("low", 0)}

    m = re.search(r"Tested (\d+) dependencies for known issues, found (\d+) issues?", text)
    if m:
        sev = Counter(s.lower() for s in re.findall(r"✗ (Critical|High|Medium|Low) severity", text))
        out["snyk"] = {"dependencies": int(m.group(1)), "total": int(m.group(2)), "critical": sev["critical"],
                       "high": sev["high"], "medium": sev["medium"], "low": sev["low"]}

    if re.search(r"dependency-check", text, re.I):
        vulnerable = bool(re.search(r"One or more dependencies were identified with known vulnerabilities", text))
        cves = sorted(set(re.findall(r"CVE-\d{4}-\d{4,}", text)))
        failed = bool(re.search(r"Failing the build|CVSS score (?:threshold|greater than)", text, re.I))
        out["dependency_check"] = {"vulnerable": vulnerable, "cves": cves[:50], "total": len(cves), "failed_build": failed,
                                   "critical": 0, "high": len(cves) if failed else 0}

    m = re.search(r"leaks found: (\d+)", text, re.I)
    if m or re.search(r"no leaks found", text, re.I):
        out["gitleaks"] = {"leaks": int(m.group(1)) if m else 0}

    m = re.search(r"Ran \d+ rules? on \d+ files?: (\d+) findings?", text)
    if m:
        out["semgrep"] = {"total": int(m.group(1))}

    ck = re.findall(r"Passed checks: (\d+), Failed checks: (\d+), Skipped checks: (\d+)", text)
    if ck:
        out["checkov"] = {"passed": sum(int(c[0]) for c in ck), "failed": sum(int(c[1]) for c in ck),
                          "skipped": sum(int(c[2]) for c in ck)}

    m = re.search(r"Total: (\d+) \(critical: (\d+), high: (\d+), medium: (\d+), low: (\d+)", text, re.I)
    if m and "trivy" not in out:
        out["grype"] = {"total": int(m.group(1)), "critical": int(m.group(2)), "high": int(m.group(3)),
                        "medium": int(m.group(4)), "low": int(m.group(5))}
    return out


# ---------------------------------------------------------------- infraestructura y avisos

WARNING_PATTERNS = {
    "mockito_self_attach": r"Mockito is currently self-attaching",
    "dynamic_agent": r"A Java agent has been loaded dynamically",
    "skipexec_deprecated": r"Parameter 'skipExec'.*deprecated",
    "sonar_jacoco_reportpath": r"'sonar\.jacoco\.reportPath' is no longer supported",
    "shallow_clone": r"Shallow clone detected",
    "sonar_plugin_unpinned": r"Using an unspecified version instead of an explicit plugin version",
    "sonar_preview_features": r"Use of preview features have been detected",
    "jacoco_xml_default": r"'sonar\.coverage\.jacoco\.xmlReportPaths' is not defined",
}


def _infra(log: PipelineLog) -> Dict[str, Any]:
    text = log.full_text()
    containers = sorted(set(re.findall(r'container name "(/[^"]+)" is already in use', text)))
    first_conflict = next((l.no for l in log.lines if "is already in use by container" in l.text), None)
    smtp = bool(re.search(r"EAUTH|Username and Password not accepted", text))
    smtp_line = next((l.no for l in log.lines if "EAUTH" in l.text), None)
    return {
        "container_conflicts": containers,
        "container_conflict_line": first_conflict,
        "oci_errors": len(re.findall(r"OCI runtime exec failed", text)),
        "smtp_auth_error": smtp,
        "smtp_line": smtp_line,
        "analysis_pushed": bool(re.search(r"All commits was pushed", text)),
    }


def _warnings(log: PipelineLog) -> Dict[str, bool]:
    text = log.full_text()
    return {k: bool(re.search(p, text)) for k, p in WARNING_PATTERNS.items()}


def _steps(log: PipelineLog) -> List[Dict[str, Any]]:
    return [{"name": s.name, "failed": s.failed, "errors": [e for e in s.errors if e][:5],
             "duration_s": s.duration, "line": s.first_line} for s in log.steps]


# ---------------------------------------------------------------- API pública


def extract(log: PipelineLog) -> Dict[str, Any]:
    sonar = _sonar(log)
    security = extract_security(log, sonar.get("server_version"))
    security["checklist"] = security_checklist(security)
    return {
        "meta": _meta(log),
        "env": _env(log),
        "tests": _tests(log),
        "jacoco": _jacoco(log),
        "sonar": sonar,
        "cxone": _cxone(log),
        "tmas": _tmas(log),
        "static": _static(log),
        "scanners": _scanners(log),
        "infra": _infra(log),
        "warnings": _warnings(log),
        "security": security,
        "steps": _steps(log),
    }
