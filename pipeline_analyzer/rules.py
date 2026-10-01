"""Motor de reglas: convierte métricas extraídas en hallazgos con recomendación."""

import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from .knowledge import SNIPPET_EMPTY_ARRAY_TEST, SNIPPET_EMPTY_STRING_TEST, lookup

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}
RATING_LETTER = {"1": "A", "2": "B", "3": "C", "4": "D", "5": "E"}
TOOL_LABEL = {"checkstyle": "Checkstyle", "pmd": "PMD", "spotbugs": "SpotBugs"}

_PLACEHOLDER = re.compile(r"\{(\w+)\}")


def safe_format(text: str, params: Dict[str, Any]) -> str:
    """Reemplaza solo los ``{nombre}`` conocidos; deja intactas otras llaves (JSON, jq, Java)."""
    return _PLACEHOLDER.sub(lambda m: str(params[m.group(1)]) if m.group(1) in params else m.group(0), text)


@dataclass
class Finding:
    id: str
    severity: str
    category: str
    title: str
    why: str
    steps: List[str]
    evidence: List[str] = field(default_factory=list)
    commands: List[str] = field(default_factory=list)
    snippet: Optional[str] = None
    key: str = ""
    line: Optional[int] = None
    location: Optional[str] = None  # "archivo.txt:123" cuando el log viene en varios archivos
    owner: str = "project"  # "project" (código, pom, manifiestos) o "pipeline" (definición, agente, plantillas: lo administra otro equipo)
    blocks: bool = False  # un hallazgo del pipeline que impide o distorsiona que el proyecto pase
    related: List[str] = field(default_factory=list)  # uids de hallazgos del pipeline que causan este
    evidence_full: List[str] = field(default_factory=list)  # evidencia sin enmascarar ni truncar (solo reporte completo)

    @property
    def where(self) -> Optional[str]:
        return self.location or ("línea %d" % self.line if self.line else None)

    @property
    def uid(self) -> str:
        return "%s:%s" % (self.id, self.key) if self.key else self.id

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d.pop("evidence_full", None)  # puede contener secretos reales: nunca va al JSON
        d["uid"] = self.uid
        return d


# Hallazgos cuya causa y solución están en la definición del pipeline, el agente o las plantillas (no en el proyecto)
PIPELINE_OWNED = {
    "DOCKER_CONTAINER_CONFLICT", "SMTP_AUTH", "TESTS_RUN_TWICE", "RUN_ATTEMPTS",
    "SONAR_STALE_GATE", "SONAR_RACE", "SONAR_BRANCH_ON_PR", "SONAR_SHALLOW_CLONE", "SONAR_SCANNER_JDK",
    "SEC_TLS_DISABLED", "SEC_PIPE_TO_SHELL", "SEC_INSECURE_HTTP", "SEC_CONTAINER_ISOLATION", "SEC_LATEST_IMAGES",
    "SEC_MUTABLE_REPOS", "SEC_UNVERIFIED_DOWNLOADS", "SEC_SONAR_UNSUPPORTED", "SEC_SCORECARD_SKIPPED",
    "SEC_REPORTS_DISTRIBUTED",
}
# Los del pipeline que además afectan a que el proyecto pase (o que mienten sobre el resultado)
PIPELINE_BLOCKERS = {"DOCKER_CONTAINER_CONFLICT", "SONAR_STALE_GATE", "SONAR_RACE"}
# Síntoma visible en el proyecto -> hallazgo del pipeline que lo causa
CAUSED_BY = {"STATIC_NOT_EXECUTED": ["DOCKER_CONTAINER_CONFLICT"]}


def is_pipeline_owned(f: "Finding") -> bool:
    return f.owner == "pipeline"


def pipeline_anchor(f: "Finding") -> str:
    """Identificador HTML estable del hallazgo del pipeline (destino de los enlaces «depende del pipeline»)."""
    return "pf-" + re.sub(r"\W+", "-", f.uid).strip("-")


def finding_anchor(f: "Finding") -> str:
    """Ancla HTML de cualquier hallazgo: ``pf-`` si es del pipeline, ``f-`` si es del proyecto."""
    return pipeline_anchor(f) if f.owner == "pipeline" else "f-" + re.sub(r"\W+", "-", f.uid).strip("-")


def classify(findings: List["Finding"]) -> None:
    """Marca quién es dueño de cada hallazgo y enlaza los síntomas del proyecto con su causa en el pipeline."""
    for f in findings:
        if f.id in PIPELINE_OWNED or f.id.startswith("PDEF_"):
            f.owner = "pipeline"
        f.blocks = f.owner == "pipeline" and f.id in PIPELINE_BLOCKERS
    by_id = {f.id: f for f in findings if f.owner == "pipeline"}
    for f in findings:
        f.related = [by_id[c].uid for c in CAUSED_BY.get(f.id, []) if c in by_id]


def make(fid: str, severity: str, category: str, params: Optional[Dict[str, Any]] = None,
         evidence: Optional[List[str]] = None, key: str = "", line: Optional[int] = None,
         kb_key: Optional[str] = None) -> Finding:
    params = params or {}
    kb = lookup(kb_key or fid)
    return Finding(
        id=fid,
        severity=severity,
        category=category,
        title=safe_format(kb["title"], params),
        why=safe_format(kb.get("why", ""), params),
        steps=[safe_format(s, params) for s in kb.get("steps", [])],
        evidence=evidence or [],
        commands=[safe_format(c, params) for c in kb.get("commands", [])],
        snippet=kb.get("snippet"),
        key=key,
        line=line,
    )


def _num(v: Any) -> Optional[float]:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _hint_for_assertion(message: str) -> Optional[str]:
    if re.search(r"<null> but was: <\[\]>", message):
        return "EMPTY_ARRAY"
    if re.search(r"<null> but was: <>", message):
        return "EMPTY_STRING"
    return None


# ------------------------------------------------------------------ reglas por sección


def _rules_tests(m: Dict[str, Any], out: List[Finding]) -> None:
    t = m["tests"]
    if not t.get("total"):
        return
    failed = t["failures"] + t["errors"]
    if failed:
        ev = []
        hints = set()
        for f in t["failing"]:
            ev.append("%s.%s:%s → %s (%s)" % (f["class"], f["method"], f["line"], f["message"],
                                              f.get("where") or "línea %s" % f["log_line"]))
            h = _hint_for_assertion(f["message"])
            if h:
                hints.add(h)
        fnd = make("TESTS_FAILED", "HIGH", "Tests", {"failures": failed}, ev, line=t.get("log_line"))
        if "EMPTY_ARRAY" in hints:
            fnd.steps.insert(0, "Patrón detectado: se esperaba null y llegó []. El código ahora retorna un arreglo "
                                "vacío (corrección típica de PMD/Sonar): actualiza los asserts, no regreses el null. "
                                "Revisa también los 'if (x == null)' de quienes lo llaman.")
            fnd.snippet = SNIPPET_EMPTY_ARRAY_TEST
        elif "EMPTY_STRING" in hints:
            fnd.steps.insert(0, "Patrón detectado: se esperaba null y llegó \"\". Alinea el test con el nuevo "
                                "comportamiento (cadena vacía) o regresa null si ese es el contrato.")
            fnd.snippet = SNIPPET_EMPTY_STRING_TEST
        out.append(fnd)
        if t.get("build_result") == "SUCCESS":
            out.append(make("TESTS_FAILURE_IGNORED", "HIGH", "Tests",
                            evidence=["Tests run: %s, Failures: %s → BUILD SUCCESS" % (t["total"], failed)],
                            line=t.get("log_line")))
    if t.get("executions", 0) > 1:
        out.append(make("TESTS_RUN_TWICE", "LOW", "Pipeline", {"executions": t["executions"]},
                        ["Pasos: " + ", ".join(t["executed_in"])]))
    if t.get("test_output_lines", 0) > 800:
        out.append(make("TEST_LOG_NOISE", "LOW", "Tests",
                        {"lines": t["test_output_lines"], "error_logs": t.get("error_log_lines", 0)}))
    if m["warnings"].get("mockito_self_attach") or m["warnings"].get("dynamic_agent"):
        out.append(make("MOCKITO_SELF_ATTACH", "LOW", "Tests"))


def _rules_sonar(m: Dict[str, Any], out: List[Finding]) -> None:
    s = m["sonar"]
    if not s.get("executed"):
        return
    conds = s.get("conditions") or {}
    t = m["tests"]
    delay = s.get("report_delay_s")
    stale = False

    # ¿El gate reportado coincide con los tests de ESTA corrida?
    tsd = conds.get("test_success_density")
    if tsd and t.get("total"):
        expected = round(100.0 * (t["total"] - t["failures"] - t["errors"]) / t["total"], 1)
        reported = _num(tsd.get("actual"))
        if reported is not None and abs(reported - expected) > 0.1:
            stale = True
            out.append(make("SONAR_STALE_GATE", "HIGH", "Sonar", {
                "passed": t["total"] - t["failures"] - t["errors"], "total": t["total"],
                "expected": expected, "reported": reported, "delay": delay if delay is not None else "?",
            }, ["test_success_density reportado=%s%% vs esperado=%s%%" % (reported, expected)], line=s.get("report_line")))
    if not stale and delay is not None and delay < 10 and not s.get("qualitygate_wait"):
        out.append(make("SONAR_RACE", "MEDIUM", "Sonar", {"delay": delay},
                        ["ANALYSIS SUCCESSFUL → Get report: %ss" % delay], line=s.get("report_line")))

    for metric, c in conds.items():
        actual, thr = c.get("actual"), c.get("threshold")
        params = {"metric": metric, "actual": actual, "threshold": thr,
                  "letter": RATING_LETTER.get(str(actual), actual)}
        if c.get("status") == "ERROR":
            if metric == "test_success_density" and stale:
                continue  # ya explicado como gate desfasado
            sev = "HIGH" if "rating" in metric or metric == "test_success_density" else "MEDIUM"
            kb_key = "SONAR:" + metric
            out.append(make("SONAR_CONDITION", sev, "Sonar", params,
                            ["%s: %s (%s %s)" % (metric, actual, c.get("comparator"), thr)],
                            key=metric, line=s.get("report_line"), kb_key=kb_key))
        elif metric in ("coverage", "new_coverage") and c.get("comparator") == "LT":
            a, th = _num(actual), _num(thr)
            if a is not None and th is not None and 0 <= a - th < 1:
                out.append(make("SONAR_COVERAGE_MARGIN", "LOW", "Sonar", params, key=metric))

    props = s.get("properties", {})
    if m["meta"].get("pull_request") and props.get("sonar.branch.name"):
        out.append(make("SONAR_BRANCH_ON_PR", "MEDIUM", "Sonar",
                        {"branch": props["sonar.branch.name"], "pr": m["meta"]["pull_request"]}))
    w = m["warnings"]
    if w.get("shallow_clone"):
        out.append(make("SONAR_SHALLOW_CLONE", "LOW", "Sonar"))
    if w.get("sonar_jacoco_reportpath") or "sonar.dynamicAnalysis" in props:
        out.append(make("SONAR_DEPRECATED_PROPS", "LOW", "Sonar"))
    if w.get("sonar_plugin_unpinned"):
        out.append(make("SONAR_PLUGIN_UNPINNED", "LOW", "Sonar"))
    proj = m["env"].get("java_release") or s.get("java_source")
    if s.get("scanner_java") and proj and s["scanner_java"] < proj:
        out.append(make("SONAR_SCANNER_JDK", "LOW", "Sonar",
                        {"scanner": s["scanner_java"], "project": proj, "server": s.get("server_version") or "?"}))


def _rules_cxone(m: Dict[str, Any], out: List[Finding]) -> None:
    c = m["cxone"]
    if not c.get("executed"):
        return
    eng = c.get("engines", {})
    mods = c.get("modules", {})
    sast = mods.get("SAST") or eng.get("SAST")
    if sast and ((sast.get("critical") or 0) + (sast.get("high") or 0)) > 0:
        sev = "CRITICAL" if (sast.get("critical") or 0) > 0 else "HIGH"
        out.append(make("CXONE_SAST", sev, "Seguridad",
                        {"critical": sast.get("critical") or 0, "high": sast.get("high") or 0},
                        ["Breaker CxOne SAST: %s" % (mods.get("SAST", {}).get("status", "?"))],
                        line=c.get("breaker_line")))
    tv = (c.get("sast_states") or {}).get("TO_VERIFY", 0)
    if tv:
        out.append(make("CXONE_SAST_TO_VERIFY", "MEDIUM", "Seguridad", {"count": tv}))
    if "baseline" in c and not c["baseline"]:
        out.append(make("CXONE_NO_BASELINE", "MEDIUM", "Seguridad", line=c.get("breaker_line")))
    sca = eng.get("SCA") or {}
    sca_high = (sca.get("critical") or 0) + (sca.get("high") or 0)
    if sca_high:
        status = mods.get("SCA", {}).get("status", "?")
        sev = "HIGH" if status == "FALLO" else "MEDIUM"
        out.append(make("CXONE_SCA_HIGH", sev, "Seguridad",
                        {"critical": sca.get("critical") or 0, "high": sca.get("high") or 0,
                         "status": "aprobado" if status == "PASO" else "bloqueando"}, line=c.get("scan_line")))
    scs = eng.get("SCS") or {}
    if scs.get("status") == "Partial":
        out.append(make("CXONE_SCS_PARTIAL", "INFO", "Seguridad"))


def _rules_tmas(m: Dict[str, Any], out: List[Finding]) -> None:
    t = m["tmas"]
    if (t.get("critical") or 0) + (t.get("high") or 0) > 0:
        out.append(make("TMAS_VULNS", "HIGH", "Seguridad", {"critical": t.get("critical"), "high": t.get("high")}))


def _rules_static(m: Dict[str, Any], out: List[Finding]) -> None:
    st = m["static"]
    infra = m["infra"]
    not_run = [n for n, d in st.items() if d.get("status") == "NO EJECUTADO"]
    if infra.get("container_conflicts"):
        names = infra["container_conflicts"]
        out.append(make("DOCKER_CONTAINER_CONFLICT", "CRITICAL", "Infraestructura",
                        {"containers": ", ".join(names), "first": names[0].lstrip("/")},
                        ["%d error(es) 'OCI runtime exec failed'" % infra.get("oci_errors", 0)],
                        line=infra.get("container_conflict_line")))
    if not_run:
        out.append(make("STATIC_NOT_EXECUTED", "HIGH", "Análisis estático",
                        {"tools": ", ".join(TOOL_LABEL[n] for n in not_run)}))
    sb = st.get("spotbugs", {})
    majors = sb.get("unsupported_class_versions") or {}
    if majors:
        major = max(int(k) for k in majors)
        out.append(make("SPOTBUGS_JAVA_UNSUPPORTED", "HIGH", "Análisis estático", {
            "plugin": sb.get("plugin_version") or "?", "java": major - 44, "major": major,
        }, ["%d clases rechazadas (major %d)" % (sum(majors.values()), major)], line=sb.get("report_line")))
    elif sb.get("status") == "FALLO":
        out.append(make("STATIC_TOOL_FAILED", "MEDIUM", "Análisis estático",
                        {"tool": "SpotBugs", "line": sb.get("report_line")}, key="spotbugs"))
    for tool, fid in (("pmd", "PMD_VIOLATIONS"), ("checkstyle", "CHECKSTYLE_VIOLATIONS")):
        d = st.get(tool, {})
        if d.get("violations"):
            out.append(make(fid, "MEDIUM", "Análisis estático", {"count": d["violations"]},
                            line=d.get("breaker_line")))
        elif d.get("status") == "FALLO":
            out.append(make("STATIC_TOOL_FAILED", "MEDIUM", "Análisis estático",
                            {"tool": TOOL_LABEL[tool], "line": d.get("report_line")}, key=tool))


def _rules_other(m: Dict[str, Any], out: List[Finding]) -> None:
    if m["infra"].get("smtp_auth_error"):
        out.append(make("SMTP_AUTH", "LOW", "Pipeline", line=m["infra"].get("smtp_line")))
    known = ("ReportBugs", "Breaker", "Maven - Verify")
    for s in m["steps"]:
        if s["failed"] and not s["name"].startswith(known):
            err = next((e for e in s["errors"] if not e.startswith("Bash exited")), s["errors"][0] if s["errors"] else "")
            out.append(make("STEP_FAILED_OTHER", "MEDIUM", "Pipeline",
                            {"step": s["name"], "error": err, "line": s["line"]}, key=s["name"], line=s["line"]))


CRITICAL_CVE_ARTIFACTS = ("log4j-core", "activemq-client", "activemq-broker", "commons-text", "spring-beans",
                          "spring-webmvc", "tomcat-embed-core")


def _rules_security(m: Dict[str, Any], out: List[Finding]) -> None:
    sec = m.get("security")
    if not sec:
        return
    cat = "Seguridad (pipeline)"
    s = sec["secrets_in_clear"]
    if s:
        out.append(make("SEC_SECRETS_IN_LOG", "CRITICAL", cat, {"count": len(s)},
                        ["%s: %s = %s" % (x["where"], x["type"], x["preview"]) for x in s[:10]], line=s[0]["line"]))
        out[-1].evidence_full = ["%s: %s = %s\n    %s" % (x["where"], x["type"], x["raw"], x["context"]) for x in s]
    mk = sec["sanitizer_markers"]
    if mk:
        out.append(make("SEC_SANITIZER_MARKERS", "LOW", cat, {"count": len(mk)},
                        ["%s %s: %s" % (x["where"], x["marker"], x["context"]) for x in mk[:10]]))
        out[-1].evidence_full = ["%s %s: %s" % (x["where"], x["marker"], x["context_full"]) for x in mk]
    if sec["tls_disabled"]:
        out.append(make("SEC_TLS_DISABLED", "HIGH", cat, evidence=sec["tls_disabled"][:5]))
    if sec["pipe_to_shell"]:
        out.append(make("SEC_PIPE_TO_SHELL", "HIGH", cat, evidence=sec["pipe_to_shell"][:5]))
    if sec["insecure_http"]:
        out.append(make("SEC_INSECURE_HTTP", "MEDIUM", cat, evidence=sec["insecure_http"][:8]))
        out[-1].evidence_full = list(sec.get("insecure_http_all") or sec["insecure_http"])
    vd = sec["vulnerable_dependencies"]
    if vd:
        sev = "CRITICAL" if any(d["artifact"] in CRITICAL_CVE_ARTIFACTS for d in vd) else "HIGH"
        out.append(make("SEC_VULNERABLE_DEPS", sev, cat, {"count": len(vd)},
                        ["%s %s → %s: %s (corregida en %s; origen: %s)" % (d["artifact"], d["version"], d["cve"], d["desc"],
                                                                           d["fixed"], d["source"]) for d in vd]))
    iso = sec["container_breakout_msgs"] or sec["docker_privileged"] or sec["docker_socket_mount"]
    if iso:
        ev = []
        if sec["container_breakout_msgs"]:
            ev.append("%d mensaje(s) 'possible container breakout detected'" % sec["container_breakout_msgs"])
        if sec["docker_privileged"]:
            ev.append("docker run --privileged")
        if sec["docker_socket_mount"]:
            ev.append("/var/run/docker.sock montado")
        out.append(make("SEC_CONTAINER_ISOLATION", "MEDIUM", cat, evidence=ev))
    if sec["build_images_latest"]:
        out.append(make("SEC_LATEST_IMAGES", "MEDIUM", cat, {"images": ", ".join(sec["build_images_latest"])}))
    if sec["mutable_repos"]:
        out.append(make("SEC_MUTABLE_REPOS", "MEDIUM", cat, {"repos": ", ".join(sec["mutable_repos"])}))
    if sec["downloads_without_integrity"]:
        out.append(make("SEC_UNVERIFIED_DOWNLOADS", "MEDIUM", cat, {"steps": ", ".join(sec["downloads_without_integrity"])}))
    if sec["sonar_unsupported"]:
        out.append(make("SEC_SONAR_UNSUPPORTED", "MEDIUM", cat, {"version": sec["sonar_version"]}))
    if sec["scorecard_skipped"]:
        out.append(make("SEC_SCORECARD_SKIPPED", "LOW", cat))
    channels = [c for c, on in (("repositorio git", sec["reports_published_git"]), ("correo", sec["reports_sent_mail"])) if on]
    if channels:
        out.append(make("SEC_REPORTS_DISTRIBUTED", "INFO", cat, {"channels": " y ".join(channels)}))

    mf = sec.get("manifest")
    if not mf:
        return
    cat = "Seguridad (Kubernetes)"
    missing = [lab for k, lab in (("run_as_non_root", "runAsNonRoot"), ("no_priv_escalation", "allowPrivilegeEscalation=false"),
                                   ("read_only_rootfs", "readOnlyRootFilesystem"), ("drop_all_caps", "drop ALL")) if not mf[k]]
    if missing:
        out.append(make("K8S_SECURITY_CONTEXT", "MEDIUM", cat,
                        {"missing": "sin securityContext" if not mf["security_context"] else "falta " + ", ".join(missing)}))
    if mf["privileged"] or mf["host_access"]:
        out.append(make("K8S_PRIVILEGED", "HIGH", cat,
                        {"detail": ", ".join((["privileged"] if mf["privileged"] else []) + mf["host_access"])}))
    if mf["admin_ports"]:
        sev = "HIGH" if any("JDWP" in p or "JMX" in p for p in mf["admin_ports"]) else "MEDIUM"
        out.append(make("K8S_ADMIN_PORTS", sev, cat, {"ports": ", ".join(mf["admin_ports"])}))
    if mf["mutable_images"]:
        out.append(make("K8S_MUTABLE_IMAGE", "MEDIUM", cat, {"images": ", ".join(mf["mutable_images"])}))
    if not mf["resource_limits"]:
        out.append(make("K8S_NO_LIMITS", "LOW", cat))
    if not mf["probes"]:
        out.append(make("K8S_NO_PROBES", "LOW", cat))
    if mf["configmap_cleartext_secrets"]:
        out.append(make("K8S_CONFIGMAP_SECRETS", "HIGH", cat, {"keys": ", ".join(mf["configmap_cleartext_secrets"])}))
    risky = mf["actuator_risky"] + (["shutdown"] if mf["actuator_shutdown"] else []) + \
        (["health show-details=always"] if mf["actuator_show_details_always"] else [])
    if risky:
        sev = "HIGH" if any(e in ("*", "env", "heapdump", "shutdown", "jolokia") for e in risky) else "MEDIUM"
        out.append(make("K8S_ACTUATOR", sev, cat, {"endpoints": ", ".join(risky)}))
    dbg = mf["debug_logging"] + (["spring.jpa.show-sql=true"] if mf["show_sql"] else [])
    if dbg:
        out.append(make("K8S_DEBUG_LOGGING", "LOW", cat, {"items": ", ".join(dbg[:4])}))


def _rules_definitions(m: Dict[str, Any], out: List[Finding]) -> None:
    cat = "Definición del pipeline"
    for d in (m.get("security") or {}).get("definitions") or []:
        f = d["file"].rsplit("/", 1)[-1]
        key = d["file"]
        sec = [t for t in d["tolerated_failures"] if t["security"]]
        other = [t for t in d["tolerated_failures"] if not t["security"]]
        if sec:
            out.append(make("PDEF_TOLERATED_SECURITY", "HIGH", cat, {"count": len(sec), "file": f},
                            ["%s:%d → %s" % (f, t["line"], t["step"]) for t in sec[:15]], key=key))
        if other:
            out.append(make("PDEF_TOLERATED_OTHER", "LOW", cat, {"count": len(other), "file": f},
                            ["%s:%d → %s" % (f, t["line"], t["step"]) for t in other[:15]], key=key))
        if d["secrets"]:
            out.append(make("PDEF_SECRETS", "CRITICAL", cat, {"file": f},
                            ["%s:%d → %s" % (f, s["line"], s["type"]) for s in d["secrets"][:10]], key=key))
        if d["mutable_template_refs"]:
            out.append(make("PDEF_MUTABLE_REFS", "MEDIUM", cat, {"file": f, "refs": ", ".join(d["mutable_template_refs"][:4])}, key=key))
        if d["persist_credentials"]:
            out.append(make("PDEF_PERSIST_CREDENTIALS", "MEDIUM", cat, {"file": f}, key=key))
        if d["system_debug"]:
            out.append(make("PDEF_SYSTEM_DEBUG", "MEDIUM", cat, {"file": f}, key=key))
        if d["set_x"]:
            out.append(make("PDEF_SET_X", "LOW", cat, {"file": f, "lines": ", ".join(map(str, d["set_x"][:8]))}, key=key))
        if d["latest_images"]:
            out.append(make("PDEF_LATEST_IMAGES", "MEDIUM", cat, {"file": f, "images": ", ".join(d["latest_images"][:4])}, key=key))
        if d["pipe_to_shell"]:
            out.append(make("PDEF_PIPE_SHELL", "HIGH", cat, {"file": f, "lines": ", ".join(map(str, d["pipe_to_shell"][:8]))}, key=key))
        if d["tls_disabled"]:
            out.append(make("PDEF_TLS", "HIGH", cat, {"file": f, "lines": ", ".join(map(str, d["tls_disabled"][:8]))}, key=key))
        if d["unpinned_actions"]:
            out.append(make("PDEF_UNPINNED_ACTIONS", "MEDIUM", cat, {"count": len(d["unpinned_actions"]), "file": f},
                            d["unpinned_actions"][:15], key=key))
        if d["pull_request_target"]:
            out.append(make("PDEF_PR_TARGET", "HIGH", cat, {"file": f}, key=key))
        if d["write_all"] or d["missing_permissions"]:
            out.append(make("PDEF_PERMISSIONS", "HIGH" if d["write_all"] else "LOW", cat, {"file": f}, key=key))


SCANNER_LABEL = {"trivy": "Trivy", "npm_audit": "npm audit", "snyk": "Snyk", "grype": "Grype",
                 "dependency_check": "OWASP Dependency-Check", "gitleaks": "Gitleaks", "semgrep": "Semgrep",
                 "checkov": "Checkov"}


def _rules_scanners(m: Dict[str, Any], out: List[Finding]) -> None:
    cat = "Seguridad (escáneres)"
    for name, d in (m.get("scanners") or {}).items():
        label = SCANNER_LABEL.get(name, name)
        if name == "gitleaks":
            if d["leaks"]:
                out.append(make("SCANNER_LEAKS", "CRITICAL", cat, {"leaks": d["leaks"]}, key=name))
        elif name in ("semgrep", "checkov"):
            n = d.get("total", d.get("failed", 0))
            if n:
                out.append(make("SCANNER_FINDINGS", "MEDIUM", cat, {"scanner": label, "count": n}, key=name))
        else:
            c, h = d.get("critical", 0) or 0, d.get("high", 0) or 0
            if name == "dependency_check" and d.get("vulnerable") and not (c or h):
                h = d.get("total", 0)
            if c or h:
                ev = ["CVE: " + ", ".join(d["cves"][:10])] if d.get("cves") else []
                out.append(make("SCANNER_VULNS", "CRITICAL" if c else "HIGH", cat,
                                {"scanner": label, "critical": c, "high": h}, ev, key=name))


def _rules_meta(m: Dict[str, Any], out: List[Finding]) -> None:
    meta = m["meta"]
    if meta.get("attempts", 1) > 1:
        out.append(make("RUN_ATTEMPTS", "INFO", "Pipeline", {"attempts": meta["attempts"], "attempt": meta["attempt"]}))


def evaluate(metrics: Dict[str, Any]) -> List[Finding]:
    out: List[Finding] = []
    for rule in (_rules_static, _rules_tests, _rules_sonar, _rules_cxone, _rules_tmas, _rules_security,
                 _rules_definitions, _rules_scanners, _rules_meta, _rules_other):
        rule(metrics, out)
    out.sort(key=lambda f: (SEVERITY_RANK[f.severity], f.category, f.id))
    classify(out)
    return out
