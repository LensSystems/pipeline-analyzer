"""Ruta para pasar el pipeline: agrupa los hallazgos por lo que bloquea y los ordena en pasos accionables."""

from typing import Any, Dict, List

from .rules import SEVERITY_RANK, Finding

_TESTS = {"TESTS_FAILED", "TESTS_FAILURE_IGNORED", "POM_TEST_FAILURE_IGNORE"}
_STATIC = {"STATIC_NOT_EXECUTED", "SPOTBUGS_JAVA_UNSUPPORTED", "PMD_VIOLATIONS", "CHECKSTYLE_VIOLATIONS", "STATIC_TOOL_FAILED",
           "POM_PLUGINS_ONLY_IN_PROFILE", "POM_SPOTBUGS_THRESHOLD"}
_SONAR = {"POM_DEPRECATED_SONAR", "POM_JACOCO_ZERO"}
_SECURITY = {"SEC_SECRETS_IN_LOG", "TMAS_VULNS", "POM_KNOWN_CVE", "POM_HTTP_REPO"}
_SECURITY_PREFIX = ("CXONE_", "SCANNER_")

# (clave, título, por qué importa, compuertas del resumen que la representan, criterio de "listo")
GROUPS = [
    ("infra", "Desbloquear el pipeline",
     "Estas causas no están en tu código: las resuelve quien administra el pipeline. Mientras sigan, los demás resultados pueden ser "
     "incompletos o de otra corrida.",
     (), "El pipeline ejecuta Checkstyle, PMD y SpotBugs sin errores de contenedor y el quality gate de Sonar corresponde a esta corrida."),
    ("tests", "Tests unitarios",
     "Un test en rojo, o un build que lo ignora, invalida el resto de la validación.",
     ("Tests unitarios",), "0 tests fallidos y el build falla si un test falla (sin testFailureIgnore)."),
    ("static", "Análisis estático (Checkstyle, PMD, SpotBugs)",
     "Son breakers: si no corren o reportan violaciones, el pipeline se detiene.",
     ("Checkstyle", "PMD", "SpotBugs"), "Las tres herramientas se ejecutan y reportan 0 violaciones (o solo las aceptadas por el equipo)."),
    ("sonar", "SonarQube",
     "El quality gate decide si el código puede avanzar.",
     ("SonarQube",), "El quality gate del análisis de esta corrida queda en OK."),
    ("security", "Seguridad (CxOne, TMAS, escáneres y secretos)",
     "Los hallazgos Critical/High activos bloquean la aprobación.",
     ("CxOne SAST", "CxOne SCA", "TMAS", "Secretos en el log", "Gitleaks", "Trivy", "Grype", "Snyk"),
     "Sin hallazgos Critical/High activos (o marcados Not Exploitable con justificación) y sin secretos en el log."),
    ("improve", "Mejoras que no bloquean",
     "No impiden pasar hoy, pero reducen el riesgo de que falle mañana o acumulan deuda.",
     (), "Las que acuerde el equipo; ninguna es obligatoria para pasar."),
]
_TITLE = {g[0]: g for g in GROUPS}


def group_of(f: Finding) -> str:
    if f.owner == "pipeline":
        return "infra" if f.blocks else ""
    if f.id in _TESTS:
        return "tests"
    if f.id in _STATIC:
        return "static"
    if f.id.startswith("SONAR_") or f.id in _SONAR:
        return "sonar"
    if f.id in _SECURITY or f.id.startswith(_SECURITY_PREFIX):
        return "security"
    return "improve"


def build_plan(project: List[Finding], pipeline: List[Finding], gates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Pasos ordenados. Cada uno: clave, título, bloquea, compuertas, hallazgos (por severidad) y criterio de listo."""
    bad = {g["name"]: g for g in gates if g["status"] not in ("OK", "PASO", "ALERTA")}
    buckets: Dict[str, List[Finding]] = {g[0]: [] for g in GROUPS}
    for f in list(project) + [p for p in pipeline if p.blocks]:
        key = group_of(f)
        if key:
            buckets[key].append(f)
    steps = []
    for key, title, why, gate_names, done in GROUPS:
        fs = sorted(buckets[key], key=lambda f: (SEVERITY_RANK[f.severity], f.id))
        if not fs:
            continue
        failing = [bad[n] for n in gate_names if n in bad]
        blocks = key == "infra" or bool(failing) or (key not in ("improve",) and any(f.severity in ("CRITICAL", "HIGH") for f in fs))
        steps.append({"key": key, "title": title, "why": why, "blocks": blocks and key != "improve", "gates": failing,
                      "findings": fs, "done": done})
    # bloqueantes primero (respetando el orden lógico), las mejoras al final
    steps.sort(key=lambda s: (s["key"] == "improve", not s["blocks"]))
    for i, s in enumerate(steps, 1):
        s["n"] = i
    return steps


def validation_commands(framework: str, steps: List[Dict[str, Any]]) -> List[str]:
    """Comandos para validar en local antes de subir (solo si el proyecto es Maven)."""
    if "maven" not in (framework or "").lower():
        return []
    keys = {s["key"] for s in steps}
    cmds = ["mvn -B clean verify"]
    if "static" in keys:
        cmds.append("mvn -B checkstyle:check pmd:check spotbugs:check")
    return cmds
