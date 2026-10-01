"""Validaciones de seguridad del pipeline.

- Secretos en claro en el log (y redacción de reportes).
- Controles del pipeline y de la cadena de suministro (TLS, http, curl|bash, imágenes :latest,
  aislamiento de contenedores, templates en ramas mutables, descargas sin verificación de integridad).
- Inventario de dependencias visibles en el log contra CVE conocidos.
- Manifiestos de Kubernetes/OpenShift impresos por el pipeline (securityContext, puertos de
  administración, credenciales en ConfigMap, Actuator, etc.).

Todo el análisis es local: este módulo no abre conexiones de red.
"""

import re
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

from .logparser import PipelineLog

# ============================================================== secretos

# (tipo, regex). El grupo 1, si existe, es el valor secreto; si no, toda la coincidencia.
SECRET_PATTERNS: List[Tuple[str, "re.Pattern[str]"]] = [
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----")),
    ("aws_access_key", re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b")),
    ("github_token", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b")),
    ("gitlab_token", re.compile(r"\b(glpat-[A-Za-z0-9_-]{20,})\b")),
    ("slack_token", re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b")),
    ("slack_webhook", re.compile(r"(https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,})")),
    ("google_api_key", re.compile(r"\b(AIza[0-9A-Za-z_-]{35})\b")),
    ("npm_token", re.compile(r"\b(npm_[A-Za-z0-9]{36})\b")),
    ("sonar_token", re.compile(r"\b(sq[pau]_[a-f0-9]{40})\b")),
    ("jwt", re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})")),
    ("azure_storage_key", re.compile(r"AccountKey=([A-Za-z0-9+/=]{40,})")),
    ("azure_sas", re.compile(r"[?&]sig=([A-Za-z0-9%+/=]{20,})")),
    ("url_credentials", re.compile(r"\b[a-z][a-z0-9+.-]*://[^/\s:@'\"]+:((?!\*\*\*)[^/\s@'\"]{3,})@")),
    ("bearer_token", re.compile(r"(?i)\bbearer\s+([A-Za-z0-9._~+/-]{20,}=*)")),
    ("basic_auth", re.compile(r"(?i)authorization:\s*basic\s+([A-Za-z0-9+/=]{12,})")),
    ("password_assignment", re.compile(
        r"(?i)\b(?:password|passwd|pwd|secret|client[_-]?secret|api[_-]?key|access[_-]?key|auth[_-]?token)"
        r"\b[\"']?\s*[:=]\s*[\"']?(?!\$\{|\$\(|\*\*\*|<|%|\s|true\b|false\b|null\b|none\b)([^\s'\",;]{6,})")),
]

MARKER_RE = re.compile(r"<(SECRET|TOKEN|PASSWORD|KEY|CREDENTIAL|PRIVATE_KEY)_(\d+)>")


def _mask(value: str) -> str:
    if len(value) <= 8:
        return "****"
    return value[:4] + "…" + "*" * 4


def find_secrets(text: str) -> List[Tuple[str, str]]:
    found = []
    for kind, rx in SECRET_PATTERNS:
        for m in rx.finditer(text):
            value = m.group(1) if m.groups() else m.group(0)
            if not value.startswith("[REDACTADO"):
                found.append((kind, value))
    return found


def redact(text: str) -> str:
    """Reemplaza secretos por ``[REDACTADO:tipo]``. Se aplica a todos los reportes por defecto."""
    for kind, rx in SECRET_PATTERNS:
        def _sub(m, kind=kind):
            if not m.groups():
                return "[REDACTADO:%s]" % kind
            start, end = m.span(1)
            s0 = m.start(0)
            whole = m.group(0)
            return whole[: start - s0] + "[REDACTADO:%s]" % kind + whole[end - s0:]
        text = rx.sub(_sub, text)
    return text


_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_URL_HOST_RE = re.compile(r"\b(https?|jdbc:[a-z]+|ssh|git)://([^/\s:'\"<>]+)")
_PUBLIC_HOSTS = ("maven.apache.org", "www.w3.org", "github.com", "docs.sonarsource.com", "hooks.slack.com")


def mask_infra(text: str, hosts: Optional[Dict[str, str]] = None) -> str:
    """Enmascara correos, IPs y hosts de URLs (para compartir reportes fuera del equipo).

    ``hosts`` permite conservar la numeración (host-1, host-2…) entre varias llamadas sobre el mismo reporte.
    """
    hosts = {} if hosts is None else hosts

    def _host(m):
        h = m.group(2)
        if h in _PUBLIC_HOSTS or h.startswith("["):
            return m.group(0)
        hosts.setdefault(h, "host-%d" % (len(hosts) + 1))
        return "%s://%s" % (m.group(1), hosts[h])

    text = _URL_HOST_RE.sub(_host, text)
    text = _EMAIL_RE.sub("[correo]", text)
    return _IPV4_RE.sub("[ip]", text)


# ============================================================== dependencias con CVE conocidos

# artifactId -> (versiones corregidas por rama, CVE, descripción)
KNOWN_VULNERABLE: Dict[str, Tuple[List[str], str, str]] = {
    "log4j-core": (["2.17.1"], "CVE-2021-44228/45046/44832", "Log4Shell: ejecución remota de código"),
    "snakeyaml": (["2.0"], "CVE-2022-1471", "Deserialización insegura (RCE)"),
    "commons-text": (["1.10.0"], "CVE-2022-42889", "Text4Shell: interpolación con RCE"),
    "activemq-client": (["5.15.16", "5.16.7", "5.17.6", "5.18.3"], "CVE-2023-46604", "RCE vía OpenWire (CVSS 10)"),
    "activemq-broker": (["5.15.16", "5.16.7", "5.17.6", "5.18.3"], "CVE-2023-46604", "RCE vía OpenWire (CVSS 10)"),
    "spring-beans": (["5.2.20", "5.3.18"], "CVE-2022-22965", "Spring4Shell: RCE por data binding"),
    "spring-webmvc": (["5.2.20", "5.3.18"], "CVE-2022-22965", "Spring4Shell: RCE por data binding"),
    "jackson-databind": (["2.12.7.1", "2.13.4.2"], "CVE-2022-42003/42004", "DoS por deserialización"),
    "h2": (["2.1.210"], "CVE-2021-42392/2022-23221", "RCE vía consola/JDBC URL"),
    "xstream": (["1.4.20"], "CVE-2022-41966", "DoS/RCE en deserialización"),
    "commons-collections": (["3.2.2"], "CVE-2015-7501", "Gadget de deserialización (RCE)"),
    "logback-classic": (["1.2.13", "1.3.14", "1.4.14"], "CVE-2023-6378/6481", "DoS en receptor de logs"),
    "logback-core": (["1.2.13", "1.3.14", "1.4.14"], "CVE-2023-6378/6481", "DoS en receptor de logs"),
    "pdfbox": (["2.0.24"], "CVE-2021-31811/31812", "OOM/bucle infinito con PDF malicioso"),
    "netty-codec-http2": (["4.1.100"], "CVE-2023-44487", "HTTP/2 Rapid Reset (DoS)"),
    "tomcat-embed-core": (["9.0.99", "10.1.35", "11.0.3"], "CVE-2025-24813", "RCE/escritura con PUT parcial"),
}


def vtuple(v: str) -> Tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", v)[:4]) or (0,)


def is_vulnerable(version: str, fixes: List[str]) -> bool:
    v = vtuple(version)
    fixes_t = sorted(vtuple(f) for f in fixes)
    same_line = [f for f in fixes_t if f[:2] == v[:2]]
    if same_line:
        return v < same_line[0]
    return v < fixes_t[0] if v[:2] < fixes_t[0][:2] else False


# Coordenadas maven en URLs (logs sin sanitizar) y nombres de jar (sanitizados o no)
MAVEN_PATH_RE = re.compile(r"/((?:[\w-]+/)+)([\w.-]+)/(\d[\w.-]*)/\2-\3(?:-[\w]+)?\.(?:jar|pom)")
JAR_RE = re.compile(r"(?<![\w.-])([a-z][\w.]*(?:-[a-z][\w.]*)*)-(\d+(?:\.\d+)+(?:[.-][\w]+)?)\.jar\b")


_GROUP_ROOTS = {"org", "com", "io", "net", "jakarta", "javax", "ch", "tools", "edu", "de", "info", "me", "dev", "biz", "co"}


def dependency_inventory(text: str) -> Dict[str, Dict[str, Any]]:
    inv: Dict[str, Dict[str, Any]] = {}
    for m in MAVEN_PATH_RE.finditer(text):
        segs = m.group(1).strip("/").split("/")
        start = next((i for i, x in enumerate(segs) if x in _GROUP_ROOTS), max(0, len(segs) - 2))
        group = ".".join(segs[start:])
        inv["%s:%s" % (m.group(2), m.group(3))] = {"group": group, "artifact": m.group(2), "version": m.group(3),
                                                    "source": "repositorio maven"}
    for m in JAR_RE.finditer(text):
        art, ver = m.group(1), m.group(2)
        key = "%s:%s" % (art, ver)
        if key in inv:
            continue
        ctx = text[max(0, m.start() - 60): m.start()]
        source = "herramienta de build" if "/usr/share/maven" in ctx or "/lib/" in ctx else "aplicación/plugins"
        inv[key] = {"group": None, "artifact": art, "version": ver, "source": source}
    return inv


def vulnerable_deps(inv: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    for d in inv.values():
        kv = KNOWN_VULNERABLE.get(d["artifact"])
        if kv and is_vulnerable(d["version"], kv[0]):
            out.append(dict(d, cve=kv[1], desc=kv[2], fixed=", ".join(kv[0])))
    return out


# ============================================================== manifiestos Kubernetes / OpenShift

SENSITIVE_KEY_RE = re.compile(r"(?i)(password|passwd|pwd|secret|token|api[-_.]?key|credential|private[-_.]?key)")
PROP_RE = re.compile(r"^\s*([A-Za-z0-9_.\-\[\]]+)\s*[=:]\s*(.*)$")
RISKY_ACTUATOR = ("*", "env", "heapdump", "threaddump", "jolokia", "configprops", "beans", "loggers", "shutdown", "mappings")


def _manifest_text(log: PipelineLog) -> Optional[str]:
    step = log.step("Validate manifest - Location")
    if step and ("containers:" in step.text() or "kind: ConfigMap" in step.text()):
        return step.text()
    t = log.full_text()
    return t if "containers:" in t else None


def manifest_checks(text: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    out["security_context"] = "securityContext:" in text
    out["run_as_non_root"] = bool(re.search(r"runAsNonRoot:\s*true", text))
    out["no_priv_escalation"] = bool(re.search(r"allowPrivilegeEscalation:\s*false", text))
    out["read_only_rootfs"] = bool(re.search(r"readOnlyRootFilesystem:\s*true", text))
    out["drop_all_caps"] = bool(re.search(r"drop:\s*\n?\s*-\s*['\"]?ALL", text))
    out["privileged"] = bool(re.search(r"privileged:\s*true", text))
    host = set(re.findall(r"(hostNetwork|hostPID|hostIPC):\s*true", text))
    if re.search(r"^\s*hostPath:", text, re.M):
        host.add("hostPath")
    out["host_access"] = sorted(host)
    ports = re.findall(r"containerPort:\s*(\d+)", text)
    names = re.findall(r"^\s*name:\s*(jolokia|debug|jdwp|jmx)\s*$", text, re.M | re.I)
    admin = []
    if "8778" in ports or any(n.lower() == "jolokia" for n in names):
        admin.append("Jolokia (8778)")
    if "5005" in ports or re.search(r"-agentlib:jdwp|-Xrunjdwp", text):
        admin.append("JDWP debug")
    if re.search(r"jmxremote\.authenticate=false", text):
        admin.append("JMX sin autenticación")
    out["admin_ports"] = admin
    images = re.findall(r"^\s*image:\s*['\"]?(\S+?)['\"]?\s*$", text, re.M)
    out["images"] = images
    out["mutable_images"] = [i for i in images if i.endswith(":latest") or (":" not in i.split("/")[-1] and "@sha256" not in i)]
    out["resource_limits"] = bool(re.search(r"limits:\s*\n\s+(cpu|memory):", text))
    out["probes"] = bool(re.search(r"livenessProbe:", text)) and bool(re.search(r"readinessProbe:", text))
    out["secret_refs"] = len(re.findall(r"secretRef:|secretKeyRef:", text))

    # ConfigMap: credenciales en claro vs referencias ${VAR}
    cleartext, placeholders = [], 0
    actuator, debug_logging, show_sql = None, [], False
    in_cm = False
    for line in text.splitlines():
        if re.match(r"^\s*kind:\s*ConfigMap", line):
            in_cm = True
        elif re.match(r"^\s*kind:\s*\w+", line):
            in_cm = False
        m = PROP_RE.match(line)
        if not m:
            continue
        key, value = m.group(1), m.group(2).strip().strip("'\"")
        if key.startswith("management.endpoints.web.exposure.include"):
            actuator = value
        if re.match(r"(?i)logging\.level\..*", key) and value.upper() in ("DEBUG", "TRACE"):
            debug_logging.append("%s=%s" % (key, value))
        if key == "spring.jpa.show-sql" and value.lower() == "true":
            show_sql = True
        if in_cm and SENSITIVE_KEY_RE.search(key) and value:
            if value.startswith("${") or value.startswith("<"):
                placeholders += 1
            elif value.lower() not in ("true", "false", "none", "null", ""):
                cleartext.append(key)
    out["configmap_cleartext_secrets"] = cleartext
    out["configmap_secret_placeholders"] = placeholders
    out["actuator_exposure"] = actuator
    out["actuator_risky"] = [e for e in (actuator or "").replace(" ", "").split(",") if e in RISKY_ACTUATOR]
    out["actuator_show_details_always"] = bool(re.search(r"management\.endpoint\.health\.show-details\s*=\s*always", text))
    out["actuator_shutdown"] = bool(re.search(r"management\.endpoint\.shutdown\.enabled\s*=\s*true", text))
    out["debug_logging"] = debug_logging
    out["show_sql"] = show_sql
    return out


# ============================================================== extracción principal

INSECURE_TLS_RE = re.compile(
    r"(?:\bcurl\b[^\n]*\s(?:-k|--insecure)\b|wget[^\n]*--no-check-certificate|maven\.wagon\.http\.ssl\.(?:insecure|allowall)=true"
    r"|GIT_SSL_NO_VERIFY=(?:1|true)|http\.sslVerify=false|NODE_TLS_REJECT_UNAUTHORIZED=0|PYTHONHTTPSVERIFY=0"
    r"|strict-ssl\s*=?\s*false|-Dcom\.sun\.net\.ssl\.checkRevocation=false)", re.I)
PIPE_SHELL_RE = re.compile(r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b")
HTTP_URL_RE = re.compile(r"\bhttp://(?!localhost|127\.0\.0\.1|maven\.apache\.org/POM|www\.w3\.org|maven\.apache\.org/xsd|<)[^\s'\"<>]+")
INTEGRITY_RE = re.compile(r"sha256sum|sha512sum|shasum|checksum|gpg --verify|cosign verify|--hash|Signature verified", re.I)


def extract_security(log: PipelineLog, sonar_version: Optional[str] = None) -> Dict[str, Any]:
    out: Dict[str, Any] = {}

    # --- secretos en claro (por línea, con valor enmascarado)
    secrets = []
    scan_lines = list(log.lines) + list(getattr(log, "aux_lines", []))  # incluye logs de diagnóstico del agente
    for l in scan_lines:
        if not l.text or "[REDACTADO" in l.text:
            continue
        for kind, value in find_secrets(l.text):
            secrets.append({"type": kind, "line": l.no, "where": l.where, "preview": _mask(value),
                            "raw": value, "context": l.text.strip()})
    out["secrets_in_clear"] = secrets

    # --- marcadores dejados por el sanitizador (el log original tenía valores sensibles)
    markers: Dict[str, int] = {}
    marker_lines: List[Dict[str, Any]] = []
    for l in scan_lines:
        for m in MARKER_RE.finditer(l.text):
            key = "%s_%s" % (m.group(1), m.group(2))
            if key not in markers:
                markers[key] = l.no
                marker_lines.append({"marker": "<%s>" % key, "line": l.no, "where": l.where, "context": l.text.strip()[:140],
                                     "context_full": l.text.strip()})
    out["sanitizer_markers"] = marker_lines
    out["azure_masked"] = sum(l.text.count("***") for l in log.lines)

    text = log.full_text()
    # --- transporte / TLS / scripts remotos
    all_http = sorted(set(HTTP_URL_RE.findall(text)))
    out["insecure_http"] = all_http[:20]
    out["insecure_http_all"] = all_http
    out["tls_disabled"] = sorted(set(m.group(0)[:120] for m in INSECURE_TLS_RE.finditer(text)))
    out["pipe_to_shell"] = sorted(set(m.group(0)[:120] for m in PIPE_SHELL_RE.finditer(text)))

    # --- imágenes y aislamiento de contenedores
    imgs = set(re.findall(r"Running on \.\.\. (\S+)", text)) | set(re.findall(r"docker (?:run|pull)[^\n]*?\s([\w./<>-]+:latest)\b", text))
    out["build_images"] = sorted(imgs)
    out["build_images_latest"] = sorted(i for i in imgs if i.endswith(":latest") or ":" not in i.split("/")[-1])
    out["container_breakout_msgs"] = len(re.findall(r"possible container breakout detected", text))
    out["docker_privileged"] = bool(re.search(r"docker run[^\n]*--privileged", text))
    out["docker_socket_mount"] = bool(re.search(r"/var/run/docker\.sock", text))

    # --- cadena de suministro del pipeline
    mutable = []
    for m in re.finditer(r"Clone repo (\S+) , branch (\S+) , on (\S+)", text):
        if m.group(2) in ("master", "main", "develop"):
            mutable.append("%s (rama %s)" % (m.group(3), m.group(2)))
    out["mutable_repos"] = sorted(set(mutable))
    unverified = []
    for s in log.steps:
        name = s.name.lower()
        if "download" in name and "settings" not in name and "secure file" not in s.text().lower():
            st = s.text()
            if re.search(r"wget|curl|Downloading|download", st, re.I) and not INTEGRITY_RE.search(st):
                unverified.append(s.name)
    out["downloads_without_integrity"] = sorted(set(unverified))

    # --- dependencias
    inv = dependency_inventory(text)
    out["dependency_inventory_size"] = len(inv)
    out["vulnerable_dependencies"] = vulnerable_deps(inv)

    # --- escáneres de seguridad incompletos
    out["scorecard_skipped"] = bool(re.search(r"Unable to start Scorecard scan", text))
    out["sonar_version"] = sonar_version
    out["sonar_unsupported"] = bool(sonar_version) and vtuple(sonar_version)[0] < 2025

    # --- publicación de reportes de seguridad
    out["reports_published_git"] = bool(re.search(r"Added analysis for", text))
    out["reports_sent_mail"] = bool(re.search(r"Prepare Send mail|Sendmail", text))

    # --- manifiestos
    mt = _manifest_text(log)
    out["manifest"] = manifest_checks(mt) if mt else None

    # --- definición del pipeline (YAML / Jenkinsfile incluidos en la descarga)
    from .pipeline_def import check_definitions  # import local: pipeline_def usa este módulo
    out["definitions"] = check_definitions(getattr(log, "definitions", []))
    return out


# ============================================================== tabla de validaciones (pasan / alertan)


def security_checklist(sec: Dict[str, Any]) -> List[Dict[str, str]]:
    OK, ALERT, NA = "OK", "ALERTA", "N/D"
    rows: List[Dict[str, str]] = []

    def add(area, name, status, detail=""):
        rows.append({"area": area, "check": name, "status": status, "detail": detail})

    n = len(sec["secrets_in_clear"])
    add("Secretos", "Secretos en claro en el log", ALERT if n else OK,
        "%d coincidencia(s): %s" % (n, ", ".join(sorted({s["type"] for s in sec["secrets_in_clear"]}))) if n else "Sin patrones de secretos")
    nm = len(sec["sanitizer_markers"])
    add("Secretos", "Valores sensibles en el log original (según el sanitizador)", ALERT if nm else OK,
        "%d marcador(es) únicos" % nm if nm else "Sin marcadores")
    add("Secretos", "Enmascarado de variables secretas de Azure (***)", OK if sec["azure_masked"] else NA,
        "%d valor(es) enmascarados" % sec["azure_masked"])
    add("Transporte", "URLs sin TLS (http://)", ALERT if sec["insecure_http"] else OK, ", ".join(sec["insecure_http"][:3]))
    add("Transporte", "Verificación TLS deshabilitada", ALERT if sec["tls_disabled"] else OK, "; ".join(sec["tls_disabled"][:2]))
    add("Supply chain", "Scripts remotos ejecutados con curl|bash", ALERT if sec["pipe_to_shell"] else OK, "; ".join(sec["pipe_to_shell"][:2]))
    add("Supply chain", "Imágenes de build fijadas (sin :latest)", ALERT if sec["build_images_latest"] else OK,
        ", ".join(sec["build_images_latest"]))
    add("Supply chain", "Templates/listas de excepciones desde rama mutable", ALERT if sec["mutable_repos"] else OK,
        ", ".join(sec["mutable_repos"]))
    add("Supply chain", "Herramientas descargadas con verificación de integridad", ALERT if sec["downloads_without_integrity"] else OK,
        ", ".join(sec["downloads_without_integrity"]))
    vd = sec["vulnerable_dependencies"]
    add("Supply chain", "Dependencias con CVE conocidos (inventario del log)", ALERT if vd else (OK if sec["dependency_inventory_size"] else NA),
        ", ".join("%s %s (%s)" % (d["artifact"], d["version"], d["cve"]) for d in vd) or "%d artefacto(s) revisados" % sec["dependency_inventory_size"])
    iso = []
    if sec["container_breakout_msgs"]:
        iso.append("runc bloqueó %d exec ('possible container breakout')" % sec["container_breakout_msgs"])
    if sec["docker_privileged"]:
        iso.append("docker --privileged")
    if sec["docker_socket_mount"]:
        iso.append("docker.sock montado")
    add("Contenedores", "Aislamiento de contenedores del agente", ALERT if iso else OK, "; ".join(iso))
    add("Escáneres", "SonarQube en versión soportada", ALERT if sec["sonar_unsupported"] else (OK if sec["sonar_version"] else NA),
        sec["sonar_version"] or "")
    add("Escáneres", "CxOne Scorecard (SCS) ejecutado", ALERT if sec["scorecard_skipped"] else OK,
        "Faltan --scs-repo-url/--scs-repo-token" if sec["scorecard_skipped"] else "")
    pub = []
    if sec["reports_published_git"]:
        pub.append("repositorio git")
    if sec["reports_sent_mail"]:
        pub.append("correo")
    add("Datos", "Reportes de vulnerabilidades distribuidos", "INFO" if pub else OK, ", ".join(pub))

    if sec.get("definitions"):
        from .pipeline_def import definition_checklist
        rows.extend(definition_checklist(sec["definitions"]))

    m = sec.get("manifest")
    if m is None:
        add("Kubernetes", "Manifiestos visibles en el log", NA, "El log no imprime manifiestos")
        return rows
    ctx_missing = [k for k, lab in (("run_as_non_root", "runAsNonRoot"), ("no_priv_escalation", "allowPrivilegeEscalation:false"),
                                    ("read_only_rootfs", "readOnlyRootFilesystem"), ("drop_all_caps", "drop ALL")) if not m[k]]
    add("Kubernetes", "securityContext endurecido", ALERT if ctx_missing else OK,
        ("Sin securityContext" if not m["security_context"] else "Falta: " + ", ".join(ctx_missing)) if ctx_missing else "")
    add("Kubernetes", "Contenedor privilegiado / acceso al host", ALERT if m["privileged"] or m["host_access"] else OK,
        ", ".join((["privileged"] if m["privileged"] else []) + m["host_access"]))
    add("Kubernetes", "Puertos de administración expuestos", ALERT if m["admin_ports"] else OK, ", ".join(m["admin_ports"]))
    add("Kubernetes", "Imagen de despliegue fijada", ALERT if m["mutable_images"] else (OK if m["images"] else NA),
        ", ".join(m["mutable_images"]) or ("imagen inyectada por el pipeline" if not m["images"] else ""))
    add("Kubernetes", "Límites de recursos", OK if m["resource_limits"] else ALERT)
    add("Kubernetes", "Liveness/readiness probes", OK if m["probes"] else ALERT)
    add("Kubernetes", "Credenciales en ConfigMap", ALERT if m["configmap_cleartext_secrets"] else OK,
        ", ".join(m["configmap_cleartext_secrets"]) or "%d referencia(s) ${VAR}; %d secretRef" % (m["configmap_secret_placeholders"], m["secret_refs"]))
    risky = m["actuator_risky"] + (["shutdown habilitado"] if m["actuator_shutdown"] else []) + (["show-details=always"] if m["actuator_show_details_always"] else [])
    add("Kubernetes", "Endpoints de Actuator expuestos", ALERT if risky else OK,
        ", ".join(risky) or ("include=%s" % m["actuator_exposure"] if m["actuator_exposure"] else ""))
    dbg = m["debug_logging"] + (["spring.jpa.show-sql=true"] if m["show_sql"] else [])
    add("Kubernetes", "Logging DEBUG/TRACE o SQL en producción", ALERT if dbg else OK, ", ".join(dbg[:3]))
    return rows
