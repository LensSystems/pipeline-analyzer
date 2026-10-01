"""Revisión de la definición del pipeline (sin dependencias: análisis por texto).

Soporta Azure DevOps (``azure-pipelines*.yml``, incluido ``azure-pipelines-expanded.yaml`` de la
descarga de logs), GitHub Actions (``.github/workflows/*.yml``), GitLab CI (``.gitlab-ci.yml``) y
Jenkins (``Jenkinsfile``). Detecta configuraciones que debilitan los controles de seguridad.
"""

import re
from typing import Any, Dict, List, Tuple

from .security import INSECURE_TLS_RE, PIPE_SHELL_RE, find_secrets

SECURITY_STEP_RE = re.compile(
    r"(?i)breaker|scan|sonar|cxone|checkmarx|tmas|trivy|snyk|grype|dependency.?check|gitleaks|semgrep|"
    r"checkstyle|pmd|spotbugs|security|sast|sca|quality.?gate|test")


def _flavor(name: str, text: str) -> str:
    n = name.lower()
    if n.endswith("jenkinsfile") or n.endswith(".groovy") or re.search(r"^\s*pipeline\s*\{", text, re.M):
        return "jenkins"
    if "gitlab-ci" in n or re.search(r"^\s*(?:stages|before_script|include):", text, re.M) and "jobs:" not in text:
        return "gitlab"
    if ".github" in n or re.search(r"^\s*(?:on|jobs):", text, re.M) and re.search(r"runs-on:", text):
        return "github"
    return "azure"


def _indent(l: str) -> int:
    return len(l) - len(l.lstrip())


_NAME_KEYS = ("displayName", "name", "task", "job", "stage", "uses", "script", "bash", "run")


def _owner(lines: List[str], idx: int) -> str:
    """Nombre del paso/job al que pertenece la línea ``idx`` (displayName/name puede estar antes o después)."""
    indent = _indent(lines[idx])
    start = None
    for j in range(idx, max(-1, idx - 80), -1):
        l = lines[j]
        if not l.strip():
            continue
        if l.lstrip().startswith("- ") and _indent(l) < indent + (2 if j == idx else 0) or j < idx and _indent(l) < indent - 2:
            start = j
            break
        if j < idx and re.match(r"^[A-Za-z0-9_.-][^:#]*:\s*$", l):  # job de GitLab en la raíz
            return l.split(":")[0]
    if start is None:
        return "?"
    base = _indent(lines[start])
    found: Dict[str, str] = {}
    for k in range(start, min(len(lines), start + 80)):
        l = lines[k]
        if k > start and l.strip() and _indent(l) <= base and not (lines[start].lstrip().startswith("- ") and _indent(l) > base):
            break
        m = re.match(r"^\s*-?\s*(%s)\s*:\s*['\"]?(.+?)['\"]?\s*$" % "|".join(_NAME_KEYS), l)
        if m:
            found.setdefault(m.group(1), m.group(2))
    for key in _NAME_KEYS:
        if key in found:
            return found[key][:80]
    return lines[start].strip()[:80]


def check_definition(name: str, text: str) -> Dict[str, Any]:
    flavor = _flavor(name, text)
    lines = text.splitlines()
    out: Dict[str, Any] = {"file": name, "flavor": flavor}

    # Fallos tolerados en pasos/jobs (los breakers no bloquean)
    tolerated = []
    rx = {"azure": r"^\s*continueOnError:\s*true", "github": r"^\s*continue-on-error:\s*true",
          "gitlab": r"^\s*allow_failure:\s*true", "jenkins": r"catchError\s*\(|unstable\s*\(|returnStatus:\s*true"}[flavor]
    for i, l in enumerate(lines):
        if re.search(rx, l):
            owner = _owner(lines, i)
            tolerated.append({"step": owner, "line": i + 1, "security": bool(SECURITY_STEP_RE.search(owner))})
    out["tolerated_failures"] = tolerated

    # Secretos en claro
    secrets = []
    for i, l in enumerate(lines):
        for kind, _value in find_secrets(l):
            secrets.append({"type": kind, "line": i + 1})
    out["secrets"] = secrets

    # Repositorios de templates por rama mutable (Azure resources.repositories / GitLab include ref)
    mutable = []
    for m in re.finditer(r"-\s*repository:\s*(\S+)((?:\n\s+\w+:.*)*)", text):
        block = m.group(2)
        ref = re.search(r"\bref:\s*(\S+)", block)
        refv = ref.group(1) if ref else "(rama por defecto)"
        if not ref or re.search(r"refs/heads/|^(?:main|master|develop)$", refv):
            mutable.append("%s → %s" % (m.group(1), refv))
    for m in re.finditer(r"project:\s*['\"]?([\w./-]+)['\"]?\s*\n\s+ref:\s*['\"]?([\w./-]+)", text):
        if not re.match(r"^v?\d+\.\d+|^[0-9a-f]{40}$", m.group(2)):
            mutable.append("%s → %s" % (m.group(1), m.group(2)))
    out["mutable_template_refs"] = mutable

    # GitHub Actions: acciones sin fijar por SHA, pull_request_target, permisos amplios
    uses = re.findall(r"^\s*-?\s*uses:\s*['\"]?([\w.-]+/[\w./-]+)@([\w.-]+)", text, re.M)
    out["unpinned_actions"] = sorted({"%s@%s" % (a, r) for a, r in uses
                                      if not re.fullmatch(r"[0-9a-f]{40}", r) and not a.startswith("./")})
    out["pull_request_target"] = bool(re.search(r"^\s*pull_request_target\s*:", text, re.M))
    out["write_all"] = bool(re.search(r"permissions:\s*write-all", text))
    out["missing_permissions"] = flavor == "github" and not re.search(r"^\s*permissions:", text, re.M)

    # Credenciales persistidas, clone superficial, debug del sistema
    out["persist_credentials"] = bool(re.search(r"persistCredentials:\s*true|persist-credentials:\s*true", text))
    out["shallow_fetch"] = bool(re.search(r"fetchDepth:\s*1\b|fetch-depth:\s*1\b|GIT_DEPTH:\s*['\"]?1\b", text))
    out["system_debug"] = bool(re.search(r"system\.debug['\"]?\s*:\s*['\"]?true|ACTIONS_STEP_DEBUG:\s*true|CI_DEBUG_TRACE:\s*['\"]?true", text, re.I))
    out["set_x"] = [i + 1 for i, l in enumerate(lines) if re.search(r"(?:^|\s|;)set -[a-wyz]*x", l)]

    # Imágenes mutables, scripts remotos y TLS deshabilitado
    images = re.findall(r"^\s*-?\s*(?:image|container|vmImage):\s*['\"]?([\w./:@${}-]+)", text, re.M)
    out["latest_images"] = sorted({i for i in images if i.endswith(":latest") or
                                   (":" not in i.split("/")[-1] and "@sha256" not in i and "$" not in i and "/" in i)})
    out["pipe_to_shell"] = [i + 1 for i, l in enumerate(lines) if PIPE_SHELL_RE.search(l)]
    out["tls_disabled"] = [i + 1 for i, l in enumerate(lines) if INSECURE_TLS_RE.search(l)]
    return out


def check_definitions(defs: List[Tuple[str, str]]) -> List[Dict[str, Any]]:
    return [check_definition(name, text) for name, text in defs]


def definition_checklist(results: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    OK, ALERT = "OK", "ALERTA"
    rows: List[Dict[str, str]] = []
    for r in results:
        area = "Definición (%s)" % r["file"].rsplit("/", 1)[-1]

        def add(check, bad, detail="", _area=area):
            rows.append({"area": _area, "check": check, "status": ALERT if bad else OK, "detail": detail if bad else ""})

        sec_tol = [t for t in r["tolerated_failures"] if t["security"]]
        add("Controles de seguridad que no bloquean (continueOnError/allow_failure)", sec_tol,
            ", ".join("%s (l.%d)" % (t["step"], t["line"]) for t in sec_tol[:5]))
        add("Secretos en claro en la definición", r["secrets"],
            ", ".join("%s (l.%d)" % (s["type"], s["line"]) for s in r["secrets"][:5]))
        add("Templates referenciados por tag/commit", r["mutable_template_refs"], ", ".join(r["mutable_template_refs"][:4]))
        add("Credenciales del checkout no persistidas", r["persist_credentials"], "persistCredentials: true")
        add("Debug del sistema deshabilitado", r["system_debug"], "system.debug / CI_DEBUG_TRACE activo")
        add("Sin 'set -x' en scripts", r["set_x"], "líneas " + ", ".join(map(str, r["set_x"][:5])))
        add("Imágenes fijadas por versión o digest", r["latest_images"], ", ".join(r["latest_images"][:4]))
        add("Sin scripts remotos curl|bash", r["pipe_to_shell"], "líneas " + ", ".join(map(str, r["pipe_to_shell"][:5])))
        add("Verificación TLS habilitada", r["tls_disabled"], "líneas " + ", ".join(map(str, r["tls_disabled"][:5])))
        if r["flavor"] == "github":
            add("Acciones fijadas por SHA", r["unpinned_actions"], ", ".join(r["unpinned_actions"][:4]))
            add("Sin pull_request_target", r["pull_request_target"], "pull_request_target ejecuta código del PR con secretos")
            add("Permisos del GITHUB_TOKEN acotados", r["write_all"] or r["missing_permissions"],
                "write-all" if r["write_all"] else "sin bloque permissions")
    return rows
