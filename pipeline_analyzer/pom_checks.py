"""Revisión estática del pom.xml (configuración de build, calidad y dependencias)."""

import re
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .rules import SEVERITY_RANK, Finding, make
from .security import KNOWN_VULNERABLE, is_vulnerable

# Artefactos con versión mínima recomendada: (groupId, artifactId) -> (versión mínima, motivo)
OUTDATED = {
    ("org.apache.pdfbox", "pdfbox"): ("3.0.0", "La rama 2.0.x está en mantenimiento; revisa CVEs en el reporte SCA."),
    ("com.github.librepdf", "openpdf"): ("2.0.0", "Versiones 1.3.x son antiguas; candidata a hallazgos SCA."),
    ("com.google.code.findbugs", "annotations"): ("99", "Artefacto abandonado (2012, LGPL); usa com.github.spotbugs:spotbugs-annotations."),
}

# Propiedades que el BOM de Spring Boot lee para sobrescribir versiones (no son "sin uso")
BOOT_OVERRIDE_PROPS = {
    "tomcat.version", "jackson-bom.version", "jackson-2-bom.version", "logback.version", "netty.version",
    "snakeyaml.version", "spring-framework.version", "spring-security.version", "mockito.version",
    "lombok.version", "hibernate-validator.version", "jetty.version", "undertow.version", "activemq.version",
    "postgresql.version", "h2.version", "kafka.version", "log4j2.version", "micrometer.version",
}

# Grupos cuyas versiones gestiona el BOM de Spring Boot
BOOT_MANAGED_GROUPS = (
    "org.springframework.boot", "org.springframework", "org.springframework.data", "ch.qos.logback",
    "com.fasterxml.jackson", "tools.jackson", "org.mockito", "org.projectlombok", "org.hibernate.validator",
    "jakarta.validation", "jakarta.jms", "jakarta.ws.rs", "org.glassfish",
)

BUILTIN_PROPS = ("project.", "env.", "settings.", "maven.", "java.", "user.", "os.", "basedir", "argLine")
STATIC_PLUGINS = ("spotbugs-maven-plugin", "maven-pmd-plugin", "maven-checkstyle-plugin")


def _vtuple(v: str) -> Tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", v)[:4]) or (0,)


class _Pom:
    def __init__(self, path: Path):
        # Los archivos sanitizados traen marcadores como <HOST_3> o <TERM_1> que no son XML válido.
        self.raw = re.sub(r"<([A-Z]+_\d+)>", r"\1", path.read_text(encoding="utf-8", errors="replace"))
        self.root = ET.fromstring(self.raw)
        m = re.match(r"\{(.*)\}", self.root.tag)
        self.ns = m.group(1) if m else ""

    def q(self, path: str) -> str:
        if not self.ns:
            return path
        return "/".join(p if p in (".", "..", "*") or p.startswith(".") else "{%s}%s" % (self.ns, p) for p in path.split("/"))

    def findall(self, el, path):
        return el.findall(self.q(path))

    def text(self, el, path) -> Optional[str]:
        x = el.find(self.q(path))
        return x.text.strip() if x is not None and x.text else None

    def local(self, el) -> str:
        return el.tag.split("}", 1)[-1]


def _dep(p: _Pom, el) -> Dict[str, Optional[str]]:
    return {k: p.text(el, k) for k in ("groupId", "artifactId", "version", "scope", "optional")}


def check_pom(path) -> List[Finding]:
    path = Path(path)
    p = _Pom(path)
    root = p.root
    out: List[Finding] = []

    props_el = root.find(p.q("properties"))
    props: List[Tuple[str, str]] = []
    if props_el is not None:
        props = [(p.local(c), (c.text or "").strip()) for c in props_el]
    prop_names = {k for k, _ in props}

    # Propiedades duplicadas
    for name, cnt in Counter(k for k, _ in props).items():
        if cnt > 1:
            last = [v for k, v in props if k == name][-1]
            out.append(make("POM_DUPLICATE_PROPERTY", "MEDIUM", "POM", {"prop": name, "count": cnt, "last": last}, key=name))

    # Propiedades Sonar obsoletas
    dep_sonar = [k for k in prop_names if k in ("sonar.jacoco.reportPath", "sonar.dynamicAnalysis", "sonar.jacoco.itReportPath")]
    if dep_sonar:
        out.append(make("POM_DEPRECATED_SONAR", "LOW", "POM", {"props": ", ".join(sorted(dep_sonar))}))

    # Propiedades usadas pero no definidas / propiedades de versión sin uso
    used = set(re.findall(r"\$\{([\w.\-]+)\}", p.raw))
    undefined = sorted(u for u in used if u not in prop_names and not u.startswith(BUILTIN_PROPS))
    if undefined:
        out.append(make("POM_UNDEFINED_PROPERTY", "LOW", "POM", {"props": ", ".join(undefined)}))
    unused = sorted(k for k in prop_names if k.endswith(".version") and k not in used
                    and k != "java.version" and k not in BOOT_OVERRIDE_PROPS)
    if unused:
        out.append(make("POM_UNUSED_VERSION_PROPERTY", "INFO", "POM", {"props": ", ".join(unused)}))

    # Parent Spring Boot
    boot = None
    parent = root.find(p.q("parent"))
    if parent is not None and p.text(parent, "artifactId") == "spring-boot-starter-parent":
        boot = p.text(parent, "version")
    boot_major = _vtuple(boot)[0] if boot else None

    # Plugins: todos los <plugin> en cualquier lugar
    all_plugins = list(root.iter(p.q("plugin") if p.ns else "plugin"))
    tfi = sum(1 for pl in all_plugins
              if p.text(pl, "artifactId") == "maven-surefire-plugin" and p.text(pl, "configuration/testFailureIgnore") == "true")
    if tfi:
        out.append(make("POM_TEST_FAILURE_IGNORE", "HIGH", "POM", {"count": tfi}))
    if any(p.text(pl, "configuration/skipExec") is not None for pl in all_plugins):
        out.append(make("POM_SKIPEXEC", "INFO", "POM"))
    for pl in all_plugins:
        if p.text(pl, "artifactId") == "spotbugs-maven-plugin":
            th = p.text(pl, "configuration/threshold")
            if th and th not in ("High", "Default", "Medium", "Low", "Ignore"):
                out.append(make("POM_SPOTBUGS_THRESHOLD", "LOW", "POM", {"value": th}, key=th))
                break
    for lim in root.iter(p.q("limit") if p.ns else "limit"):
        if p.text(lim, "minimum") in ("0", "0.0", "0.00"):
            out.append(make("POM_JACOCO_ZERO", "LOW", "POM"))
            break

    # Plugins de análisis estático solo dentro de perfiles
    main_plugins = {p.text(pl, "artifactId")
                    for path_ in ("build/plugins/plugin", "build/pluginManagement/plugins/plugin")
                    for pl in p.findall(root, path_)}
    profile_plugins = {p.text(pl, "artifactId")
                       for prof in p.findall(root, "profiles/profile")
                       for pl in list(prof.iter(p.q("plugin") if p.ns else "plugin"))}
    only_profile = sorted(a for a in STATIC_PLUGINS if a in profile_plugins and a not in main_plugins)
    if only_profile:
        out.append(make("POM_PLUGINS_ONLY_IN_PROFILE", "HIGH", "POM", {"plugins": ", ".join(only_profile)}))

    milestones = sorted({"%s %s" % (p.text(pl, "artifactId"), _resolve(p.text(pl, "version"), props))
                         for pl in all_plugins if re.search(r"-M\d", _resolve(p.text(pl, "version"), props) or "")})
    if milestones:
        out.append(make("POM_MILESTONE_PLUGIN", "LOW", "POM", {"plugins": ", ".join(milestones)}))

    # Dependencias directas
    deps = [_dep(p, d) for d in p.findall(root, "dependencies/dependency")]
    for d in deps:
        d["version"] = _resolve(d["version"], props)
    ga = {(d["groupId"], d["artifactId"]): d for d in deps}

    groups = {d["groupId"] or "" for d in deps}
    if any(g.startswith("com.fasterxml.jackson") for g in groups) and any(g.startswith("tools.jackson") for g in groups):
        out.append(make("POM_JACKSON_MIX", "MEDIUM", "POM"))

    by_group: Dict[str, Dict[str, str]] = defaultdict(dict)
    for d in deps:
        if d["version"] and d["groupId"] and re.match(r"^(tools\.jackson|com\.fasterxml\.jackson)\.core$", d["groupId"]):
            by_group[d["groupId"]][d["artifactId"]] = d["version"]
    for g, arts in by_group.items():
        if len(set(arts.values())) > 1:
            out.append(make("POM_VERSION_MISMATCH", "HIGH", "POM",
                            {"group": g, "versions": ", ".join("%s=%s" % kv for kv in sorted(arts.items()))}, key=g))

    if boot_major and boot_major >= 3:
        javax = sorted("%s:%s" % (d["groupId"], d["artifactId"]) for d in deps if (d["groupId"] or "").startswith("javax."))
        if javax:
            out.append(make("POM_JAVAX_WITH_JAKARTA", "MEDIUM", "POM", {"boot": boot, "deps": ", ".join(javax)}))

    lombok = ga.get(("org.projectlombok", "lombok"))
    if lombok and lombok.get("scope") != "provided" and lombok.get("optional") != "true":
        out.append(make("POM_LOMBOK_SCOPE", "LOW", "POM"))

    junit4 = [k for k in (("junit", "junit"), ("org.codehaus.sonar-plugins.java", "sonar-jacoco-listeners")) if k in ga]
    if junit4:
        out.append(make("POM_JUNIT4_LEFTOVERS", "LOW", "POM", {"deps": ", ".join("%s:%s" % k for k in junit4)}))

    if ("org.springframework.boot", "spring-boot-starter-validation") in ga:
        redundant = [k for k in (("org.hibernate.validator", "hibernate-validator"),
                                 ("jakarta.validation", "jakarta.validation-api"),
                                 ("org.glassfish", "jakarta.el")) if k in ga and ga[k].get("version")]
        if redundant:
            out.append(make("POM_REDUNDANT_VALIDATION", "MEDIUM", "POM",
                            {"deps": ", ".join("%s:%s:%s" % (k[0], k[1], ga[k]["version"]) for k in redundant)}))

    if boot:
        pinned = sorted("%s:%s:%s" % (d["groupId"], d["artifactId"], d["version"]) for d in deps
                        if d["version"] and (d["groupId"] or "").startswith(BOOT_MANAGED_GROUPS))
        if pinned:
            out.append(make("POM_BOM_OVERRIDES", "MEDIUM", "POM", {"count": len(pinned), "deps": ", ".join(pinned)}))

    for (g, a), (minv, reason) in OUTDATED.items():
        d = ga.get((g, a))
        ver = d.get("version") if d else None
        if d is None:
            for pl in all_plugins:
                if p.text(pl, "artifactId") == a and p.text(pl, "groupId") == g:
                    ver = _resolve(p.text(pl, "version"), props)
                    break
        if ver and _vtuple(ver) < _vtuple(minv):
            target = "spotbugs-annotations" if minv == "99" else minv
            out.append(make("POM_OUTDATED_DEP", "MEDIUM" if g != "org.apache.maven.plugins" else "LOW", "POM",
                            {"dep": "%s:%s" % (g, a), "version": ver, "reason": reason, "target": target}, key=a))

    # ---------------- seguridad
    repo_urls = [p.text(r, "url") for path_ in ("repositories/repository", "pluginRepositories/pluginRepository",
                                                "profiles/profile/repositories/repository")
                 for r in p.findall(root, path_)]
    repo_urls = [u for u in repo_urls if u]
    http_repos = [u for u in repo_urls if u.lower().startswith("http://")]
    if http_repos:
        out.append(make("POM_HTTP_REPO", "HIGH", "Seguridad (POM)", {"urls": ", ".join(http_repos)}))
    if repo_urls:
        out.append(make("POM_REPOS_IN_POM", "LOW", "Seguridad (POM)", {"count": len(repo_urls)}))
    for d in deps:
        kv = KNOWN_VULNERABLE.get(d["artifactId"] or "")
        if kv and d["version"] and "${" not in d["version"] and is_vulnerable(d["version"], kv[0]):
            out.append(make("POM_KNOWN_CVE", "HIGH", "Seguridad (POM)",
                            {"dep": "%s:%s" % (d["groupId"], d["artifactId"]), "version": d["version"], "cve": kv[1],
                             "desc": kv[2], "fixed": ", ".join(kv[0])}, key=d["artifactId"]))

    out.sort(key=lambda f: (SEVERITY_RANK[f.severity], f.id))
    return out


def _resolve(value: Optional[str], props: List[Tuple[str, str]]) -> Optional[str]:
    if not value:
        return value
    d = dict(props)
    return re.sub(r"\$\{([\w.\-]+)\}", lambda m: d.get(m.group(1), m.group(0)), value)
