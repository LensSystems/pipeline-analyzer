"""Parser de logs de CI/CD con soporte para varios proveedores.

Dialectos (se detectan solos por el contenido):
- azure:   ``##[section]Starting: <paso>`` / ``##[section]Finishing: <paso>``
- github:  ``##[group]Run <comando>`` (GitHub Actions)
- gitlab:  ``section_start:<epoch>:<id>`` / ``section_end:<epoch>:<id>``
- jenkins: ``[Pipeline] { (<stage>)`` / ``[Pipeline] // stage``
- generic: ``::group::<nombre>``, ``=== <nombre> ===``, ``Step 3/9 : ...`` o, si no hay marcas,
           el archivo completo es un paso.

Timestamps reconocidos al inicio de línea: ISO 8601 con o sin ``T``/fracción/zona, entre corchetes
(Jenkins timestamper) y con el indicador de stream de GitLab (``00O``).

Entradas (una ejecución cada una): log único, carpeta de descarga (``logs_<id>/`` de Azure DevOps,
zip de GitHub Actions, carpeta con varios logs de un mismo pipeline) o su ``.zip``.
En las carpetas:
- Los archivos por paso y los logs combinados del job se fusionan sin duplicar pasos.
- Si hay varios intentos (re-runs) se separan por tiempo; por defecto se usa el más reciente.
- ``*.yml``/``*.yaml``/``Jenkinsfile`` se guardan como definición del pipeline.
- ``Agent Diagnostic Logs/`` y similares se guardan aparte (solo para la revisión de secretos).
"""

import re
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Dict, Iterator, List, Optional, Pattern, Tuple

TS_RE = re.compile(
    r"^﻿?\[?(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:[.,](\d+))?\s?(?:Z|UTC|[+-]\d{2}:?\d{2})?\]?"
    r"(?:\s\d{2}[OE]\+?)?\s?")
# Secuencias ANSI (colores y borrado de línea), con o sin el caracter ESC.
ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]|\[(?:\d{1,2};)*\d{1,2}m")
STEP_FILE_RE = re.compile(r"^(\d+)_(.+)\.(?:txt|log)$", re.I)
BUILD_DIR_RE = re.compile(r"logs?_(\d+)", re.I)

LOG_EXT = (".txt", ".log", ".out")
DEF_NAMES = re.compile(r"(?i)(\.ya?ml$|^jenkinsfile$|\.jenkinsfile$|\.groovy$)")
AUX_DIR = re.compile(r"(?i)diagnostic|^_diag|agent[-_ ]?logs")

ATTEMPT_GAP = timedelta(minutes=2)  # pausa mayor entre archivos = otro intento (re-run)

START = "##[section]Starting: "
FINISH = "##[section]Finishing: "


# ====================================================================== modelo


@dataclass
class Line:
    no: int
    ts: Optional[datetime]
    text: str
    src: Optional[str] = None
    src_no: Optional[int] = None

    @property
    def where(self) -> str:
        """Ubicación legible: ``archivo.txt:123`` para descargas multi-archivo, ``línea 123`` si no."""
        if self.src:
            return "%s:%d" % (self.src, self.src_no)
        return "línea %d" % self.no


@dataclass
class Step:
    name: str
    index: int
    start: Optional[datetime]
    end: Optional[datetime] = None
    lines: List[Line] = field(default_factory=list)
    error_re: Optional[Pattern] = None
    sid: Optional[str] = None  # id interno del dialecto (p. ej. id de sección de GitLab)

    @property
    def errors(self) -> List[str]:
        rx = self.error_re or DIALECTS["azure"].error_re
        return [re.sub(r"^##\[error\]", "", l.text).strip() for l in self.lines if rx.search(l.text)]

    @property
    def failed(self) -> bool:
        return bool(self.errors)

    @property
    def duration(self) -> Optional[float]:
        if self.start and self.end:
            return (self.end - self.start).total_seconds()
        return None

    @property
    def first_line(self) -> Optional[int]:
        return self.lines[0].no if self.lines else None

    def text(self) -> str:
        return "\n".join(l.text for l in self.lines)

    def search(self, pattern: str, flags: int = re.M) -> Optional["re.Match[str]"]:
        return re.search(pattern, self.text(), flags)

    def find_line(self, needle: str) -> Optional[Line]:
        for l in self.lines:
            if needle in l.text:
                return l
        return None


@dataclass
class PipelineLog:
    path: Path
    job: Optional[str]
    steps: List[Step]
    lines: List[Line]
    sources: List[str] = field(default_factory=list)
    provider: str = "generic"
    aux_lines: List[Line] = field(default_factory=list)          # logs de diagnóstico del agente
    definitions: List[Tuple[str, str]] = field(default_factory=list)  # (archivo, contenido) de YAML/Jenkinsfile
    attempt: int = 1
    attempts: int = 1

    @property
    def start(self) -> Optional[datetime]:
        return next((l.ts for l in self.lines if l.ts), None)

    @property
    def end(self) -> Optional[datetime]:
        return next((l.ts for l in reversed(self.lines) if l.ts), None)

    def full_text(self) -> str:
        return "\n".join(l.text for l in self.lines)

    def steps_named(self, prefix: str) -> Iterator[Step]:
        p = prefix.lower()
        return (s for s in self.steps if s.name.lower().startswith(p))

    def step(self, prefix: str) -> Optional[Step]:
        """Primer paso cuyo nombre empieza con ``prefix`` (sin distinguir mayúsculas)."""
        return next(self.steps_named(prefix), None)

    def find_step(self, names=(), content: Optional[str] = None) -> Optional[Step]:
        """Paso por nombre y/o contenido, independiente del proveedor.

        1. Primer paso cuyo nombre empiece con alguno de ``names`` y cuyo texto coincida con ``content``.
        2. Si no hay, el primer paso (con cualquier nombre) cuyo texto coincida con ``content``.
        3. Si no hay ``content`` o nada coincide, el primer paso por nombre.
        """
        rx = re.compile(content, re.M) if content else None
        by_name = [s for s in self.steps if any(s.name.lower().startswith(n.lower()) for n in names)]
        if rx:
            for s in by_name:
                if rx.search(s.text()):
                    return s
            for s in self.steps:
                if rx.search(s.text()):
                    return s
        return by_name[0] if by_name else None

    def locate(self, no: Optional[int]) -> Optional[str]:
        """Convierte un número de línea global en ``archivo:línea`` (o ``línea N``)."""
        if not no or no > len(self.lines):
            return None
        return self.lines[no - 1].where


# ====================================================================== dialectos


@dataclass
class Dialect:
    name: str
    start: Callable[[str], Optional[Tuple[str, Optional[str]]]]  # -> (nombre, sid)
    end: Callable[[str, "Step"], bool]
    error_re: Pattern
    container: bool = False  # Azure: el primer Starting que contiene a otros es el job


def _azure_start(t):
    return (t[len(START):].strip(), None) if t.startswith(START) else None


def _azure_end(t, cur):
    return t.startswith(FINISH) and t[len(FINISH):].strip() == cur.name


_GH_START = re.compile(r"^##\[group\]Run (.+)$|^(Post job cleanup\.)$|^(Complete job)$")


def _github_start(t):
    m = _GH_START.match(t)
    if not m:
        return None
    return (("Run " + m.group(1)) if m.group(1) else (m.group(2) or m.group(3)).rstrip("."), None)


_GL_START = re.compile(r"section_start:(\d+):([^\[\s\r]+)(?:\[[^\]]*\])?\r?(.*)$")
_GL_END = re.compile(r"section_end:\d+:([^\s\r]+)")


def _gitlab_start(t):
    m = _GL_START.search(t)
    if not m:
        return None
    header = m.group(3).split("\r")[-1].strip()
    return (header or m.group(2), m.group(2))


def _gitlab_end(t, cur):
    m = _GL_END.search(t)
    return bool(m) and m.group(1) == (cur.sid or cur.name)


_JK_START = re.compile(r"^\[Pipeline\] \{ \((.+)\)\s*$")


def _jenkins_start(t):
    m = _JK_START.match(t)
    return (m.group(1), None) if m else None


def _jenkins_end(t, cur):
    return bool(re.match(r"^\[Pipeline\] // (?:stage|parallel)\b", t))


_GEN_START = re.compile(r"^::group::(.+)$|^={3,}\s*([^=].*?)\s*={3,}\s*$|^Step (\d+/\d+ : .+)$|^>{3,}\s*(.+)$")


def _generic_start(t):
    m = _GEN_START.match(t)
    if not m:
        return None
    return (next(g for g in m.groups() if g).strip(), None)


def _generic_end(t, cur):
    return t.startswith("::endgroup::")


DIALECTS: Dict[str, Dialect] = {
    "azure": Dialect("azure", _azure_start, _azure_end, re.compile(r"^##\[error\]"), container=True),
    "github": Dialect("github", _github_start, lambda t, c: False, re.compile(r"^##\[error\]")),
    "gitlab": Dialect("gitlab", _gitlab_start, _gitlab_end, re.compile(r"^ERROR: ")),
    "jenkins": Dialect("jenkins", _jenkins_start, _jenkins_end,
                       re.compile(r"^ERROR: |script returned exit code [1-9]|^Finished: (?:FAILURE|UNSTABLE)")),
    "generic": Dialect("generic", _generic_start, _generic_end,
                       re.compile(r"^##\[error\]|^ERROR: |^Error: |^FATAL[: ]|(?:returned|exited with) (?:exit )?code [1-9]")),
}

PROVIDER_LABEL = {"azure": "Azure DevOps", "github": "GitHub Actions", "gitlab": "GitLab CI",
                  "jenkins": "Jenkins", "generic": "Genérico"}


def detect_provider(text: str) -> str:
    if "##[section]Starting:" in text or "##vso[" in text:
        return "azure"
    if re.search(r"section_start:\d+:", text) or "Running with gitlab-runner" in text:
        return "gitlab"
    if "[Pipeline] " in text or re.search(r"^(?:Started by |Finished: (?:SUCCESS|FAILURE|UNSTABLE|ABORTED))", text, re.M):
        return "jenkins"
    if "##[group]" in text or "Current runner version" in text:
        return "github"
    if "##[error]" in text:
        return "azure"
    return "generic"


# ====================================================================== parseo de un archivo


def _read(path) -> str:
    """Lee sin traducir saltos de línea: read_text() convierte cada \\r en \\n."""
    with open(path, encoding="utf-8", errors="replace", newline="") as fh:
        return fh.read()


def _split(content: str) -> List[str]:
    """Divide solo por saltos de línea reales (\\n); str.splitlines() también corta en \\r y rompe GitLab."""
    lines = content.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return lines


def _parse_ts(m: "re.Match[str]") -> datetime:
    base = datetime.strptime("%s %s" % (m.group(1), m.group(2)), "%Y-%m-%d %H:%M:%S")
    frac = (m.group(3) or "0")[:6].ljust(6, "0")
    return base.replace(microsecond=int(frac))


def _clean(raw: List[str]) -> List[Tuple[Optional[datetime], str]]:
    out = []
    for rawline in raw:
        ts = None
        m = TS_RE.match(rawline)
        text = rawline
        if m and m.end() > 0:
            ts = _parse_ts(m)
            text = rawline[m.end():]
        text = ANSI_RE.sub("", text).rstrip()
        if "\r" in text and "section_" not in text:
            # Como una terminal: el retorno de carro sobrescribe la línea; queda el último segmento visible.
            segs = [x for x in text.split("\r") if x.strip()]
            text = segs[-1] if segs else ""
        out.append((ts, text))
    return out


def _parse_raw(raw: List[str], src: Optional[str] = None, provider: Optional[str] = None
               ) -> Tuple[List[Line], List[Step], Optional[str], str]:
    cleaned = _clean(raw)
    provider = provider or detect_provider("\n".join(t for _, t in cleaned[:4000]))
    d = DIALECTS[provider]
    lines: List[Line] = []
    steps: List[Step] = []
    job: Optional[str] = None
    current: Optional[Step] = None

    for no, (ts, text) in enumerate(cleaned, 1):
        line = Line(no, ts, text, src, no if src else None)
        lines.append(line)

        if current is not None and d.end(text, current):
            current.end = ts or current.end
            current = None
            if provider != "gitlab":  # en GitLab el fin y el inicio pueden venir en la misma línea
                continue
        started = d.start(text)
        if started:
            name, sid = started
            if provider == "gitlab" and not ts:
                m = _GL_START.search(text)
                ts = datetime.fromtimestamp(int(m.group(1)), timezone.utc).replace(tzinfo=None)
            if d.container and current is not None and job is None and not current.lines:
                job = current.name  # un "Starting" que contiene a otros es el job completo
                steps.pop()
            elif current is not None:
                current.end = ts
            current = Step(name, len(steps), ts, error_re=d.error_re, sid=sid)
            steps.append(current)
            if provider in ("azure",):
                continue
        if provider == "azure" and text.startswith(FINISH):
            continue
        if current is not None:
            current.lines.append(line)
            if ts:
                current.end = current.end if provider == "azure" else ts

    return lines, steps, job, provider


def _synth_step(rel: str, lines: List[Line], provider: str) -> Step:
    """Paso que abarca todo el archivo (para archivos por paso sin marcas, o logs genéricos)."""
    fname = rel.rsplit("/", 1)[-1]
    m = STEP_FILE_RE.match(fname)
    name = m.group(2) if m else fname.rsplit(".", 1)[0]
    ts = [l.ts for l in lines if l.ts]
    return Step(name, 0, ts[0] if ts else None, ts[-1] if ts else None, list(lines), DIALECTS[provider].error_re)


def parse_log(path, provider: Optional[str] = None) -> PipelineLog:
    path = Path(path)
    raw = _split(_read(path))
    lines, steps, job, provider = _parse_raw(raw, None, provider)
    if not steps and lines:
        steps = [_synth_step(path.name, lines, provider)]
    return PipelineLog(path, job, steps, lines, [path.name], provider)


# ====================================================================== descargas multi-archivo


def _natural_key(rel: str):
    return [int(t) if t.isdigit() else t.lower() for t in re.split(r"(\d+)", rel)]


def _kind(rel: str) -> Optional[str]:
    name = rel.rsplit("/", 1)[-1]
    parts = rel.split("/")[:-1]
    if DEF_NAMES.search(name):
        return "def"
    if not name.lower().endswith(LOG_EXT):
        return None
    if any(AUX_DIR.search(p) for p in parts) or re.match(r"(?i)^(?:(?:agent|worker)_\d|initializelog)", name):
        return "aux"
    return "log"


def discover(path) -> List[Tuple[str, Callable[[], str], str]]:
    """Archivos de una ejecución: [(ruta relativa, lector, tipo)] con tipo log | aux | def."""
    path = Path(path)
    members: List[Tuple[str, Callable[[], str], str]] = []
    if path.is_dir():
        for f in path.rglob("*"):
            if f.is_file():
                rel = f.relative_to(path).as_posix()
                kind = _kind(rel)
                if kind:
                    members.append((rel, lambda f=f: _read(f), kind))
    elif path.suffix.lower() == ".zip":
        zf = zipfile.ZipFile(path)
        for name in zf.namelist():
            kind = None if name.endswith("/") else _kind(name)
            if kind:
                members.append((name, lambda n=name: zf.read(n).decode("utf-8", errors="replace"), kind))
    else:
        members.append((path.name, lambda: _read(path), "log"))
    members.sort(key=lambda m: _natural_key(m[0]))
    return members


def is_multi_file(path) -> bool:
    path = Path(path)
    return path.is_dir() or path.suffix.lower() == ".zip"


def _norm(name: str) -> str:
    n = re.sub(r"[^a-z0-9]", "", name.lower())
    return re.sub(r"^(?:prejob|postjob)", "", n)


def _same_step(a: Step, b: Step) -> bool:
    """Mismo paso visto en dos archivos (combinado vs. por paso), tolerando nombres truncados o saneados."""
    if a.start and b.start and abs((a.start - b.start).total_seconds()) > 3:
        return False
    if (a.start is None) != (b.start is None):
        return False
    na, nb = _norm(a.name), _norm(b.name)
    return na == nb or (len(na) >= 6 and len(nb) >= 6 and (na.startswith(nb) or nb.startswith(na)))


@dataclass
class _File:
    rel: str
    lines: List[Line]
    steps: List[Step]
    job: Optional[str]

    @property
    def span(self) -> Tuple[Optional[datetime], Optional[datetime]]:
        ts = [l.ts for l in self.lines if l.ts]
        return (ts[0], ts[-1]) if ts else (None, None)


def _cluster_attempts(files: List[_File]) -> List[List[_File]]:
    """Agrupa archivos por intentos: los rangos de tiempo que se traslapan son del mismo intento."""
    timed = sorted((f for f in files if f.span[0]), key=lambda f: f.span[0])
    clusters: List[List[_File]] = []
    end = None
    for f in timed:
        s, e = f.span
        if clusters and end and s <= end + ATTEMPT_GAP:
            clusters[-1].append(f)
            end = max(end, e)
        else:
            clusters.append([f])
            end = e
    untimed = [f for f in files if not f.span[0]]
    if not clusters:
        return [untimed] if untimed else []
    clusters[-1].extend(untimed)
    return clusters


def _merge(path: Path, files: List[_File], provider: str) -> PipelineLog:
    # Primero los archivos por paso (ubicaciones más precisas); luego los combinados aportan solo pasos faltantes.
    ordered = sorted(files, key=lambda f: (len(f.steps) > 1, -len(f.steps), _natural_key(f.rel)))
    chunks: List[Tuple[List[Line], List[Step], str]] = []
    seen: List[Step] = []
    job = None
    for f in ordered:
        job = job or f.job
        if len(f.steps) <= 1:
            # Archivo por paso: solo se descarta si es una copia exacta de otro.
            new = [s for s in f.steps if not any(s.name == t.name and s.start == t.start and len(s.lines) == len(t.lines)
                                                 for t in seen)]
        else:
            # Log combinado: cada paso se empareja 1 a 1 con el paso ya visto más cercano en tiempo.
            available = list(seen)
            new = []
            for s in f.steps:
                cands = [t for t in available if _same_step(s, t)]
                if cands:
                    best = min(cands, key=lambda t: abs((s.start - t.start).total_seconds()) if s.start and t.start else 0)
                    available.remove(best)
                else:
                    new.append(s)
        if f.steps and not new:
            continue
        if len(new) == len(f.steps):
            chunks.append((f.lines, f.steps, f.rel))
        else:
            chunks.append(([l for s in new for l in s.lines], new, f.rel))
        seen.extend(new)
    chunks.sort(key=lambda c: (next((l.ts for l in c[0] if l.ts), datetime.max), _natural_key(c[2])))

    all_lines: List[Line] = []
    all_steps: List[Step] = []
    for lines, steps, rel in chunks:
        all_lines.extend(lines)
        all_steps.extend(steps)
        if not job and "/" in rel:
            job = rel.split("/")[0]
    for i, l in enumerate(all_lines, 1):
        l.no = i  # numeración global; Line.where conserva archivo y línea original
    for i, s in enumerate(all_steps):
        s.index = i
    return PipelineLog(path, job or path.stem, all_steps, all_lines, [c[2] for c in chunks], provider)


def parse_attempts(path, on_file: Optional[Callable[[str], None]] = None) -> List[PipelineLog]:
    """Todas las ejecuciones (intentos) contenidas en ``path``, de la más antigua a la más reciente."""
    path = Path(path)
    if not is_multi_file(path):
        if on_file:
            on_file(path.name)
        return [parse_log(path)]

    members = discover(path)
    raw: Dict[str, List[str]] = {}
    defs: List[Tuple[str, str]] = []
    aux: List[Tuple[str, List[str]]] = []
    for rel, reader, kind in members:
        if on_file:
            on_file(rel)
        content = reader()
        if kind == "def":
            defs.append((rel, content))
        elif kind == "aux":
            aux.append((rel, _split(content)))
        else:
            raw[rel] = _split(content)

    # Un solo dialecto para toda la descarga (los archivos por paso sin marcas no se detectan solos).
    sample = "\n".join("\n".join(v[:300]) for v in raw.values())
    provider = detect_provider(sample)

    files: List[_File] = []
    for rel, rl in raw.items():
        lines, steps, job, _ = _parse_raw(rl, rel, provider)
        if not lines:
            continue
        if not steps:
            steps = [_synth_step(rel, lines, provider)]
        files.append(_File(rel, lines, steps, job))

    aux_lines: List[Line] = []
    for rel, rl in aux:
        aux_lines.extend(Line(i, ts, t, rel, i) for i, (ts, t) in enumerate(_clean(rl), 1))

    clusters = _cluster_attempts(files) or [[]]
    logs = []
    for i, cl in enumerate(clusters, 1):
        log = _merge(path, cl, provider)
        log.aux_lines, log.definitions = aux_lines, defs
        log.attempt, log.attempts = i, len(clusters)
        logs.append(log)
    return logs


def parse_run(path, on_file: Optional[Callable[[str], None]] = None) -> PipelineLog:
    """La ejecución más reciente de ``path`` (log único, carpeta de descarga o .zip)."""
    return parse_attempts(path, on_file)[-1]


def build_id_from_path(path) -> Optional[str]:
    m = BUILD_DIR_RE.search(Path(path).name)
    return m.group(1) if m else None
