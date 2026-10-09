"""Inventario de lo que se revisó al compartir una carpeta o un .zip: cada archivo, cómo se trató y por qué.

Así el reporte deja claro qué se leyó (logs, definiciones de pipeline, reportes de herramientas) y qué se ignoró.
"""

import zipfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .logparser import _kind

MAX_ENTRIES = 5000
_KIND_LABEL = {"log": "log analizado", "aux": "log auxiliar del agente", "def": "definición del pipeline"}
_IGNORED_HINT = {
    ".png": "imagen", ".jpg": "imagen", ".jpeg": "imagen", ".gif": "imagen", ".svg": "imagen",
    ".jar": "binario", ".class": "binario", ".war": "binario", ".exe": "binario", ".gz": "comprimido", ".tgz": "comprimido",
    ".csv": "datos tabulares (no soportado)", ".html": "HTML (no soportado)", ".java": "código fuente",
    ".properties": "configuración", ".pom": "pom (usa --pom)",
}


def _entries(path: Path) -> Iterable[str]:
    if path.is_dir():
        for i, f in enumerate(path.rglob("*")):
            if i > MAX_ENTRIES:
                return
            if f.is_file():
                yield f.relative_to(path).as_posix()
    elif path.suffix.lower() == ".zip":
        try:
            with zipfile.ZipFile(str(path)) as zf:
                for i, n in enumerate(zf.namelist()):
                    if i > MAX_ENTRIES:
                        return
                    if not n.endswith("/"):
                        yield n
        except (zipfile.BadZipFile, OSError):
            return
    else:
        yield path.name


def build(paths: Iterable[Path], report_audit: List[Dict[str, str]],
          yaml_selection: Optional[Dict[str, bool]] = None) -> Dict[str, Any]:
    """``{"files": [{"origin", "file", "status"}], "counts": {...}}`` de todo lo compartido."""
    audit = {Path(a["file"].rsplit("!", 1)[-1]).name: a["status"] for a in report_audit}
    files: List[Dict[str, str]] = []
    for p in map(Path, paths):
        for rel in _entries(p):
            if _kind(rel) == "def" and yaml_selection is not None and not yaml_selection.get(str(p), True):
                continue
            name = rel.rsplit("/", 1)[-1]
            ext = Path(name).suffix.lower()
            kind = _kind(rel)
            if kind:
                status = _KIND_LABEL[kind]
            elif name in audit:
                status = audit[name]
            elif ext in (".xml", ".json", ".pdf", ".md"):
                status = "reporte de herramienta: no revisado"
            else:
                status = "ignorado: " + _IGNORED_HINT.get(ext, "tipo de archivo no soportado")
            files.append({"origin": p.name, "file": rel, "status": status})
    counts = {"total": len(files),
              "logs": sum(1 for f in files if f["status"] in ("log analizado", "log auxiliar del agente")),
              "definiciones": sum(1 for f in files if f["status"] == "definición del pipeline"),
              "reportes": sum(1 for f in files if f["status"].startswith("leído")),
              "ignorados": sum(1 for f in files if not (f["status"] in _KIND_LABEL.values() or f["status"].startswith("leído")))}
    return {"files": files, "counts": counts}
