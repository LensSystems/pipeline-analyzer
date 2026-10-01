#!/usr/bin/env bash
# Linux (y macOS desde terminal): ./analizar_pipeline.sh [rutas...]
# Elige el mejor Python: 1) con ventanas (tkinter)  2) cualquiera >= 3.8 (preguntas en consola).
cd "$(dirname "$0")" || exit 1

CANDIDATES=""
for n in python3.14 python3.13 python3.12 python3.11 python3.10 python3.9 python3.8 python3 python; do
  p=$(command -v "$n" 2>/dev/null) && CANDIDATES="$CANDIDATES $p"
done

pick() {
  for p in $CANDIDATES; do
    "$p" -c "$1" >/dev/null 2>&1 && { echo "$p"; return 0; }
  done
  return 1
}
PY=$(pick 'import sys, tkinter; assert sys.version_info >= (3, 8)') || PY=$(pick 'import sys; assert sys.version_info >= (3, 8)')

if [ -z "$PY" ]; then
  echo "No se encontró Python 3.8 o superior. Instálalo, por ejemplo:"
  echo "  Debian/Ubuntu: sudo apt install python3 python3-tk"
  echo "  Fedora/RHEL:   sudo dnf install python3 python3-tkinter"
  echo "  Arch:          sudo pacman -S python tk"
  exit 1
fi
exec "$PY" analizar_pipeline.py "$@"
