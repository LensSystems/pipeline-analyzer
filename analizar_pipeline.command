#!/bin/bash
# macOS: doble clic en Finder (o ./analizar_pipeline.command [rutas...]).
# Elige el mejor Python: 1) con ventanas (tkinter, Tk >= 8.6)  2) cualquiera >= 3.8 (preguntas en consola).
cd "$(dirname "$0")" || exit 1

CANDIDATES="/opt/homebrew/bin/python3 /usr/local/bin/python3 /Library/Frameworks/Python.framework/Versions/Current/bin/python3"
[ -n "$(command -v python3)" ] && CANDIDATES="$CANDIDATES $(command -v python3)"
# /usr/bin/python3 sin Command Line Tools abre el instalador de Apple: solo si ya están instaladas.
xcode-select -p >/dev/null 2>&1 && CANDIDATES="$CANDIDATES /usr/bin/python3"

pick() {
  for p in $CANDIDATES; do
    [ -x "$p" ] && "$p" -c "$1" >/dev/null 2>&1 && { echo "$p"; return 0; }
  done
  return 1
}
PY=$(pick 'import sys, tkinter; assert sys.version_info >= (3, 8) and tkinter.TkVersion >= 8.6') \
  || PY=$(pick 'import sys; assert sys.version_info >= (3, 8)')

if [ -z "$PY" ]; then
  echo "No se encontró Python 3.8 o superior."
  echo "Instálalo desde https://www.python.org/downloads/macos/  o con Homebrew:  brew install python python-tk"
else
  export TK_SILENCE_DEPRECATION=1
  "$PY" analizar_pipeline.py "$@"
fi
echo; read -n 1 -s -r -p "Presiona una tecla para cerrar…"
