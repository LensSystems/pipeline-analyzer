@echo off
REM Windows: unico archivo de arranque. Doble clic o "analizar_pipeline.bat [rutas...]" desde cmd/PowerShell.
REM Elige el mejor Python: 1) 3.8+ con ventanas (tkinter)  2) cualquiera 3.8+ (preguntas en consola).
REM Luego analizar_pipeline.py elige el modo: ventanas sin consola, ventanas, o consola.
setlocal
cd /d "%~dp0"
set "PY="
set "PYTK="
set "VER=import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)"
set "TK=from pipeline_analyzer import compat; import sys; sys.exit(0 if compat.tk_status()[0] else 1)"
for %%C in ("py -3" "python" "python3") do (
  if not defined PYTK (
    %%~C -c "%VER%" >nul 2>nul && (
      if not defined PY set "PY=%%~C"
      %%~C -c "%TK%" >nul 2>nul && set "PYTK=%%~C"
    )
  )
)
if defined PYTK set "PY=%PYTK%"
if not defined PY (
  echo No se encontro Python 3.8 o superior.
  echo Instalalo desde https://www.python.org/downloads/windows/ marcando "Add python.exe to PATH"
  echo o con:  winget install Python.Python.3.12
  pause
  exit /b 1
)
chcp 65001 >nul
set "PYTHONIOENCODING=utf-8"
%PY% analizar_pipeline.py %*
set "RC=%errorlevel%"
REM Con rutas o en modo consola se deja la ventana abierta para leer el resultado; en modo ventanas no hace falta.
if not "%~1"=="" pause
if "%~1"=="" if not defined PYTK pause
exit /b %RC%
