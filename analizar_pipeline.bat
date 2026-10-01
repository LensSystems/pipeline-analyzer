@echo off
REM Windows: doble clic o "analizar_pipeline.bat [rutas...]" desde cmd/PowerShell.
REM Busca Python 3.8+ con el lanzador "py", luego "python" y "python3".
setlocal
cd /d "%~dp0"
set "PY="
set "CHECK=import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)"
py -3 -c "%CHECK%" >nul 2>nul && set "PY=py -3"
if not defined PY python -c "%CHECK%" >nul 2>nul && set "PY=python"
if not defined PY python3 -c "%CHECK%" >nul 2>nul && set "PY=python3"
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
pause
