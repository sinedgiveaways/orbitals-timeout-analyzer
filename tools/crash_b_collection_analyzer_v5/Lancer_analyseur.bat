@echo off
setlocal
cd /d "%~dp0"
set "PY=..\..\setup\python\python.exe"
if not exist "%PY%" (
  echo Python integre introuvable.
  echo Place ce dossier dans orbitals-recomp\tools\crash_b_collection_analyzer_v5
  pause
  exit /b 1
)
"%PY%" -c "import capstone; print('Capstone OK:', capstone.__version__)"
if errorlevel 1 (pause & exit /b 2)
"%PY%" orbitals_crash_b_collection_analyzer_v5.py
if errorlevel 1 pause
