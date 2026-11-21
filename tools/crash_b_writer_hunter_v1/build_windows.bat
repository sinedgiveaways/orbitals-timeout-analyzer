@echo off
setlocal
cd /d "%~dp0"
set "PY=%~dp0..\..\setup\python\python.exe"
if not exist "%PY%" (
 echo Python integre introuvable. Verifie que le dossier est dans orbitals-recomp\tools\crash_b_writer_hunter_v1
 pause
 exit /b 1
)
"%PY%" "%~dp0orbitals_crash_b_writer_hunter.py"
if errorlevel 1 pause
