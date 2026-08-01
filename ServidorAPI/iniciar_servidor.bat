@echo off
REM Lanzador del servidor mock de Banco Alien (Windows)
cd /d "%~dp0"
python run_server.py
echo.
pause
