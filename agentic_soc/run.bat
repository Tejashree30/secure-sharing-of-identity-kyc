@echo off
REM One-click start for Windows
cd /d "%~dp0"
if not exist venv python -m venv venv
call venv\Scripts\activate
pip install -q -r requirements.txt
python server.py
pause
