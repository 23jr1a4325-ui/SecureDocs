@echo off
cd /d "%~dp0"
py -3.12 -m venv .venv
if errorlevel 1 goto error
".venv\Scripts\python.exe" -m pip install --upgrade pip
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 goto error
echo Setup complete. Set a SECRET_KEY and bootstrap admin password before running.
pause
exit /b 0
:error
echo Setup failed. Install Python 3.12 and ensure internet access, then retry.
pause
exit /b 1
