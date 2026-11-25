@echo off
cd /d "%~dp0"
echo Starting the password generator... a browser window will open in a moment.
start "PwGen Server" python app.py
timeout /t 2 >nul
start "" http://127.0.0.1:5000
echo.
echo Leave the "PwGen Server" window open during your demo. Close it when done.
pause
