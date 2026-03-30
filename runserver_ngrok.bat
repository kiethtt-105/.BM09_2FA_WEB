@echo off
cd /d E:\.BM09_2FA_WEB

echo === Activate venv ===
call venv\Scripts\activate

echo === Start Django Server ===
start cmd /k "cd /d E:\.BM09_2FA_WEB\huit_project && python manage.py runserver"

timeout /t 3 >nul

echo === Start ngrok ===
start cmd /k "ngrok http 8000"

pause