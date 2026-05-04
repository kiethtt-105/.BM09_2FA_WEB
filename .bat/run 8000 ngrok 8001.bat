@echo off
title SSO HUIT 
echo Dang khoi dong ...

:: 1. Huit_AUth (8000)
start cmd /k "cd /d D:\.BM09_2FA_WEB\.BM09_2FA_WEB\huit_project && call .venv\Scripts\activate && python manage.py runserver 8000"

:: 2. SSO_Login (8001)
start cmd /k "cd /d D:\.BM09_2FA_WEB\.BM09_2FA_WEB\SSO_WEB\appb_project && call .venv\Scripts\activate && python manage.py runserver 8001"

:: 3. Chạy Ngrok
start cmd /k "cd /d D:\.BM09_2FA_WEB\.BM09_2FA_WEB && ngrok http 8000"

echo Done
pause