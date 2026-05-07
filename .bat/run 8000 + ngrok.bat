@echo off

echo 


start cmd /k "cd /d D:\.BM09_2FA_WEB\.BM09_2FA_WEB\huit_project && call .venv\Scripts\activate && python manage.py runserver 8000"

start cmd /k "cd /d D:\.BM09_2FA_WEB\.BM09_2FA_WEB\huit_project && call .venv\Scripts\activate && python manage.py runserver 0.0.0.0:8000"

start cmd /k "cd /d D:\.BM09_2FA_WEB\.BM09_2FA_WEB && ngrok http 8000"

echo T
pause