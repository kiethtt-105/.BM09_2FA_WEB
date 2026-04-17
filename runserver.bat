@echo off
cd /d E:\.BM09_2FA_WEB\.BM09_2FA_WEB

echo === Activate venv ===
call venv\Scripts\activate

echo === Go to project ===
cd huit_project

echo === Run Django Server ===
python manage.py runserver

pause