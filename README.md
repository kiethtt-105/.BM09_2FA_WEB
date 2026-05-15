# HUIT 2FA Authentication System

Hệ thống xác thực hai lớp (2FA) sử dụng Django, hỗ trợ:
- Email OTP
- Google Authenticator (TOTP)
- FIDO2 / Passkey
- Push Authentication (xác nhận từ thiết bị khác)
- Quản lý session, lịch sử đăng nhập, export Excel...

---

## 🚀 Hướng dẫn triển khai nhanh (Local)

### 1. Yêu cầu hệ thống

- **Python 3.10+**
- **PostgreSQL** (khuyến nghị)
- **pip** và venv
- **Git**

### 2. Clone project

```bash
    git clone https://github.com/kiethtt-105/.BM09_2FA_WEB
    cd huit_project

### 3. Tạo môi trường ảo
    python -m venv .venv

# Windows
    .venv\Scripts\activate

### 4. Cài đặt dependencies

    pip install -r requirements.txt
### 5. Thiết lập file .env
     Thiết lập tại các vị trí {...} # 
     Của file ".env.txt"
     ĐỔI Tên FIle ".env.txt" thành ".env"
### 6. Tạo Database PostgreSQL
    CREATE DATABASE huit_db;
    CREATE USER postgres WITH PASSWORD '109002';
    ALTER USER postgres WITH SUPERUSER;
### 7. Chạy Migration
    python manage.py makemigrations
    python manage.py migrate
### 8. Tạo Superuser (Admin)
    python manage.py createsuperuser
### 9. Chạy server
    python manage.py runserver  

    TRUY CẬP: http://127.0.0.1:8000

---
📋 Các tính năng chính

Đăng ký / Đăng nhập có 2FA
Thiết lập Email OTP, Google Authenticator, Passkey
Xác nhận đăng nhập từ thiết bị khác (Push Auth)
Quản lý phiên đăng nhập
Lịch sử hoạt động
Export dữ liệu Excel (Admin)

---
🔧 Lệnh hữu ích
python manage.py runserver          # Chạy dev server
python manage.py createsuperuser    # Tạo admin
python manage.py migrate            # Update database
python manage.py collectstatic      # Thu thập static files

===
⚠️ Lưu ý khi triển khai Production

Đổi DEBUG=False
Set SECRET_KEY mới (dài và mạnh)
Dùng HTTPS
Thay đổi ALLOWED_HOSTS và CSRF_TRUSTED_ORIGINS
Config Email production (không nên để Gmail)
Sử dụng Gunicorn + Nginx


Người phát triển: Tuấn Kiệt
Phiên bản: 1.0 _Tháng 5 2026
