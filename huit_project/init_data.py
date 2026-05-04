import os
import django
import pyotp
import random
from django.utils import timezone
from django.db import transaction

# Setup môi trường Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'huit_project.settings')
django.setup()

from django.contrib.auth.models import User
from accounts.models import UserProfile, User2FA, ActivityLog

def generate_random_ip():
    return ".".join(map(str, (random.randint(0, 255) for _ in range(4))))

def run():
    try:
        num_users = int(input("Nhập số lượng user mẫu muốn tạo thêm: "))
    except ValueError:
        print("Vui lòng nhập một số nguyên!")
        return

    ho_list = ["Phan", "Nguyen", "Tran", "Le", "Pham", "Hoang", "Vu", "Dang", "Bui", "Do", "Ngo", "Duong", "Ly", "Truong", "Trinh"]
    ten_list = ["Khoi", "An", "Binh", "Cuong", "Dung", "Em", "Giang", "Hai", "Khanh", "Linh", "Minh", "Nam", "Oanh", "Phuc", "Quang", "Son", "Thanh", "Uyen", "Viet", "Yen"]
    
    stats = {"EMAIL_ONLY": 0, "APP_ONLY": 0, "FULL_2FA": 0, "BASIC": 0}

    print(f"\n--- Đang khởi tạo {num_users} User mẫu (Bản fix Unique) ---")

    for i in range(num_users):
        try:
            with transaction.atomic():
                ho = random.choice(ho_list)
                ten = random.choice(ten_list)
                
                # Tạo Username: tên + chữ đầu của họ
                base_username = f"{ten.lower()}{ho[0].lower()}"
                username = base_username
                suffix = 1
                while User.objects.filter(username=username).exists():
                    username = f"{base_username}{suffix}"
                    suffix += 1

                # 1. Tạo User mới
                user = User.objects.create(
                    username=username,
                    email=f"tuankiet5274+{username}@gmail.com",
                    first_name=ho,
                    last_name=ten,
                    is_active=True
                )
                user.set_password('Aa@123456')
                user.save()

                # Phân loại bảo mật ngẫu nhiên
                choice = random.choice(["EMAIL", "APP", "BOTH", "NONE"])
                has_email = choice in ["EMAIL", "BOTH"]
                has_app = choice in ["APP", "BOTH"]
                is_req = choice != "NONE"
                stats[{"EMAIL":"EMAIL_ONLY","APP":"APP_ONLY","BOTH":"FULL_2FA","NONE":"BASIC"}[choice]] += 1

                # 2. Tạo UserProfile - Dùng update_or_create để không bao giờ lỗi Unique
                UserProfile.objects.update_or_create(
                    user=user,
                    defaults={
                        'middle_name': '',
                        'phone_number': f"09{random.randint(10, 99)}{random.randint(100000, 999999)}",
                        'has_email_otp': has_email,
                        'has_app_otp': has_app,
                        'otp_secret': pyotp.random_base32() if has_email else "",
                        'has_fido2': False
                    }
                )

                # 3. Tạo User2FA
                User2FA.objects.update_or_create(
                    user=user,
                    defaults={
                        'google_auth_enabled': has_app,
                        'email_otp_enabled': has_email,
                        'google_secret': pyotp.random_base32() if has_app else None,
                        'is_required': is_req,
                        'force_disable_2fa': False
                    }
                )

                # 4. Ghi log với IP ngẫu nhiên
                random_ip = generate_random_ip()
                ActivityLog.objects.create(
                    user=user,
                    action='batch_init_pro',
                    ip_address=random_ip,
                    username_attempt=username,
                    user_agent=f'Sec:{choice}|IP:{random_ip}',
                    timestamp=timezone.now()
                )
                print(f"OK: {username} | Pass: Aa@123456 | IP: {random_ip}")

        except Exception as e:
            print(f"Lỗi tại user {i+1}: {e}")

    print("\n" + "="*50)
    print(f" HOÀN TẤT: ĐÃ TẠO {num_users} USER")
    print(f" 📧 Email: {stats['EMAIL_ONLY']} | 📱 App: {stats['APP_ONLY']}")
    print(f" 🔐 Cả hai: {stats['FULL_2FA']} | 🔓 Cơ bản: {stats['BASIC']}")
    print("="*50)

if __name__ == '__main__':
    run()