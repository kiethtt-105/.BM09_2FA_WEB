import os
import django
import pyotp
import random
import unidecode
from django.utils import timezone
from django.db import transaction

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'huit_project.settings')
django.setup()

from django.contrib.auth.models import User
from accounts.models import UserProfile, User2FA, ActivityLog


# ================= HELPERS =================
def generate_random_ip():
    return ".".join(str(random.randint(1, 255)) for _ in range(4))


def generate_phone():
    prefix = random.choice(["03", "07", "08", "09"])
    return prefix + str(random.randint(10000000, 99999999))


def generate_username(ho, ten):
    base = unidecode.unidecode(ten).lower() + unidecode.unidecode(ho[0]).lower()
    username = base
    i = 1
    while User.objects.filter(username=username).exists():
        username = f"{base}{i}"
        i += 1
    return username


# ================= MAIN =================
def run():
    print("\n===== DEMO DATA SECURITY SEEDER =====")

    print("\n1. Reset sạch + tạo mới")
    print("2. Giữ dữ liệu + tạo thêm")
    print("3. Thoát")

    choice = input("👉 Chọn (1/2/3): ").strip()

    if choice == "3":
        print("❌ Thoát")
        return

    if choice == "1":
        print("⚠️ Đang xóa user cũ...")
        User.objects.exclude(is_superuser=True).exclude(username='admin').delete()

    elif choice == "2":
        print("➕ Giữ dữ liệu cũ")

    else:
        print("❌ Lựa chọn sai")
        return

    # ===== INPUT =====
    try:
        num_users = int(input("👉 Nhập số lượng user: "))
    except:
        print("❌ Số không hợp lệ")
        return

    # ===== DATA NAME =====
    ho_array = ["Nguyễn", "Trần", "Lê", "Phạm", "Hoàng", "Phan", "Vũ", "Đặng"]
    dem_array = ["Văn", "Thị", "Minh", "Anh", "Đức", "Quang", "Ngọc"]
    ten_array = ["An", "Bình", "Cường", "Dũng", "Hải", "Linh", "Nam", "Phúc", "Tuấn", "Kiệt"]

    print(f"\n--- Đang tạo {num_users} user ---\n")

    for i in range(num_users):
        try:
            with transaction.atomic():

                # ===== NAME =====
                ho = random.choice(ho_array)
                dem = random.choice(dem_array)
                ten = random.choice(ten_array)

                username = generate_username(ho, ten)

                # ===== CREATE USER =====
                user = User.objects.create_user(
                    username=username,
                    email=f"tuankiet5274+{username}@gmail.com",
                    password="Aa@123456",
                    first_name=f"{ho} {dem}",
                    last_name=ten,
                    is_active=True
                )

                # ===== 2FA MODE =====
                mode = random.choice(["NONE", "EMAIL", "APP", "BOTH"])

                has_email = mode in ["EMAIL", "BOTH"]
                has_app = mode in ["APP", "BOTH"]

                # ===== PROFILE (FIX UNIQUE + NULL) =====
                profile, _ = UserProfile.objects.get_or_create(user=user)

                profile.phone_number = generate_phone()
                profile.has_email_otp = has_email
                profile.has_app_otp = has_app

                profile.otp_secret = pyotp.random_base32()
                profile.save()

                # ===== USER2FA =====
                User2FA.objects.update_or_create(
                    user=user,
                    defaults={
                        "google_auth_enabled": has_app,
                        "email_otp_enabled": has_email,
                        "google_secret": pyotp.random_base32() if has_app else None,
                        "is_required": (mode != "NONE"),
                        "force_disable_2fa": False
                    }
                )

                # ===== LOG =====
                ActivityLog.objects.create(
                    user=user,
                    action="demo_seed",
                    ip_address=generate_random_ip(),
                    username_attempt=username,
                    user_agent=f"Mode/{mode}",
                    timestamp=timezone.now()
                )

                print(f"✔ {username} | {mode}")

        except Exception as e:
            print(f"❌ Lỗi user {i}: {e}")

    print("\n===== DONE =====")


if __name__ == "__main__":
    run()