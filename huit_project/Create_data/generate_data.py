import os
import sys
import django
import random
import uuid
from datetime import timedelta

# ==================== CẤU HÌNH DJANGO ====================

current_dir = os.path.dirname(os.path.abspath(__file__))
project_dir = os.path.dirname(current_dir)

sys.path.insert(0, project_dir)

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "huit_project.settings")

django.setup()

# ==================== IMPORT DJANGO ====================

from django.contrib.auth.models import User
from django.utils import timezone

from accounts.models import (
    UserProfile,
    User2FA,
    ActivityLog,
    TrustedDevice,
    LoginHistory,
    EmailOTP,
    PendingRegistration,
    OTP,
    UserSessionControl,
    RemoteAuthRequest,
    UserPasskey
)

# ==================== START ====================

print("✅ Django loaded successfully!")

# ==================== LOAD TÊN ====================

def load_names(filename="create_name.txt"):

    try:
        with open(filename, "r", encoding="utf-8") as f:
            names = [line.strip() for line in f if line.strip()]

        print(f"📋 Loaded {len(names)} names")
        return names

    except Exception as e:

        print("⚠️ Không tìm thấy file create_name.txt")
        print("⚠️ Sử dụng tên mặc định")

        return [
            "Nguyễn Văn An",
            "Trần Minh Khang",
            "Lê Hoàng Nam",
            "Phạm Gia Huy",
            "Đỗ Quốc Bảo",
            "Nguyễn Thị Lan",
            "Trần Ngọc Mai"
        ]

# ==================== REMOVE ACCENTS ====================

def remove_accents(text):

    accents = {
        'á':'a','à':'a','ả':'a','ã':'a','ạ':'a',
        'ă':'a','ắ':'a','ằ':'a','ẳ':'a','ẵ':'a','ặ':'a',
        'â':'a','ấ':'a','ầ':'a','ẩ':'a','ẫ':'a','ậ':'a',

        'é':'e','è':'e','ẻ':'e','ẽ':'e','ẹ':'e',
        'ê':'e','ế':'e','ề':'e','ể':'e','ễ':'e','ệ':'e',

        'í':'i','ì':'i','ỉ':'i','ĩ':'i','ị':'i',

        'ó':'o','ò':'o','ỏ':'o','õ':'o','ọ':'o',
        'ô':'o','ố':'o','ồ':'o','ổ':'o','ỗ':'o','ộ':'o',
        'ơ':'o','ớ':'o','ờ':'o','ở':'o','ỡ':'o','ợ':'o',

        'ú':'u','ù':'u','ủ':'u','ũ':'u','ụ':'u',
        'ư':'u','ứ':'u','ừ':'u','ử':'u','ữ':'u','ự':'u',

        'ý':'y','ỳ':'y','ỷ':'y','ỹ':'y','ỵ':'y',

        'đ':'d'
    }

    return ''.join(accents.get(c.lower(), c) for c in text)

# ==================== RANDOM DATA ====================

def random_ip():

    return (
        f"{random.randint(14,223)}."
        f"{random.randint(1,255)}."
        f"{random.randint(1,255)}."
        f"{random.randint(1,255)}"
    )

def random_user_agent():

    agents = [

        "Mozilla/5.0 Chrome Windows 11",
        "Mozilla/5.0 Firefox Ubuntu",
        "Mozilla/5.0 Safari iPhone",
        "Mozilla/5.0 Chrome Android",
        "Mozilla/5.0 Edge Windows 10",
        "Mozilla/5.0 Opera Linux",

    ]

    return random.choice(agents)

def random_device():

    devices = [

        "Windows PC",
        "MacBook Pro",
        "iPhone 15 Pro",
        "Samsung Galaxy S24",
        "Ubuntu Laptop",
        "iPad Air",
        "Office Workstation",

    ]

    return random.choice(devices)

# ==================== XÓA DỮ LIỆU ====================

def wipe_database():

    print("\n🗑️ Đang xóa dữ liệu cũ...\n")

    UserPasskey.objects.all().delete()
    RemoteAuthRequest.objects.all().delete()
    TrustedDevice.objects.all().delete()
    LoginHistory.objects.all().delete()
    ActivityLog.objects.all().delete()
    EmailOTP.objects.all().delete()
    OTP.objects.all().delete()
    PendingRegistration.objects.all().delete()
    User2FA.objects.all().delete()
    UserSessionControl.objects.all().delete()

    User.objects.filter(is_superuser=False).delete()

    print("✅ Database cleaned!")

# ==================== TẠO DATA ====================

def create_full_data(num_users=100):

    names = load_names()

    print(f"\n🚀 Generating FULL DATABASE with {num_users} users...\n")

    for i in range(num_users):

        # ==================== TÊN ====================

        full_name = random.choice(names)

        parts = full_name.split()

        ho = parts[0]

        ten = parts[-1] if len(parts) > 1 else "User"

        middle = " ".join(parts[1:-1]) if len(parts) > 2 else ""

        # ==================== USERNAME ====================

        base = remove_accents(ten.lower() + ho[0].lower())

        username = base

        counter = 1

        while User.objects.filter(username=username).exists():

            username = f"{base}{counter}"

            counter += 1

        # ==================== EMAIL ====================

        email = f"{username}{random.randint(1,9999)}@gmail.com"

        # ==================== USER ====================

        joined_time = timezone.now() - timedelta(
            days=random.randint(0, 365)
        )

        user = User.objects.create_user(

            username=username,
            email=email,
            password="Ab@12345",

            first_name=ten,
            last_name=ho,

            is_active=random.choice([
                True,
                True,
                True,
                False
            ])

        )

        user.date_joined = joined_time

        user.save()

        # ==================== PROFILE ====================

        app_otp = random.choice([True, False, False])

        email_otp = random.choice([True, False])

        has_fido2 = random.choice([True, False, False])

        profile, _ = UserProfile.objects.get_or_create(

            user=user,

            defaults={

                "middle_name": middle,

                "phone_number":
                    f"09{random.randint(10000000,99999999)}",

                "has_app_otp": app_otp,

                "has_email_otp": email_otp,

                "otp_secret":
                    "JBSWY3DPEHPK3PXP"
                    if app_otp else None,

                "has_fido2": has_fido2,

                "email_otp":
                    str(random.randint(100000,999999))
                    if email_otp else None,

                "otp_expiry":
                    timezone.now() + timedelta(minutes=5)

            }

        )

        # ==================== USER 2FA ====================

        User2FA.objects.get_or_create(

            user=user,

            defaults={

                "email_otp_enabled": email_otp,

                "google_auth_enabled": app_otp,

                "google_secret":
                    "JBSWY3DPEHPK3PXP"
                    if app_otp else "",

                "force_disable_2fa":
                    random.choice([
                        False,
                        False,
                        False,
                        True
                    ]),

                "is_required":
                    random.choice([
                        True,
                        False
                    ])

            }

        )

        # ==================== SESSION CONTROL ====================

        UserSessionControl.objects.get_or_create(

            user=user,

            defaults={

                "force_logout":
                    random.choice([
                        False,
                        False,
                        True
                    ])

            }

        )

        # ==================== ACTIVITY LOG ====================

        actions = [

            "login",
            "logout",
            "otp_success",
            "otp_fail",
            "2fa_enable",
            "2fa_disable",
            "login_failed",

        ]

        for _ in range(random.randint(6, 15)):

            log = ActivityLog.objects.create(

                user=user,

                action=random.choice(actions),

                ip_address=random_ip(),

                user_agent=random_user_agent()

            )

            log.timestamp = timezone.now() - timedelta(

                days=random.randint(0, 120),

                hours=random.randint(0, 23),

                minutes=random.randint(0, 59)

            )

            log.save()

        # ==================== LOGIN HISTORY ====================

        for _ in range(random.randint(4, 10)):

            history = LoginHistory.objects.create(

                user=user,

                ip=random_ip(),

                device=random_device(),

                status=random.choice([

                    "success",
                    "failed",
                    "2fa_success",
                    "locked"

                ])

            )

            history.time = timezone.now() - timedelta(

                days=random.randint(0, 90),

                hours=random.randint(0, 23)

            )

            history.save()

        # ==================== TRUSTED DEVICES ====================

        for _ in range(random.randint(1, 3)):

            device = TrustedDevice.objects.create(

                user=user,

                device_id=uuid.uuid4(),

                session_key=f"session_{random.randint(10000,99999)}",

                name=random_device(),

                user_agent=random_user_agent(),

                ip_address=random_ip(),

                is_active=random.choice([

                    True,
                    True,
                    False

                ])

            )

            device.last_seen = timezone.now() - timedelta(

                days=random.randint(0, 30)

            )

            device.save()

        # ==================== EMAIL OTP ====================

        email_actions = [

            "register",
            "login_2fa",
            "setup_2fa",
            "update_info",
            "disable_2fa"

        ]

        for _ in range(random.randint(4, 10)):

            otp = EmailOTP.objects.create(

                user=user,

                otp_code=str(random.randint(100000,999999)),

                action=random.choice(email_actions),

                ip_address=random_ip(),

                email_sent=user.email,

                is_used=random.choice([

                    True,
                    False

                ]),

                is_active=random.choice([

                    True,
                    True,
                    False

                ])

            )

            otp.created_at = timezone.now() - timedelta(

                days=random.randint(0, 60),

                minutes=random.randint(0, 1440)

            )

            if otp.is_used:

                otp.used_at = otp.created_at + timedelta(
                    minutes=random.randint(1, 5)
                )

            otp.save()

        # ==================== OTP TABLE ====================

        for _ in range(random.randint(1, 5)):

            otp = OTP.objects.create(

                user=user,

                code=str(random.randint(100000,999999))

            )

            otp.created_at = timezone.now() - timedelta(

                minutes=random.randint(1, 120)

            )

            otp.save()

        # ==================== PASSKEY ====================

        if random.choice([True, False, False]):

            UserPasskey.objects.create(

                user=user,

                credential_id=
                    f"cred_{username}_{random.randint(1000,9999)}",

                public_key=
                    f"PUBLIC_KEY_{random.randint(100000,999999)}",

                sign_count=random.randint(0, 50)

            )

        # ==================== REMOTE AUTH ====================

        for _ in range(random.randint(0, 3)):

            auth = RemoteAuthRequest.objects.create(

                user=user,

                session_key=
                    f"remote_{random.randint(10000,99999)}",

                device_info=random_device(),

                status=random.choice([

                    "pending",
                    "approved",
                    "denied"

                ])

            )

            auth.created_at = timezone.now() - timedelta(

                days=random.randint(0, 15),

                minutes=random.randint(0, 500)

            )

            auth.save()

        # ==================== PENDING REG ====================

        if random.choice([True, False, False, False]):

            pending = PendingRegistration.objects.create(

                email=f"pending_{username}@gmail.com",

                otp_code=str(random.randint(100000,999999)),

                is_used=random.choice([

                    True,
                    False

                ]),

                temp_data={

                    "username": f"pending_{username}",

                    "email": f"pending_{username}@gmail.com",

                    "first_name": ten,

                    "last_name": ho

                }

            )

            pending.created_at = timezone.now() - timedelta(

                minutes=random.randint(1, 60)

            )

            pending.save()

        # ==================== PROGRESS ====================

        if (i + 1) % 10 == 0:

            print(f"✅ Generated {i+1}/{num_users} users")

    # ==================== DONE ====================

    print("\n" + "=" * 70)

    print("🎉 FULL DATABASE GENERATED SUCCESSFULLY!")

    print("=" * 70)

    print(f"👥 Total Users Created: {num_users}")

    print("🔑 Default Password: Ab@12345")

    print("=" * 70)

# ==================== MENU ====================

if __name__ == "__main__":

    print("\n" + "=" * 70)

    print("              🚀 HUIT FULL DATABASE GENERATOR")

    print("=" * 70)

    print("1. 🗑️ Xóa user thường")

    print("2. 🔥 Xóa toàn bộ + Tạo dữ liệu mới")

    print("0. ❌ Thoát")

    print("=" * 70)

    choice = input("👉 Chọn chức năng: ").strip()

    # ==================== DELETE USERS ====================

    if choice == "1":

        User.objects.filter(is_superuser=False).delete()

        print("\n✅ Đã xóa toàn bộ user thường!")

    # ==================== FULL GENERATE ====================

    elif choice == "2":

        wipe_database()

        try:

            num = int(
                input("\n👥 Nhập số lượng user muốn tạo: ") or 100
            )

        except:

            num = 100

        create_full_data(num)

    # ==================== EXIT ====================

    elif choice == "0":

        print("\n👋 Thoát chương trình.")

    else:

        print("\n❌ Lựa chọn không hợp lệ!")