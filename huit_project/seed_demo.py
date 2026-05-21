"""
seed_demo.py — Tạo dữ liệu giả đa dạng cho demo HUIT 2FA System
====================================================================
Chạy: python manage.py shell < seed_demo.py
  hoặc: python manage.py runscript seed_demo  (nếu dùng django-extensions)
  hoặc copy vào manage.py shell và exec()

Cấu hình:
  EMAIL_PREFIX  — tiền tố email, vd: "tuankiet5274"
  NUM_USERS     — số user thường cần tạo (mặc định 25)
"""

import os, sys, django, random, hashlib, uuid, datetime, string

# ── Auto-setup Django nếu chạy standalone ──────────────────────────────────
if __name__ == '__main__':
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'huit_project.settings')
    django.setup()

from django.utils import timezone
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password

# ── Import models ───────────────────────────────────────────────────────────
from accounts.models import (
    UserProfile, EmailOTP, ActivityLog,
    TrustedDevice, AdminAuditLog, Announcement,
    BackupCode, SystemSettings,
)

# ════════════════════════════════════════════════════════════════════════════
# CẤU HÌNH — chỉnh ở đây
# ════════════════════════════════════════════════════════════════════════════
EMAIL_PREFIX = "tuankiet5274"   # → email dạng tuankiet5274+{username}@gmail.com
NUM_USERS    = 25               # số user thường (không kể admin)
ADMIN_USERNAME = "admin"
DEMO_PASSWORD  = "Demo@1234"    # mật khẩu chung cho tất cả user demo

# ════════════════════════════════════════════════════════════════════════════
# DỮ LIỆU HỌ TÊN VIỆT NAM (>100 phần tử mỗi loại)
# ════════════════════════════════════════════════════════════════════════════
HO = [
    "Nguyễn","Trần","Lê","Phạm","Hoàng","Huỳnh","Phan","Vũ","Võ","Đặng",
    "Bùi","Đỗ","Hồ","Ngô","Dương","Lý","Đinh","Trịnh","Lưu","Mai",
    "Tô","Đào","Quách","Hà","Trương","Tạ","Tăng","Cao","Lâm","Đoàn",
    "Ông","Châu","Tiêu","Khổng","Khúc","Cù","Đới","Liêu","Nông","Vương",
    "Trương","Tống","Kiều","Bạch","Khưu","Nhâm","Mạc","Dư","Uông","Sầm",
]

CHU_LOT = [
    "Văn","Thị","Hữu","Đức","Minh","Thanh","Quốc","Ngọc","Bảo","Xuân",
    "Hồng","Thu","Mai","Lan","Kim","Anh","Phúc","Trung","Tiến","Thành",
    "Công","Gia","Bá","Khánh","Nhật","Mỹ","Hải","Tú","Long","Phương",
    "Tấn","Trọng","Việt","Quang","Khắc","Thế","Hùng","Doãn","Mạnh","Chí",
    "Nguyên","An","Lâm","Sơn","Tuấn","Khoa","Bình","Hòa","Cảnh","Thiên",
    "Viết","Trường","Ân","Nghĩa","Linh","Trang","Yến","Thảo","Hà","Diệu",
    "Lệ","Ngân","Phượng","Uyên","Thi","Thùy","Kiều","Vân","Nhung","Loan",
]

TEN = [
    "An","Bình","Cường","Dũng","Em","Phong","Giang","Hải","Inh","Khoa",
    "Long","Minh","Nam","Oanh","Phúc","Quân","Rạng","Sơn","Tuấn","Uyên",
    "Vinh","Xuân","Yến","Anh","Bảo","Chi","Đạt","Gia","Hà","Hùng",
    "Khang","Linh","My","Ngân","Phương","Quỳnh","Tâm","Thi","Trung","Vũ",
    "Bích","Châu","Diệu","Hiền","Khanh","Lan","Nga","Nhung","Quyên","Thảo",
    "Thoa","Trang","Vân","Yên","Dương","Đức","Hào","Kiên","Mạnh","Nhân",
    "Phát","Quốc","Thịnh","Toàn","Trí","Vương","Chiến","Dân","Hiếu","Kha",
    "Lộc","Nghĩa","Nhi","Phước","Quang","Sáng","Tài","Thái","Thanh","Tiến",
    "Trọng","Tú","Tùng","Việt","Được","Hưng","Khải","Lâm","Lực","Năng",
    "Phong","Quỳnh","Sương","Thắng","Thiên","Tín","Tuyết","Ý","Bảo","Đông",
]

# ── User Agents phổ biến ─────────────────────────────────────────────────
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPad; CPU OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 13; Samsung Galaxy S23) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
]

# ── IP pools ─────────────────────────────────────────────────────────────
IPS_INTERNAL = [f"192.168.1.{i}" for i in range(10, 80)]
IPS_VIETTEL  = [f"171.239.{random.randint(100,200)}.{random.randint(1,254)}" for _ in range(20)]
IPS_FPT      = [f"27.72.{random.randint(50,150)}.{random.randint(1,254)}" for _ in range(20)]
IPS_VNPT     = [f"14.161.{random.randint(1,50)}.{random.randint(1,254)}" for _ in range(20)]
IPS_FOREIGN  = ["103.45.88.12","8.8.8.8","52.221.97.14","104.21.45.67","185.220.101.45"]
ALL_IPS      = IPS_INTERNAL + IPS_VIETTEL + IPS_FPT + IPS_VNPT + IPS_FOREIGN

# ── 2FA method combos (weights) ─────────────────────────────────────────
FA_CONFIGS = [
    {"has_email_otp": True,  "has_app_otp": False, "has_hotp": False},  # Email only
    {"has_email_otp": False, "has_app_otp": True,  "has_hotp": False},  # TOTP only
    {"has_email_otp": True,  "has_app_otp": True,  "has_hotp": False},  # Email + TOTP
    {"has_email_otp": False, "has_app_otp": False, "has_hotp": True},   # HOTP only
    {"has_email_otp": True,  "has_app_otp": False, "has_hotp": True},   # Email + HOTP
    {"has_email_otp": True,  "has_app_otp": True,  "has_hotp": True},   # All
    {"has_email_otp": False, "has_app_otp": False, "has_hotp": False},  # No 2FA
    {"has_email_otp": False, "has_app_otp": False, "has_hotp": False},  # No 2FA (more weight)
]
FA_WEIGHTS = [25, 20, 15, 10, 8, 7, 8, 7]  # tỷ lệ %

# ════════════════════════════════════════════════════════════════════════════
# HELPERS
# ════════════════════════════════════════════════════════════════════════════

def unidecode_vn(s: str) -> str:
    """Chuyển tiếng Việt → ASCII không dấu (bảng map đủ)."""
    MAP = {
        'à':'a','á':'a','ả':'a','ã':'a','ạ':'a',
        'ă':'a','ằ':'a','ắ':'a','ẳ':'a','ẵ':'a','ặ':'a',
        'â':'a','ầ':'a','ấ':'a','ẩ':'a','ẫ':'a','ậ':'a',
        'è':'e','é':'e','ẻ':'e','ẽ':'e','ẹ':'e',
        'ê':'e','ề':'e','ế':'e','ể':'e','ễ':'e','ệ':'e',
        'ì':'i','í':'i','ỉ':'i','ĩ':'i','ị':'i',
        'ò':'o','ó':'o','ỏ':'o','õ':'o','ọ':'o',
        'ô':'o','ồ':'o','ố':'o','ổ':'o','ỗ':'o','ộ':'o',
        'ơ':'o','ờ':'o','ớ':'o','ở':'o','ỡ':'o','ợ':'o',
        'ù':'u','ú':'u','ủ':'u','ũ':'u','ụ':'u',
        'ư':'u','ừ':'u','ứ':'u','ử':'u','ữ':'u','ự':'u',
        'ỳ':'y','ý':'y','ỷ':'y','ỹ':'y','ỵ':'y',
        'đ':'d',
        'À':'A','Á':'A','Ả':'A','Ã':'A','Ạ':'A',
        'Ă':'A','Ằ':'A','Ắ':'A','Ẳ':'A','Ẵ':'A','Ặ':'A',
        'Â':'A','Ầ':'A','Ấ':'A','Ẩ':'A','Ẫ':'A','Ậ':'A',
        'È':'E','É':'E','Ẻ':'E','Ẽ':'E','Ẹ':'E',
        'Ê':'E','Ề':'E','Ế':'E','Ể':'E','Ễ':'E','Ệ':'E',
        'Ì':'I','Í':'I','Ỉ':'I','Ĩ':'I','Ị':'I',
        'Ò':'O','Ó':'O','Ỏ':'O','Õ':'O','Ọ':'O',
        'Ô':'O','Ồ':'O','Ố':'O','Ổ':'O','Ỗ':'O','Ộ':'O',
        'Ơ':'O','Ờ':'O','Ớ':'O','Ở':'O','Ỡ':'O','Ợ':'O',
        'Ù':'U','Ú':'U','Ủ':'U','Ũ':'U','Ụ':'U',
        'Ư':'U','Ừ':'U','Ứ':'U','Ử':'U','Ữ':'U','Ự':'U',
        'Ỳ':'Y','Ý':'Y','Ỷ':'Y','Ỹ':'Y','Ỵ':'Y',
        'Đ':'D',
    }
    return ''.join(MAP.get(c, c) for c in s)

def make_username(first_name: str, last_name: str, existing: set) -> str:
    """
    Tạo username dạng: tên (ascii) + chữ đầu họ (ascii), vd: khoip, kieth
    Nếu trùng → thêm số.
    """
    first = unidecode_vn(first_name).lower().strip()
    last_initial = unidecode_vn(last_name).lower().strip()[0]
    base = first + last_initial
    # Loại ký tự đặc biệt
    base = ''.join(c for c in base if c.isalpha())
    candidate = base
    counter = 2
    while candidate in existing or User.objects.filter(username=candidate).exists():
        candidate = f"{base}{counter}"
        counter += 1
    existing.add(candidate)
    return candidate

def rand_phone() -> str:
    prefixes = ["032","033","034","035","036","037","038","039",
                "086","096","097","098","070","079","077","076","078",
                "089","058","056","058","059","090","091","094","083","084","085","081","082",
                "092","056","058"]
    return random.choice(prefixes) + ''.join(random.choices('0123456789', k=7))

def rand_past(days_back: int = 90, hours_jitter: int = 0) -> datetime.datetime:
    """Trả về datetime ngẫu nhiên trong N ngày qua."""
    delta = datetime.timedelta(
        days=random.randint(0, days_back),
        hours=random.randint(0, 23),
        minutes=random.randint(0, 59),
        seconds=random.randint(0, 59),
    )
    return timezone.now() - delta

def rand_ip(user_ips: list) -> str:
    return random.choice(user_ips)

def fake_otp_hash(code: str = None) -> str:
    code = code or ''.join(random.choices('0123456789', k=6))
    return hashlib.sha256(code.encode()).hexdigest()

def rand_device_name(ua: str) -> str:
    if 'iPhone' in ua: return 'iPhone'
    if 'iPad' in ua:   return 'iPad'
    if 'Android' in ua and 'Samsung' in ua: return 'Samsung Galaxy'
    if 'Android' in ua and 'Pixel' in ua:   return 'Google Pixel'
    if 'Android' in ua: return 'Android Phone'
    if 'Macintosh' in ua: return 'MacBook'
    if 'Windows' in ua: return 'Windows PC'
    if 'Linux' in ua:   return 'Linux PC'
    return 'Thiết bị không xác định'

# ════════════════════════════════════════════════════════════════════════════
# BƯỚC 1: Tạo / đảm bảo admin tồn tại
# ════════════════════════════════════════════════════════════════════════════
print("=" * 60)
print("HUIT Demo Seeder — bắt đầu tạo dữ liệu")
print("=" * 60)

def ensure_admin():
    if User.objects.filter(username=ADMIN_USERNAME).exists():
        admin = User.objects.get(username=ADMIN_USERNAME)
        print(f"[SKIP] Admin '{ADMIN_USERNAME}' đã tồn tại.")
    else:
        admin = User.objects.create_superuser(
            username   = ADMIN_USERNAME,
            email      = f"{EMAIL_PREFIX}+admin@gmail.com",
            password   = DEMO_PASSWORD,
            first_name = "Admin",
            last_name  = "HUIT",
        )
        print(f"[OK] Tạo superuser: {ADMIN_USERNAME}")
    # Đảm bảo profile
    profile, _ = UserProfile.objects.get_or_create(user=admin)
    # Admin bật Email OTP
    profile.has_email_otp = True
    profile.phone_number  = rand_phone()
    profile.save()
    return admin

admin_user = ensure_admin()

# ════════════════════════════════════════════════════════════════════════════
# BƯỚC 2: Tạo users thường
# ════════════════════════════════════════════════════════════════════════════
print(f"\n[*] Tạo {NUM_USERS} user thường...")

created_users = []
existing_usernames = set()

# Đảm bảo không trùng tên
used_names = set()
name_pool = []
while len(name_pool) < NUM_USERS * 2:
    ho     = random.choice(HO)
    lot    = random.choice(CHU_LOT)
    ten    = random.choice(TEN)
    key    = (ho, lot, ten)
    if key not in used_names:
        used_names.add(key)
        name_pool.append((ho, lot, ten))

for i in range(NUM_USERS):
    ho, lot, ten = name_pool[i]
    full_last  = ho          # họ → last_name trong Django
    full_first = ten         # tên → first_name

    username = make_username(ten, ho, existing_usernames)
    email    = f"{EMAIL_PREFIX}+{username}@gmail.com"

    if User.objects.filter(username=username).exists():
        print(f"  [SKIP] User '{username}' đã tồn tại.")
        user = User.objects.get(username=username)
    else:
        joined = timezone.now() - datetime.timedelta(days=random.randint(10, 365))
        user = User(
            username   = username,
            email      = email,
            first_name = full_first,
            last_name  = full_last,
            is_active  = random.choices([True, False], weights=[88, 12])[0],
            date_joined= joined,
            last_login = joined + datetime.timedelta(days=random.randint(1, 9)),
        )
        user.password = make_password(DEMO_PASSWORD)
        user.save()
        print(f"  [OK] {username} ({ho} {lot} {ten}) — {email}")

    # Profile
    profile, _ = UserProfile.objects.get_or_create(user=user)
    profile.middle_name  = lot
    profile.phone_number = rand_phone()

    # Random 2FA config
    fa = random.choices(FA_CONFIGS, weights=FA_WEIGHTS)[0]
    profile.has_email_otp = fa["has_email_otp"]
    profile.has_app_otp   = fa["has_app_otp"]
    profile.has_hotp      = fa["has_hotp"]

    if fa["has_app_otp"] or fa["has_hotp"]:
        # Giả lập secret đã được mã hóa (placeholder — không decrypt được, chỉ để demo)
        profile.otp_secret  = None  # không thể encrypt giả vì cần ENCRYPTION_KEY thật
        profile.hotp_secret = None
        profile.hotp_counter= random.randint(0, 50)

    profile.allow_push_auth = random.choices([True, False], weights=[75, 25])[0]
    profile.force_logout    = False
    profile.save()

    created_users.append(user)

all_regular_users = list(User.objects.filter(is_superuser=False))
all_users         = list(User.objects.all())
print(f"\n[OK] Tổng user: {User.objects.count()} (admin + {len(all_regular_users)} thường)")

# ════════════════════════════════════════════════════════════════════════════
# BƯỚC 3: ActivityLog — nhật ký đa dạng 90 ngày
# ════════════════════════════════════════════════════════════════════════════
print("\n[*] Tạo ActivityLog...")

ACTION_WEIGHTS = {
    'login':                60,
    'logout':               20,
    'login_failed':         10,
    'otp_fail':              4,
    'otp_success':           8,
    '2fa_enable':            3,
    '2fa_disable':           1,
    'register':              2,
    'account_toggle':        1,
    'force_logout':          1,
}
actions      = list(ACTION_WEIGHTS.keys())
act_weights  = list(ACTION_WEIGHTS.values())

activity_logs = []
for user in all_regular_users:
    # Mỗi user có 15–60 bản ghi
    n = random.randint(15, 60)
    # IP pools riêng cho mỗi user (2–4 IP cố định + đôi khi IP lạ)
    user_ips = random.sample(ALL_IPS, random.randint(2, 4))
    if random.random() < 0.15:  # 15% có IP nước ngoài 1 lần
        user_ips.append(random.choice(IPS_FOREIGN))

    for _ in range(n):
        action = random.choices(actions, weights=act_weights)[0]
        ts     = rand_past(90)
        ua     = random.choice(USER_AGENTS)
        ip     = rand_ip(user_ips)
        activity_logs.append(ActivityLog(
            user             = user if action != 'login_failed' or random.random() > 0.3 else None,
            username_attempt = user.username if action == 'login_failed' else None,
            action           = action,
            ip_address       = ip,
            user_agent       = ua,
            timestamp        = ts,
        ))

# Thêm vài log cho admin
for _ in range(30):
    action = random.choices(['login','logout','otp_success','2fa_enable','login_failed'],
                            weights=[50,20,15,10,5])[0]
    activity_logs.append(ActivityLog(
        user       = admin_user,
        action     = action,
        ip_address = random.choice(IPS_INTERNAL),
        user_agent = random.choice(USER_AGENTS),
        timestamp  = rand_past(30),
    ))

ActivityLog.objects.bulk_create(activity_logs, batch_size=500)
print(f"  [OK] {len(activity_logs)} ActivityLog bản ghi")

# ════════════════════════════════════════════════════════════════════════════
# BƯỚC 4: EmailOTP — lịch sử OTP
# ════════════════════════════════════════════════════════════════════════════
print("\n[*] Tạo EmailOTP history...")

OTP_ACTIONS = ['register','login_2fa','setup_2fa','update_info','disable_2fa']
OTP_ACT_W   = [10, 55, 15, 12, 8]

otp_records = []
for user in all_regular_users:
    n = random.randint(5, 25)
    user_ips = random.sample(ALL_IPS, 2)
    for _ in range(n):
        action   = random.choices(OTP_ACTIONS, weights=OTP_ACT_W)[0]
        ts       = rand_past(60)
        is_used  = random.choices([True, False], weights=[80, 20])[0]
        is_active= not is_used if random.random() > 0.1 else False

        used_at_val = None
        if is_used:
            used_at_val = ts + datetime.timedelta(minutes=random.randint(1, 3))

        otp_records.append(EmailOTP(
            user       = user,
            otp_code   = '',
            otp_hash   = fake_otp_hash(),
            action     = action,
            ip_address = random.choice(user_ips),
            email_sent = user.email,
            is_used    = is_used,
            is_active  = is_active,
            used_at    = used_at_val,
            created_at = ts,
        ))

# Một số OTP đăng ký (user=None)
for _ in range(8):
    fake_email = f"{EMAIL_PREFIX}+pending{random.randint(100,999)}@gmail.com"
    ts = rand_past(30)
    otp_records.append(EmailOTP(
        user       = None,
        otp_code   = '',
        otp_hash   = fake_otp_hash(),
        action     = 'register',
        ip_address = random.choice(ALL_IPS),
        email_sent = fake_email,
        is_used    = random.choice([True, False]),
        is_active  = False,
        created_at = ts,
    ))

EmailOTP.objects.bulk_create(otp_records, batch_size=500)
print(f"  [OK] {len(otp_records)} EmailOTP bản ghi")

# ════════════════════════════════════════════════════════════════════════════
# BƯỚC 5: TrustedDevice
# ════════════════════════════════════════════════════════════════════════════
print("\n[*] Tạo TrustedDevice...")

device_records = []
for user in all_regular_users:
    n_devices = random.randint(1, 4)
    user_ips  = random.sample(ALL_IPS, 2)
    for _ in range(n_devices):
        ua        = random.choice(USER_AGENTS)
        name      = rand_device_name(ua)
        is_trusted= random.choices([True, False], weights=[55, 45])[0]
        device_records.append(TrustedDevice(
            user        = user,
            device_id   = uuid.uuid4(),
            session_key = uuid.uuid4().hex[:40],
            name        = name,
            user_agent  = ua,
            ip_address  = random.choice(user_ips),
            is_active   = random.choices([True, False], weights=[85, 15])[0],
            is_trusted  = is_trusted,
        ))

TrustedDevice.objects.bulk_create(device_records, batch_size=200)
print(f"  [OK] {len(device_records)} TrustedDevice bản ghi")

# ════════════════════════════════════════════════════════════════════════════
# BƯỚC 6: AdminAuditLog
# ════════════════════════════════════════════════════════════════════════════
print("\n[*] Tạo AdminAuditLog...")

ADMIN_ACTIONS = [
    ("login",               "Admin đăng nhập hệ thống"),
    ("login_2fa_success",   "Admin xác thực 2FA thành công"),
    ("user_toggle_active",  "Admin khóa/mở khóa tài khoản"),
    ("force_logout_user",   "Admin cưỡng chế đăng xuất user"),
    ("force_logout_session","Admin xóa phiên đăng nhập cụ thể"),
    ("otp_disable",         "Admin vô hiệu OTP của user"),
    ("system_settings_save","Admin lưu cài đặt hệ thống"),
    ("announcement_create", "Admin tạo thông báo mới"),
    ("announcement_delete", "Admin xóa thông báo"),
    ("export_excel",        "Admin xuất Excel dữ liệu"),
    ("login_failed",        "Admin đăng nhập thất bại"),
    ("2fa_setup_begin",     "Admin bắt đầu thiết lập 2FA"),
    ("logout",              "Admin đăng xuất"),
]

audit_logs = []
target_users = all_regular_users[:10] if all_regular_users else []
for _ in range(80):
    action_key, detail_base = random.choice(ADMIN_ACTIONS)
    target = random.choice(target_users) if target_users and random.random() > 0.3 else None
    detail = detail_base
    if target and action_key in ('user_toggle_active','force_logout_user','otp_disable'):
        detail += f" — user: {target.username}"

    audit_logs.append(AdminAuditLog(
        user       = admin_user,
        action     = action_key,
        detail     = detail,
        ip_address = random.choice(IPS_INTERNAL),
        user_agent = random.choice(USER_AGENTS),
        timestamp  = rand_past(60),
    ))

AdminAuditLog.objects.bulk_create(audit_logs, batch_size=200)
print(f"  [OK] {len(audit_logs)} AdminAuditLog bản ghi")

# ════════════════════════════════════════════════════════════════════════════
# BƯỚC 7: Announcement
# ════════════════════════════════════════════════════════════════════════════
print("\n[*] Tạo Announcement...")

ANNOUNCEMENTS = [
    ("info",    "Bảo trì hệ thống định kỳ",
     "Hệ thống sẽ bảo trì từ 23:00 đến 02:00 ngày 25/05/2026. Vui lòng hoàn thành công việc trước thời gian này."),
    ("warning", "Cập nhật chính sách bảo mật",
     "Từ ngày 01/06/2026, tất cả tài khoản bắt buộc kích hoạt xác thực 2 bước. Vui lòng thiết lập ngay."),
    ("danger",  "Phát hiện đăng nhập bất thường",
     "Hệ thống ghi nhận một số IP lạ cố gắng đăng nhập. Nếu không phải bạn, hãy đổi mật khẩu ngay."),
    ("info",    "Tính năng mới: Passkey / FIDO2",
     "Hệ thống đã hỗ trợ đăng nhập bằng Passkey (vân tay, Face ID). Vào Cài đặt để kích hoạt."),
    ("info",    "Nhắc nhở: Kiểm tra thiết bị đăng nhập",
     "Vui lòng định kỳ kiểm tra danh sách thiết bị đã đăng nhập và xóa thiết bị không còn sử dụng."),
    ("warning", "Lỗi email OTP một số tài khoản",
     "Một số tài khoản Gmail có thể không nhận được OTP. Vui lòng liên hệ quản trị viên nếu gặp vấn đề."),
]

existing_ann = Announcement.objects.count()
if existing_ann == 0:
    for level, title, body in ANNOUNCEMENTS:
        ts = rand_past(30)
        Announcement.objects.create(
            title      = title,
            body       = body,
            level      = level,
            created_by = admin_user,
            created_at = ts,
            is_active  = random.choices([True, False], weights=[80, 20])[0],
        )
    print(f"  [OK] {len(ANNOUNCEMENTS)} Announcement tạo thành công")
else:
    print(f"  [SKIP] Đã có {existing_ann} Announcement")

# ════════════════════════════════════════════════════════════════════════════
# BƯỚC 8: BackupCode cho users đã bật 2FA
# ════════════════════════════════════════════════════════════════════════════
print("\n[*] Tạo BackupCode...")

bc_count = 0
for user in all_regular_users:
    profile = user.profile
    if profile.is_2fa_enabled:
        existing = BackupCode.objects.filter(user=user).count()
        if existing == 0:
            # Tạo 8 mã: một số đã dùng
            import secrets as _secrets
            BackupCode.objects.filter(user=user).delete()
            for j in range(8):
                raw   = _secrets.token_hex(4)
                plain = f'{raw[:4]}-{raw[4:]}'
                is_used  = (j < random.randint(0, 3))
                used_at  = (timezone.now() - datetime.timedelta(days=random.randint(1,30))) if is_used else None
                code_hash= hashlib.sha256(plain.encode()).hexdigest()
                BackupCode.objects.create(
                    user      = user,
                    code_hash = code_hash,
                    is_used   = is_used,
                    used_at   = used_at,
                    created_at= rand_past(60),
                )
                bc_count += 1

print(f"  [OK] {bc_count} BackupCode bản ghi")

# ════════════════════════════════════════════════════════════════════════════
# BƯỚC 9: SystemSettings singleton
# ════════════════════════════════════════════════════════════════════════════
print("\n[*] Đảm bảo SystemSettings singleton...")
ss = SystemSettings.get()
ss.registration_enabled  = True
ss.require_2fa_all       = False
ss.otp_expiry_minutes    = 5
ss.otp_max_retry         = 5
ss.session_timeout_hours = 24
ss.ip_whitelist          = ""
ss.ip_blacklist          = ""
ss.save()
print("  [OK] SystemSettings cập nhật")

# ════════════════════════════════════════════════════════════════════════════
# TỔNG KẾT
# ════════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 60)
print("TỔNG KẾT DỮ LIỆU DEMO")
print("=" * 60)
print(f"  User (total)       : {User.objects.count()}")
print(f"  User (thường)      : {User.objects.filter(is_superuser=False).count()}")
print(f"  User (kích hoạt)   : {User.objects.filter(is_active=True, is_superuser=False).count()}")
print(f"  User (bị khóa)     : {User.objects.filter(is_active=False, is_superuser=False).count()}")
print(f"  Có 2FA             : {UserProfile.objects.filter(has_email_otp=True).count() + UserProfile.objects.filter(has_app_otp=True).count() + UserProfile.objects.filter(has_hotp=True).count()} profiles (có thể trùng)")

from django.db.models import Q
has_2fa_count = UserProfile.objects.filter(
    Q(has_email_otp=True) | Q(has_app_otp=True) | Q(has_hotp=True)
).count()
print(f"  User bật ít nhất 1 2FA: {has_2fa_count}")
print(f"  ActivityLog        : {ActivityLog.objects.count()}")
print(f"  EmailOTP           : {EmailOTP.objects.count()}")
print(f"  TrustedDevice      : {TrustedDevice.objects.count()}")
print(f"  AdminAuditLog      : {AdminAuditLog.objects.count()}")
print(f"  Announcement       : {Announcement.objects.count()}")
print(f"  BackupCode         : {BackupCode.objects.count()}")
print()
print(f"  Email prefix       : {EMAIL_PREFIX}+{{username}}@gmail.com")
print(f"  Mật khẩu chung     : {DEMO_PASSWORD}")
print(f"  Admin login        : {ADMIN_USERNAME} / {DEMO_PASSWORD}")
print("=" * 60)
print("✅ Seed hoàn tất! Chạy server và kiểm tra dashboard.")