"""
utils.py — Các hàm tiện ích dùng chung cho hệ thống HUIT 2FA
=============================================================
Bao gồm:
  - Tạo mã QR cho Google Authenticator
  - Tính toán TOTP (Time-based OTP)
  - Sinh và gửi OTP qua Email
  - Lấy địa chỉ IP client

LỖI ĐÃ SỬA:
  [BUG-U1] hmac.new → hmac.new không tồn tại; phải dùng hmac.new() → sửa thành hmac.new()
           Thực ra Python dùng: hmac.new(key, msg, digestmod) ✔ (tên đúng, không lỗi cú pháp)
           NHƯNG: import hmac đã có — chỉ cần đảm bảo không bị shadowed.
  [BUG-U2] generate_and_send_email_otp() trong utils.py chỉ nhận (user) nhưng
           views.py gọi với kwargs: user=None, email=, action=, ip=, subject=, body=
           → Sửa signature hàm để nhận đủ tham số.
  [BUG-U3] EmailOTP.objects.create() trong hàm cũ KHÔNG truyền action/ip/email_sent
           → Bổ sung đầy đủ.
  [BUG-U4] send_mail() hard-code địa chỉ 'your-email@gmail.com' thay vì dùng settings
           → Đổi thành from_email=None (Django tự lấy DEFAULT_FROM_EMAIL).
"""

import qrcode
import io
import base64
import time
import hmac
import hashlib
import secrets

from django.core.mail import send_mail
from django.conf import settings  # [FIX-U4] dùng settings thay vì hard-code

from .models import EmailOTP


# ─────────────────────────────────────────────────────────────────────────────
# 1. SINH MÃ QR CHO GOOGLE AUTHENTICATOR / iCLOUD KEYCHAIN
# ─────────────────────────────────────────────────────────────────────────────
def generate_qr_base64(username: str, secret: str) -> str:
    """
    Tạo ảnh QR code theo chuẩn otpauth://totp và trả về chuỗi Base64.

    Tham số:
        username (str): Tên đăng nhập của người dùng (hiển thị trong app OTP).
        secret   (str): Secret key dạng Base32 đã tạo bằng pyotp.random_base32().

    Trả về:
        str: Chuỗi Base64 của ảnh PNG — dùng trực tiếp trong <img src="data:image/png;base64,...">
    """
    # URI chuẩn RFC 6238 — tương thích Google Authenticator, Aegis, iCloud Keychain
    uri = f"otpauth://totp/HUIT_2FA:{username}?secret={secret}&issuer=HUIT_2FA"

    qr = qrcode.QRCode(version=1, box_size=10, border=2)
    qr.add_data(uri)
    qr.make(fit=True)  # [FIX] thêm fit=True để tự điều chỉnh version nếu data dài

    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()


# ─────────────────────────────────────────────────────────────────────────────
# 2. TÍNH TOÁN TOTP (RFC 6238)
# ─────────────────────────────────────────────────────────────────────────────
def get_totp_token(secret: str) -> str:
    """
    Tính mã TOTP 6 chữ số hiện tại từ secret key Base32.

    Thuật toán: HMAC-SHA1 theo chuẩn RFC 6238 (bước thời gian 30 giây).

    Tham số:
        secret (str): Secret key dạng Base32 (có thể thiếu padding '=').

    Trả về:
        str: Mã 6 chữ số dạng chuỗi, ví dụ "047382".
             Trả về "000000" nếu secret không hợp lệ (tránh crash).

    LỖI CŨ [BUG-U1]:
        - Nếu secret là None hoặc rỗng, hàm cũ gọi .upper() → AttributeError.
        - Xử lý exception quá rộng (bare except) che giấu lỗi thật.
    """
    if not secret:
        return "000000"  # [FIX-U1] guard early — tránh crash khi secret=None

    try:
        # Bổ sung padding Base32 nếu thiếu (Base32 cần bội số của 8)
        missing_padding = len(secret) % 8
        if missing_padding:
            secret += '=' * (8 - missing_padding)

        key = base64.b32decode(secret.upper(), casefold=True)

        # Số bước 30-giây kể từ Unix epoch → 8 byte big-endian
        msg = int(time.time() / 30).to_bytes(8, 'big')

        # HMAC-SHA1
        h = hmac.new(key, msg, hashlib.sha1).digest()

        # Dynamic truncation (RFC 4226 §5.4)
        offset = h[19] & 0x0F
        code = (
            ((h[offset]     & 0x7F) << 24) |
            ((h[offset + 1] & 0xFF) << 16) |
            ((h[offset + 2] & 0xFF) <<  8) |
             (h[offset + 3] & 0xFF)
        )
        return str(code % 1_000_000).zfill(6)

    except Exception as exc:
        # [FIX-U1] Log lỗi thay vì nuốt silent để dễ debug
        import logging
        logging.getLogger(__name__).error("get_totp_token error: %s", exc)
        return "000000"


# ─────────────────────────────────────────────────────────────────────────────
# 3. SINH VÀ GỬI EMAIL OTP
# ─────────────────────────────────────────────────────────────────────────────
def generate_and_send_email_otp(
    user,                           # User object hoặc None (khi đăng ký chưa có user)
    email: str,                     # [FIX-U2] thêm tham số email
    action: str  = 'login_2fa',    # [FIX-U3] thêm tham số action để log đúng loại
    ip:    str   = None,            # [FIX-U3] IP address để ghi vào EmailOTP log
    subject: str = None,            # [FIX-U2] tiêu đề email (nếu None → dùng mặc định)
    body:    str = None,            # [FIX-U2] nội dung email (nếu None → dùng mặc định)
) -> str:
    """
    Sinh mã OTP 6 chữ số bảo mật, lưu DB, và gửi qua Email.

    Tham số:
        user    : User object hoặc None (trường hợp đăng ký chưa tạo User).
        email   : Địa chỉ email nhận OTP.
        action  : Loại hành động ('register', 'login_2fa', 'setup_2fa', ...).
        ip      : Địa chỉ IP của client (dùng cho audit log).
        subject : Tiêu đề email; nếu None → dùng tiêu đề mặc định.
        body    : Nội dung email; nếu None → dùng nội dung mặc định.

    Trả về:
        str: Mã OTP vừa sinh (6 chữ số).

    LỖI CŨ:
        [BUG-U2] Hàm cũ chỉ nhận (user) → views.py gọi với 6 tham số → TypeError.
        [BUG-U3] Không lưu action/ip_address/email_sent vào EmailOTP → thiếu audit trail.
        [BUG-U4] Hard-code 'your-email@gmail.com' → gửi mail thất bại khi deploy.
    """
    # 1. Sinh mã 6 chữ số ngẫu nhiên mật mã học (không dùng random.randint)
    otp_code = ''.join(str(secrets.randbelow(10)) for _ in range(6))

    # 2. Lưu vào bảng EmailOTP (tự động hash SHA-256 trong model.save())
    EmailOTP.objects.create(
        user        = user,             # [FIX-U3] lưu user (có thể None khi register)
        otp_code    = otp_code,
        action      = action,           # [FIX-U3] loại thao tác để phân loại log
        ip_address  = ip,               # [FIX-U3] IP cho audit trail
        email_sent  = email,            # [FIX-U3] email đích để kiểm tra sau
        is_used     = False,
        is_active   = True,
    )

    # 3. Xây dựng nội dung email (dùng subject/body truyền vào hoặc fallback mặc định)
    final_subject = subject or 'Mã xác thực 2FA của bạn - HUIT'
    final_body    = body    or (
        f'Mã OTP của bạn là: {otp_code}\n\n'
        f'Mã có hiệu lực trong 5 phút. Không chia sẻ mã này với ai.\n\n'
        f'Trân trọng,\nHUIT System'
    )

    # 4. Gửi Email qua SMTP (cấu hình trong settings.py)
    # [FIX-U4] from_email=None → Django tự dùng DEFAULT_FROM_EMAIL trong settings
    send_mail(
        subject      = final_subject,
        message      = final_body,
        from_email   = None,
        recipient_list = [email],
        fail_silently  = False,  # Để caller bắt Exception nếu gửi thất bại
    )

    return otp_code


# ─────────────────────────────────────────────────────────────────────────────
# 4. LẤY ĐỊA CHỈ IP CLIENT
# ─────────────────────────────────────────────────────────────────────────────
def get_client_ip(request) -> str:
    """
    Lấy địa chỉ IP thực của client từ HTTP request.

    Ưu tiên header X-Forwarded-For (khi chạy sau reverse proxy như Nginx).
    Fallback về REMOTE_ADDR nếu không có proxy.

    Lưu ý bảo mật:
        X-Forwarded-For có thể bị giả mạo nếu không cấu hình trusted proxy.
        Trong production, nên dùng django-ipware hoặc cấu hình TRUSTED_PROXY_LIST.

    Tham số:
        request: Django HttpRequest object.

    Trả về:
        str: Địa chỉ IP (ví dụ '192.168.1.1') hoặc None nếu không xác định được.
    """
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        # Lấy IP đầu tiên trong chuỗi (IP gốc của client)
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip
