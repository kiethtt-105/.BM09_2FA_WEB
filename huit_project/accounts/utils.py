"""
utils.py — Tiện ích hệ thống HUIT 2FA  [PATCHED]
==================================================
THAY ĐỔI SO VỚI BẢN GỐC:

  [WARN-1] generate_and_send_email_otp: Tự động vô hiệu OTP cũ cùng user+action
           trước khi tạo OTP mới → tránh nhiều OTP active song song.
           User dùng mã cũ từ email cũ sẽ bị từ chối đúng chuẩn.
"""

import io
import base64
import time
import hmac
import hashlib
import secrets
import struct
import logging

import qrcode

from django.core.mail import send_mail
from django.conf import settings

from .models import EmailOTP


# ═══════════════════════════════════════════════════════════════════════════════
# 0. SECRET GENERATION — không dùng pyotp
# ═══════════════════════════════════════════════════════════════════════════════

def generate_totp_secret(length: int = 20) -> str:
    """
    Sinh Base32 secret ngẫu nhiên (160-bit mặc định) để dùng với TOTP/HOTP.
    Tương đương pyotp.random_base32() nhưng tự implement — RFC 4226 §4.
    Bổ sung padding '=' để đảm bảo Base32 hợp lệ khi decode sau.
    """
    raw = secrets.token_bytes(length)
    encoded = base64.b32encode(raw).decode()
    # Bỏ padding khi lưu (Google Auth chấp nhận không có '=')
    return encoded.rstrip('=')

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# 1. HOTP — RFC 4226
# ═══════════════════════════════════════════════════════════════════════════════

def _base32_decode(secret: str) -> bytes:
    """
    Giải mã Base32 thủ công — không dùng thư viện base64.b32decode.
    Bổ sung padding nếu thiếu (Base32 yêu cầu bội số 8).
    """
    ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
    secret = secret.upper().strip().rstrip('=')

    bits   = 0
    buffer = 0
    result = []
    for ch in secret:
        val = ALPHABET.find(ch)
        if val < 0:
            continue
        buffer = (buffer << 5) | val
        bits  += 5
        if bits >= 8:
            bits  -= 8
            result.append((buffer >> bits) & 0xFF)
    return bytes(result)


def _hmac_sha1(key: bytes, msg: bytes) -> bytes:
    """HMAC-SHA1 dùng module hmac chuẩn Python."""
    return hmac.new(key, msg, hashlib.sha1).digest()


def _dynamic_truncate(h: bytes) -> int:
    """Dynamic Truncation theo RFC 4226 §5.3."""
    offset = h[-1] & 0x0F
    p = (
        ((h[offset]     & 0x7F) << 24) |
        ((h[offset + 1] & 0xFF) << 16) |
        ((h[offset + 2] & 0xFF) <<  8) |
         (h[offset + 3] & 0xFF)
    )
    return p


def compute_hotp(secret: str, counter: int, digits: int = 6) -> str:
    """
    Tính mã HOTP theo RFC 4226.
    HOTP(K, C) = Truncate(HMAC-SHA1(K, C)) mod 10^digits
    """
    if not secret:
        return '0' * digits
    try:
        key  = _base32_decode(secret)
        msg  = struct.pack('>Q', counter)
        h    = _hmac_sha1(key, msg)
        code = _dynamic_truncate(h) % (10 ** digits)
        return str(code).zfill(digits)
    except Exception as exc:
        logger.error('compute_hotp error: %s', exc)
        return '0' * digits


def verify_hotp(secret: str, counter: int, otp_input: str,
                look_ahead: int = 5) -> tuple[bool, int]:
    logger.warning(
        'HOTP_VERIFY: secret=%s... counter=%d input=%s',
        secret[:4], counter, otp_input
    )
    for i in range(look_ahead):
        expected = compute_hotp(secret, counter + i)
        logger.warning('  thử counter=%d → mã=%s', counter + i, expected)
        if hmac.compare_digest(expected, otp_input.zfill(6)):
            logger.warning('  → KHỚP tại counter=%d', counter + i)
            return True, counter + i + 1
    logger.warning('  → KHÔNG KHỚP')
    return False, counter


# ═══════════════════════════════════════════════════════════════════════════════
# 2. TOTP — RFC 6238
# ═══════════════════════════════════════════════════════════════════════════════

def compute_totp(secret: str, digits: int = 6, step: int = 30,
                 t0: int = 0, at_time: float = None) -> str:
    """
    Tính mã TOTP theo RFC 6238.
    counter = floor((T - T0) / X)
    """
    if not secret:
        return '0' * digits
    try:
        T       = at_time if at_time is not None else time.time()
        counter = int((T - t0) // step)
        return compute_hotp(secret, counter, digits)
    except Exception as exc:
        logger.error('compute_totp error: %s', exc)
        return '0' * digits


def verify_totp(secret: str, otp_input: str,
                digits: int = 6, step: int = 30,
                window: int = 1) -> bool:
    """
    Xác thực TOTP với cửa sổ time-window ±window bước (mặc định ±1 = ±30 giây).
    hmac.compare_digest dùng để tránh timing attack.
    """
    now = time.time()
    for delta in range(-window, window + 1):
        candidate = compute_totp(secret, digits=digits, step=step,
                                 at_time=now + delta * step)
        if hmac.compare_digest(candidate, otp_input.zfill(digits)):
            return True
    return False


def get_totp_token(secret: str) -> str:
    """Alias của compute_totp để giữ backward compatibility."""
    return compute_totp(secret)


# ═══════════════════════════════════════════════════════════════════════════════
# 3. QR Code
# ═══════════════════════════════════════════════════════════════════════════════

def generate_qr_base64(username: str, secret: str,
                       otp_type: str = 'totp') -> str:
    """
    Tạo QR code theo chuẩn otpauth:// URI và trả về Base64 PNG.
    Tương thích Google Authenticator, Aegis, iCloud Keychain.
    """
    if otp_type == 'hotp':
        uri = (
            f'otpauth://hotp/HUIT_2FA:{username}'
            f'?secret={secret}&issuer=HUIT_2FA&counter=0'
        )
    else:
        uri = (
            f'otpauth://totp/HUIT_2FA:{username}'
            f'?secret={secret}&issuer=HUIT_2FA'
        )

    qr = qrcode.QRCode(version=1, box_size=10, border=2)
    qr.add_data(uri)
    qr.make(fit=True)

    img = qr.make_image(fill_color='black', back_color='white')
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    return base64.b64encode(buf.getvalue()).decode()


# ═══════════════════════════════════════════════════════════════════════════════
# 4. Email OTP
# ═══════════════════════════════════════════════════════════════════════════════

_EMAIL_TEMPLATES = {
    'register': (
        'Kích hoạt tài khoản HUIT - Mã OTP của bạn',
        (
            'Xin chào {name},\n\n'
            'Bạn vừa đăng ký tài khoản tại hệ thống HUIT.\n\n'
            'Mã OTP kích hoạt tài khoản của bạn là:\n\n'
            '    ► {otp_code}\n\n'
            'Mã có hiệu lực trong 10 phút. Không chia sẻ mã này với bất kỳ ai.\n\n'
            'Nếu bạn không thực hiện yêu cầu này, hãy bỏ qua email này.\n\n'
            'Trân trọng,\nHUIT System'
        ),
    ),
    'login_2fa': (
        'Mã xác thực đăng nhập 2FA - HUIT',
        (
            'Xin chào {name},\n\n'
            'Hệ thống HUIT phát hiện lượt đăng nhập mới.\n\n'
            'Mã OTP xác thực đăng nhập của bạn là:\n\n'
            '    ► {otp_code}\n\n'
            'Mã có hiệu lực trong 3 phút.\n\n'
            'Nếu bạn không đăng nhập lúc này, tài khoản của bạn có thể đã bị xâm phạm.\n'
            'Vui lòng đổi mật khẩu ngay.\n\n'
            'Trân trọng,\nHUIT System'
        ),
    ),
    'setup_2fa': (
        'Thiết lập bảo mật 2FA Email - HUIT',
        (
            'Xin chào {name},\n\n'
            'Bạn đang thiết lập phương thức xác thực Email OTP cho tài khoản HUIT.\n\n'
            'Mã OTP xác nhận kích hoạt là:\n\n'
            '    ► {otp_code}\n\n'
            'Mã có hiệu lực trong 3 phút.\n\n'
            'Sau khi xác nhận, mọi lần đăng nhập sẽ yêu cầu mã OTP qua email này.\n\n'
            'Trân trọng,\nHUIT System'
        ),
    ),
    'disable_2fa': (
        'Xác nhận tắt bảo mật 2FA - HUIT',
        (
            'Xin chào {name},\n\n'
            'Bạn đang yêu cầu TẮT phương thức xác thực 2FA cho tài khoản.\n\n'
            'Mã OTP xác nhận tắt bảo mật là:\n\n'
            '    ► {otp_code}\n\n'
            'Mã có hiệu lực trong 3 phút.\n\n'
            'Nếu bạn không thực hiện thao tác này, hãy bỏ qua email và liên hệ Admin ngay.\n\n'
            'Trân trọng,\nHUIT System'
        ),
    ),
    'update_info': (
        'Xác nhận cập nhật thông tin tài khoản - HUIT',
        (
            'Xin chào {name},\n\n'
            'Bạn đang yêu cầu cập nhật thông tin cá nhân / thay đổi email tài khoản HUIT.\n\n'
            'Mã OTP xác nhận là:\n\n'
            '    ► {otp_code}\n\n'
            'Mã có hiệu lực trong 3 phút.\n\n'
            'Nếu bạn không thực hiện thao tác này, hãy bỏ qua email này.\n\n'
            'Trân trọng,\nHUIT System'
        ),
    ),
}

_EMAIL_TEMPLATE_DEFAULT = (
    'Mã xác thực OTP - HUIT',
    (
        'Xin chào {name},\n\n'
        'Mã OTP của bạn là:\n\n'
        '    ► {otp_code}\n\n'
        'Mã có hiệu lực trong 3 phút. Không chia sẻ mã này với ai.\n\n'
        'Trân trọng,\nHUIT System'
    ),
)


def generate_and_send_email_otp(
    user,
    email:   str,
    action:  str = 'login_2fa',
    ip:      str = None,
    subject: str = None,
    body:    str = None,
    name:    str = None,
) -> str:
    """
    Sinh mã OTP 6 chữ số, lưu DB (chỉ hash), gửi qua Email.

    [WARN-1] Trước khi tạo OTP mới, tự động invalidate các OTP cũ
             cùng user + action còn active → tránh nhiều mã hợp lệ song song.

    Bảo mật:
        - CSPRNG: secrets.randbelow(10).
        - DB chỉ lưu SHA-256(otp_code) — không lưu plaintext.

    Trả về: str — mã OTP plaintext (chỉ tồn tại trong RAM + nội dung email).
    """
    otp_code = ''.join(str(secrets.randbelow(10)) for _ in range(6))

    # [WARN-1] Vô hiệu OTP cũ cùng user+action trước khi tạo mới
    if user is not None:
        invalidated = EmailOTP.objects.filter(
            user      = user,
            action    = action,
            is_used   = False,
            is_active = True,
        ).update(is_active=False)
        if invalidated:
            logger.debug(
                '[WARN-1] Invalidated %d old OTP(s) for user=%s action=%s',
                invalidated, user.username if hasattr(user, 'username') else user, action
            )
    else:
        # [BUG-8 FIX] user=None → flow đăng ký, phân biệt qua email_sent
        # Tránh nhiều EmailOTP active song song cùng email khi resend
        invalidated = EmailOTP.objects.filter(
            user__isnull = True,
            email_sent   = email,
            action       = action,
            is_used      = False,
            is_active    = True,
        ).update(is_active=False)
        if invalidated:
            logger.debug(
                '[BUG-8 FIX] Invalidated %d old OTP(s) for email=%s action=%s (user=None)',
                invalidated, email, action
            )

    # Lưu DB: model.save() tự hash → otp_hash, xóa plaintext
    EmailOTP.objects.create(
        user       = user,
        otp_code   = otp_code,
        action     = action,
        ip_address = ip,
        email_sent = email,
        is_used    = False,
        is_active  = True,
    )

    # Xây nội dung email theo action
    display_name = name
    if not display_name and user:
        display_name = (
            f'{user.first_name} {user.last_name}'.strip()
            or user.username
        )
    display_name = display_name or 'Bạn'

    if subject and body:
        final_subject = subject
        final_body    = body
    else:
        tmpl_subject, tmpl_body = _EMAIL_TEMPLATES.get(action, _EMAIL_TEMPLATE_DEFAULT)
        final_subject = subject or tmpl_subject
        final_body    = body    or tmpl_body.format(otp_code=otp_code, name=display_name)

    send_mail(
        subject        = final_subject,
        message        = final_body,
        from_email     = None,
        recipient_list = [email],
        fail_silently  = False,
    )

    return otp_code


# ═══════════════════════════════════════════════════════════════════════════════
# 5. IP Client
# ═══════════════════════════════════════════════════════════════════════════════

def get_client_ip(request) -> str:
    """
    Lấy IP thực của client.

    [FIX-IP] X-Forwarded-For: client, proxy1, proxy2, ...
      - IP đầu tiên (index 0): do CLIENT tự khai báo → có thể bị giả mạo.
      - IP cuối cùng (index -1): do trusted reverse-proxy ghi vào → đáng tin hơn
        khi hệ thống chạy sau đúng 1 lớp proxy (Nginx/Cloudflare).

    Nếu không có X-Forwarded-For → dùng REMOTE_ADDR (kết nối trực tiếp).

    Khuyến nghị production: cấu hình TRUSTED_PROXY_COUNT trong settings
    hoặc dùng django-ipware để xử lý multi-proxy chính xác hơn.
    """
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        # Lấy IP cuối cùng — do proxy tin cậy (Nginx) thêm vào, khó giả mạo hơn
        return x_forwarded_for.split(',')[-1].strip()
    return request.META.get('REMOTE_ADDR', '')