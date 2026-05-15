"""
utils.py — Tiện ích hệ thống HUIT 2FA
=======================================
Các thành phần:
  1. HOTP (RFC 4226) — tự cài đặt 100%, không dùng thư viện
  2. TOTP (RFC 6238) — tự cài đặt 100%, không dùng thư viện
  3. QR Code generator
  4. generate_and_send_email_otp — email nội dung theo action
  5. get_client_ip
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

    # Đổi từng ký tự Base32 → 5 bit
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
    """
    Tính HMAC-SHA1 thủ công dùng module hmac chuẩn Python (không phụ thuộc thư viện 2FA).
    hmac là module chuẩn Python — không phải thư viện bên thứ 3.
    """
    return hmac.new(key, msg, hashlib.sha1).digest()


def _dynamic_truncate(h: bytes) -> int:
    """
    Dynamic Truncation theo RFC 4226 §5.3.
    Lấy 4 byte từ offset = 4 bit cuối của byte cuối hash.
    Mask bit dấu (MSB) để luôn có số dương.
    """
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

    Công thức:
        HOTP(K, C) = Truncate(HMAC-SHA1(K, C)) mod 10^digits

    Tham số:
        secret  : Secret key dạng Base32 (như Google Authenticator).
        counter : Giá trị đếm (counter) — phải đồng bộ giữa client và server.
        digits  : Số chữ số mã OTP (mặc định 6).

    Trả về:
        Chuỗi OTP digits chữ số (có leading zero nếu cần).

    Khác TOTP ở chỗ:
        HOTP dùng counter tăng dần (event-based).
        TOTP dùng counter = floor(time / 30) (time-based).

    RFC 4226: https://www.rfc-editor.org/rfc/rfc4226
    """
    if not secret:
        return '0' * digits

    try:
        key = _base32_decode(secret)

        # Counter → 8 byte big-endian (RFC 4226 §5.2)
        msg = struct.pack('>Q', counter)

        h    = _hmac_sha1(key, msg)
        code = _dynamic_truncate(h) % (10 ** digits)
        return str(code).zfill(digits)

    except Exception as exc:
        logger.error('compute_hotp error: %s', exc)
        return '0' * digits


def verify_hotp(secret: str, counter: int, otp_input: str,
                look_ahead: int = 5) -> tuple[bool, int]:
    """
    Xác thực HOTP với cửa sổ look-ahead.

    Vì counter phải đồng bộ, server cho phép client trễ tối đa look_ahead bước.
    Nếu xác thực thành công → trả về (True, counter_matched + 1) để server cập nhật.
    Nếu thất bại            → trả về (False, counter).

    Tham số:
        look_ahead : Số bước server chấp nhận trước (mặc định 5 theo RFC 4226 §7.4).

    Ví dụ sử dụng:
        ok, new_counter = verify_hotp(secret, stored_counter, user_input)
        if ok:
            profile.hotp_counter = new_counter
            profile.save()
    """
    for i in range(look_ahead):
        expected = compute_hotp(secret, counter + i)
        if hmac.compare_digest(expected, otp_input.zfill(6)):
            return True, counter + i + 1
    return False, counter


# ═══════════════════════════════════════════════════════════════════════════════
# 2. TOTP — RFC 6238 
# ═══════════════════════════════════════════════════════════════════════════════

def compute_totp(secret: str, digits: int = 6, step: int = 30,
                 t0: int = 0, at_time: float = None) -> str:
    """
    Tính mã TOTP theo RFC 6238.

    TOTP là trường hợp đặc biệt của HOTP với:
        counter = floor((T - T0) / X)
    trong đó:
        T  = Unix timestamp hiện tại (giây)
        T0 = thời điểm gốc (mặc định 0 = Unix epoch)
        X  = bước thời gian (mặc định 30 giây)

    Tham số:
        secret  : Secret key Base32.
        digits  : Số chữ số OTP (mặc định 6).
        step    : Bước thời gian giây (mặc định 30).
        t0      : Unix epoch gốc (mặc định 0).
        at_time : Thời điểm tính (mặc định = now). Dùng để test.

    RFC 6238: https://www.rfc-editor.org/rfc/rfc6238
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
    Xác thực TOTP với cửa sổ time-window.

    Cho phép lệch tối đa ±window bước (mặc định ±1 bước = ±30 giây)
    để xử lý độ trễ mạng và clock drift nhỏ giữa client/server.

    hmac.compare_digest dùng để tránh timing attack.
    """
    now = time.time()
    for delta in range(-window, window + 1):
        candidate = compute_totp(secret, digits=digits, step=step,
                                 at_time=now + delta * step)
        if hmac.compare_digest(candidate, otp_input.zfill(digits)):
            return True
    return False


# ═══════════════════════════════════════════════════════════════════════════════
# Backward-compatible alias (views.py gọi get_totp_token)
# ═══════════════════════════════════════════════════════════════════════════════

def get_totp_token(secret: str) -> str:
    """Alias của compute_totp để giữ backward compatibility với views.py."""
    return compute_totp(secret)


# ═══════════════════════════════════════════════════════════════════════════════
# 3. QR Code
# ═══════════════════════════════════════════════════════════════════════════════

def generate_qr_base64(username: str, secret: str,
                       otp_type: str = 'totp') -> str:
    """
    Tạo QR code theo chuẩn otpauth://totp|hotp URI và trả về Base64 PNG.

    URI chuẩn RFC — tương thích Google Authenticator, Aegis, iCloud Keychain.
    Dùng trực tiếp trong <img src="data:image/png;base64,...">

    Tham số:
        otp_type : 'totp' hoặc 'hotp'. HOTP cần thêm &counter=0.
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
# 4. Email OTP — nội dung tùy theo action
# ═══════════════════════════════════════════════════════════════════════════════

# Map action → (subject, body_template)
# body_template nhận format string với {otp_code} và {name}
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
    email: str,
    action: str  = 'login_2fa',
    ip:    str   = None,
    subject: str = None,
    body:    str = None,
    name:    str = None,
) -> str:
    """
    Sinh mã OTP 6 chữ số, lưu DB (chỉ hash — không lưu plaintext), gửi qua Email.

    Tham số:
        user    : User object hoặc None (khi đăng ký chưa tạo User).
        email   : Địa chỉ email nhận OTP.
        action  : Loại thao tác — quyết định nội dung email.
                  Giá trị hợp lệ: 'register', 'login_2fa', 'setup_2fa',
                                  'disable_2fa', 'update_info'.
        ip      : Địa chỉ IP client (cho audit log).
        subject : Override tiêu đề email (None = dùng template).
        body    : Override nội dung email (None = dùng template).
        name    : Tên hiển thị trong email (None = lấy từ user hoặc 'Bạn').

    Bảo mật:
        - Mã OTP sinh bằng secrets.randbelow → CSPRNG.
        - DB chỉ lưu SHA-256(otp_code) — không lưu plaintext.
        - Plaintext chỉ tồn tại trong bộ nhớ RAM và nội dung email.

    Trả về:
        str: Mã OTP vừa sinh (chỉ dùng nội bộ để gửi email — không lưu DB).
    """
    # ── Sinh OTP ─────────────────────────────────────────────────────────
    otp_code = ''.join(str(secrets.randbelow(10)) for _ in range(6))

    # ── Lưu DB: chỉ lưu hash, không lưu plaintext ────────────────────────
    EmailOTP.objects.create(
        user       = user,
        otp_code   = otp_code,   # model.save() tự hash → otp_hash, xóa otp_code sau
        action     = action,
        ip_address = ip,
        email_sent = email,
        is_used    = False,
        is_active  = True,
    )

    # ── Xây nội dung email theo action ───────────────────────────────────
    display_name = name
    if not display_name and user:
        display_name = (
            f'{user.first_name} {user.last_name}'.strip()
            or user.username
        )
    display_name = display_name or 'Bạn'

    if subject and body:
        # Caller truyền thẳng → dùng luôn
        final_subject = subject
        final_body    = body
    else:
        tmpl_subject, tmpl_body = _EMAIL_TEMPLATES.get(action, _EMAIL_TEMPLATE_DEFAULT)
        final_subject = subject or tmpl_subject
        final_body    = body    or tmpl_body.format(otp_code=otp_code, name=display_name)

    # ── Gửi email ─────────────────────────────────────────────────────────
    send_mail(
        subject        = final_subject,
        message        = final_body,
        from_email     = None,   # Django dùng DEFAULT_FROM_EMAIL từ settings
        recipient_list = [email],
        fail_silently  = False,
    )

    return otp_code


# ═══════════════════════════════════════════════════════════════════════════════
# 5. IP Client
# ═══════════════════════════════════════════════════════════════════════════════

def get_client_ip(request) -> str:
    """
    Lấy địa chỉ IP thực của client.
    Ưu tiên X-Forwarded-For khi chạy sau Nginx/proxy.
    Fallback về REMOTE_ADDR.

    Lưu ý production: X-Forwarded-For có thể bị giả mạo nếu không
    cấu hình trusted proxy. Nên dùng django-ipware hoặc TRUSTED_PROXY_LIST.
    """
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR')