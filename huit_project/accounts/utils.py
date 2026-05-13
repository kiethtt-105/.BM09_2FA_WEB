import qrcode
import io
import base64
import time
import hmac
import hashlib
import secrets
import logging

from django.core.mail import send_mail
from django.conf import settings

from .models import EmailOTP

logger = logging.getLogger(__name__)


def generate_qr_base64(username: str, secret: str) -> str:
    """
    Tạo ảnh QR code theo chuẩn otpauth://totp và trả về chuỗi Base64.
    URI tương thích Google Authenticator, Aegis, iCloud Keychain (RFC 6238).

    Trả về chuỗi Base64 PNG — dùng trực tiếp trong <img src="data:image/png;base64,...">
    """
    uri = f"otpauth://totp/HUIT_2FA:{username}?secret={secret}&issuer=HUIT_2FA"

    qr = qrcode.QRCode(version=1, box_size=10, border=2)
    qr.add_data(uri)
    qr.make(fit=True)  # fit=True tự điều chỉnh version nếu data dài

    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()


def get_totp_token(secret: str) -> str:
    """
    Tính mã TOTP 6 chữ số hiện tại từ secret key Base32.
    Thuật toán HMAC-SHA1 theo RFC 6238, bước thời gian 30 giây.

    Trả về chuỗi 6 chữ số, ví dụ "047382".
    Trả về "000000" nếu secret không hợp lệ.
    """
    if not secret:
        return "000000"

    try:
        # Base32 cần độ dài bội số 8 — bổ sung padding nếu thiếu
        missing_padding = len(secret) % 8
        if missing_padding:
            secret += '=' * (8 - missing_padding)

        key = base64.b32decode(secret.upper(), casefold=True)

        # Số bước 30-giây kể từ Unix epoch → 8 byte big-endian
        msg = int(time.time() / 30).to_bytes(8, 'big')

        h = hmac.new(key, msg, hashlib.sha1).digest()

        # Dynamic truncation theo RFC 4226 §5.4
        offset = h[19] & 0x0F
        code = (
            ((h[offset]     & 0x7F) << 24) |
            ((h[offset + 1] & 0xFF) << 16) |
            ((h[offset + 2] & 0xFF) <<  8) |
             (h[offset + 3] & 0xFF)
        )
        return str(code % 1_000_000).zfill(6)

    except Exception as exc:
        logger.error("get_totp_token error: %s", exc)
        return "000000"


def generate_and_send_email_otp(
    user,
    email: str,
    action: str  = 'login_2fa',
    ip:    str   = None,
    subject: str = None,
    body:    str = None,
) -> str:
    """
    Sinh mã OTP 6 chữ số bảo mật, lưu DB, gửi qua Email.

    user    : User object hoặc None (khi đăng ký chưa tạo User).
    email   : Địa chỉ email nhận OTP.
    action  : Loại hành động để phân loại audit log.
    ip      : Địa chỉ IP client.
    subject : Tiêu đề email — dùng mặc định nếu None.
    body    : Nội dung email — dùng mặc định nếu None.

    Trả về mã OTP vừa sinh (6 chữ số).
    """
    # secrets.randbelow đảm bảo entropy tốt hơn random.randint
    otp_code = ''.join(str(secrets.randbelow(10)) for _ in range(6))

    EmailOTP.objects.create(
        user       = user,
        otp_code   = otp_code,
        action     = action,
        ip_address = ip,
        email_sent = email,
        is_used    = False,
        is_active  = True,
    )

    final_subject = subject or 'Mã xác thực 2FA của bạn - HUIT'
    final_body    = body or (
        f'Mã OTP của bạn là: {otp_code}\n\n'
        f'Mã có hiệu lực trong 3 phút. Không chia sẻ mã này với ai.\n\n'
        f'Trân trọng,\nHUIT System'
    )

    # from_email=None → Django tự dùng DEFAULT_FROM_EMAIL từ settings
    send_mail(
        subject        = final_subject,
        message        = final_body,
        from_email     = None,
        recipient_list = [email],
        fail_silently  = False,
    )

    return otp_code


def get_client_ip(request) -> str:
    """
    Lấy địa chỉ IP thực của client.
    Ưu tiên X-Forwarded-For (khi chạy sau Nginx/proxy).
    Fallback về REMOTE_ADDR nếu không có proxy.

    X-Forwarded-For có thể bị giả mạo nếu không cấu hình trusted proxy.
    Production nên dùng django-ipware hoặc TRUSTED_PROXY_LIST.
    """
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        # Lấy IP đầu tiên — IP gốc của client
        return x_forwarded_for.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR')
