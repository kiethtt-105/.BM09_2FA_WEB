import qrcode, io, base64, time, hmac, hashlib
import secrets
from django.core.mail import send_mail
from .models import EmailOTP

def generate_qr_base64(username, secret):
    # Tạo URI chuẩn cho Google Auth/iCloud
    uri = f"otpauth://totp/HUIT_2FA:{username}?secret={secret}&issuer=HUIT_2FA"
    qr = qrcode.QRCode(version=1, box_size=10, border=2)
    qr.add_data(uri)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()

def get_totp_token(secret):
    try:
        # Tự động thêm padding '=' nếu thiếu để base64 không báo lỗi
        missing_padding = len(secret) % 8
        if missing_padding:
            secret += '=' * (8 - missing_padding)
        
        key = base64.b32decode(secret.upper(), casefold=True)
        msg = int(time.time() / 30).to_bytes(8, 'big')
        h = hmac.new(key, msg, hashlib.sha1).digest()
        o = h[19] & 15
        bin_code = ((h[o] & 127) << 24 | (h[o+1] & 255) << 16 | (h[o+2] & 255) << 8 | (h[o+3] & 255))
        return str(bin_code % 1000000).zfill(6)
    except:
        return "000000"

def generate_and_send_email_otp(user):
    # 1. Sinh mã 6 số ngẫu nhiên bảo mật
    otp_code = ''.join([str(secrets.randbelow(10)) for _ in range(6)])
    
    # 2. Lưu vào Database
    EmailOTP.objects.create(user=user, otp_code=otp_code)
    
    # 3. Gửi Mail qua SMTP [cite: 48]
    subject = 'Mã xác thực 2FA của bạn'
    message = f'Mã OTP của bạn là: {otp_code}. Mã có hiệu lực trong 5 phút.'
    send_mail(subject, message, 'HUIT_Auth <your-email@gmail.com>', [user.email])
    
    return otp_code
# Utility để lấy IP người dùng từ request (dùng cho logging)
def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip