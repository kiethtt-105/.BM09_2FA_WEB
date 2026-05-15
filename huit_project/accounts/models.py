"""
models.py — Hệ thống HUIT 2FA
==============================
Schema tối ưu: 7 bảng (giảm từ 11)

  Đã xóa:
    - OTP              : deprecated, không có is_used/hash, không dùng trong code
    - User2FA          : trùng UserProfile (4 cột boolean + google_secret plaintext)
    - LoginHistory     : trùng ActivityLog, không có view nào query
    - UserSessionControl: 1 boolean → gộp vào UserProfile.force_logout

  Đã gộp vào UserProfile:
    - force_disable_2fa, is_required (từ User2FA)
    - force_logout (từ UserSessionControl)

  Đã xóa khỏi UserProfile:
    - email_otp, otp_expiry : OTP tạm → EmailOTP là nguồn sự thật duy nhất
    - fido2_credential      : JSONField không dùng, UserPasskey thay thế
    - has_fido2             : boolean không đồng bộ → thay bằng property
"""

from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.utils import timezone
from django.conf import settings
from cryptography.fernet import Fernet

import datetime
import hashlib
import uuid


# ════════════════════════════════════════════════════════════════════════════
# 1. UserProfile
# ════════════════════════════════════════════════════════════════════════════
class UserProfile(models.Model):
    """
    Mở rộng User Django bằng OneToOne.

    Bảo mật otp_secret:
        Luôn lưu dạng Fernet-encrypted (AES-128-CBC).
        ENCRYPTION_KEY phải là Fernet key hợp lệ (44 ký tự Base64url).

    Quản lý 2FA:
        has_app_otp / has_email_otp : user tự bật/tắt qua dashboard.
        force_disable_2fa           : admin ép tắt, ưu tiên cao hơn cờ user.
        is_required                 : admin ép user phải bật 2FA.
        force_logout                : admin đặt True → middleware logout user ở request kế tiếp.

    FIDO2:
        Không lưu cờ has_fido2 — kiểm tra qua property user.passkeys.exists().
    """

    user = models.OneToOneField(
        User, on_delete=models.CASCADE, related_name='profile'
    )

    middle_name  = models.CharField('Chữ đệm',       max_length=50, blank=True, default='')
    phone_number = models.CharField('Số điện thoại', max_length=15, blank=True, default='')

    otp_secret = models.CharField(max_length=255, blank=True, null=True)

    has_app_otp   = models.BooleanField(default=False, verbose_name='Đã bật App OTP')
    has_email_otp = models.BooleanField(default=False, verbose_name='Đã bật Email OTP')

    force_disable_2fa = models.BooleanField(default=False, verbose_name='Admin tắt buộc 2FA')
    is_required       = models.BooleanField(default=False, verbose_name='Bắt buộc bật 2FA')
    force_logout      = models.BooleanField(default=False, verbose_name='Cưỡng chế đăng xuất')

    class Meta:
        verbose_name        = 'Hồ sơ người dùng'
        verbose_name_plural = 'Hồ sơ người dùng'

    def encrypt_secret(self, raw_secret: str) -> str:
        """Mã hóa TOTP secret bằng Fernet trước khi lưu DB."""
        if not raw_secret:
            return None
        f = Fernet(settings.ENCRYPTION_KEY.encode())
        return f.encrypt(raw_secret.encode()).decode()

    def decrypt_secret(self) -> str:
        """
        Giải mã TOTP secret.
        Token Fernet nhận dạng bằng tiền tố 'gAAAA'.
        Trả None nếu không giải mã được — không bao giờ trả plaintext không xác thực.
        """
        if not self.otp_secret:
            return None
        try:
            if self.otp_secret.startswith('gAAAA'):
                f = Fernet(settings.ENCRYPTION_KEY.encode())
                return f.decrypt(self.otp_secret.encode()).decode()
            return None
        except Exception:
            return None

    def save(self, *args, **kwargs):
        """Tự động mã hóa otp_secret nếu chưa qua Fernet."""
        if self.otp_secret and not self.otp_secret.startswith('gAAAA'):
            self.otp_secret = self.encrypt_secret(self.otp_secret)
        super().save(*args, **kwargs)

    def __str__(self):
        return f'Profile({self.user.username})'

    @property
    def is_2fa_enabled(self) -> bool:
        """True nếu bật ít nhất 1 phương thức 2FA và admin không ép tắt."""
        if self.force_disable_2fa:
            return False
        return self.has_email_otp or self.has_app_otp

    @property
    def has_fido2(self) -> bool:
        """Kiểm tra trực tiếp từ UserPasskey — không cần cờ boolean riêng."""
        return self.user.passkeys.exists()

    def get_full_name(self) -> str:
        parts = [self.user.first_name, self.middle_name, self.user.last_name]
        return ' '.join(p for p in parts if p)


# ════════════════════════════════════════════════════════════════════════════
# 2. PendingRegistration
# ════════════════════════════════════════════════════════════════════════════
class PendingRegistration(models.Model):
    """
    Lưu thông tin đăng ký tạm thời trước khi OTP xác thực thành công.

    Luồng:
        1. User điền form → tạo bản ghi + gửi OTP email.
        2. User xác thực OTP → tạo User thật → xóa bản ghi.

    Bảo mật:
        temp_data['password'] là chuỗi đã qua make_password() — không lưu plaintext.
        OTP_EXPIRY_MINUTES = 10 phút.
    """

    email      = models.EmailField(unique=True)
    otp_code   = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    is_used    = models.BooleanField(default=False)
    temp_data  = models.JSONField(default=dict)

    OTP_EXPIRY_MINUTES = 10

    class Meta:
        verbose_name        = 'Đăng ký tạm chờ xác thực'
        verbose_name_plural = 'Đăng ký tạm chờ xác thực'

    def is_valid(self) -> bool:
        expiry = self.created_at + datetime.timedelta(minutes=self.OTP_EXPIRY_MINUTES)
        return not self.is_used and timezone.now() < expiry

    def __str__(self):
        return f'PendingReg({self.email})'


# ════════════════════════════════════════════════════════════════════════════
# 3. EmailOTP
# ════════════════════════════════════════════════════════════════════════════
class EmailOTP(models.Model):
    """
    Audit trail cho toàn bộ OTP email đã phát hành.
    Đây là nguồn sự thật duy nhất cho xác thực OTP — không lưu OTP vào UserProfile.

    Hai lớp lưu trữ (thiết kế có chủ ý cho đồ án demo):
        otp_code  : plaintext — để hội đồng kiểm tra trực quan luồng OTP.
        otp_hash  : SHA-256(otp_code) — dùng để so sánh khi xác thực.

    Lưu ý: production thực tế chỉ lưu otp_hash, không lưu plaintext.
    """

    ACTION_CHOICES = [
        ('register',    'Đăng ký tài khoản'),
        ('login_2fa',   'Đăng nhập 2FA'),
        ('setup_2fa',   'Thiết lập Email 2FA'),
        ('update_info', 'Cập nhật thông tin'),
        ('disable_2fa', 'Tắt Email 2FA'),
    ]

    user = models.ForeignKey(
        User, on_delete=models.CASCADE,
        null=True, blank=True,
        verbose_name='Người dùng'
    )
    otp_code = models.CharField(max_length=6,  verbose_name='Mã OTP (plaintext demo)')
    otp_hash = models.CharField(max_length=64, blank=True, null=True,
                                verbose_name='Mã OTP SHA-256')

    action     = models.CharField(max_length=20, choices=ACTION_CHOICES,
                                  default='login_2fa', verbose_name='Loại thao tác')
    ip_address = models.CharField(max_length=50,  blank=True, null=True, verbose_name='Địa chỉ IP')
    email_sent = models.CharField(max_length=254, blank=True, null=True, verbose_name='Email đích')

    created_at = models.DateTimeField(auto_now_add=True, verbose_name='Thời điểm tạo')
    used_at    = models.DateTimeField(blank=True, null=True, verbose_name='Thời điểm sử dụng')
    is_used    = models.BooleanField(default=False, verbose_name='Đã sử dụng')
    is_active  = models.BooleanField(default=True,  verbose_name='Đang hiệu lực')

    OTP_VALID_MINUTES = 3

    class Meta:
        ordering            = ['-created_at']
        verbose_name        = 'Email OTP Log'
        verbose_name_plural = 'Email OTP Logs'

    def save(self, *args, **kwargs):
        if self.otp_code and not self.otp_hash:
            self.otp_hash = hashlib.sha256(self.otp_code.encode('utf-8')).hexdigest()
        super().save(*args, **kwargs)

    def is_valid(self) -> bool:
        return (
            not self.is_used
            and self.is_active
            and timezone.now() < self.created_at + datetime.timedelta(minutes=self.OTP_VALID_MINUTES)
        )

    def mark_used(self):
        self.is_used = True
        self.used_at = timezone.now()
        self.save(update_fields=['is_used', 'used_at'])

    def disable(self):
        self.is_active = False
        self.save(update_fields=['is_active'])

    def __str__(self):
        username = self.user.username if self.user else 'pending'
        return (
            f'EmailOTP({username} | '
            f'{self.get_action_display()} | '
            f'{self.created_at.strftime("%d/%m/%Y %H:%M")})'
        )


# ════════════════════════════════════════════════════════════════════════════
# 4. ActivityLog
# ════════════════════════════════════════════════════════════════════════════
class ActivityLog(models.Model):
    """
    Nhật ký toàn bộ sự kiện bảo mật.
    Thay thế hoàn toàn LoginHistory (đã xóa khỏi schema).

    username_attempt lưu tên đăng nhập thô kể cả khi user không tồn tại
    — dùng để phát hiện brute-force theo tên đăng nhập.
    """

    ACTION_CHOICES = [
        ('login',                'Đăng nhập thành công'),
        ('logout',               'Đăng xuất'),
        ('login_failed',         'Đăng nhập thất bại'),
        ('login_locked_attempt', 'Đăng nhập tài khoản bị khóa'),
        ('force_logout',         'Admin cưỡng chế đăng xuất'),
        ('otp_fail',             'Xác thực OTP thất bại'),
        ('otp_success',          'Xác thực OTP thành công'),
        ('2fa_enable',           'Bật bảo mật 2FA'),
        ('2fa_disable',          'Tắt bảo mật 2FA'),
        ('register',             'Đăng ký tài khoản'),
    ]

    user = models.ForeignKey(
        User, on_delete=models.CASCADE,
        related_name='activities', null=True, blank=True,
        verbose_name='Người dùng'
    )
    username_attempt = models.CharField(max_length=150, null=True, blank=True,
                                        verbose_name='Tên đăng nhập thử')
    action     = models.CharField(max_length=30, choices=ACTION_CHOICES, verbose_name='Hành động')
    ip_address = models.CharField(max_length=50, blank=True, null=True, verbose_name='Địa chỉ IP')
    user_agent = models.TextField(blank=True, null=True, verbose_name='User-Agent')
    timestamp  = models.DateTimeField(auto_now_add=True, verbose_name='Thời điểm')

    class Meta:
        ordering            = ['-timestamp']
        verbose_name        = 'Nhật ký hoạt động'
        verbose_name_plural = 'Nhật ký hoạt động'

    def __str__(self):
        username = self.user.username if self.user else self.username_attempt
        return f'{username} — {self.get_action_display()} — {self.timestamp.strftime("%d/%m/%Y %H:%M")}'


# ════════════════════════════════════════════════════════════════════════════
# 5. TrustedDevice
# ════════════════════════════════════════════════════════════════════════════
class TrustedDevice(models.Model):
    """
    Mỗi session đăng nhập 2FA thành công được ghi vào đây.

    Vai trò:
        - Hiển thị danh sách thiết bị đang online.
        - Push auth: thiết bị lạ gửi yêu cầu → thiết bị online xác nhận.
        - Logout từ xa: xóa Django session tương ứng.

    is_active = False khi user tự logout, admin force_logout, hoặc session Django hết hạn.
    """

    user        = models.ForeignKey(User, on_delete=models.CASCADE, related_name='trusted_devices')
    device_id   = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    session_key = models.CharField(max_length=40, blank=True, null=True)
    name        = models.CharField(max_length=255, default='Thiết bị không xác định')
    user_agent  = models.TextField(blank=True, null=True)
    ip_address  = models.CharField(max_length=50, blank=True, null=True)
    last_seen   = models.DateTimeField(auto_now=True)
    is_active   = models.BooleanField(default=True)

    class Meta:
        verbose_name        = 'Thiết bị tin cậy'
        verbose_name_plural = 'Thiết bị tin cậy'

    def __str__(self):
        return f'{self.user.username} — {self.name}'


# ════════════════════════════════════════════════════════════════════════════
# 6. RemoteAuthRequest
# ════════════════════════════════════════════════════════════════════════════
class RemoteAuthRequest(models.Model):
    """
    Yêu cầu xác thực đẩy khi đăng nhập từ thiết bị lạ.

    Luồng push auth:
        1. Thiết bị lạ tạo bản ghi status='pending'.
        2. Thiết bị online polling /get_pending_auth_request/.
        3. Thiết bị online gọi /respond_auth_request/<id>/?status=approved|denied.
        4. Thiết bị lạ polling /check_auth_status/ → đăng nhập hoặc từ chối.

    Bản ghi bị xóa ngay sau khi xử lý xong.
    """

    STATUS_CHOICES = [
        ('pending',  'Chờ xác nhận'),
        ('approved', 'Đã đồng ý'),
        ('denied',   'Đã từ chối'),
    ]

    user        = models.ForeignKey(User, on_delete=models.CASCADE)
    session_key = models.CharField(max_length=40)
    device_info = models.CharField(max_length=255)
    status      = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    created_at  = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name        = 'Yêu cầu xác thực từ xa'
        verbose_name_plural = 'Yêu cầu xác thực từ xa'

    def __str__(self):
        return f'RemoteAuth({self.user.username} | {self.status})'


# ════════════════════════════════════════════════════════════════════════════
# 7. UserPasskey
# ════════════════════════════════════════════════════════════════════════════
class UserPasskey(models.Model):
    """
    FIDO2 / WebAuthn passkey credential.

    Mỗi user có thể đăng ký nhiều passkey (đa thiết bị).
    sign_count tăng mỗi lần xác thực — nếu giảm đột ngột → credential có thể bị clone.
    public_key lưu dạng CBOR-encoded Base64url.
    """

    user          = models.ForeignKey(User, on_delete=models.CASCADE, related_name='passkeys')
    credential_id = models.CharField(max_length=500, unique=True)
    public_key    = models.TextField()
    sign_count    = models.IntegerField(default=0)
    created_at    = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name        = 'Passkey (FIDO2)'
        verbose_name_plural = 'Passkeys (FIDO2)'

    def __str__(self):
        return f'Passkey của {self.user.username}'


# ════════════════════════════════════════════════════════════════════════════
# SIGNALS
# ════════════════════════════════════════════════════════════════════════════

@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    """
    Tự động tạo UserProfile khi User mới được tạo.
    Chỉ chạy khi created=True để tránh query thừa mỗi lần User.save().
    Signal save_user_profile (cũ) đã xóa — get_or_create trong create_user_profile đủ an toàn.
    """
    if created:
        UserProfile.objects.get_or_create(user=instance)