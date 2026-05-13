from django.db import models
from django.contrib.auth.models import User
from django.contrib.auth.signals import user_logged_in
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.utils import timezone
from django.conf import settings
from cryptography.fernet import Fernet

import datetime
import hashlib
import uuid
import pyotp


# ════════════════════════════════════════════════════════════════════════════
# 1. UserProfile — Thông tin mở rộng, cấu hình 2FA của từng User
# ════════════════════════════════════════════════════════════════════════════
class UserProfile(models.Model):
    """
    Mở rộng User mặc định của Django bằng quan hệ OneToOne.
    otp_secret lưu TOTP secret đã mã hóa Fernet (AES-128-CBC).
    Khóa mã hóa lấy từ settings.ENCRYPTION_KEY.
    """

    user = models.OneToOneField(
        User, on_delete=models.CASCADE, related_name='profile'
    )
    middle_name  = models.CharField('Chữ đệm',       max_length=50,  blank=True, default='')
    phone_number = models.CharField('Số điện thoại', max_length=15,  blank=True, default='')

    # Secret TOTP đã mã hóa Fernet
    otp_secret   = models.CharField(max_length=255, blank=True, null=True)

    has_app_otp   = models.BooleanField(default=False, verbose_name="Đã bật App OTP")
    has_email_otp = models.BooleanField(default=False, verbose_name="Đã bật Email OTP")
    has_fido2     = models.BooleanField(default=False, verbose_name="Đã bật FIDO2")

    # OTP tạm thời cho email OTP và update-info flow
    email_otp  = models.CharField(max_length=6,  blank=True, null=True)
    otp_expiry = models.DateTimeField(blank=True, null=True)

    # FIDO2 credential JSON (dự phòng — chủ yếu dùng bảng UserPasskey)
    fido2_credential = models.JSONField(null=True, blank=True)

    class Meta:
        verbose_name = "Hồ sơ người dùng"

    def encrypt_secret(self, raw_secret: str) -> str:
        """Mã hóa TOTP secret bằng Fernet trước khi lưu DB."""
        if not raw_secret:
            return None
        f = Fernet(settings.ENCRYPTION_KEY.encode())
        return f.encrypt(raw_secret.encode()).decode()

    def decrypt_secret(self) -> str:
        """
        Giải mã TOTP secret.
        Token Fernet bắt đầu bằng 'gAAAA' — nhận dạng để phân biệt với dữ liệu cũ.
        Nếu giải mã thất bại (key sai, dữ liệu hỏng) → trả None thay vì raise exception.
        """
        if not self.otp_secret:
            return None
        try:
            if self.otp_secret.startswith('gAAAA'):
                f = Fernet(settings.ENCRYPTION_KEY.encode())
                return f.decrypt(self.otp_secret.encode()).decode()
            # Dữ liệu cũ chưa mã hóa — cần migrate sang Fernet ở production
            return self.otp_secret
        except Exception:
            return None

    def save(self, *args, **kwargs):
        """Tự động mã hóa otp_secret nếu chưa được mã hóa Fernet."""
        if self.otp_secret and not self.otp_secret.startswith('gAAAA'):
            self.otp_secret = self.encrypt_secret(self.otp_secret)
        super().save(*args, **kwargs)

    def __str__(self):
        return f"Profile({self.user.username})"

    @property
    def is_2fa_enabled(self) -> bool:
        """True nếu user đã bật ít nhất một phương thức 2FA."""
        return self.has_email_otp or self.has_app_otp

    def get_full_name(self) -> str:
        """Ghép họ + chữ đệm + tên, bỏ qua phần rỗng."""
        parts = [self.user.first_name, self.middle_name, self.user.last_name]
        return ' '.join(p for p in parts if p)


# ════════════════════════════════════════════════════════════════════════════
# 2. PendingRegistration — Lưu tạm dữ liệu đăng ký chờ xác thực OTP
# ════════════════════════════════════════════════════════════════════════════
class PendingRegistration(models.Model):
    """
    Lưu thông tin đăng ký tạm thời trước khi người dùng xác thực OTP.

    Luồng:
        1. User điền form → tạo PendingRegistration + gửi OTP email.
        2. User nhập OTP → is_valid() → tạo User thật → xóa bản ghi này.

    temp_data['password'] lưu plaintext vì chưa tạo User — xóa ngay sau xác thực.
    """

    email      = models.EmailField(unique=True)
    otp_code   = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    is_used    = models.BooleanField(default=False)
    temp_data  = models.JSONField(default=dict)

    OTP_EXPIRY_MINUTES = 10

    class Meta:
        verbose_name = "Đăng ký tạm chờ xác thực"

    def is_valid(self) -> bool:
        """OTP còn hợp lệ: chưa dùng và chưa quá OTP_EXPIRY_MINUTES."""
        expiry = self.created_at + datetime.timedelta(minutes=self.OTP_EXPIRY_MINUTES)
        return not self.is_used and timezone.now() < expiry

    def __str__(self):
        return f"PendingReg({self.email})"


# ════════════════════════════════════════════════════════════════════════════
# 3. EmailOTP — Audit trail toàn bộ OTP email đã phát hành
# ════════════════════════════════════════════════════════════════════════════
class EmailOTP(models.Model):
    """
    Hai lớp lưu trữ:
      otp_code  — plaintext, chỉ để xem trực quan trong DEMO
      otp_hash  — SHA-256(otp_code), tính tự động trong save()

    Thời gian hiệu lực: 3 phút (kiểm tra trong is_valid()).
    user có thể là None khi OTP dùng cho đăng ký (chưa có User thật).
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
        verbose_name="Người dùng"
    )

    otp_code = models.CharField(max_length=6, verbose_name="Mã OTP (plaintext)")
    otp_hash = models.CharField(
        max_length=64, blank=True, null=True,
        verbose_name="Mã OTP đã băm SHA-256"
    )

    action = models.CharField(
        max_length=20, choices=ACTION_CHOICES, default='login_2fa',
        verbose_name="Loại thao tác"
    )
    ip_address = models.CharField(max_length=50, blank=True, null=True, verbose_name="Địa chỉ IP")
    email_sent = models.CharField(max_length=254, blank=True, null=True, verbose_name="Email đích")

    created_at = models.DateTimeField(auto_now_add=True, verbose_name="Thời điểm tạo")
    used_at    = models.DateTimeField(blank=True, null=True, verbose_name="Thời điểm sử dụng")
    is_used    = models.BooleanField(default=False, verbose_name="Đã sử dụng")
    is_active  = models.BooleanField(default=True,  verbose_name="Đang hiệu lực")

    class Meta:
        ordering     = ['-created_at']
        verbose_name = "Email OTP Log"

    def save(self, *args, **kwargs):
        """Tự động tính SHA-256 khi tạo mới (chỉ hash lần đầu)."""
        if self.otp_code and not self.otp_hash:
            self.otp_hash = hashlib.sha256(self.otp_code.encode('utf-8')).hexdigest()
        super().save(*args, **kwargs)

    def is_valid(self) -> bool:
        """OTP hợp lệ khi: chưa dùng, chưa bị admin vô hiệu, chưa quá 3 phút."""
        return (
            not self.is_used
            and self.is_active
            and timezone.now() < self.created_at + datetime.timedelta(minutes=3)
        )

    def mark_used(self):
        """Đánh dấu OTP đã dùng và ghi thời điểm sử dụng."""
        self.is_used = True
        self.used_at = timezone.now()
        self.save(update_fields=['is_used', 'used_at'])

    def disable(self):
        """Admin vô hiệu hoá OTP thủ công."""
        self.is_active = False
        self.save(update_fields=['is_active'])

    def __str__(self):
        username = self.user.username if self.user else 'pending'
        return (
            f"EmailOTP("
            f"{username} | "
            f"{self.get_action_display()} | "
            f"{self.created_at.strftime('%d/%m/%Y %H:%M')})"
        )


# ════════════════════════════════════════════════════════════════════════════
# 4. ActivityLog — Nhật ký hành động
# ════════════════════════════════════════════════════════════════════════════
class ActivityLog(models.Model):
    """
    Ghi lại mọi sự kiện: đăng nhập, đăng xuất, thao tác 2FA.
    username_attempt lưu tên đăng nhập thô (kể cả khi user không tồn tại)
    để phát hiện brute-force.
    """

    ACTION_CHOICES = [
        ('login',                'Đăng nhập'),
        ('logout',               'Đăng xuất'),
        ('login_failed',         'Đăng nhập thất bại'),
        ('login_locked_attempt', 'Đăng nhập tài khoản bị khoá'),
        ('force_logout',         'Cưỡng chế đăng xuất'),
        ('otp_fail',             'Xác thực OTP thất bại'),
        ('otp_success',          'Xác thực OTP thành công'),
        ('2fa_enable',           'Bật bảo mật 2FA'),
        ('2fa_disable',          'Tắt bảo mật 2FA'),
        ('register',             'Đăng ký tài khoản'),
    ]

    user = models.ForeignKey(
        User, on_delete=models.CASCADE,
        related_name='activities', null=True, blank=True,
        verbose_name="Người dùng"
    )
    username_attempt = models.CharField(max_length=150, null=True, blank=True, verbose_name="Tên đăng nhập thử")
    action     = models.CharField(max_length=30, choices=ACTION_CHOICES, verbose_name="Hành động")
    ip_address = models.CharField(max_length=50, blank=True, null=True, verbose_name="Địa chỉ IP")
    user_agent = models.TextField(blank=True, null=True, verbose_name="User-Agent")
    timestamp  = models.DateTimeField(auto_now_add=True, verbose_name="Thời điểm")

    class Meta:
        ordering     = ['-timestamp']
        verbose_name = "Nhật ký hoạt động"

    def __str__(self):
        username = self.user.username if self.user else self.username_attempt
        return f"{username} - {self.get_action_display()} - {self.timestamp.strftime('%d/%m/%Y %H:%M')}"


# ════════════════════════════════════════════════════════════════════════════
# 5. OTP — Model OTP thế hệ cũ (giữ lại để tương thích migration)
# ════════════════════════════════════════════════════════════════════════════
class OTP(models.Model):
    """
    Không dùng cho tính năng mới.
    Không có is_used → không thể ngăn replay attack.
    Thay thế bằng EmailOTP.
    """
    user       = models.ForeignKey(User, on_delete=models.CASCADE)
    code       = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "OTP (cũ)"

    def is_expired(self) -> bool:
        return timezone.now() > self.created_at + datetime.timedelta(minutes=2)


# ════════════════════════════════════════════════════════════════════════════
# 6. TrustedDevice — Thiết bị đã hoàn thành 2FA
# ════════════════════════════════════════════════════════════════════════════
class TrustedDevice(models.Model):
    """
    Mỗi session đăng nhập thành công được ghi vào đây.
    Khi logout → is_active=False.
    Dùng cho tính năng push auth (xác thực từ thiết bị đang online).
    """

    user        = models.ForeignKey(User, on_delete=models.CASCADE, related_name='trusted_devices')
    device_id   = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    session_key = models.CharField(max_length=40, blank=True, null=True)
    name        = models.CharField(max_length=255, default="Thiết bị không xác định")
    user_agent  = models.TextField(blank=True, null=True)
    ip_address  = models.CharField(max_length=50, blank=True, null=True)
    last_seen   = models.DateTimeField(auto_now=True)
    is_active   = models.BooleanField(default=True)

    class Meta:
        verbose_name = "Thiết bị tin cậy"

    def __str__(self):
        return f"{self.user.username} - {self.name}"


# ════════════════════════════════════════════════════════════════════════════
# 7. User2FA — Cấu hình 2FA do Admin quản lý
# ════════════════════════════════════════════════════════════════════════════
class User2FA(models.Model):
    """
    Tách biệt với UserProfile để admin can thiệp mà không chạm profile.
    force_disable_2fa: admin ép tắt 2FA (dùng khi user bị khóa thiết bị).
    is_required: admin ép user phải bật 2FA.
    """

    user                = models.OneToOneField(User, on_delete=models.CASCADE, related_name='user2fa')
    email_otp_enabled   = models.BooleanField(default=False, verbose_name="Bật Email OTP")
    google_auth_enabled = models.BooleanField(default=False, verbose_name="Bật Google Auth")
    google_secret       = models.CharField(max_length=100, blank=True, null=True)
    force_disable_2fa   = models.BooleanField(default=False, verbose_name="Admin tắt buộc 2FA")
    is_required         = models.BooleanField(default=False, verbose_name="Bắt buộc xác thực 2FA")

    class Meta:
        verbose_name = "Cấu hình 2FA (Admin)"

    def __str__(self):
        return self.user.username

    @property
    def is_enabled(self) -> bool:
        """2FA có hiệu lực không? False nếu admin đã bật force_disable_2fa."""
        if self.force_disable_2fa:
            return False
        return self.email_otp_enabled or self.google_auth_enabled


# ════════════════════════════════════════════════════════════════════════════
# 8. UserSessionControl — Cờ cưỡng chế đăng xuất
# ════════════════════════════════════════════════════════════════════════════
class UserSessionControl(models.Model):
    """
    Admin bật force_logout=True → middleware logout user ở request tiếp theo.
    Sau khi logout → tự đặt lại force_logout=False.
    """
    user         = models.OneToOneField(User, on_delete=models.CASCADE)
    force_logout = models.BooleanField(default=False, verbose_name="Cưỡng chế đăng xuất")

    class Meta:
        verbose_name = "Kiểm soát phiên người dùng"


# ════════════════════════════════════════════════════════════════════════════
# 9. LoginHistory — Lịch sử đăng nhập (ghi qua signal)
# ════════════════════════════════════════════════════════════════════════════
class LoginHistory(models.Model):
    """
    Ghi lịch sử đăng nhập thành công qua Django signal user_logged_in.
    Khi có Nginx/proxy phía trước, IP ghi được có thể là IP của proxy.
    Dùng get_client_ip(request) từ utils.py để lấy IP chính xác hơn.
    """
    user   = models.ForeignKey(User, on_delete=models.CASCADE)
    ip     = models.GenericIPAddressField()
    device = models.CharField(max_length=255)
    time   = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=50)

    class Meta:
        verbose_name        = "Lịch sử đăng nhập"
        verbose_name_plural = "Lịch sử đăng nhập"


# ════════════════════════════════════════════════════════════════════════════
# 10. RemoteAuthRequest — Yêu cầu xác thực đẩy từ thiết bị lạ
# ════════════════════════════════════════════════════════════════════════════
class RemoteAuthRequest(models.Model):
    """
    Luồng push auth:
      1. Thiết bị lạ tạo RemoteAuthRequest(status='pending').
      2. Thiết bị online polling /get_pending_auth_request/ → thấy yêu cầu.
      3. Thiết bị online gọi /respond_auth_request/<id>/?status=approved|denied.
      4. Thiết bị lạ polling /check_auth_status/ → nhận kết quả.
    """

    STATUS_CHOICES = [
        ('pending',  'Chờ'),
        ('approved', 'Đồng ý'),
        ('denied',   'Từ chối'),
    ]

    user        = models.ForeignKey(User, on_delete=models.CASCADE)
    session_key = models.CharField(max_length=40)
    device_info = models.CharField(max_length=255)
    status      = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    created_at  = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Yêu cầu xác thực từ xa"

    def __str__(self):
        return f"RemoteAuth({self.user.username} | {self.status})"


# ════════════════════════════════════════════════════════════════════════════
# 11. UserPasskey — FIDO2 / WebAuthn Credential
# ════════════════════════════════════════════════════════════════════════════
class UserPasskey(models.Model):
    """
    Mỗi user có thể đăng ký nhiều passkey (đa thiết bị).
    sign_count tăng dần mỗi lần xác thực — nếu giảm đột ngột → nguy cơ credential bị clone.
    """

    user          = models.ForeignKey(User, on_delete=models.CASCADE, related_name="passkeys")
    credential_id = models.CharField(max_length=500, unique=True)
    public_key    = models.TextField()
    sign_count    = models.IntegerField(default=0)
    created_at    = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Passkey (FIDO2)"

    def __str__(self):
        return f"Passkey của {self.user.username}"


# ════════════════════════════════════════════════════════════════════════════
# SIGNALS
# ════════════════════════════════════════════════════════════════════════════

@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    """Tự động tạo UserProfile mỗi khi có User mới."""
    if created:
        UserProfile.objects.get_or_create(user=instance)


@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    """
    Đồng bộ UserProfile khi User được save.
    get_or_create đảm bảo không crash khi profile chưa tồn tại (race condition).
    """
    UserProfile.objects.get_or_create(user=instance)


@receiver(user_logged_in)
def log_login(sender, request, user, **kwargs):
    """
    Ghi lịch sử đăng nhập thành công.
    REMOTE_ADDR thô — có thể không chính xác khi có reverse proxy.
    """
    LoginHistory.objects.create(
        user   = user,
        ip     = request.META.get('REMOTE_ADDR', '0.0.0.0'),
        device = request.META.get('HTTP_USER_AGENT', 'Unknown')[:255],
        status = "success"
    )
