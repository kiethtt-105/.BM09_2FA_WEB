
from django.db import models
from django.contrib.auth.models import User
import datetime
import hashlib
from django.utils import timezone
import pyotp
from django.utils.timezone import now
from django.db.models.signals import post_save
from django.dispatch import receiver
import uuid
from django.contrib.auth.signals import user_logged_in
from cryptography.fernet import Fernet
from django.conf import settings


# ────────────────────────────────────────────────────────────────
class UserProfile(models.Model):
    user          = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    middle_name   = models.CharField('Chữ đệm', max_length=50, blank=True, default='')
    phone_number  = models.CharField('Số điện thoại', max_length=15, blank=True, default='')

    # Lưu otp_secret đã mã hóa Fernet (max_length=255 để chứa chuỗi mã hóa)
    otp_secret    = models.CharField(max_length=255, blank=True, null=True)

    has_app_otp   = models.BooleanField(default=False)
    has_email_otp = models.BooleanField(default=False)
    email_otp     = models.CharField(max_length=6, blank=True, null=True)
    otp_expiry    = models.DateTimeField(blank=True, null=True)
    has_fido2     = models.BooleanField(default=False, verbose_name="Đã bật FIDO2")
    fido2_credential = models.JSONField(null=True, blank=True)

    # ── Fernet encrypt / decrypt ─────────────────────────────────
    def encrypt_secret(self, raw_secret: str) -> str:
        """Mã hóa Secret Key bằng Fernet trước khi lưu vào DB."""
        if not raw_secret:
            return None
        f = Fernet(settings.ENCRYPTION_KEY.encode())
        return f.encrypt(raw_secret.encode()).decode()

    def decrypt_secret(self) -> str:
        """
        Giải mã Secret Key để tính TOTP hoặc hiển thị.
        - Bắt đầu 'gAAAA' → đã mã hóa Fernet, giải mã
        - Ngược lại → dữ liệu cũ chưa mã hóa, trả về thẳng
        """
        if not self.otp_secret:
            return None
        try:
            if self.otp_secret.startswith('gAAAA'):
                f = Fernet(settings.ENCRYPTION_KEY.encode())
                return f.decrypt(self.otp_secret.encode()).decode()
            return self.otp_secret
        except Exception:
            return self.otp_secret

    def save(self, *args, **kwargs):
        # Tự động mã hóa otp_secret nếu chưa được mã hóa
        if self.otp_secret and not self.otp_secret.startswith('gAAAA'):
            self.otp_secret = self.encrypt_secret(self.otp_secret)
        super().save(*args, **kwargs)

    def __str__(self):
        return f"Profile({self.user.username})"

    @property
    def is_2fa_enabled(self):
        return self.has_email_otp or self.has_app_otp

    def get_full_name(self):
        parts = [self.user.first_name, self.middle_name, self.user.last_name]
        return ' '.join(p for p in parts if p)


# ────────────────────────────────────────────────────────────────
class PendingRegistration(models.Model):
    """Lưu tạm dữ liệu đăng ký trước khi xác thực OTP."""
    email      = models.EmailField(unique=True)
    otp_code   = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    is_used    = models.BooleanField(default=False)
    temp_data  = models.JSONField(default=dict)
    OTP_EXPIRY_MINUTES = 10

    def is_valid(self):
        expiry = self.created_at + datetime.timedelta(minutes=self.OTP_EXPIRY_MINUTES)
        return not self.is_used and timezone.now() < expiry

    def __str__(self):
        return f"PendingReg({self.email})"


# ════════════════════════════════════════════════════════════════
#  EmailOTP — Log đầy đủ mọi lần gửi / sử dụng OTP qua Email
#
#  THIẾT KẾ BẢO MẬT (phản biện):
#  ┌──────────────┬──────────────────────────────────────────────┐
#  │ otp_code     │ Plaintext — CHỈ lưu để DEMO trực quan       │
#  │              │ Trong production: XOÁ trường này             │
#  │ otp_hash     │ SHA-256(otp_code) — cách lưu đúng chuẩn     │
#  │              │ Verify: hash(input) == otp_hash → hợp lệ    │
#  │ is_active    │ Admin vô hiệu OTP thủ công                  │
#  │ ip_address   │ Audit trail / phát hiện bất thường           │
#  │ action       │ Phân loại mục đích gửi OTP                  │
#  │ used_at      │ Thời điểm sử dụng (forensics)               │
#  └──────────────┴──────────────────────────────────────────────┘
# ════════════════════════════════════════════════════════════════
class EmailOTP(models.Model):

    ACTION_CHOICES = [
        ('register',    'Đăng ký tài khoản'),
        ('login_2fa',   'Đăng nhập 2FA'),
        ('setup_2fa',   'Thiết lập Email 2FA'),
        ('update_info', 'Cập nhật thông tin'),
        ('disable_2fa', 'Tắt Email 2FA'),
    ]

    user = models.ForeignKey(
        User, on_delete=models.CASCADE,
        null=True, blank=True
    )

    # [DEMO] OTP plaintext — CHỈ để minh hoạ cho hội đồng
    otp_code = models.CharField(max_length=6)

    # [PRODUCTION] SHA-256 hash — tự động tính trong save()
    otp_hash = models.CharField(
        max_length=64, blank=True, null=True,
        verbose_name="Mã OTP đã băm SHA-256"
    )

    # ── Metadata ────────────────────────────────────────────────
    action = models.CharField(
        max_length=20, choices=ACTION_CHOICES, default='login_2fa',
        verbose_name="Loại thao tác"
    )
    ip_address = models.CharField(
        max_length=50, blank=True, null=True,
        verbose_name="Địa chỉ IP"
    )
    email_sent = models.CharField(
        max_length=254, blank=True, null=True,
        verbose_name="Email đích"
    )

    # ── Trạng thái ──────────────────────────────────────────────
    created_at = models.DateTimeField(auto_now_add=True)
    used_at    = models.DateTimeField(
        blank=True, null=True,
        verbose_name="Thời điểm OTP được sử dụng"
    )
    is_used   = models.BooleanField(default=False)

    # False = admin đã bấm nút "Vô hiệu" thủ công
    is_active = models.BooleanField(
        default=True,
        verbose_name="Đang hiệu lực"
    )

    class Meta:
        ordering = ['-created_at']
        verbose_name = "Email OTP Log"

    def save(self, *args, **kwargs):
        # Tự động băm SHA-256 mỗi khi tạo mới (chỉ khi chưa có hash)
        if self.otp_code and not self.otp_hash:
            self.otp_hash = hashlib.sha256(
                self.otp_code.encode('utf-8')
            ).hexdigest()
        super().save(*args, **kwargs)

    def is_valid(self):
        """
        OTP còn hợp lệ khi:
          1. Chưa dùng (is_used=False)
          2. Admin chưa vô hiệu (is_active=True)
          3. Chưa quá 3 phút
        """
        return (
            not self.is_used
            and self.is_active
            and timezone.now() < self.created_at + datetime.timedelta(minutes=3)
        )

    def mark_used(self):
        """Đánh dấu đã sử dụng + ghi thời điểm."""
        self.is_used = True
        self.used_at = timezone.now()
        self.save(update_fields=['is_used', 'used_at'])

    def disable(self):
        """Admin vô hiệu hoá thủ công."""
        self.is_active = False
        self.save(update_fields=['is_active'])

    def __str__(self):
        return (
            f"EmailOTP("
            f"{self.user.username if self.user else 'pending'} | "
            f"{self.get_action_display()} | "
            f"{self.created_at.strftime('%d/%m/%Y %H:%M')})"
        )


# ────────────────────────────────────────────────────────────────
class ActivityLog(models.Model):
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
        related_name='activities', null=True, blank=True
    )
    username_attempt = models.CharField(max_length=150, null=True, blank=True)
    action     = models.CharField(max_length=30, choices=ACTION_CHOICES)
    ip_address = models.CharField(max_length=50, blank=True, null=True)
    user_agent = models.TextField(blank=True, null=True)
    timestamp  = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        username = self.user.username if self.user else self.username_attempt
        return f"{username} - {self.get_action_display()} - {self.timestamp.strftime('%d/%m/%Y %H:%M')}"


# ────────────────────────────────────────────────────────────────
class OTP(models.Model):
    user       = models.ForeignKey(User, on_delete=models.CASCADE)
    code       = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_expired(self):
        return timezone.now() > self.created_at + datetime.timedelta(minutes=2)


# ────────────────────────────────────────────────────────────────
@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.get_or_create(user=instance)


@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    instance.profile.save()


# ────────────────────────────────────────────────────────────────
class TrustedDevice(models.Model):
    user        = models.ForeignKey(User, on_delete=models.CASCADE, related_name='trusted_devices')
    device_id   = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    session_key = models.CharField(max_length=40, blank=True, null=True)
    name        = models.CharField(max_length=255, default="Thiết bị không xác định")
    user_agent  = models.TextField(blank=True, null=True)
    ip_address  = models.CharField(max_length=50, blank=True, null=True)
    last_seen   = models.DateTimeField(auto_now=True)
    is_active   = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.user.username} - {self.name}"


# ────────────────────────────────────────────────────────────────
class User2FA(models.Model):
    user                = models.OneToOneField(User, on_delete=models.CASCADE, related_name='user2fa')
    email_otp_enabled   = models.BooleanField(default=False)
    google_auth_enabled = models.BooleanField(default=False)
    google_secret       = models.CharField(max_length=100, blank=True, null=True)
    force_disable_2fa   = models.BooleanField(default=False)
    is_required         = models.BooleanField(default=False, verbose_name="Bắt buộc xác thực 2FA")

    def __str__(self):
        return self.user.username

    @property
    def is_enabled(self):
        if self.force_disable_2fa:
            return False
        return self.email_otp_enabled or self.google_auth_enabled


# ────────────────────────────────────────────────────────────────
class UserSessionControl(models.Model):
    user         = models.OneToOneField(User, on_delete=models.CASCADE)
    force_logout = models.BooleanField(default=False)


# ────────────────────────────────────────────────────────────────
class LoginHistory(models.Model):
    user   = models.ForeignKey(User, on_delete=models.CASCADE)
    ip     = models.GenericIPAddressField()
    device = models.CharField(max_length=255)
    time   = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=50)


@receiver(user_logged_in)
def log_login(sender, request, user, **kwargs):
    LoginHistory.objects.create(
        user=user,
        ip=request.META.get('REMOTE_ADDR'),
        device=request.META.get('HTTP_USER_AGENT'),
        status="success"
    )


# ────────────────────────────────────────────────────────────────
class RemoteAuthRequest(models.Model):
    user        = models.ForeignKey(User, on_delete=models.CASCADE)
    session_key = models.CharField(max_length=40)
    device_info = models.CharField(max_length=255)
    status      = models.CharField(
        max_length=20,
        choices=[('pending','Chờ'),('approved','Đồng ý'),('denied','Từ chối')],
        default='pending'
    )
    created_at = models.DateTimeField(auto_now_add=True)


# ────────────────────────────────────────────────────────────────
class UserPasskey(models.Model):
    user          = models.ForeignKey(User, on_delete=models.CASCADE, related_name="passkeys")
    credential_id = models.CharField(max_length=500, unique=True)
    public_key    = models.TextField()
    sign_count    = models.IntegerField(default=0)
    created_at    = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Passkey của {self.user.username}"
