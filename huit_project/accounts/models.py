"""
models.py — Hệ thống HUIT 2FA  [PATCHED]
==========================================
THAY ĐỔI SO VỚI BẢN GỐC:

  [BUG-7]  PendingRegistration.otp_code lưu plaintext
           → Tăng max_length lên 64, lưu SHA-256 hash thay vì plaintext.
           → Thêm classmethod verify(email, otp_input) để xác thực đúng chuẩn.

  [WARN-2] RemoteAuthRequest không có expiry
           → Thêm field expires_at = created_at + 5 phút (auto khi save).
           → Thêm property is_expired() và classmethod cleanup_expired().
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
import hmac as _hmac
import uuid


# ════════════════════════════════════════════════════════════════════════════
# 1. UserProfile
# ════════════════════════════════════════════════════════════════════════════
class UserProfile(models.Model):
    """
    Mở rộng User Django bằng OneToOne.

    otp_secret  : TOTP/HOTP secret — luôn Fernet-encrypted trong DB.
    hotp_counter: Counter server-side cho HOTP. Tăng 1 mỗi lần xác thực thành công.
    has_hotp    : Cờ user đã bật HOTP (event-based OTP).
    allow_push_auth: Cho phép xác nhận đăng nhập từ thiết bị khác (chỉ khi có 2FA).
    """

    user = models.OneToOneField(
        User, on_delete=models.CASCADE, related_name='profile'
    )

    middle_name  = models.CharField('Chữ đệm',       max_length=50, blank=True, default='')
    phone_number = models.CharField('Số điện thoại', max_length=15, blank=True, default='')

    otp_secret   = models.CharField(max_length=255, blank=True, null=True)
    hotp_counter = models.PositiveBigIntegerField(default=0, verbose_name='HOTP Counter')

    has_app_otp   = models.BooleanField(default=False, verbose_name='Đã bật App OTP (TOTP)')
    has_email_otp = models.BooleanField(default=False, verbose_name='Đã bật Email OTP')
    has_hotp      = models.BooleanField(default=False, verbose_name='Đã bật HOTP')

    force_disable_2fa = models.BooleanField(default=False, verbose_name='Admin tắt buộc 2FA')
    is_required       = models.BooleanField(default=False, verbose_name='Bắt buộc bật 2FA')
    force_logout      = models.BooleanField(default=False, verbose_name='Cưỡng chế đăng xuất')

    # [SEC-PUSH] Toggle push auth — chỉ có tác dụng khi user có ít nhất 1 phương thức 2FA
    allow_push_auth = models.BooleanField(
        default=True,
        verbose_name='Cho phép xác nhận đăng nhập từ thiết bị khác'
    )

    class Meta:
        verbose_name        = 'Hồ sơ người dùng'
        verbose_name_plural = 'Hồ sơ người dùng'

    # ── Mã hoá / giải mã secret ────────────────────────────────────────────

    def encrypt_secret(self, raw_secret: str) -> 'str | None':
        """[FIX-TYPE] Trả None nếu raw_secret rỗng, không phải str."""
        if not raw_secret:
            return None
        f = Fernet(settings.ENCRYPTION_KEY.encode())
        return f.encrypt(raw_secret.encode()).decode()

    def decrypt_secret(self) -> str:
        """
        Giải mã TOTP/HOTP secret.
        Nhận dạng token Fernet qua tiền tố 'gAAAA'.
        Trả None nếu không giải mã được.
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
        # Auto-encrypt secret nếu chưa có tiền tố Fernet
        if self.otp_secret and not self.otp_secret.startswith('gAAAA'):
            self.otp_secret = self.encrypt_secret(self.otp_secret)
        super().save(*args, **kwargs)

    def __str__(self):
        return f'Profile({self.user.username})'

    # ── Properties ─────────────────────────────────────────────────────────

    @property
    def is_2fa_enabled(self) -> bool:
        if self.force_disable_2fa:
            return False
        return self.has_email_otp or self.has_app_otp or self.has_hotp

    @property
    def has_fido2(self) -> bool:
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
    temp_data['password'] = make_password() — không lưu plaintext password.

    [BUG-7] otp_code giờ lưu SHA-256 hash (64 ký tự hex), không phải plaintext.
    Dùng classmethod verify(email, otp_input) để xác thực — tránh so sánh plaintext.
    """

    email      = models.EmailField(unique=True)
    # [BUG-7] max_length=64 để chứa hex SHA-256; lưu hash thay vì plaintext
    otp_code   = models.CharField(max_length=64)
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

    @classmethod
    def verify(cls, email: str, otp_input: str) -> 'PendingRegistration | None':
        """
        [BUG-7] Xác thực OTP đăng ký bằng cách hash input rồi so sánh.
        Không bao giờ so sánh plaintext trực tiếp.
        """
        input_hash = hashlib.sha256(otp_input.strip().encode('utf-8')).hexdigest()
        pending = cls.objects.filter(email=email, is_used=False).first()
        if not pending:
            return None
        if not pending.is_valid():
            return None
        # So sánh an toàn bằng compare_digest — tránh timing attack
        if _hmac.compare_digest(pending.otp_code, input_hash):
            return pending
        return None

    def __str__(self):
        return f'PendingReg({self.email})'


# ════════════════════════════════════════════════════════════════════════════
# 3. EmailOTP
# ════════════════════════════════════════════════════════════════════════════
class EmailOTP(models.Model):
    """
    Audit trail cho toàn bộ OTP email đã phát hành.
    Là nguồn sự thật duy nhất cho xác thực OTP email.

    Thiết kế bảo mật:
        otp_code  — Trường nhận plaintext khi tạo.
                    Trong save(), tự động hash → otp_hash, sau đó otp_code = '' (xóa).
                    DB không bao giờ lưu plaintext sau khi save() hoàn thành.

        otp_hash  — SHA-256(otp_code). Dùng để xác thực bằng cách hash input
                    rồi so sánh — không cần đọc plaintext từ DB.

    Xác thực:
        Gọi EmailOTP.verify_otp(user, input_string, action) → trả EmailOTP hoặc None.
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

    # Trường này nhận plaintext khi create(); bị xóa (='') ngay sau khi save() hash xong
    otp_code = models.CharField(
        max_length=6, blank=True, default='',
        verbose_name='OTP plaintext (bị xóa sau hash)'
    )
    otp_hash = models.CharField(
        max_length=64, blank=True, null=True,
        verbose_name='SHA-256 hash của OTP'
    )

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
        indexes = [
            # [FIX-INDEX] Tăng tốc verify_otp và verify_otp_pending
            models.Index(fields=['user', 'action', 'is_used', 'is_active'], name='emailotp_verify_idx'),
            models.Index(fields=['email_sent', 'action', 'is_active'],      name='emailotp_pending_idx'),
        ]

    def save(self, *args, **kwargs):
        """
        Hash otp_code → otp_hash, sau đó XÓA plaintext.
        """
        if self.otp_code:
            self.otp_hash = hashlib.sha256(
                self.otp_code.encode('utf-8')
            ).hexdigest()
            self.otp_code = ''
        super().save(*args, **kwargs)

    @classmethod
    def verify_otp(cls, user, otp_input: str, action: str = None) -> 'EmailOTP | None':
        """
        Xác thực OTP bằng cách hash input rồi so sánh với otp_hash trong DB.
        Không bao giờ đọc otp_code từ DB.
        """
        input_hash = hashlib.sha256(otp_input.encode('utf-8')).hexdigest()
        qs = cls.objects.filter(
            user      = user,
            is_used   = False,
            is_active = True,
            created_at__gt = timezone.now() - datetime.timedelta(minutes=cls.OTP_VALID_MINUTES)
        )
        if action:
            qs = qs.filter(action=action)

        for record in qs.order_by('-created_at')[:10]:
            if record.otp_hash and _hmac.compare_digest(record.otp_hash, input_hash):
                return record
        return None

    @classmethod
    def verify_otp_pending(cls, email: str, otp_input: str) -> 'EmailOTP | None':
        """
        Xác thực OTP đăng ký — user chưa tồn tại, so sánh theo email.
        """
        input_hash = hashlib.sha256(otp_input.encode('utf-8')).hexdigest()
        qs = cls.objects.filter(
            user__isnull = True,
            email_sent   = email,
            action       = 'register',
            is_used      = False,
            is_active    = True,
            created_at__gt = timezone.now() - datetime.timedelta(minutes=10),
        ).order_by('-created_at')[:10]

        for record in qs:
            if record.otp_hash and _hmac.compare_digest(record.otp_hash, input_hash):
                return record
        return None

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
        ('account_toggle',       'Admin khóa / mở khóa tài khoản'),
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
# 4b. OTPAttempt — Rate limiting brute-force OTP
# ════════════════════════════════════════════════════════════════════════════
class OTPAttempt(models.Model):
    """
    [FIX-RATELIMIT] Theo dõi số lần nhập OTP sai theo user + IP.
    Dùng để block brute-force 6 chữ số (10^6 khả năng).

    Giới hạn mặc định: MAX_FAILS = 5 lần / WINDOW_MINUTES = 10 phút.
    Sau khi vượt ngưỡng → trả True từ is_blocked() → view từ chối xử lý.
    """
    MAX_FAILS      = 5
    WINDOW_MINUTES = 10

    user       = models.ForeignKey(User, on_delete=models.CASCADE, related_name='otp_attempts',
                                   null=True, blank=True)
    ip_address = models.CharField(max_length=50, db_index=True)
    action     = models.CharField(max_length=20, default='login_2fa')
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        verbose_name        = 'OTP Attempt (Rate Limit)'
        verbose_name_plural = 'OTP Attempts (Rate Limit)'
        indexes = [
            models.Index(fields=['user', 'action', 'created_at'], name='otpattempt_user_idx'),
            models.Index(fields=['ip_address', 'action', 'created_at'], name='otpattempt_ip_idx'),
        ]

    @classmethod
    def is_blocked(cls, user=None, ip: str = None, action: str = 'login_2fa') -> bool:
        """
        Trả True nếu user HOẶC IP vượt quá MAX_FAILS trong WINDOW_MINUTES.
        Block theo cả user lẫn IP để tránh bypass bằng cách đổi account.
        """
        since = timezone.now() - datetime.timedelta(minutes=cls.WINDOW_MINUTES)
        if user is not None:
            count = cls.objects.filter(user=user, action=action, created_at__gte=since).count()
            if count >= cls.MAX_FAILS:
                return True
        if ip:
            count = cls.objects.filter(ip_address=ip, action=action, created_at__gte=since).count()
            if count >= cls.MAX_FAILS:
                return True
        return False

    @classmethod
    def record_fail(cls, user=None, ip: str = None, action: str = 'login_2fa'):
        """Ghi nhận 1 lần thất bại."""
        cls.objects.create(user=user, ip_address=ip or '', action=action)

    @classmethod
    def clear(cls, user=None, ip: str = None, action: str = 'login_2fa'):
        """Xóa lịch sử sau khi xác thực thành công."""
        qs = cls.objects.filter(action=action)
        if user is not None:
            qs = qs.filter(user=user)
        if ip:
            qs = qs.filter(ip_address=ip)
        qs.delete()

    @classmethod
    def cleanup_old(cls):
        """Dọn bản ghi cũ hơn WINDOW_MINUTES — gọi từ celery beat hoặc periodic task."""
        cutoff = timezone.now() - datetime.timedelta(minutes=cls.WINDOW_MINUTES)
        cls.objects.filter(created_at__lt=cutoff).delete()

    def __str__(self):
        return f'OTPAttempt({self.ip_address} | {self.action} | {self.created_at})'


# ════════════════════════════════════════════════════════════════════════════
# 5. TrustedDevice
# ════════════════════════════════════════════════════════════════════════════
class TrustedDevice(models.Model):
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
    [WARN-2] Thêm expires_at = created_at + 5 phút.
    check_auth_status và get_pending_auth_request phải lọc is_expired() trước khi dùng.
    """
    STATUS_CHOICES = [
        ('pending',  'Chờ xác nhận'),
        ('approved', 'Đã đồng ý'),
        ('denied',   'Đã từ chối'),
    ]

    EXPIRY_MINUTES = 5

    user        = models.ForeignKey(User, on_delete=models.CASCADE)
    session_key = models.CharField(max_length=40)
    device_info = models.CharField(max_length=255)
    status      = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    created_at  = models.DateTimeField(auto_now_add=True)
    # [WARN-2] expires_at: tự tính khi save() lần đầu
    expires_at  = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name        = 'Yêu cầu xác thực từ xa'
        verbose_name_plural = 'Yêu cầu xác thực từ xa'

    def save(self, *args, **kwargs):
        # Tự set expires_at khi tạo mới
        if not self.expires_at:
            self.expires_at = timezone.now() + datetime.timedelta(minutes=self.EXPIRY_MINUTES)
        super().save(*args, **kwargs)

    @property
    def is_expired(self) -> bool:
        return timezone.now() > self.expires_at

    @classmethod
    def cleanup_expired(cls):
        """Xóa các request đã hết hạn. Gọi từ check_auth_status hoặc celery beat."""
        cls.objects.filter(expires_at__lt=timezone.now()).delete()

    def __str__(self):
        return f'RemoteAuth({self.user.username} | {self.status})'


# ════════════════════════════════════════════════════════════════════════════
# 7. UserPasskey
# ════════════════════════════════════════════════════════════════════════════
class UserPasskey(models.Model):
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
    if created:
        UserProfile.objects.get_or_create(user=instance)