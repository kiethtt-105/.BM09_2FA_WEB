"""
models.py — Hệ thống HUIT 2FA  [PATCHED v2]
=============================================
THAY ĐỔI SO VỚI BẢN NỘP:

  [FIX-1]  UserProfile.is_2fa_enabled gọi self.has_fido2 (property DB query)
           → N+1 query khi list user. Tách has_fido2 ra khỏi is_2fa_enabled.
           is_2fa_enabled giờ chỉ kiểm tra BooleanField, không query DB thêm.

  [FIX-2]  force_disable_2fa không reset hotp_secret, hotp_counter.
           → Thêm disable_all_2fa() tập trung, gọi từ middleware + login_view.

  [FIX-3]  decrypt_hotp_secret() không kiểm tra tiền tố 'gAAAA' trước Fernet
           → InvalidToken raise thay vì trả None khi giá trị lạ.
           → Dùng _decrypt() helper chung, guard đầy đủ.

  [FIX-4]  PendingRegistration.verify() dùng .first() không có order_by
           → Khi resend nhanh có 2 bản ghi, lấy sai bản ghi cũ.
           → Thêm order_by('-created_at').

  [FIX-5]  EmailOTP.mark_used() dùng save() → chạy lại toàn bộ save logic.
           → Đổi sang update() trực tiếp + đồng bộ instance trong RAM.
           Tương tự disable() cũng dùng update().

  [FIX-6]  ActivityLog thiếu index → chậm khi admin query lịch sử.
           → Thêm composite index trên (user, timestamp), (action, timestamp),
             (ip_address, action).

  [FIX-7]  RemoteAuthRequest.is_expired là property → không dùng được trong
           filter(). Thêm get_active() classmethod trả queryset chuẩn.

  [KEEP]   Tất cả logic đúng từ bản nộp: PendingRegistration hash (BUG-7),
           RemoteAuthRequest expires_at (WARN-2), OTPAttempt rate limiting,
           EmailOTP hash + hmac.compare_digest, hotp_secret field riêng.
"""

from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.utils import timezone
from django.conf import settings
from cryptography.fernet import Fernet, InvalidToken

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

    Thiết kế secret:
        otp_secret  — TOTP secret, Fernet-encrypted. Dùng cho App OTP (TOTP).
        hotp_secret — HOTP secret riêng biệt, Fernet-encrypted.
                      Tách riêng để user bật cả TOTP lẫn HOTP không bị xung đột.

    allow_push_auth — chỉ có tác dụng khi user có ít nhất 1 phương thức 2FA.
    """

    user = models.OneToOneField(
        User, on_delete=models.CASCADE, related_name='profile'
    )

    middle_name  = models.CharField('Chữ đệm',       max_length=50,  blank=True, default='')
    phone_number = models.CharField('Số điện thoại', max_length=15,  blank=True, default='')

    otp_secret   = models.CharField(max_length=255, blank=True, null=True,
                                    verbose_name='TOTP Secret (encrypted)')
    hotp_secret  = models.CharField(max_length=255, blank=True, null=True,
                                    verbose_name='HOTP Secret (encrypted)')
    hotp_counter = models.PositiveBigIntegerField(default=0, verbose_name='HOTP Counter')

    has_app_otp   = models.BooleanField(default=False, verbose_name='Đã bật App OTP (TOTP)')
    has_email_otp = models.BooleanField(default=False, verbose_name='Đã bật Email OTP')
    has_hotp      = models.BooleanField(default=False, verbose_name='Đã bật HOTP')

    force_disable_2fa = models.BooleanField(default=False, verbose_name='Admin tắt buộc 2FA')
    is_required       = models.BooleanField(default=False, verbose_name='Bắt buộc bật 2FA')
    force_logout      = models.BooleanField(default=False, verbose_name='Cưỡng chế đăng xuất')

    allow_push_auth = models.BooleanField(
        default=True,
        verbose_name='Cho phép xác nhận đăng nhập từ thiết bị khác'
    )

    class Meta:
        verbose_name        = 'Hồ sơ người dùng'
        verbose_name_plural = 'Hồ sơ người dùng'

    # ── Mã hoá / giải mã ───────────────────────────────────────────────────

    def _fernet(self) -> Fernet:
        return Fernet(settings.ENCRYPTION_KEY.encode())

    def encrypt_secret(self, raw_secret: str) -> 'str | None':
        """Mã hóa plaintext bằng Fernet. Trả None nếu rỗng."""
        if not raw_secret:
            return None
        return self._fernet().encrypt(raw_secret.encode()).decode()

    def _decrypt(self, encrypted_value: 'str | None') -> 'str | None':
        """
        [FIX-3] Helper giải mã chung cho cả otp_secret lẫn hotp_secret.
        Kiểm tra tiền tố 'gAAAA' trước khi gọi Fernet.decrypt()
        → trả None an toàn thay vì raise InvalidToken khi giá trị không hợp lệ.
        """
        if not encrypted_value:
            return None
        if not encrypted_value.startswith('gAAAA'):
            return None
        try:
            return self._fernet().decrypt(encrypted_value.encode()).decode()
        except (InvalidToken, Exception):
            return None

    def decrypt_secret(self) -> 'str | None':
        """Giải mã TOTP secret (otp_secret)."""
        return self._decrypt(self.otp_secret)

    def decrypt_hotp_secret(self) -> 'str | None':
        """Giải mã HOTP secret (hotp_secret)."""
        return self._decrypt(self.hotp_secret)

    def save(self, *args, **kwargs):
        if self.otp_secret and not self.otp_secret.startswith('gAAAA'):
            self.otp_secret = self.encrypt_secret(self.otp_secret)
        if self.hotp_secret and not self.hotp_secret.startswith('gAAAA'):
            self.hotp_secret = self.encrypt_secret(self.hotp_secret)
        super().save(*args, **kwargs)

    # ── Tắt toàn bộ 2FA ────────────────────────────────────────────────────

    def disable_all_2fa(self, save: bool = True):
        """
        [FIX-2] Tắt hoàn toàn mọi phương thức 2FA — dùng từ middleware + login_view.
        Đảm bảo nhất quán: không bỏ sót field nào.
        Không xóa passkeys FIDO2 (lưu trong UserPasskey, cần xóa riêng).
        """
        self.has_app_otp       = False
        self.has_email_otp     = False
        self.has_hotp          = False
        self.otp_secret        = None
        self.hotp_secret       = None
        self.hotp_counter      = 0
        self.force_disable_2fa = False
        if save:
            self.save(update_fields=[
                'has_app_otp', 'has_email_otp', 'has_hotp',
                'otp_secret', 'hotp_secret', 'hotp_counter',
                'force_disable_2fa',
            ])

    def __str__(self):
        return f'Profile({self.user.username})'

    # ── Properties ─────────────────────────────────────────────────────────

    @property
    def is_2fa_enabled(self) -> bool:
        """
        [FIX-1] Chỉ kiểm tra BooleanField — không query DB thêm.
        KHÔNG bao gồm FIDO2 để tránh N+1 query trong list view.
        Khi cần kiểm tra đầy đủ: profile.is_2fa_enabled or user.passkeys.exists()
        """
        if self.force_disable_2fa:
            return False
        return self.has_email_otp or self.has_app_otp or self.has_hotp

    @property
    def has_fido2(self) -> bool:
        """
        CẢNH BÁO: Thực hiện DB query.
        Tránh gọi trong vòng lặp — dùng prefetch_related('passkeys').
        """
        return self.user.passkeys.exists()

    @property
    def has_any_2fa(self) -> bool:
        """Kiểm tra đầy đủ kể cả FIDO2. Tránh gọi trong vòng lặp."""
        return self.is_2fa_enabled or self.has_fido2

    def get_full_name(self) -> str:
        parts = [self.user.first_name, self.middle_name, self.user.last_name]
        return ' '.join(p for p in parts if p)


# ════════════════════════════════════════════════════════════════════════════
# 2. PendingRegistration
# ════════════════════════════════════════════════════════════════════════════
class PendingRegistration(models.Model):
    """
    Lưu thông tin đăng ký tạm thời trước khi OTP xác thực thành công.
    temp_data['password'] = make_password() — không lưu plaintext.

    [BUG-7] otp_code lưu SHA-256 hash (64 hex chars), không phải plaintext.
    """

    email      = models.EmailField(unique=True)
    otp_code   = models.CharField(max_length=64)   # SHA-256 hex = 64 chars
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
        [BUG-7] Hash input trước khi so sánh — không bao giờ so sánh plaintext.
        [FIX-4] order_by('-created_at') → lấy bản ghi mới nhất khi có nhiều bản
                ghi cùng email (resend nhanh / race condition).
        """
        input_hash = hashlib.sha256(otp_input.strip().encode('utf-8')).hexdigest()
        pending = (
            cls.objects
            .filter(email=email, is_used=False)
            .order_by('-created_at')
            .first()
        )
        if not pending or not pending.is_valid():
            return None
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
    Audit trail + nguồn sự thật duy nhất cho xác thực OTP email.

    Bảo mật:
        otp_code  — Nhận plaintext khi create(). save() hash → otp_hash rồi xóa.
        otp_hash  — SHA-256(otp_code). Xác thực bằng hash input + compare_digest.
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
            models.Index(
                fields=['user', 'action', 'is_used', 'is_active'],
                name='emailotp_verify_idx'
            ),
            models.Index(
                fields=['email_sent', 'action', 'is_active'],
                name='emailotp_pending_idx'
            ),
        ]

    def save(self, *args, **kwargs):
        """Hash otp_code → otp_hash rồi xóa plaintext trước khi ghi DB."""
        if self.otp_code:
            self.otp_hash = hashlib.sha256(self.otp_code.encode('utf-8')).hexdigest()
            self.otp_code = ''
        super().save(*args, **kwargs)

    @classmethod
    def verify_otp(cls, user, otp_input: str, action: str = None) -> 'EmailOTP | None':
        """Hash input rồi so sánh với otp_hash. Không đọc otp_code từ DB."""
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
        """Xác thực OTP đăng ký — user chưa tồn tại, tra theo email_sent."""
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
        """
        [FIX-5] update() trực tiếp thay vì save() — tránh chạy lại toàn bộ
        save() logic và hiệu quả hơn (1 SQL UPDATE thay vì SELECT + UPDATE).
        """
        EmailOTP.objects.filter(pk=self.pk).update(
            is_used = True,
            used_at = timezone.now(),
        )
        self.is_used = True
        self.used_at = timezone.now()

    def disable(self):
        """[FIX-5] update() trực tiếp cho nhất quán với mark_used()."""
        EmailOTP.objects.filter(pk=self.pk).update(is_active=False)
        self.is_active = False

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
    Nhật ký mọi hành động bảo mật.
    max_length=30 — đủ cho tất cả choices (dài nhất: 'login_locked_attempt' = 22 ký tự).
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
        indexes = [
            # [FIX-6] Index tăng tốc các query admin phổ biến
            models.Index(fields=['user', 'timestamp'],    name='actlog_user_ts_idx'),
            models.Index(fields=['action', 'timestamp'],  name='actlog_action_ts_idx'),
            models.Index(fields=['ip_address', 'action'], name='actlog_ip_action_idx'),
        ]

    def __str__(self):
        username = self.user.username if self.user else self.username_attempt
        return f'{username} — {self.get_action_display()} — {self.timestamp.strftime("%d/%m/%Y %H:%M")}'


# ════════════════════════════════════════════════════════════════════════════
# 4b. OTPAttempt — Rate limiting
# ════════════════════════════════════════════════════════════════════════════
class OTPAttempt(models.Model):
    """
    Theo dõi số lần nhập OTP sai theo user + IP.
    Giới hạn: MAX_FAILS = 5 / WINDOW_MINUTES = 10 phút.
    """
    MAX_FAILS      = 5
    WINDOW_MINUTES = 10

    user       = models.ForeignKey(User, on_delete=models.CASCADE,
                                   related_name='otp_attempts', null=True, blank=True)
    ip_address = models.CharField(max_length=50, db_index=True)
    action     = models.CharField(max_length=20, default='login_2fa')
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        verbose_name        = 'OTP Attempt (Rate Limit)'
        verbose_name_plural = 'OTP Attempts (Rate Limit)'
        indexes = [
            models.Index(fields=['user', 'action', 'created_at'],       name='otpattempt_user_idx'),
            models.Index(fields=['ip_address', 'action', 'created_at'], name='otpattempt_ip_idx'),
        ]

    @classmethod
    def _since(cls) -> datetime.datetime:
        return timezone.now() - datetime.timedelta(minutes=cls.WINDOW_MINUTES)

    @classmethod
    def is_blocked(cls, user=None, ip: str = None, action: str = 'login_2fa') -> bool:
        """True nếu user HOẶC IP vượt MAX_FAILS trong WINDOW_MINUTES."""
        since = cls._since()
        if user is not None:
            if cls.objects.filter(user=user, action=action, created_at__gte=since).count() >= cls.MAX_FAILS:
                return True
        if ip:
            if cls.objects.filter(ip_address=ip, action=action, created_at__gte=since).count() >= cls.MAX_FAILS:
                return True
        return False

    @classmethod
    def record_fail(cls, user=None, ip: str = None, action: str = 'login_2fa'):
        cls.objects.create(user=user, ip_address=ip or '', action=action)

    @classmethod
    def clear(cls, user=None, ip: str = None, action: str = 'login_2fa'):
        """Tách 2 delete riêng — xóa đúng theo user OR ip, không bị AND condition."""
        if user is not None:
            cls.objects.filter(user=user, action=action).delete()
        if ip:
            cls.objects.filter(ip_address=ip, action=action).delete()

    @classmethod
    def cleanup_old(cls):
        """Dọn bản ghi cũ — gọi từ celery beat, không gọi trong request."""
        cls.objects.filter(created_at__lt=cls._since()).delete()

    def __str__(self):
        return f'OTPAttempt({self.ip_address} | {self.action} | {self.created_at})'


# ════════════════════════════════════════════════════════════════════════════
# 5. TrustedDevice
# ════════════════════════════════════════════════════════════════════════════
class TrustedDevice(models.Model):
    user        = models.ForeignKey(User, on_delete=models.CASCADE, related_name='trusted_devices')
    device_id   = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    session_key = models.CharField(max_length=40, blank=True, null=True, db_index=True)
    name        = models.CharField(max_length=255, default='Thiết bị không xác định')
    user_agent  = models.TextField(blank=True, null=True)
    ip_address  = models.CharField(max_length=50, blank=True, null=True)
    last_seen   = models.DateTimeField(auto_now=True)
    is_active   = models.BooleanField(default=True)

    class Meta:
        verbose_name        = 'Thiết bị tin cậy'
        verbose_name_plural = 'Thiết bị tin cậy'
        indexes = [
            models.Index(fields=['user', 'is_active'], name='trusteddev_user_active_idx'),
        ]

    def __str__(self):
        return f'{self.user.username} — {self.name}'


# ════════════════════════════════════════════════════════════════════════════
# 6. RemoteAuthRequest
# ════════════════════════════════════════════════════════════════════════════
class RemoteAuthRequest(models.Model):
    """
    Push auth request: thiết bị mới xin xác nhận từ thiết bị đang online.
    [WARN-2] expires_at tự set khi save lần đầu.
    [FIX-7] get_active() classmethod thay cho filter(expires_at__gt=...) rải rác.
    """
    STATUS_CHOICES = [
        ('pending',  'Chờ xác nhận'),
        ('approved', 'Đã đồng ý'),
        ('denied',   'Đã từ chối'),
    ]

    EXPIRY_MINUTES = 5

    user        = models.ForeignKey(User, on_delete=models.CASCADE)
    session_key = models.CharField(max_length=40, db_index=True)
    device_info = models.CharField(max_length=255)
    status      = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    created_at  = models.DateTimeField(auto_now_add=True)
    expires_at  = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name        = 'Yêu cầu xác thực từ xa'
        verbose_name_plural = 'Yêu cầu xác thực từ xa'
        indexes = [
            models.Index(fields=['session_key', 'expires_at'], name='remoteauth_session_exp_idx'),
        ]

    def save(self, *args, **kwargs):
        if not self.expires_at:
            self.expires_at = timezone.now() + datetime.timedelta(minutes=self.EXPIRY_MINUTES)
        super().save(*args, **kwargs)

    @property
    def is_expired(self) -> bool:
        """Kiểm tra instance đơn lẻ. Không dùng trong filter() — dùng get_active()."""
        if not self.expires_at:
            return True
        return timezone.now() > self.expires_at

    @classmethod
    def get_active(cls):
        """
        [FIX-7] Queryset các request chưa hết hạn.
        Dùng thay cho filter(expires_at__gt=timezone.now()) trong views.
        """
        return cls.objects.filter(expires_at__gt=timezone.now())

    @classmethod
    def cleanup_expired(cls):
        """Xóa request hết hạn. Gọi từ check_auth_status hoặc celery beat."""
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