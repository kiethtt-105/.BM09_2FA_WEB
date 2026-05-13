"""
models.py — Định nghĩa các Model cho hệ thống HUIT 2FA
=======================================================
Danh sách model:
  1. UserProfile          — Thông tin mở rộng của User, lưu secret TOTP mã hóa Fernet
  2. PendingRegistration  — Đăng ký tạm chờ xác thực OTP
  3. EmailOTP             — Log toàn bộ OTP email đã gửi (audit trail)
  4. ActivityLog          — Nhật ký hoạt động người dùng
  5. OTP                  — [DEPRECATED] Model OTP cũ, giữ lại tương thích
  6. TrustedDevice        — Thiết bị đã tin cậy (remember device)
  7. User2FA              — Cấu hình 2FA do admin quản lý
  8. UserSessionControl   — Cờ force_logout của admin
  9. LoginHistory         — Lịch sử đăng nhập (signal)
  10. RemoteAuthRequest   — Yêu cầu xác thực từ thiết bị lạ (push auth)
  11. UserPasskey         — Passkey / FIDO2 credential

"""

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
import pyotp  # Dùng để sinh secret trong views (import ở đây để model không cần import lại)


# ════════════════════════════════════════════════════════════════════════════
# 1. UserProfile — Thông tin mở rộng, cấu hình 2FA của từng User
# ════════════════════════════════════════════════════════════════════════════
class UserProfile(models.Model):
    """
    Mở rộng User mặc định của Django bằng quan hệ OneToOne.

    Lưu ý bảo mật (otp_secret):
        - Trường otp_secret lưu TOTP secret đã mã hóa bằng Fernet (AES-128-CBC).
        - Khóa mã hóa lấy từ settings.ENCRYPTION_KEY (phải là Fernet key hợp lệ).
        - Không được lưu secret dạng plaintext vào production DB.
    """

    user = models.OneToOneField(
        User, on_delete=models.CASCADE, related_name='profile'
    )
    middle_name  = models.CharField('Chữ đệm',       max_length=50,  blank=True, default='')
    phone_number = models.CharField('Số điện thoại', max_length=15,  blank=True, default='')

    # Secret TOTP đã mã hóa Fernet — max_length=255 đủ chứa token mã hóa
    otp_secret   = models.CharField(max_length=255, blank=True, null=True)

    # Cờ trạng thái từng phương thức 2FA
    has_app_otp   = models.BooleanField(default=False, verbose_name="Đã bật App OTP")
    has_email_otp = models.BooleanField(default=False, verbose_name="Đã bật Email OTP")
    has_fido2     = models.BooleanField(default=False, verbose_name="Đã bật FIDO2")

    # OTP tạm thời lưu trong profile (dùng cho email OTP và update-info flow)
    email_otp  = models.CharField(max_length=6,  blank=True, null=True)
    otp_expiry = models.DateTimeField(blank=True, null=True)

    # FIDO2 credential JSON (dự phòng — chủ yếu dùng bảng UserPasskey)
    fido2_credential = models.JSONField(null=True, blank=True)

    class Meta:
        verbose_name = "Hồ sơ người dùng"

    # ── Mã hóa / Giải mã Fernet ──────────────────────────────────────────
    def encrypt_secret(self, raw_secret: str) -> str:
        """
        Mã hóa TOTP secret bằng Fernet trước khi lưu DB.
        settings.ENCRYPTION_KEY phải là Fernet key hợp lệ (44 ký tự Base64url).
        """
        if not raw_secret:
            return None
        f = Fernet(settings.ENCRYPTION_KEY.encode())
        return f.encrypt(raw_secret.encode()).decode()

    def decrypt_secret(self) -> str:
        """
        Giải mã TOTP secret để tính TOTP hoặc hiển thị QR.

        Logic nhận dạng:
          - Chuỗi bắt đầu 'gAAAA' → token Fernet → giải mã
          - Ngược lại → dữ liệu cũ chưa mã hóa → trả thẳng

        """
        if not self.otp_secret:
            return None
        try:
            if self.otp_secret.startswith('gAAAA'):
                f = Fernet(settings.ENCRYPTION_KEY.encode())
                return f.decrypt(self.otp_secret.encode()).decode()
            return self.otp_secret
        except Exception:
            # Nếu giải mã thất bại → trả None thay vì trả plaintext
            # tránh lộ dữ liệu khi key sai
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

    Luồng sử dụng:
        1. User điền form đăng ký → tạo PendingRegistration + gửi OTP email.
        2. User nhập OTP → kiểm tra is_valid() → tạo User thật → xóa/đánh dấu bản ghi.

    Lưu ý bảo mật:
        - temp_data['password'] lưu plaintext vì chưa tạo User.
        - Nên xóa bản ghi ngay sau khi tạo User thành công (đã implement trong views).
        - OTP_EXPIRY_MINUTES = 10 phút.
    """

    email      = models.EmailField(unique=True)
    otp_code   = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    is_used    = models.BooleanField(default=False)

    # Lưu toàn bộ dữ liệu form dưới dạng JSON (bao gồm password plaintext — chỉ DEMO)
    temp_data = models.JSONField(default=dict)

    OTP_EXPIRY_MINUTES = 10  # Thời gian hiệu lực OTP đăng ký

    class Meta:
        verbose_name = "Đăng ký tạm chờ xác thực"

    def is_valid(self) -> bool:
        """
        Kiểm tra OTP còn hợp lệ:
          - Chưa được sử dụng (is_used=False)
          - Chưa quá OTP_EXPIRY_MINUTES kể từ lúc tạo
        """
        expiry = self.created_at + datetime.timedelta(minutes=self.OTP_EXPIRY_MINUTES)
        return not self.is_used and timezone.now() < expiry

    def __str__(self):
        return f"PendingReg({self.email})"


# ════════════════════════════════════════════════════════════════════════════
# 3. EmailOTP — Log đầy đủ mọi lần gửi / sử dụng OTP qua Email
# ════════════════════════════════════════════════════════════════════════════
class EmailOTP(models.Model):
    """
    Bảng audit trail cho toàn bộ OTP email đã phát hành.

    Thiết kế bảo mật (hai lớp lưu trữ):
    ┌──────────────┬─────────────────────────────────────────────────┐
    │ otp_code     │ Plaintext — CHỈ để DEMO trực quan cho hội đồng  │
    │              │ Trong production: XÓA trường này                │
    │ otp_hash     │ SHA-256(otp_code) — cách lưu đúng chuẩn        │
    │              │ Verify: sha256(input) == otp_hash               │
    │ is_active    │ Admin có thể vô hiệu OTP thủ công               │
    │ ip_address   │ Audit trail / phát hiện bất thường              │
    │ action       │ Phân loại mục đích gửi OTP                     │
    │ used_at      │ Thời điểm sử dụng (forensics)                  │
    └──────────────┴─────────────────────────────────────────────────┘

    Thời gian hiệu lực: 3 phút (kiểm tra trong is_valid()).
    """

    ACTION_CHOICES = [
        ('register',    'Đăng ký tài khoản'),
        ('login_2fa',   'Đăng nhập 2FA'),
        ('setup_2fa',   'Thiết lập Email 2FA'),
        ('update_info', 'Cập nhật thông tin'),
        ('disable_2fa', 'Tắt Email 2FA'),
    ]

    # Liên kết User — null/blank vì OTP đăng ký chưa có User
    user = models.ForeignKey(
        User, on_delete=models.CASCADE,
        null=True, blank=True,
        verbose_name="Người dùng"
    )

    # [DEMO] Plaintext OTP — chỉ để hội đồng xem trực tiếp trong DB
    otp_code = models.CharField(max_length=6, verbose_name="Mã OTP (plaintext - DEMO)")

    # [PRODUCTION] SHA-256 của otp_code — tính tự động trong save()
    otp_hash = models.CharField(
        max_length=64, blank=True, null=True,
        verbose_name="Mã OTP đã băm SHA-256"
    )

    # Metadata
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

    # Trạng thái vòng đời OTP
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="Thời điểm tạo")
    used_at    = models.DateTimeField(blank=True, null=True, verbose_name="Thời điểm sử dụng")
    is_used    = models.BooleanField(default=False, verbose_name="Đã sử dụng")
    is_active  = models.BooleanField(default=True,  verbose_name="Đang hiệu lực")

    class Meta:
        ordering     = ['-created_at']
        verbose_name = "Email OTP Log"

    def save(self, *args, **kwargs):
        """Tự động tính SHA-256 hash khi tạo mới (chỉ khi chưa có hash)."""
        if self.otp_code and not self.otp_hash:
            self.otp_hash = hashlib.sha256(
                self.otp_code.encode('utf-8')
            ).hexdigest()
        super().save(*args, **kwargs)

    def is_valid(self) -> bool:
        """
        OTP còn hợp lệ khi thỏa đồng thời 3 điều kiện:
          1. Chưa dùng (is_used=False)
          2. Admin chưa vô hiệu (is_active=True)
          3. Chưa quá 3 phút kể từ lúc tạo
        """
        return (
            not self.is_used
            and self.is_active
            and timezone.now() < self.created_at + datetime.timedelta(minutes=3)
        )

    def mark_used(self):
        """Đánh dấu OTP đã được sử dụng và ghi thời điểm."""
        self.is_used = True
        self.used_at = timezone.now()
        self.save(update_fields=['is_used', 'used_at'])

    def disable(self):
        """Admin vô hiệu hoá OTP thủ công (không chờ hết hạn)."""
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
# 4. ActivityLog — Nhật ký hành động của người dùng
# ════════════════════════════════════════════════════════════════════════════
class ActivityLog(models.Model):
    """
    Ghi lại mọi sự kiện quan trọng: đăng nhập, đăng xuất, thao tác 2FA.

    Trường username_attempt lưu tên đăng nhập thô (kể cả khi user không tồn tại)
    để phát hiện brute-force tấn công.
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
    username_attempt = models.CharField(
        max_length=150, null=True, blank=True,
        verbose_name="Tên đăng nhập thử"
    )
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
# 5. OTP — [DEPRECATED] Model OTP thế hệ cũ
# ════════════════════════════════════════════════════════════════════════════
class OTP(models.Model):
    """
    [DEPRECATED] Model OTP đơn giản từ phiên bản trước.

    Vấn đề:
      - Lưu code dạng plaintext, không hash.
      - Không có is_used → không thể ngăn replay attack.
      - Không có ip_address, action → không có audit trail.

    Trạng thái: GIỮ LẠI để tương thích migration. KHÔNG dùng cho tính năng mới.
    Thay thế bằng: EmailOTP.
    """
    user       = models.ForeignKey(User, on_delete=models.CASCADE)
    code       = models.CharField(max_length=6)  # [DEPRECATED] plaintext
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "[DEPRECATED] OTP cũ"

    def is_expired(self) -> bool:
        """OTP hết hạn sau 2 phút."""
        return timezone.now() > self.created_at + datetime.timedelta(minutes=2)


# ════════════════════════════════════════════════════════════════════════════
# 6. TrustedDevice — Thiết bị đã được tin cậy (remember this device)
# ════════════════════════════════════════════════════════════════════════════
class TrustedDevice(models.Model):
    """
    Lưu thông tin thiết bị đã hoàn thành 2FA.

    Khi user đăng nhập thành công với 2FA, session được đánh dấu is_active=True.
    Khi logout → is_active=False.
    Dùng cho tính năng "Xác thực từ thiết bị khác" (push auth).
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
    Cấu hình 2FA ở cấp admin — tách biệt với UserProfile để admin
    có thể can thiệp (force_disable_2fa, is_required) mà không sửa profile.

    Lưu ý:
      - force_disable_2fa: admin ép tắt 2FA (dùng khi user bị khóa thiết bị).
      - is_required: admin ép user phải bật 2FA (chưa implement enforce trong views).
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
        """
        2FA có hiệu lực không?
        False nếu admin đã bật force_disable_2fa.
        """
        if self.force_disable_2fa:
            return False
        return self.email_otp_enabled or self.google_auth_enabled


# ════════════════════════════════════════════════════════════════════════════
# 8. UserSessionControl — Cờ cưỡng chế đăng xuất
# ════════════════════════════════════════════════════════════════════════════
class UserSessionControl(models.Model):
    """
    Admin bật force_logout=True → middleware sẽ logout user ở request tiếp theo.
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
    Khi user đăng nhập từ thiết bị lạ, hệ thống gửi yêu cầu xác nhận
    đến thiết bị đang online (đã đăng nhập) của user đó.

    Luồng:
      1. Thiết bị lạ tạo RemoteAuthRequest(status='pending').
      2. Thiết bị online polling /get_pending_auth_request/ → thấy yêu cầu.
      3. Thiết bị online gọi /respond_auth_request/<id>/?status=approved|denied.
      4. Thiết bị lạ polling /check_auth_status/ → nhận kết quả → đăng nhập hoặc từ chối.
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
    Lưu trữ thông tin FIDO2 passkey của người dùng.

    Mỗi user có thể đăng ký nhiều passkey (đa thiết bị).
    sign_count dùng để phát hiện clone credential (nếu sign_count giảm → cảnh báo).
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
# SIGNALS — Tự động tạo/lưu Profile và ghi LoginHistory
# ════════════════════════════════════════════════════════════════════════════

@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    """Tự động tạo UserProfile mỗi khi có User mới được tạo."""
    if created:
        UserProfile.objects.get_or_create(user=instance)


@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    """
    Đồng bộ lưu UserProfile khi User được save.
    Dùng get_or_create để an toàn trong mọi trường hợp.
    """
    profile, _ = UserProfile.objects.get_or_create(user=instance)
    # Chỉ save nếu cần (tránh vòng lặp signal nếu UserProfile tự save)
    # Không gọi profile.save() ở đây vì get_or_create đã save rồi nếu created=True


@receiver(user_logged_in)
def log_login(sender, request, user, **kwargs):
    """
    Ghi lịch sử đăng nhập thành công.

    
    """
    LoginHistory.objects.create(
        user   = user,
        ip     = request.META.get('REMOTE_ADDR', '0.0.0.0'),  
        device = request.META.get('HTTP_USER_AGENT', 'Unknown')[:255],
        status = "success"
    )
