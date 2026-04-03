from django.db import models
from django.contrib.auth.models import User
import datetime
from django.utils import timezone
import pyotp  
from django.utils.timezone import now
from django.db.models.signals import post_save
from django.dispatch import receiver

class UserProfile(models.Model):
    """Mở rộng User mặc định: thêm chữ đệm, SĐT, và cấu hình 2FA."""
    user         = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')

    # Thông tin cá nhân bổ sung
    middle_name  = models.CharField('Chữ đệm', max_length=50, blank=True, default='')
    phone_number = models.CharField('Số điện thoại', max_length=15, blank=True, default='')

    # 2FA — App (Google Authenticator)
    otp_secret   = models.CharField(max_length=32, default=pyotp.random_base32)
    has_app_otp  = models.BooleanField(default=False)

    # 2FA — Email OTP
    has_email_otp = models.BooleanField(default=False)
    email_otp     = models.CharField(max_length=6, blank=True, null=True)
    otp_expiry    = models.DateTimeField(blank=True, null=True)

    # ==================== FIDO2 / PASSKEY  ====================
    has_fido2         = models.BooleanField(default=False, verbose_name="Đã bật FIDO2")
    fido2_credential  = models.JSONField(null=True, blank=True)   # Lưu credentialId + publicKey (demo)

    def __str__(self):
        return f"Profile({self.user.username})"
    @property
    def is_2fa_enabled(self):
        return self.has_email_otp or self.has_app_otp

    def get_full_name(self):
        """Trả về: Họ + Chữ đệm + Tên"""
        parts = [self.user.first_name, self.middle_name, self.user.last_name]
        return ' '.join(p for p in parts if p)



class PendingRegistration(models.Model):
    """
    Lưu tạm dữ liệu đăng ký trước khi xác thực OTP.
    Sau khi OTP hợp lệ → tạo User + UserProfile thật → xoá bản ghi này.
    """
    email      = models.EmailField(unique=True)
    otp_code   = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    is_used    = models.BooleanField(default=False)

    # Dữ liệu form tạm (JSON)
    temp_data  = models.JSONField(default=dict)

    OTP_EXPIRY_MINUTES = 10

    def is_valid(self):
        expiry = self.created_at + datetime.timedelta(minutes=self.OTP_EXPIRY_MINUTES)
        return not self.is_used and timezone.now() < expiry

    def __str__(self):
        return f"PendingReg({self.email})"


class EmailOTP(models.Model):
    """OTP ngắn hạn gắn với một User (dùng cho 2FA login)."""
    user       = models.ForeignKey(User, on_delete=models.CASCADE)
    otp_code   = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    is_used    = models.BooleanField(default=False)

    def is_valid(self):
        return not self.is_used and timezone.now() < self.created_at + datetime.timedelta(minutes=5)



#Tạo model log đăng nhập
from django.db import models
from django.contrib.auth.models import User

class ActivityLog(models.Model):
    ACTION_CHOICES = [
        ('login', 'Đăng nhập'),
        ('logout', 'Đăng xuất'),
        ('otp_fail', 'Xác thực OTP thất bại'),
        ('otp_success', 'Xác thực OTP thành công'),
        ('2fa_enable', 'Bật bảo mật 2FA'),
        ('2fa_disable', 'Tắt bảo mật 2FA'),
        ('register', 'Đăng ký tài khoản'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='activities')
    action = models.CharField(max_length=20, choices=ACTION_CHOICES)
    ip_address = models.CharField(max_length=50, blank=True, null=True)
    user_agent = models.TextField(blank=True, null=True) # Lưu trình duyệt/thiết bị
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Nhật ký hoạt động"
        verbose_name_plural = "Nhật ký hoạt động"
        ordering = ['-timestamp'] # Mới nhất hiện lên đầu

    def __str__(self):
        return f"{self.user.username} - {self.get_action_display()} - {self.timestamp.strftime('%d/%m/%Y %H:%i')}"



class OTP(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_expired(self):
        # Thiết lập thời gian hết hạn là 2 phút
        return timezone.now() > self.created_at + datetime.timedelta(minutes=2)
    
@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.get_or_create(user=instance)

@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    instance.profile.save()
    
import uuid
# models.py

class TrustedDevice(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='trusted_devices')

    device_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)

    session_key = models.CharField(max_length=40, blank=True, null=True)

    name = models.CharField(max_length=255, default="Thiết bị không xác định")

    user_agent = models.TextField(blank=True, null=True)
    ip_address = models.CharField(max_length=50, blank=True, null=True)

    last_seen = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return f"{self.user.username} - {self.name}"
# models.py
from django.db import models
from django.contrib.auth.models import User

class User2FA(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)

    email_otp_enabled = models.BooleanField(default=False)
    google_auth_enabled = models.BooleanField(default=False)

    google_secret = models.CharField(max_length=100, blank=True, null=True)

    # admin control
    force_disable_2fa = models.BooleanField(default=False)

    def __str__(self):
        return self.user.username
class UserSessionControl(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    force_logout = models.BooleanField(default=False)
    
class LoginHistory(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    ip = models.GenericIPAddressField()
    device = models.CharField(max_length=255)
    time = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=50)  # success / failed
    
from django.contrib.auth.signals import user_logged_in
from django.dispatch import receiver

@receiver(user_logged_in)
def log_login(sender, request, user, **kwargs):
    LoginHistory.objects.create(
        user=user,
        ip=request.META.get('REMOTE_ADDR'),
        device=request.META.get('HTTP_USER_AGENT'),
        status="success"
    )