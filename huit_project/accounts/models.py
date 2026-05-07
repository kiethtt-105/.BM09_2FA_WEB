#import các thư viện 
from django.db import models
from django.contrib.auth.models import User
import datetime
from django.utils import timezone
import pyotp  
from django.utils.timezone import now
from django.db.models.signals import post_save
from django.dispatch import receiver
import uuid
from django.contrib.auth.signals import user_logged_in

# Mở rộng User mặc định bằng UserProfile để lưu thêm thông tin cá nhân và cấu hình 2FA
class UserProfile(models.Model):
    """Mở rộng User mặc định: thêm chữ đệm, SĐT, và cấu hình 2FA."""
    user         = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')

    # Thông tin cá nhân bổ sung
    middle_name  = models.CharField('Chữ đệm', max_length=50, blank=True, default='')
    phone_number = models.CharField('Số điện thoại', max_length=15, blank=True, default='')

    # 2FA — App (Google Authenticator)
    otp_secret = models.CharField(max_length=32, default=pyotp.random_base32, blank=True)

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

# Model lưu tạm dữ liệu đăng ký trước khi xác thực OTP
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

# Model lưu OTP ngắn hạn cho email (dùng cho 2FA login)
class EmailOTP(models.Model):
    """OTP ngắn hạn gắn với một User (dùng cho 2FA login)."""
    user       = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    otp_code   = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    is_used    = models.BooleanField(default=False)
    def is_valid(self):
        return not self.is_used and timezone.now() < self.created_at + datetime.timedelta(minutes=5)

#   Model lưu lịch sử hoạt động quan trọng của user (đăng nhập, đăng xuất, OTP, 2FA...)
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

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='activities',
        null=True,
        blank=True
    )

    username_attempt = models.CharField(max_length=150, null=True, blank=True)

    action = models.CharField(max_length=20, choices=ACTION_CHOICES)
    ip_address = models.CharField(max_length=50, blank=True, null=True)
    user_agent = models.TextField(blank=True, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        username = self.user.username if self.user else self.username_attempt
        return f"{username} - {self.get_action_display()} - {self.timestamp.strftime('%d/%m/%Y %H:%M')}"
# Model lưu OTP tạm thời cho các mục đích khác (ví dụ: xác thực 2FA login, reset mật khẩu...)
class OTP(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    # Trường này để phân biệt mục đích của OTP (ví dụ: '2fa_login', 'password_reset', v.v.)
    def is_expired(self):
        # Thiết lập thời gian hết hạn là 2 phút
        return timezone.now() > self.created_at + datetime.timedelta(minutes=2)
  
# Tự động tạo UserProfile khi tạo User mới  
@receiver(post_save, sender=User) # Khi User được lưu (tạo mới hoặc cập nhật)
# Nếu là tạo mới (created=True) → tự động tạo UserProfile liên kết với User đó
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.get_or_create(user=instance)

# Tự động lưu UserProfile khi User được lưu (đảm bảo đồng bộ)
@receiver(post_save, sender=User) # Khi User được lưu → tự động lưu UserProfile liên quan (đảm bảo đồng bộ)
# Lưu ý: Thực tế có thể không cần thiết nếu chỉ tạo UserProfile khi tạo User, nhưng để đảm bảo mọi thay đổi đều được lưu
def save_user_profile(sender, instance, **kwargs):
    instance.profile.save()
    
   # Model lưu thiết bị tin cậy (trusted device) để bỏ qua 2FA cho những lần đăng nhập sau từ thiết bị đó 
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
    
# Model lưu cấu hình 2FA của user (bật/tắt từng phương thức, khóa bí mật cho Google Authenticator, v.v.)
class User2FA(models.Model):
    user = models.OneToOneField(
        User, 
        on_delete=models.CASCADE, 
        related_name='user2fa'
    )
    # 2FA
    email_otp_enabled = models.BooleanField(default=False) # User có bật 2FA qua email OTP không
    google_auth_enabled = models.BooleanField(default=False) # User có bật 2FA qua Google Authenticator không

    google_secret = models.CharField(max_length=100, blank=True, null=True) # Khóa bí mật cho Google Authenticator (nếu user bật phương thức này)

    # Admin control
    # Trường này để admin có thể bắt buộc user phải dùng 2FA (bất kể user có bật hay không) → nếu true thì coi như user này luôn bật 2FA, nhưng admin vẫn có thể tắt từng phương thức cụ thể nếu muốn
    force_disable_2fa = models.BooleanField(default=False)
    
    # ← THÊM TRƯỜNG NÀY: Quyết định user này có BẮT BUỘC phải dùng 2FA không
    is_required = models.BooleanField(
        default=False, 
        verbose_name="Bắt buộc xác thực 2FA"
    )
    
    def __str__(self):
        return self.user.username
    # Thuộc tính tổng hợp để kiểm tra xem user này có đang bật 2FA hay không (dựa trên các phương thức và cả trường force_disable_2fa)
    @property  #
    def is_enabled(self): 
        """Kiểm tra user này có đang bật 2FA không"""
        if self.force_disable_2fa:
            return False
        return self.email_otp_enabled or self.google_auth_enabled

# Model để admin có thể kiểm soát phiên đăng nhập của user (ví dụ: bắt buộc đăng xuất, xem lịch sử đăng nhập, v.v.) 
class UserSessionControl(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE) # Liên kết 1-1 với User để lưu thông tin về phiên đăng nhập và kiểm soát
    force_logout = models.BooleanField(default=False)# Trường này để admin có thể bắt buộc user phải đăng xuất (khi admin bật lên thì user sẽ bị đăng xuất ở lần tương tác tiếp theo và phải đăng nhập lại)
# Model lưu lịch sử đăng nhập của user (thời gian, IP, thiết bị, trạng thái thành công/thất bại)  

# Model lưu lịch sử đăng nhập của user (thời gian, IP, thiết bị, trạng thái thành công/thất bại)
class LoginHistory(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    ip = models.GenericIPAddressField()
    device = models.CharField(max_length=255)
    time = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=50)  # success / failed
    
# Tự động ghi lại lịch sử đăng nhập mỗi khi user đăng nhập thành công
@receiver(user_logged_in)
def log_login(sender, request, user, **kwargs):
    LoginHistory.objects.create(
        user=user,
        ip=request.META.get('REMOTE_ADDR'),
        device=request.META.get('HTTP_USER_AGENT'),
        status="success"
    )
    
# Model để quản lý các yêu cầu đăng nhập từ thiết bị lạ (remote login) - admin có thể xem và phê duyệt hoặc từ chối
class RemoteAuthRequest(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    session_key = models.CharField(max_length=40) # Session của máy mới
    device_info = models.CharField(max_length=255)
    status = models.CharField(
        max_length=20, 
        choices=[('pending', 'Chờ'), ('approved', 'Đồng ý'), ('denied', 'Từ chối')],
        default='pending'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    
#UserPasskey: Model lưu thông tin về passkey (FIDO2) của user, bao gồm credentialId, publicKey, và số lần đã sử dụng khóa này để đăng nhập (sign_count)
class UserPasskey(models.Model):
    # Liên kết với User đang login
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="passkeys")
    # ID của khóa do điện thoại tạo ra
    credential_id = models.CharField(max_length=500, unique=True)
    # Nội dung khóa công khai (Lưu để sau này đối chiếu khi đăng nhập)
    public_key = models.TextField()
    # Số lần đã sử dụng khóa này
    sign_count = models.IntegerField(default=0) # Trường này sẽ được cập nhật mỗi lần user đăng nhập thành công bằng passkey này (để tăng tính bảo mật, tránh replay attack)
    created_at = models.DateTimeField(auto_now_add=True) # Thời gian tạo passkey (để admin có thể quản lý, ví dụ: xoá những passkey cũ không dùng nữa)
    # Trường này để phân biệt passkey nào đang được dùng để đăng nhập (nếu user có nhiều passkey thì sẽ có một passkey chính, những passkey khác sẽ là phụ)
    def __str__(self):
        return f"Passkey của {self.user.username}"