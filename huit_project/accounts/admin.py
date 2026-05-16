from django.contrib import admin
from django.contrib.admin import AdminSite
from django.contrib.auth.models import User, Group
from django.contrib.auth.admin import (
    UserAdmin as BaseUserAdmin,
    GroupAdmin as BaseGroupAdmin,
)
from django.utils.html import format_html, mark_safe

from .models import (
    ActivityLog,
    EmailOTP,
    OTPAttempt,
    PendingRegistration,
    RemoteAuthRequest,
    TrustedDevice,
    UserPasskey,
    UserProfile,
)


# ═══════════════════════════════════════════════════════════════════════════════
# CUSTOM ADMIN SITE
# ═══════════════════════════════════════════════════════════════════════════════

class DefaultAdminSite(AdminSite):
    """Admin site tuỳ chỉnh — gắn vào /admin-origin/."""
    site_header = "HUIT Authentication System"
    site_title  = "HUIT Admin"
    index_title = "Trang quản trị hệ thống"

default_admin_site = DefaultAdminSite(name='default_admin')


# ═══════════════════════════════════════════════════════════════════════════════
# 1. USER
# ═══════════════════════════════════════════════════════════════════════════════

class CustomUserAdmin(BaseUserAdmin):
    """
    Mở rộng UserAdmin mặc định của Django.

    Hiển thị thêm họ tên đầy đủ, lọc theo trạng thái / quyền hạn.
    readonly_fields: date_joined, last_login — không chỉnh sửa trực tiếp.
    """
    list_display    = ['username', 'email', 'get_full_name', 'is_active', 'is_staff', 'is_superuser', 'date_joined']
    search_fields   = ['username', 'email', 'first_name', 'last_name']
    list_filter     = ['is_active', 'is_staff', 'is_superuser', 'groups']
    ordering        = ['-date_joined']
    readonly_fields = ['date_joined', 'last_login']
    list_per_page   = 30
    fieldsets = (
        ('🔑 Tài khoản',  {'fields': ('username', 'password')}),
        ('👤 Cá nhân',    {'fields': ('first_name', 'last_name', 'email')}),
        ('🛡️ Quyền hạn', {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        ('🕐 Thời gian',  {'fields': ('last_login', 'date_joined')}),
    )

    @admin.display(description='Họ và tên')
    def get_full_name(self, obj):
        return f"{obj.first_name} {obj.last_name}".strip() or '—'


# ═══════════════════════════════════════════════════════════════════════════════
# 2. USER PROFILE
# ═══════════════════════════════════════════════════════════════════════════════

class UserProfileAdmin(admin.ModelAdmin):
    """
    Quản lý hồ sơ người dùng mở rộng.

    Gộp các cờ từ User2FA (force_disable_2fa, is_required) và
    UserSessionControl (force_logout) vào cùng một form.
    otp_secret để readonly + collapse — lưu dạng Fernet-encrypted.
    has_fido2 là property (không phải DB field) nên không đưa vào fieldsets.
    """
    list_display    = ['user', 'get_full_name', 'phone_number',
                       'badge_email_otp', 'badge_app_otp', 'badge_fido2',
                       'badge_force_disable', 'badge_force_logout']
    search_fields   = ['user__username', 'user__email', 'phone_number']
    list_filter     = ['has_email_otp', 'has_app_otp', 'force_disable_2fa', 'is_required', 'force_logout']
    readonly_fields = ['otp_secret', 'hotp_secret']
    list_per_page   = 30
    actions         = ['kick_users', 'reset_force_logout']
    fieldsets = (
        ('👤 Người dùng',          {'fields': ('user',)}),
        ('📞 Liên hệ',             {'fields': ('phone_number', 'middle_name')}),
        ('🔐 Trạng thái 2FA',     {'fields': ('has_email_otp', 'has_app_otp', 'has_hotp', 'hotp_counter')}),
        ('⚙️ Kiểm soát Admin',    {'fields': ('force_disable_2fa', 'is_required', 'force_logout')}),
        ('🔒 Dữ liệu nhạy cảm (chỉ đọc)', {
            'classes': ('collapse',),
            'fields':  ('otp_secret', 'hotp_secret'),
        }),
    )

    @admin.display(description='Họ và tên')
    def get_full_name(self, obj):
        return obj.get_full_name() or '—'

    @admin.display(description='Email OTP', boolean=True)
    def badge_email_otp(self, obj):
        return obj.has_email_otp

    @admin.display(description='App OTP', boolean=True)
    def badge_app_otp(self, obj):
        return obj.has_app_otp

    @admin.display(description='FIDO2', boolean=True)
    def badge_fido2(self, obj):
        return obj.has_fido2  # property — gọi user.passkeys.exists()

    @admin.display(description='Admin tắt buộc')
    def badge_force_disable(self, obj):
        if obj.force_disable_2fa:
            return mark_safe('<span style="color:red;font-weight:bold">⚠ Đang tắt buộc</span>')
        return mark_safe('<span style="color:green">✓ Bình thường</span>')

    @admin.display(description='Force Logout')
    def badge_force_logout(self, obj):
        if obj.force_logout:
            return mark_safe('<span style="color:red;font-weight:bold">⚠ Đang bị kick</span>')
        return mark_safe('<span style="color:green">✓ Bình thường</span>')

    @admin.action(description='🔴 Kick — Cưỡng chế đăng xuất')
    def kick_users(self, request, queryset):
        n = queryset.update(force_logout=True)
        self.message_user(request, f'Đã kick {n} người dùng.')

    @admin.action(description='🟢 Reset force_logout → False')
    def reset_force_logout(self, request, queryset):
        n = queryset.update(force_logout=False)
        self.message_user(request, f'Đã reset {n} bản ghi.')


# ═══════════════════════════════════════════════════════════════════════════════
# 3. EMAIL OTP
# ═══════════════════════════════════════════════════════════════════════════════

class EmailOTPAdmin(admin.ModelAdmin):
    """
    Lịch sử Email OTP — log toàn bộ mã đã sinh.

    action_display: tô màu theo loại thao tác (register / login_2fa / ...).
    otp_code, otp_hash để readonly + collapse — không cho chỉnh sửa.
    """
    list_display    = ['user', 'action_display', 'email_sent', 'ip_address',
                       'created_at', 'used_at', 'badge_used', 'badge_active']
    search_fields   = ['user__username', 'email_sent', 'ip_address']
    list_filter     = ['action', 'is_used', 'is_active']
    ordering        = ['-created_at']
    date_hierarchy  = 'created_at'
    readonly_fields = ['otp_code', 'otp_hash', 'created_at', 'used_at']
    list_per_page   = 50
    fieldsets = (
        ('👤 Người dùng',    {'fields': ('user', 'email_sent', 'ip_address')}),
        ('📋 Thông tin OTP', {'fields': ('action', 'is_used', 'is_active', 'created_at', 'used_at')}),
        ('🔒 Dữ liệu mã hóa (chỉ đọc)', {
            'classes': ('collapse',),
            'fields':  ('otp_code', 'otp_hash'),
        }),
    )

    @admin.display(description='Loại thao tác')
    def action_display(self, obj):
        colors = {
            'register':    '#2196F3',
            'login_2fa':   '#4CAF50',
            'setup_2fa':   '#FF9800',
            'update_info': '#9C27B0',
            'disable_2fa': '#F44336',
        }
        color = colors.get(obj.action, '#666')
        return format_html(
            '<span style="color:{};font-weight:bold">{}</span>',
            color, obj.get_action_display(),
        )

    @admin.display(description='Đã dùng', boolean=True)
    def badge_used(self, obj):
        return obj.is_used

    @admin.display(description='Hiệu lực', boolean=True)
    def badge_active(self, obj):
        return obj.is_active


# ═══════════════════════════════════════════════════════════════════════════════
# 4. USER PASSKEY (FIDO2)
# ═══════════════════════════════════════════════════════════════════════════════

class UserPasskeyAdmin(admin.ModelAdmin):
    """
    Passkeys (FIDO2 / WebAuthn) đã đăng ký của người dùng.

    credential_id, public_key để readonly — dữ liệu khoá công khai không chỉnh sửa.
    cred_short: rút ngắn credential_id cho dễ đọc trên list view.
    """
    list_display    = ['user', 'cred_short', 'sign_count', 'created_at']
    search_fields   = ['user__username']
    ordering        = ['-created_at']
    readonly_fields = ['credential_id', 'public_key', 'created_at']
    list_per_page   = 30
    fieldsets = (
        ('👤 Người dùng', {'fields': ('user',)}),
        ('🔑 Passkey (chỉ đọc)', {
            'fields': ('credential_id', 'public_key', 'sign_count', 'created_at'),
        }),
    )

    @admin.display(description='Credential ID')
    def cred_short(self, obj):
        return (obj.credential_id[:24] + '…') if len(obj.credential_id) > 24 else obj.credential_id


# ═══════════════════════════════════════════════════════════════════════════════
# 5. TRUSTED DEVICE
# ═══════════════════════════════════════════════════════════════════════════════

class TrustedDeviceAdmin(admin.ModelAdmin):
    """
    Thiết bị tin cậy đã được user xác nhận sau 2FA.

    session_key liên kết với Django session — readonly.
    session_short: rút ngắn 12 ký tự đầu cho list view.
    is_active = False khi logout, admin kick, hoặc session hết hạn.
    """
    list_display    = ['user', 'name', 'ip_address', 'last_seen', 'badge_active', 'session_short']
    search_fields   = ['user__username', 'name', 'ip_address']
    list_filter     = ['is_active']
    ordering        = ['-last_seen']
    date_hierarchy  = 'last_seen'
    readonly_fields = ['device_id', 'session_key', 'user_agent', 'last_seen']
    list_per_page   = 30
    fieldsets = (
        ('👤 Người dùng',         {'fields': ('user',)}),
        ('💻 Thông tin thiết bị', {'fields': ('name', 'device_id', 'ip_address', 'user_agent')}),
        ('📡 Trạng thái',         {'fields': ('is_active', 'last_seen', 'session_key')}),
    )

    @admin.display(description='Hoạt động', boolean=True)
    def badge_active(self, obj):
        return obj.is_active

    @admin.display(description='Session Key')
    def session_short(self, obj):
        return (obj.session_key[:12] + '…') if obj.session_key else '—'


# ═══════════════════════════════════════════════════════════════════════════════
# 6. REMOTE AUTH REQUEST
# ═══════════════════════════════════════════════════════════════════════════════

class RemoteAuthRequestAdmin(admin.ModelAdmin):
    """
    Yêu cầu xác thực từ thiết bị khác (Remote / Push Auth).

    status: pending / approved / denied — tô màu theo trạng thái.
    session_key, created_at để readonly.
    device_info_short: cắt 55 ký tự tránh tràn cột.
    """
    list_display    = ['user', 'device_info_short', 'status_badge', 'created_at']
    search_fields   = ['user__username', 'device_info']
    list_filter     = ['status']
    ordering        = ['-created_at']
    date_hierarchy  = 'created_at'
    readonly_fields = ['session_key', 'created_at']
    list_per_page   = 30

    @admin.display(description='Thiết bị')
    def device_info_short(self, obj):
        return (obj.device_info[:55] + '…') if len(obj.device_info) > 55 else obj.device_info

    @admin.display(description='Trạng thái')
    def status_badge(self, obj):
        colors = {'pending': '#FF9800', 'approved': '#4CAF50', 'denied': '#F44336'}
        labels = {'pending': '⏳ Chờ',  'approved': '✓ Đồng ý', 'denied': '✗ Từ chối'}
        color  = colors.get(obj.status, '#666')
        label  = labels.get(obj.status, obj.status)
        return format_html('<span style="color:{};font-weight:bold">{}</span>', color, label)


# ═══════════════════════════════════════════════════════════════════════════════
# 7. ACTIVITY LOG
# ═══════════════════════════════════════════════════════════════════════════════

class ActivityLogAdmin(admin.ModelAdmin):
    """
    Nhật ký hoạt động hệ thống — thay thế hoàn toàn LoginHistory.
    Toàn bộ readonly, không chỉnh sửa.

    action_badge: xanh lá = thành công, đỏ = thất bại / nguy hiểm, cam = trung tính.
    ua_short: rút gọn User-Agent 55 ký tự.
    username_attempt lưu tên thô kể cả khi user không tồn tại — phát hiện brute-force.
    """
    list_display    = ['timestamp', 'action_badge', 'username_attempt', 'user', 'ip_address', 'ua_short']
    search_fields   = ['username_attempt', 'ip_address', 'user__username']
    list_filter     = ['action']
    ordering        = ['-timestamp']
    date_hierarchy  = 'timestamp'
    readonly_fields = ['action', 'ip_address', 'timestamp', 'user', 'user_agent', 'username_attempt']
    list_per_page   = 50

    @admin.display(description='Hành động')
    def action_badge(self, obj):
        success_actions = {'login', 'otp_success', '2fa_enable', 'register'}
        danger_actions  = {'login_failed', 'login_locked_attempt', 'force_logout', 'otp_fail'}
        if obj.action in success_actions:
            color = '#4CAF50'
        elif obj.action in danger_actions:
            color = '#F44336'
        else:
            color = '#FF9800'
        return format_html(
            '<span style="color:{};font-weight:bold">{}</span>',
            color, obj.get_action_display(),
        )

    @admin.display(description='User-Agent')
    def ua_short(self, obj):
        if obj.user_agent:
            return (obj.user_agent[:55] + '…') if len(obj.user_agent) > 55 else obj.user_agent
        return '—'


# ═══════════════════════════════════════════════════════════════════════════════
# 8. PENDING REGISTRATION
# ═══════════════════════════════════════════════════════════════════════════════

class PendingRegistrationAdmin(admin.ModelAdmin):
    """
    Đăng ký tạm — chờ user xác thực OTP email để hoàn tất tạo tài khoản.

    badge_valid: gọi is_valid() của model để kiểm tra 10 phút còn hạn.
    otp_code, temp_data để readonly + collapse — chứa dữ liệu nhạy cảm.
    temp_data['password'] đã qua make_password() — không lưu plaintext.
    """
    list_display    = ['email', 'created_at', 'badge_used', 'badge_valid']
    search_fields   = ['email']
    list_filter     = ['is_used']
    ordering        = ['-created_at']
    date_hierarchy  = 'created_at'
    readonly_fields = ['otp_code', 'created_at', 'temp_data']
    list_per_page   = 30
    fieldsets = (
        ('📧 Thông tin', {'fields': ('email', 'is_used', 'created_at')}),
        ('🔒 Dữ liệu OTP (chỉ đọc)', {
            'classes': ('collapse',),
            'fields':  ('otp_code', 'temp_data'),
        }),
    )

    @admin.display(description='Đã dùng', boolean=True)
    def badge_used(self, obj):
        return obj.is_used

    @admin.display(description='Còn hiệu lực')
    def badge_valid(self, obj):
        if obj.is_valid():
            return mark_safe('<span style="color:green">✓ Còn hạn</span>')
        return mark_safe('<span style="color:red">✗ Hết hạn</span>')


# ═══════════════════════════════════════════════════════════════════════════════
# ĐĂNG KÝ VÀO default_admin_site  (/admin-origin/)
# ═══════════════════════════════════════════════════════════════════════════════

default_admin_site.register(User,                CustomUserAdmin)
default_admin_site.register(Group,               BaseGroupAdmin)
default_admin_site.register(UserProfile,         UserProfileAdmin)
default_admin_site.register(EmailOTP,            EmailOTPAdmin)
default_admin_site.register(UserPasskey,         UserPasskeyAdmin)
default_admin_site.register(TrustedDevice,       TrustedDeviceAdmin)
default_admin_site.register(RemoteAuthRequest,   RemoteAuthRequestAdmin)
default_admin_site.register(ActivityLog,         ActivityLogAdmin)
default_admin_site.register(PendingRegistration, PendingRegistrationAdmin)


# ═══════════════════════════════════════════════════════════════════════════════
# 9. OTP ATTEMPT (Rate Limit Monitor)
# ═══════════════════════════════════════════════════════════════════════════════

class OTPAttemptAdmin(admin.ModelAdmin):
    """
    [FIX-RATELIMIT] Theo dõi các lần nhập OTP sai để phát hiện brute-force.
    Toàn bộ readonly — chỉ để giám sát, không chỉnh sửa.
    """
    list_display    = ['ip_address', 'user', 'action', 'created_at']
    search_fields   = ['ip_address', 'user__username']
    list_filter     = ['action']
    ordering        = ['-created_at']
    date_hierarchy  = 'created_at'
    readonly_fields = ['user', 'ip_address', 'action', 'created_at']
    list_per_page   = 50
    actions         = ['clear_attempts']

    @admin.action(description='🟢 Xóa các lần thử đã chọn (unblock user/IP)')
    def clear_attempts(self, request, queryset):
        n = queryset.count()
        queryset.delete()
        self.message_user(request, f'Đã xóa {n} bản ghi — user/IP được unblock.')


default_admin_site.register(OTPAttempt, OTPAttemptAdmin)

admin.site.site_header = "HUIT Authentication System"
admin.site.site_title  = "HUIT Admin"
admin.site.index_title = "Trang quản trị hệ thống"

admin.site.unregister(User)
admin.site.unregister(Group)

admin.site.register(User,                CustomUserAdmin)
admin.site.register(Group,               BaseGroupAdmin)
admin.site.register(UserProfile,         UserProfileAdmin)
admin.site.register(EmailOTP,            EmailOTPAdmin)
admin.site.register(UserPasskey,         UserPasskeyAdmin)
admin.site.register(TrustedDevice,       TrustedDeviceAdmin)
admin.site.register(RemoteAuthRequest,   RemoteAuthRequestAdmin)
admin.site.register(ActivityLog,         ActivityLogAdmin)
admin.site.register(PendingRegistration, PendingRegistrationAdmin)
admin.site.register(OTPAttempt,          OTPAttemptAdmin)