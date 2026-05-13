"""
admin.py — Cấu hình Django Admin cho hệ thống HUIT 2FA
=======================================================
Cấu trúc sidebar (theo thứ tự hiển thị):

  ACCOUNTS — Người dùng
    1. Users                    (auth.User)
    2. Hồ sơ người dùng         (UserProfile)
    3. Cấu hình 2FA (Admin)     (User2FA)
    4. Kiểm soát phiên          (UserSessionControl)

  ACCOUNTS — Xác thực & OTP
    5. Email OTP Logs           (EmailOTP)
    6. [DEPRECATED] OTP cũ     (OTP)
    7. Passkeys (FIDO2)         (UserPasskey)
    8. Thiết bị tin cậy         (TrustedDevice)
    9. Yêu cầu xác thực từ xa  (RemoteAuthRequest)

  ACCOUNTS — Nhật ký & Lịch sử
   10. Nhật ký hoạt động        (ActivityLog)
   11. Lịch sử đăng nhập        (LoginHistory)
   12. Đăng ký tạm chờ xác thực (PendingRegistration)

  AUTHENTICATION AND AUTHORIZATION
   13. Groups                   (auth.Group)
"""

from django.contrib import admin
from django.contrib.admin import AdminSite
from django.contrib.auth.models import User, Group
from django.contrib.auth.admin import (
    UserAdmin as BaseUserAdmin,
    GroupAdmin as BaseGroupAdmin,
)
from django.utils.html import format_html
from .models import (
    ActivityLog,
    EmailOTP,
    LoginHistory,
    OTP,
    PendingRegistration,
    RemoteAuthRequest,
    TrustedDevice,
    User2FA,
    UserPasskey,
    UserProfile,
    UserSessionControl,
)


# ══════════════════════════════════════════════════════════════════════════════
# CUSTOM ADMIN SITE
# ══════════════════════════════════════════════════════════════════════════════

class DefaultAdminSite(AdminSite):
    site_header = "HUIT Authentication System"
    site_title  = "HUIT Admin"
    index_title = "Trang quản trị hệ thống"

default_admin_site = DefaultAdminSite(name='default_admin')


# ══════════════════════════════════════════════════════════════════════════════
# 1. USER
# ══════════════════════════════════════════════════════════════════════════════

class CustomUserAdmin(BaseUserAdmin):
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


# ══════════════════════════════════════════════════════════════════════════════
# 2. USER PROFILE
# ══════════════════════════════════════════════════════════════════════════════

class UserProfileAdmin(admin.ModelAdmin):
    list_display    = ['user', 'get_full_name', 'phone_number', 'badge_email_otp', 'badge_app_otp', 'badge_fido2']
    search_fields   = ['user__username', 'user__email', 'phone_number']
    list_filter     = ['has_email_otp', 'has_app_otp', 'has_fido2']
    readonly_fields = ['otp_secret', 'fido2_credential', 'otp_expiry']
    list_per_page   = 30
    fieldsets = (
        ('👤 Người dùng',    {'fields': ('user',)}),
        ('📞 Liên hệ',       {'fields': ('phone_number', 'middle_name')}),
        ('🔐 Trạng thái 2FA', {'fields': ('has_email_otp', 'has_app_otp', 'has_fido2')}),
        ('🔒 Dữ liệu nhạy cảm (chỉ đọc)', {
            'classes': ('collapse',),
            'fields': ('otp_secret', 'email_otp', 'otp_expiry', 'fido2_credential'),
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
        return obj.has_fido2


# ══════════════════════════════════════════════════════════════════════════════
# 3. USER 2FA
# ══════════════════════════════════════════════════════════════════════════════

class User2FAAdmin(admin.ModelAdmin):
    list_display    = ['user', 'badge_email_otp', 'badge_google_auth', 'badge_required', 'badge_force_disable']
    search_fields   = ['user__username', 'user__email']
    list_filter     = ['email_otp_enabled', 'google_auth_enabled', 'is_required', 'force_disable_2fa']
    readonly_fields = ['google_secret']
    list_per_page   = 30
    fieldsets = (
        ('👤 Người dùng',    {'fields': ('user',)}),
        ('⚙️ Cấu hình 2FA', {'fields': ('email_otp_enabled', 'google_auth_enabled', 'is_required', 'force_disable_2fa')}),
        ('🔒 Bí mật (chỉ đọc)', {'classes': ('collapse',), 'fields': ('google_secret',)}),
    )

    @admin.display(description='Email OTP', boolean=True)
    def badge_email_otp(self, obj):
        return obj.email_otp_enabled

    @admin.display(description='Google Auth', boolean=True)
    def badge_google_auth(self, obj):
        return obj.google_auth_enabled

    @admin.display(description='Bắt buộc', boolean=True)
    def badge_required(self, obj):
        return obj.is_required

    @admin.display(description='Admin tắt buộc')
    def badge_force_disable(self, obj):
        if obj.force_disable_2fa:
            return format_html('<span style="color:red;font-weight:bold">⚠ Đang tắt buộc</span>')
        return format_html('<span style="color:green">✓ Bình thường</span>')


# ══════════════════════════════════════════════════════════════════════════════
# 4. USER SESSION CONTROL
# ══════════════════════════════════════════════════════════════════════════════

class UserSessionControlAdmin(admin.ModelAdmin):
    list_display  = ['user', 'status_badge']
    search_fields = ['user__username']
    list_filter   = ['force_logout']
    actions       = ['kick_users', 'reset_force_logout']
    list_per_page = 30

    @admin.display(description='Trạng thái phiên')
    def status_badge(self, obj):
        if obj.force_logout:
            return format_html('<span style="color:red;font-weight:bold">⚠ Đang bị kick</span>')
        return format_html('<span style="color:green">✓ Bình thường</span>')

    @admin.action(description='🔴 Kick — Cưỡng chế đăng xuất')
    def kick_users(self, request, queryset):
        n = queryset.update(force_logout=True)
        self.message_user(request, f'Đã kick {n} người dùng.')

    @admin.action(description='🟢 Reset force_logout → False')
    def reset_force_logout(self, request, queryset):
        n = queryset.update(force_logout=False)
        self.message_user(request, f'Đã reset {n} bản ghi.')


# ══════════════════════════════════════════════════════════════════════════════
# 5. EMAIL OTP
# ══════════════════════════════════════════════════════════════════════════════

class EmailOTPAdmin(admin.ModelAdmin):
    list_display    = ['user', 'action_display', 'email_sent', 'ip_address', 'created_at', 'used_at', 'badge_used', 'badge_active']
    search_fields   = ['user__username', 'email_sent', 'ip_address']
    list_filter     = ['action', 'is_used', 'is_active']
    ordering        = ['-created_at']
    date_hierarchy  = 'created_at'
    readonly_fields = ['otp_code', 'otp_hash', 'created_at', 'used_at']
    list_per_page   = 50
    fieldsets = (
        ('👤 Người dùng',       {'fields': ('user', 'email_sent', 'ip_address')}),
        ('📋 Thông tin OTP',    {'fields': ('action', 'is_used', 'is_active', 'created_at', 'used_at')}),
        ('🔒 Dữ liệu mã hóa (chỉ đọc)', {
            'classes': ('collapse',),
            'fields': ('otp_code', 'otp_hash'),
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
            color, obj.get_action_display()
        )

    @admin.display(description='Đã dùng', boolean=True)
    def badge_used(self, obj):
        return obj.is_used

    @admin.display(description='Hiệu lực', boolean=True)
    def badge_active(self, obj):
        return obj.is_active


# ══════════════════════════════════════════════════════════════════════════════
# 6. OTP (DEPRECATED)
# ══════════════════════════════════════════════════════════════════════════════

class OTPAdmin(admin.ModelAdmin):
    list_display    = ['user', 'code', 'created_at', 'is_expired_display']
    search_fields   = ['user__username']
    ordering        = ['-created_at']
    readonly_fields = ['code', 'created_at']
    list_per_page   = 50

    @admin.display(description='Hết hạn')
    def is_expired_display(self, obj):
        if obj.is_expired():
            return format_html('<span style="color:red">✗ Hết hạn</span>')
        return format_html('<span style="color:green">✓ Còn hạn</span>')


# ══════════════════════════════════════════════════════════════════════════════
# 7. USER PASSKEY (FIDO2)
# ══════════════════════════════════════════════════════════════════════════════

class UserPasskeyAdmin(admin.ModelAdmin):
    list_display    = ['user', 'cred_short', 'sign_count', 'created_at']
    search_fields   = ['user__username']
    ordering        = ['-created_at']
    date_hierarchy  = 'created_at'
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


# ══════════════════════════════════════════════════════════════════════════════
# 8. TRUSTED DEVICE
# ══════════════════════════════════════════════════════════════════════════════

class TrustedDeviceAdmin(admin.ModelAdmin):
    list_display    = ['user', 'name', 'ip_address', 'last_seen', 'badge_active', 'session_short']
    search_fields   = ['user__username', 'name', 'ip_address']
    list_filter     = ['is_active']
    ordering        = ['-last_seen']
    date_hierarchy  = 'last_seen'
    readonly_fields = ['device_id', 'session_key', 'user_agent', 'last_seen']
    list_per_page   = 30
    fieldsets = (
        ('👤 Người dùng',      {'fields': ('user',)}),
        ('💻 Thông tin thiết bị', {'fields': ('name', 'device_id', 'ip_address', 'user_agent')}),
        ('📡 Trạng thái',      {'fields': ('is_active', 'last_seen', 'session_key')}),
    )

    @admin.display(description='Hoạt động', boolean=True)
    def badge_active(self, obj):
        return obj.is_active

    @admin.display(description='Session Key')
    def session_short(self, obj):
        return (obj.session_key[:12] + '…') if obj.session_key else '—'


# ══════════════════════════════════════════════════════════════════════════════
# 9. REMOTE AUTH REQUEST
# ══════════════════════════════════════════════════════════════════════════════

class RemoteAuthRequestAdmin(admin.ModelAdmin):
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
        labels = {'pending': '⏳ Chờ', 'approved': '✓ Đồng ý', 'denied': '✗ Từ chối'}
        color = colors.get(obj.status, '#666')
        label = labels.get(obj.status, obj.status)
        return format_html('<span style="color:{};font-weight:bold">{}</span>', color, label)


# ══════════════════════════════════════════════════════════════════════════════
# 10. ACTIVITY LOG
# ══════════════════════════════════════════════════════════════════════════════

class ActivityLogAdmin(admin.ModelAdmin):
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
            color, obj.get_action_display()
        )

    @admin.display(description='User-Agent')
    def ua_short(self, obj):
        if obj.user_agent:
            return (obj.user_agent[:55] + '…') if len(obj.user_agent) > 55 else obj.user_agent
        return '—'


# ══════════════════════════════════════════════════════════════════════════════
# 11. LOGIN HISTORY
# ══════════════════════════════════════════════════════════════════════════════

class LoginHistoryAdmin(admin.ModelAdmin):
    list_display    = ['user', 'ip', 'device_short', 'time', 'status_badge']
    search_fields   = ['user__username', 'ip', 'device']
    list_filter     = ['status']
    ordering        = ['-time']
    date_hierarchy  = 'time'
    readonly_fields = ['user', 'ip', 'device', 'time', 'status']
    list_per_page   = 50

    @admin.display(description='Thiết bị')
    def device_short(self, obj):
        return (obj.device[:55] + '…') if len(obj.device) > 55 else obj.device

    @admin.display(description='Trạng thái')
    def status_badge(self, obj):
        color = '#4CAF50' if obj.status == 'success' else '#F44336'
        return format_html('<b style="color:{}">{}</b>', color, obj.status)


# ══════════════════════════════════════════════════════════════════════════════
# 12. PENDING REGISTRATION
# ══════════════════════════════════════════════════════════════════════════════

class PendingRegistrationAdmin(admin.ModelAdmin):
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
            'fields': ('otp_code', 'temp_data'),
        }),
    )

    @admin.display(description='Đã dùng', boolean=True)
    def badge_used(self, obj):
        return obj.is_used

    @admin.display(description='Còn hiệu lực')
    def badge_valid(self, obj):
        if obj.is_valid():
            return format_html('<span style="color:green">✓ Còn hạn</span>')
        return format_html('<span style="color:red">✗ Hết hạn</span>')


# ══════════════════════════════════════════════════════════════════════════════
# ĐĂNG KÝ VÀO default_admin_site  (/admin-origin/)
# ══════════════════════════════════════════════════════════════════════════════

default_admin_site.register(User,                 CustomUserAdmin)
default_admin_site.register(Group,                BaseGroupAdmin)
default_admin_site.register(UserProfile,          UserProfileAdmin)
default_admin_site.register(User2FA,              User2FAAdmin)
default_admin_site.register(UserSessionControl,   UserSessionControlAdmin)
default_admin_site.register(EmailOTP,             EmailOTPAdmin)
default_admin_site.register(OTP,                  OTPAdmin)
default_admin_site.register(UserPasskey,          UserPasskeyAdmin)
default_admin_site.register(TrustedDevice,        TrustedDeviceAdmin)
default_admin_site.register(RemoteAuthRequest,    RemoteAuthRequestAdmin)
default_admin_site.register(ActivityLog,          ActivityLogAdmin)
default_admin_site.register(LoginHistory,         LoginHistoryAdmin)
default_admin_site.register(PendingRegistration,  PendingRegistrationAdmin)


# ══════════════════════════════════════════════════════════════════════════════
# ĐĂNG KÝ VÀO admin.site MẶC ĐỊNH  (/admin/)
# ══════════════════════════════════════════════════════════════════════════════

admin.site.site_header = "HUIT Authentication System"
admin.site.site_title  = "HUIT Admin"
admin.site.index_title = "Trang quản trị hệ thống"

admin.site.unregister(User)
admin.site.unregister(Group)

admin.site.register(User,                 CustomUserAdmin)
admin.site.register(Group,                BaseGroupAdmin)
admin.site.register(UserProfile,          UserProfileAdmin)
admin.site.register(User2FA,              User2FAAdmin)
admin.site.register(UserSessionControl,   UserSessionControlAdmin)
admin.site.register(EmailOTP,             EmailOTPAdmin)
admin.site.register(OTP,                  OTPAdmin)
admin.site.register(UserPasskey,          UserPasskeyAdmin)
admin.site.register(TrustedDevice,        TrustedDeviceAdmin)
admin.site.register(RemoteAuthRequest,    RemoteAuthRequestAdmin)
admin.site.register(ActivityLog,          ActivityLogAdmin)
admin.site.register(LoginHistory,         LoginHistoryAdmin)
admin.site.register(PendingRegistration,  PendingRegistrationAdmin)
