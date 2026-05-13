from django.contrib import admin
from django.contrib.admin import AdminSite
from django.contrib.auth.models import User, Group
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin, GroupAdmin as BaseGroupAdmin
from django.utils.html import format_html
from .models import (
    ActivityLog,
    UserProfile,
    User2FA,
    EmailOTP,
    LoginHistory,
    OTP,
    PendingRegistration,
    RemoteAuthRequest,
    UserPasskey,
    UserSessionControl,
    TrustedDevice,
)


# ==================== CUSTOM ADMIN SITE ====================

class DefaultAdminSite(AdminSite):
    site_header = "HUIT Authentication System"
    site_title  = "HUIT Admin"
    index_title = "Trang quản trị hệ thống"

default_admin_site = DefaultAdminSite(name='default_admin')


# ==================== ADMIN CLASSES ====================

class CustomUserAdmin(BaseUserAdmin):
    list_display    = ['username', 'email', 'first_name', 'last_name', 'is_active', 'is_staff', 'date_joined']
    search_fields   = ['username', 'email', 'first_name', 'last_name']
    list_filter     = ['is_active', 'is_staff', 'is_superuser']
    ordering        = ['-date_joined']
    readonly_fields = ['date_joined', 'last_login']
    fieldsets = (
        ('Tài khoản',     {'fields': ('username', 'password')}),
        ('Cá nhân',       {'fields': ('first_name', 'last_name', 'email')}),
        ('Quyền hạn',     {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        ('Thời gian',     {'fields': ('last_login', 'date_joined')}),
    )


class UserProfileAdmin(admin.ModelAdmin):
    list_display    = ['user', 'phone_number', 'has_email_otp', 'has_app_otp', 'has_fido2']
    search_fields   = ['user__username', 'user__email', 'phone_number']
    list_filter     = ['has_email_otp', 'has_app_otp', 'has_fido2']
    readonly_fields = ['otp_secret', 'fido2_credential']
    fieldsets = (
        ('Người dùng',    {'fields': ('user',)}),
        ('Liên hệ',       {'fields': ('phone_number', 'middle_name')}),
        ('Xác thực 2FA',  {'fields': ('has_email_otp', 'has_app_otp', 'has_fido2')}),
        ('Dữ liệu OTP',   {'classes': ('collapse',), 'fields': ('otp_secret', 'email_otp', 'otp_expiry', 'fido2_credential')}),
    )


class User2FAAdmin(admin.ModelAdmin):
    list_display    = ['user', 'email_otp_enabled', 'google_auth_enabled', 'is_required', 'force_disable_2fa']
    search_fields   = ['user__username']
    list_filter     = ['email_otp_enabled', 'google_auth_enabled', 'is_required', 'force_disable_2fa']
    readonly_fields = ['google_secret']
    fieldsets = (
        ('Người dùng',   {'fields': ('user',)}),
        ('Cấu hình 2FA', {'fields': ('email_otp_enabled', 'google_auth_enabled', 'is_required', 'force_disable_2fa')}),
        ('Bí mật',       {'classes': ('collapse',), 'fields': ('google_secret',)}),
    )


class ActivityLogAdmin(admin.ModelAdmin):
    list_display    = ['action', 'username_attempt', 'ip_address', 'ua_short', 'timestamp', 'user']
    search_fields   = ['username_attempt', 'ip_address', 'user__username']
    list_filter     = ['action']
    ordering        = ['-timestamp']
    date_hierarchy  = 'timestamp'
    readonly_fields = ['action', 'ip_address', 'timestamp', 'user', 'user_agent', 'username_attempt']

    @admin.display(description='User Agent')
    def ua_short(self, obj):
        if obj.user_agent:
            return (obj.user_agent[:55] + '...') if len(obj.user_agent) > 55 else obj.user_agent
        return '-'


class LoginHistoryAdmin(admin.ModelAdmin):
    list_display    = ['user', 'ip', 'device_short', 'time', 'status_badge']
    search_fields   = ['user__username', 'ip', 'device']
    list_filter     = ['status']
    ordering        = ['-time']
    date_hierarchy  = 'time'
    readonly_fields = ['user', 'ip', 'device', 'time', 'status']

    @admin.display(description='Thiết bị')
    def device_short(self, obj):
        return (obj.device[:55] + '...') if len(obj.device) > 55 else obj.device

    @admin.display(description='Trạng thái')
    def status_badge(self, obj):
        color = 'green' if obj.status == 'success' else 'red'
        return format_html('<b style="color:{}">{}</b>', color, obj.status)


class EmailOTPAdmin(admin.ModelAdmin):
    list_display    = ['user', 'action', 'email_sent', 'ip_address', 'created_at', 'used_at', 'is_used', 'is_active']
    search_fields   = ['user__username', 'email_sent', 'ip_address']
    list_filter     = ['action', 'is_used', 'is_active']
    ordering        = ['-created_at']
    date_hierarchy  = 'created_at'
    readonly_fields = ['otp_code', 'otp_hash', 'created_at', 'used_at']
    fieldsets = (
        ('Người dùng',      {'fields': ('user', 'email_sent', 'ip_address')}),
        ('Trạng thái',      {'fields': ('action', 'is_used', 'is_active', 'created_at', 'used_at')}),
        ('Dữ liệu mã hóa',  {'classes': ('collapse',), 'fields': ('otp_code', 'otp_hash')}),
    )


class OTPAdmin(admin.ModelAdmin):
    list_display    = ['user', 'code', 'created_at']
    search_fields   = ['user__username']
    ordering        = ['-created_at']
    readonly_fields = ['code', 'created_at']


class TrustedDeviceAdmin(admin.ModelAdmin):
    list_display    = ['user', 'name', 'ip_address', 'last_seen', 'is_active', 'session_short']
    search_fields   = ['user__username', 'name', 'ip_address']
    list_filter     = ['is_active']
    ordering        = ['-last_seen']
    date_hierarchy  = 'last_seen'
    readonly_fields = ['device_id', 'session_key', 'user_agent']
    fieldsets = (
        ('Người dùng',       {'fields': ('user',)}),
        ('Thiết bị',         {'fields': ('name', 'device_id', 'ip_address', 'user_agent')}),
        ('Trạng thái',       {'fields': ('is_active', 'last_seen', 'session_key')}),
    )

    @admin.display(description='Session Key')
    def session_short(self, obj):
        return (obj.session_key[:12] + '...') if obj.session_key else '-'


class PendingRegistrationAdmin(admin.ModelAdmin):
    list_display    = ['email', 'created_at', 'is_used']
    search_fields   = ['email']
    list_filter     = ['is_used']
    ordering        = ['-created_at']
    date_hierarchy  = 'created_at'
    readonly_fields = ['otp_code', 'created_at', 'temp_data']


class RemoteAuthRequestAdmin(admin.ModelAdmin):
    list_display    = ['user', 'device_info', 'status', 'created_at']
    search_fields   = ['user__username', 'device_info']
    list_filter     = ['status']
    ordering        = ['-created_at']
    date_hierarchy  = 'created_at'
    readonly_fields = ['session_key', 'created_at']


class UserPasskeyAdmin(admin.ModelAdmin):
    list_display    = ['user', 'cred_short', 'sign_count', 'created_at']
    search_fields   = ['user__username']
    ordering        = ['-created_at']
    date_hierarchy  = 'created_at'
    readonly_fields = ['credential_id', 'public_key', 'created_at']
    fieldsets = (
        ('Người dùng', {'fields': ('user',)}),
        ('Passkey',    {'fields': ('credential_id', 'public_key', 'sign_count', 'created_at')}),
    )

    @admin.display(description='Credential ID')
    def cred_short(self, obj):
        return (obj.credential_id[:20] + '...') if len(obj.credential_id) > 20 else obj.credential_id


class UserSessionControlAdmin(admin.ModelAdmin):
    list_display  = ['user', 'status_badge']
    search_fields = ['user__username']
    list_filter   = ['force_logout']
    actions       = ['reset_force_logout']

    @admin.display(description='Trạng thái phiên')
    def status_badge(self, obj):
        if obj.force_logout:
            return format_html('<b style="color:red">⚠ Đang bị kick</b>')
        return format_html('<b style="color:green">✓ Bình thường</b>')

    @admin.action(description='Reset force_logout → False')
    def reset_force_logout(self, request, queryset):
        n = queryset.update(force_logout=False)
        self.message_user(request, f'Đã reset {n} bản ghi.')


# ==================== ĐĂNG KÝ default_admin_site ====================

default_admin_site.register(User,                CustomUserAdmin)
default_admin_site.register(Group,               BaseGroupAdmin)
default_admin_site.register(UserProfile,         UserProfileAdmin)
default_admin_site.register(User2FA,             User2FAAdmin)
default_admin_site.register(ActivityLog,         ActivityLogAdmin)
default_admin_site.register(LoginHistory,        LoginHistoryAdmin)
default_admin_site.register(EmailOTP,            EmailOTPAdmin)
default_admin_site.register(OTP,                 OTPAdmin)
default_admin_site.register(TrustedDevice,       TrustedDeviceAdmin)
default_admin_site.register(PendingRegistration, PendingRegistrationAdmin)
default_admin_site.register(RemoteAuthRequest,   RemoteAuthRequestAdmin)
default_admin_site.register(UserPasskey,         UserPasskeyAdmin)
default_admin_site.register(UserSessionControl,  UserSessionControlAdmin)


# ==================== ĐĂNG KÝ admin.site MẶC ĐỊNH ====================

admin.site.site_header = "HUIT Authentication System"
admin.site.site_title  = "HUIT Admin"
admin.site.index_title = "Trang quản trị hệ thống"

admin.site.unregister(User)
admin.site.unregister(Group)

admin.site.register(User,                CustomUserAdmin)
admin.site.register(Group,               BaseGroupAdmin)
admin.site.register(UserProfile,         UserProfileAdmin)
admin.site.register(User2FA,             User2FAAdmin)
admin.site.register(ActivityLog,         ActivityLogAdmin)
admin.site.register(LoginHistory,        LoginHistoryAdmin)
admin.site.register(EmailOTP,            EmailOTPAdmin)
admin.site.register(OTP,                 OTPAdmin)
admin.site.register(TrustedDevice,       TrustedDeviceAdmin)
admin.site.register(PendingRegistration, PendingRegistrationAdmin)
admin.site.register(RemoteAuthRequest,   RemoteAuthRequestAdmin)
admin.site.register(UserPasskey,         UserPasskeyAdmin)
admin.site.register(UserSessionControl,  UserSessionControlAdmin)