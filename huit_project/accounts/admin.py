from django.contrib import admin
from .models import ActivityLog
from django.contrib.admin import AdminSite
from django.contrib.auth.models import User, Group
from .models import ActivityLog, UserProfile 
from .models import User2FA


@admin.register(ActivityLog)
class ActivityLogAdmin(admin.ModelAdmin):
    list_display = ('user', 'action', 'ip_address', 'timestamp')
    list_filter = ('action', 'timestamp')
    search_fields = ('user__username', 'ip_address')
    readonly_fields = ('user', 'action', 'ip_address', 'user_agent', 'timestamp') # Không cho sửa log

    # Tô màu cho các hành động quan trọng (tùy chọn)
    def get_action_display(self, obj):
        return obj.get_action_display()
    get_action_display.short_description = 'Hành động'

# 1. Khai báo một Site Admin mới (Đặt tên là Default để nó hiện trắng xanh)
class DefaultAdminSite(AdminSite):
    site_header = "Giao diện trắng xanh huyền thoại"
    index_title = "Quản trị hệ thống gốc"

# 2. Khởi tạo nó
default_admin_site = DefaultAdminSite(name='default_admin')

# 3. Đăng ký các bảng dữ liệu ông muốn xem ở trang trắng xanh này
default_admin_site.register(User)
default_admin_site.register(Group)
default_admin_site.register(ActivityLog)

# admin.py
from django.contrib import admin
from .models import User2FA
@admin.register(User2FA)
class User2FAAdmin(admin.ModelAdmin):
    list_display = (
        "user",
        "email_otp_enabled",
        "google_auth_enabled",
        "force_disable_2fa"
    )

    actions = ["disable_2fa", "force_logout_user"]

    @admin.action(description="❌ Tắt 2FA user")
    def disable_2fa(self, request, queryset):
        for obj in queryset:
            obj.email_otp_enabled = False
            obj.google_auth_enabled = False
            obj.google_secret = None
            obj.force_disable_2fa = True
            obj.save()

    @admin.action(description="🚪 Force logout user")
    def force_logout_user(self, request, queryset):
        from .models import UserSessionControl

        for obj in queryset:
            control, _ = UserSessionControl.objects.get_or_create(user=obj.user)
            control.force_logout = True
            control.save()