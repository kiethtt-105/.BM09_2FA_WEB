from django.contrib import admin
from .models import ActivityLog
from django.contrib.admin import AdminSite
from django.contrib.auth.models import User, Group
from .models import ActivityLog, UserProfile 


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