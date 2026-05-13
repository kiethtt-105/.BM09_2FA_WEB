from django.contrib import admin
from .models import ActivityLog
from django.contrib.admin import AdminSite
from django.contrib.auth.models import User, Group
from .models import ActivityLog, UserProfile 
from .models import User2FA

# 1. Khai báo một Site Admin mới
class DefaultAdminSite(AdminSite):
    site_header = "Giao diện trắng xanh"
    index_title = "Quản trị hệ thống gốc"

# 2. Khởi tạo 
default_admin_site = DefaultAdminSite(name='default_admin')

# 3. Đăng ký các bảng dữ liệu 
default_admin_site.register(User)
default_admin_site.register(Group)
default_admin_site.register(ActivityLog)
default_admin_site.register(UserProfile)
default_admin_site.register(User2FA)

