''' from django.contrib import admin
from django.urls import path # Import hàm path để định nghĩa URL patterns
 '''
''' from .views import (
    home,
    register,
    verify_register_otp,
    login_view,
    logout_view,
    dashboard,
    setup_2fa,
    verify_2fa
) # Import các view từ ứng dụng accounts '''

''' urlpatterns = [
    path('admin/',                  admin.site.urls),
    # path('',                        home,                   name='home'), # Trang chủ có thể là một trang giới thiệu hoặc trang đăng nhập tùy theo thiết kế của bạn
    path('register/',               register,               name='register'),# Đăng ký tài khoản mới
    path('register/verify-otp/',    verify_register_otp,    name='verify_register_otp'),# Xác thực OTP sau khi đăng ký
    path('login/',                  login_view,             name='login'),# Đăng nhập
    path('logout/',                 logout_view,            name='logout'),# Đăng xuất
    path('account/',                dashboard,              name='account'),# Trang quản lý tài khoản, có thể hiển thị thông tin người dùng và các tùy chọn khác
    path('dashboard/',              dashboard,              name='dashboard'),# Trang dashboard sau khi đăng nhập thành công, có thể hiển thị thông tin người dùng và các tùy chọn khác
    path('setup-2fa/',              setup_2fa,              name='setup_2fa'),# Trang thiết lập 2FA, nơi người dùng có thể quét mã QR và nhập mã OTP để kích hoạt 2FA
    path('verify-2fa/',             verify_2fa,             name='verify_2fa'),# Trang xác thực 2FA sau khi đăng nhập, nơi người dùng nhập mã OTP để hoàn tất quá trình đăng nhập
    path('',                        include('accounts.urls')),# dùng app accounts để quản lý các URL liên quan đến tài khoản, như đăng ký, đăng nhập, v.v.
] '''

from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),

    # tất cả route giao cho app accounts
    path('', include('accounts.urls')),
]