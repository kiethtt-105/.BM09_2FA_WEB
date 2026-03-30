from django.urls import path
from . import views

urlpatterns = [
    #   path('admin/', admin.site.urls),
    # URL admin mặc định của Django 

    path('',                      views.home,                name='home'),
    # Các URL liên quan đến tài khoản và 2FA
    
    # Đăng ký → gửi OTP email → xác thực OTP → tạo tài khoản
    path('register/',             views.register,            name='register'),  
    # Sau khi submit form đăng ký → gửi OTP email → chuyển đến trang verify-otp
    path('register/verify-otp/',  views.verify_register_otp, name='verify_register_otp'),
    # Đăng nhập → nếu 2FA bật → chuyển đến verify-2fa → xác thực OTP → vào dashboard
    path('login/',                views.login_view,          name='login'),
    # Đăng xuất
    path('logout/',               views.logout_view,         name='logout'),
    # Trang cá nhân / dashboard (yêu cầu đăng nhập)
    path('account/',              views.dashboard,           name='account'), 
    # Trang dashboard chính (yêu cầu đăng nhập) 
    path('dashboard/',            views.dashboard,           name='dashboard'),
    # Cấu hình 2FA (yêu cầu đăng nhập)
    path('setup-2fa/',            views.setup_2fa,           name='setup_2fa'),
    # Xác thực OTP 2FA (sau khi đăng nhập nếu 2FA bật)
    path('verify-2fa/',           views.verify_2fa,          name='verify_2fa'),
]
# urlpatterns của app accounts, định nghĩa các URL liên quan đến đăng ký, đăng nhập, 2FA, và dashboard.
