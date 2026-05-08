# accounts/urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('admin-dashboard/', views.admin_dashboard, name='admin_dashboard'),
    path('register/', views.register, name='register'),
    path('register/verify-otp/', views.verify_register_otp, name='verify_register_otp'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('setup-2fa/', views.setup_2fa, name='setup_2fa'),
    path('verify-2fa/', views.verify_2fa, name='verify_2fa'),
    path('export-users/', views.export_users_excel, name='export_users'),
    path('admin-dashboard/toggle-user/<int:user_id>/', views.toggle_user_status, name='toggle_user'),
    path('admin-dashboard/stats/', views.user_stats, name='user_stats'),
    path('devices/', views.device_list, name='device_list'),
    path('login-history/', views.login_history, name='login_history'),
    path('active-sessions/', views.active_sessions, name='active_sessions'),
    path('logout-device/<int:device_id>/', views.logout_device, name='logout_device'),
    path('logout-all-devices/', views.logout_all_devices, name='logout_all_devices'),
    path('confirm-device/', views.confirm_device, name='confirm_device'),

    # API
    path('api/get-auth-request/', views.get_pending_auth_request, name='get_pending_auth_request'),
    path('api/respond-auth/<int:req_id>/', views.respond_auth_request, name='respond_auth_request'),
    path('api/check-auth-status/', views.check_auth_status, name='check_auth_status'),  # ← chỉ 1 lần, có name

    # FIDO2 Registration
    path('fido2/begin/',    views.fido2_reg_begin,    name='fido2_reg_begin'),
    path('fido2/complete/', views.fido2_reg_complete, name='fido2_reg_complete'),

    # FIDO2 Authentication
    path('fido2/auth/begin/',    views.fido2_auth_begin,    name='fido2_auth_begin'),
    path('fido2/auth/complete/', views.fido2_auth_complete, name='fido2_auth_complete'),

    # Passkey management
    path('passkeys/',                    views.manage_passkeys, name='manage_passkeys'),
    path('passkeys/delete/<int:pk_id>/', views.delete_passkey,  name='delete_passkey'),

    # Test
    path('test-passkey/', views.test_passkey_view, name='test_passkey'),
    
      # Custom Admin Dashboard
    path('admin-dashboard/otp-history/', views.admin_otp_history, name='admin_otp_history'),
    path('admin-dashboard/login-history/', views.admin_login_history, name='admin_login_history'),
    path('manage/force-logout/<str:username>/', views.admin_force_logout, name='admin_force_logout'),
    #path('admin-dashboard/otp/export-txt/', views.export_otp_txt, name='export_otp_txt'),
    path('export-excel/', views.export_otp_excel, name='export_otp_excel'),
    # SSO Endpoint  
    path('sso/send/', views.sso_send, name='sso_send'),

    path('admin-dashboard/users/', views.user_management, name='admin_users'),

    path('admin-dashboard/export-users-excel/', views.export_users_excel, name='export_users_excel'),
    path('admin-dashboard/users/toggle/<int:user_id>/', views.admin_toggle_status, name='admin_toggle_status'),
    
    path('admin/otp/disable/<int:otp_id>/', views.admin_disable_otp, name='admin_disable_otp'),

 
    path('dtb-admin/', views.dtb_admin_view, name='dtb_admin'),
    path('admin-dashboard/dtb_admin/', views.dtb_admin_view, name='dtb_admin'),      
    path('admin-dashboard/export-dtb/', views.export_dtb, name='export_dtb'),
]
