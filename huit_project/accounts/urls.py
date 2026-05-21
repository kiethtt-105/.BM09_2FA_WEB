from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('admin-dashboard/', views.admin_dashboard, name='admin_dashboard'),
    path('security-2fa/', views.security_2fa, name='security_2fa'),
    path('verify-2fa-multi/', views.verify_2fa_multi, name='verify_2fa_multi'),
    path('register/', views.register, name='register'),
    path('register/verify-otp/', views.verify_register_otp, name='verify_register_otp'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('setup-2fa/', views.setup_2fa, name='setup_2fa'),

    # ── Admin 2FA bắt buộc ──────────────────────────────────────────────────
    path('admin-setup-2fa/', views.admin_setup_2fa, name='admin_setup_2fa'),
    path('admin-manage-2fa/', views.admin_manage_2fa, name='admin_manage_2fa'),

    path('verify-2fa/', views.verify_2fa, name='verify_2fa'),
    path('export-users/', views.export_users_excel, name='export_users'),
    path('devices/', views.device_list, name='device_list'),
    path('login-history/', views.login_history, name='login_history'),
    path('active-sessions/', views.active_sessions, name='active_sessions'),
    path('logout-device/<int:device_id>/', views.logout_device, name='logout_device'),
    path('trust-device/<int:device_id>/',  views.trust_device,  name='trust_device'),
    path('logout-all-devices/', views.logout_all_devices, name='logout_all_devices'),
    path('confirm-device/', views.confirm_device, name='confirm_device'),
    path('toggle-push-auth/', views.toggle_push_auth, name='toggle_push_auth'),

    # API
    path('api/get-auth-request/', views.get_pending_auth_request, name='get_pending_auth_request'),
    path('api/respond-auth/<int:req_id>/', views.respond_auth_request, name='respond_auth_request'),
    path('api/check-auth-status/', views.check_auth_status, name='check_auth_status'),

    # ── [NEW] Admin Email OTP trong verify_2fa_multi ────────────────────────
    path('api/admin/send-email-otp/', views.admin_send_email_otp, name='admin_send_email_otp'),

    # FIDO2 Registration
    path('fido2/begin/',    views.fido2_reg_begin,    name='fido2_reg_begin'),
    path('fido2/complete/', views.fido2_reg_complete, name='fido2_reg_complete'),

    # FIDO2 Authentication (user thường — dùng pre_2fa_user_id)
    path('fido2/auth/begin/',    views.fido2_auth_begin,    name='fido2_auth_begin'),
    path('fido2/auth/complete/', views.fido2_auth_complete, name='fido2_auth_complete'),

    # ── [NEW] FIDO2 Authentication cho Admin Multi-Factor ───────────────────
    # Admin đã login() → không có pre_2fa_user_id → dùng request.user trực tiếp
    path('fido2/admin/auth/begin/',    views.fido2_admin_auth_begin,    name='fido2_admin_auth_begin'),
    path('fido2/admin/auth/complete/', views.fido2_admin_auth_complete, name='fido2_admin_auth_complete'),

    # Passkey management
    path('passkeys/',                    views.manage_passkeys, name='manage_passkeys'),
    path('passkeys/delete/<int:pk_id>/', views.delete_passkey,  name='delete_passkey'),

    # Auth Approval (Push Auth) — chỉ dành cho user thường
    path('auth-approval/',                              views.auth_approval,         name='auth_approval'),
    path('auth-approval/<int:req_id>/<str:action>/',    views.auth_approval_respond, name='auth_approval_respond'),

    # HOTP
    path('api/generate-hotp/', views.generate_hotp_code, name='generate_hotp_code'),

    # Test
    path('test-passkey/', views.test_passkey_view, name='test_passkey'),

    # Custom Admin Dashboard
    path('admin-dashboard/otp-history/', views.admin_otp_history, name='admin_otp_history'),
    path('admin-dashboard/login-history/', views.admin_login_history, name='admin_login_history'),
    path('manage/force-logout/<str:username>/', views.admin_force_logout, name='admin_force_logout'),
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