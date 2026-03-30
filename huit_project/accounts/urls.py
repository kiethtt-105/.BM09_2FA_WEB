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
]