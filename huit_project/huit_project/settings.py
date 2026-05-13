"""
Django settings for huit_project.
Đã bảo mật: tất cả thông tin nhạy cảm chuyển sang file .env
"""

from pathlib import Path
from decouple import config

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# ===========================================================
# BẢO MẬT CỐT LÕI
# ===========================================================

SECRET_KEY = config('SECRET_KEY')

DEBUG = config('DEBUG', default=False, cast=bool)

ALLOWED_HOSTS = config('ALLOWED_HOSTS', default='localhost,127.0.0.1').split(',')

CSRF_TRUSTED_ORIGINS = config(
    'CSRF_TRUSTED_ORIGINS',
    default='http://localhost:8000'
).split(',')

# Bật khi deploy HTTPS thật (đặt True trong .env production)
CSRF_COOKIE_SECURE = config('CSRF_COOKIE_SECURE', default=False, cast=bool)
SESSION_COOKIE_SECURE = config('SESSION_COOKIE_SECURE', default=False, cast=bool)

# Thêm bảo vệ HTTP headers
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'


# ===========================================================
# ỨNG DỤNG
# ===========================================================

INSTALLED_APPS = [
    'jazzmin',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'accounts',
]

# Giao diện tùy chỉnh cho Jazzmin
JAZZMIN_UI_CONFIG = {
    "navbar_small_text": False,
    "footer_small_text": False,
    "body_small_text": False,
    "brand_small_text": False,
    "brand_colour": "navbar-indigo",
    "accent": "accent-primary",
    "navbar": "navbar-dark",
    "no_navbar_border": False,
    "sidebar": "sidebar-dark-indigo",
    "sidebar_nav_small_text": False,
    "sidebar_disable_expand": False,
    "sidebar_nav_child_indent": False,
    "sidebar_nav_compact_style": False,
    "sidebar_nav_legacy_style": False,
    "sidebar_nav_flat_style": False,
    "theme": "default",
    "dark_mode_theme": None,
    "topmenu_links": [
        {"name": "Trang chủ", "url": "admin:index"},
        {"name": "Dashboard Tự Chế", "url": "/admin-dashboard/"},
        {"name": "Giao diện Trắng Xanh", "url": "/admin-origin/"},
    ],
}


# ===========================================================
# MIDDLEWARE
# ===========================================================

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'accounts.middleware.RoleMiddleware',
    'accounts.middleware.ForceDisable2FAMiddleware',
    'accounts.middleware.ForceLogoutMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'accounts.middleware.UpdateDeviceMiddleware',
]


# ===========================================================
# TEMPLATES
# ===========================================================

ROOT_URLCONF = 'huit_project.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'huit_project.wsgi.application'
ASGI_APPLICATION = 'huit_project.asgi.application'


# ===========================================================
# DATABASE — PostgreSQL (thay thế SQLite)
# ===========================================================

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': config('DB_NAME'),
        'USER': config('DB_USER'),
        'PASSWORD': config('DB_PASSWORD'),
        'HOST': config('DB_HOST', default='localhost'),
        'PORT': config('DB_PORT', default='5432'),
        'OPTIONS': {
            # Bỏ 'require' khi chạy local không có SSL,
            # đổi lại 'require' khi deploy production
            'sslmode': config('DB_SSL_MODE', default='prefer'),
        },
        'CONN_MAX_AGE': 60,  # giữ kết nối tối đa 60s để tối ưu hiệu năng
    }
}

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'


# ===========================================================
# XÁC THỰC MẬT KHẨU
# ===========================================================

AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]


# ===========================================================
# NGÔN NGỮ & MÚI GIỜ
# ===========================================================

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'Asia/Ho_Chi_Minh'
USE_I18N = True
USE_TZ = True


# ===========================================================
# FILE TĨNH & MEDIA
# ===========================================================

STATIC_URL = 'static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'

MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'


# ===========================================================
# ĐĂNG NHẬP / ĐĂNG XUẤT
# ===========================================================

LOGIN_REDIRECT_URL = 'dashboard'
LOGOUT_REDIRECT_URL = 'home'
LOGIN_URL = 'login'


# ===========================================================
# CẤU HÌNH EMAIL — Gmail (Drive015)
# ===========================================================

EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = config('EMAIL_HOST_USER', default='kiethtt@drive015.com')
EMAIL_HOST_PASSWORD = config('EMAIL_HOST_PASSWORD')
DEFAULT_FROM_EMAIL = config('EMAIL_HOST_USER', default='kiethtt@drive015.com')


# ===========================================================
# SESSION
# ===========================================================

SESSION_SERIALIZER = 'django.contrib.sessions.serializers.JSONSerializer'


# ===========================================================
# SSO — Single Sign-On
# ===========================================================

SSO_SECRET_KEY = config('SSO_SECRET_KEY')
SSO_TOKEN_EXPIRY = 300  # 5 phút

WEB_SSO_CALLBACK_URL = config(
    'WEB_SSO_CALLBACK_URL',
    default='http://localhost:8001/sso/callback/'
)


# ===========================================================
# MÃ HÓA
# ===========================================================

ENCRYPTION_KEY = config('ENCRYPTION_KEY')