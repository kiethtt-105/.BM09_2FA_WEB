from pathlib import Path
from datetime import timedelta

BASE_DIR = Path(__file__).resolve().parent.parent

# PHẢI GIỐNG HỆT SECRET_KEY  huit_project
SECRET_KEY = 'django-insecure-0x=ef3hz-1)yv+-c#*^pkzsqejmg!x)nf*d%fdz!_xjhfu-!@d'
DEBUG = True
#ALLOWED_HOSTS = ['*']
ALLOWED_HOSTS = ['spellable-sciuroid-maybell.ngrok-free.dev', '127.0.0.1', 'localhost']

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'portal',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'appb_project.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'portal' / 'templates'],  # ← SỬA DÒNG NÀY
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

WSGI_APPLICATION = 'appb_project.wsgi.application'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'Asia/Ho_Chi_Minh'
USE_I18N = True
USE_TZ = True

STATIC_URL = 'static/'
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# JWT — dùng cùng SECRET_KEY với App A để xác minh token
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(hours=1),
    'ALGORITHM': 'HS256',
    'SIGNING_KEY': 'huit-sso-secret-2024-change-this',
    'USER_ID_FIELD': 'id',        # Trường ID trong Model User của App B
    'USER_ID_CLAIM': 'user_id',   # Trường ID tương ứng trong Token Payload
}


SESSION_ENGINE = 'django.contrib.sessions.backends.db'
SESSION_COOKIE_NAME = 'appb_sessionid'
SESSION_COOKIE_AGE = 3600
SESSION_SAVE_EVERY_REQUEST = True
SESSION_COOKIE_SAMESITE = 'Lax'
SESSION_COOKIE_SECURE = False