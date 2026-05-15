import jwt
import time
import random
import hashlib
import pyotp
import io
import base64
import json
import datetime
import pickle
import sqlite3
import secrets
import uuid
from decimal import Decimal
from datetime import timedelta

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.models import User
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm
from django.contrib.auth.decorators import login_required, user_passes_test
from django.http import JsonResponse, HttpResponse
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.cache import never_cache
from django.core.mail import send_mail
from django.utils import timezone
from django.utils.dateparse import parse_date
from django.db.models import Q
from django.core.paginator import Paginator
from django.contrib.sessions.models import Session
from django import forms

import openpyxl
from openpyxl import Workbook
from openpyxl.utils import get_column_letter
from openpyxl.styles import Font, Alignment, PatternFill
from django.contrib.auth.hashers import make_password

from .models import (
    LoginHistory, RemoteAuthRequest, TrustedDevice,
    EmailOTP, UserProfile, PendingRegistration,
    ActivityLog, UserPasskey
)
from .utils import get_totp_token, generate_qr_base64, get_client_ip, generate_and_send_email_otp

from fido2.server import Fido2Server
from fido2.webauthn import (
    PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity,
    UserVerificationRequirement, ResidentKeyRequirement,
    CollectedClientData, AuthenticatorData
)
from fido2.utils import websafe_encode, websafe_decode
from fido2.features import webauthn_json_mapping

try:
    webauthn_json_mapping.enabled = True
except ValueError:
    pass


# ═══════════════════════════════════════════════════════════════════════════════
# A. FORM & HELPER
# ═══════════════════════════════════════════════════════════════════════════════

class RegisterForm(UserCreationForm):
    """Form đăng ký mở rộng: thêm họ, chữ đệm, tên, email, số điện thoại."""

    first_name = forms.CharField(
        max_length=50, required=True, label='Họ',
        widget=forms.TextInput(attrs={'placeholder': 'Họ'}),
    )
    middle_name = forms.CharField(
        max_length=50, required=False, label='Chữ đệm',
        widget=forms.TextInput(attrs={'placeholder': 'Chữ đệm (không bắt buộc)'}),
    )
    last_name = forms.CharField(
        max_length=50, required=True, label='Tên',
        widget=forms.TextInput(attrs={'placeholder': 'Tên'}),
    )
    email = forms.EmailField(
        required=True, label='Email',
        widget=forms.EmailInput(attrs={'placeholder': 'Email'}),
    )
    phone_number = forms.CharField(
        max_length=15, required=False, label='Số điện thoại',
        widget=forms.TextInput(attrs={'placeholder': 'Số điện thoại'}),
    )

    class Meta:
        model  = User
        fields = ['username', 'first_name', 'middle_name', 'last_name',
                  'email', 'phone_number', 'password1', 'password2']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['username'].widget.attrs['placeholder'] = 'Tên đăng nhập'
        self.fields['password1'].widget.attrs['placeholder'] = 'Mật khẩu'
        self.fields['password2'].widget.attrs['placeholder'] = 'Nhập lại mật khẩu'

    def clean_email(self):
        email = self.cleaned_data.get('email', '').lower()
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError('Email này đã được sử dụng.')
        return email


def _b64url_to_bytes(s) -> bytes:
    """Chuyển đổi chuỗi Base64url (WebAuthn) về bytes. Xử lý padding và ký tự đặc biệt."""
    if isinstance(s, bytes):
        return s
    s = s.replace('-', '+').replace('_', '/')
    s += '=' * (4 - len(s) % 4)
    return base64.b64decode(s)


# ═══════════════════════════════════════════════════════════════════════════════
# B. AUTH VIEWS
# ═══════════════════════════════════════════════════════════════════════════════

def home(request):
    """Trang chủ — redirect về dashboard nếu đã đăng nhập."""
    if request.user.is_authenticated:
        return redirect('dashboard')
    return render(request, 'accounts/home.html')


def register(request):
    """
    Đăng ký tài khoản mới (bước 1/2).

    Luồng: validate form → tạo PendingRegistration → gửi OTP email
    → redirect sang verify_register_otp.

    temp_data lưu password plaintext vì chưa tạo User — bản ghi này
    bị xóa ngay sau khi xác thực OTP thành công.
    """
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']

            # Xóa bản ghi pending cũ nếu user đăng ký lại
            PendingRegistration.objects.filter(email=email).delete()

            otp_code = ''.join(str(secrets.randbelow(10)) for _ in range(6))

            PendingRegistration.objects.create(
                email     = email,
                otp_code  = otp_code,
                temp_data = {
                    'username':     form.cleaned_data['username'],
                    'first_name':   form.cleaned_data['first_name'],
                    'middle_name':  form.cleaned_data.get('middle_name', ''),
                    'last_name':    form.cleaned_data['last_name'],
                    'email':        email,
                    'phone_number': form.cleaned_data.get('phone_number', ''),
                    'password': make_password(form.cleaned_data['password1']),
                },
            )

            try:
                ip    = get_client_ip(request)
                first = form.cleaned_data['first_name']
                last  = form.cleaned_data['last_name']
                generate_and_send_email_otp(
                    user    = None,
                    email   = email,
                    action  = 'register',
                    ip      = ip,
                    subject = '🔐 Mã OTP Kích hoạt tài khoản - HUIT',
                    body    = (
                        f"Xin chào {first} {last},\n\n"
                        f"Mã OTP kích hoạt tài khoản của bạn là: {otp_code}\n\n"
                        f"Mã có hiệu lực trong 10 phút. Không chia sẻ mã này.\n\n"
                        f"Trân trọng,\nHUIT System"
                    ),
                )
            except Exception as e:
                messages.error(request, f'Lỗi gửi email: {str(e)}')
                return render(request, 'accounts/register.html', {'form': form})

            request.session['pending_register_email'] = email
            messages.success(request, f'Mã OTP đã gửi tới {email}. Kiểm tra hộp thư!')
            return redirect('verify_register_otp')
    else:
        form = RegisterForm()

    return render(request, 'accounts/register.html', {'form': form})


def verify_register_otp(request):
    """
    Xác thực OTP đăng ký (bước 2/2).

    action='resend': sinh OTP mới, lưu lại temp_data trước khi xóa bản ghi cũ
    để không mất dữ liệu form đã điền.
    """
    email = request.session.get('pending_register_email')
    if not email:
        messages.error(request, 'Phiên đã hết hạn. Vui lòng đăng ký lại.')
        return redirect('register')

    pending = PendingRegistration.objects.filter(email=email).first()
    if not pending:
        return redirect('register')

    username = pending.temp_data.get('username')

    if request.method == 'POST':
        action = request.POST.get('action')

        if action == 'resend':
            pending = PendingRegistration.objects.filter(email=email).first()
            if pending:
                new_otp   = ''.join(str(secrets.randbelow(10)) for _ in range(6))
                temp_data = pending.temp_data  # Lưu lại trước khi xóa

                PendingRegistration.objects.filter(email=email).delete()
                PendingRegistration.objects.create(
                    email     = email,
                    otp_code  = new_otp,
                    temp_data = temp_data,
                )
                try:
                    send_mail(
                        subject        = '🔐 Mã OTP mới - HUIT',
                        message        = f'Mã OTP mới của bạn: {new_otp}\n\nHiệu lực 10 phút.\n\nHUIT System',
                        from_email     = None,
                        recipient_list = [email],
                        fail_silently  = False,
                    )
                    EmailOTP.objects.create(
                        user       = None,
                        otp_code   = new_otp,
                        action     = 'register',
                        ip_address = get_client_ip(request),
                        email_sent = email,
                        is_used    = False,
                        is_active  = True,
                    )
                    messages.success(request, 'Đã gửi lại mã OTP mới.')
                except Exception as e:
                    messages.error(request, f'Lỗi gửi email: {str(e)}')
            return redirect('verify_register_otp')

        otp_entered = request.POST.get('otp_code', '').strip()
        pending = PendingRegistration.objects.filter(
            email=email, otp_code=otp_entered, is_used=False
        ).first()

        if not pending:
            messages.error(request, 'Mã OTP không đúng. Vui lòng thử lại.')
            return render(request, 'accounts/verify_register_otp.html', {'email': email})

        if not pending.is_valid():
            messages.error(request, 'Mã OTP đã hết hạn (10 phút). Vui lòng gửi lại.')
            return render(request, 'accounts/verify_register_otp.html', {'email': email})

        data = pending.temp_data
        user = User.objects.create(
            username   = data['username'],
            email      = data['email'],
            password   = data['password'],
            is_active  = True,
            first_name = data['first_name'],
            last_name  = data['last_name'],
        )

        # Liên kết bản ghi OTP đăng ký với user vừa tạo
        EmailOTP.objects.filter(otp_code=otp_entered, user__isnull=True).update(
            user=user, is_used=True
        )

        UserProfile.objects.get_or_create(
            user=user,
            defaults={
                'middle_name':  data.get('middle_name', ''),
                'phone_number': data.get('phone_number', ''),
            }
        )

        pending.is_used = True
        pending.save()

        del request.session['pending_register_email']

        messages.success(request, f'🎉 Chào mừng {user.first_name} {user.last_name}! Tài khoản đã kích hoạt.')
        return redirect('login')

    return render(request, 'accounts/verify_register_otp.html', {
        'email':    email,
        'username': username,
    })


def logout_view(request):
    """Đánh dấu TrustedDevice của session hiện tại là offline trước khi logout."""
    session_key = request.session.session_key
    if session_key:
        TrustedDevice.objects.filter(session_key=session_key).update(is_active=False)
    logout(request)
    return redirect('home')


@never_cache
def login_view(request):
    """
    Đăng nhập với ba luồng:
      1. Admin → bỏ qua 2FA, vào thẳng admin_dashboard.
      2. User có 2FA → lưu user_id vào session, redirect verify_2fa.
      3. User không có 2FA → đăng nhập thẳng.
    """
    if request.user.is_authenticated:
        next_url = request.GET.get('next')
        if next_url:
            return redirect(next_url)
        return redirect('admin_dashboard' if request.user.is_superuser else 'dashboard')

    ip         = get_client_ip(request)
    user_agent = request.META.get('HTTP_USER_AGENT', 'Unknown')

    if request.method == 'POST':
        username_input = request.POST.get('username')
        form = AuthenticationForm(request, data=request.POST)

        if form.is_valid():
            user    = form.get_user()
            profile = UserProfile.objects.select_related('user').get(user=user)

            if not user.is_active:
                messages.error(request, "Tài khoản của bạn đã bị khóa.")
                return render(request, 'accounts/login.html', {'form': form})

            # Admin bỏ qua 2FA
            if user.is_superuser:
                login(request, user)
                ActivityLog.objects.create(
                    user             = user,
                    username_attempt = username_input,
                    action           = 'login',
                    ip_address       = ip,
                    user_agent       = user_agent,
                )
                messages.success(request, f"Chào Admin, {user.username}!")
                return redirect('admin_dashboard')

            # Đồng bộ cờ force_disable_2fa của admin xuống profile
            user_2fa = getattr(user, 'user2fa', None)
            if user_2fa and user_2fa.force_disable_2fa:
                profile.has_app_otp   = False
                profile.has_email_otp = False
                profile.save()

            # Nếu có bất kỳ phương thức 2FA nào → chuyển sang bước xác thực
            has_fido2 = user.passkeys.exists()
            if profile.has_app_otp or profile.has_email_otp or has_fido2:
                request.session['pre_2fa_user_id'] = user.id

                methods_enabled = []
                if profile.has_app_otp:   methods_enabled.append("Authenticator")
                if profile.has_email_otp: methods_enabled.append("Email OTP")
                if has_fido2:             methods_enabled.append("Passkey")

                other_devices = TrustedDevice.objects.filter(
                    user=user, is_active=True
                ).exclude(session_key=request.session.session_key)
                if other_devices.exists():
                    methods_enabled.append("Thiết bị khác")

                if len(methods_enabled) > 1:
                    msg = "Xác thực bằng " + ", ".join(methods_enabled[:-1]) + " hoặc " + methods_enabled[-1]
                elif methods_enabled:
                    msg = f"Xác thực bằng {methods_enabled[0]}"
                else:
                    msg = "Vui lòng xác thực 2FA"

                messages.info(request, msg)
                return redirect('verify_2fa')

            # Không có 2FA → đăng nhập thẳng
            login(request, user)
            next_url = request.GET.get('next')
            if next_url:
                return redirect(next_url)

            ActivityLog.objects.create(
                user             = user,
                username_attempt = username_input,
                action           = 'login',
                ip_address       = ip,
                user_agent       = user_agent,
            )

            if not request.session.session_key:
                request.session.create()

            TrustedDevice.objects.update_or_create(
                session_key = request.session.session_key,
                defaults    = {
                    "user":       user,
                    "user_agent": user_agent,
                    "ip_address": ip,
                    "last_seen":  timezone.now(),
                    "is_active":  True,
                }
            )
            messages.success(request, f"Chào mừng trở lại, {user.username}!")
            if request.session.get('sso_pending'):
                request.session.pop('sso_pending', None)
                return redirect('sso_send')
            return redirect('dashboard')

        else:
            # Phân biệt lý do lỗi để hiển thị thông báo rõ hơn
            try:
                check_user = User.objects.get(username=username_input)
                if not check_user.is_active:
                    ActivityLog.objects.create(
                        username_attempt = username_input,
                        action           = 'login_locked_attempt',
                        ip_address       = ip,
                        user_agent       = user_agent,
                    )
                    messages.error(request, "Tài khoản của bạn hiện đang bị khóa. Vui lòng liên hệ Admin HUIT.")
                else:
                    messages.error(request, "Tên đăng nhập hoặc mật khẩu không đúng.")
            except User.DoesNotExist:
                messages.error(request, "Tên đăng nhập hoặc mật khẩu không đúng.")

            ActivityLog.objects.create(
                username_attempt = username_input,
                action           = 'login_failed',
                ip_address       = ip,
                user_agent       = user_agent,
            )
    else:
        form = AuthenticationForm()

    return render(request, 'accounts/login.html', {'form': form})


# ═══════════════════════════════════════════════════════════════════════════════
# C. DASHBOARD & 2FA SETUP
# ═══════════════════════════════════════════════════════════════════════════════

@login_required
def dashboard(request):
    """Dashboard người dùng — cập nhật thông tin, bật/tắt 2FA."""
    if request.user.is_superuser:
        return redirect('admin_dashboard')

    profile, _      = UserProfile.objects.get_or_create(user=request.user)
    confirm_disable = None
    pending_update  = request.session.get('pending_update')

    if request.method == 'POST':

        if 'update_profile' in request.POST:
            new_first_name  = request.POST.get('first_name', '').strip()
            new_middle_name = request.POST.get('middle_name', '').strip()
            new_last_name   = request.POST.get('last_name', '').strip()
            new_phone       = request.POST.get('phone_number', '').strip()
            new_email       = request.POST.get('email', '').strip().lower()

            if not new_email:
                messages.error(request, 'Email là bắt buộc!')
                return redirect('dashboard')

            old_email = request.user.email

            # Trường hợp 1: chưa có email hoặc chưa bật email OTP → OTP tới email mới
            if not old_email or not profile.has_email_otp:
                otp = ''.join(str(secrets.randbelow(10)) for _ in range(6))
                profile.email_otp  = otp
                profile.otp_expiry = timezone.now() + timedelta(minutes=3)
                profile.save()
                try:
                    send_mail(
                        subject        = '🔐 Xác nhận cập nhật thông tin - HUIT',
                        message        = (
                            f"Xin chào {new_first_name} {new_last_name},\n\n"
                            f"Mã OTP xác nhận cập nhật thông tin: ► {otp}\n\n"
                            f"Hiệu lực 3 phút.\n\nHUIT System"
                        ),
                        from_email     = None,
                        recipient_list = [new_email],
                        fail_silently  = False,
                    )
                    EmailOTP.objects.create(
                        user       = request.user,
                        otp_code   = otp,
                        action     = 'update_info',
                        ip_address = get_client_ip(request),
                        email_sent = new_email,
                        is_used    = False,
                        is_active  = True,
                    )
                    messages.success(request, f'Mã OTP đã gửi tới {new_email}')
                except Exception as e:
                    messages.error(request, f'Lỗi gửi email: {str(e)}')

                request.session['pending_update'] = {
                    'first_name': new_first_name, 'middle_name': new_middle_name,
                    'last_name': new_last_name,   'new_email': new_email,
                    'phone_number': new_phone,     'is_first_email': True,
                }
                return redirect('dashboard')

            # Trường hợp 2: email thay đổi → OTP tới email cũ để xác nhận
            elif new_email != old_email:
                otp = ''.join(str(secrets.randbelow(10)) for _ in range(6))
                profile.email_otp  = otp
                profile.otp_expiry = timezone.now() + timedelta(minutes=3)
                profile.save()
                try:
                    send_mail(
                        subject        = '🔐 Xác nhận thay đổi Email - HUIT',
                        message        = (
                            f"Xin chào {request.user.first_name},\n\n"
                            f"Mã OTP xác nhận thay đổi email: ► {otp}\n\n"
                            f"Hiệu lực 3 phút.\n\nHUIT System"
                        ),
                        from_email     = None,
                        recipient_list = [old_email],  # Gửi về email cũ để xác nhận danh tính
                        fail_silently  = False,
                    )
                    EmailOTP.objects.create(
                        user       = request.user,
                        otp_code   = otp,
                        action     = 'update_info',
                        ip_address = get_client_ip(request),
                        email_sent = old_email,
                        is_used    = False,
                        is_active  = True,
                    )
                except Exception as e:
                    import logging
                    logging.getLogger(__name__).error("EMAIL ERROR update_info: %s", e)

                request.session['pending_update'] = {
                    'first_name': new_first_name, 'middle_name': new_middle_name,
                    'last_name': new_last_name,   'new_email': new_email,
                    'old_email': old_email,        'phone_number': new_phone,
                    'is_first_email': False,
                }
                return redirect('dashboard')

            # Trường hợp 3: email không đổi → cập nhật luôn, không cần OTP
            else:
                request.user.first_name = new_first_name
                request.user.last_name  = new_last_name
                profile.middle_name     = new_middle_name
                profile.phone_number    = new_phone
                request.user.save()
                profile.save()
                messages.success(request, 'Đã cập nhật thông tin thành công!')
                return redirect('dashboard')

        elif 'confirm_update' in request.POST:
            otp_input = request.POST.get('otp_code', '').strip()
            pending   = request.session.get('pending_update')

            if not pending:
                messages.error(request, 'Không có yêu cầu cập nhật.')
                return redirect('dashboard')

            if not profile.email_otp or profile.otp_expiry < timezone.now():
                messages.error(request, 'Mã OTP đã hết hạn.')
                request.session.pop('pending_update', None)
                return redirect('dashboard')

            if otp_input != profile.email_otp:
                otp_log = EmailOTP.objects.filter(
                    user=request.user, otp_code=otp_input, is_used=False
                ).first()
                if otp_log:
                    otp_log.mark_used()
                request.session.pop('pending_update', None)
                messages.error(request, 'Mã OTP không đúng!')
                return redirect('dashboard')

            # OTP đúng → cập nhật thông tin
            otp_log = EmailOTP.objects.filter(
                user=request.user, otp_code=otp_input, is_used=False
            ).first()
            if otp_log:
                otp_log.mark_used()

            request.user.first_name = pending['first_name']
            request.user.last_name  = pending['last_name']
            request.user.email      = pending['new_email']
            request.user.save()

            profile.middle_name  = pending.get('middle_name', '')
            profile.phone_number = pending.get('phone_number', '')
            profile.email_otp    = None
            profile.otp_expiry   = None
            profile.save()

            request.session.pop('pending_update', None)
            messages.success(request, 'Đã cập nhật thông tin thành công!')
            return redirect('dashboard')

        else:
            action = request.POST.get('action', '')

            if action == 'disable_email':
                otp = ''.join(str(secrets.randbelow(10)) for _ in range(6))
                profile.email_otp  = otp
                profile.otp_expiry = timezone.now() + timedelta(minutes=3)
                profile.save()
                try:
                    send_mail(
                        subject        = '🔐 Xác nhận tắt Email OTP - HUIT',
                        message        = f'Mã OTP xác nhận tắt 2FA email: {otp}\n\nHiệu lực 3 phút.',
                        from_email     = None,
                        recipient_list = [request.user.email],
                        fail_silently  = False,
                    )
                    EmailOTP.objects.create(
                        user       = request.user,
                        otp_code   = otp,
                        action     = 'disable_2fa',
                        ip_address = get_client_ip(request),
                        email_sent = request.user.email,
                        is_used    = False,
                        is_active  = True,
                    )
                    confirm_disable = 'disable_email'
                except Exception:
                    messages.error(request, 'Lỗi gửi mail xác nhận tắt.')

            elif action == 'disable_app':
                confirm_disable = 'disable_app'

            elif 'confirm_disable_action' in request.POST:
                code   = request.POST.get('disable_otp_code', '').strip()
                target = request.POST.get('confirm_disable_action')
                valid  = False

                if target == 'disable_email' and profile.email_otp == code and profile.otp_expiry > timezone.now():
                    valid = True
                elif target == 'disable_app':
                    raw_secret = profile.decrypt_secret()
                    if raw_secret and code == get_totp_token(raw_secret):
                        valid = True

                if valid:
                    otp_log = EmailOTP.objects.filter(
                        user=request.user, otp_code=code, is_used=False
                    ).first()
                    if otp_log:
                        otp_log.mark_used()
                    if target == 'disable_email':
                        profile.has_email_otp = False
                    else:
                        profile.has_app_otp = False
                        profile.otp_secret  = pyotp.random_base32()  # Reset secret khi tắt App OTP
                    profile.email_otp = None
                    profile.save()
                    messages.success(request, 'Đã hủy bảo mật thành công.')
                    return redirect('dashboard')
                else:
                    messages.error(request, 'Mã xác nhận không đúng!')
                    confirm_disable = target

        if not confirm_disable:
            return redirect('dashboard')

    current_session = request.session.session_key
    device = TrustedDevice.objects.filter(
        user=request.user, session_key=current_session
    ).first()

    return render(request, 'accounts/user_dashboard.html', {
        'profile':           profile,
        'confirm_disable':   confirm_disable,
        'pending_update':    pending_update,
        'show_device_alert': bool(device and not device.is_active),
    })


@login_required
def setup_2fa(request):
    """
    Thiết lập phương thức 2FA.

    method='email': gửi OTP qua email → xác nhận → bật has_email_otp.
    method='app': hiển thị QR code → user quét → nhập TOTP → bật has_app_otp.

    Mỗi lần GET method='app' đều sinh secret mới lưu vào session.
    """
    profile, _ = UserProfile.objects.get_or_create(user=request.user)
    method     = request.GET.get('method', 'email')

    context = {
        'profile':        profile,
        'method':         method,
        'user_email':     request.user.email or 'Chưa có email',
        'qr_code_base64': None,
        'otp_secret':     None,
    }

    if request.method == 'POST':
        if method == 'email':
            if 'send_email_otp' in request.POST:
                if not request.user.email:
                    messages.error(request, 'Vui lòng cập nhật email trước!')
                    return redirect('dashboard')
                otp = ''.join(str(secrets.randbelow(10)) for _ in range(6))
                profile.email_otp  = otp
                profile.otp_expiry = timezone.now() + timedelta(minutes=3)
                profile.save()
                try:
                    send_mail(
                        subject        = '🔐 Mã OTP Thiết lập Email 2FA - HUIT',
                        message        = f'Mã OTP thiết lập 2FA: {otp}\n\nHiệu lực 3 phút.\n\nHUIT System',
                        from_email     = None,
                        recipient_list = [request.user.email],
                        fail_silently  = False,
                    )
                    EmailOTP.objects.create(
                        user       = request.user,
                        otp_code   = otp,
                        action     = 'setup_2fa',
                        ip_address = get_client_ip(request),
                        email_sent = request.user.email,
                        is_used    = False,
                        is_active  = True,
                    )
                    messages.success(request, '✅ Mã OTP đã gửi đến email của bạn!')
                except Exception as e:
                    messages.error(request, f'Lỗi gửi email: {str(e)}')

            elif 'verify_email_otp' in request.POST:
                code = request.POST.get('email_otp_code', '').strip()
                if (profile.email_otp
                        and code == profile.email_otp
                        and profile.otp_expiry > timezone.now()):
                    profile.has_email_otp = True
                    profile.email_otp     = None
                    profile.otp_expiry    = None
                    profile.save()
                    otp_log = EmailOTP.objects.filter(
                        user=request.user, otp_code=code, is_used=False
                    ).first()
                    if otp_log:
                        otp_log.mark_used()
                    messages.success(request, '🎉 Đã kích hoạt Email OTP thành công!')
                    return redirect('dashboard')
                else:
                    messages.error(request, 'Mã OTP không đúng hoặc đã hết hạn!')

        elif method == 'app':
            if 'verify_app_otp' in request.POST:
                code        = request.POST.get('otp_code', '').strip()
                temp_secret = request.session.get('temp_otp_secret')
                if temp_secret and code == get_totp_token(temp_secret):
                    profile.otp_secret  = temp_secret
                    profile.has_app_otp = True
                    profile.save()
                    request.session.pop('temp_otp_secret', None)
                    messages.success(request, '✅ Thiết lập Google Authenticator thành công!')
                    return redirect('dashboard')
                else:
                    messages.error(request, 'Mã OTP không đúng!')

    if method == 'app':
        new_secret = pyotp.random_base32()
        request.session['temp_otp_secret'] = new_secret
        context['qr_code_base64'] = generate_qr_base64(request.user.username, new_secret)
        context['otp_secret']     = new_secret

    return render(request, 'accounts/setup_2fa.html', context)


# ═══════════════════════════════════════════════════════════════════════════════
# D. 2FA VERIFICATION
# ═══════════════════════════════════════════════════════════════════════════════

def verify_2fa(request):
    """
    Bước xác thực 2FA sau khi nhập đúng username/password.
    Hỗ trợ: app (TOTP), email OTP, fido2 (Passkey), push (thiết bị online khác).
    """
    uid = request.session.get('pre_2fa_user_id')
    if not uid:
        return redirect('login')

    try:
        user    = User.objects.get(id=uid)
        profile = user.profile
    except Exception:
        return redirect('login')

    ip         = get_client_ip(request)
    user_agent = request.META.get('HTTP_USER_AGENT', 'Unknown')

    other_devices = TrustedDevice.objects.filter(
        user=user, is_active=True
    ).exclude(session_key=request.session.session_key)

    has_fido2 = user.passkeys.exists()

    methods = []
    if profile.has_app_otp:    methods.append({'key': 'app',   'name': 'Authenticator', 'icon': '📱'})
    if profile.has_email_otp:  methods.append({'key': 'email', 'name': 'Email OTP',     'icon': '📧'})
    if has_fido2:              methods.append({'key': 'fido2', 'name': 'Passkey',       'icon': '🔑'})
    if other_devices.exists(): methods.append({'key': 'push',  'name': 'Thiết bị khác','icon': '🔔'})

    if not methods:
        messages.error(request, 'Tài khoản chưa thiết lập 2FA!')
        return redirect('login')

    method       = request.GET.get('method')
    enabled_keys = [m['key'] for m in methods]
    if method not in enabled_keys:
        return redirect(f"{request.path}?method={enabled_keys[0]}")

    push_request_sent = False

    if request.method == 'POST':
        action = request.POST.get('action')
        code   = request.POST.get('otp_code', '').strip()

        if action == 'send_push_request':
            RemoteAuthRequest.objects.filter(
                user=user, session_key=request.session.session_key
            ).delete()
            RemoteAuthRequest.objects.create(
                user        = user,
                session_key = request.session.session_key,
                status      = 'pending',
                device_info = request.META.get('HTTP_USER_AGENT', 'Thiết bị lạ')[:255],
            )
            return render(request, 'accounts/verify_2fa.html', {
                'methods': methods, 'method': 'push', 'profile': profile,
                'has_app_otp': profile.has_app_otp, 'has_email_otp': profile.has_email_otp,
                'has_fido2': has_fido2, 'has_other_devices': other_devices.exists(),
                'other_devices_list': list(other_devices[:3]), 'push_request_sent': True,
            })

        if action == 'send_email_code' and profile.has_email_otp:
            otp = ''.join(str(secrets.randbelow(10)) for _ in range(6))
            profile.email_otp  = otp
            profile.otp_expiry = timezone.now() + timedelta(minutes=3)
            profile.save()
            send_mail(
                subject        = 'Mã xác thực đăng nhập - HUIT',
                message        = f'Mã OTP của bạn là: {otp}\n\nHiệu lực 3 phút.',
                from_email     = None,
                recipient_list = [user.email],
                fail_silently  = True,
            )
            EmailOTP.objects.create(
                user       = user,
                otp_code   = otp,
                action     = 'login_2fa',
                ip_address = get_client_ip(request),
                email_sent = user.email,
                is_used    = False,
                is_active  = True,
            )
            messages.success(request, 'Đã gửi mã OTP mới vào Email.')
            return redirect(f'{request.path}?method=email')

        valid = False
        if method == 'app' and profile.has_app_otp:
            raw_secret = profile.decrypt_secret()
            if raw_secret and code == get_totp_token(raw_secret):
                valid = True
        elif method == 'email' and profile.has_email_otp:
            if code == profile.email_otp and profile.otp_expiry > timezone.now():
                valid = True

        if valid:
            login(request, user)
            request.session.pop('pre_2fa_user_id', None)

            if method == 'email':
                profile.email_otp  = None
                profile.otp_expiry = None
                profile.save()
                # Chỉ đánh dấu đúng bản ghi OTP vừa dùng
                otp_log = EmailOTP.objects.filter(
                    user=user, otp_code=code, is_used=False
                ).first()
                if otp_log:
                    otp_log.mark_used()

            ActivityLog.objects.create(
                user             = user,
                action           = 'login',
                username_attempt = user.username,
                ip_address       = ip,
                user_agent       = user_agent,
            )
            if request.session.get('sso_pending'):
                request.session.pop('sso_pending', None)
                return redirect('sso_send')
            return redirect('dashboard')

        ActivityLog.objects.create(
            user             = user,
            action           = 'login_failed',
            username_attempt = user.username,
            ip_address       = ip,
            user_agent       = user_agent,
        )
        messages.error(request, 'Mã xác thực không chính xác hoặc hết hạn.')

    return render(request, 'accounts/verify_2fa.html', {
        'methods': methods, 'method': method, 'profile': profile,
        'has_app_otp': profile.has_app_otp, 'has_email_otp': profile.has_email_otp,
        'has_fido2': has_fido2, 'has_other_devices': other_devices.exists(),
        'other_devices_list': list(other_devices[:3]),
        'push_request_sent': push_request_sent,
    })


# ── Push Auth APIs ──────────────────────────────────────────────────────────

@login_required
def get_pending_auth_request(request):
    """API polling: thiết bị đang online kiểm tra có yêu cầu xác thực mới không."""
    req = RemoteAuthRequest.objects.filter(
        user=request.user, status='pending'
    ).order_by('-created_at').first()
    if req:
        return JsonResponse({
            'has_request': True,
            'request_id':  req.id,
            'device_info': req.device_info,
        })
    return JsonResponse({'has_request': False})


@login_required
def respond_auth_request(request, req_id):
    """API: thiết bị online đồng ý hoặc từ chối yêu cầu xác thực."""
    status = request.GET.get('status')
    if status in ['approved', 'denied']:
        RemoteAuthRequest.objects.filter(
            id=req_id, user=request.user
        ).update(status=status)
        return JsonResponse({'status': 'success'})
    return JsonResponse({'status': 'error'}, status=400)


def check_auth_status(request):
    """
    API polling: thiết bị mới kiểm tra trạng thái yêu cầu xác thực.
    user có thể chưa được gán nếu uid không có trong session → dùng fallback "Unknown".
    """
    session_key = request.session.session_key
    ip          = get_client_ip(request)
    user_agent  = request.META.get('HTTP_USER_AGENT', 'Unknown')

    req = RemoteAuthRequest.objects.filter(
        session_key=session_key
    ).order_by('-created_at').first()

    if not req:
        return JsonResponse({'status': 'pending'})

    if req.status == 'approved':
        uid  = request.session.get('pre_2fa_user_id')
        user = None
        if uid:
            try:
                user = User.objects.get(id=uid)
                login(request, user)
                request.session.pop('pre_2fa_user_id', None)
            except User.DoesNotExist:
                pass
        req.delete()
        ActivityLog.objects.create(
            user             = user,
            username_attempt = user.username if user else "Unknown",
            action           = 'login',
            ip_address       = ip,
            user_agent       = user_agent,
        )
        return JsonResponse({'status': 'approved'})

    elif req.status == 'denied':
        req.delete()
        ActivityLog.objects.create(
            username_attempt = "Unknown",
            action           = 'login_failed',
            ip_address       = ip,
            user_agent       = user_agent,
        )
        return JsonResponse({'status': 'denied'})

    return JsonResponse({'status': 'pending'})


# ═══════════════════════════════════════════════════════════════════════════════
# E. FIDO2 / PASSKEY
# ═══════════════════════════════════════════════════════════════════════════════

def test_passkey_view(request):
    return render(request, 'accounts/test_passkey.html')


def _get_fido2_server(request) -> Fido2Server:
    """Tạo Fido2Server với rp_id = hostname hiện tại. Tách helper để tránh lặp code."""
    rp_id = request.get_host().split(':')[0]
    return Fido2Server(PublicKeyCredentialRpEntity(id=rp_id, name="HUIT MFA System"))


@login_required
def fido2_reg_begin(request):
    """
    Bắt đầu đăng ký Passkey — trả về options JSON cho browser gọi WebAuthn API.
    fido2_state serialize bằng pickle + base64url lưu vào session.
    """
    try:
        user          = request.user
        rp_id         = request.get_host().split(':')[0]
        server_local  = _get_fido2_server(request)
        user_id_bytes = str(user.id).encode('utf-8')

        user_entity = PublicKeyCredentialUserEntity(
            id           = user_id_bytes,
            name         = user.username,
            display_name = user.username,
        )

        registration_data, state = server_local.register_begin(
            user_entity,
            user_verification        = UserVerificationRequirement.PREFERRED,
            resident_key_requirement = ResidentKeyRequirement.PREFERRED,
        )

        request.session.pop('fido2_state', None)
        request.session['fido2_state'] = websafe_encode(pickle.dumps(state))

        options = {
            "challenge": websafe_encode(bytes(registration_data.public_key.challenge)),
            "rp":   {"name": "HUIT MFA System", "id": rp_id},
            "user": {
                "id":          websafe_encode(user_id_bytes),
                "name":        user.username,
                "displayName": user.username,
            },
            "pubKeyCredParams": [
                {"type": "public-key", "alg": -7},    # ES256 (ECDSA P-256)
                {"type": "public-key", "alg": -257},   # RS256 (RSA) — fallback
            ],
            "timeout":    60000,
            "attestation": "none",
            "authenticatorSelection": {
                "residentKey":      "preferred",
                "userVerification": "preferred",
            },
        }
        return JsonResponse(options)

    except Exception as e:
        import traceback; traceback.print_exc()
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


@csrf_exempt
@login_required
def fido2_reg_complete(request):
    """
    Hoàn tất đăng ký Passkey — nhận attestation từ browser, lưu credential vào DB.
    public_key lưu dạng CBOR-encoded Base64url.
    """
    try:
        from fido2.cbor import decode as cbor_decode, encode as cbor_encode
        from fido2.webauthn import AuthenticatorData

        data = json.loads(request.body)

        state_encoded = request.session.get('fido2_state')
        if not state_encoded:
            return JsonResponse({'status': 'error', 'message': 'Hết hạn phiên'}, status=400)

        attestation_obj_bytes = _b64url_to_bytes(data["response"]["attestationObject"])
        att_obj      = cbor_decode(attestation_obj_bytes)
        auth_data_raw = att_obj.get("authData") or att_obj.get(b"authData")
        auth_data     = AuthenticatorData(bytes(auth_data_raw))
        credential_data = auth_data.credential_data
        pk_bytes     = cbor_encode(dict(credential_data.public_key))

        UserPasskey.objects.update_or_create(
            user          = request.user,
            credential_id = data['id'],
            defaults      = {
                'public_key': websafe_encode(pk_bytes),
                'sign_count': auth_data.counter,
            }
        )

        request.session.pop('fido2_state', None)
        profile, _ = UserProfile.objects.get_or_create(user=request.user)
        profile.has_fido2 = True
        profile.save()
        return JsonResponse({'status': 'success'})

    except Exception as e:
        import traceback; traceback.print_exc()
        return JsonResponse({'status': 'error', 'message': str(e)}, status=400)


def fido2_auth_begin(request):
    """Bắt đầu xác thực bằng Passkey — trả về challenge cho browser."""
    try:
        uid = request.session.get('pre_2fa_user_id')
        if not uid:
            return JsonResponse({'status': 'error', 'message': 'Không tìm thấy phiên'}, status=400)

        user         = User.objects.get(id=uid)
        server_local = _get_fido2_server(request)
        rp_id        = request.get_host().split(':')[0]
        passkeys     = user.passkeys.all()

        if not passkeys.exists():
            return JsonResponse({'status': 'error', 'message': 'Không có passkey nào'}, status=400)

        auth_data, state = server_local.authenticate_begin(
            credentials       = [],  # Để trống → browser tự chọn passkey phù hợp
            user_verification = UserVerificationRequirement.PREFERRED,
        )

        request.session['fido2_auth_state'] = websafe_encode(pickle.dumps(state))

        options = {
            'challenge':        websafe_encode(bytes(auth_data.public_key.challenge)),
            'rpId':             rp_id,
            'timeout':          60000,
            'userVerification': 'preferred',
            'allowCredentials': [
                {'type': 'public-key', 'id': pk.credential_id}
                for pk in passkeys
            ],
        }
        return JsonResponse(options)

    except Exception as e:
        import traceback; traceback.print_exc()
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


@csrf_exempt
def fido2_auth_complete(request):
    """
    Hoàn tất xác thực Passkey.

    Lưu ý: pickle.loads() deserialize state từ session.
    Nếu SECRET_KEY bị lộ và session bị tamper, có thể dẫn đến RCE.
    Production nên thay bằng JSON serializer hoặc lưu state trong DB.
    """
    ip         = get_client_ip(request)
    user_agent = request.META.get('HTTP_USER_AGENT', 'Unknown')

    try:
        from fido2.cbor import decode as cbor_decode, encode as cbor_encode
        from fido2.webauthn import AttestedCredentialData, CollectedClientData, AuthenticatorData

        data = json.loads(request.body)

        uid = request.session.get('pre_2fa_user_id')
        if not uid:
            return JsonResponse({'status': 'error', 'message': 'Không tìm thấy phiên'}, status=400)

        user         = User.objects.get(id=uid)
        server_local = _get_fido2_server(request)

        state_encoded = request.session.get('fido2_auth_state')
        if not state_encoded:
            return JsonResponse({'status': 'error', 'message': 'Hết hạn phiên xác thực'}, status=400)

        state = pickle.loads(websafe_decode(state_encoded))

        credential_id = data.get('id')
        passkey = user.passkeys.filter(credential_id=credential_id).first()
        if not passkey:
            return JsonResponse({'status': 'error', 'message': 'Không tìm thấy passkey'}, status=400)

        pk_dict = cbor_decode(websafe_decode(passkey.public_key))
        credential_data = AttestedCredentialData.create(
            aaguid        = b'\x00' * 16,
            credential_id = _b64url_to_bytes(credential_id),
            public_key    = pk_dict,
        )

        client_data_bytes = _b64url_to_bytes(data["response"]["clientDataJSON"])
        auth_data_bytes   = _b64url_to_bytes(data["response"]["authenticatorData"])
        signature_bytes   = _b64url_to_bytes(data["response"]["signature"])

        client_data = CollectedClientData(client_data_bytes)
        auth_data   = AuthenticatorData(auth_data_bytes)

        server_local.authenticate_complete(
            state,
            [credential_data],
            _b64url_to_bytes(credential_id),
            client_data,
            auth_data,
            signature_bytes,
        )

        passkey.sign_count = auth_data.counter
        passkey.save()

        request.session.pop('fido2_auth_state', None)
        request.session.pop('pre_2fa_user_id', None)
        login(request, user)

        ActivityLog.objects.create(
            user             = user,
            username_attempt = user.username,
            action           = 'login',
            ip_address       = ip,
            user_agent       = user_agent,
        )
        return JsonResponse({'status': 'success', 'redirect': '/dashboard/'})

    except Exception as e:
        ActivityLog.objects.create(
            username_attempt = user.username if 'user' in locals() else "Unknown",
            action           = 'login_failed',
            ip_address       = ip,
            user_agent       = user_agent,
        )
        import traceback; traceback.print_exc()
        return JsonResponse({'status': 'error', 'message': str(e)}, status=400)


@login_required
def manage_passkeys(request):
    passkeys = request.user.passkeys.all().order_by('-created_at')
    return render(request, 'accounts/manage_passkeys.html', {'passkeys': passkeys})


@login_required
def delete_passkey(request, pk_id):
    passkey = get_object_or_404(UserPasskey, id=pk_id, user=request.user)
    passkey.delete()
    messages.success(request, 'Đã xóa passkey thành công!')
    return redirect('manage_passkeys')


# ═══════════════════════════════════════════════════════════════════════════════
# F. DEVICE MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════════

@login_required
def device_list(request):
    """Danh sách tất cả thiết bị đã đăng nhập (kể cả offline)."""
    devices = request.user.trusted_devices.all().order_by('-last_seen')
    return render(request, 'accounts/devices.html', {'devices': devices})


@login_required
def active_sessions(request):
    """Danh sách phiên làm việc đang hoạt động."""
    devices = TrustedDevice.objects.filter(
        user=request.user, is_active=True
    ).order_by('-last_seen')
    return render(request, 'accounts/active_sessions.html', {'devices': devices})


@login_required
def logout_device(request, device_id):
    """Đăng xuất một thiết bị cụ thể — xóa session vật lý."""
    device = get_object_or_404(TrustedDevice, id=device_id, user=request.user)
    if device.session_key:
        Session.objects.filter(session_key=device.session_key).delete()
    device.is_active = False
    device.save()
    messages.success(request, f"Đã đăng xuất thiết bị {device.name}")
    return redirect('active_sessions')


@login_required
def logout_all_devices(request):
    """Đăng xuất tất cả thiết bị khác, giữ nguyên session hiện tại."""
    current_session_key = request.session.session_key
    other_devices = TrustedDevice.objects.filter(
        user=request.user, is_active=True
    ).exclude(session_key=current_session_key)

    for device in other_devices:
        if device.session_key:
            Session.objects.filter(session_key=device.session_key).delete()
        device.is_active = False
        device.save()

    messages.success(request, "Đã đăng xuất tất cả các thiết bị khác thành công.")
    return redirect('active_sessions')


@login_required
def confirm_device(request):
    """API: đánh dấu thiết bị hiện tại là tin cậy."""
    if request.method == 'POST' and request.user.is_authenticated:
        session_key = request.session.session_key
        TrustedDevice.objects.filter(
            user=request.user, session_key=session_key
        ).update(is_active=True)
        return JsonResponse({'status': 'ok'})
    return JsonResponse({'status': 'error'}, status=400)


@login_required
def disable_2fa_request(request):
    """Khởi động luồng tắt 2FA — xác định phương thức và redirect đúng trang."""
    profile = request.user.profile

    if profile.has_app_otp:
        method = 'app'
    elif profile.has_email_otp:
        method = 'email'
    else:
        messages.error(request, "Bạn chưa bật 2FA.")
        return redirect('dashboard')

    request.session['disable_2fa_user_id'] = request.user.id
    request.session['disable_2fa_method']  = method

    if method == 'email':
        try:
            generate_and_send_email_otp(
                user   = request.user,
                email  = request.user.email,
                action = 'disable_2fa',
                ip     = get_client_ip(request),
            )
        except Exception as e:
            messages.error(request, f'Lỗi gửi email: {str(e)}')

    return redirect(f'/verify-2fa/?mode=disable&method={method}')


@login_required
def login_history(request):
    """Lịch sử đăng nhập của user hiện tại — dùng ActivityLog."""
    logs = ActivityLog.objects.filter(user=request.user).order_by('-timestamp')
    return render(request, 'accounts/login_history.html', {'logs': logs})


# ═══════════════════════════════════════════════════════════════════════════════
# G. ADMIN VIEWS
# ═══════════════════════════════════════════════════════════════════════════════

@login_required
@user_passes_test(lambda u: u.is_staff or u.is_superuser)
def admin_dashboard(request):
    """
    Trang tổng quan admin.
    chart_data và login_chart hiện dùng dữ liệu tĩnh để demo.
    Thay bằng query thật từ ActivityLog khi cần.
    """
    context = {
        'total_users':     User.objects.count(),
        'active_otps':     EmailOTP.objects.filter(is_used=False, is_active=True).count(),
        'failed_logins':   ActivityLog.objects.filter(action='login_failed').count(),
        'security_alerts': 0,
        'chart_data': [
            {'day': '08/04', 'users': 29, 'otps': 18},
            {'day': '09/04', 'users': 31, 'otps': 22},
            {'day': '10/04', 'users': 33, 'otps': 25},
            {'day': '11/04', 'users': 35, 'otps': 30},
            {'day': '12/04', 'users': 37, 'otps': 28},
            {'day': '13/04', 'users': 25, 'otps': 20},
            {'day': '14/04', 'users': 27, 'otps': 24},
        ],
        'login_chart': [
            {'hour': '00', 'success': 30, 'failed': 2},
            {'hour': '04', 'success': 28, 'failed': 1},
            {'hour': '08', 'success': 35, 'failed': 0},
            {'hour': '12', 'success': 33, 'failed': 3},
            {'hour': '16', 'success': 40, 'failed': 2},
            {'hour': '20', 'success': 32, 'failed': 1},
        ],
    }
    return render(request, 'admin_dashboard/dashboard.html', context)


@login_required
@user_passes_test(lambda u: u.is_staff or u.is_superuser)
def admin_users(request):
    """Danh sách tất cả user."""
    users = User.objects.select_related('profile').prefetch_related('groups').all().order_by('-date_joined')
    return render(request, 'admin_dashboard/users.html', {'users': users})


@login_required
@user_passes_test(lambda u: u.is_staff or u.is_superuser)
def user_management(request):
    """Quản lý user với tìm kiếm, lọc theo trạng thái và 2FA."""
    users = User.objects.select_related('profile').prefetch_related('groups').order_by('-date_joined')

    search        = request.GET.get('search', '').strip()
    status_filter = request.GET.get('status', '')
    twofa_filter  = request.GET.get('2fa', '')

    if search:
        users = users.filter(
            Q(username__icontains=search) | Q(email__icontains=search) |
            Q(first_name__icontains=search) | Q(last_name__icontains=search)
        )

    if status_filter == 'active':
        users = users.filter(is_active=True)
    elif status_filter == 'locked':
        users = users.filter(is_active=False)

    if twofa_filter == 'on':
        users = users.filter(Q(profile__has_app_otp=True) | Q(profile__has_email_otp=True))
    elif twofa_filter == 'off':
        users = users.filter(profile__has_app_otp=False, profile__has_email_otp=False)

    total_users    = User.objects.count()
    active_count   = User.objects.filter(is_active=True).count()
    twofa_on_count = UserProfile.objects.filter(Q(has_app_otp=True) | Q(has_email_otp=True)).count()

    context = {
        'users':        users,
        'total_users':  total_users,
        'active_users': active_count,
        'locked_users': total_users - active_count,
        'twofa_users':  twofa_on_count,
        'search_val':   search,
        'status_val':   status_filter,
        'twofa_val':    twofa_filter,
    }
    return render(request, 'admin_dashboard/users.html', context)


@login_required
@user_passes_test(lambda u: u.is_superuser)
def admin_otp_history(request):
    """
    Lịch sử OTP với bộ lọc username, trạng thái, ngày.
    Hiển thị cả Email OTP log và Google Authenticator info.
    """
    email_otp_queryset = EmailOTP.objects.select_related('user').order_by('-created_at')

    username_query = request.GET.get('username', '').strip()
    status_query   = request.GET.get('status', '')
    date_query     = request.GET.get('date', '')

    if username_query:
        email_otp_queryset = email_otp_queryset.filter(user__username__icontains=username_query)

    if status_query == 'used':
        email_otp_queryset = email_otp_queryset.filter(is_used=True)
    elif status_query == 'pending':
        email_otp_queryset = email_otp_queryset.filter(
            is_used=False,
            created_at__gt=timezone.now() - timedelta(minutes=3)
        )
    elif status_query == 'expired':
        email_otp_queryset = email_otp_queryset.filter(
            is_used=False,
            created_at__lt=timezone.now() - timedelta(minutes=3)
        )

    if date_query:
        email_otp_queryset = email_otp_queryset.filter(created_at__date=date_query)

    paginator   = Paginator(email_otp_queryset, 15)
    page_number = request.GET.get('page')
    email_otps  = paginator.get_page(page_number)

    # Hiển thị secret đã che để kiểm tra trong DEMO
    google_auths = []
    for profile in UserProfile.objects.filter(has_app_otp=True).select_related('user'):
        raw_secret = profile.decrypt_secret()                    # mã đã giải mã
        encrypted_secret = profile.otp_secret or ""              # mã hóa gốc trong DB (gAAAA...)

        #raw_secret = profile.decrypt_secret()
        masked = (
            raw_secret[:8] + "****" + raw_secret[-4:]
            if raw_secret and len(raw_secret) > 8
            else "********"
        )
        google_auths.append({
            'username':      profile.user.username,
            'masked_secret': masked,
            'encrypted_secret': encrypted_secret,
            'full_secret':   raw_secret,
            'current_totp':  get_totp_token(raw_secret),
        })

    context = {
        'email_otps':   email_otps,
        'google_auths': google_auths,
        'total_otp':    email_otp_queryset.count() + len(google_auths),
        'paginator':    paginator,
        'page_obj':     email_otps,
    }
    return render(request, 'admin_dashboard/otp_history.html', context)


@login_required
@user_passes_test(lambda u: u.is_superuser)
def admin_login_history(request):
    """Lịch sử đăng nhập với tìm kiếm, lọc action, date range, user-agent."""
    logs_list = ActivityLog.objects.all().order_by('-timestamp')

    query         = request.GET.get('search', '').strip()
    action_filter = request.GET.get('action', '').strip()
    start_date    = request.GET.get('start_date', '').strip()
    end_date      = request.GET.get('end_date', '').strip()
    device_filter = request.GET.get('device', '').strip()
    per_page      = request.GET.get('per_page', '10')
    if not per_page.isdigit():
        per_page = '10'

    if query:
        logs_list = logs_list.filter(
            Q(username_attempt__icontains=query) |
            Q(ip_address__icontains=query)
        )

    if action_filter:
        logs_list = logs_list.filter(action=action_filter)

    if start_date:
        logs_list = logs_list.filter(timestamp__date__gte=parse_date(start_date))

    if end_date:
        logs_list = logs_list.filter(timestamp__date__lte=parse_date(end_date))

    if device_filter:
        logs_list = logs_list.filter(user_agent__icontains=device_filter)

    paginator   = Paginator(logs_list, int(per_page))
    page_number = request.GET.get('page')
    page_obj    = paginator.get_page(page_number)

    context = {
        'logs':          page_obj,
        'query':         query,
        'action_filter': action_filter,
        'start_date':    start_date,
        'end_date':      end_date,
        'device_filter': device_filter,
        'per_page':      per_page,
        'total_count':   logs_list.count(),
    }
    return render(request, 'admin_dashboard/login_history.html', context)


@login_required
@user_passes_test(lambda u: u.is_superuser)
def admin_force_logout(request, username):
    """Admin cưỡng chế đăng xuất tất cả session của một user."""
    all_sessions = Session.objects.filter(expire_date__gte=timezone.now())
    target_user  = User.objects.filter(username=username).first()
    logout_count = 0

    if target_user:
        for session in all_sessions:
            data = session.get_decoded()
            if str(target_user.pk) == str(data.get('_auth_user_id')):
                session.delete()
                logout_count += 1

    ActivityLog.objects.create(
        user             = request.user,
        username_attempt = request.user.username,
        action           = 'force_logout',
        ip_address       = get_client_ip(request),
        user_agent       = f"Admin cưỡng chế đăng xuất: {username}",
    )

    if logout_count > 0:
        messages.success(request, f"Đã cưỡng chế đăng xuất {logout_count} phiên của {username}.")
    else:
        messages.warning(request, f"Không tìm thấy phiên đang hoạt động của {username}.")

    return redirect('admin_login_history')


@user_passes_test(lambda u: u.is_superuser)
def toggle_user_status(request, user_id):
    """Admin bật/tắt is_active của user."""
    user = get_object_or_404(User, id=user_id)
    if not user.is_superuser:
        user.is_active = not user.is_active
        user.save()
        messages.success(request, f"Đã cập nhật trạng thái cho {user.username}")
    return redirect('admin_dashboard')


@login_required
@user_passes_test(lambda u: u.is_superuser)
def admin_toggle_status(request, user_id):
    """Admin bật/tắt tài khoản user. Không cho phép thao tác trên superuser khác."""
    target_user = get_object_or_404(User, id=user_id)
    if target_user.is_superuser:
        messages.error(request, "Không thể thao tác trên tài khoản Quản trị viên.")
    else:
        target_user.is_active = not target_user.is_active
        target_user.save()
        status_text = "mở khóa" if target_user.is_active else "khóa"
        messages.success(request, f"Đã {status_text} tài khoản {target_user.username} thành công.")
    return redirect('admin_users')


@login_required
@user_passes_test(lambda u: u.is_superuser)
def ban_user(request, user_id):
    """Khóa tài khoản user (is_active=False)."""
    user = get_object_or_404(User, id=user_id)
    if not user.is_superuser:
        user.is_active = False
        user.save()
    return redirect('admin_dashboard')


@login_required
@user_passes_test(lambda u: u.is_superuser)
def admin_disable_otp(request, otp_id):
    """Admin vô hiệu hoá một OTP — chỉ chấp nhận POST để tránh CSRF qua GET link."""
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)

    otp_obj = get_object_or_404(EmailOTP, id=otp_id)

    if not otp_obj.is_active:
        return JsonResponse({'status': 'already_disabled', 'message': 'OTP đã bị vô hiệu trước đó.'})

    otp_obj.disable()

    ActivityLog.objects.create(
        user             = request.user,
        username_attempt = request.user.username,
        action           = '2fa_disable',
        ip_address       = get_client_ip(request),
        user_agent       = f"Admin vô hiệu OTP #{otp_id} của {otp_obj.user.username if otp_obj.user else 'pending'}",
    )

    return JsonResponse({
        'status':  'disabled',
        'message': f'Đã vô hiệu hoá OTP #{otp_id}.',
        'otp_id':  otp_id,
    })

from django.db import connection

@login_required
@user_passes_test(lambda u: u.is_superuser)
def dtb_admin_view(request):
    selected_table = request.GET.get('table', '').strip()
    search_query = request.GET.get('search', '').strip()
    db_path = settings.DATABASES['default']['NAME']  # tên DB để hiển thị

    table_data = {}
    all_tables = []
    error = None

    try:
        with connection.cursor() as cursor:
            # Lấy danh sách bảng (PostgreSQL)
            cursor.execute("""
                SELECT tablename FROM pg_tables
                WHERE schemaname = 'public'
                ORDER BY tablename
            """)
            all_tables = [row[0] for row in cursor.fetchall()]

            tables_to_load = [selected_table] if selected_table in all_tables else all_tables[:8]

            for table in tables_to_load:
                try:
                    # Lấy tên cột
                    cursor.execute("""
                        SELECT column_name FROM information_schema.columns
                        WHERE table_schema = 'public' AND table_name = %s
                        ORDER BY ordinal_position
                    """, [table])
                    columns = [row[0] for row in cursor.fetchall()]

                    # Tổng số dòng
                    cursor.execute(f'SELECT COUNT(*) FROM "{table}"')
                    total_rows = cursor.fetchone()[0]

                    # Dữ liệu
                    if search_query and columns:
                        conditions = ' OR '.join([f'CAST("{col}" AS TEXT) ILIKE %s' for col in columns])
                        sql = f'SELECT * FROM "{table}" WHERE {conditions} LIMIT 100'
                        params = ['%' + search_query + '%'] * len(columns)
                        cursor.execute(sql, params)
                    else:
                        cursor.execute(f'SELECT * FROM "{table}" LIMIT 100')

                    rows = cursor.fetchall()

                    table_data[table] = {
                        'columns': columns,
                        'rows': rows,
                        'total_rows': total_rows,
                    }
                except Exception as e_inner:
                    table_data[table] = {
                        'columns': [], 'rows': [],
                        'total_rows': 0, 'error': str(e_inner)
                    }

    except Exception as e:
        error = str(e)

    context = {
        'tables': table_data,
        'all_tables': all_tables,
        'selected_table': selected_table,
        'db_path': db_path,
        'search_query': search_query,
        'error': error,
    }
    return render(request, 'admin_dashboard/dtb_admin.html', context) 
# ═══════════════════════════════════════════════════════════════════════════════
# H. EXPORT
# ═══════════════════════════════════════════════════════════════════════════════

@user_passes_test(lambda u: u.is_superuser)
def export_users_excel(request):
    """Export danh sách user ra file Excel."""
    users   = User.objects.all()
    keyword = request.GET.get('q')
    if keyword:
        users = users.filter(username__icontains=keyword)

    wb = Workbook()
    ws = wb.active
    ws.title = "Users List"
    ws.append(['ID', 'Username', 'Email', 'Họ Tên', 'Ngày tham gia', 'Trạng thái'])

    for u in users:
        status = "Active" if u.is_active else "Banned"
        ws.append([
            u.id, u.username, u.email,
            f"{u.first_name} {u.last_name}",
            u.date_joined.strftime("%d/%m/%Y"),
            status,
        ])

    response = HttpResponse(
        content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )
    response['Content-Disposition'] = (
        f'attachment; filename="Huit_Auth_User_Log_{timezone.now().strftime("%Y%m%d_%H%M%S")}.xlsx"'
    )
    wb.save(response)
    return response


@user_passes_test(lambda u: u.is_superuser)
def export_otp_excel(request):
    """Export lịch sử Email OTP ra file Excel."""
    logs = EmailOTP.objects.select_related('user').order_by('-created_at')

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Lich_Su_OTP"

    headers = ["STT", "THỜI GIAN", "USERNAME", "MÃ OTP", "DỮ LIỆU MÃ HÓA (SHA-256)", "TRẠNG THÁI"]
    for col, header in enumerate(headers, 1):
        cell = ws.cell(row=4, column=col, value=header)
        cell.font      = Font(bold=True, color="FFFFFF")
        cell.fill      = PatternFill(start_color="1E40AF", end_color="1E40AF", fill_type="solid")
        cell.alignment = Alignment(horizontal="center")

    for idx, log in enumerate(logs, start=1):
        row = idx + 4
        if log.is_used:
            status = "ĐÃ SỬ DỤNG"
        elif log.created_at > timezone.now() - timedelta(minutes=3):
            status = "ĐANG HIỆU LỰC"
        else:
            status = "HẾT HẠN"

        ws.cell(row=row, column=1, value=idx)
        ws.cell(row=row, column=2, value=log.created_at.strftime('%d/%m/%Y %H:%M:%S'))
        ws.cell(row=row, column=3, value=log.user.username if log.user else "Chưa xác thực")
        ws.cell(row=row, column=4, value=log.otp_code)
        ws.cell(row=row, column=5, value=log.otp_hash)
        ws.cell(row=row, column=6, value=status)

    for i, width in enumerate([6, 22, 20, 15, 40, 20], start=1):
        ws.column_dimensions[get_column_letter(i)].width = width

    response = HttpResponse(
        content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    )
    response['Content-Disposition'] = (
        f'attachment; filename="OTP_Log_{timezone.now().strftime("%Y%m%d_%H%M")}.xlsx"'
    )
    wb.save(response)
    return response

def sanitize_row(row):
    """Convert các kiểu dữ liệu đặc biệt về dạng Excel-compatible."""
    result = []
    for val in row:
        if isinstance(val, uuid.UUID):
            result.append(str(val))
        elif isinstance(val, Decimal):
            result.append(float(val))
        elif isinstance(val, (datetime.date, datetime.datetime)):
            result.append(str(val))
        elif isinstance(val, (dict, list)):
            result.append(json.dumps(val, ensure_ascii=False))
        elif val is None:
            result.append('')
        else:
            result.append(val)
    return result


@user_passes_test(lambda u: u.is_superuser)
def export_dtb(request):
    table_name = request.GET.get('table')

    try:
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT tablename FROM pg_tables
                WHERE schemaname = 'public' ORDER BY tablename
            """)
            all_tables = [row[0] for row in cursor.fetchall()]

            wb = Workbook()

            if table_name:
                if table_name not in all_tables:
                    return HttpResponse("Bảng không hợp lệ.", status=400)
                cursor.execute(f'SELECT * FROM "{table_name}"')
                rows = cursor.fetchall()
                columns = [desc[0] for desc in cursor.description]
                ws = wb.active
                ws.title = table_name[:31]
                ws.append(columns)
                for row in rows:
                    ws.append(sanitize_row(row))
                filename = f"{table_name}_{timezone.now().strftime('%Y%m%d_%H%M')}.xlsx"
            else:
                wb.remove(wb.active)
                for table in all_tables:
                    cursor.execute(f'SELECT * FROM "{table}"')
                    rows = cursor.fetchall()
                    columns = [desc[0] for desc in cursor.description]
                    ws = wb.create_sheet(title=table[:31])
                    ws.append(columns)
                    for row in rows:
                        ws.append(sanitize_row(row))
                if not wb.sheetnames:
                    wb.create_sheet("Trống")
                filename = f"FULL_DATABASE_{timezone.now().strftime('%Y%m%d_%H%M')}.xlsx"

        response = HttpResponse(
            content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        )
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        wb.save(response)
        return response

    except Exception as e:
        return HttpResponse(f"Lỗi xuất file: {str(e)}", status=400)

# ═══════════════════════════════════════════════════════════════════════════════
# I. SSO
# ═══════════════════════════════════════════════════════════════════════════════

@login_required
def sso_send(request):
    """
    Sinh JWT token SSO và redirect về callback URL của ứng dụng ngoài.

    Cần cấu hình trong settings.py:
      SSO_SECRET_KEY, SSO_TOKEN_EXPIRY, WEB_SSO_CALLBACK_URL
    """
    user    = request.user
    profile = getattr(user, 'profile', None)
    phone_number = profile.phone_number if profile else ""

    payload = {
        'token_type': 'access',
        'user_id':    user.id,
        'username':   user.username,
        'email':      user.email,
        'first_name': user.first_name,
        'last_name':  user.last_name,
        'phone':      phone_number,
        'iat':        int(time.time()),
        'exp':        int(time.time()) + settings.SSO_TOKEN_EXPIRY,
    }

    token = jwt.encode(payload, settings.SSO_SECRET_KEY, algorithm='HS256')
    return redirect(f"{settings.WEB_SSO_CALLBACK_URL}?token={token}")
