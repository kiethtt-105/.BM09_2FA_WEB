import jwt
import time
import random
import hashlib
import pyotp
import io
import base64
import json
import datetime
from datetime import timedelta
from cryptography.fernet import Fernet     
import pickle
import openpyxl
from datetime import timedelta
from urllib import request
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.models import User
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm
# CHỖ THÊM QUAN TRỌNG: user_passes_test PHẢI ở đây mới đúng
from django.contrib.auth.decorators import login_required, user_passes_test
from django.http import JsonResponse, HttpResponse
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.cache import never_cache
from django.core.mail import send_mail
from django.utils import timezone
from django.utils.timezone import now
from django.utils.dateparse import parse_date
from django.db.models import Q, Count
from django.core.paginator import Paginator
from django.contrib.sessions.models import Session
from django.core.serializers.json import DjangoJSONEncoder
from django import forms
# Import từ local app
from .models import (
    LoginHistory, RemoteAuthRequest, TrustedDevice, 
    EmailOTP, UserProfile, PendingRegistration, 
    OTP, ActivityLog, UserPasskey
)
from .utils import get_totp_token, generate_qr_base64, get_client_ip
# Thư viện FIDO2/WebAuthn
from fido2.server import Fido2Server
from fido2.webauthn import (
    PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity,
    UserVerificationRequirement, ResidentKeyRequirement,
    CollectedClientData, AttestationObject, AuthenticatorData
)
from fido2.utils import websafe_encode, websafe_decode
from fido2.features import webauthn_json_mapping
from fido2.cbor import decode as cbor_decode
# Thư viện Excel
from openpyxl import Workbook
from openpyxl.utils import get_column_letter
from openpyxl.styles import Font, Alignment, PatternFill
try:
    webauthn_json_mapping.enabled = True
except ValueError:
    pass

#
class RegisterForm(UserCreationForm):
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
        model = User
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


def home(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    return render(request, 'accounts/home.html')

def register(request):
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']

            # Xoá pending cũ nếu có
            PendingRegistration.objects.filter(email=email).delete()

            otp_code = str(random.randint(100000, 999999))

            PendingRegistration.objects.create(
                email    = email,
                otp_code = otp_code,
                temp_data = {
                    'username':     form.cleaned_data['username'],
                    'first_name':   form.cleaned_data['first_name'],
                    'middle_name':  form.cleaned_data.get('middle_name', ''),
                    'last_name':    form.cleaned_data['last_name'],
                    'email':        email,
                    'phone_number': form.cleaned_data.get('phone_number', ''),
                    'password':     form.cleaned_data['password1'],
                },
            )

            # Gửi OTP
            try:
                send_mail(
                    subject='🔐 Mã OTP Kích hoạt tài khoản - HUIT',
                    message=f"""Xin chào {form.cleaned_data['first_name']} {form.cleaned_data['last_name']},

                    Mã OTP để kích hoạt tài khoản của bạn là:

                        ► {otp_code}

                    Mã có hiệu lực trong 10 phút. Không chia sẻ mã này với bất kỳ ai.

                    Trân trọng,
                    HUIT System""",
                    from_email=None,
                    recipient_list=[email],
                    fail_silently=False,
                )
                EmailOTP.objects.create(
                    user=None, 
                    otp_code=otp_code,
                    is_used=False
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

        # Gửi lại OTP
        if action == 'resend':
            pending = PendingRegistration.objects.filter(email=email).first()
            if pending:
                new_otp = str(random.randint(100000, 999999))
                old_data = pending.temp_data 
                PendingRegistration.objects.filter(email=email).delete()
                PendingRegistration.objects.create(
                    email     = email,
                    otp_code  = new_otp,
                    temp_data = pending.temp_data,
                )
                try:
                    send_mail(
                        subject='🔐 Mã OTP mới - HUIT',
                        message=f'Mã OTP mới của bạn: {new_otp}\n\nHiệu lực 5 phút.\n\nHUIT System',
                        from_email=None,
                        recipient_list=[email],
                        fail_silently=False,
                    )

                    EmailOTP.objects.create(
                        user=None, 
                        otp_code=new_otp,
                        is_used=False
                    )
                    messages.success(request, 'Đã gửi lại mã OTP mới.')
                except Exception as e:
                    messages.error(request, f'Lỗi gửi email: {str(e)}')
            return redirect('verify_register_otp')

        # Xác nhận OTP
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

        # OTP hợp lệ → Tạo User thật
        data = pending.temp_data
        user = User.objects.create_user(
            username   = data['username'],
            email      = data['email'],
            password   = data['password'],
            first_name = data['first_name'],
            last_name  = data['last_name'],
            is_active  = True,
        )
        
        EmailOTP.objects.filter(otp_code=otp_entered, user__isnull=True).update(user=user, is_used=True)

        UserProfile.objects.get_or_create(
            user=user,
            defaults={
                'middle_name': data.get('middle_name', ''),
                'phone_number': data.get('phone_number', ''),
            }
        )

        pending.is_used = True
        pending.save()

        del request.session['pending_register_email']

        messages.success(request, f'🎉 Chào mừng {user.first_name} {user.last_name}! Tài khoản đã kích hoạt. Hãy đăng nhập.')
        return redirect('login')

    return render(request, 'accounts/verify_register_otp.html', {   
        'email': email,
        'username': username
        })


def logout_view(request):
    from .models import TrustedDevice

    session_key = request.session.session_key
    if session_key:
        TrustedDevice.objects.filter(session_key=session_key).update(is_active=False)

    logout(request)
    return redirect('home')


@login_required
def dashboard(request):
    if request.user.is_superuser:
        return redirect('admin_dashboard')
    profile, _ = UserProfile.objects.get_or_create(user=request.user)
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

         
            if not old_email or not profile.has_email_otp:
                otp = str(random.randint(100000, 999999))
                profile.email_otp  = otp
                profile.otp_expiry = timezone.now() + timedelta(minutes=3)
                profile.save()
                try:
                    send_mail(
                        subject='🔐 Xác nhận cập nhật thông tin - HUIT',
                        message=f"""Xin chào {new_first_name} {new_last_name},

                        Bạn vừa yêu cầu cập nhật thông tin tài khoản trên hệ thống HUIT.
                        Mã OTP xác nhận của bạn là:

                            ► {otp}

                        Thông tin đang chờ cập nhật:
                        - Chữ đệm: {new_middle_name}
                        - Số điện thoại: {new_phone}
                        - Email liên kết: {new_email}

                        Mã có hiệu lực trong 5 phút. Vui lòng không cung cấp mã này cho người khác.

                        Trân trọng,
                        HUIT System""",
                        from_email=None, recipient_list=[new_email], fail_silently=False,
                    )
                    
                    EmailOTP.objects.create(user=request.user, otp_code=otp, is_used=False)
                    messages.success(request, f'Mã OTP đã gửi tới {new_email}')

                except Exception as e:
                    messages.error(request, f'Lỗi gửi email: {str(e)}')

                request.session['pending_update'] = {
                    'first_name': new_first_name, 'middle_name': new_middle_name,
                    'last_name': new_last_name, 'new_email': new_email,
                    'phone_number': new_phone, 'is_first_email': True
                }
                return redirect('dashboard')

            elif new_email != old_email:
                profile.has_email_otp = False
                profile.email_otp = None
                profile.save()
                otp = str(random.randint(100000, 999999))
                profile.email_otp  = otp
                profile.otp_expiry = timezone.now() + timedelta(minutes=3)
                profile.save()
                try:
                    send_mail(
                        subject='🔐 Xác nhận thay đổi Email - HUIT',
                        message=f"""Xin chào {request.user.first_name} {request.user.last_name},

                        Mã OTP xác nhận thay đổi thông tin và Email của bạn là:

                            ► {otp}

                        Thông tin cập nhật:
                        - Họ và tên mới: {new_first_name} {new_middle_name} {new_last_name}
                        - Số điện thoại mới: {new_phone}
                        - Email mới: {new_email}

                        Mã có hiệu lực trong 5 phút.

                        HUIT System""",     
                        from_email=None, recipient_list=[old_email], fail_silently=False,
                    )
                    EmailOTP.objects.create(user=request.user, otp_code=otp, is_used=False)
                except Exception as e:
                    print(f'EMAIL ERROR: {e}')

                request.session['pending_update'] = {
                    'first_name': new_first_name, 'middle_name': new_middle_name,
                    'last_name': new_last_name, 'new_email': new_email,
                    'old_email': old_email, 'phone_number': new_phone, 'is_first_email': False
                }
                return redirect('dashboard')

            else:
                request.user.first_name = new_first_name
                request.user.last_name  = new_last_name
                profile.middle_name     = new_middle_name
                profile.phone_number    = new_phone
                request.user.save()
                EmailOTP.objects.filter(user=request.user, otp_code=otp, is_used=False).update(is_used=True)                
                profile.save()
                messages.success(request, 'Đã cập nhật thông tin thành công!')
                return redirect('dashboard')

        elif 'confirm_update' in request.POST:
            otp_input = request.POST.get('otp_code', '').strip()
            pending   = request.session.get('pending_update')
            
            # 1. Thực hiện băm mã người dùng vừa nhập để so khớp
            input_hash = hashlib.sha256(otp_input.encode()).hexdigest()

            if not pending:
                messages.error(request, 'Không có yêu cầu cập nhật.')
                return redirect('dashboard')

            # 2. Kiểm tra hết hạn (Dùng 3 phút như ông đã yêu cầu trước đó)
            if not profile.email_otp or profile.otp_expiry < timezone.now():
                messages.error(request, 'Mã OTP đã hết hạn.')
                request.session.pop('pending_update', None)
                return redirect('dashboard')

            # 3. So khớp bằng mã Hash (Bảo mật cao)
            # Lưu ý: profile.email_otp lúc này nên lưu chuỗi băm để so sánh
            if otp_input != profile.email_otp:
                # Nếu sai, đánh dấu mã này đã hỏng/đã dùng trong log để Dashboard hiện màu xanh (đã dùng) hoặc đỏ (hết hạn)
                EmailOTP.objects.filter(user=request.user, otp_code=otp_input, is_used=False).update(is_used=True)
                request.session.pop('pending_update', None)
                messages.error(request, 'Mã OTP không đúng!')
                return redirect('dashboard')

            # 4. Nếu đúng -> Cập nhật trạng thái log và lưu thông tin mới
            # Dùng dấu = cho filter, không dùng dấu -
            EmailOTP.objects.filter(user=request.user, otp_code=otp_input, is_used=False).update(is_used=True)
            
            # Cập nhật dữ liệu từ session vào User model
            request.user.first_name = pending['first_name']
            request.user.last_name  = pending['last_name']
            request.user.email      = pending['new_email']
            request.user.save()

            # Cập nhật dữ liệu vào Profile model
            profile.middle_name  = pending.get('middle_name', '')
            profile.phone_number = pending.get('phone_number', '')
            profile.email_otp    = None
            profile.otp_expiry   = None
            profile.save()

            # Xóa session tạm sau khi thành công
            request.session.pop('pending_update', None)
            messages.success(request, 'Đã cập nhật thông tin thành công!')
            return redirect('dashboard')

        else:
            action = request.POST.get('action', '')

            if action == 'disable_email':
                otp = str(random.randint(100000, 999999))
                profile.email_otp  = otp
                profile.otp_expiry = timezone.now() + timedelta(minutes=3)
                profile.save()
                try:
                    send_mail(
                        subject='🔐 Xác nhận tắt Email OTP - HUIT',
                        message=f'Mã OTP xác nhận tắt 2FA email: {otp}\n\nHiệu lực 5 phút.\n\nHUIT System',
                        from_email=None, recipient_list=[request.user.email], fail_silently=False,
                    )
                    confirm_disable = 'disable_email'
                except Exception as e:
                    messages.error(request, 'Lỗi gửi mail xác nhận tắt.')

            elif action == 'disable_app':
                confirm_disable = 'disable_app'

            elif 'confirm_disable_action' in request.POST:
                code   = request.POST.get('disable_otp_code', '').strip()
                target = request.POST.get('confirm_disable_action')
                valid  = False
                if target == 'disable_email' and profile.email_otp == code and profile.otp_expiry > timezone.now():
                    valid = True
                elif target == 'disable_app' and code == get_totp_token(profile.otp_secret):
                    valid = True

                if valid:
                    EmailOTP.objects.filter(user=request.user, otp_code=code, is_used=False).update(is_used=True)
                    if target == 'disable_email':
                        profile.has_email_otp = False
                    else:
                        profile.has_app_otp = False
                        profile.otp_secret  = pyotp.random_base32()
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
        user=request.user, 
        session_key=current_session
    ).first()

    show_alert = False
    if device and not device.is_active:
        show_alert = True

    # Chỉ dùng 1 return render duy nhất cuối cùng để đóng gói tất cả biến
    return render(request, 'accounts/user_dashboard.html', {
        'profile':         profile,
        'confirm_disable': confirm_disable,
        'pending_update':  pending_update,
        'show_device_alert': show_alert,
    })


@login_required
def setup_2fa(request):
    profile, _ = UserProfile.objects.get_or_create(user=request.user)
    method = request.GET.get('method', 'email')

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
                otp = str(random.randint(100000, 999999))
                profile.email_otp  = otp
                profile.otp_expiry = timezone.now() + timedelta(minutes=3)
                profile.save()
                try:
                    send_mail(
                        subject='🔐 Mã OTP Thiết lập Email 2FA - HUIT',
                        message=f'Mã OTP thiết lập 2FA: {otp}\n\nHiệu lực 5 phút.\n\nHUIT System',
                        from_email=None,
                        recipient_list=[request.user.email],
                        fail_silently=False,
                    )
                    # ✅ GHI LOG EmailOTP
                    EmailOTP.objects.create(
                        user=request.user,
                        otp_code=otp,
                        is_used=False,
                    )
                    messages.success(request, '✅ Mã OTP đã gửi đến email của bạn!')
                except Exception as e:
                    messages.error(request, f'Lỗi gửi email: {str(e)}')

            elif 'verify_email_otp' in request.POST:
                code = request.POST.get('email_otp_code', '').strip()
                if profile.email_otp and code == profile.email_otp and profile.otp_expiry > timezone.now():
                    profile.has_email_otp = True
                    profile.email_otp     = None
                    profile.otp_expiry    = None
                    profile.save()
                    # ✅ ĐÁNH DẤU ĐÃ DÙNG
                    EmailOTP.objects.filter(
                        user=request.user, otp_code=code, is_used=False
                    ).update(is_used=True)
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


def verify_2fa(request):
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
    if profile.has_app_otp:   methods.append({'key': 'app',   'name': 'Authenticator', 'icon': '📱'})
    if profile.has_email_otp: methods.append({'key': 'email', 'name': 'Email OTP',     'icon': '📧'})
    if has_fido2:             methods.append({'key': 'fido2', 'name': 'Passkey',       'icon': '🔑'})
    if other_devices.exists():methods.append({'key': 'push',  'name': 'Thiết bị khác','icon': '🔔'})

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

        # ── Push request ─────────────────────────────────
        if action == 'send_push_request':
            from .models import RemoteAuthRequest
            RemoteAuthRequest.objects.filter(
                user=user, session_key=request.session.session_key
            ).delete()
            RemoteAuthRequest.objects.create(
                user=user,
                session_key=request.session.session_key,
                status='pending',
                device_info=request.META.get('HTTP_USER_AGENT', 'Thiết bị lạ')[:255]
            )
            return render(request, 'accounts/verify_2fa.html', {
                'methods': methods, 'method': 'push', 'profile': profile,
                'has_app_otp': profile.has_app_otp, 'has_email_otp': profile.has_email_otp,
                'has_fido2': has_fido2, 'has_other_devices': other_devices.exists(),
                'other_devices_list': list(other_devices[:3]), 'push_request_sent': True,
            })

        # ── Gửi Email OTP mới ────────────────────────────
        if action == 'send_email_code' and profile.has_email_otp:
            otp = str(random.randint(100000, 999999))
            profile.email_otp  = otp
            profile.otp_expiry = timezone.now() + timedelta(minutes=3)
            profile.save()
            send_mail(
                'Mã xác thực đăng nhập - HUIT',
                f'Mã OTP của bạn là: {otp}\n\nHiệu lực 5 phút.',
                None, [user.email], fail_silently=True
            )
            # ✅ GHI LOG EmailOTP
            EmailOTP.objects.create(
                user=user,
                otp_code=otp,
                is_used=False,
            )
            messages.success(request, 'Đã gửi mã OTP mới vào Email.')
            return redirect(f'{request.path}?method=email')

        # ── Xác thực OTP ─────────────────────────────────
        valid = False
        if method == 'app' and profile.has_app_otp:
            raw_secret = profile.decrypt_secret()
            if code == get_totp_token(raw_secret):
                valid = True
        elif method == 'email' and profile.has_email_otp:
            input_hash = hashlib.sha256(code.encode()).hexdigest()

            if code == profile.email_otp and profile.otp_expiry > timezone.now():
                valid = True

        if valid:
            login(request, user)
            request.session.pop('pre_2fa_user_id', None)

            if method == 'email':
                profile.email_otp = None
                profile.save()
                EmailOTP.objects.filter(user=user, otp_code=code, is_used=False).update(is_used=True)
                EmailOTP.objects.filter(
                    user=user, is_used=False
                ).order_by('-created_at').first() and \
                EmailOTP.objects.filter(
                    user=user, is_used=False
                ).order_by('-created_at').update(is_used=True)

            ActivityLog.objects.create(
                user=user, action='login',
                username_attempt=user.username,
                ip_address=ip, user_agent=user_agent
            )
            if request.session.get('sso_pending'):
                request.session.pop('sso_pending', None)
                return redirect('sso_send')
            return redirect('dashboard')

        # ✅ GHI LOG thất bại
        ActivityLog.objects.create(
            user=user, action='login_failed',
            username_attempt=user.username,
            ip_address=ip, user_agent=user_agent
        )
        messages.error(request, 'Mã xác thực không chính xác hoặc hết hạn.')

    return render(request, 'accounts/verify_2fa.html', {
        'methods': methods, 'method': method, 'profile': profile,
        'has_app_otp': profile.has_app_otp, 'has_email_otp': profile.has_email_otp,
        'has_fido2': has_fido2, 'has_other_devices': other_devices.exists(),
        'other_devices_list': list(other_devices[:3]),
        'push_request_sent': push_request_sent,
    })

# ── API: Thiết bị đang online lấy request chờ ────────────
@login_required
def get_pending_auth_request(request):
    from .models import RemoteAuthRequest
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


# ── API: Thiết bị online Đồng ý/Từ chối ─────────────────
@login_required
def respond_auth_request(request, req_id):
    from .models import RemoteAuthRequest
    status = request.GET.get('status')
    if status in ['approved', 'denied']:
        RemoteAuthRequest.objects.filter(
            id=req_id, user=request.user
        ).update(status=status)
        return JsonResponse({'status': 'success'})
    return JsonResponse({'status': 'error'}, status=400)


# ── API: Máy mới polling trạng thái ──────────────────────
def check_auth_status(request):
    from .models import RemoteAuthRequest
    session_key = request.session.session_key
    ip = get_client_ip(request)
    user_agent = request.META.get('HTTP_USER_AGENT', 'Unknown')
    req = RemoteAuthRequest.objects.filter(
        session_key=session_key
    ).order_by('-created_at').first()

    if not req:
        return JsonResponse({'status': 'pending'})

    if req.status == 'approved':
        uid = request.session.get('pre_2fa_user_id')
        if uid:
            try:
                user = User.objects.get(id=uid)
                login(request, user)
                request.session.pop('pre_2fa_user_id', None)
            except User.DoesNotExist:
                pass
        req.delete()
        ActivityLog.objects.create(
            user=user, 
            username_attempt=user.username,
            action='login', # Hiện SUCCESS xanh
            ip_address=ip, 
            user_agent=user_agent
        )
        return JsonResponse({'status': 'approved'})

    elif req.status == 'denied':
        req.delete()
        ActivityLog.objects.create(
            username_attempt=user.username if 'user' in locals() else "Unknown",
            action='login_failed', # Hiện FAILED đỏ
            ip_address=ip, 
            user_agent=user_agent
        )
        return JsonResponse({'status': 'denied'})

    return JsonResponse({'status': 'pending'})

def fido2_auth_begin(request):
    """Trả về challenge để browser gọi WebAuthn API"""
    try:
        uid = request.session.get('pre_2fa_user_id')
        if not uid:
            return JsonResponse({'status': 'error', 'message': 'Không tìm thấy phiên'}, status=400)

        user  = User.objects.get(id=uid)
        rp_id = request.get_host().split(':')[0]

        server_local = Fido2Server(
            PublicKeyCredentialRpEntity(id=rp_id, name="HUIT MFA System")
        )

        # Lấy tất cả passkey của user để tạo allowCredentials
        passkeys = user.passkeys.all()
        if not passkeys.exists():
            return JsonResponse({'status': 'error', 'message': 'Không có passkey nào'}, status=400)

        credentials = []
        for pk in passkeys:
            credentials.append({
                'type': 'public-key',
                'id': pk.credential_id,
            })

        # Tạo authentication challenge
        auth_data, state = server_local.authenticate_begin(
            credentials=[],  # để trống → browser tự chọn passkey phù hợp
            user_verification=UserVerificationRequirement.PREFERRED,
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
    ip = get_client_ip(request)
    user_agent = request.META.get('HTTP_USER_AGENT', 'Unknown')
    try:
        data = json.loads(request.body)

        uid = request.session.get('pre_2fa_user_id')
        if not uid:
            return JsonResponse({'status': 'error', 'message': 'Không tìm thấy phiên'}, status=400)

        user  = User.objects.get(id=uid)
        rp_id = request.get_host().split(':')[0]

        state_encoded = request.session.get('fido2_auth_state')
        if not state_encoded:
            return JsonResponse({'status': 'error', 'message': 'Hết hạn phiên xác thực'}, status=400)

        state = pickle.loads(websafe_decode(state_encoded))

        server_local = Fido2Server(
            PublicKeyCredentialRpEntity(id=rp_id, name="HUIT MFA System")
        )

        credential_id = data.get('id')
        passkey = user.passkeys.filter(credential_id=credential_id).first()
        if not passkey:
            return JsonResponse({'status': 'error', 'message': 'Không tìm thấy passkey'}, status=400)

        # Decode public key từ DB
        from fido2.cbor import decode as cbor_decode, encode as cbor_encode
        pk_dict = cbor_decode(websafe_decode(passkey.public_key))

        from fido2.webauthn import AttestedCredentialData
        credential_data = AttestedCredentialData.create(
            aaguid=b'\x00' * 16,
            credential_id=_b64url_to_bytes(credential_id),
            public_key=pk_dict,
        )

        # ── Parse thủ công clientDataJSON + authData ──────────────
        client_data_bytes  = _b64url_to_bytes(data["response"]["clientDataJSON"])
        auth_data_bytes    = _b64url_to_bytes(data["response"]["authenticatorData"])
        signature_bytes    = _b64url_to_bytes(data["response"]["signature"])

        from fido2.webauthn import CollectedClientData, AuthenticatorData
        client_data = CollectedClientData(client_data_bytes)
        auth_data   = AuthenticatorData(auth_data_bytes)

        # Verify thủ công: challenge + origin + signature
        server_local.authenticate_complete(
            state,
            [credential_data],
            _b64url_to_bytes(credential_id),
            client_data,
            auth_data,
            signature_bytes,
        )

        # Cập nhật sign_count từ authData (không phải từ result)
        passkey.sign_count = auth_data.counter
        passkey.save()

        request.session.pop('fido2_auth_state', None)
        request.session.pop('pre_2fa_user_id', None)

        login(request, user)
        print(f"[FIDO2 AUTH OK] user={user.username}")
        ActivityLog.objects.create(
            user=user, 
            username_attempt=user.username,
            action='login', 
            ip_address=ip, 
            user_agent=user_agent
        )
        return JsonResponse({'status': 'success', 'redirect': '/dashboard/'})

    except Exception as e:
        ActivityLog.objects.create(
            username_attempt=user.username if 'user' in locals() else "Unknown",
            action='login_failed', 
            ip_address=ip, 
            user_agent=user_agent
        )
        import traceback; traceback.print_exc()
        return JsonResponse({'status': 'error', 'message': str(e)}, status=400)
    
#  9. BAN USER (Dành cho admin)
def ban_user(request, user_id):
    user = User.objects.get(id=user_id)
    user.is_active = False
    user.save()
    return redirect('admin_dashboard')

# ══════════════════════════════════════════════════════════
#   ADMIN DASHBOARD
# 2. BẬT/TẮT TRẠNG THÁI USER
@user_passes_test(lambda u: u.is_superuser)
def toggle_user_status(request, user_id):
    user = get_object_or_404(User, id=user_id)
    if not user.is_superuser: # Không cho tự khóa chính mình
        user.is_active = not user.is_active
        user.save()
        messages.success(request, f"Đã cập nhật trạng thái cho {user.username}")
    return redirect('admin_dashboard')

# 3. HÀM LOGIN PHÂN QUYỀN + BỎ QUA 2FA CHO ADMIN
@never_cache
def login_view(request): 
    if request.user.is_authenticated:
        next_url = request.GET.get('next')
        if next_url:
            return redirect(next_url)
        if request.user.is_superuser:
            return redirect('admin_dashboard')
        return redirect('dashboard')
    ip = get_client_ip(request)             
    user_agent = request.META.get('HTTP_USER_AGENT', 'Unknown') 
    if request.method == 'POST':
        username_input = request.POST.get('username')
        form = AuthenticationForm(request, data=request.POST)  
        if form.is_valid():                                     
            user    = form.get_user()
            #username_input = request.POST.get('username') 
            profile = UserProfile.objects.select_related('user').get(user=user) 
            ip          = get_client_ip(request) 
            user_agent  = request.META.get('HTTP_USER_AGENT', 'Unknown') #  Lấy user agent của client để ghi log và có thể dùng cho tính năng nhận diện thiết bị sau này

            # Kiểm tra nếu tài khoản bị khóa (is_active=False), không cho đăng nhập và hiển thị thông báo lỗi
            if not user.is_active:
                messages.error(request, "Tài khoản của bạn đã bị khóa.")
                return render(request, 'accounts/login.html', {'form': form}) # Không redirect về login mà render lại trang login với form và thông báo lỗi, để giữ nguyên URL /login/ và không mất thông tin form đã nhập

            # 1. ADMIN — bỏ qua 2FA
            if user.is_superuser:
                login(request, user)                   
                ActivityLog.objects.create(
                    #user=user if user else None,        nhưng không liên kết với user nào
                    username_attempt=username_input,   
                    action='login',                     
                    ip_address=ip,                      
                    user_agent=user_agent               
                ) 
                messages.success(request, f"Chào Admin, {user.username}!")  
                return redirect('admin_dashboard') 

            # 2. Đồng bộ force_disable
            # Nếu admin bật force_disable_2fa trên user, tự động tắt 2FA và bỏ qua bước xác thực
            user_2fa = getattr(user, 'user2fa', None)   # Trường hợp user chưa có record User2FA nào, tránh lỗi bằng getattr
            if user_2fa and user_2fa.force_disable_2fa: # Nếu admin đã bật force_disable_2fa cho user này
                profile.has_app_otp   = False           # Tắt app OTP
                profile.has_email_otp = False           # Tắt email OTP
                profile.save()                          # Lưu profile sau khi tắt 2FA  
            # 3. Kiểm tra 2FA
            has_fido2 = user.passkeys.exists() # Kiểm tra nếu user có passkey nào đã đăng ký hay không để hiển thị phương thức Passkey trong lựa chọn 2FA
            # Nếu user có bất kỳ phương thức 2FA nào đã bật, chuyển đến trang chọn phương thức 2FA
            if profile.has_app_otp or profile.has_email_otp or has_fido2:
                request.session['pre_2fa_user_id'] = user.id    # Lưu user ID vào session để dùng cho bước xác thực 2FA tiếp theo, tránh lưu toàn bộ user object vào session

                methods_enabled = []    # Tạo danh sách tên phương thức 2FA đã bật để hiển thị trong thông báo
                if profile.has_app_otp: # Nếu user đã bật app OTP, thêm "Authenticator" vào danh sách phương thức đã bật
                    methods_enabled.append("Authenticator") # Nếu user đã bật email OTP, thêm "Email OTP" vào danh sách phương thức đã bật
                if profile.has_email_otp:   # Nếu user đã bật email OTP, thêm "Email OTP" vào danh sách phương thức đã bật
                    methods_enabled.append("Email OTP") # Nếu user có passkey đã đăng ký, thêm "Passkey" vào danh sách phương thức đã bật
                if has_fido2:           #   Nếu user có passkey đã đăng ký, thêm "Passkey" vào danh sách phương thức đã bật
                    methods_enabled.append("Passkey") # Nếu user có thiết bị khác đang online (trừ session hiện tại), thêm "Thiết bị khác" vào danh sách phương thức đã bật
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

            # 4. Không có 2FA — đăng nhập thẳng
            login(request, user)
            next_url = request.GET.get('next')
            if next_url:
                return redirect(next_url)
            ActivityLog.objects.create(
                user=user, action='login', 
                username_attempt=username_input,
                ip_address=ip, 
                user_agent=user_agent,
                #username_attempt=request.POST.get('username')
            ) # Ghi log đăng nhập cho user thường
            if not request.session.session_key:
                request.session.create()

            TrustedDevice.objects.update_or_create(
                session_key=request.session.session_key,
                defaults={
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
            from django.contrib.auth.models import User
            try:
                # Kiểm tra xem có phải user tồn tại nhưng bị Admin khóa (is_active=False) không
                check_user = User.objects.get(username=username_input)
                if not check_user.is_active:
                    # Nếu bị khóa, ghi log  và báo lỗi rõ ràng
                    ActivityLog.objects.create(
                        username_attempt=username_input,
                        action='login_locked_attempt', 
                        ip_address=ip,
                        user_agent=user_agent
                    )
                    messages.error(request, "Tài khoản của bạn hiện đang bị khóa. Vui lòng liên hệ Admin HUIT.")
                else:
                    # User vẫn active nhưng nhập sai pass
                    messages.error(request, "Tên đăng nhập hoặc mật khẩu không đúng.")
            except User.DoesNotExist:
                # Không có user này trong hệ thống
                messages.error(request, "Tên đăng nhập hoặc mật khẩu không đúng.")

            # Vẫn ghi log failed chung để theo dõi
            ActivityLog.objects.create(
                username_attempt=username_input,
                action='login_failed',
                ip_address=ip,
                user_agent=user_agent
            )
    else:
        form = AuthenticationForm()

    return render(request, 'accounts/login.html', {'form': form})


# 1. EXPORT USER LIST RA EXCEL
@user_passes_test(lambda u: u.is_superuser)
def export_users_excel(request):
    users = User.objects.all()
    keyword = request.GET.get('q')
    if keyword:
        users = users.filter(username__icontains=keyword)

    wb = Workbook()
    #wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Users List"
    ws.append(['ID', 'Username', 'Email', 'Họ Tên', 'Ngày tham gia', 'Trạng thái'])

    for u in users:
        status = "Active" if u.is_active else "Banned"
        ws.append([u.id, u.username, u.email, f"{u.first_name} {u.last_name}", 
                   u.date_joined.strftime("%d/%m/%Y"), status])
    response = HttpResponse(content_type='application/ms-excel')
    #response['Content-Disposition'] = 'attachment; filename = f"Huit_Auth_User_Log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"'
    response['Content-Disposition'] = f'attachment; filename="Huit_Auth_User_Log_{  timezone.now().strftime("%Y%m%d_%H%M%S")}.xlsx"'
    wb.save(response)
    return response

@user_passes_test(lambda u: u.is_superuser)
def user_stats(request):
    return render(request, 'admin/stats.html', {})


@login_required
def device_list(request):
    devices = request.user.trusted_devices.all().order_by('-last_seen')

    return render(request, 'accounts/devices.html', {
        'devices': devices
    })

@login_required
def disable_2fa_request(request):
    profile = request.user.profile

    if profile.has_app_otp:
        method = 'app'
    elif profile.has_email_otp:
        method = 'email'
    else:
        messages.error(request, "Bạn chưa bật 2FA.")
        return redirect('dashboard')

    request.session['disable_2fa_user_id'] = request.user.id
    request.session['disable_2fa_method'] = method

    if method == 'email':
        send_email_otp(request.user)

    return redirect(f'/verify-2fa/?mode=disable&method={method}')

@login_required
def login_history(request):
    logs = ActivityLog.objects.filter(user=request.user).order_by('-timestamp')
    return render(request, 'accounts/login_history.html', {'logs': logs})


@login_required
def active_sessions(request):
    # Lấy danh sách thiết bị còn hoạt động (is_active=True)
    devices = TrustedDevice.objects.filter(user=request.user, is_active=True).order_by('-last_seen')
    
    return render(request, 'accounts/active_sessions.html', {
        'devices': devices
    })
    

@login_required
def logout_all_devices(request):
    current_session_key = request.session.session_key
    
    # Lấy tất cả thiết bị đang hoạt động TRỪ thiết bị hiện tại
    other_devices = TrustedDevice.objects.filter(
        user=request.user, 
        is_active=True
    ).exclude(session_key=current_session_key)
    
    for device in other_devices:
        # Xóa session vật lý
        if device.session_key:
            Session.objects.filter(session_key=device.session_key).delete()
        # Cập nhật trạng thái
        device.is_active = False
        device.save()
        
    messages.success(request, "Đã đăng xuất tất cả các thiết bị khác thành công.")
    return redirect('active_sessions')    

@login_required
def logout_device(request, device_id):
    # Tìm thiết bị cụ thể của user
    device = get_object_or_404(TrustedDevice, id=device_id, user=request.user)
    
    # 1. Xóa Session vật lý trong database của Django để user bị văng ra ngay lập tức
    if device.session_key:
        Session.objects.filter(session_key=device.session_key).delete()
    
    # 2. Đánh dấu trong DB là đã offline
    device.is_active = False
    device.save()
    
    messages.success(request, f"Đã đăng xuất thiết bị {device.name}")
    return redirect('active_sessions')

@login_required
def login_history(request):
    logs = LoginHistory.objects.filter(user=request.user).order_by('-time')

    return render(request, 'accounts/login_history.html', {
        'logs': logs
    })

@login_required
def devices(request):
    devices = TrustedDevice.objects.filter(user=request.user, is_active=True)
    return render(request, 'accounts/devices.html', {'devices': devices})

# accounts/views.py

def confirm_device(request):
    if request.method == 'POST' and request.user.is_authenticated:
        session_key = request.session.session_key
        # Tìm và kích hoạt thiết bị hiện tại
        TrustedDevice.objects.filter(
            user=request.user, 
            session_key=session_key
        ).update(is_active=True)
        return JsonResponse({'status': 'ok'})
    return JsonResponse({'status': 'error'}, status=400)


# API để Máy đang online lấy yêu cầu xác thực mới nhất
@login_required
def get_pending_auth_request(request):
    req = RemoteAuthRequest.objects.filter(user=request.user, status='pending').last()
    if req:
        return JsonResponse({
            'has_request': True,
            'request_id': req.id,
            'device_info': req.device_info
        })
    return JsonResponse({'has_request': False})

# API để Máy đang online bấm Đồng ý/Từ chối
@login_required
def respond_auth_request(request, req_id):
    status = request.GET.get('status') # 'approved' hoặc 'denied'
    if status in ['approved', 'denied']:
        RemoteAuthRequest.objects.filter(id=req_id, user=request.user).update(status=status)
        return JsonResponse({'status': 'success'})
    return JsonResponse({'status': 'error'}, status=400)

# API để Máy mới (đang chờ) kiểm tra trạng thái duyệt
def check_auth_status(request):
    session_key = request.session.session_key
    req = RemoteAuthRequest.objects.filter(session_key=session_key).last()
    if req and req.status == 'approved':
        # Nếu đã duyệt, tiến hành đăng nhập chính thức cho session này
        from django.contrib.auth import login
        login(request, req.user)
        req.delete() # Xóa yêu cầu sau khi xong
        return JsonResponse({'status': 'approved'})
    elif req and req.status == 'denied':
        req.delete()
        return JsonResponse({'status': 'denied'})
    return JsonResponse({'status': 'pending'})

#TEST FIDO2from django.shortcuts import render
from django.shortcuts import render

def test_passkey_view(request):
    return render(request, 'accounts/test_passkey.html')

# FIDO2 


# Lưu ý: RP_ID phải khớp chính xác với domain ngrok bạn đang chạy trong terminal
from fido2.webauthn import (
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    UserVerificationRequirement,
    ResidentKeyRequirement,
)
from fido2.server import Fido2Server
from fido2.utils import websafe_encode, websafe_decode
import pickle, json

RP_ID = "spellable-sciuroid-maybell.ngrok-free.dev"
rp = PublicKeyCredentialRpEntity(id=RP_ID, name="HUIT MFA System")
server = Fido2Server(rp)


# ── Helper ở TOP-LEVEL (ngoài mọi hàm) ──────────────────────────
def _b64url_to_bytes(s):
    if isinstance(s, bytes):
        return s
    s = s.replace('-', '+').replace('_', '/')
    s += '=' * (4 - len(s) % 4)
    return base64.b64decode(s)

# ── BEGIN ────────────────────────────────────────────────────────
@login_required # Bắt buộc user phải đăng nhập trước khi bắt đầu đăng ký passkey (để biết user_id)
def fido2_reg_begin(request):       # Trả về options để browser gọi WebAuthn API
    try:                            #WebAuthn API sẽ trả về response rồi gọi tiếp API complete để hoàn tất đăng ký
        user   = request.user
        rp_id  = request.get_host().split(':')[0]
        
        server_local = Fido2Server(
            PublicKeyCredentialRpEntity(id=rp_id, name="HUIT MFA System")
        )

        # Tạo public key
        user_id_bytes = str(user.id).encode('utf-8')
        user_entity   = PublicKeyCredentialUserEntity(
            id=user_id_bytes,
            name=user.username,
            display_name=user.username,
        )   
        
        # Tạo registration challenge
        registration_data, state = server_local.register_begin(
            user_entity,
            user_verification=UserVerificationRequirement.PREFERRED,
            resident_key_requirement=ResidentKeyRequirement.PREFERRED,
        )

        # Xóa state cũ trước khi lưu mới — tránh lỗi quét 2 lần
        request.session.pop('fido2_state', None)
        request.session['fido2_state'] = websafe_encode(pickle.dumps(state))
        
        # Trả về options cho browser
        options = {
            "challenge": websafe_encode(bytes(registration_data.public_key.challenge)),     #challenge phải được encode thành base64url để gửi qua JSON
            "rp":   {"name": "HUIT MFA System", "id": rp_id},                               #rp_id phải khớp với domain đang chạy trong terminal
            "user": {                                                                      #user cũng phải encode id thành base64url, còn name và displayName thì giữ nguyên
                "id":          websafe_encode(user_id_bytes),   #encode user_id thành bytes rồi encode tiếp thành base64url để gửi qua JSON
                "name":        user.username,                   #name và displayName có thể giữ nguyên vì chúng chỉ dùng để hiển thị, không ảnh hưởng đến logic xác thực
                "displayName": user.username,                   #displayName cũng giữ nguyên để hiển thị trong prompt của trình duyệt khi user đăng ký passkey mới
            },
            "pubKeyCredParams": [                               #Định nghĩa thuật toán cho public key, alg -7 là ES256 (ECDSA với curve P-256), alg -257 là RS256 (RSA với SHA-256)
                {"type": "public-key", "alg": -7},              #ES256 là thuật toán phổ biến nhất hiện nay cho passkey, được hầu hết các authenticator hỗ trợ, nên ưu tiên đưa lên trước để tăng khả năng tương thích và tránh lỗi "No supported algorithms" khi trình duyệt không tìm thấy alg phù hợp trong options trả về từ server
                {"type": "public-key", "alg": -257},            #Thêm cả 2 alg để tăng khả năng tương thích với nhiều loại authenticator khác nhau, tránh lỗi "No supported algorithms" khi trình duyệt không tìm thấy alg phù hợp trong options trả về từ server
            ],
            "timeout":    60000,
            "attestation": "none",
            "authenticatorSelection": {
                "residentKey":       "preferred",
                "userVerification":  "preferred",
            },
        }
        
        #In log để kiểm tra rp_id có khớp với domain đang chạy trong terminal không, 
        #nếu không khớp sẽ bị lỗi "NotAllowedError: No supported algorithms" khi trình duyệt gọi WebAuthn API 
        #vì server trả về options có rp_id không đúng nên trình duyệt không tìm thấy passkey phù hợp để đăng ký

        print(f"[BEGIN OK] user={user.username} rp_id={rp_id}") 
        return JsonResponse(options)
        #Nếu có lỗi gì trong quá trình tạo challenge hoặc lưu state, sẽ trả về lỗi 500 và log chi tiết lỗi để debug 
        #nếu có exception xảy ra trong quá trình tạo challenge hoặc lưu state, sẽ trả về lỗi 500 và log chi tiết lỗi để debug
    except Exception as e:
        import traceback; traceback.print_exc()
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


# ── COMPLETE ─────────────────────────────────────────────────────
@csrf_exempt #API này sẽ được gọi bởi browser sau khi user hoàn tất bước quét QR code và xác nhận đăng ký passkey trên thiết bị, nên không bắt buộc phải có session cookie, nhưng vẫn cần xác thực user đã đăng nhập trước đó bằng cách kiểm tra session và user_id trong session
@login_required #Bắt buộc user phải đăng nhập trước khi hoàn tất đăng ký passkey, để đảm bảo có user_id để liên kết với passkey mới, và để tránh lỗi "User is not authenticated" khi API này được gọi mà không có session hợp lệ
def fido2_reg_complete(request):
    try: #API này sẽ được gọi bởi browser sau khi user hoàn tất bước quét QR code và xác nhận đăng ký passkey trên thiết bị, nên không bắt buộc phải có session cookie, nhưng vẫn cần xác thực user đã đăng nhập trước đó bằng cách kiểm tra session và user_id trong session
        data = json.loads(request.body)

        state_encoded = request.session.get('fido2_state')
        if not state_encoded:
            return JsonResponse({'status': 'error', 'message': 'Hết hạn phiên'}, status=400)

        attestation_obj_bytes = _b64url_to_bytes(data["response"]["attestationObject"])

        from fido2.cbor import decode as cbor_decode, encode as cbor_encode
        att_obj = cbor_decode(attestation_obj_bytes)

        auth_data_raw = att_obj.get("authData") or att_obj.get(b"authData")

        from fido2.webauthn import AuthenticatorData
        auth_data = AuthenticatorData(bytes(auth_data_raw))

        credential_data = auth_data.credential_data

        # ✅ public_key là dict (CoseKey) → dùng cbor_encode thay vì bytes()
        pk_bytes = cbor_encode(dict(credential_data.public_key))

        UserPasskey.objects.update_or_create(
            user=request.user,
            credential_id=data['id'],
            defaults={
                'public_key': websafe_encode(pk_bytes),
                'sign_count': auth_data.counter,
            }
        )

        request.session.pop('fido2_state', None)
        print(f"[COMPLETE OK] user={request.user.username}")
        profile, _ = UserProfile.objects.get_or_create(user=request.user)
        profile.has_fido2 = True    # Cập nhật cờ has_fido2 trong profile để hiển thị trên UI
        profile.save()              # Lưu profile sau khi cập nhật cờ has_fido2
        return JsonResponse({'status': 'success'})
    #Nếu có lỗi gì trong quá trình decode attestation object, tạo AuthenticatorData, 
    # hoặc lưu passkey mới vào database, sẽ trả về lỗi 400 và log chi tiết lỗi để debug
    except Exception as e:
        import traceback; traceback.print_exc()
        return JsonResponse({'status': 'error', 'message': str(e)}, status=400)
    
@login_required
def manage_passkeys(request):
    passkeys = request.user.passkeys.all().order_by('-created_at')
    return render(request, 'accounts/manage_passkeys.html', {
        'passkeys': passkeys,
    })

@login_required
def delete_passkey(request, pk_id):
    passkey = get_object_or_404(UserPasskey, id=pk_id, user=request.user)
    passkey.delete()
    messages.success(request, 'Đã xóa passkey thành công!')
    return redirect('manage_passkeys')

# ====================== ADMIN DASHBOARD VIEWS ======================
# Trang Tổng quan admin_dashboard
@login_required
@user_passes_test(lambda u: u.is_staff or u.is_superuser)
def admin_dashboard(request):
    context = {
        'total_users': User.objects.count(),
        'active_otps': 4,           # sau bạn thay bằng query thật của OTP
        'failed_logins': 0,
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
        ]
    }
    return render(request, 'admin_dashboard/dashboard.html', context)

@login_required
@user_passes_test(lambda u: u.is_staff or u.is_superuser)
def admin_users(request):
    users = User.objects.select_related('profile').prefetch_related('groups').all().order_by('-date_joined')
    return render(request, 'admin_dashboard/users.html', {'users': users})



@login_required
@user_passes_test(lambda u: u.is_staff or u.is_superuser)
def admin_otp_history(request):
    # ====================== EMAIL OTP ======================
    email_otp_queryset = EmailOTP.objects.select_related('user').order_by('-created_at')

    # Bộ lọc
    username_query = request.GET.get('username', '').strip()
    status_query = request.GET.get('status', '')
    date_query = request.GET.get('date', '')

    if username_query:
        email_otp_queryset = email_otp_queryset.filter(user__username__icontains=username_query)

    if status_query:
        if status_query == 'used':
            email_otp_queryset = email_otp_queryset.filter(is_used=True)
        elif status_query == 'pending':
            email_otp_queryset = email_otp_queryset.filter(is_used=False, created_at__gt=timezone.now() - timezone.timedelta(minutes=3))
        elif status_query == 'expired':
            email_otp_queryset = email_otp_queryset.filter(is_used=False, created_at__lt=timezone.now() - timezone.timedelta(minutes=3))

    if date_query:
        email_otp_queryset = email_otp_queryset.filter(created_at__date=date_query)

    # Phân trang
    paginator = Paginator(email_otp_queryset, 15)  # 15 dòng mỗi trang
    page_number = request.GET.get('page')
    email_otps = paginator.get_page(page_number)

    # ====================== GOOGLE AUTHENTICATOR ======================
    google_auths = []
    for profile in UserProfile.objects.filter(has_app_otp=True).select_related('user'):
        raw_secret = profile.decrypt_secret() 
        
        masked = raw_secret[:8] + "****" + raw_secret[-4:] if raw_secret and len(raw_secret) > 8 else "********"
        
        google_auths.append({
            'username': profile.user.username,
            'masked_secret': masked,
            'full_secret': raw_secret,
            'current_totp': get_totp_token(raw_secret), # Dùng key đã giải mã để tính mã 6 số
        })

    # Tổng số
    total_otp = email_otp_queryset.count() + len(google_auths)

    context = {
        'email_otps': email_otps,           
        'google_auths': google_auths,       
        'total_otp': total_otp,
        'paginator': paginator,
        'page_obj': email_otps,
    }

    return render(request, 'admin_dashboard/otp_history.html', context)
@login_required
@user_passes_test(lambda u: u.is_staff or u.is_superuser)
def admin_login_history(request):
    return render(request, 'admin_dashboard/login_history.html', {
        'title': 'Hoạt động Đăng nhập'
    })


  
def user_list(request):
    users = User.objects.all()

    search = request.GET.get('search')
    if search:
        users = users.filter(Q(username__icontains=search) | Q(email__icontains=search))

    status = request.GET.get('status')
    if status == 'active':
        users = users.filter(is_active=True)
    elif status == 'inactive':
        users = users.filter(is_active=False)

    twofa = request.GET.get('2fa')
    # Logic lọc 2FA tùy theo model User2FA của bạn

    date_filter = request.GET.get('date_joined')
    if date_filter == 'today':
        users = users.filter(date_joined__date=timezone.now().date())
    elif date_filter == '7days':
        users = users.filter(date_joined__gte=timezone.now() - timedelta(days=7))
    elif date_filter == '30days':
        users = users.filter(date_joined__gte=timezone.now() - timedelta(days=30))

    context = {'users': users}
    return render(request, 'admin/users.html', context)

@login_required
@user_passes_test(lambda u: u.is_staff or u.is_superuser)
def user_management(request):
    # 1. Query dữ liệu: Dùng select_related để gộp bảng Profile giúp load nhanh
    users = User.objects.select_related('profile').prefetch_related('groups').order_by('-date_joined')

    # 2. Nhận tham số từ bộ lọc (Filter) trên giao diện
    search = request.GET.get('search', '').strip()
    status_filter = request.GET.get('status', '')
    twofa_filter = request.GET.get('2fa', '')

    # 3. Thực hiện lọc dữ liệu
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

    # 4. Tính toán số liệu cho các thẻ thống kê (Stat Cards)[cite: 2]
    total_users = User.objects.count()
    active_count = User.objects.filter(is_active=True).count()
    twofa_on_count = UserProfile.objects.filter(Q(has_app_otp=True) | Q(has_email_otp=True)).count()

    context = {
        'users': users,
        'total_users': total_users,
        'active_users': active_count,
        'locked_users': total_users - active_count,
        'twofa_users': twofa_on_count,
        # Trả lại các giá trị lọc để giữ trạng thái trên thanh input[cite: 2]
        'search_val': search,
        'status_val': status_filter,
        'twofa_val': twofa_filter,
    }
    return render(request, 'admin_dashboard/users.html', context)
def is_admin(user):
    return user.is_superuser



@login_required
@user_passes_test(lambda u: u.is_superuser)
def admin_login_history(request):
    # 1. Lấy toàn bộ danh sách log mới nhất
    logs_list = ActivityLog.objects.all().order_by('-timestamp')

    # 2. Lấy các tham số lọc từ URL (GET)
    query = request.GET.get('search', '').strip()
    action_filter = request.GET.get('action', '').strip()
    start_date = request.GET.get('start_date', '').strip()
    end_date = request.GET.get('end_date', '').strip()
    device_filter = request.GET.get('device', '').strip()
    
    # --- THÀNH BAR CHỌN SỐ DÒNG ---
    per_page = request.GET.get('per_page', '10')
    if not per_page.isdigit(): per_page = '10'

    # 3. Thực hiện Logic Lọc chi tiết
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

    # 4. Phân trang
    paginator = Paginator(logs_list, int(per_page))
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    # 5. Dữ liệu gửi xuống Template
    context = {
        'logs': page_obj,
        'query': query,
        'action_filter': action_filter,
        'start_date': start_date,
        'end_date': end_date,
        'device_filter': device_filter,
        'per_page': per_page,
        'total_count': logs_list.count(),
    }
    return render(request, 'admin_dashboard/login_history.html', context)


# 6. ADMIN CƯỠNG CHẾ ĐĂNG XUẤT USER KHÔNG TUYỆT ĐỐI (Dành cho admin)
@login_required
@user_passes_test(lambda u: u.is_superuser)
def admin_force_logout(request, username):
    # 1. Tìm tất cả các session của username này
    # Chúng ta lọc trong bảng Session của Django
    all_sessions = Session.objects.filter(expire_date__gte=timezone.now())
    
    logout_count = 0
    for session in all_sessions:
        data = session.get_decoded()
        # Kiểm tra ID của user trong session data
        if data.get('_auth_user_hash'): # Kiểm tra session có chứa thông tin auth
            # Tìm user object dựa trên username
            from django.contrib.auth.models import User
            target_user = User.objects.filter(username=username).first()
            
            if target_user and str(target_user.pk) == str(data.get('_auth_user_id')):
                session.delete()
                logout_count += 1

    # 2. Ghi log hành động của Admin
    ActivityLog.objects.create(
        user=request.user,            # Gắn trực tiếp user object vào
        username_attempt=request.user.username, # Chỉ để là 'admin' thôi
        action='force_logout',        # Để nó hiện màu vàng KICKED
        ip_address=get_client_ip(request),
        user_agent=f"Đã cưỡng chế đăng xuất: {username}" 
    )

    if logout_count > 0:
        messages.success(request, f"Đã cưỡng chế đăng xuất {logout_count} phiên làm việc của {username}.")
    else:
        messages.warning(request, f"Không tìm thấy phiên làm việc đang hoạt động của {username}.")
        
    return redirect('admin_login_history')

@user_passes_test(lambda u: u.is_superuser)
def export_otp_excel(request):
    logs = EmailOTP.objects.select_related('user').order_by('-created_at')

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Lich_Su_OTP"

    # ... (giữ nguyên phần tiêu đề A1, A2) ...

    # Thêm cột "DỮ LIỆU MÃ HÓA" vào Header
    headers = ["STT", "THỜI GIAN", "USERNAME", "MÃ OTP", "DỮ LIỆU MÃ HÓA (SHA-256)", "TRẠNG THÁI"]
    for col, header in enumerate(headers, 1):
        cell = ws.cell(row=4, column=col, value=header)
        cell.font = Font(bold=True, color="FFFFFF")
        cell.fill = PatternFill(start_color="1E40AF", end_color="1E40AF", fill_type="solid")
        cell.alignment = Alignment(horizontal="center")

    for idx, log in enumerate(logs, start=1):
        row = idx + 4
        # Logic trạng thái
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

    # Chỉnh lại độ rộng cột (Thêm 1 cột nên mảng có 6 phần tử)
    for i, width in enumerate([6, 22, 20, 15, 40, 20], start=1):
        ws.column_dimensions[get_column_letter(i)].width = width

    # ... (giữ nguyên phần response) ...


@login_required
def sso_send(request):
    user = request.user
    
    # Lấy profile an toàn để tránh lỗi 'User' object has no attribute 'userprofile'
    profile = getattr(user, 'userprofile', None)
    phone_number = profile.phone if profile else ""

    payload = {
        'token_type': 'access',
        'user_id':    user.id,
        'username':   user.username,
        'email':      user.email,
        'first_name': user.first_name, # Phan[cite: 3]
        'last_name':  user.last_name,  # Khoi[cite: 3]
        'phone':      phone_number,    # Số điện thoại[cite: 3]
        'iat':        int(time.time()),
        'exp':        int(time.time()) + settings.SSO_TOKEN_EXPIRY,
    }

    token = jwt.encode(payload, settings.SSO_SECRET_KEY, algorithm='HS256')
    
    # ĐẢM BẢO dòng return này nằm riêng biệt, không dính với def sso_send[cite: 3]
    return redirect(f"{settings.WEB_SSO_CALLBACK_URL}?token={token}")

@user_passes_test(lambda u: u.is_superuser)
def admin_toggle_status(request, user_id):
    # Lấy user cần thao tác, nếu không thấy trả về 404
    target_user = get_object_or_404(User, id=user_id)
    
    # Không cho phép khóa chính mình hoặc các Admin khác để đảm bảo an toàn
    if target_user.is_superuser:
        messages.error(request, "Không thể thao tác trên tài khoản Quản trị viên.")
    else:
        # Đảo ngược trạng thái is_active[cite: 2]
        target_user.is_active = not target_user.is_active
        target_user.save()
        
        status_text = "mở khóa" if target_user.is_active else "khóa"
        messages.success(request, f"Đã {status_text} tài khoản {target_user.username} thành công.")
    
    # Quay lại trang quản lý người dùng[cite: 2]
    return redirect('admin_users')
