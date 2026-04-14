import profile
from urllib import request
from .models import LoginHistory, RemoteAuthRequest, TrustedDevice
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import login, logout
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.core.mail import send_mail
from django.utils import timezone
from datetime import timedelta
import random
import pyotp
from django.shortcuts import redirect
from .models import TrustedDevice, UserProfile, PendingRegistration
from .utils import get_totp_token, generate_qr_base64
from openpyxl import Workbook
from django.http import HttpResponse
from django.db.models import Count
from django.utils.timezone import now, timedelta
from .models import OTP
#from django.shortcuts import from django.shortcuts import render
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import user_passes_test
from django.contrib.auth.models import User
from .models import OTP, UserProfile # Giả sử bạn có UserProfile
from django.db.models import Count
from django.utils.timezone import now, timedelta
import random
import random
import pyotp
import io
import base64
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.models import User
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm
from django.contrib.auth.decorators import login_required, user_passes_test
from django.core.mail import send_mail
from django.utils import timezone
from django.utils.timezone import now
from django.contrib.auth import login, authenticate
from django.contrib.auth.forms import AuthenticationForm
from .models import UserProfile, ActivityLog
from .utils import get_client_ip 
from openpyxl import Workbook
from django.core.mail import send_mail
from .models import UserProfile, PendingRegistration, OTP, ActivityLog
from .utils import get_totp_token, generate_qr_base64
from django.contrib.auth import login, authenticate
from django.contrib.auth.forms import AuthenticationForm
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.models import User
from .models import UserProfile, ActivityLog
from .utils import get_client_ip
from django.db.models import Q, Count 
from django.http import JsonResponse  
from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from .models import LoginHistory
from django.contrib.sessions.models import Session
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity
import json
import json
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity
from fido2.utils import websafe_encode
from .models import UserPasskey
import json
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from fido2.utils import websafe_encode, websafe_decode
import pickle 
from fido2.utils import websafe_encode, websafe_decode
from fido2.features import webauthn_json_mapping
import json
import pickle
from django.http import JsonResponse
from fido2.utils import websafe_encode, websafe_decode
import json, pickle
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from fido2.utils import websafe_encode, websafe_decode
from fido2.webauthn import PublicKeyCredentialRpEntity
from fido2.server import Fido2Server
from fido2.webauthn import (
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    UserVerificationRequirement,
    ResidentKeyRequirement,
    CollectedClientData,     
    AttestationObject,        
)
from fido2.server import Fido2Server
from fido2.utils import websafe_encode, websafe_decode
import pickle, json

from fido2.webauthn import AuthenticatorData
from fido2.cbor import decode as cbor_decode
import base64, json, pickle
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
try:
    webauthn_json_mapping.enabled = True
except ValueError:
    pass

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


# ══════════════════════════════════════════════════════════
#  1. TRANG CHỦ
# ══════════════════════════════════════════════════════════
def home(request):
    if request.user.is_authenticated:
        return redirect('dashboard')
    return render(request, 'accounts/home.html')


# ══════════════════════════════════════════════════════════
#  2. ĐĂNG KÝ — Bước 1: Nhận form → gửi OTP
# ══════════════════════════════════════════════════════════
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
            except Exception as e:
                messages.error(request, f'Lỗi gửi email: {str(e)}')
                return render(request, 'accounts/register.html', {'form': form})

            request.session['pending_register_email'] = email
            messages.success(request, f'Mã OTP đã gửi tới {email}. Kiểm tra hộp thư!')
            return redirect('verify_register_otp')
    else:
        form = RegisterForm()

    return render(request, 'accounts/register.html', {'form': form})


# ══════════════════════════════════════════════════════════
#  3. ĐĂNG KÝ — Bước 2: Xác nhận OTP → tạo tài khoản
# ══════════════════════════════════════════════════════════
def verify_register_otp(request):
    email = request.session.get('pending_register_email')
    if not email:
        messages.error(request, 'Phiên đã hết hạn. Vui lòng đăng ký lại.')
        return redirect('register')

    if request.method == 'POST':
        action = request.POST.get('action')

        # Gửi lại OTP
        if action == 'resend':
            pending = PendingRegistration.objects.filter(email=email).first()
            if pending:
                new_otp = str(random.randint(100000, 999999))
                PendingRegistration.objects.filter(email=email).delete()
                PendingRegistration.objects.create(
                    email     = email,
                    otp_code  = new_otp,
                    temp_data = pending.temp_data,
                )
                try:
                    send_mail(
                        subject='🔐 Mã OTP mới - HUIT',
                        message=f'Mã OTP mới của bạn: {new_otp}\n\nHiệu lực 10 phút.\n\nHUIT System',
                        from_email=None,
                        recipient_list=[email],
                        fail_silently=False,
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

    return render(request, 'accounts/verify_register_otp.html', {'email': email})


# ══════════════════════════════════════════════════════════
#  4. ĐĂNG XUẤT
# ══════════════════════════════════════════════════════════
def logout_view(request):
    from .models import TrustedDevice

    session_key = request.session.session_key
    if session_key:
        TrustedDevice.objects.filter(session_key=session_key).update(is_active=False)

    logout(request)
    return redirect('home')
#  6. DASHBOARD
# ══════════════════════════════════════════════════════════

@login_required
def dashboard(request):
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

            # FIX NỘI DUNG MAIL TẠI ĐÂY
            if not old_email or not profile.has_email_otp:
                otp = str(random.randint(100000, 999999))
                profile.email_otp  = otp
                profile.otp_expiry = timezone.now() + timedelta(minutes=5)
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
                profile.otp_expiry = timezone.now() + timedelta(minutes=5)
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
                messages.error(request, 'Mã OTP không đúng!')
                return redirect('dashboard')

            request.user.first_name = pending['first_name']
            request.user.last_name  = pending['last_name']
            request.user.email      = pending['new_email']
            request.user.save()
            profile.middle_name = pending.get('middle_name', '')
            profile.phone_number = pending.get('phone_number', '')
            profile.email_otp   = None
            profile.otp_expiry  = None
            profile.save()
            request.session.pop('pending_update', None)
            messages.success(request, 'Đã cập nhật thông tin thành công!')
            return redirect('dashboard')

        else:
            action = request.POST.get('action', '')

            if action == 'disable_email':
                otp = str(random.randint(100000, 999999))
                profile.email_otp  = otp
                profile.otp_expiry = timezone.now() + timedelta(minutes=5)
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
    
    urrent_session = request.session.session_key
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
# ══════════════════════════════════════════════════════════
#  7. SETUP 2FA
# ══════════════════════════════════════════════════════════
@login_required
def setup_2fa(request):
    profile, _ = UserProfile.objects.get_or_create(user=request.user)
    method = request.GET.get('method', 'email')

    context = {
        'profile':        profile,
        'method':         method,
        'user_email':      request.user.email or 'Chưa có email',
        'qr_code_base64': None,
        'otp_secret':      None,
    }

    if request.method == 'POST':
        if method == 'email':
            if 'send_email_otp' in request.POST:
                if not request.user.email:
                    messages.error(request, 'Vui lòng cập nhật email trước!')
                    return redirect('dashboard')
                otp = str(random.randint(100000, 999999))
                profile.email_otp  = otp
                profile.otp_expiry = timezone.now() + timedelta(minutes=5)
                profile.save()
                try:
                    send_mail(
                        subject='🔐 Mã OTP Thiết lập Email 2FA - HUIT',
                        message=f'Mã OTP thiết lập 2FA: {otp}\n\nHiệu lực 5 phút.\n\nHUIT System',
                        from_email=None, recipient_list=[request.user.email], fail_silently=False,
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
                    messages.success(request, '🎉 Đã kích hoạt Email OTP thành công!')
                    return redirect('dashboard')
                else:
                    messages.error(request, 'Mã OTP không đúng hoặc đã hết hạn!')

        elif method == 'app':
            if 'verify_app_otp' in request.POST:
                code         = request.POST.get('otp_code', '').strip()
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
        context['otp_secret']      = new_secret

    return render(request, 'accounts/setup_2fa.html', context)


# ══════════════════════════════════════════════════════════
#  8. VERIFY 2FA

def verify_2fa(request):
    uid = request.session.get('pre_2fa_user_id')
    if not uid:
        return redirect('login')
    try:
        user    = User.objects.get(id=uid)
        profile = user.profile
    except Exception:
        return redirect('login')

    # Thiết bị đang online (trừ session hiện tại)
    other_devices = TrustedDevice.objects.filter(
        user=user, is_active=True
    ).exclude(session_key=request.session.session_key)

    has_fido2 = user.passkeys.exists()

    # Chỉ thêm method user đã bật
    methods = []
    if profile.has_app_otp:
        methods.append({'key': 'app',   'name': 'Authenticator', 'icon': '📱'})
    if profile.has_email_otp:
        methods.append({'key': 'email', 'name': 'Email OTP',     'icon': '📧'})
    if has_fido2:
        methods.append({'key': 'fido2', 'name': 'Passkey',       'icon': '🔑'})
    if other_devices.exists():
        methods.append({'key': 'push',  'name': 'Thiết bị khác', 'icon': '🔔'})

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

        # ── Push request ────────────────────────────────
        if action == 'send_push_request':
            from .models import RemoteAuthRequest
            RemoteAuthRequest.objects.filter(
                user=user,
                session_key=request.session.session_key
            ).delete()
            RemoteAuthRequest.objects.create(
                user=user,
                session_key=request.session.session_key,
                status='pending',
                device_info=request.META.get('HTTP_USER_AGENT', 'Thiết bị lạ')[:255]
            )
            push_request_sent = True
            return render(request, 'accounts/verify_2fa.html', {
                'methods':           methods,
                'method':            'push',
                'profile':           profile,
                'has_app_otp':       profile.has_app_otp,
                'has_email_otp':     profile.has_email_otp,
                'has_fido2':         has_fido2,
                'has_other_devices': other_devices.exists(),
                'other_devices_list': list(other_devices[:3]),
                'push_request_sent': True,
            })

        # ── Email OTP ────────────────────────────────────
        if action == 'send_email_code' and profile.has_email_otp:
            otp = str(random.randint(100000, 999999))
            profile.email_otp  = otp
            profile.otp_expiry = timezone.now() + timedelta(minutes=5)
            profile.save()
            send_mail(
                'Mã xác thực đăng nhập - HUIT',
                f'Mã OTP của bạn là: {otp}\n\nHiệu lực 5 phút.',
                None, [user.email], fail_silently=True
            )
            messages.success(request, 'Đã gửi mã OTP mới vào Email.')
            return redirect(f'{request.path}?method=email')

        # ── Verify OTP ───────────────────────────────────
        valid = False
        if method == 'app' and profile.has_app_otp:
            if code == get_totp_token(profile.otp_secret):
                valid = True
        elif method == 'email' and profile.has_email_otp:
            if code == profile.email_otp and profile.otp_expiry > timezone.now():
                valid = True

        if valid:
            login(request, user)
            request.session.pop('pre_2fa_user_id', None)
            if method == 'email':
                profile.email_otp = None
                profile.save()
            return redirect('dashboard')

        messages.error(request, 'Mã xác thực không chính xác hoặc hết hạn.')

    return render(request, 'accounts/verify_2fa.html', {
        'methods':           methods,
        'method':            method,
        'profile':           profile,
        'has_app_otp':       profile.has_app_otp,
        'has_email_otp':     profile.has_email_otp,
        'has_fido2':         has_fido2,
        'has_other_devices': other_devices.exists(),
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
        return JsonResponse({'status': 'approved'})

    elif req.status == 'denied':
        req.delete()
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
        return JsonResponse({'status': 'success', 'redirect': '/dashboard/'})

    except Exception as e:
        import traceback; traceback.print_exc()
        return JsonResponse({'status': 'error', 'message': str(e)}, status=400)
    
#  9. BAN USER (Dành cho admin)
def ban_user(request, user_id):
    user = User.objects.get(id=user_id)
    user.is_active = False
    user.save()
    return redirect('admin_dashboard')

# ══════════════════════════════════════════════════════════
#  10. EXPORT USERS TO EXCEL (Dành cho admin)
from openpyxl import Workbook
from django.http import HttpResponse
from django.contrib.auth.models import User
#  11. ADMIN DASHBOARD
from django.contrib.auth.decorators import user_passes_test
def admin_dashboard(request):
    total_users = User.objects.count()  
    
    active_otps = UserProfile.objects.filter(
        Q(has_app_otp=True) | Q(has_email_otp=True)
    ).count()

    recent_users = User.objects.order_by('-date_joined')[:5]

    last_7_days = timezone.now() - timedelta(days=6)
    stats = User.objects.filter(date_joined__gte=last_7_days) \
        .extra(select={'day': "date(date_joined)"}) \
        .values('day') \
        .annotate(count=Count('id')) \
        .order_by('day')

    chart_data = []
    for i in range(7):
        date = (last_7_days + timedelta(days=i)).date()
        count = next((item['count'] for item in stats if str(item['day']) == str(date)), 0)
        chart_data.append({'day': date.strftime('%d/%m'), 'count': count})

    return render(request, 'admin_dashboard/dashboard.html', {
        'total_users': total_users,
        'active_otps': active_otps,
        'recent_users': recent_users,
        'chart_data': chart_data,
    })
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


def login_view(request):
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            user    = form.get_user()
            profile = UserProfile.objects.select_related('user').get(user=user)
            ip          = get_client_ip(request)
            user_agent  = request.META.get('HTTP_USER_AGENT', 'Unknown')

            if not user.is_active:
                messages.error(request, "Tài khoản của bạn đã bị khóa.")
                return render(request, 'accounts/login.html', {'form': form})

            # 1. ADMIN — bỏ qua 2FA
            if user.is_superuser:
                login(request, user)
                ActivityLog.objects.create(user=user, action='login', ip_address=ip, user_agent=user_agent)
                messages.success(request, f"Chào Admin, {user.username}!")
                return redirect('admin_dashboard')

            # 2. Đồng bộ force_disable
            user_2fa = getattr(user, 'user2fa', None)
            if user_2fa and user_2fa.force_disable_2fa:
                profile.has_app_otp   = False
                profile.has_email_otp = False
                profile.save()

            # 3. Kiểm tra 2FA
            has_fido2 = user.passkeys.exists()

            if profile.has_app_otp or profile.has_email_otp or has_fido2:
                request.session['pre_2fa_user_id'] = user.id

                methods_enabled = []
                if profile.has_app_otp:
                    methods_enabled.append("Authenticator")
                if profile.has_email_otp:
                    methods_enabled.append("Email OTP")
                if has_fido2:
                    methods_enabled.append("Passkey")

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
            ActivityLog.objects.create(user=user, action='login', ip_address=ip, user_agent=user_agent)

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
            return redirect('dashboard')

        else:
            messages.error(request, "Tên đăng nhập hoặc mật khẩu không đúng.")
    else:
        form = AuthenticationForm()

    return render(request, 'accounts/login.html', {'form': form})

@user_passes_test(lambda u: u.is_superuser)
def export_users_excel(request):
    users = User.objects.all()
    keyword = request.GET.get('q')
    if keyword:
        users = users.filter(username__icontains=keyword)

    wb = Workbook()
    ws = wb.active
    ws.title = "Users List"
    ws.append(['ID', 'Username', 'Email', 'Họ Tên', 'Ngày tham gia', 'Trạng thái'])

    for u in users:
        status = "Active" if u.is_active else "Banned"
        ws.append([u.id, u.username, u.email, f"{u.first_name} {u.last_name}", 
                   u.date_joined.strftime("%d/%m/%Y"), status])
    response = HttpResponse(content_type='application/ms-excel')
    response['Content-Disposition'] = 'attachment; filename=Users_HUIT.xlsx'
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
@login_required
def fido2_reg_begin(request):
    try:
        user   = request.user
        rp_id  = request.get_host().split(':')[0]

        server_local = Fido2Server(
            PublicKeyCredentialRpEntity(id=rp_id, name="HUIT MFA System")
        )

        user_id_bytes = str(user.id).encode('utf-8')
        user_entity   = PublicKeyCredentialUserEntity(
            id=user_id_bytes,
            name=user.username,
            display_name=user.username,
        )

        registration_data, state = server_local.register_begin(
            user_entity,
            user_verification=UserVerificationRequirement.PREFERRED,
            resident_key_requirement=ResidentKeyRequirement.PREFERRED,
        )

        # Xóa state cũ trước khi lưu mới — tránh lỗi quét 2 lần
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
                {"type": "public-key", "alg": -7},
                {"type": "public-key", "alg": -257},
            ],
            "timeout":    60000,
            "attestation": "none",
            "authenticatorSelection": {
                "residentKey":       "preferred",
                "userVerification":  "preferred",
            },
        }

        print(f"[BEGIN OK] user={user.username} rp_id={rp_id}")
        return JsonResponse(options)

    except Exception as e:
        import traceback; traceback.print_exc()
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


# ── COMPLETE ─────────────────────────────────────────────────────
@csrf_exempt
@login_required
def fido2_reg_complete(request):
    try:
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
        return JsonResponse({'status': 'success'})

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