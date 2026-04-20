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
from .models import ActivityLog
import base64, json, pickle
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils.dateparse import parse_date
from django.shortcuts import render
from django.contrib.auth.decorators import login_required, user_passes_test
from django.core.paginator import Paginator
from django.db.models import Q
from django.utils.dateparse import parse_date
from .models import ActivityLog 
from django.contrib.sessions.models import Session
from django.utils import timezone
from django.shortcuts import get_object_or_404, redirect
from django.contrib import messages
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
    # Chỉ cho phép chọn method đã bật
    if request.method == 'POST':    # Xử lý form submit cho từng method
        if method == 'email':       # Nếu user chưa có email, yêu cầu cập nhật email trước khi bật email OTP
            if 'send_email_otp' in request.POST: 
                if not request.user.email:
                    messages.error(request, 'Vui lòng cập nhật email trước!')
                    return redirect('dashboard')
                otp = str(random.randint(100000, 999999))   # Tạo OTP mới mỗi lần gửi
                profile.email_otp  = otp                    # Lưu OTP vào profile để sau này so sánh khi user nhập
                profile.otp_expiry = timezone.now() + timedelta(minutes=5) # OTP có hiệu lực 5 phút
                profile.save()                              # Lưu profile sau khi cập nhật OTP và thời gian hết hạn
                try: # Gửi email OTP cho user
                    send_mail(
                        subject='🔐 Mã OTP Thiết lập Email 2FA - HUIT',
                        message=f'Mã OTP thiết lập 2FA: {otp}\n\nHiệu lực 5 phút.\n\nHUIT System',
                        from_email=None, recipient_list=[request.user.email], fail_silently=False,
                    )
                    messages.success(request, '✅ Mã OTP đã gửi đến email của bạn!')
                    # Gửi email OTP thành công, yêu cầu user nhập mã OTP để xác nhận kích hoạt
                except Exception as e:
                    messages.error(request, f'Lỗi gửi email: {str(e)}')
                    # Gửi email OTP thất bại, không yêu cầu user nhập mã OTP nữa
            elif 'verify_email_otp' in request.POST: # Xử lý khi user submit mã OTP để xác nhận kích hoạt email OTP
                code = request.POST.get('email_otp_code', '').strip()
                if profile.email_otp and code == profile.email_otp and profile.otp_expiry > timezone.now(): 
                    # So sánh mã OTP user nhập với mã OTP đã lưu và kiểm tra thời gian hết hạn
                    profile.has_email_otp = True    # Nếu OTP hợp lệ, bật email OTP cho user
                    profile.email_otp     = None    # Xoá mã OTP đã lưu sau khi xác nhận thành công
                    profile.otp_expiry    = None    # Xoá thời gian hết hạn sau khi xác nhận thành công
                    profile.save()                  # Lưu profile sau khi cập nhật trạng thái email OTP
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
# ══════════════════════════════════════════════════════════
def verify_2fa(request):
    user_id = request.session.get('pre_2fa_user_id')
    uid = request.session.get('pre_2fa_user_id') # Lấy user_id tạm thời đã lưu ở bước đăng nhập trước khi xác thực 2FA
    if not uid:             # Nếu không tìm thấy user_id trong session, chuyển hướng về trang login để bắt đầu lại quá trình đăng nhập
        return redirect('login') # Nếu không tìm thấy user_id trong session, chuyển hướng về trang login để bắt đầu lại quá trình đăng nhập
    try:
        user    = User.objects.get(id=uid) # Lấy đối tượng User từ database dựa trên user_id đã lưu trong session
        profile = user.profile # Lấy đối tượng UserProfile của user
    except Exception:
        return redirect('login') # Nếu có lỗi (ví dụ user không tồn tại), chuyển hướng về trang login để bắt đầu lại quá trình đăng nhập

    user = User.objects.get(id=user_id)
    ip = get_client_ip(request)
    user_agent = request.META.get('HTTP_USER_AGENT', 'Unknown')
    
    other_devices = TrustedDevice.objects.filter(
        user=user, is_active=True
    ).exclude(session_key=request.session.session_key)

    has_fido2 = user.passkeys.exists()  # Kiểm tra xem user có passkey nào đã đăng ký hay không để hiển thị tùy chọn đăng nhập bằng Passkey (FIDO2)

    # Chỉ thêm method user đã bật
    methods = []
    if profile.has_app_otp:     # Nếu user đã bật app OTP, thêm tùy chọn đăng nhập bằng Authenticator vào danh sách phương thức xác thực
        methods.append({'key': 'app',   'name': 'Authenticator', 'icon': '📱'}) 
    if profile.has_email_otp:   #   
        methods.append({'key': 'email', 'name': 'Email OTP',     'icon': '📧'})
    if has_fido2:               # Nếu user đã đăng ký passkey, thêm tùy chọn đăng nhập bằng Passkey (FIDO2) vào danh sách phương thức xác thực
        methods.append({'key': 'fido2', 'name': 'Passkey',       'icon': '🔑'})
    if other_devices.exists():  # Nếu có thiết bị tin cậy khác đang hoạt động, thêm tùy chọn đăng nhập qua thiết bị khác vào danh sách phương thức xác thực
        methods.append({'key': 'push',  'name': 'Thiết bị khác', 'icon': '🔔'})

    if not methods: # Nếu user chưa bật bất kỳ phương thức 2FA nào, hiển thị thông báo lỗi và chuyển hướng về trang login để bắt đầu lại quá trình đăng nhập
        messages.error(request, 'Tài khoản chưa thiết lập 2FA!')
        return redirect('login')    # Nếu user chưa bật bất kỳ phương thức 2FA nào, hiển thị thông báo lỗi và chuyển hướng về trang login để bắt đầu lại quá trình đăng nhập

    method       = request.GET.get('method')    # Lấy phương thức xác thực được chọn từ query parameter để hiển thị form tương ứng
    enabled_keys = [m['key'] for m in methods]  # Tạo danh sách các key của phương thức đã bật để kiểm tra tính hợp lệ của phương thức được chọn
    if method not in enabled_keys:              # Nếu phương thức được chọn không hợp lệ (không có trong danh sách phương thức đã bật), chuyển hướng lại với phương thức mặc định là phương thức đầu tiên trong danh sách đã bật
        return redirect(f"{request.path}?method={enabled_keys[0]}")

    push_request_sent = False # Biến cờ để theo dõi xem đã gửi yêu cầu đăng nhập qua thiết bị khác hay chưa, dùng để hiển thị thông báo trên giao diện nếu cần
        # Nếu request là POST, 
        # xử lý các hành động tương ứng với từng phương thức xác thực 
        # như gửi OTP mới, xác nhận OTP, hoặc gửi yêu cầu đăng nhập qua thiết bị khác
    if request.method == 'POST':
        action = request.POST.get('action') # Lấy hành động được thực hiện từ form submit để xác định loại xử lý cần thực hiện, ví dụ như gửi OTP mới, xác nhận OTP, hoặc gửi yêu cầu đăng nhập qua thiết bị khác
        code   = request.POST.get('otp_code', '').strip()   # Lấy mã OTP được user nhập từ form submit để xác thực nếu hành động là xác nhận OTP cho app hoặc email, mã này sẽ được so sánh với mã OTP đã lưu trong profile để xác thực tính hợp lệ

        # ── Push request ────────────────────────────────
        if action == 'send_push_request':   # Nếu hành động là gửi yêu cầu đăng nhập qua thiết bị khác, thực hiện các bước sau:
            from .models import RemoteAuthRequest   # Import model RemoteAuthRequest để lưu trữ yêu cầu đăng nhập qua thiết bị khác vào database
            
            # Xoá các yêu cầu cũ cùng session để tránh tồn đọng nhiều yêu cầu nếu user gửi đi gửi lại nhiều lần
            RemoteAuthRequest.objects.filter(
                user=user,
                session_key=request.session.session_key
            ).delete()
            # Tạo một bản ghi mới trong RemoteAuthRequest với trạng thái 'pending' 
            # để đánh dấu có một yêu cầu đăng nhập qua thiết bị khác đang chờ xử lý,
            # lưu thông tin thiết bị từ user agent để hiển thị trên thiết bị nhận yêu cầu
            RemoteAuthRequest.objects.create(
                user=user,
                session_key=request.session.session_key,
                status='pending',
                device_info=request.META.get('HTTP_USER_AGENT', 'Thiết bị lạ')[:255]
            )
            
            # Đặt biến cờ push_request_sent thành True để hiển thị thông báo đã gửi yêu cầu trên giao diện
            push_request_sent = True
            
            # Chuyển hướng lại trang verify_2fa với method hiện tại 
            # để hiển thị thông báo đã gửi yêu cầu đăng nhập qua thiết bị khác
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
            # Nếu hành động là gửi mã OTP mới cho phương thức email OTP, thực hiện các bước sau:
        if action == 'send_email_code' and profile.has_email_otp:
            otp = str(random.randint(100000, 999999))   # Tạo mã OTP mới
            profile.email_otp  = otp            # Lưu mã OTP mới vào profile để sau này so sánh khi user nhập
            profile.otp_expiry = timezone.now() + timedelta(minutes=5)              # Cập nhật thời gian hết hạn của mã OTP mới (5 phút từ thời điểm tạo)
            profile.save()  #   Lưu profile sau khi cập nhật mã OTP và thời gian hết hạn
             # Gửi email chứa mã OTP mới cho user để xác thực khi user chọn phương thức
             # Nếu gửi email thành công, hiển thị thông báo đã gửi mã OTP mới trên giao diện, 
             # nếu có lỗi khi gửi email, hiển thị thông báo lỗi
            send_mail(
                'Mã xác thực đăng nhập - HUIT',
                f'Mã OTP của bạn là: {otp}\n\nHiệu lực 5 phút.',
                None, [user.email], fail_silently=True
            )
            messages.success(request, 'Đã gửi mã OTP mới vào Email.')
            return redirect(f'{request.path}?method=email')

        # ── Verify OTP ───────────────────────────────────
        # Nếu hành động là xác nhận mã OTP cho phương thức app OTP hoặc email OTP, thực hiện các bước sau:
        valid = False
        # Kiểm tra tính hợp lệ của mã OTP dựa trên phương thức được chọn, 
        # nếu là app OTP thì so sánh với mã OTP được tạo từ secret đã lưu trong profile, 
        # nếu là email OTP thì so sánh với mã OTP đã lưu trong profile và kiểm tra thời gian hết hạn
        if method == 'app' and profile.has_app_otp:     #
            if code == get_totp_token(profile.otp_secret):
                valid = True
        # Nếu mã OTP hợp lệ, thực hiện đăng nhập cho user, 
        # xoá user_id tạm thời đã lưu trong session, 
        # nếu là phương thức email OTP thì xoá mã OTP đã lưu trong profile sau khi xác nhận thành công, 
        # sau đó chuyển hướng về dashboard
        elif method == 'email' and profile.has_email_otp:
            if code == profile.email_otp and profile.otp_expiry > timezone.now():
                valid = True
        # Nếu mã OTP không hợp lệ, hiển thị thông báo lỗi trên giao diện
        # ── XỬ LÝ KẾT QUẢ XÁC THỰC ───────────────────────
        if valid:
            login(request, user)
            request.session.pop('pre_2fa_user_id', None)
            
            # Nếu là email thì dọn dẹp mã
            if method == 'email':
                profile.email_otp = None
                profile.save()

            # ✅ GHI LOG THÀNH CÔNG
            ActivityLog.objects.create(
                user=user, 
                action='login', 
                username_attempt=user.username,
                ip_address=ip, 
                user_agent=user_agent
            )
            return redirect('dashboard')
        
        # ✅ GHI LOG THẤT BẠI (Copy đoạn này đè lên cái cũ)
        ActivityLog.objects.create(
            user=user, 
            action='login_failed', 
            username_attempt=user.username,
            ip_address=ip, 
            user_agent=user_agent
        )
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
from django.views.decorators.cache import never_cache
from django.contrib.auth import login
# Dùng @never_cache để đảm bảo trình duyệt không cache trang login, tránh các vấn đề liên quan đến session và xác thực
@never_cache
def login_view(request): 
    if request.user.is_authenticated:
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
            return redirect('dashboard')

        else:
            ActivityLog.objects.create(
                username_attempt=username_input,
                action='login_failed',
                ip_address=ip,
                user_agent=user_agent
            )
            messages.error(request, "Tên đăng nhập hoặc mật khẩu không đúng.")
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

from django.shortcuts import render
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.models import User

# Trang Tổng quan (đã có)
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
def admin_users(request):
    from accounts.models import UserProfile

    profiles = UserProfile.objects.select_related('user').all()
    fields = [f.name for f in UserProfile._meta.fields]

    return render(request, 'admin_dashboard/users.html', {
        'profiles': profiles,
        'fields': fields
    })

@login_required
@user_passes_test(lambda u: u.is_staff or u.is_superuser)
def admin_otp_history(request):
    from .models import ActivityLog
    from django.db.models import Q
    from django.core.paginator import Paginator

    # 1. Lọc các log liên quan đến OTP (dựa trên action hoặc user_agent)
    # Bạn kiểm tra xem action của bạn lưu là gì (login_failed, login...)
    otp_logs_list = ActivityLog.objects.filter(
        Q(user_agent__icontains="OTP") | Q(action__icontains="otp")
    ).order_by('-timestamp')

    # 2. Xử lý bộ lọc từ Giao diện (Search/Status/Date)
    username_query = request.GET.get('username')
    status_query = request.GET.get('status')
    date_query = request.GET.get('date')

    if username_query:
        otp_logs_list = otp_logs_list.filter(username_attempt__icontains=username_query)
    if status_query:
        otp_logs_list = otp_logs_list.filter(action=status_query)
    if date_query:
        otp_logs_list = otp_logs_list.filter(timestamp__date=date_query)

    # 3. Phân trang (10 dòng mỗi trang)
    paginator = Paginator(otp_logs_list, 10)
    page_number = request.GET.get('page')
    otp_logs = paginator.get_page(page_number)

    # 4. Truyền dữ liệu ra ngoài Template
    context = {
        'otp_logs': otp_logs,
        'total_otp': otp_logs_list.count(),
        'title': 'Lịch sử OTP'
    }
    # Nhớ để đúng đường dẫn template mà bạn vừa fix xong nhé
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


def user_list_view(request):
    # Sử dụng select_related để tránh lỗi N+1 query khi truy cập vào profile
    users = User.objects.select_related('profile').all().order_by('-date_joined')

    # --- Lấy tham số từ URL ---
    search = request.GET.get('search', '').strip()
    status = request.GET.get('status')
    twofa = request.GET.get('2fa')
    date_filter = request.GET.get('date_joined')

    # 1. Logic Tìm kiếm
    if search:
        users = users.filter(
            Q(username__icontains=search) |
            Q(email__icontains=search) |
            Q(first_name__icontains=search) |
            Q(last_name__icontains=search)
        )

    # 2. Logic Trạng thái
    if status == 'active':
        users = users.filter(is_active=True)
    elif status == 'inactive':
        users = users.filter(is_active=False)

    # 3. Logic Lọc 2FA (Dựa trên bảng UserProfile của bạn)
    if twofa == 'enabled':
        # Người dùng có bật app HOẶC bật email
        users = users.filter(Q(profile__has_app_otp=True) | Q(profile__has_email_otp=True))
    elif twofa == 'disabled':
        # Người dùng chưa bật cả hai
        users = users.filter(Q(profile__has_app_otp=False) & Q(profile__has_email_otp=False))
    elif twofa == 'forced_off':
        # Nếu bạn có trường force_disable trong model thì lọc ở đây
        # Giả sử: users = users.filter(profile__force_disable_2fa=True)
        pass

    # 4. Logic Ngày tham gia
    now = timezone.now()
    if date_filter == 'today':
        users = users.filter(date_joined__date=now.date())
    elif date_filter == '7days':
        users = users.filter(date_joined__gte=now - timedelta(days=7))
    elif date_filter == '30days':
        users = users.filter(date_joined__gte=now - timedelta(days=30))

    context = {
        'users': users,
    }
    return render(request, 'accounts/user_management.html', context)

#
# 4. TRANG QUẢN LÝ USER (Dành cho admin)    
def user_management(request):
    # Lấy dữ liệu profile đi kèm để hiển thị 2FA chính xác
    users = User.objects.all().select_related('profile').order_by('-date_joined')

    # Lấy tham số từ Filter Bar
    search = request.GET.get('search')
    two_fa = request.GET.get('2fa')

    # Xử lý tìm kiếm
    if search:
        users = users.filter(
            Q(username__icontains=search) | 
            Q(email__icontains=search)
        )

    # Xử lý lọc 2FA
    if two_fa == 'enabled':
        users = users.filter(
            Q(profile__has_email_otp=True) | 
            Q(profile__has_app_otp=True) | 
            Q(profile__has_fido2=True)
        )
    elif two_fa == 'disabled':
        users = users.filter(
            profile__has_email_otp=False,
            profile__has_app_otp=False,
            profile__has_fido2=False
        )

    return render(request, 'accounts/users.html', {'users': users})

# 5. TRANG LỊCH SỬ OTP (Dành cho admin)
def admin_otp_history(request):
    # Lấy log OTP từ database, sắp xếp mới nhất lên đầu
    # Lưu ý: Thay đổi tên model 'OTP' nếu bạn đặt tên khác trong models.py
    from .models import OTP 
    otp_logs = OTP.objects.all().order_by('-created_at')
    
    return render(request, 'admin_dashboard/otp_history.html', {
        'otp_logs': otp_logs
    })



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

# 7. ADMIN EXPORT LỊCH SỬ OTP RA FILE TXT (Dành cho admin)
@user_passes_test(lambda u: u.is_superuser)
def export_otp_txt(request):
    # 1. Lấy dữ liệu (có thể kết hợp với các bộ lọc hiện tại của bạn)
    logs = ActivityLog.objects.filter(
        Q(action='login') | Q(action='login_failed'),
        user_agent__icontains="OTP" 
    ).order_by('-timestamp')

    # 2. Tạo nội dung file TXT
    content = f"BAO CAO LICH SU XAC THUC OTP - HUIT SECURITY\n"
    content += f"Ngay xuat: {datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n"
    content += "="*60 + "\n\n"
    
    # Định dạng cột
    content += f"{'THOI GIAN':<20} | {'USER':<15} | {'TRANG THAI':<10} | {'IP ADDRESS':<15}\n"
    content += "-"*60 + "\n"

    for log in logs:
        status = "THANH CONG" if log.action == 'login' else "THAT BAI"
        time_str = log.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        content += f"{time_str:<20} | {log.username_attempt:<15} | {status:<10} | {log.ip_address:<15}\n"

    # 3. Phản hồi về trình duyệt để tải xuống
    response = HttpResponse(content, content_type='text/plain; charset=utf-8')
    filename = f"otp_history_{datetime.datetime.now().strftime('%Y%md_%H%M%S')}.txt"
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    
    return response