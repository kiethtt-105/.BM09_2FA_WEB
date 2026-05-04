from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib import messages
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework_simplejwt.exceptions import TokenError
from .models import UserProfile
from django.contrib.auth import login
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework_simplejwt.exceptions import TokenError
from django.contrib.auth import login
from django.contrib.auth.models import User
from django.contrib.auth import login, logout
import jwt

# ══════════════════════════════════════════════════════
#  LOGIN / REGISTER
# ══════════════════════════════════════════════════════
def portal_login(request):
    if request.session.get('sso_authenticated') or request.user.is_authenticated:
        return redirect('portal_home')

    if request.method == 'POST':
        action = request.POST.get('action')

        # Đăng nhập trực tiếp
        if action == 'login':
            username = request.POST.get('username')
            password = request.POST.get('password')
            user = authenticate(request, username=username, password=password)
            if user:
                login(request, user)
                request.session['appb_user_id'] = user.id
                request.session.save()
                return redirect('portal_home')
            else:
                messages.error(request, 'Sai tài khoản hoặc mật khẩu!')

        # Đăng ký trực tiếp
        elif action == 'register':
            username = request.POST.get('username', '').strip()
            email    = request.POST.get('email', '').strip()
            password = request.POST.get('password', '').strip()
            password2= request.POST.get('password2', '').strip()

            if not username or not password:
                messages.error(request, 'Vui lòng nhập đầy đủ thông tin!')
            elif password != password2:
                messages.error(request, 'Mật khẩu không khớp!')
            elif User.objects.filter(username=username).exists():
                messages.error(request, 'Tên đăng nhập đã tồn tại!')
            else:
                user = User.objects.create_user(
                    username=username, email=email, password=password
                )
                login(request, user)
                request.session['appb_user_id'] = user.id
                request.session.save()
                messages.success(request, f'Đăng ký thành công! Chào mừng {username}!')
                return redirect('portal_home')

    return render(request, 'portal/login.html')


# ══════════════════════════════════════════════════════
#  HOME
# ══════════════════════════════════════════════════════
def portal_home(request):
    username = request.GET.get('u')
    email    = request.GET.get('e')

    if not username:
        username = request.session.get('sso_username')
        email    = request.session.get('sso_email')

    if not username and request.user.is_authenticated:
        username = request.user.username
        email    = request.user.email

    if not username:
        return redirect('portal_login')

    # Lưu session
    request.session['sso_username']      = username
    request.session['sso_email']         = email
    request.session['sso_authenticated'] = True
    request.session.save()

    # Lấy profile
    user_id = request.session.get('appb_user_id')
    profile = None
    if user_id:
        try:
            profile = UserProfile.objects.get(user_id=user_id)
        except UserProfile.DoesNotExist:
            pass

    return render(request, 'portal/home.html', {
        'user': {
            'username': username,
            'email':    email,
        },
        'profile': profile,
    })


# ══════════════════════════════════════════════════════
#  LIÊN KẾT TÀI KHOẢN HUIT Auth

def sso_callback(request):
    token = request.GET.get('token')
    if not token:
        return redirect('portal_login')

    try:
        # 1. Giải mã cưỡng bức bằng PyJWT để lấy dữ liệu (Hết lỗi NameError)
        # Khóa bí mật phải khớp 100% với App A: huit-sso-secret-2024-change-this
        payload = jwt.decode(token, 'huit-sso-secret-2024-change-this', algorithms=['HS256'])
        
        username = payload.get('username')
        email    = payload.get('email')

        # 2. Logout sạch sẽ session cũ (admin) để không bị kẹt trang Login
        if request.user.is_authenticated:
            logout(request)

        # 3. Tìm User hoặc tạo mới (Dùng tiền tố huit_ để không trùng admin)
        user, created = User.objects.get_or_create(
            username=f"huit_{username}",
            defaults={'email': email}
        )
        
        if created:
            user.set_unusable_password()
            user.save()

        # 4. Đăng nhập User mới vào App B
        login(request, user)
        
        # Cập nhật trạng thái liên kết vào Profile
        profile, _ = UserProfile.objects.get_or_create(user=user)
        profile.huit_username = username
        profile.is_linked = True
        profile.save()

        # 5. Đưa thẳng vào Dashboard App B
        return redirect('portal_home')

    except Exception as e:
        # Nếu có bất kỳ lỗi gì, hiện thông báo và đẩy về Login
        messages.error(request, f'Lỗi xác thực SSO: {str(e)}')
        return redirect('portal_login')

def link_huit_account(request):
    """Nút liên kết nhảy sang App A lấy Token"""
    return redirect('https://spellable-sciuroid-maybell.ngrok-free.dev/sso/send/')

def link_callback(request):
    """Nhận token sau khi user xác thực HUIT để liên kết"""
    token   = request.GET.get('token')
    user_id = request.session.get('appb_user_id')

    if not token or not user_id:
        return redirect('portal_login')

    try:
        access_token  = AccessToken(token)
        huit_username = access_token['username']
        huit_email    = access_token['email']

        user    = User.objects.get(id=user_id)
        profile = UserProfile.objects.get(user=user)

        # Kiểm tra tài khoản HUIT đã liên kết với ai chưa
        if UserProfile.objects.filter(
            huit_username=huit_username
        ).exclude(user=user).exists():
            messages.error(
                request,
                'Tài khoản HUIT này đã được liên kết với tài khoản khác!'
            )
            return redirect('portal_home')

        profile.huit_username = huit_username
        profile.huit_email    = huit_email
        profile.is_linked     = True
        profile.save()

        messages.success(
            request,
            f'Đã liên kết thành công với tài khoản HUIT: {huit_username}!'
        )
        return redirect('portal_home')

    except (TokenError, User.DoesNotExist):
        messages.error(request, 'Liên kết thất bại!')
        return redirect('portal_home')


# ══════════════════════════════════════════════════════
#  LOGOUT
# ══════════════════════════════════════════════════════
def logout_view(request):
    request.session.flush()
    logout(request)
    return redirect('portal_login')