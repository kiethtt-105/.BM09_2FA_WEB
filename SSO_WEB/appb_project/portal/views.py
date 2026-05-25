from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib import messages
import jwt
from .models import UserProfile
import requests
from django.shortcuts import redirect
from django.conf import settings 
import hashlib
from django.contrib.auth.hashers import make_password
from django.contrib.auth.decorators import login_required

# ══════════════════════════════════════════════════════
#  HOME
# ═════════════════════════════════════════════════════     
def portal_home(request):
    if not request.user.is_authenticated:
        return redirect('portal_login')

    # Lấy Profile để kiểm tra trạng thái liên kết
    profile, _ = UserProfile.objects.get_or_create(user=request.user)

    return render(request, 'portal/home.html', {
        'user': request.user,
        'profile': profile,
        'huit_sso_url': settings.HUIT_SSO_URL
    })

# ══════════════════════════════════════════════════════
def sso_callback(request):
    """
    Hàm xử lý logic SSO: nhận token, giải mã dữ liệu, đồng bộ thông tin
    người dùng và thực hiện đăng nhập vào hệ thống App B.
    """
    token = request.GET.get('token')
    
    if not token:
        messages.error(request, "Hệ thống không nhận được mã xác thực từ App A.")
        return redirect('portal_login')

    try:
        payload = jwt.decode(token, '1669a995c7053fbf22cb9bd6babd28db27fab99e8f58f04d38a683aa125054d9', algorithms=['HS256'])
        
        huit_username = payload.get('username')
        huit_email    = payload.get('email', '')
        first_name    = payload.get('first_name', '')
        last_name     = payload.get('last_name', '')
        phone         = payload.get('phone', '')

        existing_profile = UserProfile.objects.filter(huit_username=huit_username).first()
        
        if existing_profile:
            if request.user.is_authenticated and existing_profile.user != request.user:
                messages.error(request, f"Tài khoản HUIT '{huit_username}' đã được liên kết với một người dùng khác!")
                return redirect('portal_home')
            target_user = existing_profile.user
        else:
            # Đọc linking_user_id từ JWT payload (do HUIT đính vào khi sinh token)
            linking_user_id = payload.get('linking_user_id')

            if linking_user_id:
                # Luồng liên kết: gắn HUIT vào tài khoản AppB đã có
                try:
                    target_user = User.objects.get(id=linking_user_id)
                except User.DoesNotExist:
                    messages.error(request, 'Không tìm thấy tài khoản AppB. Vui lòng thử lại.')
                    return redirect('portal_login')
            else:
                # Luồng đăng nhập SSO lần đầu: tạo tài khoản mới từ HUIT
                target_user, created = User.objects.get_or_create(
                    username=f"huit_{huit_username}",
                    defaults={'email': huit_email}
                )
                if created:
                    target_user.set_unusable_password()
                    target_user.save()

        target_user.first_name = first_name
        target_user.last_name  = last_name
        target_user.email      = huit_email
        target_user.save()

        profile, _ = UserProfile.objects.get_or_create(user=target_user)
        profile.huit_username = huit_username
        profile.is_linked     = True
        if phone:
            profile.phone = phone
        profile.save()

        if request.user.is_authenticated:
            logout(request)
            
        login(request, target_user)
        messages.success(request, f"Chào mừng {first_name} {last_name}, đăng nhập thành công!")
        return redirect('portal_home')

    except jwt.ExpiredSignatureError:
        messages.error(request, "Mã xác thực SSO đã hết hạn. Vui lòng thử lại.")
        return redirect('portal_login')
    except Exception as e:
        messages.error(request, f"Lỗi hệ thống xác thực: {str(e)}")
        return redirect('portal_login')

# ══════════════════════════════════════════════════════
@login_required
def link_huit_account(request):
    """Truyền linking_user_id qua URL để HUIT đính kèm vào callback"""
    sso_url = f"{settings.HUIT_SSO_URL}/sso/send/?linking_user_id={request.user.id}"
    return redirect(sso_url)

def logout_view(request):
    request.session.flush()
    logout(request)
    return redirect('portal_login')

#  LOGIN / REGISTER BÌNH THƯỜNG
# ══════════════════════════════════════════════════════
def portal_login(request):
    if request.user.is_authenticated:
        return redirect('portal_home')

    if request.method == 'POST':
        action = request.POST.get('action')

        # Xử lý Đăng nhập thủ công
        if action == 'login':
            u = request.POST.get('username')
            p = request.POST.get('password')
            user = authenticate(request, username=u, password=p)
            if user:
                login(request, user)
                return redirect('portal_home')
            messages.error(request, 'Sai tài khoản hoặc mật khẩu!')

        # Xử lý Đăng ký thủ công
        elif action == 'register':
            u = request.POST.get('username', '').strip()
            e = request.POST.get('email', '').strip()
            p = request.POST.get('password', '').strip()
            p2 = request.POST.get('password2', '').strip()

            if p != p2:
                messages.error(request, 'Mật khẩu không khớp!')
            elif User.objects.filter(username=u).exists():
                messages.error(request, 'Tên đăng nhập đã tồn tại!')
            else:
                new_user = User.objects.create_user(username=u, email=e, password=p)
                login(request, new_user)
                messages.success(request, f'Chào mừng {u} đã đăng ký thành công!')
                return redirect('portal_home')

    return render(request, 'portal/login.html', {'huit_sso_url': settings.HUIT_SSO_URL})