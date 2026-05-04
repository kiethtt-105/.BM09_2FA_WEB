from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.contrib import messages
import jwt
from .models import UserProfile

# ══════════════════════════════════════════════════════
#  HOME
# ══════════════════════════════════════════════════════
def portal_home(request):
    if not request.user.is_authenticated:
        return redirect('portal_login')

    # Lấy Profile để kiểm tra trạng thái liên kết
    profile, _ = UserProfile.objects.get_or_create(user=request.user)

    return render(request, 'portal/home.html', {
        'user': request.user,
        'profile': profile,
    })

# ══════════════════════════════════════════════════════

def sso_callback(request):
    """
    Hàm xử lý logic SSO: nhận token, giải mã dữ liệu, đồng bộ thông tin
    người dùng và thực hiện đăng nhập vào hệ thống App B.
    """
    # Bước 1: Trích xuất Token từ tham số GET trong URL
    token = request.GET.get('token')
    
    if not token:
        # Nếu không có token, báo lỗi và quay về trang đăng nhập
        messages.error(request, "Hệ thống không nhận được mã xác thực từ App A.")
        return redirect('portal_login')

    try:
        # Bước 2: Giải mã Token JWT bằng Secret Key chung
        # Lưu ý: Tuyệt đối không để dính các ký tự lạ như cite vào đây
        payload = jwt.decode(token, 'huit-sso-secret-2024-change-this', algorithms=['HS256'])
        
        # Bước 3: Lấy các thông tin cá nhân được App A gửi sang
        huit_username = payload.get('username')
        huit_email    = payload.get('email', '')
        first_name    = payload.get('first_name', '')
        last_name     = payload.get('last_name', '')
        phone         = payload.get('phone', '')

        # Bước 4: Kiểm tra ràng buộc duy nhất (1 HUIT ID - 1 User App B)
        # Tìm xem tài khoản HUIT này đã được ai liên kết trước đó chưa
        existing_profile = UserProfile.objects.filter(huit_username=huit_username).first()
        
        if existing_profile:
            # Nếu đã có người liên kết, kiểm tra xem có phải chính chủ không
            if request.user.is_authenticated and existing_profile.user != request.user:
                messages.error(request, f"Tài khoản HUIT '{huit_username}' đã được liên kết với một người dùng khác!")
                return redirect('portal_home')
            
            # Nếu chưa đăng nhập, sử dụng User đã có bản ghi liên kết này
            target_user = existing_profile.user
        else:
            # Nếu chưa có ai liên kết, tìm User theo username hoặc tạo mới
            # User tạo từ SSO sẽ có tiền tố huit_ để định danh
            target_user, created = User.objects.get_or_create(
                username=f"huit_{huit_username}",
                defaults={'email': huit_email}
            )
            
            if created:
                # Vô hiệu hóa mật khẩu trực tiếp vì User này dùng SSO
                target_user.set_unusable_password()
                target_user.save()

        # Bước 5: Đồng bộ thông tin Họ tên, Email, SĐT vào Database App B
        # Điều này giúp hiển thị đầy đủ thông tin trên Dashboard
        target_user.first_name = first_name
        target_user.last_name = last_name
        target_user.email = huit_email
        target_user.save()

        # Cập nhật thông tin vào UserProfile mở rộng
        profile, _ = UserProfile.objects.get_or_create(user=target_user)
        profile.huit_username = huit_username
        profile.is_linked = True
        
        # Lưu số điện thoại nếu App A có cung cấp
        if phone:
            profile.phone = phone
        profile.save()

        # Bước 6: Xử lý Session và thực hiện đăng nhập
        if request.user.is_authenticated:
            # Đăng xuất user cũ (ví dụ admin) trước khi nạp user mới
            logout(request)
            
        # Đăng nhập chính thức người dùng vào App B
        login(request, target_user)
        
        # Thông báo thành công kèm theo họ tên lấy từ App A
        messages.success(request, f"Chào mừng {first_name} {last_name}, đăng nhập thành công!")
        
        # Chuyển hướng về trang chủ
        return redirect('portal_home')

    except jwt.ExpiredSignatureError:
        # Xử lý khi mã token đã hết hạn
        messages.error(request, "Mã xác thực SSO đã hết hạn. Vui lòng thử lại.")
        return redirect('portal_login')
    except Exception as e:
        # Xử lý các lỗi ngoại lệ phát sinh khác
        messages.error(request, f"Lỗi hệ thống xác thực: {str(e)}")
        return redirect('portal_login')

# ══════════════════════════════════════════════════════
def link_huit_account(request):
    """Nút liên kết  sang App A lấy Token"""
    return redirect('https://spellable-sciuroid-maybell.ngrok-free.dev/sso/send/')

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

    return render(request, 'portal/login.html')