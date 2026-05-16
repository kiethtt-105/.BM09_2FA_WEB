from django.contrib.auth import logout
from django.shortcuts import redirect

from .models import TrustedDevice


# ═══════════════════════════════════════════════════════════════════════════════
# 1. ROLE MIDDLEWARE
# ═══════════════════════════════════════════════════════════════════════════════

class RoleMiddleware:
    """Chặn user không phải staff truy cập /admin*."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.path.startswith('/admin') and request.user.is_authenticated:
            if not request.user.is_staff:
                return redirect('dashboard')
        return self.get_response(request)


# ═══════════════════════════════════════════════════════════════════════════════
# 2. FORCE DISABLE 2FA MIDDLEWARE
# ═══════════════════════════════════════════════════════════════════════════════

class ForceDisable2FAMiddleware:
    """
    Khi admin bật force_disable_2fa trên UserProfile:
      - Tắt has_email_otp, has_app_otp, xóa otp_secret.
      - Reset cờ về False sau khi thực hiện xong.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            try:
                profile = request.user.profile  # FIX-1: bỏ request.user.user2fa
                if profile.force_disable_2fa:
                    profile.has_email_otp     = False
                    profile.has_app_otp       = False
                    profile.otp_secret        = None   # FIX-5: None, không phải ""
                    profile.force_disable_2fa = False
                    profile.save()
            except Exception as e:
                pass  # profile chưa tạo — bỏ qua

        return self.get_response(request)


# ═══════════════════════════════════════════════════════════════════════════════
# 3. FORCE LOGOUT MIDDLEWARE
# ═══════════════════════════════════════════════════════════════════════════════

class ForceLogoutMiddleware:
    """
    Khi admin bật force_logout trên UserProfile:
      - Reset cờ về False trước khi logout (tránh loop logout).
      - Gọi logout() để xóa session.

    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            try:
                profile = request.user.profile  # FIX-2: bỏ request.user.usersessioncontrol
                if profile.force_logout:
                    profile.force_logout = False
                    profile.save(update_fields=['force_logout'])
                    logout(request)
            except Exception:
                pass

        return self.get_response(request)


# ═══════════════════════════════════════════════════════════════════════════════
# 4. UPDATE DEVICE MIDDLEWARE
# ═══════════════════════════════════════════════════════════════════════════════

class UpdateDeviceMiddleware:
    """
    Cập nhật TrustedDevice mỗi request — giữ last_seen và thông tin thiết bị mới nhất.
    Tạo mới nếu session_key chưa có bản ghi.

    FIX: Thêm debounce — chỉ cập nhật khi last_seen cũ hơn 5 phút.
    Loại trừ các path static/media và AJAX polling để giảm áp lực DB.
    """

    DEBOUNCE_MINUTES = 5
    # Các path không cần cập nhật device
    SKIP_PATHS = ('/static/', '/media/', '/api/get-auth-request/', '/api/check-auth-status/')

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            # Bỏ qua các path không cần thiết
            if not any(request.path.startswith(p) for p in self.SKIP_PATHS):
                if not request.session.session_key:
                    request.session.create()
                session_key = request.session.session_key

                user_agent = request.META.get('HTTP_USER_AGENT', '')
                ip         = request.META.get('REMOTE_ADDR')

                device_type = '📱 Mobile' if 'Mobile' in user_agent else '💻 Desktop'
                if 'Edg' in user_agent:
                    browser = 'Edge'
                elif 'Chrome' in user_agent:
                    browser = 'Chrome'
                elif 'Firefox' in user_agent:
                    browser = 'Firefox'
                else:
                    browser = 'Unknown'

                device_name = f'{device_type} - {browser}'

                from django.utils import timezone
                import datetime

                # FIX: Debounce — chỉ UPDATE nếu chưa có hoặc last_seen cũ hơn 5 phút
                existing = TrustedDevice.objects.filter(session_key=session_key).first()
                if existing is None:
                    TrustedDevice.objects.create(
                        session_key = session_key,
                        user        = request.user,
                        user_agent  = user_agent,
                        ip_address  = ip,
                        name        = device_name,
                        is_active   = True,
                    )
                else:
                    threshold = timezone.now() - datetime.timedelta(minutes=self.DEBOUNCE_MINUTES)
                    if existing.last_seen < threshold:
                        TrustedDevice.objects.filter(session_key=session_key).update(
                            user       = request.user,
                            user_agent = user_agent,
                            ip_address = ip,
                            name       = device_name,
                            is_active  = True,
                        )

        return self.get_response(request)


# ═══════════════════════════════════════════════════════════════════════════════
# 5. DEVICE ALERT MIDDLEWARE
# ═══════════════════════════════════════════════════════════════════════════════

class DeviceAlertMiddleware:
    """
    Đặt request.is_new_device = True nếu session hiện tại chưa có TrustedDevice is_active.
    Template dùng flag này để hiển thị popup cảnh báo thiết bị mới.

    FIX-3: is_recognized không tồn tại trong TrustedDevice
           → dùng is_active=True (UpdateDeviceMiddleware sẽ tạo/cập nhật record,
             nên nếu is_active=True tức thiết bị đã được ghi nhận).
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            session_key = request.session.session_key
            is_trusted  = TrustedDevice.objects.filter(
                user        = request.user,
                session_key = session_key,
                is_active   = True,   # FIX-3: bỏ is_recognized
            ).exists()
            request.is_new_device = not is_trusted
        else:
            request.is_new_device = False

        return self.get_response(request)