from django.shortcuts import redirect
from django.contrib.auth import logout
from django.utils.timezone import now
from .models import TrustedDevice
from user_agents import parse

class RoleMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.path.startswith("/admin"):
            if request.user.is_authenticated:
                if not request.user.is_staff:
                    return redirect("dashboard")

        return self.get_response(request)


class ForceDisable2FAMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            try:
                user_2fa = request.user.user2fa
                profile = request.user.profile

                if user_2fa.force_disable_2fa:
                    profile.has_email_otp = False
                    profile.has_app_otp = False
                    profile.otp_secret = ""

                    profile.save()

                    user_2fa.force_disable_2fa = False
                    user_2fa.save()

            except Exception as e:
                print("2FA middleware error:", e)

        return self.get_response(request)


class ForceLogoutMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            try:
                control = request.user.usersessioncontrol
                if control.force_logout:
                    control.force_logout = False
                    control.save()
                    logout(request)
            except:
                pass

        return self.get_response(request)

from .models import TrustedDevice

class UpdateDeviceMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            session_key = request.session.session_key

            if not session_key:
                request.session.create()
                session_key = request.session.session_key

            user_agent = request.META.get('HTTP_USER_AGENT', '')
            ip = request.META.get('REMOTE_ADDR')

            # detect đơn giản
            if "Mobile" in user_agent:
                device_type = "📱 Mobile"
            else:
                device_type = "💻 Desktop"

            browser = "Unknown"
            if "Chrome" in user_agent:
                browser = "Chrome"
            elif "Edg" in user_agent:
                browser = "Edge"
            elif "Firefox" in user_agent:
                browser = "Firefox"

            device_name = f"{device_type} - {browser}"

            TrustedDevice.objects.update_or_create(
                session_key=session_key,
                defaults={
                    'user': request.user,
                    'user_agent': user_agent,
                    'ip_address': ip,
                    'name': device_name,
                    'is_active': True
                }
            )

        return self.get_response(request)

# accounts/middleware.py
# Middleware để kiểm tra nếu thiết bị mới thì hiển thị popup cảnh báo
class DeviceAlertMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.user.is_authenticated:
            # Kiểm tra xem session hiện tại đã được đánh dấu là "đã biết" chưa
            session_key = request.session.session_key
            is_trusted = TrustedDevice.objects.filter(
                user=request.user, 
                session_key=session_key,
                is_recognized=True # Bạn nên thêm trường này vào model TrustedDevice
            ).exists()

            # Nếu chưa trusted, gửi flag vào request để template hiển thị popup
            request.is_new_device = not is_trusted
            
        response = self.get_response(request)
        return response