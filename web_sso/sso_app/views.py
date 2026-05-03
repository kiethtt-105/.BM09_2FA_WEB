import jwt
from django.conf import settings
from django.contrib.auth import login, logout, get_user_model
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render
from django.http import HttpResponseBadRequest

User = get_user_model()


def sso_login(request):
    return redirect(settings.HUIT_SSO_ENTRY_URL)


def sso_callback(request):
    token = request.GET.get('token')
    if not token:
        return HttpResponseBadRequest('Thiếu token.')

    try:
        payload = jwt.decode(token, settings.SSO_SECRET_KEY, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return HttpResponseBadRequest('Token đã hết hạn. Vui lòng đăng nhập lại.')
    except jwt.InvalidTokenError:
        return HttpResponseBadRequest('Token không hợp lệ.')

    user, created = User.objects.get_or_create(
        username=payload['username'],
        defaults={
            'email':      payload.get('email', ''),
            'first_name': payload.get('first_name', ''),
            'last_name':  payload.get('last_name', ''),
            'is_staff':   payload.get('is_staff', False),
        }
    )

    if not created:
        user.email      = payload.get('email', user.email)
        user.first_name = payload.get('first_name', user.first_name)
        user.last_name  = payload.get('last_name', user.last_name)
        user.save()

    user.backend = 'django.contrib.auth.backends.ModelBackend'
    login(request, user)
    return redirect('home')


@login_required
def home(request):
    return render(request, 'home.html', {'user': request.user})


def logout_view(request):
    logout(request)
    return redirect('sso_login')