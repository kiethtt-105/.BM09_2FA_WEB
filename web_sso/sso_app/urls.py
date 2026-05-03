from django.urls import path
from . import views

urlpatterns = [
    path('',              views.home,         name='home'),
    path('sso/login/',    views.sso_login,    name='sso_login'),
    path('sso/callback/', views.sso_callback, name='sso_callback'),
    path('logout/',       views.logout_view,  name='logout'),
]