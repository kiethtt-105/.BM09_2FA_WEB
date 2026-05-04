from django.urls import path
from . import views

urlpatterns = [
    path('',                views.portal_home,    name='portal_home'),
    path('login/',          views.portal_login,   name='portal_login'),
    path('logout/',         views.logout_view,    name='logout'),
    path('sso/callback/',   views.sso_callback,   name='sso_callback'),
    path('sso/link/',       views.link_huit_account, name='link_huit'),
]