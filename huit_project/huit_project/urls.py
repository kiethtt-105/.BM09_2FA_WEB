from django.contrib import admin
from django.urls import path, include
from accounts.admin import default_admin_site

urlpatterns = [
              
    path('admin-origin/', default_admin_site.urls),
    path('', include('accounts.urls')),      
    
    
    
    
    path('admin/', admin.site.urls),
]

