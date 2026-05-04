from django.db import models
from django.contrib.auth.models import User


class UserProfile(models.Model):
    
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    # Thêm unique=True để 1 tài khoản HUIT chỉ được liên kết 1 lần[cite: 4]
    huit_username = models.CharField(max_length=150, unique=True, null=True, blank=True)
    is_linked = models.BooleanField(default=False)
    phone = models.CharField(max_length=15, null=True, blank=True)
    
    user = models.OneToOneField(
        User, on_delete=models.CASCADE, related_name='portal_profile'
    )
    # Liên kết với tài khoản HUIT (App A)
    huit_username = models.CharField(
        max_length=150, blank=True, null=True,
        unique=True,
        verbose_name='Tài khoản HUIT liên kết'
    )
    huit_email = models.EmailField(
        blank=True, null=True,
        verbose_name='Email HUIT'
    )
    is_linked = models.BooleanField(
        default=False,
        verbose_name='Đã liên kết với HUIT'
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Profile({self.user.username})"


from django.db.models.signals import post_save
from django.dispatch import receiver

@receiver(post_save, sender=User)
def create_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.get_or_create(user=instance)
        
        