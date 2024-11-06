from django.contrib import admin

# Register your models here.
from django.contrib import admin
from .models import User, OneTimePassword
from unfold.admin import ModelAdmin


@admin.register(User)
class UserAdmin(ModelAdmin):
    list_display = (
        'id',
        'email',
        'first_name',
        'last_name',
        'is_verified',
        'is_staff',
        'is_superuser'
    )
    search_fields = ('email', 'username', 'first_name', 'last_name')
    list_filter = ('is_verified', 'is_staff', 'is_superuser')


@admin.register(OneTimePassword)
class OneTimePasswordAdmin(ModelAdmin):
    list_display = ('user', 'code', 'expires_at', 'created_at', 'secret_key')
    search_fields = ('user__email', 'code')
