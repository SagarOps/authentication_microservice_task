from django.contrib import admin
from users.models import Role, User
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from app import constant

admin.site.register(Role)
@admin.register(User)
class UserAdmin(BaseUserAdmin):
    fieldsets = (
        (_('User credential'), {'fields': ('email', 'password', 'phone_otp')}),
        (_('Personal info'), {'fields': ('first_name', 'last_name', 'phone', 'role','is_phone_verified')}),
        (_('Permissions'), {
            'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions'),
        }),
        (_(constant.IMPORTANT_DATES), {'fields': ('last_login', 'date_joined')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('first_name', 'last_name', 'country_code', 'phone', 'email', 'role', 'password1', 'password2')}
        ),
    )

    list_display = ('email', 'first_name', 'last_name', 'phone', 'role')
    list_filter = ('is_staff', 'is_superuser', 'is_active', 'groups')
    search_fields = ('phone', 'first_name', 'last_name', 'email')
    ordering = ('email',)
