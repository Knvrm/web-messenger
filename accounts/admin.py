from datetime import timedelta

from django.contrib import admin
from django import forms
from django.utils import timezone
from chat.models import SecurityLog
from .models import CustomUser, EmailConfirmation

class CustomUserAdminForm(forms.ModelForm):
    password1 = forms.CharField(widget=forms.PasswordInput, label="Пароль", required=False)
    password2 = forms.CharField(widget=forms.PasswordInput, label="Подтверждение пароля", required=False)
    decrypt_password = forms.CharField(widget=forms.PasswordInput, label="Пароль для расшифровки ключа", required=False)

    class Meta:
        model = CustomUser
        fields = '__all__'

    def clean(self):
        cleaned_data = super().clean()
        password1 = cleaned_data.get('password1')
        password2 = cleaned_data.get('password2')
        if password1 or password2:
            if password1 != password2:
                raise forms.ValidationError("Пароли не совпадают")
        return cleaned_data

    def save(self, commit=True):
        user = super().save(commit=False)
        password1 = self.cleaned_data.get('password1')
        if password1:
            user.set_password(password1)
            user.generate_rsa_keys(password1)
        if commit:
            user.save()
        return user

@admin.register(CustomUser)
class CustomUserAdmin(admin.ModelAdmin):
    form = CustomUserAdminForm
    list_display = ('username', 'email', 'first_name', 'last_name', 'is_active', 'is_staff', 'is_restricted', 'has_keys', 'suspicious_links_count', 'link_restriction_until')
    list_filter = ('is_active', 'is_staff', 'is_superuser', 'link_restriction_until')
    search_fields = ('username', 'email', 'first_name', 'last_name')
    ordering = ('username',)
    readonly_fields = ('password_hash', 'salt', 'public_key', 'private_key', 'key_salt')
    fieldsets = (
        (None, {'fields': ('email', 'username', 'first_name', 'last_name')}),
        ('Пароль', {'fields': ('password_hash', 'salt')}),
        ('Ключи RSA', {'fields': ('public_key', 'private_key', 'key_salt')}),
        ('Безопасность', {'fields': ('suspicious_links_count', 'last_suspicious_link_at', 'link_restriction_until')}),
        ('Права', {'fields': ('is_active', 'is_staff', 'is_superuser')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'username', 'first_name', 'last_name', 'password1', 'password2', 'is_active', 'is_staff', 'is_superuser'),
        }),
    )
    actions = ['force_delete_users', 'remove_link_restriction']

    def is_restricted(self, obj):
        """Проверяет, заблокирован ли пользователь (не может отправлять сообщения)."""
        one_hour_ago = timezone.now() - timedelta(hours=1)
        malicious_count = SecurityLog.objects.filter(
            user=obj,
            checked_at__gte=one_hour_ago,
            is_malicious=True
        ).count()
        return malicious_count >= 3

    is_restricted.boolean = True
    is_restricted.short_description = 'Заблокирован'

    def has_keys(self, obj):
        return bool(obj.public_key and obj.private_key and obj.key_salt)

    has_keys.boolean = True
    has_keys.short_description = 'Ключи созданы'

    def force_delete_users(self, request, queryset):
        deleted_count = 0
        for user in queryset:
            EmailConfirmation.objects.filter(user=user).delete()
            user.delete(force_real_delete=True)
            deleted_count += 1
        self.message_user(
            request,
            f"Успешно удалено {deleted_count} пользователей и все связанные данные"
        )

    force_delete_users.short_description = "Полное удаление (включая связанные данные)"

    def remove_link_restriction(self, request, queryset):
        updated_count = 0
        one_hour_ago = timezone.now() - timedelta(hours=1)
        for user in queryset:
            # Сбрасываем подозрительные логи за последний час
            SecurityLog.objects.filter(
                user=user,
                checked_at__gte=one_hour_ago,
                is_malicious=True
            ).delete()
            # Сбрасываем поля в CustomUser, если они используются
            if user.link_restriction_until or user.suspicious_links_count > 0:
                user.link_restriction_until = None
                user.suspicious_links_count = 0
                user.save()
                updated_count += 1
        self.message_user(
            request,
            f"Ограничения на отправку сообщений сняты для {updated_count} пользователей"
        )

    remove_link_restriction.short_description = "Снять ограничения на отправку сообщений"

@admin.register(EmailConfirmation)
class EmailConfirmationAdmin(admin.ModelAdmin):
    list_display = ('user', 'code', 'created_at', 'is_used', 'is_expired')
    list_filter = ('is_used', 'created_at')
    search_fields = ('user__username', 'user__email', 'code')
    readonly_fields = ('created_at',)
    date_hierarchy = 'created_at'

    def is_expired(self, obj):
        return obj.is_expired()

    is_expired.boolean = True
    is_expired.short_description = 'Истек срок'