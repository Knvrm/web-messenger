from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser, EmailConfirmation


@admin.register(CustomUser)
class CustomUserAdmin(UserAdmin):
    # Наследуем от UserAdmin для стандартного интерфейса пользователей
    list_display = ('username', 'email', 'first_name', 'last_name', 'is_active', 'is_staff')
    list_filter = ('is_active', 'is_staff', 'is_superuser')
    search_fields = ('username', 'email', 'first_name', 'last_name')
    ordering = ('username',)
    actions = ['force_delete_users']

    def force_delete_users(self, request, queryset):
        # Полное удаление пользователей
        deleted_count = 0
        for user in queryset:
            # Удаляем связанные объекты
            EmailConfirmation.objects.filter(user=user).delete()

            # Полное удаление пользователя
            user.delete(force_real_delete=True)
            deleted_count += 1

        self.message_user(
            request,
            f"Успешно удалено {deleted_count} пользователей и все связанные данные"
        )

    force_delete_users.short_description = "Полное удаление (включая связанные данные)"


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