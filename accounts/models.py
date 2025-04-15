from django.contrib.auth.models import AbstractUser
from django.db import models
import random
import string
from django.utils import timezone

class CustomUser(AbstractUser):
    email = models.EmailField(unique=True, blank=False, null=False)

    def delete(self, *args, **kwargs):
        force_real_delete = kwargs.pop('force_real_delete', False)

        if force_real_delete:
            # Реальное удаление из БД
            super().delete(*args, **kwargs)
        else:
            # Стандартное поведение - деактивация
            self.is_active = False
            self.email = f"deleted_{self.id}_{self.email}"
            self.username = f"deleted_{self.id}_{self.username}"
            self.save()

            # Удаляем связанные объекты
            EmailConfirmation.objects.filter(user=self).delete()

    class Meta:
        verbose_name = 'Пользователь'
        verbose_name_plural = 'Пользователи'


class EmailConfirmation(models.Model):
    user = models.ForeignKey('CustomUser', on_delete=models.CASCADE)  # Используем строковую ссылку
    code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    is_used = models.BooleanField(default=False)

    @classmethod
    def generate_code(cls):
        return ''.join(random.choices(string.digits, k=6))

    def is_expired(self):
        return timezone.now() > self.created_at + timezone.timedelta(minutes=15)

    def __str__(self):
        return f"Код подтверждения для {self.user.email}"

    class Meta:
        verbose_name = 'Подтверждение email'
        verbose_name_plural = 'Подтверждения email'