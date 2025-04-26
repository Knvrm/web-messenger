from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
import random
import string
from django.utils import timezone
from .pbkdf2_hmac import hash_password, verify_password

class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('Поле Email обязательно')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        if password:
            user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        if extra_fields.get('is_staff') is not True:
            raise ValueError('Суперпользователь должен иметь is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Суперпользователь должен иметь is_superuser=True.')
        return self.create_user(email, password, **extra_fields)

class CustomUser(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True, blank=False, null=False)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    username = models.CharField(max_length=150, unique=True, blank=True, null=True)
    first_name = models.CharField(max_length=150, blank=True)
    last_name = models.CharField(max_length=150, blank=True)
    password_hash = models.CharField(max_length=256, default='')
    salt = models.BinaryField(max_length=16, default=b'')
    date_joined = models.DateTimeField(auto_now_add=True)

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    def set_password(self, raw_password):
        salt, hashed = hash_password(raw_password)
        self.salt = salt
        self.password_hash = hashed

    def check_password(self, raw_password):
        return verify_password(self.salt, self.password_hash, raw_password)

    def delete(self, *args, **kwargs):
        force_real_delete = kwargs.pop('force_real_delete', False)
        if force_real_delete:
            super().delete(*args, **kwargs)
        else:
            self.is_active = False
            self.email = f"deleted_{self.id}_{self.email}"
            self.username = f"deleted_{self.id}_{self.username or ''}"
            self.save()
            EmailConfirmation.objects.filter(user=self).delete()

    class Meta:
        verbose_name = 'Пользователь'
        verbose_name_plural = 'Пользователи'

class EmailConfirmation(models.Model):
    user = models.ForeignKey('CustomUser', on_delete=models.CASCADE)
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