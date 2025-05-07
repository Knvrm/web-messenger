from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
import random
import string
from django.utils import timezone
from .pbkdf2_hmac import hash_password, verify_password, generate_salt
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('Поле Email обязательно')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        if password:
            user.set_password(password)
            user.generate_rsa_keys(password)
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
    password_hash = models.CharField(max_length=256)
    salt = models.BinaryField(max_length=16)
    date_joined = models.DateTimeField(auto_now_add=True)
    public_key = models.TextField(blank=True, null=True)
    private_key = models.TextField(blank=True, null=True)
    key_salt = models.BinaryField(max_length=16, blank=True, null=True)
    suspicious_links_count = models.IntegerField(default=0)  # Счётчик подозрительных ссылок
    last_suspicious_link_at = models.DateTimeField(null=True, blank=True)  # Время последнего нарушения
    link_restriction_until = models.DateTimeField(null=True, blank=True)  # Ограничение на отправку ссылок

    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    def set_password(self, raw_password):
        salt, hashed = hash_password(raw_password)
        print(f"Setting password: hash={hashed[:10]}..., salt={salt.hex()[:10]}...")
        self.salt = salt
        self.password_hash = hashed

    def check_password(self, raw_password):
        salt = bytes(self.salt) if isinstance(self.salt, memoryview) else self.salt
        result = verify_password(salt, self.password_hash, raw_password)
        print(f"Checking password for {self.email}: {result}")
        return result

    def generate_rsa_keys(self, password: str):
        print("Generating RSA keys...")
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')

        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = kdf.derive(password.encode())

        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(private_pem.encode()) + encryptor.finalize()
        encrypted_private_key = base64.b64encode(iv + ciphertext + encryptor.tag).decode('utf-8')

        self.public_key = public_pem
        self.private_key = encrypted_private_key
        self.key_salt = salt
        print(f"Encrypted private_key length: {len(encrypted_private_key)}")

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)

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