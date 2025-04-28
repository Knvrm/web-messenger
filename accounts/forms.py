from django import forms
from django.core.exceptions import ValidationError
from .models import CustomUser
from .domain_check import validate_domain

class RegistrationForm(forms.ModelForm):
    password1 = forms.CharField(widget=forms.PasswordInput, label="Пароль", min_length=8)
    password2 = forms.CharField(widget=forms.PasswordInput, label="Подтверждение пароля")
    email = forms.EmailField(required=True, label="Email")

    class Meta:
        model = CustomUser
        fields = ["username", "email", "first_name", "last_name", "password1", "password2"]

    def clean_email(self):
        email = self.cleaned_data['email']
        if CustomUser.objects.filter(email=email, is_active=True).exists():
            raise forms.ValidationError("Этот email уже зарегистрирован")
        try:
            validate_domain(email)
        except ValidationError as e:
            raise forms.ValidationError(e.message)
        return email

    def clean(self):
        cleaned_data = super().clean()
        password1 = cleaned_data.get('password1')
        password2 = cleaned_data.get('password2')
        if password1 and password2 and password1 != password2:
            raise forms.ValidationError("Пароли не совпадают")
        return cleaned_data

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data['password1'])
        user.generate_rsa_keys(self.cleaned_data['password1'])  # Генерация RSA-ключей
        if commit:
            user.save()
        return user

class LoginForm(forms.Form):
    email = forms.EmailField(label='Email')
    password = forms.CharField(widget=forms.PasswordInput, label='Пароль')
    confirmation_code = forms.CharField(max_length=6, required=False, label='Код подтверждения')

    def clean(self):
        cleaned_data = super().clean()
        email = cleaned_data.get('email')
        password = cleaned_data.get('password')
        if email and password:
            user = CustomUser.objects.filter(email=email).first()
            if user is None:
                raise forms.ValidationError('Пользователь с таким email не найден.')
            if not user.is_active:
                raise forms.ValidationError('Учётная запись не активирована.')
            if not user.check_password(password):
                raise forms.ValidationError('Неверный пароль.')
            self.user = user
        return cleaned_data

    def get_user(self):
        return getattr(self, 'user', None)