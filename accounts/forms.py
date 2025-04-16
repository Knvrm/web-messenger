from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.core.exceptions import ValidationError

from .models import CustomUser  # Импортируем напрямую
from .domain_check import validate_domain

class RegistrationForm(UserCreationForm):
    email = forms.EmailField(required=True)

    class Meta:
        model = CustomUser  # Используем CustomUser вместо get_user_model()
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

class LoginForm(AuthenticationForm):
    username = forms.CharField()
