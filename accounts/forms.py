from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from .models import CustomUser  # Импортируем напрямую

class RegistrationForm(UserCreationForm):
    email = forms.EmailField(required=True)

    class Meta:
        model = CustomUser  # Используем CustomUser вместо get_user_model()
        fields = ["username", "email", "first_name", "last_name", "password1", "password2"]

    def clean_email(self):
        email = self.cleaned_data['email']
        if CustomUser.objects.filter(email=email, is_active=True).exists():
            raise forms.ValidationError("Этот email уже зарегистрирован")
        return email

class LoginForm(AuthenticationForm):
    username = forms.CharField()
