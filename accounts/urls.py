from django.urls import path
from .views import register_view, login_view, logout_view, resend_confirmation_code, verify_auth_code

urlpatterns = [
    path("register/", register_view, name="register"),
    path("login/", login_view, name="login"),
    path("logout/", logout_view, name="logout"),
    path('resend-confirmation-code/', resend_confirmation_code, name='resend_confirmation_code'),
    path('verify-auth-code/', verify_auth_code, name='verify_auth_code'),
]
