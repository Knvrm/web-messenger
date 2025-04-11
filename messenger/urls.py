from django.contrib import admin
from django.urls import path, include
from .views import home, placeholder, logout_view

urlpatterns = [
    path('admin/', admin.site.urls),
    path("", home, name="home"),
    path("placeholder/", placeholder, name="placeholder"),
    path("accounts/", include("accounts.urls")),
    path("logout/", logout_view, name="logout"),  # Выход
    path('chat/', include('chat.urls')),
]
