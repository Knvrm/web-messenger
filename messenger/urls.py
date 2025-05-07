from django.contrib import admin
from django.urls import path, include
from django.views.generic import RedirectView
from .views import home, placeholder, logout_view
from django.conf import settings
from django.conf.urls.static import static
from django.contrib.staticfiles.storage import staticfiles_storage

urlpatterns = [
    path('admin/', admin.site.urls),
    path("", home, name="home"),
    path("placeholder/", placeholder, name="placeholder"),
    path("accounts/", include("accounts.urls")),
    path("logout/", logout_view, name="logout"),
    path('chat/', include('chat.urls')),
    path('favicon.ico', RedirectView.as_view(url=staticfiles_storage.url('img/favicon.ico'))),
]

urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
