import os
import django
from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack
from django.urls import path

# Установка переменной окружения ПЕРВОЙ строкой
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'messenger.settings')

# Инициализация Django ДО импорта любых моделей
django.setup()

# Получаем стандартное Django приложение
django_application = get_asgi_application()

# Импорт consumers только ПОСЛЕ django.setup()
from chat.consumers import ChatConsumer

# WebSocket routing
websocket_application = AuthMiddlewareStack(
    URLRouter([
        path("ws/chat/<int:chat_id>/", ChatConsumer.as_asgi()),
    ])
)

application = ProtocolTypeRouter({
    "http": django_application,
    "websocket": websocket_application,
})