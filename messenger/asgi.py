import os
import django
from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack
from django.urls import path

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'messenger.settings')

django.setup()
django_application = get_asgi_application()

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