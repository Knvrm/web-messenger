import os
from daphne.server import Server
from channels.routing import get_default_application

# Настройки
host = "mymessenger.local"
port = 8444
cert_path = os.path.join("certs", "cert.pem").replace(os.sep, "/")
key_path = os.path.join("certs", "key.pem").replace(os.sep, "/")

# Загрузка ASGI-приложения
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "messenger.settings")
application = get_default_application()

# Экранирование путей для Windows
cert_path_escaped = cert_path.replace(":", "\\:")
key_path_escaped = key_path.replace(":", "\\:")

# Настройка SSL через endpoint
endpoints = [f"ssl:{port}:interface={host}:privateKey={key_path_escaped}:certKey={cert_path_escaped}"]

# Запуск Daphne
server = Server(
    application=application,
    endpoints=endpoints,
)
server.run()