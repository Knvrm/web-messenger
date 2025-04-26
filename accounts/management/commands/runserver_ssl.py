import os
import ssl
from django.core.management.commands.runserver import Command as RunserverCommand
from django.core.servers.basehttp import WSGIServer
from wsgiref.simple_server import make_server

class Command(RunserverCommand):
    help = "Runs a development server with HTTPS."

    def add_arguments(self, parser):
        super().add_arguments(parser)
        parser.add_argument(
            '--certificate', default='certs/cert.pem',
            help='Path to the SSL certificate file.'
        )
        parser.add_argument(
            '--key', default='certs/key.pem',
            help='Path to the SSL key file.'
        )

    def handle(self, *args, **options):
        self.certificate = options['certificate']
        self.key = options['key']
        super().handle(*args, **options)

    def get_handler(self, *args, **options):
        handler = super().get_handler(*args, **options)
        return handler

    def inner_run(self, *args, **options):
        from django.conf import settings
        from django.utils import autoreload

        # Извлечение addr и port из addrport
        addrport = options.get('addrport', '127.0.0.1:8000')
        addr, port = addrport.split(':') if ':' in addrport else (addrport, '8000')
        port = int(port)

        quit_command = 'CTRL-BREAK' if os.name == 'nt' else 'CONTROL-C'

        self.stdout.write(
            f"Starting development server at https://{addr}:{port}/"
        )
        self.stdout.write(f"Quit the server with {quit_command}.")

        # Создание SSL-контекста
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(certfile=self.certificate, keyfile=self.key)

        # Запуск сервера с SSL
        server = make_server(addr, port, self.get_handler(*args, **options), WSGIServer)
        server.socket = ssl_context.wrap_socket(server.socket, server_side=True)

        # Поддержка autoreload
        if options['use_reloader']:
            autoreload.run_with_reloader(self.inner_run, **options)
        else:
            server.serve_forever()