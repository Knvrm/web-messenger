import os
import django

# Указываем путь к settings.py вашего проекта
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'messenger.settings')
django.setup()

from django.core.mail import send_mail

def send_test_email():
    send_mail(
        'Тестовое письмо из Django',
        'Это тестовое сообщение.',
        'messengerservice@yandex.ru',
        ['messengerservice@yandex.ru'],
        fail_silently=False,
    )
    print("SUCCESS")

    return

send_test_email()