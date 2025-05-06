import os
import django
from django.core.exceptions import ValidationError

# Настройка окружения Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'messenger.settings')
django.setup()

from chat.link import validate_url

def check_safe_url():
    print("https://google.com ")
    try:
        validate_url("https://google.com")
        print("✓ Безопасный URL распознан правильно")
    except ValidationError:
        print("ОШИБКА: Безопасный URL вызвал ошибку")

def check_phishing_url():
    print("http://appleid-verify.com ")
    try:
        validate_url("http://appleid-verify.com")
        print("ОШИБКА: Фишинговый URL не был обнаружен")
    except ValidationError as e:
        print(f"✓ Фишинг обнаружен: {e}")

def check_danger_url():
    print("http://72.135.17.58:37956/bin.sh ")
    try:
        validate_url("http://72.135.17.58:37956/bin.sh")
        print("ОШИБКА: Фишинговый URL не был обнаружен")
    except ValidationError as e:
        print(f"✓ Фишинг обнаружен: {e}")

if __name__ == "__main__":
    check_safe_url()
    check_phishing_url()
    check_danger_url()