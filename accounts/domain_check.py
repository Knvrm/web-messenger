import requests
from django.conf import settings
from django.core.exceptions import ValidationError
import socket
import ssl
import re

VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3/domains/"

TRUSTED_EMAIL_DOMAINS = {
    'gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com',
    'yahoo.com', 'protonmail.com', 'icloud.com', 'aol.com',

    'yandex.ru', 'ya.ru', 'mail.ru', 'inbox.ru', 'list.ru', 'bk.ru',
    'rambler.ru', 'lenta.ru', 'autorambler.ru', 'myrambler.ru',

    'zoho.com', 'fastmail.com', 'tutanota.com', 'mailbox.org'
}

suspicious_keywords = [
    # Международные финансовые/торговые
    'paypal', 'payeer', 'wise', 'westernunion',
    'moneygram', 'coinbase', 'binance', 'crypto',
    'amazon', 'ebay', 'aliexpress', 'alibaba', 'apple',
    'microsoft', 'google', 'meta', 'facebook',

    # Банковские термины
    'bank', 'банк', 'alfabank', 'sberbank', 'tinkoff',
    'raiffeisen', 'vtb', 'gazprombank', 'credit',
    'кредит', 'card', 'карта', 'account', 'аккаунт',
    'payment', 'платеж', 'transfer', 'перевод',

    # Безопасность и доступ
    'security', 'безопасность', 'login', 'log-in',
    'signin', 'войти', 'authorize', 'аутентификация',
    'verify', 'подтверждение', 'confirm', 'подтвердить',
    'validation', 'проверка', 'access', 'доступ',
    'password', 'пароль', 'recovery', 'восстановление',

    # Государственные/официальные
    'government', 'правительство', 'tax', 'налог',
    'fns', 'фнс', 'pfr', 'пфр', 'gosuslugi',
    'госуслуги', 'police', 'полиция', 'mvd', 'мвд',

    # Почтовые и сервисы
    'mail', 'почта', 'gmail', 'yandex', 'rambler',
    'outlook', 'hotmail', 'protonmail', 'icloud',

    # Технические
    'support', 'поддержка', 'service', 'сервис',
    'update', 'обновление', 'system', 'система',
    'tech', 'техподдержка', 'admin', 'администратор',

    # Социальные сети
    'facebook', 'instagram', 'twitter', 'vk',
    'vkontakte', 'telegram', 'whatsapp', 'viber',

    # Мошеннические паттерны
    'free', 'бесплатно', 'bonus', 'бонус', 'win',
    'выигрыш', 'prize', 'приз', 'reward', 'награда',
    'urgent', 'срочно', 'limited', 'ограничено',

    # Другие подозрительные
    'official', 'официальный', 'partner', 'партнер',
    'client', 'клиент', 'personal', 'персональный',
    'important', 'важно', 'attention', 'внимание'
]

suspicious_patterns = [
    # Поддельные домены типа "apple-id.com"
    r'\b(?:[a-z]+-)+(?:id|auth|verify|login|account|support)\b',

    # Омофоны (визуально похожие на бренды)
    r'[аa][рp][рp][l1][еe]',  # apple
    r'[g9][оo][оo][g9][l1][еe]',  # google
    r'[уy][аa][n][d][еe][x]',  # yandex
    r'[m][аa][i1][l1]',  # mail
    r'[s][b][e][r]',  # sber
]

disposable_domains = [
    'mailinator.com', 'tempmail.com', '10minutemail.com',
    'guerrillamail.com', 'yopmail.com', 'trashmail.com'
]

def validate_domain(email: str) -> None:
    """
    Основная функция валидации домена email
    """
    domain = email.split('@')[-1]

    if domain in TRUSTED_EMAIL_DOMAINS:
        return

    # 1. Проверка DNS-записей
    if not has_valid_dns(domain):
        raise ValidationError("Некорректный домен", code="invalid_domain")

    # 2. Проверка подозрительных доменов
    if is_suspicious_domain(domain):
        raise ValidationError(
            "Регистрация с подозрительных доменов ограничена",
            code="suspicious_domain"
        )

    # 3. Проверка через VirusTotal
    if settings.VIRUSTOTAL_API_KEY:  # Проверяем только если есть API ключ
        if is_phishing_domain_virustotal(domain):
            raise ValidationError(
                "Регистрация с этого домена запрещена по соображениям безопасности",
                code="phishing_domain"
            )

def has_valid_dns(domain: str) -> bool:
    try:
        socket.gethostbyname(domain)
        return True
    except (socket.gaierror, socket.timeout):
        return False


def is_phishing_domain_virustotal(domain: str) -> bool:
    headers = {
        "x-apikey": settings.VIRUSTOTAL_API_KEY,
        "Accept": "application/json"
    }

    try:
        response = requests.get(
            f"{VIRUSTOTAL_API_URL}{domain}",
            headers=headers,
            timeout=5
        )

        # Обработка ответа VirusTotal
        if response.status_code == 200:
            data = response.json()
            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            return stats.get('malicious', 0) > 2 or stats.get('phishing', 0) > 0

        print(f"VirusTotal API error: HTTP {response.status_code}")
        return False

    except requests.exceptions.RequestException as e:
        print(f"VirusTotal connection error: {e}")
        return False


def is_suspicious_domain(domain: str) -> bool:
    # 1. Проверка на disposable-домены
    if domain in disposable_domains:
        return True

    # 2. Проверка подозрительных паттернов
    domain_lower = domain.lower()

    # Проверка по ключевым словам
    if any(keyword in domain_lower for keyword in suspicious_keywords):
        return True

    # Проверка по регулярным выражениям
    if any(re.search(pattern, domain_lower) for pattern in suspicious_patterns):
        return True

    return False


def check_ssl_certificate(domain: str) -> bool:
    """
    Проверка SSL сертификата (дополнительная проверка)
    """
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return bool(cert)
    except (ssl.SSLError, socket.timeout, ConnectionError):
        return False