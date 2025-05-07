import requests
from urllib.parse import urlparse
from django.conf import settings
from django.core.exceptions import ValidationError

VIRUSTOTAL_URL_API = "https://www.virustotal.com/api/v3/urls"
URLHAUS_API_URL = "https://urlhaus-api.abuse.ch/v1/url/"

def validate_url(url: str) -> None:
    print('checking: ', url)
    # 1. Проверка формата URL
    if not is_valid_url_format(url):
        raise ValidationError("Некорректный URL", code="invalid_url")

    # 2. Проверка через URLhaus (бесплатный)
    if is_malicious_urlhaus(url):
        raise ValidationError("Ссылка в базе URLhaus как вредоносная", code="malicious_url")

    # 3. Проверка через VirusTotal
    if settings.VIRUSTOTAL_API_KEY and is_malicious_virustotal(url):
        raise ValidationError("Ссылка помечена как опасная (VirusTotal)", code="malicious_url")

    # 4. Эвристический анализ
    if is_suspicious_url(url):
        raise ValidationError("Подозрительная ссылка", code="suspicious_url")

def is_valid_url_format(url: str) -> bool:
    """Проверяет валидность формата URL"""
    try:
        result = urlparse(url)
        return all([result.scheme in ('http', 'https'), result.netloc])
    except:
        return False

def extract_domain(url: str) -> str:
    """Извлекает домен из URL"""
    return urlparse(url).netloc.lower()

def is_malicious_virustotal(url: str) -> bool:
    """Проверка через VirusTotal API"""
    headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}
    try:
        # 1. Отправляем URL для анализа
        response = requests.post(
            VIRUSTOTAL_URL_API,
            headers=headers,
            data={"url": url},
            timeout=5
        )
        scan_id = response.json().get('data', {}).get('id')

        # 2. Получаем результаты
        report_url = f"{VIRUSTOTAL_URL_API}/{scan_id}"
        report = requests.get(report_url, headers=headers, timeout=5).json()

        stats = report.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        return stats.get('malicious', 0) > 0 or stats.get('phishing', 0) > 0

    except Exception as e:
        print(f"VirusTotal error: {e}")
        return False

def is_malicious_urlhaus(url: str) -> bool:
    """Проверка через URLhaus API"""
    try:
        response = requests.post(
            URLHAUS_API_URL,
            data={"url": url},
            timeout=5
        )
        return response.json().get('query_status') == 'ok'
    except:
        return False

def is_suspicious_url(url: str) -> bool:
    """Эвристический анализ URL"""
    domain = extract_domain(url)

    # 1. Проверка подозрительных ключевых слов
    phishing_keywords = ['login', 'verify', 'account', 'bank', 'paypal']
    if any(kw in domain for kw in phishing_keywords):
        return True

    # 2. Проверка IDN-доменов (кириллица в URL)
    if 'xn--' in domain.lower():  # Punycode
        return True

    # 3. Проверка коротких URL (bit.ly и т.д.)
    shorteners = ['bit.ly', 'goo.gl', 't.co']
    if any(short in domain for short in shorteners):
        return True

    return False