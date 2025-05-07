import requests
import re
from urllib.parse import urlparse
from django.conf import settings

VIRUSTOTAL_URL_API = "https://www.virustotal.com/api/v3/urls"
URLHAUS_API_URL = "https://urlhaus-api.abuse.ch/v1/url/"

# Белый список доверенных доменов
WHITELISTED_DOMAINS = [
    'google.com',
    'youtube.com',
    'facebook.com',
    'twitter.com',
    'instagram.com',
    'linkedin.com',
    'wikipedia.org',
    'github.com',
    'stackoverflow.com',
    'reddit.com',
    'amazon.com',
    'ebay.com',
    'etsy.com',
    'bing.com',
    'yahoo.com',
    'bbc.com',
    'cnn.com',
    'reuters.com',
    'nytimes.com',
    'dropbox.com',
    'drive.google.com',
    'onedrive.live.com',
    'coursera.org',
    'edx.org',
    'khanacademy.org',
    'vimeo.com',
    'medium.com',
    'quora.com',
    'spotify.com',
    'codepen.io',
    'gitlab.com',
]

def validate_url(url: str) -> dict:
    """
    Проверяет URL и возвращает уровень угрозы: 'safe', 'suspicious', 'malicious'.
    """
    #print('Checking URL:', url)

    # 1. Проверка белого списка
    domain = extract_domain(url)
    if domain in WHITELISTED_DOMAINS or any(domain.endswith('.' + allowed) for allowed in WHITELISTED_DOMAINS):
        return {"status": "safe", "reason": "URL в белом списке"}

    # 2. Проверка формата URL
    if not is_valid_url_format(url):
        return {"status": "malicious", "reason": "Некорректный формат URL"}

    # 3. Проверка через URLhaus
    if is_malicious_urlhaus(url):
        return {"status": "malicious", "reason": "Ссылка в базе URLhaus как вредоносная"}

    # 4. Эвристический анализ
    suspicious_reason = is_suspicious_url(url)
    if suspicious_reason:
        return {"status": "suspicious", "reason": suspicious_reason}

    # 5. Проверка на исполняемые файлы
    malicious_files = [r'\.sh$', r'\.exe$', r'\.bat$', r'\.cmd$', r'\.bin$']
    for pattern in malicious_files:
        if re.search(pattern, url, re.IGNORECASE):
            return {"status": "malicious", "reason": "URL указывает на потенциально вредоносный файл"}

    # 6. Проверка IP-адресов
    ip_pattern = re.compile(r'^(https?:\/\/)?(\d{1,3}\.){3}\d{1,3}(:\d+)?(/.*)?$')
    if ip_pattern.match(url):
        return {"status": "suspicious", "reason": "URL использует IP-адрес"}

    # 7. Проверка нестандартных портов
    port_pattern = re.compile(r'https?:\/\/[^/]+:(\d+)/')
    match = port_pattern.search(url)
    if match and match.group(1) not in ['80', '443']:
        return {"status": "suspicious", "reason": f"URL использует нестандартный порт: {match.group(1)}"}

    # 8. Проверка через VirusTotal
    if settings.VIRUSTOTAL_API_KEY and is_malicious_virustotal(url):
        return {"status": "malicious", "reason": "Ссылка помечена как опасная (VirusTotal)"}

    return {"status": "safe", "reason": "URL безопасен"}

def is_valid_url_format(url: str) -> bool:
    """Проверяет валидность формата URL."""
    try:
        result = urlparse(url)
        return all([result.scheme in ('http', 'https'), result.netloc])
    except:
        return False

def extract_domain(url: str) -> str:
    """Извлекает домен из URL."""
    return urlparse(url).netloc.lower()

def is_malicious_virustotal(url: str) -> bool:
    """Проверка через VirusTotal API."""
    headers = {"x-apikey": settings.VIRUSTOTAL_API_KEY}
    try:
        response = requests.post(
            VIRUSTOTAL_URL_API,
            headers=headers,
            data={"url": url},
            timeout=5
        )
        scan_id = response.json().get('data', {}).get('id')
        report_url = f"{VIRUSTOTAL_URL_API}/{scan_id}"
        report = requests.get(report_url, headers=headers, timeout=5).json()
        stats = report.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        return stats.get('malicious', 0) > 0 or stats.get('phishing', 0) > 0
    except Exception as e:
        print(f"VirusTotal error: {e}")
        return False

def is_malicious_urlhaus(url: str) -> bool:
    """Проверка через URLhaus API."""
    try:
        response = requests.post(
            URLHAUS_API_URL,
            data={"url": url},
            timeout=5
        )
        return response.json().get('query_status') == 'ok'
    except:
        return False

def is_suspicious_url(url: str) -> str:
    """Эвристический анализ URL, возвращает причину подозрительности или пустую строку."""
    domain = extract_domain(url)

    # 1. Подозрительные ключевые слова
    phishing_keywords = ['login', 'verify', 'account', 'bank', 'paypal']
    if any(kw in domain for kw in phishing_keywords):
        return "URL содержит подозрительные ключевые слова"

    # 2. IDN-домены (кириллица в URL)
    if 'xn--' in domain.lower():
        return "URL использует Punycode (возможный IDN-домен)"

    # 3. Короткие URL
    shorteners = ['bit.ly', 'goo.gl', 't.co']
    if any(short in domain for short in shorteners):
        return "URL является укороченной ссылкой"

    return ""