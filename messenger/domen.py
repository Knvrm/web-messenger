import whois
import requests
from datetime import datetime
from .email_model import Email

class DomainCheck:
    def __init__(self, api_key): # конструктор, который инициализирует объект с ключом API
        self.api_key = api_key #
        self.virustotal_url = "https://www.virustotal.com/api/v3/domains/"

    def checkDomain(self, email: Email): #метод, для проверки домена
        domain = email.sender_domain #извлекаем домен из объекта email
        # Проверка через WHOIS
        whois_info = self.check_whois(domain)
        if whois_info:
            # Проверка на необычные или подозрительные данные WHOIS
            if 'creation_date' in whois_info and whois_info['creation_date']:
                creation_date = whois_info['creation_date']
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                # Если домен был зарегистрирован недавно, это может быть подозрительно
                if (domain_age := (datetime.now() - creation_date).days) < 30:
                    email.classification.set_result_domain_check(result="Недавно зарегистрирован") # Если домен новый, помечаем как подозрительный
                    return # Прекращаем дальнейшие проверки

        # Проверка через VirusTotal API
        if self.check_virustotal(domain):
            email.classification.set_result_domain_check(result="Фишинговый") # Классифицируем домен как фишинговый
            return  # Прекращаем дальнейшие проверки

        email.classification.set_result_domain_check(result="Безопасный") # Классифицируем домен как безопасный

    def check_whois(self, domain: str):
        try:
            # Получаем информацию WHOIS для домена
            whois_info = whois.whois(domain)
            return whois_info
        except Exception as e:
            print(f"Ошибка при получении WHOIS данных: {e}")
            return None

    def check_virustotal(self, domain: str) -> bool:
        headers = {
            "x-apikey": self.api_key # Устанавливаем заголовок с API ключом для авторизации
        }
        try:
            # Отправка запроса к VirusTotal API
            response = requests.get(self.virustotal_url + domain, headers=headers)
            if response.status_code == 200:
                data = response.json()
                # Проверим, есть ли данные о фишинговых ссылках
                if 'data' in data and 'attributes' in data['data']:
                    attributes = data['data']['attributes']
                    if 'last_analysis_stats' in attributes:
                        stats = attributes['last_analysis_stats']
                        # Проверяем, есть ли отметка о фишинговых репортах
                        if stats.get('phishing', 0) > 0:
                            return True
            else:
                print(f"Ошибка при запросе в VirusTotal: {response.status_code}")
        except Exception as e:
            print(f"Ошибка при подключении к VirusTotal API: {e}")
        return False