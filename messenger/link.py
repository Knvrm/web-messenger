import requests
from .email_model import Email #импорт модели Email, которая содержит информацию о письме

class LinkCheck:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {"x-apikey": self.api_key}
        self.url_base = "https://www.virustotal.com/api/v3/"

    def analyze_url(self, website: str) -> str:
        url = f"{self.url_base}urls"
        try:
            response = requests.post(url, headers=self.headers, data={"url": website})

            if response.status_code == 200:
                result = response.json()
                analysis_id = result.get("data", {}).get("id", "Не найден")
                return analysis_id
            else:
                print(f"Ошибка при отправке URL: {response.status_code} - {response.text}")
        except Exception as e:
            print(f"Ошибка: {e}")
        return None

    def check_analysis_status(self, analysis_id: str) -> str:
        url = f"{self.url_base}analyses/{analysis_id}"
        try:
            response = requests.get(url, headers=self.headers)

            if response.status_code == 200:
                result = response.json()
                status_report = []

                # Получаем результаты анализа
                for engine, report in result.get("data", {}).get("attributes", {}).get("results", {}).items():
                    status_report.append(f"{engine} | Статус: {report.get('result', 'Неизвестно')}")

                return "\n".join(status_report)

            else:
                print(f"Ошибка при проверке статуса: {response.status_code} - {response.text}")
        except Exception as e:
            print(f"Ошибка: {e}")
        return "Не удалось получить результаты"

    def checkLink(self, email: Email): #получаем ссылку из объекта email
        link = email.link #извлекаем ссылку
        results = []
        if link: #если в письме есть ссылка
            analysis_id = self.analyze_url(link)

            if analysis_id:
                status = self.check_analysis_status(analysis_id)
                results.append(f":\n{status}\n") #добавляем полученный статус
            else:
                results.append(f"Ошибка при отправке на анализ\n") #ошибка
        else: #ссылка не найдена
            results.append("Ссылка не найдена в письме\n")                                                #

        if any("статус: phishing" in result.lower() for result in results): # Если хотя бы в одном результате встречается "phishing"
            email.classification.set_result_link_check("Фишинговая") # Устанавливаем классификацию как "Фишинговая"
        elif any("статус: suspicious" in result.lower() for result in results): # Если хотя бы в одном результате встречается "suspicious"
            email.classification.set_result_link_check("Подозрительная")  # Устанавливаем классификацию как "Подозрительная"
        elif results is not None:  # Если результаты есть, но не найдено фишинга или подозрительности
            email.classification.set_result_link_check("Безопасная") # Устанавливаем классификацию как "Безопасная"
        else:  # Если результаты вообще не были получены
            email.classification.set_result_link_check(None) #классификация неопределенна