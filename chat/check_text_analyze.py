from transformers import AutoTokenizer, AutoModelForSequenceClassification, pipeline
import torch
import re
from typing import Dict


class OptimizedPhishingDetector:
    def __init__(self):
        self.model_name = "cybersectony/phishing-email-detection-distilbert_v2.4.1"
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        self._load_model()
        self._setup_rules()

    def _load_model(self):
        """Загрузка модели с кешированием"""
        try:
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
            self.model = AutoModelForSequenceClassification.from_pretrained(self.model_name)
            self.classifier = pipeline(
                "text-classification",
                model=self.model,
                tokenizer=self.tokenizer,
                device=self.device
            )
            print(f"✅ Модель {self.model_name} готова (устройство: {self.device.upper()})")

            # Based on the model's documentation and your debug output:
            self.label_mapping = {
                'LABEL_0': 'phishing',
                'LABEL_1': 'phishing_url',
                'LABEL_2': 'legitimate',
                'LABEL_3': 'legitimate_url'
            }

        except Exception as e:
            print(f"❌ Ошибка загрузки: {e}")
            raise

    def _setup_rules(self):
        """Правила для постобработки"""
        self.phishing_triggers = [
            "заблокирован", "срочно", "verify", "account",
            "пароль", "карта", "click", "требует", "проверк"
        ]
        self.safe_phrases = [
            "добрый день", "прикрепляю", "документ",
            "коллега", "проект", "напоминание", "совещание"
        ]

    def analyze(self, text: str) -> Dict:
        """Улучшенный анализ с правилами"""
        try:
            # Предварительная обработка
            text_lower = text.lower()
            has_url = bool(re.search(r"https?://\S+", text_lower))

            # Классификация моделью (ограничение до 512 токенов)
            model_result = self.classifier(text[:512])[0]
            label = model_result["label"]
            confidence = model_result["score"]

            # Преобразуем техническую метку в смысловую
            mapped_label = self.label_mapping.get(label, 'unknown')

            print(f"Debug: Model returned '{label}' -> '{mapped_label}' with confidence {confidence:.2f}")

            # Основная логика классификации
            if mapped_label in ['phishing', 'phishing_url']:
                # Проверка на ложные срабатывания
                if any(phrase in text_lower for phrase in self.safe_phrases):
                    return self._safe_result(text, "Ложное срабатывание", confidence=0.3)
                return self._phishing_result(text, confidence, has_url)

            elif mapped_label in ['legitimate', 'legitimate_url']:
                # Проверка на пропущенные угрозы
                if any(trigger in text_lower for trigger in self.phishing_triggers):
                    return self._phishing_result(text, max(0.7, confidence), has_url)
                return self._safe_result(text, "Безопасное письмо")

            else:
                # Резервная логика для неизвестных меток
                if confidence > 0.7:
                    return self._phishing_result(text, confidence, has_url)
                return self._safe_result(text, "Неопределенный результат", 0.5)

        except Exception as e:
            return {
                "error": str(e),
                "is_phishing": False,
                "confidence": 0.0,
                "details": {
                    "reason": "Ошибка обработки",
                    "text_sample": text[:50] + "..." if len(text) > 50 else text
                }
            }

    def _phishing_result(self, text: str, confidence: float, has_url: bool) -> Dict:
        """Форматирование результата для фишинга"""
        return {
            "is_phishing": True,
            "confidence": round(confidence, 2),
            "details": {
                "reason": "URL + триггерные слова" if has_url else "Триггерные слова",
                "text_sample": text[:50] + "..." if len(text) > 50 else text
            }
        }

    def _safe_result(self, text: str, reason: str, confidence: float = 0.0) -> Dict:
        """Форматирование безопасного результата"""
        return {
            "is_phishing": False,
            "confidence": confidence,
            "details": {
                "reason": reason,
                "text_sample": text[:50] + "..." if len(text) > 50 else text
            }
        }


if __name__ == "__main__":
    detector = OptimizedPhishingDetector()

    test_emails = [
        "Ваш аккаунт заблокирован. Срочно перейдите по ссылке: http://amazon-security-update.com",
        "Добрый день! Прикрепляю документ по проекту",
        "URGENT! Your PayPal account requires verification: http://paypal-secure.com",
        "Напоминание: совещание завтра в 15:00",
        "Invoice #45892: http://fake-invoice.com/pay",
        "Проверьте, пожалуйста, этот отчет до конца недели"
    ]

    for email in test_emails:
        print("\n" + "=" * 50)
        print(f"Анализируем письмо: {email[:100]}...")
        result = detector.analyze(email)

        if "error" in result:
            print(f"❌ Ошибка: {result['error']}")
            continue

        verdict = "🚨 ФИШИНГ" if result["is_phishing"] else "✅ Безопасно"
        print(f"\nРезультат:")
        print(f"📧 {result['details']['text_sample']}")
        print(f"{verdict} | Уверенность: {result['confidence']:.0%}")
        print(f"Причина: {result['details']['reason']}")