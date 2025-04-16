from transformers import AutoTokenizer, AutoModelForSequenceClassification, pipeline
import torch
from typing import Dict


class PhishingDetectorBERT:
    def __init__(self):
        self.model_name = "ealvaradob/bert-finetuned-phishing"
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        self._load_model()
        self._setup_keywords()

    def _load_model(self):
        """Загрузка модели с обработкой ошибок"""
        try:
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
            self.model = AutoModelForSequenceClassification.from_pretrained(self.model_name)
            self.classifier = pipeline(
                "text-classification",
                model=self.model,
                tokenizer=self.tokenizer,
                device=self.device
            )
            print(f"✅ Модель {self.model_name} загружена на {self.device.upper()}")
        except Exception as e:
            print(f"❌ Ошибка загрузки модели: {e}")
            raise

    def _setup_keywords(self):
        """Ключевые слова для дополнительной проверки"""
        self.phishing_keywords = [
            "заблокирован", "срочно", "verify", "account",
            "подтвердите", "карта", "password", "логин",
            "требует", "действи", "проверк", "click",
            "link", "счёт", "банк", "security"
        ]

    def analyze(self, text: str) -> Dict:
        """Улучшенный анализ с дополнительными проверками"""
        try:
            # Базовый анализ моделью
            result = self.classifier(text[:1024])[0]  # Обрезаем длинные тексты

            # Дополнительные признаки
            text_lower = text.lower()
            has_url = "http://" in text_lower or "https://" in text_lower
            has_keywords = any(kw in text_lower for kw in self.phishing_keywords)

            # Корректировка результата
            is_phishing = result['label'] == 'phishing'
            confidence = result['score']

            if has_url and has_keywords:
                confidence = max(confidence, 0.85)  # Повышаем уверенность
            elif not has_url and is_phishing:
                confidence = min(confidence, 0.4)  # Понижаем уверенность

            return {
                "is_phishing": is_phishing,
                "confidence": round(confidence, 4),
                "features": {
                    "has_url": has_url,
                    "has_keywords": has_keywords,
                    "text_sample": text[:50] + "..." if len(text) > 50 else text
                }
            }

        except Exception as e:
            return {
                "error": str(e),
                "is_phishing": False,
                "confidence": 0.0
            }


# Тестирование
if __name__ == "__main__":
    try:
        detector = PhishingDetectorBERT()

        test_cases = [
            "Ваш аккаунт Amazon был заблокирован. Перейдите по ссылке: http://amazon-security-update.com",
            "Добрый день! Прикрепляю документ по проекту, проверьте пожалуйста",
            "URGENT! Your PayPal account requires verification. Click here: http://paypal-secure.com",
            "Системное уведомление: ваш пароль будет сброшен через 24 часа",
            "Invoice #45892: http://fake-invoice.com/pay"
        ]

        for text in test_cases:
            result = detector.analyze(text)
            print(f"\n📧 Текст: {result['features']['text_sample']}")
            print(f"🔍 Вердикт: {'🚨 ФИШИНГ' if result['is_phishing'] else '✅ Безопасно'}")
            print(f"🔢 Уверенность: {result['confidence']:.1%}")
            print(f"🌐 URL: {'есть' if result['features']['has_url'] else 'нет'}")
            print(f"🔑 Ключевые слова: {'есть' if result['features']['has_keywords'] else 'нет'}")

    except Exception as e:
        print(f"❌ Критическая ошибка: {e}")