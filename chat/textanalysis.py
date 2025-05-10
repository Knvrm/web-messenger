import os
import torch
from functools import lru_cache
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from django.conf import settings
from django.core.exceptions import ValidationError
import re

# Конфигурация модели
MODEL_NAME = "cybersectony/phishing-email-detection-distilbert_v2.4.1"
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"

class PhishingDetector:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialize()
        return cls._instance

    def _initialize(self):
        """Инициализация модели с обработкой ошибок"""
        try:
            self.tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
            self.model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME)
            self.model.eval()
            self.model.to(DEVICE)

            # Обновленные параметры на основе тестов
            self.phishing_keywords = [
                "заблокирован", "срочно", "verify", "account", "password",
                "карта", "click here", "требует", "подтвердите", "urgent",
                "invoice", "payment", "требуется", "обновить", "security"
            ]
            self.safe_keywords = [
                "добрый день", "прикрепляю", "документ", "отчет",
                "коллега", "проект", "уведомление", "встреча",
                "совещание", "документ", "проверьте", "отчет"
            ]

            print(f"✅ Модель {MODEL_NAME} загружена на {DEVICE.upper()}")
        except Exception as e:
            print(f"❌ Ошибка загрузки модели: {e}")
            raise

    @lru_cache(maxsize=1000)
    def analyze_text(self, text: str) -> dict:
        """
        Улучшенный анализ текста на фишинг с кешированием результатов
        Возвращает:
        {
            "is_phishing": bool,
            "reason": str,
            "confidence": float,
            "details": dict
        }
        """
        try:
            # Предварительная обработка текста (сохраняем оригинал для URL проверки)
            clean_text = self._preprocess_text(text)
            original_text = text.lower()

            # Анализ моделью
            inputs = self.tokenizer(
                clean_text,
                return_tensors="pt",
                truncation=True,
                max_length=512,
                padding=True
            ).to(DEVICE)

            with torch.no_grad():
                outputs = self.model(**inputs)
                probs = torch.nn.functional.softmax(outputs.logits, dim=-1)[0]

            # Интерпретация результатов на основе тестов
            class_mapping = {
                0: "phishing",
                1: "phishing_url",
                2: "legitimate",
                3: "legitimate_url"
            }

            pred_class = torch.argmax(probs).item()
            max_prob = float(probs[pred_class])
            label = class_mapping[pred_class]

            # Дополнительные проверки
            has_url = bool(re.search(r"https?://\S+|www\.\S+", original_text))
            has_phishing_kw = any(kw in clean_text for kw in self.phishing_keywords)
            has_safe_kw = any(kw in clean_text for kw in self.safe_keywords)

            # Логика принятия решения
            is_phishing = "phishing" in label
            confidence = max_prob
            reason = label

            # Корректировки на основе дополнительных признаков
            if is_phishing:
                if has_safe_kw and not has_url:
                    # Ложное срабатывание на деловую переписку
                    is_phishing = False
                    confidence = max(0.1, confidence - 0.3)
                    reason = "safe_keyword_override"
                elif has_url and has_phishing_kw:
                    # Явный фишинг
                    confidence = min(1.0, confidence + 0.15)
            else:
                if has_url and has_phishing_kw:
                    # Пропущенная угроза
                    is_phishing = True
                    confidence = max(confidence, 0.85)
                    reason = "url_with_phishing_keywords"

            # Формирование результата
            return {
                "is_phishing": is_phishing,
                "reason": reason,
                "confidence": round(confidence, 4),
                "details": {
                    "text_sample": clean_text[:100] + "..." if len(clean_text) > 100 else clean_text,
                    "has_url": has_url,
                    "has_phishing_keywords": has_phishing_kw,
                    "has_safe_keywords": has_safe_kw,
                    "model_label": label,
                    "model_confidence": max_prob
                }
            }

        except Exception as e:
            return {
                "error": str(e),
                "is_phishing": False,
                "confidence": 0.0,
                "details": {
                    "error": True,
                    "message": "Ошибка при анализе текста"
                }
            }

    def _preprocess_text(self, text: str) -> str:
        """Очистка текста перед анализом"""
        text = text.lower().strip()
        # Сохраняем основные символы для URL и ключевых слов
        text = re.sub(r"[^\w\s@./-]", "", text)
        return text


def validate_message_content(text: str) -> None:
    """
    Улучшенная валидация текста для Django-форм
    """
    if not getattr(settings, "ENABLE_PHISHING_CHECK", True):
        return

    detector = PhishingDetector()
    result = detector.analyze_text(text)

    if result.get("error"):
        raise ValidationError(
            "Не удалось проверить сообщение на безопасность. Пожалуйста, проверьте его вручную.",
            code="phishing_check_error"
        )

    if result["is_phishing"] and result["confidence"] > 0.7:
        details = (
            f"Причина: {result['reason']}\n"
            f"Уверенность: {result['confidence']:.1%}\n"
            f"Обнаружены: {'URL + ' if result['details']['has_url'] else ''}"
            f"{'ключевые слова фишинга' if result['details']['has_phishing_keywords'] else ''}"
        )
        raise ValidationError(
            f"Обнаружено потенциально опасное сообщение!\n{details}",
            code="phishing_content"
        )