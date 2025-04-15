import os #взаимодействие с ос
import torch #нейросеть
from transformers import AutoTokenizer, AutoModelForSequenceClassification #автотоке
from .email_model import Email # Импортируем класс Email для работы с письмами

class TextAnalysis:#класс
    def __init__(self):
        # загружаем модель и токенизатор для классификации фишинговых  писем
        current_dir = os.path.dirname(os.path.abspath(__file__))   #d

        # загрузка токенизатора и модели для детектирования  фишинговых писем
        self.tokenizer = AutoTokenizer.from_pretrained("cybersectony/phishing-email-detection-distilbert_v2.1") #token
        self.model = AutoModelForSequenceClassification.from_pretrained(  #model
            "cybersectony/phishing-email-detection-distilbert_v2.1") #модель

    def analyzeText(self, email: 'Email') -> bool:# Метод для анализа текста письма с использованием модели машинного обучения.
        #Возвращает True, если письмо фишинговое, иначе False.
        # Извлекаем текст из  email
        text = email.text #текст
        # преобразуем текст письма в формат,  который принимает  модель
        inputs = self.tokenizer( #токен
            text,  #текст
            return_tensors="pt",  # формат для  PyTorch
            truncation=True,  # обрезка текста, если он слишком  длинный
            max_length=512  # максимальная длина  текста
        )
        # получаем предсказание  модели
        with torch.no_grad(): # отключаем вычисление градиентов, так как это только предсказание
            outputs = self.model(**inputs) # Передаем данные в модель
            predictions = torch.nn.functional.softmax(outputs.logits, dim=-1) # Применяем softmax для вероятностей
        # получаем вероятности  для каждого класса
        probs = predictions[0].tolist() #используется для преобразования тензора (или многомерного массива) в список

        labels = { # создаем  словарь с результатами
            "legitimate_email": probs[0], #класс
            "phishing_url": probs[1], #класс
            "legitimate_url": probs[2], #класс
            "phishing_url_alt": probs[3] #класс
        } #закончили
        max_label = max(labels.items(), key=lambda x: x[1]) # находим класс с максимальной вероятностью.
        if max_label[0] == "phishing_url": #проверка
            #print(text)
            #  print('фишинговый текст')
            email.classification.set_result_text_analyze('Фишинговый') #Проверяем, если класс с наибольшей вероятностью — это phishing_url, то считаем письмо фишинговым и присваиваем результат через метод set_result_text_analyze объекта classification у email.
        else: #иначе
            #print(text)
            #  print('безопасный текст')
            email.classification.set_result_text_analyze('Без признаков фишинга') #Возвращаем результат анализа, где True означает, что письмо фишинговое (max_label[0] == "phishing_url"), а False — что письмо безопасное.
        return max_label[0] == "phishing_url" #Возвращаем результат анализа
