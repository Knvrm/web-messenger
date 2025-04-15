class Classification: #Здесь создается класс Classification, который будет использоваться для классификации результатов проверки различных аспектов письма
    def __init__(self):
        self.resultLinkCheck = None #ссылка
        self.resultDomainCheck = None #домен
        self.resultTextAnalyze = None #текст анализ
        self.resultClassification = None #классификация
    def set_result_link_check(self, result: str): #функция
        self.resultLinkCheck = result #ссылка
    def set_result_domain_check(self, result: str):#функция
        self.resultDomainCheck = result #домен
    def set_result_text_analyze(self, result: bool):#функция
        self.resultTextAnalyze = result #текст
    def classify(self):#функция
        if self.resultDomainCheck == 'Фишинговый' or self.resultLinkCheck == "Фишинговая": #ссылка или  домен
            self.resultClassification = 'Опасное' #опасный
            return "Опасное" #возвращаем
        elif (self.resultDomainCheck == "Недавно зарегистрирован" #ничего страшного
              or self.resultTextAnalyze == 'Фишинговый' or self.resultLinkCheck == "Подозрительная"): #домен ссылка   или текста
            self.resultClassification = 'Подозрительное' #всё плохо
            return "Подозрительное" #возвращаем #всё плохо
        else:
            self.resultClassification = 'Безопасное' #всё отлично
            return "Безопасное" #возвращаем