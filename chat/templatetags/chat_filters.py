from django import template
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

register = template.Library()

# Словарь для перевода дней недели
WEEKDAYS = {
    'Mon': 'Пн',
    'Tue': 'Вт',
    'Wed': 'Ср',
    'Thu': 'Чт',
    'Fri': 'Пт',
    'Sat': 'Сб',
    'Sun': 'Вс'
}

@register.filter
def telegram_time(value, has_messages=True):
    if not has_messages or not value:
        return ""

    try:
        # Принудительно приводим к московскому времени
        moscow_tz = timezone.get_fixed_timezone(180)  # UTC+3
        local_time = value.astimezone(moscow_tz)
        now = timezone.now().astimezone(moscow_tz)
        diff = now - local_time

        if diff.days == 0:
            return local_time.strftime('%H:%M')
        elif diff.days == 1:
            return 'вчера'
        elif diff.days < 7:
            # Получаем английское сокращение и переводим его
            eng_day = local_time.strftime('%a')
            return WEEKDAYS.get(eng_day, eng_day)
        elif now.year == local_time.year:
            return local_time.strftime('%d %b').lower()
        else:
            return local_time.strftime('%d.%m.%y')

    except Exception as e:
        print(f"Time error: {e}")
        return str(value)[11:16]  # Возвращаем время как есть