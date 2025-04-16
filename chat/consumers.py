import asyncio
import json
import re
import time

from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from .link import validate_url
from .models import ChatRoom, Message
from .textanalysis import PhishingDetector


class ChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.room_id = self.scope['url_route']['kwargs']['chat_id']
        self.room_group_name = f'chat_{self.room_id}'
        self.user = self.scope['user']
        self.is_dm = False  # Флаг для определения типа чата

        if not await self.room_exists():
            await self.close(code=4001)
            return

        # Определяем тип чата
        self.is_dm = await self.is_direct_message()

        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )
        await self.accept()
        await self.send_history()

    async def receive(self, text_data):
        try:
            data = json.loads(text_data)
            message = data['message'].strip()  # Удаляем лишние пробелы
            user = self.scope['user']
            print(message)
            if not message:
                await self.send_error("Сообщение не может быть пустым")
                return

            detector = PhishingDetector()
            # 1. Проверка текста ML-моделью (асинхронно с таймаутом)
            try:
                loop = asyncio.get_running_loop()
                ml_result = await asyncio.wait_for(
                    loop.run_in_executor(
                        None,
                        lambda: detector.analyze_text(message)  # Обернули в lambda для безопасности
                    ),
                    timeout=3.0  # Таймаут для ML-анализа
                )

                if ml_result.get('is_phishing', False) and ml_result.get('confidence', 0) > 0.7:
                    await self.send_security_alert(
                        "Сообщение содержит признаки фишинга",
                        ml_result,
                        alert_type="phishing"
                    )
                    print('123')
                    return

            except asyncio.TimeoutError:
                print("ML анализ превысил таймаут, продолжаем базовые проверки")
            except Exception as e:
                print(f"Ошибка ML анализа: {str(e)}")

            # 2. Проверка URL (параллельно для всех URL)
            urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', message)
            if urls:
                try:
                    # Параллельная проверка всех URL
                    loop = asyncio.get_running_loop()
                    url_checks = await asyncio.gather(*[
                        loop.run_in_executor(
                            None,
                            lambda url=url: validate_url(url)  # Замыкание для каждой URL
                        )
                        for url in urls
                    ], return_exceptions=True)

                    for url, check_result in zip(urls, url_checks):
                        if isinstance(check_result, Exception):
                            await self.send_security_alert(
                                "Обнаружена подозрительная ссылка",
                                {
                                    "url": url,
                                    "error": str(check_result)
                                },
                                alert_type="malicious_url"
                            )
                            return

                except Exception as e:
                    print(f"Ошибка проверки URL: {str(e)}")
                    await self.send_security_alert(
                        "Не удалось проверить ссылки в сообщении",
                        {"error": str(e)},
                        alert_type="url_check_error"
                    )
                    return

            # 3. Если проверки пройдены - сохраняем и отправляем
            message_obj = await self.save_message(user, message)
            await self.send_message_to_chat(message_obj)

        except json.JSONDecodeError:
            await self.send_error("Неверный формат сообщения (ожидается JSON)")
        except KeyError:
            await self.send_error("Отсутствует обязательное поле 'message'")
        except Exception as e:
            await self.send_error("Внутренняя ошибка обработки сообщения")
            #print(f"Chat error: {str(e)}", exc_info=True)  # Логируем с traceback

    async def send_security_alert(self, message, details=None, alert_type="security"):
        """Отправка security alert клиенту с дополнительными метаданными"""
        await self.send(text_data=json.dumps({
            'type': 'security_alert',
            'alert_type': alert_type,
            'message': message,
            'details': details or {},
            'timestamp': int(time.time())
        }))

    async def send_error(self, error_msg, details=None):
        """Отправка ошибки клиенту"""
        await self.send(text_data=json.dumps({
            'type': 'error',
            'error': error_msg,
            'details': details or {}
        }))

    async def send_message_to_chat(self, message_obj):
        """Отправка сообщения в чат"""
        await self.channel_layer.group_send(
            self.room_group_name,
            {
                'type': 'chat.message',
                'message': message_obj.content,
                'sender': message_obj.user.username,
                'timestamp': message_obj.timestamp.isoformat()
            }
        )

    async def chat_message(self, event):
        # Проверяем, нужно ли исключить этого пользователя
        if event.get('exclude_sender') and str(self.user.id) == str(event['sender_id']):
            return

        await self.send(text_data=json.dumps({
            'type': 'new_message',
            'message': event['message'],
            'sender': event['sender'],
            'timestamp': event['timestamp'],
            'message_id': event['message_id']
        }))

    @database_sync_to_async
    def is_direct_message(self):
        """Проверяем, является ли чат личным (DM)"""
        room = ChatRoom.objects.get(id=self.room_id)
        return room.type == 'DM'

    @database_sync_to_async
    def get_recipient(self):
        """Получаем получателя для личного чата"""
        room = ChatRoom.objects.get(id=self.room_id)
        if room.type == 'DM':
            return room.participants.exclude(id=self.user.id).first()
        return None

    @database_sync_to_async
    def room_exists(self):
        return ChatRoom.objects.filter(id=self.room_id).exists()

    @database_sync_to_async
    def save_message(self, user, message):
        room = ChatRoom.objects.get(id=self.room_id)
        return Message.objects.create(
            room=room,
            sender=user,
            content=message
        )

    @database_sync_to_async
    def get_message_history(self):
        messages = Message.objects.filter(room_id=self.room_id).order_by('timestamp')
        return [
            {
                'id': msg.id,
                'content': msg.content,
                'sender__username': msg.sender.username,
                'timestamp': msg.timestamp.isoformat()
            }
            for msg in messages
        ]

    async def send_history(self):
        history = await self.get_message_history()
        await self.send(text_data=json.dumps({
            'type': 'history',
            'messages': history
        }))

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )