# chat/consumers.py
import asyncio
import json
import re
import time

from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from django.contrib.auth import get_user_model
from .link import validate_url
from .models import ChatRoom, Message
from .textanalysis import PhishingDetector

User = get_user_model()

class ChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.room_id = self.scope['url_route']['kwargs']['chat_id']
        self.room_group_name = f'chat_{self.room_id}'
        self.user = self.scope['user']
        self.is_dm = False

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
            message_type = data.get('type', 'message')

            if message_type != 'message':
                await self.send_error("Неподдерживаемый тип сообщения")
                return

            # Извлечение данных
            content = data.get('content', '').strip()
            encrypted_key = data.get('encrypted_key') if self.is_dm else None
            iv = data.get('iv') if self.is_dm else None
            tag = data.get('tag') if self.is_dm else None

            if not content:
                await self.send_error("Сообщение не может быть пустым")
                return

            detector = PhishingDetector()
            # 1. Проверка текста ML-моделью
            try:
                loop = asyncio.get_running_loop()
                ml_result = await asyncio.wait_for(
                    loop.run_in_executor(
                        None,
                        lambda: detector.analyze_text(content)
                    ),
                    timeout=3.0
                )

                # Раскомментируйте, если хотите включить блокировку фишинга
                # if ml_result.get('is_phishing', False) and ml_result.get('confidence', 0) > 0.7:
                #     await self.send_security_alert(
                #         "Сообщение содержит признаки фишинга",
                #         ml_result,
                #         alert_type="phishing"
                #     )
                #     return

            except asyncio.TimeoutError:
                print("ML анализ превысил таймаут, продолжаем базовые проверки")
            except Exception as e:
                print(f"Ошибка ML анализа: {str(e)}")

            # 2. Проверка URL
            urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', content)
            if urls:
                try:
                    loop = asyncio.get_running_loop()
                    url_checks = await asyncio.gather(*[
                        loop.run_in_executor(
                            None,
                            lambda url=url: validate_url(url)
                        )
                        for url in urls
                    ], return_exceptions=True)

                    for url, check_result in zip(urls, url_checks):
                        if isinstance(check_result, Exception):
                            await self.send_security_alert(
                                "Обнаружена подозрительная ссылка",
                                {"url": url, "error": str(check_result)},
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

            # 3. Сохранение и отправка сообщения
            message_obj = await self.save_message(self.user, content, encrypted_key, iv, tag)
            await self.send_message_to_chat(message_obj)

        except json.JSONDecodeError:
            await self.send_error("Неверный формат сообщения (ожидается JSON)")
        except Exception as e:
            await self.send_error("Внутренняя ошибка обработки сообщения")
            print(f"Chat error: {str(e)}")

    async def send_security_alert(self, message, details=None, alert_type="security"):
        await self.send(text_data=json.dumps({
            'type': 'security_alert',
            'alert_type': alert_type,
            'message': message,
            'details': details or {},
            'timestamp': int(time.time())
        }))

    async def send_error(self, error_msg, details=None):
        await self.send(text_data=json.dumps({
            'type': 'error',
            'error': error_msg,
            'details': details or {}
        }))

    async def send_message_to_chat(self, message_obj):
        await self.channel_layer.group_send(
            self.room_group_name,
            {
                'type': 'chat.message',
                'message': message_obj.content,
                'sender': message_obj.sender.username,
                'sender_id': message_obj.sender.id,
                'message_id': message_obj.id,
                'encrypted_key': message_obj.encrypted_key,
                'iv': message_obj.iv,
                'tag': message_obj.tag,
                'timestamp': message_obj.timestamp.isoformat(),
                'is_read': message_obj.is_read
            }
        )

    async def chat_message(self, event):
        # Исключаем отправителя, если нужно
        if event.get('exclude_sender') and str(self.user.id) == str(event['sender_id']):
            return

        await self.send(text_data=json.dumps({
            'type': 'new_message',
            'message': event['message'],
            'sender': event['sender'],
            'sender_id': event['sender_id'],
            'message_id': event['message_id'],
            'encrypted_key': event['encrypted_key'],
            'iv': event['iv'],
            'tag': event['tag'],
            'timestamp': event['timestamp'],
            'is_read': event['is_read']
        }))

    @database_sync_to_async
    def is_direct_message(self):
        room = ChatRoom.objects.get(id=self.room_id)
        return room.type == 'DM'

    @database_sync_to_async
    def get_recipient(self):
        room = ChatRoom.objects.get(id=self.room_id)
        if room.type == 'DM':
            return room.participants.exclude(id=self.user.id).first()
        return None

    @database_sync_to_async
    def room_exists(self):
        return ChatRoom.objects.filter(id=self.room_id).exists()

    @database_sync_to_async
    def save_message(self, user, content, encrypted_key=None, iv=None, tag=None):
        room = ChatRoom.objects.get(id=self.room_id)
        return Message.objects.create(
            room=room,
            sender=user,
            content=content,
            encrypted_key=encrypted_key,
            iv=iv,
            tag=tag
        )

    @database_sync_to_async
    def get_message_history(self):
        messages = Message.objects.filter(room_id=self.room_id).order_by('timestamp')
        return [
            {
                'id': msg.id,
                'content': msg.content,
                'sender__username': msg.sender.username,
                'sender_id': msg.sender.id,
                'encrypted_key': msg.encrypted_key,
                'iv': msg.iv,
                'tag': msg.tag,
                'timestamp': msg.timestamp.isoformat(),
                'is_read': msg.is_read
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