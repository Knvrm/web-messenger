import asyncio
import json
import time
from datetime import timedelta
from django.utils import timezone

from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from django.contrib.auth import get_user_model
from .link import validate_url
from .models import ChatRoom, Message

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

        self.is_dm = await self.is_direct_message()

        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )
        await self.accept()
        await self.send_history()

    async def receive(self, text_data):
        print(f"[{time.time()}] Received message: {text_data}")
        try:
            data = json.loads(text_data)
            message_type = data.get('type', 'message')

            if message_type != 'message':
                await self.send_error("Неподдерживаемый тип сообщения")
                return

            content = data.get('content', '').strip()
            iv = data.get('iv')
            tag = data.get('tag')
            urls = data.get('urls', [])
            print(f"[{time.time()}] Parsed message: type={message_type}, content={content}, iv={iv}, tag={tag}, urls={urls}")

            if not content:
                await self.send_error("Сообщение не может быть пустым")
                return

            # Проверка ограничений пользователя
            if await self.is_user_restricted():
                await self.send_security_alert(
                    "Вы временно ограничены в отправке ссылок",
                    {"reason": "Превышен лимит подозрительных ссылок"},
                    alert_type="user_restricted"
                )
                return

            # Проверка URL
            is_suspicious = False
            if urls:
                print(f"[{time.time()}] Checking URLs: {urls}")
                try:
                    loop = asyncio.get_running_loop()
                    url_checks = await asyncio.gather(*[
                        loop.run_in_executor(None, lambda url=url: validate_url(url))
                        for url in urls
                    ], return_exceptions=True)

                    for url, check_result in zip(urls, url_checks):
                        if isinstance(check_result, Exception):
                            print(f"[{time.time()}] URL check error: {str(check_result)}")
                            await self.send_security_alert(
                                "Не удалось проверить ссылку",
                                {"url": url, "error": str(check_result)},
                                alert_type="url_check_error"
                            )
                            return
                        if check_result["status"] == "malicious":
                            print(f"[{time.time()}] Malicious URL detected: {url}")
                            await self.log_suspicious_link(url, check_result["reason"], is_malicious=True)
                            await self.apply_user_restrictions()
                            await self.send_security_alert(
                                f"Сообщение заблокировано: обнаружена опасная ссылка: {url}",
                                {"url": url, "reason": check_result["reason"]},
                                alert_type="malicious_url"
                            )
                            return
                        elif check_result["status"] == "suspicious":
                            print(f"[{time.time()}] Suspicious URL detected: {url}")
                            is_suspicious = True
                            await self.log_suspicious_link(url, check_result["reason"], is_malicious=False)

                except Exception as e:
                    print(f"[{time.time()}] URL check failed: {str(e)}")
                    await self.send_security_alert(
                        "Не удалось проверить ссылки в сообщении",
                        {"error": str(e)},
                        alert_type="url_check_error"
                    )
                    return

            # Сохранение и отправка сообщения
            print(f"[{time.time()}] Saving message for user: {self.user.username}, content: {content}")
            message_obj = await self.save_message(self.user, content, iv, tag, is_suspicious)
            print(f"[{time.time()}] Message saved: ID={message_obj.id}")
            print(f"[{time.time()}] Sending message to group: {self.room_group_name}")
            await self.send_message_to_chat(message_obj)
            if is_suspicious:
                await self.send_security_alert(
                    f"Сообщение отправлено, но содержит подозрительную ссылку",
                    {"urls": urls},
                    alert_type="suspicious_url"
                )
            print(f"[{time.time()}] Sent message to group: {self.room_group_name}")

        except json.JSONDecodeError:
            await self.send_error("Неверный формат сообщения (ожидается JSON)")
        except Exception as e:
            await self.send_error("Внутренняя ошибка обработки сообщения")
            print(f"[{time.time()}] Chat error: {str(e)}")

    async def send_security_alert(self, message, details=None, alert_type="security"):
        alert_data = {
            'type': 'security_alert',
            'alert_type': alert_type,
            'message': message,
            'details': details or {},
            'timestamp': int(time.time())
        }
        print(f"[{time.time()}] Sending security alert: {alert_data}")
        await self.send(text_data=json.dumps(alert_data))

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
                'iv': message_obj.iv,
                'tag': message_obj.tag,
                'timestamp': message_obj.timestamp.isoformat(),
                'is_read': message_obj.is_read,
                'is_suspicious': message_obj.is_suspicious
            }
        )

    async def chat_message(self, event):
        await self.send(text_data=json.dumps({
            'type': 'new_message',
            'message': event['message'],
            'sender': event['sender'],
            'sender_id': event['sender_id'],
            'message_id': event['message_id'],
            'iv': event['iv'],
            'tag': event['tag'],
            'timestamp': event['timestamp'],
            'is_read': event['is_read'],
            'is_suspicious': event['is_suspicious']
        }))

    @database_sync_to_async
    def is_user_restricted(self):
        """Проверяет, ограничен ли пользователь в отправке ссылок."""
        user = self.user
        if user.link_restriction_until and user.link_restriction_until > timezone.now():
            return True
        return False

    @database_sync_to_async
    def apply_user_restrictions(self):
        """Применяет ограничения или бан на основе количества нарушений."""
        user = self.user
        user.suspicious_links_count += 1
        user.last_suspicious_link_at = timezone.now()

        if user.suspicious_links_count == 2:
            # Ограничение на отправку ссылок на 1 час
            user.link_restriction_until = timezone.now() + timedelta(hours=1)
        elif user.suspicious_links_count >= 3:
            # Временный бан на 24 часа
            user.is_active = False
            user.link_restriction_until = timezone.now() + timedelta(hours=24)

        user.save()

    @database_sync_to_async
    def log_suspicious_link(self, url, reason, is_malicious):
        """Логирует подозрительную или опасную ссылку."""
        from .models import SuspiciousLinkLog
        SuspiciousLinkLog.objects.create(
            user=self.user,
            url=url,
            reason=reason,
            is_malicious=is_malicious,
            room_id=self.room_id
        )

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
    def save_message(self, user, content, iv, tag, is_suspicious=False):
        room = ChatRoom.objects.get(id=self.room_id)
        return Message.objects.create(
            room=room,
            sender=user,
            content=content,
            iv=iv,
            tag=tag,
            is_suspicious=is_suspicious
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
                'iv': msg.iv,
                'tag': msg.tag,
                'timestamp': msg.timestamp.isoformat(),
                'is_read': msg.is_read,
                'is_suspicious': msg.is_suspicious
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