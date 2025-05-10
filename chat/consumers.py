import asyncio
import json
import time
from datetime import timedelta
from django.utils import timezone
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from django.contrib.auth import get_user_model
from .link import validate_url
from .models import ChatRoom, Message, SecurityLog

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

    async def disconnect(self, close_code):
        if hasattr(self, 'room_group_name'):
            await self.channel_layer.group_discard(
                self.room_group_name,
                self.channel_name
            )

    async def receive(self, text_data):
        print(f"[{time.time()}] Received message: {text_data}")
        try:
            data = json.loads(text_data)
            message_type = data.get('type', 'message')

            if message_type == 'phishing_alert':
                print(f"[{time.time()}] Processing phishing alert: {data}")
                await self.handle_phishing_alert(data)
                return

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

            # Проверка черного списка
            if self.is_dm:
                recipient = await self.get_dm_recipient()
                # Проверка: заблокирован ли отправитель получателем
                if await self.is_blocked_by(recipient):
                    await self.send_error("Вы заблокированы этим пользователем")
                    return
                # Проверка: заблокировал ли отправитель получателя
                if await self.has_blocked(recipient):
                    await self.send_error("Вы не можете отправить сообщение, так как заблокировали этого пользователя")
                    return

            # Проверка ограничений пользователя
            if await self.is_user_restricted():
                print(f"[{time.time()}] User {self.user.username} is restricted, blocking message")
                await self.send_security_alert(
                    "Вы временно ограничены в отправке сообщений",
                    {"reason": "Превышен лимит подозрительных действий"},
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
                            await self.log_security_event(
                                url=url,
                                reason=check_result["reason"],
                                is_malicious=True,
                                confidence=0.9
                            )
                            await self.apply_user_restrictions()
                            await self.send_security_alert(
                                f"Обнаружена вредоносная ссылка: {url}",
                                {"reason": check_result["reason"]},
                                alert_type="malicious_url"
                            )
                            return
                        elif check_result["status"] == "suspicious":
                            print(f"[{time.time()}] Suspicious URL detected: {url}")
                            is_suspicious = True
                            await self.log_security_event(
                                url=url,
                                reason=check_result["reason"],
                                is_malicious=False,
                                confidence=0.7
                            )
                            await self.send_security_alert(
                                f"Подозрительная ссылка: {url}",
                                {"reason": check_result["reason"]},
                                alert_type="suspicious_url"
                            )

                except Exception as e:
                    print(f"[{time.time()}] Unexpected error during URL check: {str(e)}")
                    await self.send_error(f"Ошибка проверки ссылок: {str(e)}")
                    return

            # Сохранение сообщения
            message = await self.save_message(content, iv, tag, is_suspicious)
            print(f"[{time.time()}] Message saved: {message.id}")

            # Отправка сообщения в группу
            await self.channel_layer.group_send(
                self.room_group_name,
                {
                    'type': 'chat_message',
                    'message_id': str(message.id),
                    'message': content,
                    'iv': iv,
                    'tag': tag,
                    'sender_id': self.user.id,
                    'sender__username': self.user.username,
                    'timestamp': message.timestamp.isoformat(),
                    'is_read': False,
                    'is_suspicious': is_suspicious
                }
            )
            print(f"[{time.time()}] Message sent to group: {self.room_group_name}")

        except json.JSONDecodeError:
            await self.send_error("Некорректный формат данных")
        except Exception as e:
            print(f"[{time.time()}] Unexpected error: {str(e)}")
            await self.send_error(f"Произошла ошибка: {str(e)}")

    async def chat_message(self, event):
        print(f"[{time.time()}] Sending chat message to client: {event}")
        await self.send(text_data=json.dumps({
            'type': 'new_message',
            'message_id': event['message_id'],
            'message': event['message'],
            'iv': event['iv'],
            'tag': event['tag'],
            'sender_id': event['sender_id'],
            'sender': event['sender__username'],
            'timestamp': event['timestamp'],
            'is_read': event['is_read'],
            'is_suspicious': event['is_suspicious']
        }))

    async def send_error(self, error_message):
        print(f"[{time.time()}] Sending error: {error_message}")
        await self.send(text_data=json.dumps({
            'type': 'error',
            'error': error_message,
            'details': {}
        }))

    async def send_security_alert(self, message, details, alert_type):
        print(f"[{time.time()}] Sending security alert: {message}, type={alert_type}")
        await self.send(text_data=json.dumps({
            'type': 'security_alert',
            'message': message,
            'details': details,
            'alert_type': alert_type
        }))

    async def handle_phishing_alert(self, data):
        message_id = data.get('message_id', '')
        confidence = data.get('confidence', 0.0)
        reason = data.get('reason', 'phishing_detected')
        has_url = data.get('has_url', False)
        details = data.get('details', {})
        url = data.get('url', '') if has_url else None

        # Проверка ограничений пользователя
        if await self.is_user_restricted():
            print(f"[{time.time()}] User {self.user.username} is restricted, blocking phishing alert")
            await self.send_security_alert(
                "Вы временно ограничены в отправке сообщений",
                {"reason": "Превышен лимит подозрительных действий"},
                alert_type="user_restricted"
            )
            return

        try:
            # Логирование фишингового сообщения
            await self.log_security_event(
                url=url,
                reason=reason,
                is_malicious=confidence > 0.7,
                message_id=message_id,
                confidence=confidence,
                details=details
            )
            await self.apply_user_restrictions()
            await self.send_security_alert(
                "Сообщение заблокировано: обнаружен фишинг",
                {
                    "reason": reason,
                    "confidence": confidence,
                    "has_url": has_url,
                    **details
                },
                alert_type="phishing_detected"
            )
        except Exception as e:
            print(f"[{time.time()}] Error handling phishing alert: {str(e)}")
            await self.send_error(f"Ошибка обработки фишинг-алерта: {str(e)}")

    @database_sync_to_async
    def room_exists(self):
        try:
            ChatRoom.objects.get(id=self.room_id)
            return True
        except ChatRoom.DoesNotExist:
            return False

    @database_sync_to_async
    def is_direct_message(self):
        try:
            room = ChatRoom.objects.get(id=self.room_id)
            return room.type == 'DM'
        except ChatRoom.DoesNotExist:
            return False

    @database_sync_to_async
    def get_dm_recipient(self):
        room = ChatRoom.objects.get(id=self.room_id)
        return room.participants.exclude(id=self.user.id).first()

    @database_sync_to_async
    def is_blocked_by(self, recipient):
        return recipient.blacklist.filter(id=self.user.id).exists()

    @database_sync_to_async
    def has_blocked(self, recipient):
        return self.user.blacklist.filter(id=recipient.id).exists()

    @database_sync_to_async
    def send_history(self):
        room = ChatRoom.objects.get(id=self.room_id)
        messages = Message.objects.filter(room=room).select_related('sender').order_by('timestamp')[:50]
        return self.send(text_data=json.dumps({
            'type': 'history',
            'messages': [
                {
                    'id': str(message.id),
                    'content': message.content,
                    'iv': message.iv,
                    'tag': message.tag,
                    'sender_id': message.sender.id,
                    'sender__username': message.sender.username,
                    'timestamp': message.timestamp.isoformat(),
                    'is_read': message.is_read,
                    'is_suspicious': message.is_suspicious
                } for message in messages
            ]
        }))

    @database_sync_to_async
    def save_message(self, content, iv, tag, is_suspicious):
        room = ChatRoom.objects.get(id=self.room_id)
        return Message.objects.create(
            room=room,
            sender=self.user,
            content=content,
            iv=iv,
            tag=tag,
            is_suspicious=is_suspicious
        )

    @database_sync_to_async
    def log_security_event(self, url, reason, is_malicious, message_id=None, confidence=None, details=None):
        print(f"[{time.time()}] Logging security event: url={url}, reason={reason}, is_malicious={is_malicious}")
        room = ChatRoom.objects.get(id=self.room_id)
        SecurityLog.objects.create(
            user=self.user,
            room=room,
            url=url,
            reason=reason,
            is_malicious=is_malicious,
            message_id=message_id,
            confidence=confidence or 0.0,
            details=details or {}
        )

    @database_sync_to_async
    def is_user_restricted(self):
        one_hour_ago = timezone.now() - timedelta(hours=1)
        recent_logs = SecurityLog.objects.filter(
            user=self.user,
            checked_at__gte=one_hour_ago,
            is_malicious=True
        ).count()
        print(f"[{time.time()}] Checking user restrictions: recent_logs={recent_logs}")
        return recent_logs >= 3

    @database_sync_to_async
    def apply_user_restrictions(self):
        one_hour_ago = timezone.now() - timedelta(hours=1)
        recent_logs = SecurityLog.objects.filter(
            user=self.user,
            checked_at__gte=one_hour_ago,
            is_malicious=True
        )
        suspicious_logs_count = recent_logs.count()
        print(f"[{time.time()}] Applying restrictions: suspicious_logs_count={suspicious_logs_count}")

        if suspicious_logs_count >= 3:
            recent_logs.update(is_malicious=True)
            print(f"[{time.time()}] User {self.user.username} restricted due to {suspicious_logs_count} suspicious logs")