# chat/consumers.py
import json
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from .models import ChatRoom, Message
from django.contrib.auth import get_user_model

User = get_user_model()


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
        data = json.loads(text_data)
        message = data['message']

        # Сохраняем сообщение в БД
        message_obj = await self.save_message(self.user, message)

        # Для личных чатов отправляем только получателю
        if self.is_dm:
            recipient = await self.get_recipient()
            if recipient:
                await self.channel_layer.group_send(
                    self.room_group_name,
                    {
                        'type': 'chat_message',
                        'message': message_obj.content,
                        'sender': self.user.username,
                        'sender_id': self.user.id,
                        'timestamp': message_obj.timestamp.isoformat(),
                        'message_id': message_obj.id,
                        'exclude_sender': True  # Исключаем отправителя
                    }
                )
        else:
            # Для групповых чатов отправляем всем
            await self.channel_layer.group_send(
                self.room_group_name,
                {
                    'type': 'chat_message',
                    'message': message_obj.content,
                    'sender': self.user.username,
                    'sender_id': self.user.id,
                    'timestamp': message_obj.timestamp.isoformat(),
                    'message_id': message_obj.id,
                    'exclude_sender': True  # Исключаем отправителя
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