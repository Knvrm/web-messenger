# chat/admin.py
from django.contrib import admin
from .models import ChatRoom, Message

@admin.register(ChatRoom)
class ChatRoomAdmin(admin.ModelAdmin):
    filter_horizontal = ['participants']  # Заменили members на participants
    list_display = ['id', 'name', 'type', 'created_at']
    list_filter = ['type']

@admin.register(Message)
class MessageAdmin(admin.ModelAdmin):
    list_display = ['id', 'room', 'sender', 'timestamp', 'is_read']
    list_filter = ['room', 'sender', 'is_read']