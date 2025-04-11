from django.contrib import admin
from .models import ChatRoom, Message

@admin.register(ChatRoom)
class ChatRoomAdmin(admin.ModelAdmin):
    list_display = ('id', 'type', 'name', 'created_at')
    filter_horizontal = ('members',)  # Удобный выбор участников

@admin.register(Message)
class MessageAdmin(admin.ModelAdmin):
    list_display = ('sender', 'room', 'timestamp', 'is_read')
    list_filter = ('room', 'sender')