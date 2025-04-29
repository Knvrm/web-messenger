# chat/admin.py
from django.contrib import admin
from .models import ChatRoom, Message

@admin.register(ChatRoom)
class ChatRoomAdmin(admin.ModelAdmin):
    filter_horizontal = ['participants']
    list_display = ['id', 'name', 'type', 'created_at']
    list_filter = ['type']
    search_fields = ['name', 'participants__username']

@admin.register(Message)
class MessageAdmin(admin.ModelAdmin):
    list_display = ['id', 'room', 'sender', 'content_preview', 'encrypted_key', 'iv', 'tag', 'timestamp', 'is_read']
    list_filter = ['room', 'sender', 'is_read']
    search_fields = ['content', 'sender__username']
    readonly_fields = ['encrypted_key', 'iv', 'tag', 'timestamp']

    def content_preview(self, obj):
        """Отображает первые 60 символов содержимого сообщения"""
        return obj.content[:60] + ('...' if len(obj.content) > 60 else '')
    content_preview.short_description = 'Content'