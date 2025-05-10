from django.contrib import admin
from .models import ChatRoom, Message, SecurityLog

@admin.register(ChatRoom)
class ChatRoomAdmin(admin.ModelAdmin):
    filter_horizontal = ['participants']
    list_display = ['id', 'name', 'type', 'created_at', 'get_participants']
    list_filter = ['type']
    search_fields = ['name', 'participants__username']
    readonly_fields = ['created_at', 'encrypted_session_keys']

    def get_participants(self, obj):
        return ", ".join([user.username for user in obj.participants.all()])
    get_participants.short_description = 'Participants'

@admin.register(Message)
class MessageAdmin(admin.ModelAdmin):
    list_display = ['id', 'room', 'sender', 'content_preview', 'iv', 'tag', 'timestamp', 'is_read', 'is_suspicious']
    list_filter = ['room', 'sender', 'is_read', 'is_suspicious']
    search_fields = ['content', 'sender__username']
    readonly_fields = ['iv', 'tag', 'timestamp', 'is_suspicious']

    def content_preview(self, obj):
        """Отображает первые 60 символов содержимого сообщения"""
        return obj.content[:60] + ('...' if len(obj.content) > 60 else '')
    content_preview.short_description = 'Content'

@admin.register(SecurityLog)
class SecurityLogAdmin(admin.ModelAdmin):
    list_display = ('user', 'url', 'checked_at', 'reason', 'is_malicious')
    list_filter = ('checked_at', 'is_malicious')
    search_fields = ('user__username', 'url', 'reason')
    readonly_fields = ('checked_at',)
    date_hierarchy = 'checked_at'