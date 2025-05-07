from django.db import models
from django.contrib.auth import get_user_model

User = get_user_model()

class ChatRoom(models.Model):
    ROOM_TYPE_CHOICES = [
        ('DM', 'Direct Message'),
        ('GM', 'Group Chat'),
    ]

    name = models.CharField(max_length=100, blank=True)
    type = models.CharField(max_length=2, choices=ROOM_TYPE_CHOICES, default='DM')
    participants = models.ManyToManyField(User, related_name='chat_rooms')
    created_at = models.DateTimeField(auto_now_add=True)
    encrypted_session_keys = models.JSONField(blank=True, null=True)

    def __str__(self):
        if self.type == 'DM':
            members = self.participants.all()[:2]
            if len(members) == 2:
                return f"DM: {members[0]} ↔ {members[1]}"
        return f"Group: {self.name or 'Unnamed'}"

class Message(models.Model):
    room = models.ForeignKey(ChatRoom, on_delete=models.CASCADE, related_name='messages')
    sender = models.ForeignKey(User, on_delete=models.CASCADE)
    content = models.TextField()  # Base64 AES-GCM encrypted message
    iv = models.TextField(blank=True, null=True)  # Base64 AES initialization vector
    tag = models.TextField(blank=True, null=True)  # Base64 GCM authentication tag
    timestamp = models.DateTimeField(auto_now_add=True)
    is_read = models.BooleanField(default=False)
    is_suspicious = models.BooleanField(default=False)  # Новый флаг для подозрительных сообщений

    class Meta:
        ordering = ['timestamp']
        indexes = [
            models.Index(fields=['timestamp']),
            models.Index(fields=['is_read']),
            models.Index(fields=['is_suspicious']),
        ]

    def __str__(self):
        return f"{self.sender} ({self.timestamp:%Y-%m-%d %H:%M}): {self.content[:30]}..."

class SuspiciousLinkLog(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    url = models.TextField()
    reason = models.TextField()
    is_malicious = models.BooleanField(default=False)
    room = models.ForeignKey(ChatRoom, on_delete=models.CASCADE, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['timestamp']),
            models.Index(fields=['user']),
        ]

    def __str__(self):
        return f"{self.user} sent {self.url} ({'malicious' if self.is_malicious else 'suspicious'})"