from django.db import models
from django.contrib.auth import get_user_model

User = get_user_model()

class ChatRoom(models.Model):
    ROOM_TYPE_CHOICES = [
        ('DM', 'Direct Message'),  # Личная переписка (2 участника)
        ('GM', 'Group Chat'),      # Групповой чат (N участников)
    ]

    name = models.CharField(max_length=100, blank=True)  # Название (для групповых чатов)
    type = models.CharField(max_length=2, choices=ROOM_TYPE_CHOICES, default='DM')
    members = models.ManyToManyField(User, related_name='chat_rooms')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        if self.type == 'DM':
            # Для личных чатов: выводим имена участников
            members = self.members.all()
            return f"DM: {members[0]} ↔ {members[1]}"
        return f"Group: {self.name}"

    def get_last_message(self):
        return self.messages.last()  # Последнее сообщение в чате

class Message(models.Model):
    room = models.ForeignKey(ChatRoom, on_delete=models.CASCADE, related_name='messages')
    sender = models.ForeignKey(User, on_delete=models.CASCADE)
    content = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)
    is_read = models.BooleanField(default=False)  # Флаг "прочитано"

    def __str__(self):
        return f"{self.sender} ({self.timestamp}): {self.content[:20]}..."

    class Meta:
        ordering = ['timestamp']  # Сортировка по времени