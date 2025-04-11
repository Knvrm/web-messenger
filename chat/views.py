from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.db.models import Q
from .models import ChatRoom, Message
from django.contrib.auth import get_user_model

User = get_user_model()


@login_required
def chat_home(request):
    """Главная страница чатов"""
    user_chats = request.user.chat_rooms.all().order_by('-created_at')

    # Получаем выбранный чат (из GET-параметра)
    selected_chat = None
    chat_messages = []
    if 'chat_id' in request.GET:
        selected_chat = get_object_or_404(ChatRoom, id=request.GET['chat_id'], members=request.user)
        chat_messages = selected_chat.messages.all().order_by('timestamp')

    # Помечаем сообщения как прочитанные
    if selected_chat:
        selected_chat.messages.filter(is_read=False).exclude(sender=request.user).update(is_read=True)

    return render(request, 'chat/home.html', {
        'chats': user_chats,
        'selected_chat': selected_chat,
        'messages': chat_messages
    })


@login_required
def create_chat(request):
    if request.method == 'POST':
        chat_type = request.POST.get('type', 'DM')

        if chat_type == 'DM':
            # Логика для личного чата
            username = request.POST.get('username')
            try:
                other_user = User.objects.get(username=username)

                # Проверяем, не существует ли уже такой чат
                existing_chat = ChatRoom.objects.filter(
                    type='DM',
                    members=request.user
                ).filter(members=other_user).first()

                if existing_chat:
                    return redirect(f'/chat/?chat_id={existing_chat.id}')

                # Создаем чат без названия (оно сгенерируется автоматически)
                chat = ChatRoom.objects.create(type='DM')
                chat.members.add(request.user, other_user)
                messages.success(request, f'Чат с {other_user.username} создан')
                return redirect(f'/chat/?chat_id={chat.id}')

            except User.DoesNotExist:
                messages.error(request, 'Пользователь не найден')
                return redirect('chat-home')

        else:
            # Логика для группового чата
            group_name = request.POST.get('group_name', '').strip()
            if not group_name:
                messages.error(request, 'Укажите название группы')
                return redirect('chat-home')

            # Создаем групповой чат с указанным названием
            chat = ChatRoom.objects.create(type='GM', name=group_name)
            chat.members.add(request.user)
            messages.success(request, f'Групповой чат "{group_name}" создан')
            return redirect(f'/chat/?chat_id={chat.id}')

    return redirect('chat-home')


@login_required
def send_message(request, room_id):
    """Отправка сообщения"""
    if request.method == 'POST':
        chat = get_object_or_404(ChatRoom, id=room_id, members=request.user)
        message_text = request.POST.get('message', '').strip()

        if message_text:
            Message.objects.create(
                room=chat,
                sender=request.user,
                content=message_text
            )

    return redirect(f'/chat/?chat_id={room_id}')


@login_required
def add_to_group(request, room_id):
    """Добавление участника в групповой чат"""
    chat = get_object_or_404(ChatRoom, id=room_id, type='GM', members=request.user)

    if request.method == 'POST':
        username = request.POST.get('username')
        try:
            user = User.objects.get(username=username)
            if user not in chat.members.all():
                chat.members.add(user)
                messages.success(request, f'{username} добавлен в чат')
            else:
                messages.info(request, f'{username} уже в чате')
        except User.DoesNotExist:
            messages.error(request, 'Пользователь не найден')

    return redirect(f'/chat/?chat_id={room_id}')