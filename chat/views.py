from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .models import ChatRoom, Message
from django.contrib.auth import get_user_model
import json
from django.http import JsonResponse
from django.views.decorators.http import require_GET, require_POST
from django.views.decorators.csrf import ensure_csrf_cookie

User = get_user_model()

@login_required
def chat_home(request):
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

@ensure_csrf_cookie
@require_POST
@login_required
def create_chat(request):
    try:
        # Парсим JSON данные из запроса
        data = json.loads(request.body)
        user_ids = data.get('users', [])

        # Проверяем, что выбраны пользователи
        if not user_ids:
            return JsonResponse({'status': 'error', 'message': 'No users selected'}, status=400)

        # Получаем объекты пользователей (исключая текущего)
        users = User.objects.filter(id__in=user_ids).exclude(id=request.user.id)

        # Проверяем существующий личный чат (если выбран 1 пользователь)
        if users.count() == 1:
            existing_chat = ChatRoom.objects.filter(
                type='DM',
                members=request.user
            ).filter(members=users.first()).first()

            if existing_chat:
                return JsonResponse({
                    'status': 'exists',
                    'chat_id': existing_chat.id
                })

        # Создаем новый чат
        new_chat = ChatRoom.objects.create()
        new_chat.members.add(request.user, *users)

        if new_chat.members.count() > 2:
            new_chat.type = 'GM'
            # Получаем имена всех участников (кроме текущего пользователя, если нужно)
            member_names = list(users.values_list('username', flat=True))
            # Добавляем текущего пользователя, если требуется
            if request.user.username not in member_names:
                member_names.insert(0, request.user.username)
            # Формируем название чата
            new_chat.name = ", ".join(member_names)
            new_chat.save()

        # Возвращаем успешный ответ
        return JsonResponse({
            'status': 'success',
            'chat_id': new_chat.id,
            'type': new_chat.type
        })

    except Exception as e:
        return JsonResponse({
            'status': 'error',
            'message': str(e)
        }, status=500)

@require_GET
@login_required
def get_users_for_chat(request):
    try:
        users = User.objects.exclude(id=request.user.id).values('id', 'username')
        return JsonResponse({
            'status': 'success',
            'users': list(users)
        })
    except Exception as e:
        return JsonResponse({
            'status': 'error',
            'message': str(e)
        }, status=500)

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
def chat_settings(request):
    return render(request, 'chat/settings.html', {
        'title': 'Настройки чата',
        'user': request.user
    })