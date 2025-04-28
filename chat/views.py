from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from .models import ChatRoom, Message
from django.contrib.auth import get_user_model
import json
from django.http import JsonResponse
from django.views.decorators.http import require_GET, require_POST, require_http_methods
from django.views.decorators.csrf import ensure_csrf_cookie
from django.db.models import Prefetch, Q  # Добавляем импорт Max
from django.urls import reverse

User = get_user_model()

@login_required
def chat_home(request):
    user_chats = request.user.chat_rooms.prefetch_related(
        Prefetch('messages',
                 queryset=Message.objects.order_by('-timestamp'),
                 to_attr='last_message_list')
    ).order_by('-created_at')

    print(f"Session data: {request.session.items()}")
    context = {
        'private_key': request.session.get('private_key', ''),
        'key_salt': request.session.get('key_salt', '')
    }
    print(f"Rendering chat.html with context: {context}")

    for chat in user_chats:
        chat.has_messages = len(chat.last_message_list) > 0
        chat.last_message = chat.last_message_list[0] if chat.has_messages else None

    selected_chat = None
    chat_messages = []
    recipient = None  # Добавляем переменную для собеседника

    if 'chat_id' in request.GET:
        chat_id = request.GET['chat_id']
        selected_chat = get_object_or_404(ChatRoom, id=chat_id, participants=request.user)
        chat_messages = selected_chat.messages.all().order_by('timestamp')
        selected_chat.messages.filter(is_read=False).exclude(sender=request.user).update(is_read=True)

        # Получаем собеседника для личных чатов
        if selected_chat.type == 'DM' and selected_chat.participants.count() == 2:
            recipient = selected_chat.participants.exclude(id=request.user.id).first()

    return render(request, 'chat/home.html', {
        'chats': user_chats,
        'selected_chat': selected_chat,
        'messages': chat_messages,
        'recipient': recipient,
        'private_key': request.session.get('private_key', ''),
        'key_salt': request.session.get('key_salt', '')
    })


@login_required
def rename_chat(request, chat_id):
    if request.method == 'POST':
        chat = get_object_or_404(ChatRoom, id=chat_id, participants=request.user)
        data = json.loads(request.body)
        new_name = data.get('name', '').strip()

        if not new_name:
            return JsonResponse({'status': 'error', 'message': 'Название не может быть пустым'}, status=400)

        if len(new_name) > 100:
            return JsonResponse({'status': 'error', 'message': 'Название слишком длинное'}, status=400)

        chat.name = new_name
        chat.save()
        return JsonResponse({'status': 'success'})

    return JsonResponse({'status': 'error', 'message': 'Неверный метод запроса'}, status=405)

@ensure_csrf_cookie
@require_POST
@login_required
def create_chat(request):
    try:
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
                participants=request.user
            ).filter(participants=users.first()).first()

            if existing_chat:
                return JsonResponse({
                    'status': 'exists',
                    'chat_id': existing_chat.id
                })

        # Создаем новый чат
        new_chat = ChatRoom.objects.create()
        new_chat.participants.add(request.user, *users)

        if new_chat.participants.count() > 2:
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
        chat = get_object_or_404(ChatRoom, id=room_id, participants=request.user)
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


@login_required
def leave_chat(request, chat_id):  # Используем chat_id для согласованности
    if request.method == 'POST':
        try:
            room = ChatRoom.objects.get(id=chat_id)
            user = request.user

            if request.user not in room.participants.all():
                return JsonResponse(...)

            # Проверяем, что пользователь участник чата
            if user not in room.participants.all():
                return JsonResponse({
                    'success': False,
                    'message': 'Вы не состоите в этом чате'
                }, status=400)

            # Удаляем пользователя из участников
            room.participants.remove(user)

            return JsonResponse({
                'success': True,
                'message': 'Вы успешно покинули чат'
            })

        except ChatRoom.DoesNotExist:
            return JsonResponse({
                'success': False,
                'message': 'Чат не найден'
            }, status=404)

        except Exception as e:
            return JsonResponse({
                'success': False,
                'message': f'Ошибка сервера: {str(e)}'
            }, status=500)

    return JsonResponse({
        'success': False,
        'message': 'Метод не разрешен'
    }, status=405)

@login_required
@require_POST
def remove_user_from_chat(request, chat_id):
    try:

        # Получаем данные из тела запроса
        try:
            data = json.loads(request.body.decode('utf-8'))
            user_id = data.get('user_id')
        except json.JSONDecodeError:
            return JsonResponse({
                'success': False,
                'message': 'Неверный формат данных'
            }, status=400)

        # Проверяем обязательные поля
        if not user_id:
            return JsonResponse({
                'success': False,
                'message': 'Не указан ID пользователя'
            }, status=400)

        # Получаем объекты
        try:
            chat = ChatRoom.objects.get(id=chat_id)
            user_to_remove = User.objects.get(id=user_id)
            current_user = request.user
        except (ChatRoom.DoesNotExist, User.DoesNotExist) as e:
            return JsonResponse({
                'success': False,
                'message': 'Чат или пользователь не найдены'
            }, status=404)

        # Нельзя исключить себя
        if user_to_remove == current_user:
            return JsonResponse({
                'success': False,
                'message': 'Вы не можете исключить себя'
            }, status=400)

        # Удаляем пользователя
        chat.members.remove(user_to_remove)

        return JsonResponse({
            'success': True,
            'message': 'Пользователь успешно исключен'
        })

    except Exception as e:
        return JsonResponse({
            'success': False,
            'message': f'Ошибка сервера: {str(e)}'
        }, status=500)

