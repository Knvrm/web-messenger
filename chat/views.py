from datetime import timedelta

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.utils import timezone

from .models import ChatRoom, Message, SecurityLog
from django.contrib.auth import get_user_model
import json
from django.http import JsonResponse
from django.views.decorators.http import require_GET, require_POST
from django.views.decorators.csrf import ensure_csrf_cookie
from django.db.models import Prefetch
from transformers import DistilBertTokenizer
import onnxruntime as ort
import numpy as np

User = get_user_model()

@login_required
def chat_home(request):
    #print(f"Chat view - User authenticated: {request.user.is_authenticated}")
    #print(f"Chat view - User: {request.user}")
    #print(f"Chat view - Session: {request.session.items()}")
    user_chats = request.user.chat_rooms.prefetch_related(
        Prefetch('messages',
                 queryset=Message.objects.order_by('-timestamp'),
                 to_attr='last_message_list')
    ).order_by('-created_at')

    #print(f"Session data: {request.session.items()}")
    context = {
        'private_key': request.session.get('private_key', ''),
        'key_salt': request.session.get('key_salt', ''),
        'current_user_id': request.user.id
    }
    #print(f"Rendering chat.html with context: {context}")

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
        'key_salt': request.session.get('key_salt', ''),
        'current_user_id': request.user.id
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
        encrypted_session_keys = data.get('encrypted_session_keys', {})

        #print(user_ids)
        #print(encrypted_session_keys)

        if not user_ids:
            return JsonResponse({'status': 'error', 'message': 'No users selected'}, status=400)

        users = User.objects.filter(id__in=user_ids).exclude(id=request.user.id)

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

        new_chat = ChatRoom.objects.create(
            type='DM' if users.count() == 1 else 'GM',
            encrypted_session_keys=encrypted_session_keys
        )
        new_chat.participants.add(request.user, *users)

        if new_chat.type == 'GM':
            member_names = list(users.values_list('username', flat=True))
            if request.user.username not in member_names:
                member_names.insert(0, request.user.username)
            new_chat.name = ", ".join(member_names)
            new_chat.save()

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
@require_GET
def get_session_key(request, chat_id):
    try:
        chat = ChatRoom.objects.get(id=chat_id, participants=request.user)
        user_id = str(request.user.id)
        encrypted_key = chat.encrypted_session_keys.get(user_id)
        if not encrypted_key:
            return JsonResponse({'status': 'error', 'message': 'Session key not found'}, status=404)
        return JsonResponse({'status': 'success', 'encrypted_key': encrypted_key})
    except ChatRoom.DoesNotExist:
        return JsonResponse({'status': 'error', 'message': 'Chat not found'}, status=404)
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


@login_required
def send_message(request, room_id):
    """Отправка сообщения"""
    if request.method == 'POST':
        chat = get_object_or_404(ChatRoom, id=room_id, participants=request.user)

        # Проверка ограничений пользователя
        one_hour_ago = timezone.now() - timedelta(hours=1)
        malicious_count = SecurityLog.objects.filter(
            user=request.user,
            checked_at__gte=one_hour_ago,
            is_malicious=True
        ).count()
        if malicious_count >= 3:
            return JsonResponse({
                'status': 'error',
                'message': 'Вы временно ограничены в отправке сообщений',
                'details': {'reason': 'Превышен лимит подозрительных действий'}
            }, status=403)

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

@login_required
@require_GET
def get_public_key(request, user_id):
    try:
        user = User.objects.get(id=user_id)
        if not user.public_key:
            return JsonResponse({'status': 'error', 'message': 'Public key not found'}, status=404)
        return JsonResponse({'status': 'success', 'public_key': user.public_key})
    except User.DoesNotExist:
        return JsonResponse({'status': 'error', 'message': 'User not found'}, status=404)
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)

@login_required
def get_last_message(request, chat_id):
    try:
        chat = ChatRoom.objects.get(id=chat_id, participants=request.user)
        last_message = chat.messages.last()
        if not last_message:
            return JsonResponse({'status': 'success', 'content': None, 'iv': None, 'tag': None})
        return JsonResponse({
            'status': 'success',
            'content': last_message.content,
            'iv': last_message.iv,
            'tag': last_message.tag
        })
    except ChatRoom.DoesNotExist:
        return JsonResponse({'status': 'error', 'message': 'Chat not found'}, status=403)
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)

# Путь к ONNX-модели (используем неквантованную для надёжности)
MODEL_PATH = "C:/Users/Roman/Desktop/#1/Messenger/chat/models/phishing-email-detection-distilbert_v2.4.1/model.onnx"
# Инициализация токенизатора и сессии ONNX
tokenizer = DistilBertTokenizer.from_pretrained('distilbert-base-uncased')
ort_session = ort.InferenceSession(MODEL_PATH)

def tokenize_text(request):
    if request.method == 'POST':
        text = request.POST.get('text', '')
        if not text:
            return JsonResponse({'error': 'No text provided'}, status=400)
        try:
            # Токенизация
            inputs = tokenizer(text, truncation=True, max_length=256, padding=True, return_tensors='np')
            input_ids = inputs['input_ids']
            attention_mask = inputs['attention_mask']

            # Инференс
            ort_inputs = {
                'input_ids': input_ids.astype(np.int64),
                'attention_mask': attention_mask.astype(np.int64)
            }
            ort_outputs = ort_session.run(None, ort_inputs)
            logits = ort_outputs[0]

            # Вычисление вероятностей
            probs = np.exp(logits) / np.sum(np.exp(logits), axis=-1, keepdims=True)
            pred_class = np.argmax(probs, axis=-1)[0]
            max_prob = float(probs[0, pred_class])

            return JsonResponse({
                'predClass': int(pred_class),
                'maxProb': max_prob
            })
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    return JsonResponse({'error': 'Invalid request method'}, status=405)