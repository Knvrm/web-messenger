import base64
import json
import time

from django.contrib.auth import login, authenticate, logout
from django.db import transaction
from django.http import JsonResponse
from django.contrib import messages
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt, csrf_protect
from django.views.decorators.http import require_POST
from .forms import RegistrationForm, LoginForm
from django.shortcuts import render, redirect
from django.core.mail import send_mail
from django.conf import settings
import random
import string
from datetime import datetime, timedelta
from .models import EmailConfirmation, CustomUser

def generate_confirmation_code():
    return ''.join(random.choices(string.digits, k=6))

def register_view(request):
    # Удаление неактивных пользователей старше 30 минут
    CustomUser.objects.filter(
        is_active=False,
        date_joined__lt=timezone.now() - timedelta(minutes=30)
    ).delete()

    if request.method == "POST" and 'register' in request.POST:
        form = RegistrationForm(request.POST)
        if form.is_valid():
            try:
                # Удаление неактивных пользователей с таким email
                CustomUser.objects.filter(
                    email=form.cleaned_data['email'],
                    is_active=False
                ).delete()
                with transaction.atomic():
                    user = form.save(commit=False)
                    user.is_active = False
                    user.save()
                    code = EmailConfirmation.generate_code()
                    EmailConfirmation.objects.create(user=user, code=code)
                    # Отладка: проверить, доходит ли до отправки письма
                    print(f"Отправка кода {code} на {user.email}")
                    send_mail(
                        'Код подтверждения регистрации',
                        f'Ваш код подтверждения: {code}\nКод действителен 15 минут.',
                        settings.DEFAULT_FROM_EMAIL,
                        [user.email],
                        fail_silently=False,
                    )
                    request.session['registration_user_id'] = user.id
                    request.session.set_expiry(1800)
                    return render(request, 'accounts/register.html', {
                        'code_sent': True,
                        'email': user.email,
                        'form': RegistrationForm()
                    })
            except Exception as e:
                # Логирование ошибки
                print(f"Ошибка регистрации: {str(e)}")
                messages.error(request, f'Ошибка регистрации: {str(e)}')
                return redirect('register')
        else:
            # Отладка: вывести ошибки формы
            print(f"Ошибки формы: {form.errors}")
            messages.error(request, 'Пожалуйста, исправьте ошибки в форме.')
            return render(request, 'accounts/register.html', {
                'form': form,
                'code_sent': False
            })
    elif request.method == "POST" and 'verify' in request.POST:
        user_id = request.session.get('registration_user_id')
        if not user_id:
            messages.error(request, 'Сессия регистрации истекла. Начните заново.')
            return redirect('register')
        try:
            with transaction.atomic():
                user = CustomUser.objects.get(pk=user_id, is_active=False)
                confirmation = EmailConfirmation.objects.filter(
                    user=user,
                    is_used=False
                ).latest('created_at')
                entered_code = request.POST.get('confirmation_code', '').strip()
                if not entered_code:
                    messages.error(request, 'Введите код подтверждения')
                    return render(request, 'accounts/register.html', {
                        'code_sent': True,
                        'email': CustomUser.objects.get(pk=user_id).email,
                        'form': RegistrationForm()
                    })
                if confirmation.code != entered_code:
                    messages.error(request, 'Неверный код подтверждения')
                elif confirmation.is_expired():
                    messages.error(request, 'Срок действия кода истёк. Начните регистрацию заново.')
                    user.delete()
                    del request.session['registration_user_id']
                else:
                    user.is_active = True
                    user.save()
                    confirmation.is_used = True
                    confirmation.save()
                    del request.session['registration_user_id']
                    messages.success(request, 'Регистрация завершена! Можете войти.')
                    return redirect('login')
                return render(request, 'accounts/register.html', {
                    'code_sent': True,
                    'email': user.email,
                    'form': RegistrationForm()
                })
        except CustomUser.DoesNotExist:
            del request.session['registration_user_id']
            messages.error(request, 'Сессия истекла')
            return redirect('register')
        except EmailConfirmation.DoesNotExist:
            messages.error(request, 'Код подтверждения не найден. Начните заново.')
            return redirect('register')
    else:
        user_id = request.session.get('registration_user_id')
        if user_id:
            try:
                user = CustomUser.objects.get(pk=user_id, is_active=False)
                if user.date_joined < timezone.now() - timedelta(minutes=30):
                    user.delete()
                    del request.session['registration_user_id']
                    messages.info(request, 'Сессия регистрации истекла.')
                    return redirect('register')
                return render(request, 'accounts/register.html', {
                    'code_sent': True,
                    'email': user.email,
                    'form': RegistrationForm()
                })
            except CustomUser.DoesNotExist:
                del request.session['registration_user_id']
        return render(request, 'accounts/register.html', {'form': RegistrationForm()})

@require_POST
@csrf_protect
def resend_confirmation_code(request):
    try:
        data = json.loads(request.body)
        email = data.get('email')

        # Удаляем все предыдущие неактивные регистрации
        inactive_users = CustomUser.objects.filter(
            email=email,
            is_active=False,
            date_joined__lt=timezone.now() - timedelta(minutes=30)
        ).delete()

        user = CustomUser.objects.filter(email=email, is_active=False).first()
        if not user:
            return JsonResponse({
                'success': False,
                'error': 'Сессия регистрации истекла. Начните заново.'
            }, status=410)  # Gone

        # Проверка временного интервала (1 минута)
        if EmailConfirmation.objects.filter(
            user=user,
            created_at__gte=timezone.now() - timedelta(minutes=1)
        ).exists():
            return JsonResponse({
                'success': False,
                'error': 'Код уже отправлен'
            }, status=429)

        # Создаем новый код
        new_code = EmailConfirmation.generate_code()
        EmailConfirmation.objects.create(user=user, code=new_code)

        # Отправляем email
        send_mail(
            'Новый код подтверждения',
            f'Ваш новый код подтверждения: {new_code}\nКод действителен 15 минут.',
            settings.DEFAULT_FROM_EMAIL,
            [email],
            fail_silently=False,
        )

        return JsonResponse({
            'success': True,
            'message': 'Код отправлен повторно'
        })

    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Неверный формат данных'
        }, status=400)

    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': 'Произошла ошибка при обработке запроса'
        }, status=500)

def login_view(request):
    if request.method == "POST":
        print(f"Received POST data: {request.POST}")
        form = LoginForm(data=request.POST)
        if form.is_valid():
            user = form.get_user()
            auth_code = generate_confirmation_code()
            request.session['auth_user_id'] = user.id
            request.session['auth_code'] = auth_code
            request.session.set_expiry(300)
            send_mail(
                'Код подтверждения входа',
                f'Никому не сообщайте данный код.\nВаш код подтверждения: {auth_code}\nЕго спрашивают ТОЛЬКО мошенники.',
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
                fail_silently=False,
            )
            return JsonResponse({
                'status': 'code_required',
                'message': 'Код отправлен на вашу почту'
            })
        print(f"Form errors: {form.errors.as_json()}")
        return JsonResponse({
            'status': 'error',
            'errors': form.errors.as_json()
        }, status=400)
    return render(request, "accounts/login.html", {"form": LoginForm()})

def verify_auth_code(request):
    if request.method == "POST":
        entered_code = request.POST.get('code', '')
        csrf_token = request.POST.get('csrfmiddlewaretoken', '')
        user_id = request.session.get('auth_user_id')
        stored_code = request.session.get('auth_code')

        print(f"Verifying code: entered={entered_code}, stored={stored_code}, user_id={user_id}")

        if not entered_code or not csrf_token:
            return JsonResponse({'status': 'error', 'message': 'Неверный код или токен'}, status=400)

        if not user_id or not stored_code:
            return JsonResponse({'status': 'error', 'message': 'Сессия истекла'}, status=400)

        if entered_code == stored_code:
            user = CustomUser.objects.get(id=user_id)
            login(request, user)

            # Проверка private_key
            try:
                base64.b64decode(user.private_key)
                print(f"Valid Base64 private_key, length: {len(user.private_key)}")
            except Exception as e:
                print(f"Invalid Base64 private_key: {e}")
                return JsonResponse({'status': 'error', 'message': 'Ошибка ключа'}, status=500)

            request.session['private_key'] = user.private_key
            request.session['key_salt'] = user.key_salt.hex()
            request.session.modified = True
            print(f"Session after login: {request.session.items()}")

            del request.session['auth_user_id']
            del request.session['auth_code']

            return JsonResponse({
                'status': 'success',
                'private_key': user.private_key,
                'key_salt': user.key_salt.hex(),
                'redirect': reverse('chat-home'),
                'debug': {
                    'private_key_length': len(user.private_key),
                    'key_salt_length': len(user.key_salt.hex())
                }
            })

        return JsonResponse({'status': 'error', 'message': 'Неверный код подтверждения'}, status=400)
    return JsonResponse({'status': 'error', 'message': 'Метод не поддерживается'}, status=405)

def logout_view(request):
    logout(request)
    return redirect("login")
