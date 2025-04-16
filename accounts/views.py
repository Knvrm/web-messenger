import json
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
    CustomUser.objects.filter(
        is_active=False,
        date_joined__lt=timezone.now() - timedelta(minutes=30)
    ).delete()
    if request.method == "POST" and 'register' in request.POST:
        form = RegistrationForm(request.POST)
        if form.is_valid():
            try:

                # Удаляем предыдущие незавершенные регистрации для этого email
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

                    send_mail(
                        'Код подтверждения регистрации',
                        f'Ваш код подтверждения: {code}\nКод действителен 15 минут.',
                        settings.DEFAULT_FROM_EMAIL,
                        [user.email],
                        fail_silently=False,
                    )

                    # Сохраняем в сессии только ID пользователя (не email)
                    request.session['registration_user_id'] = user.id
                    request.session.set_expiry(1800)  # 30 минут на подтверждение

                    return render(request, 'accounts/register.html', {
                        'code_sent': True,
                        'email': user.email,  # Только для отображения
                        'form': RegistrationForm()
                    })

            except Exception as e:
                messages.error(request, 'Ошибка регистрации. Попробуйте позже.')
                return redirect('register')

        return render(request, 'accounts/register.html', {
            'form': form,
            'code_sent': False
        })

    # Обработка подтверждения кода
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
                    # Удаляем просроченную регистрацию
                    user.delete()
                    del request.session['registration_user_id']
                else:
                    # Финальное подтверждение
                    user.is_active = True
                    user.save()
                    confirmation.is_used = True
                    confirmation.save()

                    # Очистка сессии
                    del request.session['registration_user_id']

                    messages.success(request, 'Регистрация завершена! Можете войти.')
                    return redirect('login')

        except CustomUser.DoesNotExist:
            del request.session['registration_user_id']
            messages.error(request, 'Сессия истекла')
            return redirect('register')

    # GET запрос
    else:
        user_id = request.session.get('registration_user_id')
        if user_id:
            try:
                user = CustomUser.objects.get(pk=user_id, is_active=False)
                # Проверяем, не истекла ли сессия
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
        form = LoginForm(data=request.POST)
        if form.is_valid():
            user = form.get_user()

            # Генерируем и отправляем код
            auth_code = generate_confirmation_code()
            request.session['auth_user_id'] = user.id
            request.session['auth_code'] = auth_code
            request.session.set_expiry(300)  # 5 минут на ввод кода

            send_mail(
                'Код подтверждения входа',
                f'Ваш код подтверждения: {auth_code}',
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
                fail_silently=False,
            )

            return JsonResponse({
                'status': 'code_required',
                'message': 'Код отправлен на вашу почту'
            })

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

        if not entered_code or not csrf_token:
            return JsonResponse({'status': 'error', 'message': 'Неверный код или токен'}, status=400)

        if not user_id or not stored_code:
            return JsonResponse({
                'status': 'error',
                'message': 'Сессия истекла'
            }, status=400)

        if entered_code == stored_code:
            user = CustomUser.objects.get(id=user_id)
            login(request, user)

            # Очищаем сессию
            del request.session['auth_user_id']
            del request.session['auth_code']

            return JsonResponse({
                'status': 'success',
                'redirect': reverse('chat-home')
            })

        return JsonResponse({
            'status': 'error',
            'message': 'Неверный код подтверждения'
        }, status=400)

def logout_view(request):
    logout(request)
    return redirect("login")
