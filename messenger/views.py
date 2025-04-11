from django.shortcuts import render, redirect
from django.contrib.auth import logout

def home(request):
    if request.user.is_authenticated:
        return redirect("chat-home")   # Название маршрута для авторизованных
    return redirect("login")  # Название маршрута для неавторизованных

def placeholder(request):
    return render(request, "placeholder.html")  # Заглушка

def logout_view(request):
    logout(request)
    return redirect("login")  # После выхода отправляем на страницу логина

