from django.shortcuts import render, redirect
from django.contrib.auth import logout

def home(request):
    if request.user.is_authenticated:
        return redirect("chat-home")
    return redirect("login")

def logout_view(request):
    logout(request)
    return redirect("login")

