from django.urls import path
from . import views

urlpatterns = [
    path('', views.chat_home, name='chat-home'),
    path('create/', views.create_chat, name='create-chat'),
    path('get-users/', views.get_users_for_chat, name='get-users'),
    path('<int:room_id>/send/', views.send_message, name='send-message'),
    path('settings/', views.chat_settings, name='chat_settings'),
    path('rename/<int:chat_id>/', views.rename_chat, name='rename-chat'),
    path('<int:chat_id>/leave/', views.leave_chat, name='leave_chat'),
]