from django.urls import path
from . import views

urlpatterns = [
    path('', views.chat_home, name='chat-home'),
    path('create/', views.create_chat, name='create-chat'),
    path('<int:room_id>/send/', views.send_message, name='send-message'),
    path('<int:room_id>/add/', views.add_to_group, name='add-to-group'),
]