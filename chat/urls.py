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
    path('<int:chat_id>/remove_user/', views.remove_user_from_chat, name='remove_user_from_chat'),
    path('get-public-key/<int:user_id>/', views.get_public_key, name='get_public_key'),
    path('get-session-key/<int:chat_id>/', views.get_session_key, name='get_session_key'),
    path('get-last-message/<int:chat_id>/', views.get_last_message, name='get-last-message'),
    path('tokenize/', views.tokenize_text, name='tokenize_text'),
    path('settings/blacklist/', views.get_blacklist, name='get-blacklist'),
    path('settings/blacklist/add/', views.add_to_blacklist, name='add-to-blacklist'),
    path('settings/blacklist/remove/', views.remove_from_blacklist, name='remove-from-blacklist'),
    path('get-user-status/<int:user_id>/', views.get_user_status, name='get-user-status'),
    path('settings/update-privacy/', views.update_privacy, name='update-privacy'),
    path('upload-file/', views.upload_file, name='upload_file'),
    path('check-file-hash/', views.check_file_hash, name='check_file_hash'),
    path('upload-and-check-file/', views.upload_and_check_file, name='upload_and_check_file'),
]