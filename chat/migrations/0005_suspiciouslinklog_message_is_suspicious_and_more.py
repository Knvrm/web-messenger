# Generated by Django 5.1.7 on 2025-05-07 18:33

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('chat', '0004_remove_message_encrypted_key_and_more'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='SuspiciousLinkLog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('url', models.TextField()),
                ('reason', models.TextField()),
                ('is_malicious', models.BooleanField(default=False)),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
            ],
            options={
                'ordering': ['-timestamp'],
            },
        ),
        migrations.AddField(
            model_name='message',
            name='is_suspicious',
            field=models.BooleanField(default=False),
        ),
        migrations.AddIndex(
            model_name='message',
            index=models.Index(fields=['is_suspicious'], name='chat_messag_is_susp_d6f38c_idx'),
        ),
        migrations.AddField(
            model_name='suspiciouslinklog',
            name='room',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='chat.chatroom'),
        ),
        migrations.AddField(
            model_name='suspiciouslinklog',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddIndex(
            model_name='suspiciouslinklog',
            index=models.Index(fields=['timestamp'], name='chat_suspic_timesta_2f5036_idx'),
        ),
        migrations.AddIndex(
            model_name='suspiciouslinklog',
            index=models.Index(fields=['user'], name='chat_suspic_user_id_e24ffc_idx'),
        ),
    ]
