from django.db.models.signals import pre_delete
from django.dispatch import receiver
from .models import EmailConfirmation, CustomUser

@receiver(pre_delete, sender=CustomUser)
def delete_user_confirmations(sender, instance, **kwargs):
    EmailConfirmation.objects.filter(user=instance).delete()