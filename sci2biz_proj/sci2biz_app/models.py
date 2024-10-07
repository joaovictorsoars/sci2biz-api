from uuid import uuid4
from django.db import models
from django.utils import timezone
from pytz import timezone as pytz_timezone


class Roles(models.Model):
    """Model definition for Roles."""
    role_id = models.AutoField(primary_key=True)
    role_name = models.CharField(max_length=100, null=False)

class Users(models.Model):
    """Model definition for Users."""
    user_id = models.BigAutoField(primary_key=True)
    full_name = models.CharField(max_length=255, null=False)
    email = models.EmailField(max_length=255, unique=True, null=False)
    role_id = models.ForeignKey(Roles, on_delete=models.CASCADE, null=False)
    is_active = models.BooleanField(default=True, null=False)
    created_at = models.DateTimeField(null=False)
    public_id = models.UUIDField(default=uuid4, editable=False, unique=True, null=False)
    password = models.CharField(max_length=255, null=False)

    def save(self, *args, **kwargs):
        if not self.created_at:
            self.created_at = timezone.now().astimezone(pytz_timezone("America/Sao_Paulo"))
        return super(Users, self).save(*args, **kwargs)