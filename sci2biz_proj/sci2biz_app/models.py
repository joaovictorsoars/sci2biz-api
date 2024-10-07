from uuid import uuid4
from django.db import models


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
    created_at = models.DateTimeField(auto_now_add=True, null=False)
    public_id = models.UUIDField(default=uuid4, editable=False, unique=True, null=False)
    password = models.CharField(max_length=255, null=False)