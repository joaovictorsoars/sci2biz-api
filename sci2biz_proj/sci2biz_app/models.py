from uuid import uuid4
from django.db import models
from django.utils import timezone
from pytz import timezone as pytz_timezone
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin

class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        return self.create_user(email, password, **extra_fields)

class Roles(models.Model):
    """Model definition for Roles."""
    role_id = models.AutoField(primary_key=True)
    role_name = models.CharField(max_length=100, null=False)

class Users(AbstractBaseUser, PermissionsMixin):
    """Model definition for Users."""
    id = models.BigAutoField(primary_key=True)
    full_name = models.CharField(max_length=255, null=False)
    email = models.EmailField(max_length=255, unique=True, null=False)
    role_id = models.ForeignKey(Roles, on_delete=models.CASCADE, null=False)
    is_active = models.BooleanField(default=True, null=False)
    is_staff = models.BooleanField(default=False, null=False)
    created_at = models.DateTimeField(null=False)
    public_id = models.UUIDField(default=uuid4, editable=False, unique=True, null=False)
    password = models.CharField(max_length=255, null=False)
    refresh_token = models.CharField(max_length=255, null=True)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['full_name', 'role_id']

    def save(self, *args, **kwargs):
        if not self.created_at:
            self.created_at = timezone.now().astimezone(pytz_timezone("America/Sao_Paulo"))
        return super(Users, self).save(*args, **kwargs)