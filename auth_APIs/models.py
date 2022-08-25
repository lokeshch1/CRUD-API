from datetime import timedelta

from django.utils import timezone
from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser, AbstractUser, PermissionsMixin


from django.utils.translation import gettext_lazy as _


# Create your models here.
class CustomAccountManager(BaseUserManager):
    def create_user(self, email, password=None, is_active=True, is_superuser=False, is_staff=False, **extra_fields):
        # Creates and saves a User with the given email and password.
        if not email:
            raise ValueError('Users must have an Email')
        user = self.model(
            email=email, is_active=is_active, is_superuser=is_superuser, is_staff=is_staff, **extra_fields
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password, **extra_fields):
        user = self.create_user(email, password=password, is_active=True, is_superuser=True, is_staff=True,
                                **extra_fields)
        user.save(using=self._db)
        return user


class User(AbstractBaseUser, PermissionsMixin):
    firstName = models.CharField(max_length=255, null=True)
    lastName = models.CharField(max_length=255, null=True)
    companyName = models.CharField(max_length=255, null=True, blank=True)
    email = models.EmailField(max_length=255, unique=True, null=False)
    age = models.IntegerField(null=True, blank=True)
    city = models.CharField(max_length=255, null=True)
    state = models.CharField(max_length=255, null=True)
    password = models.CharField(max_length=255, null=True)
    zip = models.IntegerField(null=True, blank=True)
    web = models.CharField(max_length=255, null=True)
    is_superuser = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['firstName', 'lastName']
    objects = CustomAccountManager()
    date_joined = models.DateTimeField(_('date joined'), default=timezone.now)
    updated_at = models.DateTimeField(_('date updated'), default=timezone.now)

    def __str__(self):
        return self.email

    class Meta:
        db_table = 'users'

