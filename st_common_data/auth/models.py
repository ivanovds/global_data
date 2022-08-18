from django.contrib.auth.models import AbstractUser
from django.db import models


class User(AbstractUser):
    auth0 = models.CharField(
        max_length=24,
        db_index=True, unique=True,
        verbose_name='Auth0 ID')
    updated = models.DateTimeField(
        auto_now=True, verbose_name='Updated')

    class Meta(AbstractUser.Meta):
        swappable = "AUTH_USER_MODEL"

    def __str__(self):
        return f'{self.username} | {self.auth0}'
