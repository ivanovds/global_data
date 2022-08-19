from django.contrib.auth import get_user_model
from django.db import models

UserModel = get_user_model()


# Account management system models
class FIDAbstract(models.Model):
    fid = models.IntegerField(
        unique=True,
        verbose_name='Foreign ID')

    class Meta:
        abstract = True

    def __str__(self):
        return str(self.fid)


class TradingAccountDetailsAbstract(FIDAbstract):
    name = models.CharField(max_length=63, unique=True)

    class Meta:
        abstract = True

    def __str__(self):
        return self.name


class Clearing(TradingAccountDetailsAbstract):
    pass


class Company(TradingAccountDetailsAbstract):
    pass


class Broker(TradingAccountDetailsAbstract):
    pass


class Source(TradingAccountDetailsAbstract):
    pass


class TradingAccount(FIDAbstract):
    ENABLED = 0
    DISABLED = 1
    PAUSED = 2

    STATUS_CHOICES = (
        (ENABLED, 'ENABLED'),
        (DISABLED, 'DISABLED'),
        (PAUSED, 'PAUSED'),
    )

    fid = models.IntegerField(
        unique=True,
        verbose_name='Foreign ID')

    user = models.ForeignKey(
        UserModel, on_delete=models.PROTECT,
        null=True, blank=True, default=None,
        related_name='owner_user')

    account = models.CharField(
        unique=True,
        max_length=255)

    broker = models.ForeignKey(
        Broker, on_delete=models.PROTECT)
    company = models.ForeignKey(
        Company, on_delete=models.PROTECT)
    clearing = models.ForeignKey(
        Clearing, on_delete=models.PROTECT)
    source = models.ForeignKey(
        Source, on_delete=models.PROTECT,
        verbose_name='Executions source')

    status = models.PositiveSmallIntegerField(
        default=0, choices=STATUS_CHOICES,
        verbose_name='Status')
    type = models.CharField(
        null=True, blank=True, default=None,
        max_length=63)
    service_status = models.BooleanField(
        default=False,
        verbose_name='Is service account')
    service_start_date = models.DateField(
        null=True, blank=True, default=None,
        verbose_name='Service account start operation')

    created_by = models.ForeignKey(
        UserModel, on_delete=models.PROTECT,
        null=True, blank=True, default=None,
        related_name='created_by_user',
        verbose_name='Created by')
    created = models.DateTimeField(
        auto_now_add=True, verbose_name='Created')
    updated = models.DateTimeField(
        auto_now=True, verbose_name='Updated')

    class Meta:
        verbose_name = 'Trading account'
        verbose_name_plural = 'Trading accounts'

    def __str__(self):
        return self.account
