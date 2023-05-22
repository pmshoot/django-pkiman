import datetime
import os

from django.contrib import admin
from django.core.exceptions import MultipleObjectsReturned
from django.db import models, transaction
from django.db.models.signals import post_delete, pre_save
from django.db.models.indexes import Index
from django.dispatch import receiver
from django.utils import timezone
from treebeard.mp_tree import MP_Node, MP_NodeManager
from treebeard.ns_tree import NS_Node

from django_pkiman.errors import PKICrtDoesNotFoundError, PKICrtMultipleFoundError, PKIDuplicateError, PKIOldError
from django_pkiman.utils import clean_file_name
from django_pkiman.utils.pki_parser import PKIObject

DEFAULT_JOURNAL_LAST_RECORDS = 50


# todo - путь cdp вынести в настройки для возможности смены
def get_upload_file_path(instance, *args):
    return f'cdp/{instance.upload_file_path()}'


# Managers
class CrtManager(MP_NodeManager):
    """"""

    @transaction.atomic
    def get_from_pki(self, pki: 'PKIObject') -> ('Crt', bool):
        """Чтение данных из объекта PKIObject сертификата, чтение или создание нового,
        поиск родительских или дочерних и привязка
        """
        created = False
        try:
            object = self.get(
                subject_dn=pki.subject,
                serial=pki.subject_serial_number
                )

        except self.model.DoesNotExist:
            created = True
            pki_data = {
                'subject_identifier': pki.subject_identifier,
                'subject_dn': pki.subject,
                'serial': pki.subject_serial_number,
                'issuer_identifier': pki.issuer_identifier,
                'issuer_dn': pki.issuer,
                'issuer_serial': pki.issuer_serial_number,
                'fingerprint': pki.fingerprint,
                'valid_after': pki.not_valid_before,
                'valid_before': pki.not_valid_after,
                'is_ca': pki.CA,
                'is_root_ca': pki.is_root,
                'cdp_info': pki.cdp_info,
                'auth_info': pki.auth_info,
                'file': pki.up_file
                }

            # корневой сертификат сам себе родитель
            if pki.is_root:
                object = self.model.add_root(**pki_data)
            else:
                try:
                    # если есть в БД сертификат subject == issuer добавляемого сертификата - присвоить его как родителя
                    issuer: Crt = self.get(
                        subject_dn=pki.issuer,
                        subject_identifier=pki.issuer_identifier)
                    object: Crt = issuer.add_child(**pki_data)
                    object.issuer = issuer
                    object.save()
                except self.model.DoesNotExist:
                    # Иначе оставляем сертификат как сироту в корне
                    object = self.model.add_root(**pki_data)

            # Найти "битые" сертификаты без родителя и установить издателя у сертификатов с таким же issuer_identifier
            if pki.CA:
                orphans = self.filter(
                    issuer_dn=pki.subject,
                    issuer_identifier=pki.subject_identifier,
                    issuer=None,
                    is_root_ca=False)
                if orphans.exists():
                    for orphan in orphans.all():
                        orphan.move(object, pos='sorted-child')
                    object.refresh_from_db()
                    orphans.update(issuer=object)

        return object, created


# Models
class Crt(MP_Node):
    """Сертификаты"""
    subject_identifier = models.CharField(max_length=128, null=True, db_index=True)
    issuer_identifier = models.CharField(max_length=128, null=True)
    subject_dn = models.JSONField()
    serial = models.CharField('серийный номер', max_length=128)  # todo change to subject_serial_number
    issuer_dn = models.JSONField()
    issuer_serial = models.CharField(max_length=128, null=True)  # todo change to issuer_serial_number
    issuer = models.ForeignKey('self', on_delete=models.SET_NULL, null=True, related_name='children')
    fingerprint = models.CharField(max_length=64, unique=True)
    file = models.FileField(upload_to=get_upload_file_path)
    valid_after = models.DateTimeField()
    valid_before = models.DateTimeField()
    is_ca = models.BooleanField(default=False)
    is_root_ca = models.BooleanField(default=False)
    revoked_date = models.DateTimeField(null=True)
    cdp_info = models.JSONField(null=True)
    auth_info = models.JSONField(null=True)
    created_at = models.DateTimeField(auto_now_add=True, editable=False)

    objects = CrtManager()
    node_order_by = ['subject_dn']

    class Meta:
        verbose_name = 'Сертификат'
        verbose_name_plural = 'Сертификаты'
        unique_together = ('issuer_dn', 'serial')  # RFC 5280 4.1.2.2
        indexes = (
            Index(name='crt_get_issuer_idx', fields=('subject_dn', 'subject_identifier')),
            Index(name='crt_filter_orphans_idx', fields=('issuer_dn',
                                                         'issuer_identifier',
                                                         'issuer',
                                                         'is_root_ca',
                                                         )),
            Index(name='crl_get_issuer_crt', fields=('subject_dn',
                                                     'subject_identifier',
                                                     'serial'))
            )

    def __str__(self):
        return self.name()

    def name(self):
        return self.cn or self.subject_as_text()

    def get_absolute_url(self):
        return self.file.url

    @property
    def cn(self):
        return self.subject_dn.get('commonName')

    @property
    def issuer_cn(self):
        return self.issuer_dn.get('commonName')

    def subject_as_text(self):
        return ', '.join([f'{k}={v.strip()}' for k, v in self.subject_dn.items()])

    def serial_number_hex(self):
        return f'{int(self.serial):x}'

    def is_valid_date(self):
        return self.valid_after < timezone.make_aware(datetime.datetime.now()) < self.valid_before

    def is_valid(self):
        """Есть привязка к родительскому сертификату, не просрочен и не отозван"""
        if self.is_root():
            if not self.is_valid_date() or self.is_revoked():
                return False
        else:
            if self.issuer and not self.issuer.is_valid():
                return False
            else:
                if not self.issuer or not self.is_valid_date() or self.is_revoked():
                    return False
        return True

    def is_bound(self):
        """Есть привязка к родительскому сертификату. Корневой привязан сам к себе"""
        return self.is_root_ca or self.issuer is not None

    def is_revoked(self):
        return self.revoked_date is not None

    def is_final(self):
        """Конечный сертификат - не корневой и не промежуточный"""
        return not (self.is_root_ca or self.is_ca)

    def upload_file_name(self):
        """"""
        if self.subject_identifier is not None:
            name = self.subject_identifier
        else:
            name = f'{clean_file_name(self.cn)}_{self.fingerprint}' if self.cn else self.fingerprint
        serial_hex = self.serial_number_hex()
        return f'{name}_{serial_hex}'

    def upload_file_path(self):
        """"""
        name = self.upload_file_name()
        ftype = 'crt'
        return f'{ftype}/{name}.{ftype}'

    # todo - add func для проверки наличия файла на диске


@receiver(post_delete, sender=Crt, weak=False)
def delete_crt_object(sender, instance: Crt, **kwargs):
    """Удаляет файл на диске после удаления объекта"""
    fpath = instance.file.file.name
    if os.path.exists(fpath):
        try:
            os.unlink(fpath)
        except Exception:
            pass


class CrlManager(models.Manager):
    """"""

    @transaction.atomic
    def get_from_pki(self, pki):
        """Возвращает новый или существующий Crl. Обновляет существующий"""
        try:
            issuer = Crt.objects.get(subject_dn=pki.issuer,
                                     subject_identifier=pki.issuer_identifier)
        except Crt.DoesNotExist:
            # todo заменить после переработки класса PKIObject
            raise PKICrtDoesNotFoundError(value=pki.issuer_identifier)

        except MultipleObjectsReturned:
            if pki.issuer_serial_number:
                try:
                    issuer = Crt.objects.get(subject_dn=pki.issuer,
                                             subject_identifier=pki.issuer_identifier,
                                             serial=pki.issuer_serial_number,
                                             )
                except Crt.DoesNotExist:
                    raise PKICrtDoesNotFoundError(value=pki.issuer_identifier)
                except MultipleObjectsReturned:
                    raise PKICrtMultipleFoundError(value=pki.issuer_identifier)

        object, created = self.get_or_create(
            issuer=issuer,
            defaults={
                'crl_number': pki.crl_number,
                'fingerprint': pki.fingerprint,
                'last_update': pki.last_update,
                'next_update': pki.next_update,
                'revoked_count': len(pki.revoked_list),
                'file': pki.up_file,
                }
            )

        if not created:
            if pki.fingerprint == object.fingerprint:
                raise PKIDuplicateError(value=f'fingerprint={pki.fingerprint}')
            if (pki.crl_number and object.crl_number >= pki.crl_number) or object.last_update >= pki.last_update:
                raise PKIOldError

            # update exists crl
            object.crl_number = pki.crl_number
            object.fingerprint = pki.fingerprint
            object.last_update = pki.last_update
            object.next_update = pki.next_update
            object.revoked_count = len(pki.revoked_list)
            object.file = pki.up_file
            object.save()

        return object, created


class Crl(models.Model):
    """Списки отзыва"""
    issuer = models.OneToOneField('Crt', on_delete=models.CASCADE, related_name='crl')
    fingerprint = models.CharField(max_length=64, unique=True)
    file = models.FileField(upload_to=get_upload_file_path)
    crl_number = models.TextField(null=True)
    last_update = models.DateTimeField()
    next_update = models.DateTimeField()
    revoked_count = models.IntegerField(default=0)
    # update info section
    urls = models.CharField(max_length=128, blank=True)
    active = models.BooleanField(default=False)
    schedule = models.ForeignKey(
        'CrlUpdateSchedule',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='crl_list')
    proxy = models.ForeignKey(
        'Proxy',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        )
    no_proxy = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True, editable=False)
    edited_at = models.DateTimeField(auto_now=True, editable=False)
    # last remote file data
    f_date = models.DateTimeField(null=True)
    f_size = models.PositiveSmallIntegerField(null=True)
    f_etag = models.CharField(max_length=128, null=True)
    f_sync = models.DateTimeField(null=True)

    objects = CrlManager()

    class Meta:
        verbose_name = 'Список отзыва'
        verbose_name_plural = 'Списки отзыва'
        ordering = ('issuer',)

    def __str__(self):
        return self.issuer.upload_file_name()

    def get_absolute_url(self):
        return self.file.url

    def is_valid(self):
        return timezone.now() < self.next_update

    def get_urls_list(self):
        if self.urls:
            return [url.strip() for url in self.urls.split(',')]

    def get_proxy(self):
        if not self.no_proxy and self.proxy:
            return self.proxy.get_url()

    def upload_file_path(self):
        """"""
        name = self.issuer.upload_file_name()
        ftype = 'crl'
        return f'{ftype}/{name}.{ftype}'


@receiver(post_delete, sender=Crl, weak=False)
def delete_crl_object(sender, instance: Crl, **kwargs):
    """Удаление файла на диске после удаления объекта"""
    fpath = instance.file.file.name
    if os.path.exists(fpath):
        try:
            os.unlink(fpath)
        except Exception:
            pass


@receiver(pre_save, sender=Crl, weak=False)
def set_proxy_crl_object(sender, instance: Crl, **kwargs):
    """При установке опции 'no_proxy' удаляет существующую ссылку на инстанс прокси-сервера.
    При снятии установленной опции 'no_proxy' устанавливает прокси-сервер по-умолчанию, если у
    одного из прокси установлена опция 'is_default'
    """
    if instance.no_proxy and instance.proxy:
        instance.proxy = None
    elif not instance.no_proxy and not instance.proxy:
        try:
            proxy = Proxy.objects.get_default_proxy()
            instance.proxy = proxy
        except (Proxy.DoesNotExist, MultipleObjectsReturned):
            pass


###

class CrlUpdateSchedulerManager(models.Manager):
    def get_tasks(self):
        nowday = timezone.datetime.now()
        # weekday = nowday.isoweekday()
        return self.filter(crl_list__isnull=False,
                           is_active=True,
                           # dow__contains=weekday,
                           std__lte=nowday,
                           etd__gte=nowday,
                           )


class CrlUpdateSchedule(models.Model):
    """"""
    name = models.CharField(max_length=64)
    dow = models.JSONField('дни недели')
    # dom = models.JSONField('числа месяца') # todo add in the future
    std = models.TimeField('начало временного диапазона')
    etd = models.TimeField('конец временного диапазона')
    is_active = models.BooleanField(default=True)
    # todo коэффициент определяющий кол-во раз в день

    objects = CrlUpdateSchedulerManager()

    class Meta:
        verbose_name = 'Расписание'
        verbose_name_plural = 'Расписание'
        ordering = ('name',)
        indexes = (
            Index(name='crl_schedule_get_tasks_idx', fields=('is_active', 'std', 'etd')),
        )

    def __str__(self):
        return self.name

    @admin.display(boolean=True)
    def active(self):
        return self.is_active


class ProxyManager(models.Manager):

    def get_default_proxy_url(self):
        proxy = self.get_default_proxy()
        if proxy:
            return proxy.get_url()

    def get_default_proxy(self):
        try:
            proxy = self.get(is_default=True)
            return proxy
        except Exception:
            pass


class Proxy(models.Model):
    name = models.CharField(max_length=128)
    url = models.URLField(null=True)
    username = models.CharField(max_length=128, blank=True, null=True)
    password = models.CharField(max_length=64, blank=True, null=True)
    is_default = models.BooleanField(default=False, db_index=True)

    objects = ProxyManager()

    class Meta:
        verbose_name = 'Прокси-сервер'
        verbose_name_plural = 'Прокси'
        ordering = ('name',)

    def __str__(self):
        return f'{self.username}:***@{self.url}' if self.username else self.url

    def get_url(self):
        if self.username and self.password:
            scheme, path = self.url.split('://')
            return f'{scheme}://{self.username}:{self.password}@{path}'
        return self.url

    def get_url_map(self):
        return {
            'http': self.get_url(),
            'https': self.get_url()
            }


class JournalManager(models.Manager):

    def create_record(self, level: 'JournalTypeChoices', message: str):
        self.create(level=level, message=message)

    def last(self, count=DEFAULT_JOURNAL_LAST_RECORDS):
        return self.get_queryset()[:count]

    def last_5(self):
        return self.last(5)

    def last_10(self):
        return self.last(10)

    def last_30(self):
        return self.last(30)


class JournalTypeChoices(models.TextChoices):
    INFO = 'I', "ИНФО"
    WARN = 'W', "Предупреждение"
    ERROR = 'E', "Ошибка"


class Journal(models.Model):
    created_at = models.DateTimeField(auto_now=True, editable=False, db_index=True)
    level = models.CharField(max_length=1, choices=JournalTypeChoices.choices,
                             default=JournalTypeChoices.INFO, db_index=True)
    message = models.TextField()

    objects = JournalManager()

    class Meta:
        verbose_name = 'Запись журнала'
        verbose_name_plural = 'Журнал'
        ordering = ('-created_at',)
