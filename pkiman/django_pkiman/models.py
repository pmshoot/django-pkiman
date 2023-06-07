import datetime

from django.conf import settings
from django.contrib import admin
from django.core.exceptions import MultipleObjectsReturned
from django.db import models, transaction
from django.db.models import Q
from django.db.models.indexes import Index
from django.db.models.signals import post_delete, pre_save
from django.dispatch import receiver
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from taggit.managers import TaggableManager
from taggit.models import TagBase, GenericTaggedItemBase
from treebeard.mp_tree import MP_Node, MP_NodeManager

from django_pkiman.errors import PKICrtDoesNotFoundError, PKICrtMultipleFoundError, PKIDuplicateError, PKIOldError
from django_pkiman.utils import clean_file_name
from django_pkiman.utils.pki_parser import PKIObject

DEFAULT_JOURNAL_LAST_RECORDS = 50
DEFAULT_PKIMAN_MAX_OLD_PKI_TIME = getattr(settings, 'PKIMAN_MAX_OLD_PKI_TIME', 12)


# todo - путь cdp вынести в настройки для возможности смены
def get_upload_file_path(instance, *args):
    return f'cdp/{instance.upload_file_path()}'


# Tags model
class PKITag(TagBase):
    desc = models.TextField('Описание', blank=True)

    class Meta:
        verbose_name = _("Tag")
        verbose_name_plural = _("Tags")


class TaggedPKI(GenericTaggedItemBase):
    tag = models.ForeignKey(
        PKITag,
        on_delete=models.CASCADE,
        related_name="%(app_label)s_%(class)s_items",
        )


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

            # обновляем, в случае отсутствия файла на диске
            if not object.file_exists():
                object.file = pki.up_file
                object.save()
                created = True

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
                        serial=pki.issuer_serial_number
                        )
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

    def get_root_ca_qs(self):
        return self.filter(is_root_ca=True, is_ca=True).prefetch_related('crl', 'tags')

    def get_ca_qs(self):
        return self.filter(is_root_ca=False, is_ca=True).prefetch_related('crl', 'tags')

    def get_leaf_qs(self):
        return self.filter(is_root_ca=False, is_ca=False)

    def get_reestr(self):
        return self.get_queryset()

    def get_critical_count(self):
        max_datetime = timezone.now() + datetime.timedelta(hours=DEFAULT_PKIMAN_MAX_OLD_PKI_TIME)
        return self.filter(Q(valid_before__lte=max_datetime) | Q(revoked_date__isnull=False)).count()


class PKIAddonsMixin:
    def get_absolute_url(self):
        if self.file_exists():
            return self.file.url
        return '#'

    def file_exists(self):
        return bool(self.file.name) and self.file.storage.exists(self.file.name)

    def tag_list(self):
        if self.tags.exists():
            return ', '.join(self.tags.all().values_list('slug', flat=True))
        return ''


# Models
class Crt(PKIAddonsMixin, MP_Node):
    """Сертификаты"""
    subject_identifier = models.CharField('идентификатор субъекта',
                                          max_length=128, null=True, db_index=True)
    issuer_identifier = models.CharField('идентификатор издателя',
                                         max_length=128, null=True)
    subject_dn = models.JSONField()
    serial = models.CharField('серийный номер', max_length=128)  # todo change to subject_serial_number
    issuer_dn = models.JSONField()
    issuer_serial = models.CharField(max_length=128, null=True)  # todo change to issuer_serial_number
    issuer = models.ForeignKey('self', verbose_name='привязка к издателю',
                               on_delete=models.SET_NULL, null=True, related_name='children')
    fingerprint = models.CharField('отпечаток', max_length=64, unique=True)
    file = models.FileField('ссылка на файл', upload_to=get_upload_file_path)
    valid_after = models.DateTimeField('Действителен с')
    valid_before = models.DateTimeField('Действителен до')
    is_ca = models.BooleanField('удостоверяющий', default=False)
    is_root_ca = models.BooleanField('корневой', default=False)
    revoked_date = models.DateTimeField('отозван', null=True)
    cdp_info = models.JSONField('точки распространения СОС УЦ', null=True)
    auth_info = models.JSONField('точки распространения УЦ', null=True)
    created_at = models.DateTimeField('загружен', auto_now_add=True, editable=False)
    comment = models.TextField('комментарий', blank=True)

    objects = CrtManager()
    tags = TaggableManager(blank=True, through=TaggedPKI)
    node_order_by = ['subject_dn']

    class Meta:
        verbose_name = 'Сертификат'
        verbose_name_plural = 'Сертификаты'
        unique_together = ('issuer_dn', 'serial')  # RFC 5280 4.1.2.2
        permissions = [('pki_admin', 'Администратор PKI')]
        indexes = (
            Index(name='crt_filter_orphans_idx', fields=('issuer_dn',
                                                         'issuer_identifier',
                                                         'issuer',
                                                         'is_root_ca',
                                                         )),
            Index(name='crt_get_by_type', fields=('is_root_ca',
                                                  'is_ca',
                                                  )),
            )

    def __str__(self):
        return self.name()

    def name(self):
        return self.cn or self.subject_as_text()

    @property
    @admin.display(description='Наименование')
    def cn(self):
        return self.subject_dn.get('commonName')

    @property
    @admin.display(description='Наименование')
    def issuer_cn(self):
        return self.issuer_dn.get('commonName')

    def subject_as_text(self):
        return ', '.join([f'{k}={v.strip()}' for k, v in self.subject_dn.items()])

    def subject_as_text_nl(self):
        return ',\n'.join([f'{k}={v.strip()}' for k, v in self.subject_dn.items()])

    def issuer_as_text_nl(self):
        return ',\n'.join([f'{k}={v.strip()}' for k, v in self.issuer_dn.items()])

    def serial_number_hex(self):
        return f'{int(self.serial):x}'

    def issuer_serial_number_hex(self):
        if self.issuer_serial:
            return f'{int(self.issuer_serial):x}'

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

    @property
    def user_pki_store(self):
        """Тип хранилища на ПК пользователя для записи в индекс-файл"""
        if self.is_root_ca:
            return 'Root'
        if self.is_ca:
            return 'CA'
        return 'AddressBook'

    @property
    def user_pki_type(self):
        return 'CRT'

    def get_cdp_list(self):
        if self.auth_info:
            cdp_list = self.auth_info.get('caIssuers')
            if not cdp_list:
                return
            if isinstance(cdp_list, str):
                cdp_list = [cdp_list]
            return cdp_list

    def come_to_end(self):
        max_hours_to_end = DEFAULT_PKIMAN_MAX_OLD_PKI_TIME
        remains = self.valid_before - timezone.now()
        return remains < datetime.timedelta(hours=max_hours_to_end)

    # todo - add func для проверки наличия файла на диске


@receiver(post_delete, sender=Crt, weak=False)
def delete_crt_object(sender, instance: Crt, **kwargs):
    """Удаляет файл на диске после удаления объекта"""
    if hasattr(instance, 'file'):
        try:
            instance.file.delete(False)
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

    def get_root_ca_qs(self):
        return self.filter(issuer__is_root_ca=True, issuer__is_ca=True)

    def get_ca_qs(self):
        return self.filter(issuer__is_root_ca=False, issuer__is_ca=True)

    def get_reestr(self):
        return self.get_queryset().order_by('issuer__path')

    def get_critical_count(self):
        max_datetime = timezone.now() + datetime.timedelta(hours=DEFAULT_PKIMAN_MAX_OLD_PKI_TIME)
        return self.filter(next_update__lte=max_datetime).count()


class Crl(PKIAddonsMixin, models.Model):
    """Списки отзыва"""
    issuer = models.OneToOneField('Crt', verbose_name='Сертификат', on_delete=models.CASCADE, related_name='crl')
    fingerprint = models.CharField('отпечаток', max_length=64, unique=True)
    file = models.FileField('ссылка на файл', upload_to=get_upload_file_path)
    crl_number = models.TextField('номер', null=True)
    last_update = models.DateTimeField('обновлен')
    next_update = models.DateTimeField('следующее обновление')
    revoked_count = models.IntegerField('количество отозванных сертификатов', default=0)
    # update info section
    urls = models.TextField('URL',
                            help_text='список URL для загрузки обновленных файлов через запятую',
                            blank=True)
    active = models.BooleanField('обновляемый',
                                 help_text='при установленной опции обновляется по выбранному расписанию и может '
                                           'обновлять со страницы сайта',
                                 default=False)
    schedule = models.ForeignKey(
        'CrlUpdateSchedule',
        verbose_name='расписание',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='crl_list')
    proxy = models.ForeignKey(
        'Proxy',
        verbose_name='прокси сервер',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        )
    no_proxy = models.BooleanField('не использовать прокси', default=False)
    created_at = models.DateTimeField(auto_now_add=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True, editable=False)
    comment = models.TextField('комментарий', blank=True)
    # last remote file data
    f_date = models.DateTimeField('дата файла', null=True)
    f_size = models.PositiveSmallIntegerField('размер файла', null=True)
    f_etag = models.CharField('хэш файла', max_length=128, null=True)
    f_sync = models.DateTimeField('дата последней синхронизации', null=True)

    objects = CrlManager()
    tags = TaggableManager(blank=True, through=TaggedPKI)

    class Meta:
        verbose_name = 'Список отзыва'
        verbose_name_plural = 'Списки отзыва'
        ordering = ('issuer',)

    def __str__(self):
        return self.issuer.upload_file_name()

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

    def come_to_end(self):
        max_hours_to_end = DEFAULT_PKIMAN_MAX_OLD_PKI_TIME
        remains = self.next_update - timezone.now()
        return remains < datetime.timedelta(hours=max_hours_to_end)

    @property
    def user_pki_store(self):
        """Тип хранилища на ПК пользователя для записи в индекс-файл"""
        if self.issuer.is_root_ca:
            return 'Root'
        return 'CA'

    @property
    def user_pki_type(self):
        return 'CRL'


@receiver(post_delete, sender=Crl, weak=False)
def delete_crl_object(sender, instance: Crl, **kwargs):
    """Удаление файла на диске после удаления объекта"""
    if hasattr(instance, 'file'):
        try:
            instance.file.delete(False)
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
    name = models.CharField('наименование',
                            max_length=64)
    dow = models.JSONField('дни недели',
                           help_text='используйте JSON формат. Например: [1,2,3,4,5]',
                           )  # todo доработать для удобства ввода данных
    # dom = models.JSONField('числа месяца') # todo add in the future
    std = models.TimeField('начало временного диапазона')
    etd = models.TimeField('конец временного диапазона')
    is_active = models.BooleanField('активный',
                                    help_text='при активации данное расписание будет использовано планировщиков при '
                                              'запуске обновлений',
                                    default=True)
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

    def get_active(self):
        return self.filter(is_active=True)

    def get_form_choices(self):
        yield '', '-----'
        if self.get_active().exists():
            for proxy in self.get_active():
                yield proxy.pk, proxy.name


class Proxy(models.Model):
    name = models.CharField('наименование',
                            help_text='краткое наименование сервера для отображения в списке',
                            max_length=128)
    url = models.URLField('url адрес',
                          help_text='например: http://my.proxy.server:3128',
                          null=True)
    proxy_user = models.CharField('пользователь',
                                  max_length=128,
                                  blank=True,
                                  null=True)
    proxy_pass = models.CharField('пароль',
                                  max_length=64,
                                  blank=True,
                                  null=True)
    is_default = models.BooleanField('по-умолчанию',
                                     help_text='при выборе данный прокси сервер будет использоваться по-умолчанию при загрузке файлов',
                                     default=False,
                                     db_index=True)
    is_active = models.BooleanField('действующий прокси',
                                    default=True,
                                    help_text='при отключенной опции данный прокси сервер не будет отображаться в '
                                              'списке доступных серверов'
                                    )

    objects = ProxyManager()

    class Meta:
        verbose_name = 'Прокси-сервер'
        verbose_name_plural = 'Прокси'
        ordering = ('name',)

    def __str__(self):
        return self.name

    def get_url(self):
        if self.proxy_user and self.proxy_pass:
            scheme, path = self.url.split('://')
            return f'{scheme}://{self.proxy_user}:{self.proxy_pass}@{path}'
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
