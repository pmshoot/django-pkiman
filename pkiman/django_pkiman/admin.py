from django.contrib import admin, messages
from django.http import HttpResponseRedirect
from django.urls import reverse_lazy

from django_pkiman.forms import CrlModelForm, CrlUpdateScheduleModelForm, ProxyModelForm, CrtModelForm
from django_pkiman.models import Crl, CrlUpdateSchedule, Crt, Proxy, PKITag


class PKIAdminSite(admin.AdminSite):
    site_header = 'PKI manager - администратор'
    site_title = 'PKI manager - администратор'
    site_url = reverse_lazy('pkiman:index')

    def each_context(self, request):
        context = super().each_context(request)
        context['site_url'] = self.get_site_url(request)
        return context

    def get_site_url(self, request):
        next = request.GET.get('next')
        if next:
            return next
        return self.site_url


pki_admin = PKIAdminSite(name='pkiadmin')


class PKIModelAdminMixin:

    def response_delete(self, request, obj_display, obj_id):
        next = request.GET.get('next')
        if next:
            return HttpResponseRedirect(next)
        return super().response_delete(request, obj_display, obj_id)

    def response_change(self, request, obj):
        next = request.GET.get('next')
        if next:
            return HttpResponseRedirect(next)
        return super().response_change(request, obj)


@admin.register(Crt, site=pki_admin)
class CrtAdmin(PKIModelAdminMixin, admin.ModelAdmin):
    """"""
    form = CrtModelForm
    ordering = ('path',)
    list_display = ('title',
                    'subject_identifier',
                    'tag_list',
                    'serial',
                    'valid_before',
                    'file_exists',
                    )
    readonly_fields = ('subject_identifier',
                       'subject_dn_as_text_nl',
                       'subject_serial_number',
                       'fingerprint',
                       'valid_after',
                       'valid_before',
                       'cdp_info',
                       'auth_info',
                       'issuer_identifier',
                       'issuer_dn_as_text_nl',
                       'issuer_serial_number',
                       'issuer',
                       'file',
                       'is_ca',
                       'is_root_ca',
                       'revoked_date',
                       'created_at',
                       'file_exists',
                       )
    actions = None
    view_on_site = False
    search_fields = ('subject_identifier', 'subject_dn__commonName')
    search_help_text = 'введите часть наименования или идентификационного номера сертификата'
    date_hierarchy = "valid_before"
    fieldsets = [
        ('Субъект', {
            # 'description': '',
            'classes': ('wide',),
            'fields': ('subject_identifier',
                       'subject_dn_as_text_nl',
                       'subject_serial_number',
                       'fingerprint',
                       'valid_after',
                       'valid_before',
                       'cdp_info',
                       'auth_info',
                       )
            }),
        ('Издатель', {
            # 'description': '',
            'classes': ('wide',),
            'fields': ('issuer_identifier',
                       'issuer_dn_as_text_nl',
                       'issuer_serial_number',
                       'issuer',
                       )
            }),
        ('Объект', {
            'classes': ('wide',),
            'fields': ('file',
                       'is_ca',
                       'is_root_ca',
                       'revoked_date',
                       'created_at',
                       'file_exists',
                       'comment',
                       )
            }),
        ('Тегирование', {
            'fields': ('tags',),
            }),
        ]

    @admin.display(description='Наименование')
    def title(self, obj):
        if obj.is_root_ca:
            return obj.cn + ' (root)'
        return obj.cn

    @admin.display(description='DN')
    def subject_dn_as_text_nl(self, obj):
        return obj.subject_as_text_nl()

    @admin.display(description='Серийный номер')
    def subject_serial_number(self, obj):
        return obj.serial_number_hex()

    @admin.display(description='DN')
    def issuer_dn_as_text_nl(self, obj):
        return obj.issuer_as_text_nl()

    @admin.display(description='Серийный номер')
    def issuer_serial_number(self, obj):
        return obj.issuer_serial_number_hex()

    @admin.display(description='файл', boolean=True)
    def file_exists(self, obj):
        return obj.file_exists()

    @admin.display(description='набор тегов')
    def tag_list(self, obj):
        return obj.tag_list()

    def has_add_permission(self, request):
        return False


@admin.register(Crl, site=pki_admin)
class CrlAdmin(PKIModelAdminMixin, admin.ModelAdmin):
    """"""
    form = CrlModelForm
    ordering = ('issuer',)
    save_as_continue = False
    save_as = False
    actions = None
    view_on_site = False
    list_select_related = ('issuer', 'schedule')
    search_fields = ('issuer__subject_identifier', 'issuer__subject_dn__commonName')
    search_help_text = 'введите часть наименования или идентификационного номера сертификата, относящегося к списку'
    date_hierarchy = "next_update"
    list_display = ('issuer_name',
                    'issuer_subject_identifier',
                    'tag_list',
                    'next_update',
                    'schedule',
                    'active',
                    'file_exists')
    readonly_fields = ('issuer',
                       'fingerprint',
                       'file',
                       'crl_number',
                       'revoked_count',
                       'last_update',
                       'next_update',
                       'f_date',
                       'f_size',
                       'f_etag',
                       'f_sync',
                       )
    fieldsets = [
        ('Данные списка отзыва', {
            # 'description': '',
            'classes': ('wide',),
            'fields': ('issuer',
                       'fingerprint',
                       'crl_number',
                       'file',
                       'revoked_count',
                       'last_update',
                       'next_update',
                       )
            }),
        ('Обновление', {
            # 'description': '',
            'classes': ('wide',),
            'fields': ('urls',
                       'schedule',
                       'proxy',
                       'active',
                       'no_proxy',
                       'comment',
                       )
            }),
        ('Данные синхронизации', {
            # 'description': ''
            'classes': ('wide',),
            'fields': ('f_date',
                       'f_etag',
                       'f_size',
                       'f_sync',
                       )
            }),
        ('Тегирование', {
            'fields': ('tags',),
            }),
        ]

    @admin.display(description='Наименование')
    def issuer_name(self, obj):
        return obj.issuer.name()

    @admin.display
    @admin.display(description='Идентификатор')
    def issuer_subject_identifier(self, obj):
        return obj.issuer.subject_identifier

    @admin.display(description='файл', boolean=True)
    def file_exists(self, obj):
        return obj.file_exists()

    @admin.display(description='набор тегов')
    def tag_list(self, obj):
        return obj.tag_list()

    def has_add_permission(self, request):
        return False

    def delete_queryset(self, request, queryset):
        for obj in queryset:
            try:
                obj.delete()
                obj.update_from_db()
            except FileExistsError as e:
                self.message_user(request, e, level=messages.WARNING)


@admin.register(CrlUpdateSchedule, site=pki_admin)
class CrlUpdateScheduleAdmin(PKIModelAdminMixin, admin.ModelAdmin):
    """"""
    form = CrlUpdateScheduleModelForm
    ordering = ('name',)
    list_display = ('name', 'dow', 'std', 'etd', 'active')


@admin.register(Proxy, site=pki_admin)
class ProxyAdmin(admin.ModelAdmin):
    """"""
    form = ProxyModelForm
    ordering = ('name',)
    list_display = ('name', 'url', 'is_default')


@admin.register(PKITag, site=pki_admin)
class TagAdmin(admin.ModelAdmin):
    """"""
    readonly_fields = ('slug',)
    list_display = ('name', 'desc')
