import os

from django.contrib import admin, messages
from django.contrib.auth.models import Group, User
from django.http import HttpResponseRedirect
from treebeard.admin import TreeAdmin
from django_pkiman.forms import CrlModelForm, CrlUpdateScheduleModelForm, ProxyModelForm
from django_pkiman.models import Crl, CrlUpdateSchedule, Crt, Proxy


class PKIAdminSite(admin.AdminSite):
    site_header = 'PKI manager - администратор'
    site_title = 'PKI manager - администратор'
    site_url = '/reestr/'

    def each_context(self, request):
        context = super().each_context(request)
        context['site_url'] = self.get_site_url(request)
        return context

    def get_site_url(self, request):
        next = request.GET.get('next')
        if next:
            return next
        return self.site_url


admin_site = PKIAdminSite(name='pkiadmin')


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


class CrtAdmin(PKIModelAdminMixin, admin.ModelAdmin):
    """"""
    ordering = ('issuer',)
    list_display = ('cn',
                    'subject_identifier',
                    'serial',
                    'valid_after',
                    'valid_before',
                    'file_exists',
                    )
    actions = None
    fieldsets = [
        ('Субъект', {
            # 'description': '',
            'classes': ('wide',),
            'fields': ('subject_identifier',
                       # 'subject_dn',
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
                       )
            }),
        ]

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

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


class CrlAdmin(PKIModelAdminMixin, admin.ModelAdmin):
    """"""
    form = CrlModelForm
    ordering = ('issuer',)
    save_as_continue = False
    save_as = False
    list_display = (
    'issuer_name', 'issuer_subject_identifier', 'last_update', 'next_update', 'schedule', 'active', 'file_exists')
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

    def has_add_permission(self, request):
        return False

    def delete_queryset(self, request, queryset):
        for obj in queryset:
            try:
                obj.delete()
                obj.update_from_db()
            except FileExistsError as e:
                self.message_user(request, e, level=messages.WARNING)


class CrlUpdateScheduleAdmin(PKIModelAdminMixin, admin.ModelAdmin):
    """"""
    form = CrlUpdateScheduleModelForm
    ordering = ('name',)
    list_display = ('name', 'dow', 'std', 'etd', 'active')


class ProxyAdmin(admin.ModelAdmin):
    """"""
    form = ProxyModelForm
    ordering = ('name',)
    list_display = ('name', 'url', 'is_default')


admin_site.register(User)
admin_site.register(Group)
admin_site.register(Crt, CrtAdmin)
admin_site.register(Crl, CrlAdmin)
admin_site.register(CrlUpdateSchedule, CrlUpdateScheduleAdmin)
admin_site.register(Proxy, ProxyAdmin)
