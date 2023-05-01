from django.contrib import admin
from django.contrib.auth.models import Group, User
from django.http import HttpResponseRedirect

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


class CrtAdmin(admin.ModelAdmin):
    """"""
    ordering = ('issuer',)
    list_display = ('cn',
                    'subject_identifier',
                    'serial',
                    'valid_after',
                    'valid_before',
                    )

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def response_delete(self, request, obj_display, obj_id):
        next = request.GET.get('next')
        if next:
            return HttpResponseRedirect(next)
        response = super().response_delete(request, obj_display, obj_id)
        return response


class CrlAdmin(admin.ModelAdmin):
    """"""
    form = CrlModelForm
    ordering = ('issuer',)
    save_as_continue = False
    save_as = False
    list_display = ('issuer_name', 'issuer_subject_identifier', 'last_update', 'next_update', 'schedule', 'active')
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
                       ('active', 'no_proxy'),
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

    @admin.display
    def issuer_name(self, obj):
        return obj.issuer.name()

    @admin.display
    def issuer_subject_identifier(self, obj):
        return obj.issuer.subject_identifier

    def has_add_permission(self, request):
        return False

    def response_change(self, request, obj):
        next = request.GET.get('next')
        if next:
            return HttpResponseRedirect(next)
        response = super().response_change(request, obj)
        return response

    def response_delete(self, request, obj_display, obj_id):
        next = request.GET.get('next')
        if next:
            return HttpResponseRedirect(next)
        response = super().response_delete(request, obj_display, obj_id)
        return response


class CrlUpdateScheduleAdmin(admin.ModelAdmin):
    """"""
    form = CrlUpdateScheduleModelForm
    ordering = ('name',)
    list_display = ('name', 'dow', 'std', 'etd', 'active')

    def response_change(self, request, obj):
        next = request.GET.get('next')
        if next:
            return HttpResponseRedirect(next)
        response = super().response_change(request, obj)
        return response

    def response_delete(self, request, obj_display, obj_id):
        next = request.GET.get('next')
        if next:
            return HttpResponseRedirect(next)
        response = super().response_delete(request, obj_display, obj_id)
        return response


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
