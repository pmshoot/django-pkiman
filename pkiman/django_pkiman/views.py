import urllib.parse
from datetime import datetime
from pathlib import Path

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin, PermissionRequiredMixin
from django.db import IntegrityError
from django.middleware import csrf
from django.urls import reverse_lazy, resolve
from django.views.generic import ListView, RedirectView, TemplateView
from django.views.generic.detail import SingleObjectMixin
from django.conf import settings

from django_pkiman import forms, models
from django_pkiman.errors import PKIError, PKIUrlError
from django_pkiman.models import Proxy
from django_pkiman.utils.download import get_from_url, get_from_url_list, update_crl
from django_pkiman.utils.logger import logger
from django_pkiman.utils.pki_parser import PKIObject


class IndexView(ListView):
    template_name = 'django-pkiman/index.html'
    url = '/'

    def setup(self, request, *args, **kwargs):
        self.pki_type = request.GET.get('pki', 'crt')
        super().setup(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        kwargs['url_path'] = self.url
        kwargs['pki_type'] = self.pki_type
        return super().get_context_data(**kwargs)

    def get_queryset(self):
        """"""
        if self.pki_type == 'crt':
            return models.Crt.objects.all()
        elif self.pki_type == 'crl':
            return models.Crl.objects.all()


class ManagementModeMixin:
    def get_context_data(self, **kwargs):
        kwargs['mgmt'] = True
        return super().get_context_data(**kwargs)


class ManagementView(RedirectView):
    pattern_name = 'pkiman:reestr'

    def get_redirect_url(self, *args, **kwargs):
        url = super().get_redirect_url(*args, **kwargs)
        pki = self.request.GET.get('pki')
        if pki:
            return f'{url}?pki={pki}'
        return url


class ManagementReestrView(LoginRequiredMixin, ManagementModeMixin, IndexView):
    """"""
    url = reverse_lazy('pkiman:reestr')
    template_name = 'django-pkiman/mgmt/reestr.html'


class ManagementUploadsView(LoginRequiredMixin, ManagementModeMixin, TemplateView):
    """"""
    file_form = forms.ManagementLocalUploadsForm
    url_form = forms.ManagementURLUploadsForm
    template_name = 'django-pkiman/mgmt/upload.html'

    def get_url_form(self, form=None):
        if not form:
            form = self.url_form()
        form.fields['proxy'].choices = Proxy.objects.get_form_choices()
        return form

    def get_context_data(self, file_form=None, url_form=None, **kwargs):
        kwargs['file_form'] = file_form or self.file_form
        kwargs['url_form'] = self.get_url_form(url_form)
        kwargs['csrf_token'] = csrf.get_token(self.request)
        return super().get_context_data(**kwargs)

    def post(self, request, *args, **kwargs):
        action = request.POST.get('action')

        if action == 'file_uploads':
            form = self.file_form(request.POST, request.FILES)
            if form.is_valid():
                up_file = form.cleaned_data['file']
                return self._handel_uploaded_file(request, up_file)
            else:
                context = self.get_context_data(file_form=form)
                return self.render_to_response(context=context)

        elif action == 'url_uploads':
            form = self.url_form(request.POST, request.FILES)
            form = self.get_url_form(form)
            if form.is_valid():
                file_url = form.cleaned_data['file']
                proxy_id = form.cleaned_data.get('proxy') or None
                if proxy_id:
                    proxy = models.Proxy.objects.get(pk=proxy_id)
                    proxy_url = proxy.get_url()
                else:
                    proxy_url = None

                try:
                    up_file, _ = get_from_url(file_url, proxy=proxy_url)
                except PKIUrlError as e:
                    messages.error(request, e)
                    context = self.get_context_data(url_form=form)
                    return self.render_to_response(context=context)
                return self._handel_uploaded_file(request, up_file)
            else:
                context = self.get_context_data(url_form=form)
                return self.render_to_response(context=context)

        else:
            message = 'Форма загрузки файлов: попытка загрузки файла неопознанного типа'
            logger.error(message)
            messages.warning(request, message)
            return self.render_to_response(self.get_context_data())

    def _handel_uploaded_file(self, request, up_file):
        pki = PKIObject()
        pki.read_x509(up_file)
        try:
            if pki.pki_type == 'crt':
                model = models.Crt
            else:
                model = models.Crl
            object, created = model.objects.get_from_pki(pki)

            if created:
                message = f'Файл "{pki.pki_type}::{object}" успешно загружен'
            else:
                if pki.pki_type == 'crt':
                    message = f'Файл "{pki.pki_type}::{object}" был загружен ранее {object.created_at}'
                    logger.warn(message)
                    messages.warning(request, message)
                    return self.render_to_response(self.get_context_data())
                message = f'Файл "{pki.pki_type}::{object}" успешно обновлен'
            logger.info(message)
            messages.success(request, message)
            return self.render_to_response(self.get_context_data())

        except (PKIError, FileExistsError) as e:
            message = e
        except IntegrityError as e:
            # Дублирование subject_dn и serial
            if 'UNIQUE constraint failed' in e.__str__():
                message = f'Ошибка добавления дубликата сертификата {pki}'
            else:
                message = f'Ошибка загрузки сертификата: {e}'
        logger.error(message)
        messages.error(request, message)
        return self.render_to_response(self.get_context_data())


class ManagementUpdateCrl(LoginRequiredMixin, PermissionRequiredMixin, ManagementModeMixin, RedirectView):
    permission_required = 'crl:change_crl'
    pattern_name = 'pkiman:reestr'
    query_string = True
    model = models.Crl

    def get(self, request, *args, **kwargs):
        """"""
        pk = kwargs.get('pk')
        try:
            crl = models.Crl.objects.get(pk=pk)
            crl = update_crl(crl)
            message = f'Список отзыва {crl} успешно обновлен'
            logger.info(message)
            messages.success(request, message)
        except PKIError as e:
            messages.error(request, e.__str__())
        except Exception as e:
            messages.error(request, f'Ошибка при загрузке файла: {e}')
        return super().get(request)


class ManagementGetParentCrt(LoginRequiredMixin, PermissionRequiredMixin, SingleObjectMixin, RedirectView):
    permission_required = 'crl:add_crt'
    pattern_name = 'pkiman:reestr'
    query_string = True
    model = models.Crt

    def get(self, request, *args, **kwargs):
        object: 'models.Crt' = self.get_object()
        proxy = Proxy.objects.get_default_proxy_url()
        parent_crt = None
        # сертификат без родителя, не корневой и есть ссылка на родительский сертификат
        if not object.is_bound() and object.auth_info:
            try:
                url_list = object.auth_info.values()
                up_file = get_from_url_list(url_list, proxy=proxy)
                pki = PKIObject()
                pki.read_x509(up_file)
                parent_crt, _ = self.model.objects.get_from_pki(pki)
                message = f'Сертификат "ID:{parent_crt.subject_identifier}" успешно загружен'
                logger.info(message)
                messages.success(request, message)

                # попытка загрузить список отзыва при успешной загрузке сертификата
                if object.cdp_info and parent_crt:
                    url_list = [cdp[0] for cdp in object.cdp_info.values()]
                    up_file = get_from_url_list(url_list, proxy=proxy)
                    pki.read_x509(up_file)
                    parent_crl, _ = models.Crl.objects.get_from_pki(pki)
                    parent_crl.urls = ','.join(url_list)
                    parent_crl.save()
                    message = f'Список отзыва сертификата "ID:{parent_crt.subject_identifier}" успешно загружен'
                    logger.info(message)
                    messages.success(request, message)

            except PKIError as e:
                messages.error(request, e)

        return super().get(request, *args)


class ManagementJournalView(LoginRequiredMixin, ManagementModeMixin, ListView):
    """"""
    template_name = 'django-pkiman/mgmt/journal.html'
    model = models.Journal
    paginate_by = 50


class ManagementScheduleView(LoginRequiredMixin, ManagementModeMixin, ListView):
    """"""
    template_name = 'django-pkiman/mgmt/schedule.html'
    model = models.CrlUpdateSchedule
    paginate_by = 25


class ManagementUrlIndexView(LoginRequiredMixin, ManagementModeMixin, TemplateView):
    """"""
    template_name = 'django-pkiman/mgmt/index.html'
    index_file_name = 'index.txt'

    def setup(self, request, *args, **kwargs):
        super().setup(request, *args, **kwargs)
        self.index_file = Path(
            settings.BASE_DIR,
            settings.MEDIA_ROOT,
            self.index_file_name
            )

    def get_store_path(self, request):
        absolute_uri = request.build_absolute_uri()
        server_path = absolute_uri.split(request.path_info.strip('/'))[0]
        store_url = urllib.parse.urljoin(server_path, settings.MEDIA_URL)
        return store_url

    def get_context_data(self, **kwargs):
        if self.index_file.exists():
            file_stat = self.index_file.stat()
            index_file = {
                'fname': self.index_file.name,
                'fsize': file_stat.st_size,
                'fdate': datetime.fromtimestamp(file_stat.st_mtime),
                }
            kwargs['index_file'] = index_file
            kwargs['index_list'] = self.get_index_list(self.request)
        return super().get_context_data(**kwargs)

    def get_index_list(self, request):
        """"""
        index_list = ['# [ХРАНИЛИЩЕ]\t[ТИП]\t[ПУТЬ]\n']
        info_list = (
            ('Корневые сертификаты / СОС', models.Crt.objects.get_root_ca_qs()),
            ('Промежуточные сертификаты / СОС', models.Crt.objects.get_ca_qs()),
            ('Конечные сертификаты / СОС', models.Crt.objects.get_leaf_qs()),
            )
        for info, queryset in info_list:
            index_list.extend(self._generate_index_block(info, queryset))
        return index_list

    def _generate_index_block(self, info, queryset):
        index_block = [f'# ----- {info} {"-" * (140 - len(info))}\n']
        get_index_line = self._get_index_line_wrapper()
        for object in queryset:
            index_block.extend(get_index_line(object))
            if hasattr(object, 'crl'):
                object = object.crl
                index_block.extend(get_index_line(object))
        return index_block

    def _get_index_line_wrapper(self):
        server_path = self.get_store_path(self.request)
        line_template = "{store}\t{type}\t{url}\n"
        data = {}

        def inner(object):
            if object.file_exists():
                data['store'] = object.user_pki_store
                data['type'] = object.user_pki_type
                data['url'] = urllib.parse.urljoin(server_path, object.file.url)
                return [line_template.format(**data)]
            return []

        return inner

    def post(self, request, *args, **kwargs):
        """"""
        index_list = self.get_index_list(request)
        with self.index_file.open('w', encoding='utf-8') as fp:
            fp.writelines(index_list)
        return super().get(request, *args, **kwargs)

    def get_index_list_from_file(self, request):
        if self.index_file.exists():
            with self.index_file.open('rt', encoding='utf-8') as fp:
                yield fp.readline()


class DocsView(TemplateView):
    """"""
    template_name = 'django-pkiman/docs.html'
