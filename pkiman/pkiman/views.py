import urllib.parse
from datetime import datetime
from functools import lru_cache
from pathlib import Path

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin, PermissionRequiredMixin
from django.db import IntegrityError
from django.db.models import Q
from django.middleware import csrf
from django.urls import reverse_lazy
from django.views.generic import ListView, RedirectView, TemplateView
from django.views.generic.detail import SingleObjectMixin
from django.views.generic.edit import FormMixin

from pkiman import forms, models
from pkiman.errors import PKIError, PKIUrlError
from pkiman.forms import SearchForm
from pkiman.models import Proxy
from pkiman.utils.download import get_from_url, get_from_url_list, update_crl
from pkiman.utils.logger import logger
from pkiman.utils.pki_parser import PKIObject


class MgmtModeMixin:
    def get_context_data(self, **kwargs):
        if self.request.user.has_perm('pkiman:pki_admin'):
            kwargs['mgmt'] = True
        return super().get_context_data(**kwargs)


class MgmtAccessMixin(PermissionRequiredMixin, LoginRequiredMixin):
    """"""
    permission_required = 'pkiman:pki_admin'


class IndexView(MgmtModeMixin, FormMixin, ListView):
    template_name = 'pkiman/index.html'
    paginate_by = getattr(settings, 'PKIMAN_PAGINATE_BY', 20)
    form_class = SearchForm
    url = reverse_lazy('pkiman:index')

    def setup(self, request, *args, **kwargs):
        self.pki_type = request.GET.get('pki', 'crt')
        super().setup(request, *args, **kwargs)

    def get_form_kwargs(self):
        kwargs = {
            "initial": self.get_initial(),
            "prefix": self.get_prefix(),
            "data": self.request.GET,
            }
        return kwargs

    def get_context_data(self, **kwargs):
        kwargs = super().get_context_data(**kwargs)
        kwargs['url_path'] = self.url
        kwargs['pki_type'] = self.pki_type  # todo перенести в query и переделать шаблоны
        kwargs['query'] = f'pki={self.pki_type}'

        # добавляем предков первого объекта, при наличии, чтобы не разрывать цепочку
        if self.pki_type == 'crt' and self.object_list and self.object_list.exists():
            first_object = self.object_list[0]
            ancestors = first_object.get_ancestors()
            if ancestors.count() > 0:
                queryset = ancestors | self.object_list
                kwargs['object_list'] = queryset.order_by('path')

        return kwargs

    def get(self, request, *args, **kwargs):
        """"""
        form = self.get_form()
        qs = self.get_queryset()

        if form.is_valid():
            s = form.cleaned_data['s']
            if not s:
                pass
            elif s.startswith('tag:'):
                tag = s.split(':')[1]
                if tag:
                    qs = qs.filter(tags__slug__in=[tag])
            else:
                if self.pki_type == 'crt':
                    qs = qs.filter(Q(subject_dn__commonName__icontains=s)
                                   | Q(subject_identifier__icontains=s))
                else:
                    qs = qs.filter(Q(issuer__subject_dn__commonName__icontains=s)
                                   | Q(issuer__subject_identifier__icontains=s))

        self.object_list = qs
        context = self.get_context_data(form=form)
        return self.render_to_response(context)

    def get_queryset(self):
        """"""
        if self.pki_type == 'crt':
            model = models.Crt
        elif self.pki_type == 'crl':
            model = models.Crl
        else:
            return models.Crt.objects.none()
        return model.objects.get_reestr()


class ManagementUploadsView(MgmtAccessMixin, MgmtModeMixin, TemplateView):
    """"""
    file_form = forms.ManagementLocalUploadsForm
    url_form = forms.ManagementURLUploadsForm
    template_name = 'pkiman/mgmt/upload.html'

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
                message = f'Файл "{pki.pki_type}::{object}" загружен'
            else:
                if pki.pki_type == 'crt':
                    message = f'Файл "{pki.pki_type}::{object}" был загружен ранее {object.created_at}'
                    logger.warn(message)
                    messages.warning(request, message)
                    return self.render_to_response(self.get_context_data())
                message = f'Файл "{pki.pki_type}::{object}" обновлен'
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
        except Exception as e:
            message = e
        logger.error(message)
        messages.error(request, message)
        return self.render_to_response(self.get_context_data())


class ManagementUpdateCrl(MgmtAccessMixin, MgmtModeMixin, RedirectView):
    pattern_name = 'pkiman:index'
    query_string = True
    model = models.Crl

    def get(self, request, *args, **kwargs):
        """"""
        pk = kwargs.get('pk')
        try:
            crl = models.Crl.objects.get(pk=pk)
            crl = update_crl(crl)
            message = f'Список отзыва {crl} обновлен'
            logger.info(message)
            messages.success(request, message)
        except PKIError as e:
            messages.error(request, e.__str__())
        except Exception as e:
            messages.error(request, f'Ошибка при загрузке файла: {e}')
        return super().get(request)


class ManagementGetParentCrt(MgmtAccessMixin, SingleObjectMixin, RedirectView):
    pattern_name = 'pkiman:index'
    query_string = True
    model = models.Crt

    def get(self, request, *args, **kwargs):
        object: 'models.Crt' = self.get_object()
        proxy = Proxy.objects.get_default_proxy_url()
        # сертификат без родителя, не корневой и есть ссылка на родительский сертификат
        if not object.is_bound() and object.auth_info:
            cdp_list = object.get_cdp_list()
            if cdp_list:
                try:
                    up_file = get_from_url_list(cdp_list, proxy=proxy)
                    pki = PKIObject()
                    pki.read_x509(up_file)
                    parent_crt, _ = self.model.objects.get_from_pki(pki)
                    message = f'Сертификат "ID:{parent_crt.subject_identifier}" загружен'
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
                        message = f'Список отзыва сертификата "ID:{parent_crt.subject_identifier}" загружен'
                        logger.info(message)
                        messages.success(request, message)

                except PKIError as e:
                    messages.error(request, e)

        return super().get(request, *args)


class ManagementJournalView(MgmtAccessMixin, MgmtModeMixin, ListView):
    """"""
    template_name = 'pkiman/mgmt/journal.html'
    model = models.Journal
    paginate_by = 50


class ManagementScheduleView(MgmtAccessMixin, MgmtModeMixin, ListView):
    """"""
    template_name = 'pkiman/mgmt/schedule.html'
    model = models.CrlUpdateSchedule
    paginate_by = 25


class ManagementUrlIndexView(MgmtAccessMixin, MgmtModeMixin, TemplateView):
    """"""
    store_nginx_use_https = getattr(settings, 'PKIMAN_STORE_NGINX_USE_HTTPS', False)
    template_name = 'pkiman/mgmt/index_file.html'
    index_file_name = 'index.txt'

    def setup(self, request, *args, **kwargs):
        super().setup(request, *args, **kwargs)
        self.index_file = Path(
            settings.BASE_DIR,
            settings.MEDIA_ROOT,
            self.index_file_name
            )

    @lru_cache
    def get_store_scheme(self):
        return 'https' if self.store_nginx_use_https else 'http'

    def get_store_path(self, request):
        absolute_uri = request.build_absolute_uri()
        server_path = absolute_uri.split(request.path_info.strip('/'))[0]
        _, addr = server_path.split('://')
        scheme = self.get_store_scheme()
        server_path = f'{scheme}://{addr}'
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
        index_list = ['# [ХРАНИЛИЩЕ]\t[ТИП]\t[ПУТЬ]\t[ТЕГИ]\n']
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
        line_template = "{store}\t{type}\t{url}\t{tags}\n"
        data = {}

        def inner(object):
            if object.file_exists():
                data['store'] = object.user_pki_store
                data['type'] = object.user_pki_type
                data['url'] = urllib.parse.urljoin(server_path, object.file.url)
                data['tags'] = object.tag_list()
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
    template_name = 'pkiman/docs.html'
