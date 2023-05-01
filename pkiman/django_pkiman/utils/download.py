# Загрузка файла из сети по URL
import itertools
import mimetypes
from io import BytesIO
from urllib.parse import urlsplit

import requests
from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import InMemoryUploadedFile, TemporaryUploadedFile
from django.core.validators import URLValidator
from django.db import transaction
from django.utils import timezone

from django_pkiman.errors import PKIDuplicateError, PKIUrlConnectionError, PKIUrlContentTypeInvalid, PKIUrlError, \
    PKIUrlInvalid
from django_pkiman.models import Crl, CrlUpdateSchedule
from django_pkiman.utils import mime_content_type_map
from django_pkiman.utils.logger import logger
from django_pkiman.utils.pki_parser import PKIObject

USER_AGENT = 'PKIManager/0.1'
HEADERS = {'user-agent': USER_AGENT}


def validate_url(url: str) -> None:
    validate = URLValidator()
    try:
        validate(url)
    except ValidationError:
        raise PKIUrlInvalid(value=url)


def define_filename_content_type(url: str) -> tuple:
    filename = urlsplit(url).path.split('/')[-1]
    content_type, _ = mimetypes.guess_type(url)

    if content_type not in mime_content_type_map:
        raise PKIUrlContentTypeInvalid(value=content_type)

    return filename, content_type


def define_proxy(proxy) -> dict:
    if isinstance(proxy, str):
        proxy = {
            'http': proxy,
            'https': proxy,
        }

    return proxy


def get_from_url(url: str, method: str = 'get', session=None, proxy: 'str | dict | None' = None,
                 headers=None) -> ('InMemoryUploadedFile | TemporaryUploadedFile | None', 'requests.Response | None'):
    """"""
    # check it
    if method not in ('get', 'head'):
        raise PKIUrlError('Неверный метод', value=method)
    validate_url(url)
    filename, content_type = define_filename_content_type(url)
    # set
    proxy = define_proxy(proxy)
    headers = HEADERS if not headers else headers.update(HEADERS)
    handler = session if session else requests
    handler_method = getattr(handler, method)

    try:
        resp: requests.Response = handler_method(url, headers=headers, proxies=proxy)
    except requests.exceptions.RetryError:
        raise PKIUrlConnectionError(message="Превышено допустимое количество попыток соединения с сервером", value=url)
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
        raise PKIUrlConnectionError(value=e)
    else:
        if not resp.status_code == requests.codes.ok:
            raise PKIUrlConnectionError(value=f'{resp.status_code}-{resp.reason}')

    if method == 'head':
        return None, resp

    content_length = int(resp.headers['content-length'])

    if content_length <= settings.FILE_UPLOAD_MAX_MEMORY_SIZE:
        fobj = BytesIO()
        fobj.write(resp.content)
        upfile = InMemoryUploadedFile(
                file=fobj,
                field_name=None,
                name=filename,
                content_type=content_type,
                size=content_length,
                charset=None,
        )
    else:
        upfile = TemporaryUploadedFile(
                name=filename,
                content_type=content_type,
                size=content_length,
                charset='utf-8',
        )
        upfile.write(resp.content)
    upfile.seek(0)
    logger.info(f'Загружен файл {url}, size={upfile.size}, elapsed={resp.elapsed}')
    return upfile, resp


def get_from_url_list(urls_list: list, proxy=None) -> tuple:
    """Загрузка файла из первого удачного URl по списку"""
    last_error = None
    for url in urls_list:
        try:
            up_file, _ = get_from_url(url, proxy=proxy)
            return up_file
        except PKIUrlError as e:
            logger.error(f'get_from_url_list url:{url} {e}')
            last_error = e
            continue
    if last_error:
        raise PKIUrlError(last_error)


def update_crl(crl: 'Crl'):
    proxy = crl.get_proxy()
    has_updates = False
    last_error = None
    with requests.Session() as session:
        for url in crl.get_urls_list():
            try:
                # check updates on site by etag or size header
                _, resp = get_from_url(url, 'head', session, proxy)
                r_etag = resp.headers.get('etag')
                r_date = timezone.datetime.strptime(resp.headers.get('date'), '%a, %d %b %Y %H:%M:%S %Z')
                if r_etag and r_etag != crl.f_etag:
                    has_updates = True
                elif r_date and r_date != crl.f_date:
                    has_updates = True

                if has_updates:
                    # get updated file
                    try:
                        up_file, _ = get_from_url(url, proxy=proxy, session=session)
                        pki = PKIObject()
                        pki.read_x509(up_file)

                        with transaction.atomic():
                            crl, _ = crl.__class__.objects.get_from_pki(pki)
                            crl.f_etag = r_etag
                            crl.f_date = r_date
                            crl.f_sync = timezone.now()
                            crl.save()

                        if last_error:
                            last_error = None
                        break
                    except PKIUrlConnectionError as e:
                        logger.error(f'update_crl::get url:{url} {e}')
                        last_error = e
                        continue

            except PKIUrlConnectionError as e:
                logger.error(f'update_crl::head url:{url} {e}')
                last_error = e
                continue

    if last_error:
        raise PKIUrlError(value=e)

    return crl


def update_handle():
    """Обработчик задачи обновления файлов CRL. Запускается crontab'ом по заданным настройкам в settings"""
    task_qs = CrlUpdateSchedule.objects.get_tasks()
    if not task_qs.exists():
        return
    msg = f'Cron update crl: <{0}>, {1}'
    for crl in itertools.chain(*[task.crl_list.all() for task in task_qs.all()]):
        try:
            up_file = update_crl(crl)
            if not up_file:
                continue
            #
            pki = PKIObject()
            pki.read_x509(up_file)
            object, _ = Crl.objects.get_from_pki(pki, up_file)
            logger.info(msg.format(crl, 'success'))
        except PKIDuplicateError as e:
            logger.warn(message=f'Cron update crl <{crl}>, {e}')
        except Exception as e:
            logger.error(message=f'Cron update crl <{crl}>, {e}')
