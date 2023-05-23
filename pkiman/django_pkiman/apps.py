from django.apps import AppConfig
from django.contrib.admin.apps import AdminConfig


class DjangoPkimanConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'django_pkiman'
    verbose_name = 'PKI менеджер'


class PKIAdminConfig(AdminConfig):
    default_site = "django_pkiman.admin.PKIAdminSite"
