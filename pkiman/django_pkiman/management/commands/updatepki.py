from django.core.management import BaseCommand

from django_pkiman.utils.download import update_handle


class Command(BaseCommand):
    help = "Обновление списков отзывов сертификатов по URL, согласно установленному периоду времени в задаче"

    def handle(self, *args, **options):
        try:
            update_handle()
        except Exception as e:
            print(e)
