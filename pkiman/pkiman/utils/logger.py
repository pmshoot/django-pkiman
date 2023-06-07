from django.conf import settings
from django.db import transaction
from django.utils import timezone

from pkiman.models import Journal, JournalTypeChoices

DEFAULT_PKIMAN_JOURNAL_STORE_PERIOD = 365


class PKILogger:
    emit = Journal.objects.create_record

    def __init__(self, level=JournalTypeChoices.INFO):
        self.level = level

    def info(self, message: str):
        self.emit(level=JournalTypeChoices.INFO, message=message)

    def warn(self, message: str):
        self.emit(level=JournalTypeChoices.WARN, message=message)

    def error(self, message: str):
        self.emit(level=JournalTypeChoices.ERROR, message=message)


logger = PKILogger()


@transaction.atomic
def journal_clean():
    period = getattr(settings, 'PKIMAN_JOURNAL_STORE_PERIOD', DEFAULT_PKIMAN_JOURNAL_STORE_PERIOD)
    timedelta = timezone.timedelta(days=period)
    last_date = timezone.now() - timedelta
    queryset = Journal.objects.filter(created_at__lt=last_date)
    count = queryset.count()
    if count:
        queryset.delete()
        logger.info(f'Очистка журнала. Удалено записей: {count} старше {period} дней')
