import random
import string
import time

from django.template.defaulttags import lorem
from django.test import TestCase

from django_pkiman import models
from django_pkiman.models import Journal, JournalTypeChoices


class TestJournalModel(TestCase):
    @classmethod
    def setUpTestData(cls):
        letters = string.ascii_letters
        count = 20
        level_list = (JournalTypeChoices.INFO,
                      JournalTypeChoices.WARN,
                      JournalTypeChoices.ERROR,
                      )
        for level in level_list:
            for _ in range(count):
                text = ''.join(random.choice(letters) for _ in range(10))
                Journal.objects.create_record(level, text)
                # time.sleep(0.05)

    def test_count(self):
        qs = Journal.objects.all()
        self.assertTrue(qs.exists())
        self.assertEqual(qs.count(), 60)

    def test_last_5(self):
        qs = Journal.objects.last_5()
        self.assertEqual(qs.count(), 5)

    def test_last_10(self):
        qs = Journal.objects.last_10()
        self.assertEqual(qs.count(), 10)

    def test_last_30(self):
        qs = Journal.objects.last_30()
        self.assertEqual(qs.count(), 30)

    def test_last(self):
        count_list = [0, 1, 7, 29, 59]
        for count in count_list:
            qs = Journal.objects.last(count)
            self.assertEqual(qs.count(), count)

    def test_ordering(self):
        first = Journal.objects.get(pk=1)
        median = Journal.objects.get(pk=20 * 3 / 2)
        last = Journal.objects.latest('pk')
        self.assertTrue(first.created_at < median.created_at < last.created_at)


class TestProxyModel(TestCase):
    @classmethod
    def setUpTestData(cls):
        models.Proxy.objects.create(name='proxy_1', url='http://proxy.server.ltd', is_default=True)
        models.Proxy.objects.create(name='proxy_2', url='http://proxy.server.ltd', username='username',
                                    password='password', is_default=False)

    def setUp(self) -> None:
        self.proxy_1 = models.Proxy.objects.get(pk=1)
        self.proxy_2 = models.Proxy.objects.get(pk=2)


    def test_get_url(self):
        self.assertEqual(self.proxy_1.get_url(), 'http://proxy.server.ltd')
        self.assertEqual(self.proxy_2.get_url(), 'http://username:password@proxy.server.ltd')

    def test_get_url_map(self):
        self.assertEqual(self.proxy_1.get_url_map(), {'http': 'http://proxy.server.ltd',
                                                      'https': 'http://proxy.server.ltd'})
        self.assertEqual(self.proxy_2.get_url_map(), {'http': 'http://username:password@proxy.server.ltd',
                                                      'https': 'http://username:password@proxy.server.ltd'})

    def test_get_default_proxy(self):
        url = models.Proxy.objects.get_default_proxy_url()
        self.assertEqual(url, 'http://proxy.server.ltd')


