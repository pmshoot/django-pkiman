import unittest

from django_pkiman.errors import PKIUrlInvalid
from django_pkiman.utils.download import validate_url


class TestUtils(unittest.TestCase):

    def test_validate_url_valid(self):
        url_list = [
            'http://site.com',
            'http://site.com/path/',
            'http://site.com/path/to/file.txt',
            'https://site.com',
            'https://site.com/path/',
            'https://site.com/path/to/file.txt',
        ]

        for url in url_list:
            try:
                validate_url(url)
            except PKIUrlInvalid:
                self.fail('PKIUrlInvalid: unexpected exception')
            except Exception as e:
                self.fail(f'{e}: unexpected exception')
