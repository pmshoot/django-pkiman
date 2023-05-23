import unittest

from django_pkiman.errors import PKIUrlInvalid
from django_pkiman.utils.download import validate_url, define_proxy, define_filename_content_type


class TestUtils(unittest.TestCase):

    def test_validate_url_valid(self):
        url_list = [
            'http://site.com',
            'http://site.com/path',
            'http://site.com/path/to/file.txt',
            'https://site.com/',
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

    def test_define_proy(self):
        test_list = [
            ('http://proxy.server.ltd:3128', {'http': 'http://proxy.server.ltd:3128',
                                              'https': 'http://proxy.server.ltd:3128',
                                              }),
            ({'http': 'http://proxy.server.ltd:3128',
              'https': 'http://proxy.server.ltd:3128',
              },
             {'http': 'http://proxy.server.ltd:3128',
              'https': 'http://proxy.server.ltd:3128',
              }),
            (None, {})
            ]
        for proxy_in, proxy_out in test_list:
            proxy = define_proxy(proxy_in)
            self.assertDictEqual(proxy, proxy_out)

    def test_define_filename_content_type(self):
        test_list = [
            ('http://server.ltd/file.crt', ('file.crt', 'application/x-x509-ca-cert')),
            ('https://some.server.ltd/path/file_crl.crl', ('file_crl.crl', 'application/pkix-crl')),
            ('http://secert.server/path/path2/3/4/54/long.name.file.cer', ('long.name.file.cer',
                                                                           ('application/pkix-cert',  # linux
                                                                           'application/x-x509-ca-cert',  # ms
                                                                            )
                                                                           )),
            ('http://s.ltd/file_binary.der', ('file_binary.der', ('application/x-x509-ca-cert',))),
            ]

        for n, data in enumerate(test_list):
            url_in, (fname_in, mime_in) = data
            fname_out, mime_out = define_filename_content_type(url_in)
            self.assertEqual(fname_in, fname_out, n)
            self.assertIn(mime_out, mime_in, n)
