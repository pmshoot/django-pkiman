import re

mime_content_type_map = {
    'application/pkix-cert': 'crt',
    'application/x-x509-ca-cert': 'crt',
    'application/pkix-crl': 'crl',
    # 'application/x-pkcs7-certificates': 'p7b'
    }
# todo add ('pem', 'p7b') after adding proper functional
mime_content_type_extensions = extensions = ('crt', 'cer', 'crl', 'der')


def clean_file_name(string: str) -> str:
    """"""
    quote_dot_replace = ''
    space_replace = '_'
    string = re.sub(r'[\"\'.]', quote_dot_replace, string)
    string = re.sub(r'\s', space_replace, string)

    return string.strip()
