from cryptography import x509
from cryptography.hazmat._oid import _OID_NAMES, NameOID as _NameOID
from cryptography.hazmat.bindings._rust import (
    ObjectIdentifier as ObjectIdentifier,
    )
from cryptography.hazmat.primitives import hashes
from django.utils.timezone import make_aware

from pkiman import utils

# первые два байта DER кодировки
DER_BYTE_1 = bytes(b'\x30')
DER_BYTE_2 = (bytes(b'\x82'), bytes(b'\x83'))  # todo выяснить допустимый диапазон байт для ASN.1 и x509 полей


class NameOID(_NameOID):
    INNLE = ObjectIdentifier("1.2.643.100.4")
    OGRNIP = ObjectIdentifier("1.2.643.100.5")


_OID_NAMES.update({
    NameOID.INNLE: 'INNLE',
    NameOID.OGRNIP: 'OGRNIP',
})

oid2name = _OID_NAMES


# @TODO - структура PKIObject - разделить на два класса - ParsedCertificate, ParsedCertificateRevocationList
# @TODO - структуры ParsedCertificate, ParsedCertificateRevocationList - описания полей, хранение данных в dict, (см ДЗ)
# @TODO - проверку сертификата при загрузке

class PKIObject:
    """"""

    def __init__(self, x509obj: 'x509.Certificate|x509.CertificateRevocationList|None' = None):
        self.pki_type = None
        self._up_file = None
        self._object = x509obj
        self._parsed = {}

        if x509obj:
            if isinstance(x509obj, x509.Certificate):
                self.pki_type = 'crt'
            elif isinstance(x509obj, x509.CertificateRevocationList):
                self.pki_type = 'crl'
            else:
                raise ValueError('Неверный тип объекта')

        if x509obj:
            self.parse()

    def __str__(self):
        return f'PKI:<{self.subject_identifier}>'

    def __getattribute__(self, item):
        # проверка имен для предотвращения рекурсии
        if item != '_parsed' and item in self._parsed:
            return self._parsed.get(item)
        return super().__getattribute__(item)

    @property
    def parsed(self):
        return self._parsed

    @property
    def object(self):
        return self._object

    @property
    def up_file(self):
        return self._up_file

    def clean(self):
        self.pki_type = None
        self._up_file = None
        self._object = None
        self._parsed = {}

    def read_x509(self, up_file):
        """"""
        if self._object:
            self.clean()

        self._up_file = up_file
        suffix = utils.mime_content_type_map.get(up_file.content_type)
        raw_data = up_file.file.read()
        if raw_data[:1] == DER_BYTE_1 and raw_data[1:2] in DER_BYTE_2:
            # DER
            if suffix == 'crl':
                self.pki_type = suffix
                self._object = x509.load_der_x509_crl(raw_data)
            else:
                self.pki_type = 'crt'
                self._object = x509.load_der_x509_certificate(raw_data)
        else:
            # PEM
            if suffix == 'crl':
                self.pki_type = suffix
                self._object = x509.load_pem_x509_crl(raw_data)
            else:
                self.pki_type = 'crt'
                self._object = x509.load_pem_x509_certificate(raw_data)
        self.parse()

    def parse(self):
        """"""
        if self._object is None:
            raise ValueError('Объект x509 не определен или не загружен')
        if self.pki_type == 'crt':
            parser = self._parse_crt
        elif self.pki_type == 'crl':
            parser = self._parse_crl
        else:
            raise ValueError(f'Неопределенный тип объекта: {self.pki_type}')

        self._parsed = parser(self._object)

    def get_parsed(self):
        if not self._parsed:
            self.parse()
        return self._parsed

    @staticmethod
    def _parse_crt(pki_obj):
        """"""
        subject_id = issuer_id = None
        parsed = {
            'version': {pki_obj.version.value: pki_obj.version.name},
            'subject': {oid2name.get(obj_attr.oid, obj_attr.oid.dotted_string): obj_attr.value for obj_attr in
                        pki_obj.subject},
            'subject_identifier': None,
            'subject_serial_number': str(pki_obj.serial_number) if pki_obj.serial_number else None,  # todo check for
            # unsigned
            'issuer': {oid2name.get(obj_attr.oid, obj_attr.oid.dotted_string): obj_attr.value for obj_attr in
                       pki_obj.issuer},
            'issuer_identifier': None,
            'issuer_serial_number': None,
            'not_valid_after': make_aware(pki_obj.not_valid_after),
            'not_valid_before': make_aware(pki_obj.not_valid_before),
            'CA': False,
            'cdp_info': None,
            'auth_info': None,
            'fingerprint': pki_obj.fingerprint(algorithm=hashes.SHA1()).hex(),
        }
        #
        for extension in pki_obj.extensions:
            # CA=True or False
            if extension.oid.dotted_string == '2.5.29.19':
                parsed['CA'] = extension.value.ca
            # SubjectKeyIdentifier
            if extension.oid.dotted_string == '2.5.29.14':
                parsed['subject_identifier'] = extension.value.key_identifier.hex()
                subject_id = extension.value.key_identifier.hex()
            #
            if extension.oid.dotted_string == '1.3.6.1.4.1.311.20.2':
                parsed['1.3.6.1.4.1.311.20.2'] = extension.value.value
            # authorityKeyIdentifier
            if extension.oid.dotted_string == '2.5.29.35':
                # parsed['issuerKeyIdentifier'] = {
                #     'authority_cert_serial_number': str(extension.value.authority_cert_serial_number),
                #     'key_identifier': extension.value.key_identifier.hex()
                # }
                parsed['issuer_identifier'] = extension.value.key_identifier.hex()
                parsed['issuer_serial_number'] = str(extension.value.authority_cert_serial_number)
                issuer_id = extension.value.key_identifier.hex()
            # CDP
            if extension.oid.dotted_string == '2.5.29.31':
                parsed['cdp_info'] = {num: [cdp.value for cdp in cdp_list.full_name] for num, cdp_list in
                                      enumerate(extension.value)}
            # authorityInfoAccess
            if extension.oid.dotted_string == '1.3.6.1.5.5.7.1.1':
                parsed['auth_info'] = {ia.access_method._name: ia.access_location.value for ia in
                                       extension.value}

        parsed['is_root'] = parsed['CA'] and (subject_id == issuer_id or parsed['subject'] == parsed['issuer'])
        return parsed

    @staticmethod
    def _parse_crl(pki_obj):
        """"""
        parsed = {
            'issuer': {oid2name.get(obj_attr.oid, obj_attr.oid.dotted_string): obj_attr.value for obj_attr in
                       pki_obj.issuer},
            'issuer_identifier': None,
            'issuer_serial_number': None,
            'crl_number': None,
            'last_update': make_aware(pki_obj.last_update),
            'next_update': make_aware(pki_obj.next_update),
            'revoked_list': None,
            'fingerprint': pki_obj.fingerprint(algorithm=hashes.SHA1()).hex(),
        }
        for extension in pki_obj.extensions:
            # issuerKeyIdentifier
            if extension.oid.dotted_string == '2.5.29.35':
                parsed['issuer_identifier'] = extension.value.key_identifier.hex()
                parsed['issuer_serial_number'] = extension.value.authority_cert_serial_number
            # cRLNumber
            if extension.oid.dotted_string == '2.5.29.20':
                parsed['crl_number'] = str(extension.value.crl_number)
        # RevokedList
        parsed['revoked_list'] = {
            str(revoked.serial_number): (make_aware(revoked.revocation_date),
                                         [ext.value.reason.value for ext in revoked.extensions if hasattr(ext.value,
                                                                                                          'reason'
                                                                                                          )]) for
            revoked in
            pki_obj
        }

        return parsed

# def read_from_file(fp: 'str|Path') -> (bytes, str):
#     """"""
#     if isinstance(fp, str):
#         fp = Path(fp)
#     if not fp.exists():
#         raise FileNotFoundError(f'{fp} не найден')
#     fobj = fp.read_bytes()
#     suffix = fp.suffix[1:]
#     return fobj, suffix
#
#
# def read_from_url(uri: 'str') -> (bytes, str):  # !!!
#     fobj = BytesIO().read()
#     suffix = uri.split('.')[-1]
#     return fobj, suffix
