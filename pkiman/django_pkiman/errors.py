class PKIError(Exception):
    """"""
    message = 'Ошибка обработки PKI'

    def __init__(self, message=None, value=None):
        if message:
            self.message = message
        self.value = value

    def __str__(self):
        if self.value:
            return f'{self.message}: "{self.value}"'
        return self.message


class PKICrtDoesNotFoundError(PKIError):
    message = 'Не найден соответствующий списку отзыва сертификат'


class PKICrtMultipleFoundError(PKIError):
    message = 'Обнаружено несколько сертификатов с одним идентификационным номером'


###
class PKIParseError(PKIError):
    message = "Ошибки при разборе PKI из файла"


class PKIOldError(PKIError):
    message = "Загружаемый файл старше существующего"


class PKIDuplicateError(PKIError):
    message = "Загружаемый/обновляемый файл идентичен существующему файлу"


###
class PKIUrlError(PKIError):
    message = 'Ошибка при загрузке URL'


class PKIUrlConnectionError(PKIUrlError):
    message = 'Ошибка при установлении соединения сервером'


class PKIUrlContentTypeInvalid(PKIUrlError):
    message = 'Тип контента не допустим к загрузке'


class PKIUrlInvalid(PKIUrlError):
    message = 'Не валидный URL'
