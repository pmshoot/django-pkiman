from django.core.files.storage import FileSystemStorage


class FileSystemOverwriteStorage(FileSystemStorage):
    """
    Локальное файловое хранилище для перезаписи существующих файлов с тем же именем,
    вместо создания новых дублей с заменой имени
    """

    def get_available_name(self, name, max_length=None):
        if self.exists(name):
            self.delete(name)
        return super().get_available_name(name, max_length)
