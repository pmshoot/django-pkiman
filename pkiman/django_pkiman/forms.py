from django import forms
from django.core.exceptions import ValidationError
from django.core.validators import URLValidator
from django.forms import PasswordInput, TextInput

from django_pkiman.models import Crl, CrlUpdateSchedule, Proxy
from django_pkiman.utils import mime_content_type_extensions


class SearchForm(forms.Form):
    """Форма поиска на главной странице"""
    s = forms.CharField(
        widget=forms.TextInput(attrs={
            'aria-label': 'Search',
            'class': 'uk-search-input',
            'placeholder': 'Поиск',
            'type': 'search'
            }),
        required=False,
        label=None,
        )


class ManagementURLUploadsForm(forms.Form):
    file = forms.URLField(
        widget=forms.URLInput(attrs={
            'aria-label': 'Custom controls',
            'class': 'uk-input',
            'placeholder': 'URL'
            }),
        required=False,
        help_text='Загрузка данных из URL',
        )
    proxy = forms.ChoiceField(
        widget=forms.Select(attrs={
            'class': 'uk-select uk-width-1-2 uk-form-small',
            'aria-label': 'Select',
            }),
        required=False,
        choices=(),
        help_text='выберите прокси сервер из списка при необходимости'
        )

    def clean_file(self):
        file = self.cleaned_data['file']
        if not file:
            self.add_error('file', ValidationError('Не выбран путь для загрузки'))
            return file
        if not file_extension_permitted(file):
            self.add_error('file', ValidationError('Не подходящее расширение файла'))
        return file


class ManagementLocalUploadsForm(forms.Form):
    file = forms.FileField(
        widget=forms.FileInput(attrs={
            'aria-label': 'Custom controls',
            }),
        required=False,
        help_text='Загрузка данных из локального файла',
        )

    def clean_file(self):
        file = self.cleaned_data['file']
        if not file:
            self.add_error('file', ValidationError('Не выбран файл'))
            return file
        if not file_extension_permitted(file.name):
            self.add_error('file', ValidationError('Не подходящее расширение файла'))
        return file


def file_extension_permitted(fname: str) -> bool:
    """"""
    fnch = fname.lower().split('.')
    return len(fnch) > 1 and fnch[-1] in mime_content_type_extensions


class CrtModelForm(forms.ModelForm):
    validator = URLValidator()

    class Meta:
        model = Crl
        fields = '__all__'
        widgets = {
            'comment': forms.Textarea(attrs={'rows': 5, 'cols': 120}),
            }


class CrlModelForm(forms.ModelForm):
    validator = URLValidator()

    class Meta:
        model = Crl
        fields = '__all__'
        widgets = {
            'urls': forms.Textarea(attrs={'rows': 5, 'cols': 120}),
            'comment': forms.Textarea(attrs={'rows': 5, 'cols': 120}),
            }

    def clean(self):
        is_active = self.cleaned_data['active']
        urls = self.cleaned_data.get('urls')
        if is_active and not urls:
            raise ValidationError('Укажите URL файлов crl списком через запятую')
        return self.cleaned_data

    def clean_urls(self):
        urls = self.cleaned_data['urls']
        if urls:
            url_list = [url.strip() for url in urls.split(',')]
            for url in url_list:
                self.validator(url)
            return ',\n'.join(url_list)
        return ''


class CrlUpdateScheduleModelForm(forms.ModelForm):
    class Meta:
        model = CrlUpdateSchedule
        fields = '__all__'

    def clean_dow(self):
        # todo add check for crontab right string
        data = self.cleaned_data['dow']
        return data


class ProxyModelForm(forms.ModelForm):
    class Meta:
        model = Proxy
        fields = '__all__'
        widgets = {
            'proxy_user': TextInput(attrs={'autocomplete': 'off'}),
            'proxy_pass': PasswordInput(attrs={'autocomplete': 'off'}),
            }

    def clean(self):
        proxy_user = self.cleaned_data.get('proxy_user')
        proxy_pass = self.cleaned_data.get('proxy_pass')
        if proxy_user and not proxy_pass:
            raise ValidationError('Укажите пароль')
        return self.cleaned_data

    def clean_is_default(self):
        default = self.cleaned_data['is_default']
        if 'is_default' in self.changed_data:
            if default:
                # очищаем флаг прокси у кого бы он не установлен
                Proxy.objects.update(is_default=False)
        return default
