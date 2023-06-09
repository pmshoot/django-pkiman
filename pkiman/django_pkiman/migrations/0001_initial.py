# Generated by Django 4.2.1 on 2023-05-23 12:11

from django.db import migrations, models
import django.db.models.deletion
import django_pkiman.models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Journal',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now=True, db_index=True)),
                ('level', models.CharField(choices=[('I', 'ИНФО'), ('W', 'Предупреждение'), ('E', 'Ошибка')], db_index=True, default='I', max_length=1)),
                ('message', models.TextField()),
            ],
            options={
                'verbose_name': 'Запись журнала',
                'verbose_name_plural': 'Журнал',
                'ordering': ('-created_at',),
            },
        ),
        migrations.CreateModel(
            name='Proxy',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(help_text='краткое наименование сервера для отображения в списке', max_length=128, verbose_name='наименование')),
                ('url', models.URLField(help_text='например: http://my.proxy.server:3128', null=True, verbose_name='url адрес')),
                ('proxy_user', models.CharField(blank=True, max_length=128, null=True, verbose_name='пользователь')),
                ('proxy_pass', models.CharField(blank=True, max_length=64, null=True, verbose_name='пароль')),
                ('is_default', models.BooleanField(db_index=True, default=False, help_text='при выборе данный прокси сервер будет использоваться по-умолчанию при загрузке файлов', verbose_name='по-умолчанию')),
            ],
            options={
                'verbose_name': 'Прокси-сервер',
                'verbose_name_plural': 'Прокси',
                'ordering': ('name',),
            },
        ),
        migrations.CreateModel(
            name='Crt',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('path', models.CharField(max_length=255, unique=True)),
                ('depth', models.PositiveIntegerField()),
                ('numchild', models.PositiveIntegerField(default=0)),
                ('subject_identifier', models.CharField(db_index=True, max_length=128, null=True, verbose_name='идентификатор субъекта')),
                ('issuer_identifier', models.CharField(max_length=128, null=True, verbose_name='идентификатор издателя')),
                ('subject_dn', models.JSONField()),
                ('serial', models.CharField(max_length=128, verbose_name='серийный номер')),
                ('issuer_dn', models.JSONField()),
                ('issuer_serial', models.CharField(max_length=128, null=True)),
                ('fingerprint', models.CharField(max_length=64, unique=True, verbose_name='отпечаток')),
                ('file', models.FileField(upload_to=django_pkiman.models.get_upload_file_path, verbose_name='ссылка на файл')),
                ('valid_after', models.DateTimeField(verbose_name='Действителен с')),
                ('valid_before', models.DateTimeField(verbose_name='Действителен до')),
                ('is_ca', models.BooleanField(default=False, verbose_name='корневой')),
                ('is_root_ca', models.BooleanField(default=False, verbose_name='удостоверяющий')),
                ('revoked_date', models.DateTimeField(null=True, verbose_name='отозван')),
                ('cdp_info', models.JSONField(null=True, verbose_name='точки распространения СОС УЦ')),
                ('auth_info', models.JSONField(null=True, verbose_name='точки распространения УЦ')),
                ('created_at', models.DateTimeField(auto_now_add=True, verbose_name='загружен')),
                ('issuer', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='children', to='django_pkiman.crt', verbose_name='привязка к издателю')),
            ],
            options={
                'verbose_name': 'Сертификат',
                'verbose_name_plural': 'Сертификаты',
            },
        ),
        migrations.CreateModel(
            name='CrlUpdateSchedule',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=64, verbose_name='наименование')),
                ('dow', models.JSONField(help_text='используйте JSON формат. Например: [1,2,3,4,5]', verbose_name='дни недели')),
                ('std', models.TimeField(verbose_name='начало временного диапазона')),
                ('etd', models.TimeField(verbose_name='конец временного диапазона')),
                ('is_active', models.BooleanField(default=True, help_text='при активации данное расписание будет использовано планировщиков при запуске обновлений', verbose_name='активный')),
            ],
            options={
                'verbose_name': 'Расписание',
                'verbose_name_plural': 'Расписание',
                'ordering': ('name',),
                'indexes': [models.Index(fields=['is_active', 'std', 'etd'], name='crl_schedule_get_tasks_idx')],
            },
        ),
        migrations.CreateModel(
            name='Crl',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('fingerprint', models.CharField(max_length=64, unique=True, verbose_name='отпечаток')),
                ('file', models.FileField(upload_to=django_pkiman.models.get_upload_file_path, verbose_name='ссылка на файл')),
                ('crl_number', models.TextField(null=True, verbose_name='номер')),
                ('last_update', models.DateTimeField(verbose_name='обновлен')),
                ('next_update', models.DateTimeField(verbose_name='следующее обновление')),
                ('revoked_count', models.IntegerField(default=0, verbose_name='количество отозванных сертификатов')),
                ('urls', models.TextField(blank=True, help_text='список URL для загрузки обновленных файлов через запятую', verbose_name='URL')),
                ('active', models.BooleanField(default=False, help_text='при установленной опции обновляется по выбранному расписанию и может обновлять со страницы сайта', verbose_name='обновляемый')),
                ('no_proxy', models.BooleanField(default=False, verbose_name='не использовать прокси')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('edited_at', models.DateTimeField(auto_now=True)),
                ('f_date', models.DateTimeField(null=True, verbose_name='дата файла')),
                ('f_size', models.PositiveSmallIntegerField(null=True, verbose_name='размер файла')),
                ('f_etag', models.CharField(max_length=128, null=True, verbose_name='хэш файла')),
                ('f_sync', models.DateTimeField(null=True, verbose_name='дата последней синхронизации')),
                ('issuer', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='crl', to='django_pkiman.crt', verbose_name='Сертификат')),
                ('proxy', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to='django_pkiman.proxy', verbose_name='прокси сервер')),
                ('schedule', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='crl_list', to='django_pkiman.crlupdateschedule', verbose_name='расписание')),
            ],
            options={
                'verbose_name': 'Список отзыва',
                'verbose_name_plural': 'Списки отзыва',
                'ordering': ('issuer',),
            },
        ),
        migrations.AddIndex(
            model_name='crt',
            index=models.Index(fields=['subject_dn', 'subject_identifier'], name='crt_get_issuer_idx'),
        ),
        migrations.AddIndex(
            model_name='crt',
            index=models.Index(fields=['issuer_dn', 'issuer_identifier', 'issuer', 'is_root_ca'], name='crt_filter_orphans_idx'),
        ),
        migrations.AddIndex(
            model_name='crt',
            index=models.Index(fields=['subject_dn', 'subject_identifier', 'serial'], name='crl_get_issuer_crt'),
        ),
        migrations.AlterUniqueTogether(
            name='crt',
            unique_together={('issuer_dn', 'serial')},
        ),
    ]
