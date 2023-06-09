"""
Django settings for pkiman project.

Generated by 'django-admin startproject' using Django 4.2.

For more information on this file, see
https://docs.djangoproject.com/en/4.2/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/4.2/ref/settings/
"""

from pathlib import Path

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/4.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-#_^0u#zyvsp86*s%t!gj1=echgv)7zz=(f-2@_)2j)h6f!y$7f'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = ['127.0.0.1']

# Application definition

INSTALLED_APPS = [
    'django_pkiman.apps.PKIAdminConfig',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.humanize',
    'django_crontab',
    'django_pkiman.apps.DjangoPkimanConfig',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'pkiman.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        # 'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'pkiman.wsgi.application'

# Database
# https://docs.djangoproject.com/en/4.2/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

# Password validation
# https://docs.djangoproject.com/en/4.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Internationalization
# https://docs.djangoproject.com/en/4.2/topics/i18n/

LANGUAGE_CODE = 'RU'

TIME_ZONE = 'Asia/Yekaterinburg'

USE_I18N = True
USE_L10N = True

USE_TZ = True

LOGIN_REDIRECT_URL = 'pkiman:reestr'
LOGOUT_REDIRECT_URL = 'pkiman:index'

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.2/howto/static-files/

STATIC_URL = 'assets/'
STATIC_ROOT = BASE_DIR / 'assets'
STATICFILES_DIRS = (
    BASE_DIR / 'django_pkiman/static/django_pkiman',
)
MEDIA_URL = 'store/'
MEDIA_ROOT = BASE_DIR / 'store'

DEFAULT_FILE_STORAGE = 'django_pkiman.utils.storage.FileSystemOverwriteStorage'

# Default primary key field type
# https://docs.djangoproject.com/en/4.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
FIRST_DAY_OF_WEEK = 1

# --- PKIMAN ---
# Период хранения записей журнала в БД (дни)
# PKIMAN_JOURNAL_STORE_PERIOD = 365

# Периодический запуск функции обновления CRL
# MIN HOURS DAY MONTH WEEKDAY
CRONJOBS = [
    # ('*/15 12-18 * * *', 'django_pkiman.utils.download.update_handle'),
    ('1 0-23 * * *', 'django_pkiman.utils.download.update_handle'),
    # ('0 0 1 * *', 'django_pkiman.utils.logger.journal_clean')
]
