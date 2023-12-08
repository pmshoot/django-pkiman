from django import template
from django.contrib.messages.constants import (DEBUG, ERROR, INFO, SUCCESS, WARNING)
from django.templatetags.static import static
from django.utils.safestring import mark_safe
from django.urls import reverse
from django.core.cache import cache

from pkiman import models

register = template.Library()


@register.filter
def alert_tag(value):
    alert_tags = {
        DEBUG: 'warning',
        INFO: 'primary',
        SUCCESS: 'success',
        WARNING: 'warning',
        ERROR: 'danger',
        }
    tag = alert_tags.get(value, '')
    return tag


@register.filter
def cert_padding_left(item):
    padding_multiplier = 2
    # padding_left = padding_multiplier * item.depth if item.depth > 1 else 0
    padding_left = padding_multiplier * item.depth
    return padding_left


@register.filter
def mark_cert(item):
    if item.is_root_ca:
        # return 'font-weight:bold;color: brown;'
        return 'font-weight:bold;'
    elif item.is_final():
        return 'color: green;'
    else:
        return ''


@register.filter
def cert_icon_url(item):
    icon = 'crt.png' if (item.is_valid() and item.is_bound()) else 'miss.png'
    icon_url = static(f'img/{icon}')
    return icon_url


# todo add cache
def _pki_critical_period():
    crt_count = models.Crt.objects.get_critical_count()
    crl_count = models.Crl.objects.get_critical_count()
    if crl_count or crt_count:
        return {'crt': crt_count, 'crl': crl_count}


@register.filter
def pki_critical_period_tag(value='all'):
    critical_period_map = _pki_critical_period()
    if critical_period_map:
        if value == 'all':
            count = sum(critical_period_map.values())
        elif value == 'crt':
            count = critical_period_map.get('crt')
        elif value == 'crl':
            count = critical_period_map.get('crl')
        else:
            count = None
        if count:
            # return mark_safe(f'<span style="background-color: orange" class="uk-badge uk-light uk-text-bold">{count}</span>')
            return mark_safe(f'<span style="background-color: orange" class="uk-badge">{count}</span>')
    return ''


@register.filter
def boolicon(value):
    tag = '<span class="{1}" uk-icon="icon: {0}"></span>'
    if value:
        return mark_safe(tag.format('check', 'uk-text-success'))
    return mark_safe(tag.format('close', 'uk-text-danger'))


@register.filter(name='level_tag')
def journal_level_tag(value):
    return {
        'I': 'black',
        'W': 'orange',
        'E': 'red',
        }.get(value, '')
