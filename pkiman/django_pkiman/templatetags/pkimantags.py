from django import template
from django.contrib.messages.constants import (DEBUG, ERROR, INFO, SUCCESS, WARNING)
from django.templatetags.static import static
from django.utils.safestring import mark_safe

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
def cert_pad_span(item):
    """"""
    padding_multiplier = 1
    padding_left = padding_multiplier * item.depth if item.depth > 1 else 0
    icon = 'crt.png' if (item.is_valid() and item.is_bound()) else 'miss.png'
    icon_url = static(f'img/{icon}')
    mark_root = 'color: brown;' if item.is_root_ca else ''
    # tag = f'''<div style="padding-left: {padding_left}ex">
    #       <span style="font-weight:bold;{mark_root}"><img src="{icon_url}">{item}</span>
    #       <div><small>{item.subject_as_text()}</small></div>
    #       </div>'''
    tag = f'''<div style="padding-left: {padding_left}ex">
          <span style="font-weight:bold;{mark_root}"><img src="{icon_url}">{item}</span>
          </div>'''
    return mark_safe(tag)


@register.filter
def boolicon(value):
    tag = '<span class="{1}" uk-icon="icon: {0}"></span>'
    if value:
        return mark_safe(tag.format('check', 'uk-text-success'))
    return mark_safe(tag.format('close', 'uk-text-danger'))
