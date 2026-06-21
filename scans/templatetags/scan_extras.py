from django import template

from scans.services.formatters import format_module_output

register = template.Library()


@register.filter(is_safe=True)
def format_output(text, module):
    return format_module_output(text or "", module)
