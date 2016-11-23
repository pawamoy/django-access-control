# -*- coding: utf-8 -*-

from django.conf import settings

from .permission import Permission, is_denied, is_allowed, allowed, denied

__version__ = "0.1.0"

ACCESS_APP_LABEL = getattr(settings, 'ACCESS_APP_LABEL', 'accesscontrol')
ACCESS_CONTROL_PERMISSION = getattr(settings, 'ACCESS_CONTROL_PERMISSION_CLASS', Permission)
ACCESS_CONTROL_MODELS = getattr(settings, 'ACCESS_CONTROL_MODELS', {})
ACCESS_CONTROL_IMPLICIT = getattr(settings, 'ACCESS_CONTROL_IMPLICIT', True)
ACCESS_CONTROL_DEFAULT_RESPONSE = getattr(settings, 'ACCESS_CONTROL_DEFAULT_RESPONSE', False)

allowed = getattr(settings, 'ACCESS_ALLOWED', allowed)
denied = getattr(settings, 'ACCESS_DENIED', denied)
is_allowed = getattr(settings, 'ACCESS_IS_ALLOWED', is_allowed)
is_denied = getattr(settings, 'ACCESS_IS_DENIED', is_denied)

if isinstance(ACCESS_CONTROL_PERMISSION, str):
    ACCESS_CONTROL_PERMISSION = __import__(ACCESS_CONTROL_PERMISSION)

if isinstance(allowed, str):
    allowed = __import__(allowed)

if isinstance(denied, str):
    denied = __import__(denied)

if isinstance(is_allowed, str):
    is_allowed = __import__(is_allowed)

if isinstance(is_denied, str):
    is_denied = __import__(is_denied)


def authorize(user, perm, resource):
    return ACCESS_CONTROL_MODELS.get(resource.__class__).authorize(user, perm, resource)


def allow(user, perm, resource):
    return ACCESS_CONTROL_MODELS.get(resource.__class__).allow(user, perm, resource)


def deny(user, perm, resource):
    return ACCESS_CONTROL_MODELS.get(resource.__class__).deny(user, perm, resource)


def forget(user, perm, resource):
    return ACCESS_CONTROL_MODELS.get(resource.__class__).forget(user, perm, resource)


