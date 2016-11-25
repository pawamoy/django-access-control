# -*- coding: utf-8 -*-

import importlib

from django.conf import settings

from .permission import Permission, allowed, denied, is_allowed, is_denied

__version__ = "0.2.1"

ACCESS_CONTROL_APP_LABEL = getattr(settings, 'ACCESS_CONTROL_APP_LABEL', 'accesscontrol')
ACCESS_CONTROL_PERMISSION = getattr(settings, 'ACCESS_CONTROL_PERMISSION_CLASS', Permission)
ACCESS_CONTROL_IMPLICIT = getattr(settings, 'ACCESS_CONTROL_IMPLICIT', True)
ACCESS_CONTROL_DEFAULT_RESPONSE = getattr(settings, 'ACCESS_CONTROL_DEFAULT_RESPONSE', False)

allowed = getattr(settings, 'ACCESS_CONTROL_ALLOWED', allowed)
denied = getattr(settings, 'ACCESS_CONTROL_DENIED', denied)
is_allowed = getattr(settings, 'ACCESS_CONTROL_IS_ALLOWED', is_allowed)
is_denied = getattr(settings, 'ACCESS_CONTROL_IS_DENIED', is_denied)

if isinstance(ACCESS_CONTROL_PERMISSION, str):
    ACCESS_CONTROL_PERMISSION = importlib.import_module(ACCESS_CONTROL_PERMISSION)

if isinstance(allowed, str):
    allowed = importlib.import_module(allowed)

if isinstance(denied, str):
    denied = importlib.import_module(denied)

if isinstance(is_allowed, str):
    is_allowed = importlib.import_module(is_allowed)

if isinstance(is_denied, str):
    is_denied = importlib.import_module(is_denied)


class DummyAttempt(object):
    def __init__(self, *args, **kwargs):
        pass

    def save(self, *args, **kwargs):
        pass


class Control(object):
    def __init__(self, control_mapping):
        self.control_mapping = control_mapping

    def _get_func_attempt(self, control, resource):
        key = None
        if isinstance(resource, type):
            key = resource
            resource = None
        elif isinstance(resource, str):
            for k in self.control_mapping.keys():
                if k.__name__ == resource:
                    key = k
                    break
            resource = None
        elif hasattr(resource, '__class__'):
            key = resource.__class__
        access_model, attempt_model = self.control_mapping.get(
            key, (None, DummyAttempt))
        if access_model is None:
            raise ValueError('Mapping between resources '
                             'and access models does not contain '
                             '%s' % key.__name__)
        return getattr(access_model, control), attempt_model, resource

    def authorize(self, user, perm, resource):
        func, attempt, resource = self._get_func_attempt('authorize', resource)
        return func(user, perm, resource, attempt_model=attempt)

    def allow(self, user, perm, resource):
        func, attempt, resource = self._get_func_attempt('allow', resource)
        return func(user, perm, resource)

    def deny(self, user, perm, resource):
        func, attempt, resource = self._get_func_attempt('deny', resource)
        return func(user, perm, resource)

    def forget(self, user, perm, resource):
        func, attempt, resource = self._get_func_attempt('forget', resource)
        return func(user, perm, resource)

    def get_controls(self):
        return self.authorize, self.allow, self.deny, self.forget
