# -*- coding: utf-8 -*-

"""
Django Access Control package.

Three submodules:
- dsm: build a DSM based on data provided by an access model.
- models: access and access attempts abstract models.
- permission: permission class. Can be overridden with settings.
"""

import importlib

from django.conf import settings

from .permission import Permission, allowed, denied, is_allowed, is_denied

__version__ = "0.2.2"

ACCESS_CONTROL_APP_LABEL = getattr(settings, 'ACCESS_CONTROL_APP_LABEL',
                                   'accesscontrol')
ACCESS_CONTROL_PERMISSION = getattr(
    settings, 'ACCESS_CONTROL_PERMISSION_CLASS', Permission)
ACCESS_CONTROL_IMPLICIT = getattr(settings, 'ACCESS_CONTROL_IMPLICIT', True)
ACCESS_CONTROL_DEFAULT_RESPONSE = getattr(
    settings, 'ACCESS_CONTROL_DEFAULT_RESPONSE', False)
ACCESS_CONTROL_INHERIT_GROUP_PERMS = getattr(
    settings, 'ACCESS_CONTROL_INHERIT_GROUP_PERMS', True)

allowed = getattr(settings, 'ACCESS_CONTROL_ALLOWED', allowed)
denied = getattr(settings, 'ACCESS_CONTROL_DENIED', denied)
is_allowed = getattr(settings, 'ACCESS_CONTROL_IS_ALLOWED', is_allowed)
is_denied = getattr(settings, 'ACCESS_CONTROL_IS_DENIED', is_denied)

if isinstance(ACCESS_CONTROL_PERMISSION, str):
    ACCESS_CONTROL_PERMISSION = importlib.import_module(
        ACCESS_CONTROL_PERMISSION)

if isinstance(allowed, str):
    allowed = importlib.import_module(allowed)

if isinstance(denied, str):
    denied = importlib.import_module(denied)

if isinstance(is_allowed, str):
    is_allowed = importlib.import_module(is_allowed)

if isinstance(is_denied, str):
    is_denied = importlib.import_module(is_denied)


class DummyAttempt(object):
    """Dummy access attempt model that will pass init and save."""

    def __init__(self, *args, **kwargs):
        """Noop init method."""
        pass

    def save(self, *args, **kwargs):
        """Noop save method."""
        pass


class Control(object):
    """
    Control class.

    A Control object lets you map models to access and access attempts models,
    in order to get method to authorize (check access rights), allow, deny or
    forget access rules between users and resources.

    A call to the authorize method will thus record an entry in the
    corresponding access attempt model, with all related information.

    Examples:
        from ..security.models import MyModelAccess, MyModelAccessAttempt
        from .models import MyModel

        authorize, allow, deny, forget = Control({
            MyModel: (MyModelAccess, MyModelAccessAttempt),
            ...
        }).get_controls()
    """

    def __init__(self, control_mapping):
        """
        Init method.

        Args:
            control_mapping (dict): a dict with your models as keys, and
                2-tuples (access model, access attempt model) as values.
        """
        self.control_mapping = control_mapping

    def _get_func_group_attempt_resource(self, control, resource):
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
        access_model, group_model, attempt_model = self.control_mapping.get(
            key, (None, None, DummyAttempt))
        if access_model is None:
            raise ValueError('Mapping between resources '
                             'and access models does not contain '
                             '%s' % key.__name__)
        return (getattr(access_model, control),
                group_model,
                attempt_model,
                resource)

    def _get_func_resource(self, control, resource):
        f, g, a, r = self._get_func_group_attempt_resource(control, resource)
        return f, r

    def authorize(self, user, perm, resource):
        """
        Authorize access to a resource or a type of resource.

        This method checks if a user has access to a resource or a type of
        resource. Calling this method will also try to record an entry log
        in the corresponding access attempt model.

        Call will not break if there is no access attempt model. Simply,
        nothing will be recorded.

        Args:
            user (User): an instance of settings.AUTH_USER_MODEL or a user id.
            perm (Permission's constant): one of the permissions available
                in Permission class.
            resource (): an instance of one of your models, a model,
                or a string equal to the name of a model.

        Returns:
            bool: user has perm on resource (or not).
        """
        func, group, attempt, resource = self._get_func_group_attempt_resource(
            'authorize', resource)
        return func(user, perm, resource,
                    attempt_model=attempt,
                    group_access_model=group)

    def allow(self, user, perm, resource):
        """
        Explicitly give perm to user on resource.

        Args:
            user (User): an instance of settings.AUTH_USER_MODEL or a user id.
            perm (Permission's constant): one of the permissions available
                in Permission class.
            resource (): an instance of one of your models, a model,
                or a string equal to the name of a model.

        Returns:
            access instance: the created rule.
        """
        func, resource = self._get_func_resource('allow', resource)
        return func(user, perm, resource)

    def deny(self, user, perm, resource):
        """
        Explicitly remove perm to user on resource.

        Args:
            user (User): an instance of settings.AUTH_USER_MODEL or a user id.
            perm (Permission's constant): one of the permissions available
                in Permission class.
            resource (): an instance of one of your models, a model,
                or a string equal to the name of a model.

        Returns:
            access instance: the created rule.
        """
        func, resource = self._get_func_resource('deny', resource)
        return func(user, perm, resource)

    def forget(self, user, perm, resource):
        """
        Forget any rule present between user and resource.

        Args:
            user (User): an instance of settings.AUTH_USER_MODEL or a user id.
            perm (Permission's constant): one of the permissions available
                in Permission class.
            resource (): an instance of one of your models, a model,
                or a string equal to the name of a model.

        Returns:
            int, dict: the number of rules deleted and a dictionary with the
            number of deletions per object type (django's delete return).
        """
        func, resource = self._get_func_resource('forget', resource)
        return func(user, perm, resource)

    def get_controls(self):
        """
        Get the different control methods.

        Returns:
            tuple: in order, authorize, allow, deny and forget.
        """
        return self.authorize, self.allow, self.deny, self.forget
