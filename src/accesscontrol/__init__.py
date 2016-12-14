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
    settings, 'ACCESS_CONTROL_PERMISSION', Permission)
ACCESS_CONTROL_IMPLICIT = getattr(settings, 'ACCESS_CONTROL_IMPLICIT', True)
ACCESS_CONTROL_DEFAULT_RESPONSE = getattr(
    settings, 'ACCESS_CONTROL_DEFAULT_RESPONSE', False)
ACCESS_CONTROL_INHERIT_GROUP_PERMS = getattr(
    settings, 'ACCESS_CONTROL_INHERIT_GROUP_PERMS', True)

allowed = getattr(settings, 'ACCESS_CONTROL_ALLOWED', allowed)
denied = getattr(settings, 'ACCESS_CONTROL_DENIED', denied)
is_allowed = getattr(settings, 'ACCESS_CONTROL_IS_ALLOWED', is_allowed)
is_denied = getattr(settings, 'ACCESS_CONTROL_IS_DENIED', is_denied)


def _import(complete_path):
    module_name = '.'.join(complete_path.split('.')[:-1])
    module = importlib.import_module(name=module_name)
    function_or_class = getattr(module, complete_path.split('.')[-1])
    return function_or_class


if isinstance(ACCESS_CONTROL_PERMISSION, str):
    ACCESS_CONTROL_PERMISSION = _import(ACCESS_CONTROL_PERMISSION)

if isinstance(allowed, str):
    allowed = _import(allowed)

if isinstance(denied, str):
    denied = _import(denied)

if isinstance(is_allowed, str):
    is_allowed = _import(is_allowed)

if isinstance(is_denied, str):
    is_denied = _import(is_denied)


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

    def _get_mapped_value(self, resource):
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
        return access_model, group_model, attempt_model, resource

    def _get_user_func_resource(self, control, resource):
        u, g, a, r = self._get_mapped_value(resource)
        return getattr(u, control), r

    def _get_group_func_resource(self, control, resource):
        u, g, a, r = self._get_mapped_value(resource)
        return getattr(g, control), r

    def authorize(self, user, perm, resource, save=True, skip_implicit=False):
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
            save (bool): record an entry in access attempt model or not.
            skip_implicit (bool): whether to skip implicit authorization.
                It will always be skipped if you set ACCESS_CONTROL_IMPLICIT
                setting to False.

        Returns:
            bool: user has perm on resource (or not).
        """
        user_access_model, group_access_model, attempt_model, resource = (
            self._get_mapped_value(resource))
        return getattr(user_access_model, 'authorize')(
            user, perm, resource,
            save=save, skip_implicit=skip_implicit,
            attempt_model=attempt_model,
            group_access_model=group_access_model)

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
        func, resource = self._get_user_func_resource('allow', resource)
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
        func, resource = self._get_user_func_resource('deny', resource)
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
        func, resource = self._get_user_func_resource('forget', resource)
        return func(user, perm, resource)

    def authorize_group(self,
                        group,
                        perm,
                        resource,
                        save=True,
                        skip_implicit=False):
        """
        Authorize access to a resource or a type of resource.

        This method checks if a group has access to a resource or a type of
        resource. Calling this method will also try to record an entry log
        in the corresponding access attempt model.

        Call will not break if there is no access attempt model. Simply,
        nothing will be recorded.

        Args:
            group (Group): an instance of Group or a group id.
            perm (Permission's constant): one of the permissions available
                in Permission class.
            resource (): an instance of one of your models, a model,
                or a string equal to the name of a model.
            save (bool): record an entry in access attempt model or not.
            skip_implicit (bool): whether to skip implicit authorization.
                It will always be skipped if you set ACCESS_CONTROL_IMPLICIT
                setting to False.

        Returns:
            bool: group has perm on resource (or not).
        """
        user_access_model, group_access_model, attempt_model, resource = (
            self._get_mapped_value(resource))
        return getattr(group_access_model, 'authorize')(
            group, perm, resource,
            save=save, skip_implicit=skip_implicit,
            attempt_model=attempt_model)

    def allow_group(self, group, perm, resource):
        """
        Explicitly give perm to group on resource.

        Args:
            group (Group): an instance of Group or a group id.
            perm (Permission's constant): one of the permissions available
                in Permission class.
            resource (): an instance of one of your models, a model,
                or a string equal to the name of a model.

        Returns:
            access instance: the created rule.
        """
        func, resource = self._get_group_func_resource('allow', resource)
        return func(group, perm, resource)

    def deny_group(self, group, perm, resource):
        """
        Explicitly remove perm to group on resource.

        Args:
            group (Group): an instance of Group or a group id.
            perm (Permission's constant): one of the permissions available
                in Permission class.
            resource (): an instance of one of your models, a model,
                or a string equal to the name of a model.

        Returns:
            access instance: the created rule.
        """
        func, resource = self._get_group_func_resource('deny', resource)
        return func(group, perm, resource)

    def forget_group(self, group, perm, resource):
        """
        Forget any rule present between group and resource.

        Args:
            group (Group): an instance of Group or a group id.
            perm (Permission's constant): one of the permissions available
                in Permission class.
            resource (): an instance of one of your models, a model,
                or a string equal to the name of a model.

        Returns:
            int, dict: the number of rules deleted and a dictionary with the
            number of deletions per object type (django's delete return).
        """
        func, resource = self._get_group_func_resource('forget', resource)
        return func(group, perm, resource)

    def get_controls(self, for_group=False):
        """
        Get the different control methods.

        Args:
            for_group (bool): get the controls for groups, not users.

        Returns:
            tuple: in order, authorize, allow, deny and forget.
        """
        if for_group:
            return (self.authorize_group, self.allow_group,
                    self.deny_group, self.forget_group)
        return self.authorize, self.allow, self.deny, self.forget
