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

from .models import UserAccessRule, GroupAccessRule
from .permission import Permission, allowed, denied, is_allowed, is_denied

__version__ = '0.2.4'


def _import(complete_path):
    module_name = '.'.join(complete_path.split('.')[:-1])
    module = importlib.import_module(name=module_name)
    function_or_class = getattr(module, complete_path.split('.')[-1])
    return function_or_class


class AppSettings(object):
    """
    Application settings class.

    This class provides static getters for each setting, and also an instance
    ``load`` method to load every setting in an instance.
    """

    def __init__(self):
        """Init method."""
        self.ACCESS_CONTROL_PERMISSION_CLASS = None
        self.ACCESS_CONTROL_IMPLICIT = None
        self.ACCESS_CONTROL_DEFAULT_RESPONSE = None
        self.ACCESS_CONTROL_INHERIT_GROUP_PERMS = None
        self.allowed = None
        self.denied = None
        self.is_allowed = None
        self.is_denied = None

    def load(self):
        """Load every settings in self."""
        self.ACCESS_CONTROL_PERMISSION_CLASS = AppSettings.get_permission_class()  # noqa
        self.ACCESS_CONTROL_IMPLICIT = AppSettings.get_implicit()
        self.ACCESS_CONTROL_DEFAULT_RESPONSE = AppSettings.get_default_response()  # noqa
        self.ACCESS_CONTROL_INHERIT_GROUP_PERMS = AppSettings.get_inherit_group_perms()  # noqa
        self.allowed = AppSettings.get_allowed()
        self.denied = AppSettings.get_denied()
        self.is_allowed = AppSettings.get_is_allowed()
        self.is_denied = AppSettings.get_is_denied()

    @staticmethod
    def get_permission_class():
        """Return permission class."""
        _class = getattr(settings, 'ACCESS_CONTROL_PERMISSION_CLASS',
                         Permission)
        if isinstance(_class, str):
            _class = _import(_class)
        return _class

    @staticmethod
    def get_implicit():
        """Return implicit setting."""
        return getattr(settings, 'ACCESS_CONTROL_IMPLICIT', True)

    @staticmethod
    def get_default_response():
        """Return default response setting."""
        return getattr(settings, 'ACCESS_CONTROL_DEFAULT_RESPONSE', False)

    @staticmethod
    def get_inherit_group_perms():
        """Return inherit group perms setting."""
        return getattr(settings, 'ACCESS_CONTROL_INHERIT_GROUP_PERMS', True)


app_settings = AppSettings()


# TODO: shortcut authorize(actor, perm, resource)
# and full methods in AccessRule.authorize(actor_type, actor_id, resource_type, resource_id)
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

    # TODO: update docstring
    def __init__(self, control_mapping):
        """
        Init method.

        Args:
            control_mapping (dict): a dict with your models as keys, and
                2-tuples (access model, access attempt model) as values.
        """
        self.control_mapping = control_mapping

    def _get_actor_resource(self, actor, resource):
        actor_type = actor.__class__.__name__
        actor_id = actor.id
        if isinstance(resource, str):
            resource_type = resource
            resource_id = None
        elif isinstance(resource, type):
            resource_type = resource.__name__
            resource_id = None
        else:
            resource_type = resource.__class__.__name__
            resource_id = resource.id
        return actor_type, actor_id, resource_type, resource_id

    def authorize(self, user, perm, resource, skip_implicit=False, log=True):
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
            skip_implicit (bool): whether to skip implicit authorization.
                It will always be skipped if you set ACCESS_CONTROL_IMPLICIT
                setting to False.
            log (bool): record an entry in access attempt model or not.

        Returns:
            bool: user has perm on resource (or not).
        """
        u_type, u_id, r_type, r_id = self._get_actor_resource(user, resource)

        return UserAccessRule.authorize(
            u_type, u_id, perm, r_type, r_id,
            skip_implicit=skip_implicit, log=log)

    def allow(self, actor, perm, resource, user=None, log=True):
        """
        Explicitly give perm to user on resource.

        Args:
            actor (User): an instance of settings.AUTH_USER_MODEL.
            perm (Permission's constant): one of the permissions available
                in Permission class.
            resource (): an instance of one of your models, a model,
                or a string equal to the name of a model.
            user (User): an instance of settings.AUTH_USER_MODEL.

        Returns:
            access instance: the created rule.
        """
        a_type, a_id, r_type, r_id = self._get_actor_resource(actor, resource)
        return UserAccessRule.allow(
            a_type, a_id, perm, r_type, r_id, user=user, log=log)

    def deny(self, actor, perm, resource, user=None, log=True):
        """
        Explicitly remove perm to user on resource.

        Args:
            actor (User): an instance of settings.AUTH_USER_MODEL or a user id.
            perm (Permission's constant): one of the permissions available
                in Permission class.
            resource (): an instance of one of your models, a model,
                or a string equal to the name of a model.

        Returns:
            access instance: the created rule.
        """
        a_type, a_id, r_type, r_id = self._get_actor_resource(actor, resource)
        return UserAccessRule.allow(
            a_type, a_id, perm, r_type, r_id, user=user, log=log)

    def forget(self, actor, perm, resource, user=None, log=True):
        """
        Forget any rule present between user and resource.

        Args:
            actor (User): an instance of settings.AUTH_USER_MODEL or a user id.
            perm (Permission's constant): one of the permissions available
                in Permission class.
            resource (): an instance of one of your models, a model,
                or a string equal to the name of a model.

        Returns:
            int, dict: the number of rules deleted and a dictionary with the
            number of deletions per object type (django's delete return).
        """
        a_type, a_id, r_type, r_id = self._get_actor_resource(actor, resource)
        return UserAccessRule.allow(
            a_type, a_id, perm, r_type, r_id, user=user, log=log)

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
