# -*- coding: utf-8 -*-

"""
Base models for access control.

- Access
- AccessAttempt
"""

from __future__ import unicode_literals

from django.contrib.auth import get_user_model
from django.db import models
from django.db.models import Q
from django.utils import timezone
from django.utils.translation import ugettext_lazy as _

from . import AppSettings, DummyAttempt


# TODO: add roles and logs in the algorithm
# Algorithm authorize
# Check user's explicit perms
# If found deny -> deny (deny > allow)
# If found allow -> allow
# Else
#   If user inherits groups permissions
#   Check group's explicit perms
#   If found deny -> deny (deny > allow)
#   If found allow -> allow
#   Else
#       If implicit authorized
#       Get implicit user authorization
#       If got something, return it
#       Else, get implicit group authorization
#           If got something, return it
#           Else, return default response.

# TODO: add verbose_names, add __str__ methods
# TODO: have flexible id types from app settings


class DownCastIntegerMixin(object):
    """Class methods to cast actor and resource to integers."""

    @classmethod
    def downcast_actor(cls, actor):
        """
        Cast down an actor to its id.

        Args:
            actor (User/Group/int): a User, a Group or an int.

        Returns:
            int: the actor's id.
        """
        actor_id = actor
        if not isinstance(actor_id, int):
            actor_id = actor.id
        return actor_id

    @classmethod
    def downcast_resource(cls, resource):
        """
        Cast down a resource to its id.

        Args:
            resource (Model/int): a instance of a model, or an int.

        Returns:
            int: the resource's id.
        """
        resource_id = resource
        if resource and not isinstance(resource_id, int):
            resource_id = resource.id
        return resource_id


class AuthorizeUserMixin(object):
    """Authorize access to a resource or a type of resource."""

    @classmethod
    def authorize(cls,
                  user,
                  perm,
                  resource=None,
                  user_type=None,
                  resource_type=None,
                  skip_implicit=False,
                  save=True):
        """
        Implementation for UserAccessRule class.

        This method checks if a user has access to a resource or a type of
        resource. Calling this method will also try to record an entry log
        in the corresponding access attempt model.

        Call will not break if there is no access attempt model. Simply,
        nothing will be recorded.

        Args:
            user (User): an instance of settings.AUTH_USER_MODEL or a user id.
            perm (Permission's constant): one of the permissions available
                in Permission class.
            resource (): an instance of one of your models, its id, or None.
            save (bool): record an entry in access attempt model or not.
            skip_implicit (bool): whether to skip implicit authorization.
                It will always be skipped if you set ACCESS_CONTROL_IMPLICIT
                setting to False.

        Returns:
            bool: user has perm on resource (or not).
        """
        user_id, resource_id = cls.downcast_actor_resource(user, resource)

        # TODO: try first to get user type from mapping
        if user_type is None:
            user_type = AppSettings.get_default_user_type()

        # TODO: try ONLY to get resource type from mapping
        if resource_type is None:
            resource_type = AppSettings.get_mapping().resource_type(resource)

        attempt = AccessHistory(actor_type=user_type, actor_id=user_id,
                                resource_id=resource_id, access_type=perm)
        attempt.response = None

        # Check user explicit perms
        attempt.response = cls.authorize_explicit(user_id, perm, resource_id)

        if (attempt.response is None and
                AppSettings.get_inherit_group_perms()):

            # Else check group explicit perms
            user_model = get_user_model()
            if not isinstance(user, user_model):
                user = user_model.objects.get(id=user)

            for group in user.groups.all():
                attempt.response = GroupAccessRule.authorize_explicit(
                    group.id, perm, resource_id)

                if attempt.response is not None:
                    attempt.group_inherited = True
                    attempt.group = group.id
                    break

        # Else check user implicit perms
        if attempt.response is None and not skip_implicit:
            attempt.response = cls.authorize_implicit(
                user_id, perm, resource_id)

            if attempt.response is not None:
                attempt.implicit = True

            # Else check group implicit perms
            elif AppSettings.get_inherit_group_perms():

                for group in user.groups.all():
                    attempt.response = GroupAccessRule.authorize_implicit(
                        user_id, perm, resource_id)

                    if attempt.response is not None:
                        attempt.implicit = True
                        attempt.group_inherited = True
                        attempt.group = group.id
                        break

        # Else give default response
        if attempt.response is None:
            attempt.response = AppSettings.get_default_response()
            attempt.default = True

        if save:
            attempt.save()

        return attempt.response


class AuthorizeGroupMixin(object):
    """Authorize access to a resource or a type of resource."""

    # TODO: change default to app settings GROUP_TYPE_DEFAULT
    actor_type = models.CharField(max_length=255, default='group')

    @classmethod
    def authorize(cls,
                  group,
                  perm,
                  resource=None,
                  save=False,
                  skip_implicit=False):
        """
        Implementation for GroupAccessRule class.

        This method checks if a group has access to a resource or a type of
        resource. Calling this method will also try to record an entry log
        in the corresponding access attempt model.

        Call will not break if there is no access attempt model. Simply,
        nothing will be recorded.
        """
        group_id, resource_id = cls.downcast_actor_resource(group, resource)

        attempt = AccessHistory(group=group_id, resource=resource_id,
                                perm=perm)
        attempt.response = None

        # Check group explicit perms
        attempt.response = cls.authorize_explicit(group_id, perm, resource_id)

        # Else check group implicit perms
        if attempt.response is None and not skip_implicit:
            attempt.response = cls.authorize_implicit(
                group_id, perm, resource_id)

            if attempt.response is not None:
                attempt.implicit = True

        # Else give default response
        if attempt.response is None:
            attempt.response = AppSettings.get_default_response()
            attempt.default = True

        if save:
            attempt.save()

        return attempt.response


class AccessRule(models.Model):
    """
    Access model.

    Attributes:
        actor_name (str): name of the actor.
        resource_name (str): name of the resource.
        ignored_perms (tuple): set of permissions to ignore when checking
            implicit permissions.
        actor (int): model field to store the actor id.
        res (int): model field to store the resource id.
        perm (str): model field to store the permission.
    """

    actor_id = models.PositiveIntegerField()
    actor_type = models.CharField(max_length=255)

    # TODO: get default from app settings
    authorized = models.BooleanField(default=False)
    # TODO: add choices from app settings (ontology generated class of perms)
    access_type = models.CharField(max_length=255)

    resource_type = models.CharField(max_length=255)
    resource_id = models.PositiveIntegerField(null=True)

    creation_date = models.DateTimeField(auto_now_add=True)
    modification_date = models.DateTimeField(auto_now=True)

    class Meta:
        """Meta class for Django."""

        abstract = True
        unique_together = (
            'actor_type', 'actor_id',
            'access_type',
            'resource_type', 'resource_id'
        )

    def __str__(self):
        return '%s %s %s %s for %s %s' % (
            'allow' if self.authorized else 'deny', self.access_type,
            self.resource_type, self.resource_id if self.resource_id else '',
            self.actor_type, self.actor_id)

    @classmethod
    def downcast_actor_resource(cls, actor, resource):
        """
        Cast actor and resource to ids.

        Args:
            actor (User/Group/int): a User, a Group or an id.
            resource (Model/int): a instance of a model, or an id.

        Returns:
            tuple: actor's id, resource's id.
        """
        return cls.downcast_actor(actor), cls.downcast_resource(resource)

    @classmethod
    def authorize_explicit(cls,
                           actor,
                           perm,
                           resource=None):
        """
        Run an explicit authorization check.

        Args:
            actor (): an instance of settings.AUTH_USER_MODEL, an instance of
                Group or a user/group id.
            perm (Permission's constant): one of the permissions available
                in Permission class.
            resource (): an instance of one of your models, its id, or None.

        Returns:

        """
        actor_id, resource_id = cls.downcast_actor_resource(actor, resource)

        found_allow, found_deny = False, False
        for permission in cls.objects.filter(actor=actor_id,
                                             resource=resource_id):
            if permission.perm == AppSettings.get_allowed()(perm):
                found_allow = True
            elif permission.perm == AppSettings.get_denied()(perm):
                found_deny = True

        if found_deny:
            return False

        elif found_allow:
            return True

        return None

    @classmethod
    def authorize_implicit(cls,
                           actor,
                           perm,
                           resource=None):
        """
        Run an implicit authorization check.

        This method checks that the given permission can be implicitly
        obtained through the ``implicit_perms`` method.

        Args:
            actor (): an instance of settings.AUTH_USER_MODEL, an instance of
                Group, or a user/group id.
            perm (str): the permission to check for.
            resource (): an instance of one of your models, its id, or None.

        Returns:
            bool: denied(perm) or allowed(perm) found in implicit_perms().
            None: if ACCESS_CONTROL_IMPLICIT is False,
                or perm is in ignored_perms.
        """
        if not AppSettings.get_implicit() or perm in cls.ignored_perms:
            return None

        actor_id, resource_id = cls.downcast_actor_resource(actor, resource)

        implicit_perms = cls.implicit_perms(actor_id, resource_id)

        if AppSettings.get_denied()(perm) in implicit_perms:
            return False

        elif AppSettings.get_allowed()(perm) in implicit_perms:
            return True

        return None

    @classmethod
    def implicit_perms(cls, actor, resource=None):
        """
        Overwrite this method to implement implicit checking.

        Args:
            actor (): an instance of settings.AUTH_USER_MODEL, an instance of
                Group, or a user/group id.
            resource (): an instance of one of your models, its id, or None.

        Returns:
            set: a set of permissions that can be obtained implicitly.
        """
        return ()

    @classmethod
    def allow(cls, actor, perm, resource=None):
        """
        Explicitly give perm to actor on resource.

        Args:
            actor (): an instance of settings.AUTH_USER_MODEL, an instance of
                Group, or a user/group id.
            perm (Permission's constant): one of the permissions available
                in Permission class.
            resource (): an instance of one of your models, its id, or None.

        Returns:
            access instance: the created rule.
        """
        actor_id, resource_id = cls.downcast_actor_resource(actor, resource)
        try:
            p = cls.objects.get(actor=actor_id,
                                perm=AppSettings.get_denied()(perm),
                                resource=resource_id)
            p.perm = AppSettings.get_allowed()(perm)
            p.save()
            return p
        except cls.DoesNotExist:
            return cls.objects.create(
                actor=actor_id,
                perm=AppSettings.get_allowed()(perm),
                resource=resource_id)

    @classmethod
    def deny(cls, actor, perm, resource=None):
        """
        Explicitly remove perm to actor on resource.

        Args:
            actor (): an instance of settings.AUTH_USER_MODEL, an instance of
                Group, or a user/group id.
            perm (Permission's constant): one of the permissions available
                in Permission class.
            resource (): an instance of one of your models, its id, or None.

        Returns:
            access instance: the created rule.
        """
        actor_id, resource_id = cls.downcast_actor_resource(actor, resource)
        try:
            p = cls.objects.get(
                actor=actor_id,
                perm=AppSettings.get_allowed()(perm),
                resource=resource_id)
            p.perm = AppSettings.get_denied()(perm)
            p.save()
            return p
        except cls.DoesNotExist:
            return cls.objects.create(
                actor=actor_id,
                perm=AppSettings.get_denied()(perm),
                resource=resource_id)

    @classmethod
    def forget(cls, actor, perm, resource=None):
        """
        Forget any rule present between actor and resource.

        Args:
            actor (): an instance of settings.AUTH_USER_MODEL, an instance of
                Group, or a user/group id.
            perm (Permission's constant): one of the permissions available
                in Permission class.
            resource (): an instance of one of your models, its id, or None.

        Returns:
            int, dict: the number of rules deleted and a dictionary with the
            number of deletions per object type (django's delete return).
        """
        actor_id, resource_id = cls.downcast_actor_resource(actor, resource)
        return cls.objects.filter(
            Q(actor=actor_id) & Q(resource=resource_id) & (
                Q(perm=AppSettings.get_allowed()(perm)) |
                Q(perm=AppSettings.get_denied()(perm)))).delete()


class UserAccessRule(AccessRule, DownCastIntegerMixin, AuthorizeUserMixin):
    """User access class. To be inherited."""


class GroupAccessRule(AccessRule, DownCastIntegerMixin, AuthorizeGroupMixin):
    """Group access class. To be inherited."""


class AccessHistory(models.Model):
    """
    Access history model.

    Attributes:
        resource_name (str): name of the resource.
        user (int): model field to store the user id (if any).
        resource (int): model field to store the resource id.
        perm (str): model field to store the permission.
        datetime (datetime): the date and time of the authorization check.
        response (bool): the response given, authorized or not.
        implicit (bool): if the response was implicit or not.
        default (bool): if the response was the default response.
        group (int): model field to store the group id (if any).
        group_inherited (bool): if the response was inherited from a group.
    """

    actor_type = models.CharField(max_length=255)
    actor_id = models.PositiveIntegerField()

    # TODO: AppSettings.get_default_response()
    response = models.BooleanField(default=False)
    access_type = models.CharField(max_length=255)

    resource_type = models.CharField(max_length=255)
    resource_id = models.PositiveIntegerField(null=True)

    datetime = models.DateTimeField(_('Date and time'), default=timezone.now)
    implicit = models.BooleanField(_('Implicit'), default=False)
    default = models.BooleanField(_('Default'), default=False)
    group = models.PositiveIntegerField(_('Inherited from group'), null=True)

    # TODO: update
    def __str__(self):
        inherited = ''

        if self.user:
            actor_name = 'user'
            actor = self.user
            if self.group:
                inherited = ' (inherited from group %s)' % self.group
        else:
            actor_name = 'group'
            actor = self.group

        if self.default:
            way = 'by default'
        elif self.implicit:
            way = 'implicitly'
        else:
            way = 'explicitly'

        able = 'able' if self.response else 'unable'

        string = '[%s] %s %s was %s %s to %s %s %s' % (
            self.datetime, actor_name, actor, way,
            able, self.perm, self.resource_name, self.resource)

        if inherited:
            return string + inherited
        else:
            return string


class RuleHistory(models.Model):
    """Rule history model."""

    CREATE = 'c'
    # READ = 'r'  # makes no sense here
    UPDATE = 'u'
    DELETE = 'd'
    ACTIONS = (
        CREATE, _('Create'),
        UPDATE, _('Update'),
        DELETE, _('Delete'),
    )

    reference_id = models.PositiveIntegerField()
    action = models.CharField(max_length=1, choices=ACTIONS)
    datetime = models.DateTimeField(auto_now_add=True)

    old_authorized = models.NullBooleanField(default=None)
    old_access_type = models.CharField(max_length=255, blank=True)
    old_resource_type = models.CharField(max_length=255, blank=True)
    old_resource_id = models.PositiveIntegerField(null=True)

    new_authorized = models.NullBooleanField(default=None)
    new_access_type = models.CharField(max_length=255, blank=True)
    new_resource_type = models.CharField(max_length=255, blank=True)
    new_resource_id = models.PositiveIntegerField(null=True)

    class Meta:
        """Meta class for Django."""

        abstract = True


class UserRuleHistory(RuleHistory):
    """User rules history model."""

    reference = models.ForeignKey(
        UserAccessRule, on_delete=models.SET_NULL, null=True)

    old_user_type = models.CharField(max_length=255, blank=True)
    old_user_id = models.PositiveIntegerField(null=True)

    new_user_type = models.CharField(max_length=255, blank=True)
    new_user_id = models.PositiveIntegerField(null=True)


class GroupRuleHistory(RuleHistory):
    """Group rules history model."""

    reference = models.ForeignKey(
        GroupAccessRule, on_delete=models.SET_NULL, null=True)

    old_group_type = models.CharField(max_length=255, blank=True)
    old_group_id = models.PositiveIntegerField(null=True)

    new_group_type = models.CharField(max_length=255, blank=True)
    new_group_id = models.PositiveIntegerField(null=True)
