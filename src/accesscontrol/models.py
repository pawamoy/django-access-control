# -*- coding: utf-8 -*-

"""
Models for access control.

- Users and groups access rules
- Users and groups rule history
- Access history
"""

from __future__ import unicode_literals

from django.contrib.auth import get_user_model
from django.db import models
from django.db.models import Q
from django.utils import timezone
from django.utils.translation import ugettext_lazy as _

from . import AppSettings


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

    actor_type = models.CharField(_('Actor type'), max_length=255)
    actor_id = models.PositiveIntegerField(_('Actor ID'))

    # TODO: get default from app settings
    authorized = models.BooleanField(default=False)
    # TODO: add choices from app settings (ontology generated class of perms)
    access_type = models.CharField(max_length=255)

    resource_type = models.CharField(_('Resource type'), max_length=255)
    resource_id = models.PositiveIntegerField(_('Resource ID'), null=True)

    creation_date = models.DateTimeField(_('Created'), auto_now_add=True)
    modification_date = models.DateTimeField(_('Last modified'), auto_now=True)

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
    def authorize_explicit(cls,
                           actor_type,
                           actor_id,
                           perm,
                           resource_type,
                           resource_id=None):
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
        try:
            rule = cls.objects.get(
                actor_type=actor_type, actor_id=actor_id,
                resource_type=resource_type, resource_id=resource_id,
                access_type=perm)
            return rule.authorized
        except cls.DoesNotExist:
            return None

    @classmethod
    def authorize_implicit(cls,
                           actor_type,
                           actor_id,
                           perm,
                           resource_type,
                           resource_id=None):
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

        # TODO: add setting, add class implementation default
        implicit_perms = AppSettings.get_implied_rules_class().implicit_perms(
            actor_type, actor_id, resource_type, resource_id)

        if perm in implicit_perms:
            return perm.authorized

        return None

    @classmethod
    def allow(cls, actor_type, actor_id, perm, resource_type, resource_id=None):  # noqa
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
        return cls.objects.update_or_create(
            actor_type=actor_type,
            actor_id=actor_id,
            access_type=perm,
            resource_type=resource_type,
            resource_id=resource_id,
            defaults={'authorized': True})

    @classmethod
    def deny(cls, actor_type, actor_id, perm, resource_type, resource_id=None):  # noqa
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
        return cls.objects.update_or_create(
            actor_type=actor_type,
            actor_id=actor_id,
            access_type=perm,
            resource_type=resource_type,
            resource_id=resource_id,
            defaults={'authorized': False})

    @classmethod
    def forget(cls, actor_type, actor_id, perm, resource_type, resource_id=None):  # noqa
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
        return cls.objects.filter(
            Q(actor_type=actor_type) & Q(actor_id=actor_id) &
            Q(resource_type=resource_type) & Q(resource_id=resource_id) &
            Q(access_type=perm) & (Q(authorized=True) | Q(authorized=False))
        ).delete()


class UserAccessRule(AccessRule):
    """User access class."""

    @classmethod
    def authorize(cls,
                  user_type,
                  user_id,
                  perm,
                  resource_type,
                  resource_id,
                  skip_implicit=False,
                  log=True):
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
            log (bool): record an entry in access history model or not.
            skip_implicit (bool): whether to skip implicit authorization.
                It will always be skipped if you set ACCESS_CONTROL_IMPLICIT
                setting to False.

        Returns:
            bool: user has perm on resource (or not).
        """

        attempt = AccessHistory(actor_type=user_type, actor_id=user_id,
                                resource_type=resource_type,
                                resource_id=resource_id, access_type=perm)
        attempt.response = None

        # Check user explicit perms
        attempt.response = cls.authorize_explicit(user_id, perm, resource_id)

        if (attempt.response is None and
                AppSettings.get_inherit_group_perms()):

            # Else check group explicit perms
            user_model = get_user_model()
            user = user_model.objects.get(id=user_id)

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

        if log:
            attempt.save()

        return attempt.response


class GroupAccessRule(AccessRule):
    """Group access class."""

    @classmethod
    def authorize(cls,
                  group_type,
                  group_id,
                  perm,
                  resource_type,
                  resource_id,
                  skip_implicit=False,
                  log=False):
        """
        Implementation for GroupAccessRule class.

        This method checks if a group has access to a resource or a type of
        resource. Calling this method will also try to record an entry log
        in the corresponding access attempt model.

        Call will not break if there is no access attempt model. Simply,
        nothing will be recorded.

        Args:
            user (User): an instance of settings.AUTH_USER_MODEL or a user id.
            perm (Permission's constant): one of the permissions available
                in Permission class.
            resource (): an instance of one of your models, its id, or None.
            log (bool): record an entry in access history model or not.
            skip_implicit (bool): whether to skip implicit authorization.
                It will always be skipped if you set ACCESS_CONTROL_IMPLICIT
                setting to False.

        Returns:
            bool: user has perm on resource (or not).
        """

        attempt = AccessHistory(actor_type=group_type, actor_id=group_id,
                                resource_type=resource_type,
                                resource_id=resource_id, access_type=perm)
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

        if log:
            attempt.save()

        return attempt.response


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

    actor_type = models.CharField(_('Actor type'), max_length=255)
    actor_id = models.PositiveIntegerField(_('Actor ID'))

    # TODO: AppSettings.get_default_response()
    response = models.BooleanField(_('Response'), default=False)
    access_type = models.CharField(_('Access'), max_length=255)

    resource_type = models.CharField(_('Resource type'), max_length=255)
    resource_id = models.PositiveIntegerField(_('Resource ID'), null=True)

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

    reference_id = models.PositiveIntegerField(_('Rule reference ID'))
    action = models.CharField(_('Action'), max_length=1, choices=ACTIONS)
    datetime = models.DateTimeField(_('Date and time'), auto_now_add=True)

    old_authorized = models.NullBooleanField(
        _('Previous authorization'), default=None)
    old_access_type = models.CharField(
        _('Previous access type'), max_length=255, blank=True)
    old_resource_type = models.CharField(
        _('Previous resource type'), max_length=255, blank=True)
    old_resource_id = models.PositiveIntegerField(
        _('Previous resource ID'), null=True)

    new_authorized = models.NullBooleanField(
        _('New authorization'), default=None)
    new_access_type = models.CharField(
        _('New access type'), max_length=255, blank=True)
    new_resource_type = models.CharField(
        _('New resource type'), max_length=255, blank=True)
    new_resource_id = models.PositiveIntegerField(
        _('New resource ID'), null=True)

    class Meta:
        """Meta class for Django."""

        abstract = True


class UserRuleHistory(RuleHistory):
    """User rules history model."""

    reference = models.ForeignKey(
        UserAccessRule, on_delete=models.SET_NULL, null=True,
        verbose_name=_('Rule reference'), related_name='history')

    old_user_type = models.CharField(
        _('Previous user type'), max_length=255, blank=True)
    old_user_id = models.PositiveIntegerField(
        _('Previous user ID'), null=True)

    new_user_type = models.CharField(
        _('New user type'), max_length=255, blank=True)
    new_user_id = models.PositiveIntegerField(
        _('New user ID'), null=True)


class GroupRuleHistory(RuleHistory):
    """Group rules history model."""

    reference = models.ForeignKey(
        GroupAccessRule, on_delete=models.SET_NULL, null=True,
        verbose_name=_('Rule reference'), related_name='history')

    old_group_type = models.CharField(
        _('Previous group type'), max_length=255, blank=True)
    old_group_id = models.PositiveIntegerField(
        _('Previous group ID'), null=True)

    new_group_type = models.CharField(
        _('New group type'), max_length=255, blank=True)
    new_group_id = models.PositiveIntegerField(
        _('New group ID'), null=True)
