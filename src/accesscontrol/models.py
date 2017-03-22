# -*- coding: utf-8 -*-

"""
Models for access control.

- Users and groups access rules
- Users and groups rule history
- Access history
"""

from __future__ import unicode_literals

from django.conf import settings
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

    authorized = models.BooleanField(
        _('Authorization'), default=AppSettings.get_default_response())
    access_type = models.CharField(
        _('Access type'), max_length=255,
        choices=AppSettings.get_access_type_choices())

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
            actor_type (str): a string describing the type of actor.
            actor_id (int): the actor's ID.
            perm (str): one of the permissions available in Permission class.
            resource_type (str): a string describing the type of resource.
            resource_id (int): the resource's ID.

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
            actor_type (str): a string describing the type of actor.
            actor_id (int): the actor's ID.
            perm (str): one of the permissions available in Permission class.
            resource_type (str): a string describing the type of resource.
            resource_id (int): the resource's ID.

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

        return implicit_perms.get(perm, None)

    @classmethod
    def allow(cls,
              actor_type,
              actor_id,
              perm,
              resource_type,
              resource_id=None,
              user=None,
              log=True):
        """
        Explicitly give perm to actor on resource.

        Args:
            actor_type (str): a string describing the type of actor.
            actor_id (int): the actor's ID.
            perm (str): one of the permissions available in Permission class.
            resource_type (str): a string describing the type of resource.
            resource_id (int): the resource's ID.
            user (User): an instance of settings.AUTH_USER_MODEL.
            log (bool): whether to record an entry in rules history.

        Returns:
            access instance: the created rule.
        """
        rule, created = cls.objects.update_or_create(
            actor_type=actor_type,
            actor_id=actor_id,
            access_type=perm,
            resource_type=resource_type,
            resource_id=resource_id,
            defaults={'authorized': True})

        if log:
            record = cls.get_history_model()(
                user=user, action={True: RuleHistory.CREATE}.get(
                    created, RuleHistory.UPDATE))
            record.update_from_rule(rule)

        return rule

    @classmethod
    def deny(cls,
             actor_type,
             actor_id,
             perm,
             resource_type,
             resource_id=None,
             user=None,
             log=True):
        """
        Explicitly remove perm to actor on resource.

        Args:
            actor_type (str): a string describing the type of actor.
            actor_id (int): the actor's ID.
            perm (str): one of the permissions available in Permission class.
            resource_type (str): a string describing the type of resource.
            resource_id (int): the resource's ID.
            user (User): an instance of settings.AUTH_USER_MODEL.
            log (bool): whether to record an entry in rules history.

        Returns:
            access instance: the created rule.
        """
        rule, created = cls.objects.update_or_create(
            actor_type=actor_type,
            actor_id=actor_id,
            access_type=perm,
            resource_type=resource_type,
            resource_id=resource_id,
            defaults={'authorized': False})

        if log:
            record = cls.get_history_model()(
                user=user, action={True: RuleHistory.CREATE}.get(
                    created, RuleHistory.UPDATE))
            record.update_from_rule(rule)

        return rule

    @classmethod
    def forget(cls,
               actor_type,
               actor_id,
               perm,
               resource_type,
               resource_id=None,
               user=None,
               log=True):
        """
        Forget any rule present between actor and resource.

        Args:
            actor_type (str): a string describing the type of actor.
            actor_id (int): the actor's ID.
            perm (str): one of the permissions available in Permission class.
            resource_type (str): a string describing the type of resource.
            resource_id (int): the resource's ID.
            user (User): an instance of settings.AUTH_USER_MODEL.
            log (bool): whether to record an entry in rules history.

        Returns:
            int, dict: the number of rules deleted and a dictionary with the
            number of deletions per object type (django's delete return).
        """
        try:
            rule = cls.objects.get(
                actor_type=actor_type, actor_id=actor_id,
                resource_type=resource_type, resource_id=resource_id,
                access_type=perm)

            if log:
                cls.get_history_model().objects.create(
                    user=user, action=RuleHistory.DELETE,
                    reference_id=rule.id)

            rule.delete()
            return True
        except cls.DoesNotExist:
            return False


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
        attempt.response = cls.authorize_explicit(
            user_type, user_id, perm, resource_type, resource_id)

        if (attempt.response is None and
                AppSettings.get_inherit_group_perms()):

            # Else check group explicit perms
            user_model = get_user_model()
            user = user_model.objects.get(id=user_id)

            for group in user.groups.all():
                attempt.response = GroupAccessRule.authorize_explicit(
                    group.__class__.name, group.id, perm,
                    resource_type, resource_id)

                if attempt.response is not None:
                    attempt.group_inherited = True
                    attempt.group = group.id
                    break

        # Else check user implicit perms
        if attempt.response is None and not skip_implicit:
            attempt.response = cls.authorize_implicit(
                user_type, user_id, perm, resource_type, resource_id)

            if attempt.response is not None:
                attempt.implicit = True

            # Else check group implicit perms
            elif AppSettings.get_inherit_group_perms():

                user_model = get_user_model()
                user = user_model.objects.get(id=user_id)

                for group in user.groups.all():
                    attempt.response = GroupAccessRule.authorize_implicit(
                        group.__class__.name, group.id, perm,
                        resource_type, resource_id)

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

    @classmethod
    def get_history_model(cls):
        return UserRuleHistory


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
                  log=True):
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

    @classmethod
    def get_history_model(cls):
        return GroupRuleHistory


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

    DEFAULT = 'd'
    IMPLICIT = 'i'
    EXPLICIT = 'e'

    RESPONSE_TYPE_VERBOSE = {
        DEFAULT: 'by default',
        IMPLICIT: 'implicitly',
        EXPLICIT: 'explicitly'
    }

    RESPONSE_TYPE = (
        (DEFAULT, _(RESPONSE_TYPE_VERBOSE[DEFAULT])),
        (IMPLICIT, _(RESPONSE_TYPE_VERBOSE[IMPLICIT])),
        (EXPLICIT, _(RESPONSE_TYPE_VERBOSE[EXPLICIT]))
    )

    actor_type = models.CharField(_('Actor type'), max_length=255, blank=True)
    actor_id = models.PositiveIntegerField(_('Actor ID'), null=True)

    # We don't want to store false info, None says "we don't know"
    response = models.NullBooleanField(_('Response'), default=None)
    response_type = models.CharField(
        _('Response type'), max_length=1, choices=RESPONSE_TYPE)
    access_type = models.CharField(_('Access'), max_length=255)

    resource_type = models.CharField(_('Resource type'), max_length=255)
    resource_id = models.PositiveIntegerField(_('Resource ID'), null=True)

    datetime = models.DateTimeField(_('Date and time'), default=timezone.now)

    group_type = models.CharField(_('Group type'), max_length=255, blank=True)
    group_id = models.PositiveIntegerField(_('Group ID'), null=True)

    def __str__(self):
        inherited = ''
        if self.actor_type and self.group_type and self.group_id:
            if self.actor_id:
                actor = '%s %s' % (self.actor_type, self.actor_id)
            else:
                actor = self.actor_type
            inherited = ' (inherited from %s %s)' % (
                self.group_type, self.group_id)
        elif self.group_type:
            if self.group_id:
                actor = '%s %s' % (self.group_type, self.group_id)
            else:
                actor = self.group_type
        else:
            return 'invalid: no actor & no group: %s' % self.__dict__

        authorized = 'authorized' if self.response else 'unauthorized'
        string = '[%s] %s was %s %s to %s %s %s' % (
            self.datetime, actor,
            AccessHistory.RESPONSE_TYPE[str(self.response_type)],
            authorized, self.access_type, self.resource_type, self.resource_id)
        if inherited:
            return string + inherited
        return string


class RuleHistory(models.Model):
    """Rule history model."""

    rule_type = 'generic'

    CREATE = 'c'
    # READ = 'r'  # makes no sense here
    UPDATE = 'u'
    DELETE = 'd'

    ACTIONS_VERBOSE = {
        CREATE: 'create',
        # READ: 'read',
        UPDATE: 'update',
        DELETE: 'delete'
    }

    ACTIONS = (
        CREATE, _(ACTIONS_VERBOSE[CREATE]),
        # READ, _(ACTIONS_VERBOSE[READ]),
        UPDATE, _(ACTIONS_VERBOSE[UPDATE]),
        DELETE, _(ACTIONS_VERBOSE[DELETE]),
    )

    reference_id = models.PositiveIntegerField(_('Rule reference ID'))
    action = models.CharField(_('Action'), max_length=1, choices=ACTIONS)
    datetime = models.DateTimeField(_('Date and time'), auto_now_add=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.SET_NULL,
        verbose_name=_('User'), related_name='rules_changes',
        null=True)

    actor_type = models.CharField(_('Actor type'), max_length=255, blank=True)
    actor_id = models.PositiveIntegerField(_('Actor ID'), null=True)

    authorized = models.NullBooleanField(_('Authorization'), default=None)
    access_type = models.CharField(
        _('Access type'), max_length=255, blank=True)

    resource_type = models.CharField(
        _('Resource type'), max_length=255, blank=True)
    resource_id = models.PositiveIntegerField(_('Resource ID'), null=True)

    class Meta:
        """Meta class for Django."""

        abstract = True

    def __str__(self):
        return '[%s] user %s has %sd %s rule <%s>' % (
            self.datetime, self.user,
            RuleHistory.ACTIONS_VERBOSE[str(self.action)], self.rule_type,
            self.reference if self.reference else self.reference_id)

    def update_from_rule(self, rule, save=True):
        self.reference = rule
        self.reference_id = rule.id
        self.actor_type = rule.actor_type
        self.actor_id = rule.actor_id
        self.authorized = rule.authorized
        self.access_type = rule.access_type
        self.resource_type = rule.resource_type
        self.resource_id = rule.resource_id
        if save:
            self.save()


class UserRuleHistory(RuleHistory):
    """User rules history model."""

    rule_type = 'user'

    reference = models.ForeignKey(
        UserAccessRule, on_delete=models.SET_NULL, null=True,
        verbose_name=_('Rule reference'), related_name='history')


class GroupRuleHistory(RuleHistory):
    """Group rules history model."""

    rule_type = 'group'

    reference = models.ForeignKey(
        GroupAccessRule, on_delete=models.SET_NULL, null=True,
        verbose_name=_('Rule reference'), related_name='history')
