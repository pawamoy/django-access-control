# -*- coding: utf-8 -*-

"""
Base models for access control.

- Access
- AccessAttempt
"""

from __future__ import unicode_literals

from django.db import models
from django.db.models import Q
from django.utils import timezone
from django.utils.translation import ugettext_lazy as _

from . import (ACCESS_CONTROL_APP_LABEL, ACCESS_CONTROL_DEFAULT_RESPONSE,
               ACCESS_CONTROL_IMPLICIT, ACCESS_CONTROL_PERMISSION,
               DummyAttempt, allowed, denied)


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


class Access(models.Model):
    """
    Access model.

    Attributes:
        ignored_perms (tuple): set of permissions to ignore when checking
            implicit permissions.
        usr (int): model field to store the user id.
        res (int): model field to store the resource id.
        val (str): model field to store the permission.
    """

    resource_name = None
    ignored_perms = ()

    usr = models.PositiveIntegerField(_('User ID'))
    res = models.PositiveIntegerField(_('Resource ID'), blank=True, null=True)
    val = models.CharField(
        verbose_name=_('Permission'),
        max_length=30,
        choices=ACCESS_CONTROL_PERMISSION.CHOICES_ALLOW_DENY)

    class Meta:
        """Meta class for Django."""

        abstract = True
        app_label = ACCESS_CONTROL_APP_LABEL
        unique_together = ('usr', 'res', 'val')

    def __str__(self):
        return '%s %s %s for user %s' % (self.val, self.resource_name, self.res
                                         if self.res else '', self.usr)

    @classmethod
    def user_id(cls, user):
        user_id = user
        if not isinstance(user_id, int):
            user_id = user.id
        return user_id

    @classmethod
    def resource_id(cls, resource):
        resource_id = resource
        if resource and not isinstance(resource_id, int):
            resource_id = resource.id
        return resource_id

    @classmethod
    def user_resource_id(cls, user, resource):
        """Use this method to cast user and resource to integers (ids)."""
        return cls.user_id(user), cls.resource_id(resource)

    @classmethod
    def authorize(cls,
                  user,
                  perm,
                  resource=None,
                  save=True,
                  skip_implicit=False,
                  attempt_model=DummyAttempt):
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
            resource (): an instance of one of your models, its id, or None.
            save (bool): record an entry in access attempt model or not.
            skip_implicit (bool): whether to skip implicit authorization.
                It will always be skipped if you set ACCESS_CONTROL_IMPLICIT
                setting to False.
            attempt_model (model): the access attempt model to use.

        Returns:
            bool: user has perm on resource (or not).
        """
        user_id, resource_id = cls.user_resource_id(user, resource)

        attempt = attempt_model(usr=user_id, res=resource_id, val=perm)

        found_allow, found_deny = False, False
        for permission in cls.objects.filter(usr=user_id, res=resource_id):
            if permission.val == allowed(perm):
                found_allow = True
            elif permission.val == denied(perm):
                found_deny = True

        if found_deny:
            attempt.response = False

        elif found_allow:
            attempt.response = True

        elif perm in cls.ignored_perms:
            attempt.response = False

        elif ACCESS_CONTROL_IMPLICIT and not skip_implicit:
            attempt.response = cls.authorize_implicit(user_id, perm,
                                                      resource_id)
            attempt.implicit = True
        else:
            attempt.response = ACCESS_CONTROL_DEFAULT_RESPONSE

        if save:
            attempt.save()

        return attempt.response

    @classmethod
    def authorize_implicit(cls, user, perm, resource=None):
        """
        Run an implicit authorization check.

        This method checks that the given permission can be implicitly
        obtained through the ``implicit_perms`` method.

        Args:
            user (User): an instance of settings.AUTH_USER_MODEL or a user id.
            perm (str): the permission to check for.
            resource (): an instance of one of your models, its id, or None.

        Returns:

        """
        user_id, resource_id = cls.user_resource_id(user, resource)
        return perm in cls.implicit_perms(user_id, resource_id)

    @classmethod
    def implicit_perms(cls, user, resource=None):
        """
        Overwrite this method to implement implicit checking.

        Args:
            user (User): an instance of settings.AUTH_USER_MODEL or a user id.
            resource (): an instance of one of your models, its id, or None.

        Returns:
            set: a set of permissions that can be obtained implicitly.
        """
        return ()

    @classmethod
    def allow(cls, user, perm, resource=None):
        """
        Explicitly give perm to user on resource.

        Args:
            user (User): an instance of settings.AUTH_USER_MODEL or a user id.
            perm (Permission's constant): one of the permissions available
                in Permission class.
            resource (): an instance of one of your models, its id, or None.

        Returns:
            access instance: the created rule.
        """
        user_id, resource_id = cls.user_resource_id(user, resource)
        try:
            p = cls.objects.get(usr=user_id, val=denied(perm), res=resource_id)
            p.val = allowed(perm)
            p.save()
            return p
        except cls.DoesNotExist:
            return cls.objects.create(
                usr=user_id, val=allowed(perm), res=resource_id)

    @classmethod
    def deny(cls, user, perm, resource=None):
        """
        Explicitly remove perm to user on resource.

        Args:
            user (User): an instance of settings.AUTH_USER_MODEL or a user id.
            perm (Permission's constant): one of the permissions available
                in Permission class.
            resource (): an instance of one of your models, its id, or None.

        Returns:
            access instance: the created rule.
        """
        user_id, resource_id = cls.user_resource_id(user, resource)
        try:
            p = cls.objects.get(
                usr=user_id, val=allowed(perm), res=resource_id)
            p.val = denied(perm)
            p.save()
            return p
        except cls.DoesNotExist:
            return cls.objects.create(
                usr=user_id, val=denied(perm), res=resource_id)

    @classmethod
    def forget(cls, user, perm, resource=None):
        """
        Forget any rule present between user and resource.

        Args:
            user (User): an instance of settings.AUTH_USER_MODEL or a user id.
            perm (Permission's constant): one of the permissions available
                in Permission class.
            resource (): an instance of one of your models, its id, or None.

        Returns:
            int, dict: the number of rules deleted and a dictionary with the
            number of deletions per object type (django's delete return).
        """
        user_id, resource_id = cls.user_resource_id(user, resource)
        return cls.objects.filter(
            Q(usr=user_id) & Q(res=resource_id) & (Q(val=allowed(perm)) | Q(
                val=denied(perm)))).delete()


class AccessAttempt(models.Model):
    """
    Access attempt model.

    Attributes:
        usr (int): model field to store the user id.
        res (int): model field to store the resource id.
        val (str): model field to store the permission.
        datetime (datetime): the date and time of the authorization check.
        response (bool): the response given, authorized or not.
        implicit (bool): if the response was implicit or not.
    """

    usr = models.PositiveIntegerField(_('User ID'))
    res = models.PositiveIntegerField(_('Resource ID'), blank=True, null=True)
    val = models.CharField(
        verbose_name=_('Permission'),
        max_length=30,
        choices=ACCESS_CONTROL_PERMISSION.CHOICES)
    datetime = models.DateTimeField(_('Date and time'), default=timezone.now)
    response = models.BooleanField(_('Accepted'), default=False)
    implicit = models.BooleanField(_('Implicit'), default=False)

    class Meta:
        """Meta class for Django."""

        abstract = True
        app_label = ACCESS_CONTROL_APP_LABEL

    def __str__(self):
        return '[%s] user %s was %s %s to %s %s %s' % (
            self.datetime, self.usr, 'implicitely'
            if self.implicit else 'explicitely', 'able' if self.response else
            'unable', self.val, self.resource_name, self.res)

    def like_this(self, response=None, implicit=None, **time_filters):
        """
        Find similar entries. Values usr, res and val are fixed.

        Args:
            response (bool): was authorized or not.
            implicit (bool): was implicit or not.
            **time_filters (): filters for the date and time as kwargs.

        Returns:
            queryset: filtered entries given the arguments specified.
        """
        result = self.objects.filter(usr=self.usr, res=self.res, val=self.val)
        if response is not None:
            result = result.filter(response=response)
        if implicit is not None:
            result = result.filter(implicit=implicit)
        if time_filters:
            result = result.filter(**time_filters)
        return result

    def total(self, response=None, implicit=None, **time_filters):
        """
        Count the similar entries. Values usr, res and val are fixed.

        Args:
            response (bool): was authorized or not.
            implicit (bool): was implicit or not.
            **time_filters (): filters for the date and time as kwargs.

        Returns:
            int: the number of similar entries.
        """
        return self.like_this(response, implicit, **time_filters).count()
