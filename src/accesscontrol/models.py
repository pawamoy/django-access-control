# -*- coding: utf-8 -*-

from __future__ import unicode_literals

from django.db import models
from django.db.models import Q
from django.utils import timezone
from django.utils.translation import ugettext_lazy as _

from . import (ACCESS_CONTROL_APP_LABEL, ACCESS_CONTROL_DEFAULT_RESPONSE,
               ACCESS_CONTROL_IMPLICIT, ACCESS_CONTROL_PERMISSION,
               DummyAttempt, allowed, denied)


class Access(models.Model):
    ignored_perms = ()
    attempt_model = None

    usr = models.PositiveIntegerField(_('User ID'))
    res = models.PositiveIntegerField(_('Resource ID'), blank=True, null=True)
    val = models.CharField(
        verbose_name=_('Permission'),
        max_length=30,
        choices=ACCESS_CONTROL_PERMISSION.CHOICES_ALLOW_DENY)

    class Meta:
        abstract = True
        app_label = ACCESS_CONTROL_APP_LABEL
        unique_together = ('usr', 'res', 'val')

    def __str__(self):
        return '%s %s %s for user %s' % (self.val, self.resource_name, self.res
                                         if self.res else '', self.usr)

    @staticmethod
    def _user_resource_id(user, resource):
        user_id = user
        if not isinstance(user_id, int):
            user_id = user.id
        resource_id = resource
        if resource and not isinstance(resource_id, int):
            resource_id = resource.id
        return user_id, resource_id

    @classmethod
    def authorize(cls,
                  user,
                  perm,
                  resource=None,
                  save=True,
                  attempt_model=DummyAttempt):
        user_id, resource_id = Access._user_resource_id(user, resource)

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

        elif ACCESS_CONTROL_IMPLICIT:
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
        user_id, resource_id = Access._user_resource_id(user, resource)
        return perm in cls.implicit_perms(user_id, resource_id)

    @classmethod
    def implicit_perms(cls, user, resource=None):
        """Overwrite this method to implement implicit checking."""
        return ()

    @classmethod
    def allow(cls, user, perm, resource=None):
        user_id, resource_id = Access._user_resource_id(user, resource)
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
        user_id, resource_id = Access._user_resource_id(user, resource)
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
        user_id, resource_id = Access._user_resource_id(user, resource)
        return cls.objects.filter(
            Q(usr=user_id) & Q(res=resource_id) & (Q(val=allowed(perm)) | Q(
                val=denied(perm)))).delete()


class AccessAttempt(models.Model):
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
        abstract = True
        app_label = ACCESS_CONTROL_APP_LABEL

    def __str__(self):
        return '[%s] user %s was %s %s to %s %s %s' % (
            self.datetime, self.usr, 'implicitely'
            if self.implicit else 'explicitely', 'able' if self.response else
            'unable', self.val, self.resource_name, self.res)

    def like_this(self, response=None, implicit=None, **time_filters):
        result = self.objects.filter(usr=self.usr, res=self.res, val=self.val)
        if response is not None:
            result = result.filter(response=response)
        if implicit is not None:
            result = result.filter(implicit=implicit)
        if time_filters:
            result = result.filter(**time_filters)
        return result

    def total(self, response=None, implicit=None, **time_filters):
        return self.like_this(response, implicit, **time_filters).count()
