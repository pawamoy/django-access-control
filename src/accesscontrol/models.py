# -*- coding: utf-8 -*-

from __future__ import unicode_literals

from django.apps import apps
from django.db import models
from django.db.models import Q
from django.utils import timezone
from django.utils.translation import ugettext_lazy as _

from . import ACCESS_CONTROL_PERMISSION as Permission
from . import (
    ACCESS_APP_LABEL, ACCESS_CONTROL_DEFAULT_RESPONSE, ACCESS_CONTROL_IMPLICIT,
    ACCESS_CONTROL_MODELS, allowed, denied)


class Access(models.Model):
    ignored_perms = ()
    attempt_model = None

    usr = models.PositiveIntegerField(_('User ID'))
    res = models.PositiveIntegerField(_('Resource ID'), blank=True, null=True)
    val = models.CharField(
        verbose_name=_('Permission'), max_length=30, choices=Permission.CHOICES_ALLOW_DENY)

    class Meta:
        abstract = True
        app_label = ACCESS_APP_LABEL
        unique_together = ('usr', 'res', 'val')

    def __str__(self):
        return '%s %s %s for user %s' % (
            self.val, self.resource_name, self.res if self.res else '', self.usr)

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
    def authorize(cls, user, perm, resource=None, save=True):
        user_id, resource_id = Access._user_resource_id(user, resource)

        attempt_model = cls.attempt_model
        if attempt_model is None:
            attempt_model = apps.get_model(ACCESS_APP_LABEL, '%sAttempt' % cls.__name__)
        elif isinstance(attempt_model, str):
            attempt_model = apps.get_model(ACCESS_APP_LABEL, attempt_model)

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
            attempt.response = cls.authorize_implicit(user, perm, resource)
            attempt.implicit = True
        else:
            attempt.response = ACCESS_CONTROL_DEFAULT_RESPONSE

        if save:
            attempt.save()

        return attempt.response

    @classmethod
    def authorize_implicit(cls, user, perm, resource=None):
        return perm in cls.implicit_perms(user, resource)

    @classmethod
    def allow(cls, user, perm, resource=None):
        user_id, resource_id = Access._user_resource_id(user, resource)
        try:
            p = cls.objects.get(usr=user_id, val=denied(perm), res=resource_id)
            p.val = allowed(perm)
            p.save()
            return p
        except cls.DoesNotExist:
            return cls.objects.create(usr=user_id, val=allowed(perm), res=resource_id)

    @classmethod
    def deny(cls, user, perm, resource=None):
        user_id, resource_id = Access._user_resource_id(user, resource)
        try:
            p = cls.objects.get(usr=user_id, val=allowed(perm), res=resource_id)
            p.val = denied(perm)
            p.save()
            return p
        except cls.DoesNotExist:
            return cls.objects.create(usr=user_id, val=denied(perm), res=resource_id)

    @classmethod
    def forget(cls, user, perm, resource=None):
        user_id, resource_id = Access._user_resource_id(user, resource)
        return cls.objects.filter(Q(usr=user_id) & Q(res=resource_id) & (
            Q(val=allowed(perm)) | Q(val=denied(perm)))).delete()


class AccessAttempt(models.Model):
    usr = models.PositiveIntegerField(_('User ID'))
    res = models.PositiveIntegerField(_('Resource ID'), blank=True, null=True)
    val = models.CharField(
        verbose_name=_('Permission'), max_length=30, choices=Permission.CHOICES)
    datetime = models.DateTimeField(_('Date and time'), default=timezone.now)
    response = models.BooleanField(_('Accepted'), default=False)
    implicit = models.BooleanField(_('Implicit'), default=False)

    class Meta:
        app_label = 'app'
        abstract = True

    def __str__(self):
        return '[%s] user %s was %s %s to %s %s %s' % (
            self.datetime, self.usr, 'implicitely' if self.implicit else 'explicitely',
            'able' if self.response else 'unable', self.val, self.resource_name, self.res)

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


def _create_access_model(base_model):
    resource_name = base_model.split('.')[-1]

    class AccessModel(Access):
        resource_name = resource_name
    setattr(AccessModel, '__name__', '%sAccess' % resource_name)

    return AccessModel


def _create_attempt_model(base_model):
    resource_name = base_model.split('.')[-1]

    class AttemptModel(AccessAttempt):
        resource_name = resource_name
    setattr(AttemptModel, '__name__', '%sAccessAttempt' % resource_name)

    return AttemptModel


def _create_access_attempt_model(base_model):
    resource_name = base_model.split('.')[-1]

    class AttemptModel(AccessAttempt):
        resource_name = resource_name
    setattr(AttemptModel, '__name__', '%sAccessAttempt' % resource_name)

    class AccessModel(Access):
        resource_name = resource_name
        attempt_model = AttemptModel
    setattr(AccessModel, '__name__', '%sAccess' % resource_name)

    return AccessModel, AttemptModel


def _auto_build_models(model_list):
    built = []
    for model in model_list:
        if isinstance(model, str):
            access, attempt = _create_access_attempt_model(model)
            built.append({'model': model, 'access': access, 'attempt': attempt})
        elif isinstance(model, dict):
            if 'model' not in model.keys():
                raise ValueError()
            if 'attempt' not in model.keys():
                attempt = _create_attempt_model(model['model'])
                model['attempt'] = attempt
            if 'access' not in model.keys():
                access = _create_access_model(model['model'])
                model['access'] = access
            built.append(model)
    return built


auto_built = _auto_build_models(ACCESS_CONTROL_MODELS)
