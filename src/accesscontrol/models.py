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

from . import (ACCESS_CONTROL_APP_LABEL, ACCESS_CONTROL_DEFAULT_RESPONSE,
               ACCESS_CONTROL_IMPLICIT, ACCESS_CONTROL_INHERIT_GROUP_PERMS,
               ACCESS_CONTROL_PERMISSION, DummyAttempt, allowed, denied)


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
        entity_name (str): name of the entity.
        resource_name (str): name of the resource.
        ignored_perms (tuple): set of permissions to ignore when checking
            implicit permissions.
        entity (int): model field to store the entity id.
        res (int): model field to store the resource id.
        perm (str): model field to store the permission.
    """

    entity_name = None
    resource_name = 'resource'
    ignored_perms = ()

    entity = models.PositiveIntegerField(_('User ID'))
    resource = models.PositiveIntegerField(_('Resource ID'), blank=True,
                                           null=True)
    perm = models.CharField(
        verbose_name=_('Permission'),
        max_length=30,
        choices=ACCESS_CONTROL_PERMISSION.CHOICES_ALLOW_DENY)

    class Meta:
        """Meta class for Django."""

        abstract = True
        app_label = ACCESS_CONTROL_APP_LABEL
        unique_together = ('entity', 'resource', 'perm')

    def __str__(self):
        return '%s %s %s for %s %s' % (
            self.perm, self.resource_name, self.resource
            if self.resource else '', self.entity_name,
            self.entity)

    @classmethod
    def entity_id(cls, entity):
        """
        Cast down an entity to its id.

        Args:
            entity (User/Group/int): a User, a Group or an int.

        Returns:
            int: the entity's id.
        """
        entity_id = entity
        if not isinstance(entity_id, int):
            entity_id = entity.id
        return entity_id

    @classmethod
    def resource_id(cls, resource):
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

    @classmethod
    def entity_resource_id(cls, entity, resource):
        """
        Cast entity and resource to integers (ids).

        Args:
            entity (User/Group/int): a User, a Group or an int.
            resource (Model/int): a instance of a model, or an int.

        Returns:
            tuple: entity's id, resource's id.
        """
        return cls.entity_id(entity), cls.resource_id(resource)

    @classmethod
    def authorize(cls,
                  user,
                  perm,
                  resource=None,
                  save=True,
                  skip_implicit=False,
                  attempt_model=DummyAttempt,
                  group_access_model=None):
        """
        Interface for authorize method. See UserAccess.authorize code source.

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
            group_access_model (model): the group access model to use.

        Returns:
            bool: user has perm on resource (or not).
        """
        raise NotImplementedError('Authorize method '
                                  'not implemented for %s' % cls)

    @classmethod
    def authorize_explicit(cls,
                           entity,
                           perm,
                           resource=None):
        """
        Run an explicit authorization check.

        Args:
            entity (): an instance of settings.AUTH_USER_MODEL, an instance of
                Group or a user/group id.
            perm (Permission's constant): one of the permissions available
                in Permission class.
            resource (): an instance of one of your models, its id, or None.

        Returns:

        """
        entity_id, resource_id = cls.entity_resource_id(entity, resource)

        found_allow, found_deny = False, False
        for permission in cls.objects.filter(entity=entity_id,
                                             resource=resource_id):
            if permission.perm == allowed(perm):
                found_allow = True
            elif permission.perm == denied(perm):
                found_deny = True

        if found_deny:
            return False

        elif found_allow:
            return True

        return None

    @classmethod
    def authorize_implicit(cls,
                           entity,
                           perm,
                           resource=None):
        """
        Run an implicit authorization check.

        This method checks that the given permission can be implicitly
        obtained through the ``implicit_perms`` method.

        Args:
            entity (): an instance of settings.AUTH_USER_MODEL, an instance of
                Group, or a user/group id.
            perm (str): the permission to check for.
            resource (): an instance of one of your models, its id, or None.

        Returns:
            bool: denied(perm) or allowed(perm) found in implicit_perms().
            None: if ACCESS_CONTROL_IMPLICIT is False,
                or perm is in ignored_perms.
        """
        if not ACCESS_CONTROL_IMPLICIT or perm in cls.ignored_perms:
            return None

        entity_id, resource_id = cls.entity_resource_id(entity, resource)

        implicit_perms = cls.implicit_perms(entity_id, resource_id)

        if denied(perm) in implicit_perms:
            return False

        elif allowed(perm) in implicit_perms:
            return True

        return None

    @classmethod
    def implicit_perms(cls, entity, resource=None):
        """
        Overwrite this method to implement implicit checking.

        Args:
            entity (): an instance of settings.AUTH_USER_MODEL, an instance of
                Group, or a user/group id.
            resource (): an instance of one of your models, its id, or None.

        Returns:
            set: a set of permissions that can be obtained implicitly.
        """
        return ()

    @classmethod
    def allow(cls, entity, perm, resource=None):
        """
        Explicitly give perm to entity on resource.

        Args:
            entity (): an instance of settings.AUTH_USER_MODEL, an instance of
                Group, or a user/group id.
            perm (Permission's constant): one of the permissions available
                in Permission class.
            resource (): an instance of one of your models, its id, or None.

        Returns:
            access instance: the created rule.
        """
        entity_id, resource_id = cls.entity_resource_id(entity, resource)
        try:
            p = cls.objects.get(entity=entity_id, perm=denied(perm),
                                resource=resource_id)
            p.perm = allowed(perm)
            p.save()
            return p
        except cls.DoesNotExist:
            return cls.objects.create(
                entity=entity_id, perm=allowed(perm), resource=resource_id)

    @classmethod
    def deny(cls, entity, perm, resource=None):
        """
        Explicitly remove perm to entity on resource.

        Args:
            entity (): an instance of settings.AUTH_USER_MODEL, an instance of
                Group, or a user/group id.
            perm (Permission's constant): one of the permissions available
                in Permission class.
            resource (): an instance of one of your models, its id, or None.

        Returns:
            access instance: the created rule.
        """
        entity_id, resource_id = cls.entity_resource_id(entity, resource)
        try:
            p = cls.objects.get(
                entity=entity_id, perm=allowed(perm), resource=resource_id)
            p.perm = denied(perm)
            p.save()
            return p
        except cls.DoesNotExist:
            return cls.objects.create(
                entity=entity_id, perm=denied(perm), resource=resource_id)

    @classmethod
    def forget(cls, entity, perm, resource=None):
        """
        Forget any rule present between entity and resource.

        Args:
            entity (): an instance of settings.AUTH_USER_MODEL, an instance of
                Group, or a user/group id.
            perm (Permission's constant): one of the permissions available
                in Permission class.
            resource (): an instance of one of your models, its id, or None.

        Returns:
            int, dict: the number of rules deleted and a dictionary with the
            number of deletions per object type (django's delete return).
        """
        entity_id, resource_id = cls.entity_resource_id(entity, resource)
        return cls.objects.filter(
            Q(entity=entity_id) & Q(resource=resource_id) & (
                Q(perm=allowed(perm)) | Q(perm=denied(perm)))).delete()


class UserAccess(Access):
    """User access class. To be inherited."""

    entity_name = 'user'

    class Meta:
        """Meta class for Django."""

        abstract = True

    @classmethod
    def authorize(cls,
                  user,
                  perm,
                  resource=None,
                  save=True,
                  skip_implicit=False,
                  attempt_model=DummyAttempt,
                  group_access_model=None):
        """
        Authorize access to a resource or a type of resource.

        Implementation for UserAccess class.

        This method checks if a user has access to a resource or a type of
        resource. Calling this method will also try to record an entry log
        in the corresponding access attempt model.

        Call will not break if there is no access attempt model. Simply,
        nothing will be recorded.
        """
        user_id, resource_id = cls.entity_resource_id(user, resource)

        attempt = attempt_model(user=user_id, resource=resource_id, perm=perm)
        attempt.response = None

        # Check user explicit perms
        attempt.response = cls.authorize_explicit(user_id, perm, resource_id)

        if (attempt.response is None and
                ACCESS_CONTROL_INHERIT_GROUP_PERMS and
                group_access_model):

            # Else check group explicit perms
            user_model = get_user_model()
            if not isinstance(user, user_model):
                user = user_model.objects.get(id=user)

            for group in user.groups.all():
                attempt.response = group_access_model.authorize_explicit(
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
            elif ACCESS_CONTROL_INHERIT_GROUP_PERMS and group_access_model:

                for group in user.groups.all():
                    attempt.response = group_access_model.authorize_implicit(
                        user_id, perm, resource_id)

                    if attempt.response is not None:
                        attempt.implicit = True
                        attempt.group_inherited = True
                        attempt.group = group.id
                        break

        # Else give default response
        if attempt.response is None:
            attempt.response = ACCESS_CONTROL_DEFAULT_RESPONSE
            attempt.default = True

        if save:
            attempt.save()

        return attempt.response


class GroupAccess(Access):
    """Group access class. To be inherited."""

    entity_name = 'group'

    class Meta:
        """Meta class for Django."""

        abstract = True

    @classmethod
    def authorize(cls,
                  group,
                  perm,
                  resource=None,
                  save=True,
                  skip_implicit=False,
                  attempt_model=DummyAttempt,
                  **kwargs):
        """
        Authorize access to a resource or a type of resource.

        Implementation for GroupAccess class.

        This method checks if a group has access to a resource or a type of
        resource. Calling this method will also try to record an entry log
        in the corresponding access attempt model.

        Call will not break if there is no access attempt model. Simply,
        nothing will be recorded.
        """
        group_id, resource_id = cls.entity_resource_id(group, resource)

        attempt = attempt_model(group=group_id, resource=resource_id,
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
            attempt.response = ACCESS_CONTROL_DEFAULT_RESPONSE
            attempt.default = True

        if save:
            attempt.save()

        return attempt.response


class AccessAttempt(models.Model):
    """
    Access attempt model.

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

    resource_name = 'resource'

    user = models.PositiveIntegerField(_('User ID'), blank=True, null=True)
    group = models.PositiveIntegerField(_('Group ID'), blank=True, null=True)
    resource = models.PositiveIntegerField(_('Resource ID'), blank=True,
                                           null=True)
    perm = models.CharField(verbose_name=_('Permission'),
                            max_length=30,
                            choices=ACCESS_CONTROL_PERMISSION.CHOICES)
    datetime = models.DateTimeField(_('Date and time'), default=timezone.now)
    response = models.BooleanField(_('Accepted'),
                                   default=ACCESS_CONTROL_DEFAULT_RESPONSE)
    implicit = models.BooleanField(_('Implicit'), default=False)
    default = models.BooleanField(_('Default'), default=False)
    group_inherited = models.BooleanField(_('Inherited from group'),
                                          default=False)

    class Meta:
        """Meta class for Django."""

        abstract = True
        app_label = ACCESS_CONTROL_APP_LABEL

    def __str__(self):
        inherited = ''

        if self.user:
            entity_name = 'user'
            entity = self.user
            if self.group:
                inherited = ' (inherited from group %s)' % self.group
        else:
            entity_name = 'group'
            entity = self.group

        if self.default:
            way = 'by default'
        elif self.implicit:
            way = 'implicitly'
        else:
            way = 'explicitly'

        able = 'able' if self.response else 'unable'

        string = '[%s] %s %s was %s %s to %s %s %s' % (
            self.datetime, entity_name, entity, way,
            able, self.perm, self.resource_name, self.resource)

        if inherited:
            return string + inherited
        else:
            return string

    def like_this(self, response=None, implicit=None, **time_filters):
        """
        Find similar entries. Values user, resource and perm are fixed.

        Args:
            response (bool): was authorized or not.
            implicit (bool): was implicit or not.
            **time_filters (): filters for the date and time as kwargs.

        Returns:
            queryset: filtered entries given the arguments specified.
        """
        result = self.objects.filter(user=self.user, resource=self.resource,
                                     perm=self.perm)
        if response is not None:
            result = result.filter(response=response)
        if implicit is not None:
            result = result.filter(implicit=implicit)
        if time_filters:
            result = result.filter(**time_filters)
        return result

    def total(self, response=None, implicit=None, **time_filters):
        """
        Count the similar entries. Values user, resource and perm are fixed.

        Args:
            response (bool): was authorized or not.
            implicit (bool): was implicit or not.
            **time_filters (): filters for the date and time as kwargs.

        Returns:
            int: the number of similar entries.
        """
        return self.like_this(response, implicit, **time_filters).count()
