# -*- coding: utf-8 -*-

"""Main test script."""

from django.contrib.auth.models import Group, User
from django.db import models
from django.test import TestCase

import pytest

from django_fake_model import models as f

from accesscontrol import (
    Control, DummyAttempt, Permission, allowed, denied, is_allowed, is_denied)
from accesscontrol.dsm import DSM
from accesscontrol.models import Access, AccessAttempt, GroupAccess, UserAccess


class FakeUser(f.FakeModel, User):
    """Fake user model."""


class FakeGroup(f.FakeModel, Group):
    """Fake group model."""


class FakeResource(f.FakeModel, models.Model):
    """Fake resource model."""

    name = models.CharField(max_length=100)


class FakeResourceAccess(f.FakeModel, UserAccess):
    """Fake resource access model with implicit_perms method."""

    @classmethod
    def implicit_perms(cls, user, resource=None):
        """
        Implicit permissions based on IDs.

        If the user has the same id than the resource, then we assume he has
        all permissions on the resource.

        If resource is None, then the user has permission to create this
        type of resource.

        Else, he has no permissions at all.
        """
        user_id, resource_id = cls.entity_resource_id(user, resource)
        if user_id == resource_id:
            return Permission.ALLOW_ALL
        elif resource is None:
            return allowed(Permission.CREATE),
        return ()


class FakeResourceGroupAccess(f.FakeModel, GroupAccess):
    """Fake resource group access model with same implicit_perms method."""

    @classmethod
    def implicit_perms(cls, group, resource=None):
        """
        Implicit permissions based on IDs.

        If the group has the same id than the resource, then we assume he has
        all permissions on the resource.

        If resource is None, then the group has permission to create this
        type of resource.

        Else, he has no permissions at all.
        """
        group_id, resource_id = cls.entity_resource_id(group, resource)
        if group_id == resource_id:
            return Permission.ALLOW_ALL
        elif resource is None:
            return allowed(Permission.CREATE),
        return ()


class FakeResourceAccessAttempt(f.FakeModel, AccessAttempt):
    """Fake resource access attempt model."""


control = Control({
    FakeResource: (FakeResourceAccess,
                   FakeResourceGroupAccess,
                   FakeResourceAccessAttempt)
})


class MainTestCase(TestCase):
    """Tests general settings and behaviors."""

    def test_permission_class(self):
        """Test conversions of permissions (allowed, denied)."""
        for perm in Permission.ALL:
            assert is_allowed(allowed(perm))
            assert is_denied(denied(perm))
        for perm in Permission.ALLOW_ALL:
            assert is_allowed(perm)
        for perm in Permission.DENY_ALL:
            assert is_denied(perm)

    def test_access_authorize_not_implemented(self):
        """Assert a NotImplementedError is raised from Access.authorize."""
        with pytest.raises(NotImplementedError) as e:
            Access.authorize(None, None)
        assert 'Authorize method not implemented' in str(e.value)


def dummy(*args, **kwargs):
    print(args, kwargs)


class AbstractTestCase(object):
    """Test case to mirror tests between UserAccess and GroupAccess."""

    entities = []
    resources = []
    entity_name = ''
    model, access_model = None, None
    authorize, allow, deny, forget = dummy, dummy, dummy, dummy

    def test_implicit_rights(self):
        """Test implicit rights."""
        for e, entity in enumerate(self.entities):
            for r, resource in enumerate(self.resources):
                if e == r:
                    assert self.authorize(entity, Permission.SEE, resource)
                    assert self.authorize(entity, Permission.CHANGE, resource)
                    assert self.authorize(entity, Permission.DELETE, resource)
                    assert self.authorize(entity, Permission.CREATE, resource)
                else:
                    assert not self.authorize(entity, Permission.SEE, resource)
                    assert not self.authorize(entity, Permission.CHANGE,
                                              resource)
                    assert not self.authorize(entity, Permission.DELETE,
                                              resource)
                    assert not self.authorize(entity, Permission.CREATE,
                                              resource)

        for entity in self.entities:
            assert self.authorize(entity, Permission.CREATE, FakeResource)

    def test_implicit_access_attempts(self):
        """Test implicit access attempts. Will call test_implicit_rights."""
        self.test_implicit_rights()

        for e, entity in enumerate(self.entities):
            for r, resource in enumerate(self.resources):
                if e == r:
                    for perm in Permission.GENERAL_PERMS:
                        assert FakeResourceAccessAttempt.objects.get(
                            resource=resource.id, perm=perm,
                            response=True, implicit=True,
                            **{self.entity_name: entity.id}
                        )
                else:
                    for perm in Permission.GENERAL_PERMS:
                        assert FakeResourceAccessAttempt.objects.get(
                            resource=resource.id, perm=perm,
                            response=False, default=True,
                            **{self.entity_name: entity.id}
                        )

        for entity in self.entities:
            assert FakeResourceAccessAttempt.objects.get(
                resource=None, perm=Permission.CREATE,
                response=True, implicit=True, **{self.entity_name: entity.id})

    def test_explicit_rights(self):
        """Test explicit rights."""
        for resource in self.resources:
            self.allow(self.entities[0], Permission.SEE, resource)
            self.allow(self.entities[0], Permission.CHANGE, resource)
            self.allow(self.entities[0], Permission.DELETE, resource)

        self.allow(self.entities[0], Permission.CREATE, FakeResource)

        for resource in self.resources:
            assert self.authorize(self.entities[0], Permission.SEE, resource)
            assert self.authorize(self.entities[0], Permission.CHANGE,
                                  resource)
            assert self.authorize(self.entities[0], Permission.DELETE,
                                  resource)

        assert self.authorize(self.entities[0], Permission.CREATE,
                              'FakeResource')

        self.forget(self.entities[0], Permission.DELETE, self.resources[-1])
        assert not self.authorize(self.entities[0], Permission.DELETE,
                                  self.resources[-1])

        for resource in self.resources:
            self.deny(self.entities[-1], Permission.SEE, resource)
            self.deny(self.entities[-1], Permission.CHANGE, resource)
            self.deny(self.entities[-1], Permission.DELETE, resource)

        self.deny(self.entities[-1], Permission.CREATE, 'FakeResource')

        for resource in self.resources:
            assert not self.authorize(self.entities[-1], Permission.SEE,
                                      resource)
            assert not self.authorize(self.entities[-1], Permission.CHANGE,
                                      resource)
            assert not self.authorize(self.entities[-1], Permission.DELETE,
                                      resource)

        assert not self.authorize(self.entities[-1], Permission.CREATE,
                                  FakeResource)

        self.forget(self.entities[-1], Permission.CREATE, FakeResource)
        assert self.authorize(self.entities[-1], Permission.CREATE,
                              FakeResource)

    def test_explicit_access_attempts(self):
        """Test explicit access attempts. Will call test_explicit_rights."""
        self.test_explicit_rights()

        for resource in self.resources:
            assert FakeResourceAccessAttempt.objects.get(
                perm=Permission.SEE,
                resource=resource.id, response=True, implicit=False,
                **{self.entity_name: self.entities[0].id})
            assert FakeResourceAccessAttempt.objects.get(
                perm=Permission.CHANGE,
                resource=resource.id, response=True, implicit=False,
                **{self.entity_name: self.entities[0].id})
            assert FakeResourceAccessAttempt.objects.get(
                perm=Permission.DELETE,
                resource=resource.id, response=True, implicit=False,
                **{self.entity_name: self.entities[0].id})

        assert FakeResourceAccessAttempt.objects.get(
            perm=Permission.CREATE, resource=None,
            response=True, implicit=False,
            **{self.entity_name: self.entities[0].id})

        assert FakeResourceAccessAttempt.objects.get(
            perm=Permission.DELETE,
            resource=self.resources[-1].id,
            response=False, default=True,
            **{self.entity_name: self.entities[0].id})

        for resource in self.resources:
            assert FakeResourceAccessAttempt.objects.get(
                perm=Permission.SEE,
                resource=resource.id, response=False, implicit=False,
                **{self.entity_name: self.entities[-1].id})
            assert FakeResourceAccessAttempt.objects.get(
                perm=Permission.CHANGE,
                resource=resource.id, response=False, implicit=False,
                **{self.entity_name: self.entities[-1].id})
            assert FakeResourceAccessAttempt.objects.get(
                perm=Permission.DELETE,
                resource=resource.id, response=False, implicit=False,
                **{self.entity_name: self.entities[-1].id})

        assert FakeResourceAccessAttempt.objects.get(
            perm=Permission.CREATE, resource=None,
            response=False, implicit=False,
            **{self.entity_name: self.entities[-1].id})

        assert FakeResourceAccessAttempt.objects.get(
            perm=Permission.CREATE, resource=None,
            response=True, implicit=True,
            **{self.entity_name: self.entities[-1].id})

    def test_implicit_rights_again(self):
        """Test implicit rights after having set explicit rights."""
        self.test_explicit_rights()

        assert self.access_model.authorize_implicit(
            self.entities[-1], Permission.SEE, self.resources[-1])
        assert self.access_model.authorize_implicit(
            self.entities[-1], Permission.CHANGE, self.resources[-1])
        assert self.access_model.authorize_implicit(
            self.entities[-1], Permission.DELETE, self.resources[-1])

    def test_no_records(self):
        """Test that no record is saved when using save=False."""
        self.test_explicit_rights()

        access_attempts_number = FakeResourceAccessAttempt.objects.all().count()  # noqa

        self.authorize(
            self.entities[-1], Permission.SEE, self.resources[-1],
            save=False)
        self.authorize(
            self.entities[-1], Permission.CHANGE, self.resources[-1],
            save=False)
        self.authorize(
            self.entities[-1], Permission.DELETE, self.resources[-1],
            save=False)

        assert FakeResourceAccessAttempt.objects.all().count() == access_attempts_number  # noqa

    def test_matrix(self):
        """Test matrix creation with entities as entities."""
        matrix = DSM(FakeResource, self.access_model, self.model)
        heatmap = matrix.to_highcharts_heatmap()
        assert heatmap['series'][0]['data'] == []
        heatmap_implicit = matrix.to_highcharts_heatmap(implicit=True)
        assert len(heatmap_implicit['series'][0]['data']) == 5
        heatmap_reverse = matrix.to_highcharts_heatmap(
            reverse=True, filters={'id__in': (1, 2)}, orders=['-id'])
        assert heatmap_reverse['series'][0]['data'] == []
        heatmap_implicit_reverse = matrix.to_highcharts_heatmap(
            implicit=True, reverse=True,
            entity_filters={'id__in': (1, 2)}, entity_orders=['-id'],
            resource_filters={'id__in': (1, 2)}, resource_orders=['-id'])
        assert len(heatmap_implicit_reverse['series'][0]['data']) == 2

    def test_dummy_attempt(self):
        """Assert using the DummyAttempt model won't record any attempt."""
        access_attempts_number = FakeResourceAccessAttempt.objects.all().count()  # noqa

        self.access_model.authorize(
            self.entities[0], Permission.SEE, self.resources[0],
            save=True, attempt_model=DummyAttempt)

        assert FakeResourceAccessAttempt.objects.all().count() == access_attempts_number  # noqa

        self.access_model.authorize(
            self.entities[0], Permission.SEE, self.resources[0],
            save=True)  # should default to DummyAttempt

        assert FakeResourceAccessAttempt.objects.all().count() == access_attempts_number  # noqa

    def test_print_access(self):
        """Assert printing is OK."""
        self.test_explicit_rights()

        for access in self.access_model.objects.all():
            print(access)

        for attempt in FakeResourceAccessAttempt.objects.all():
            print(attempt)


@FakeUser.fake_me
@FakeResource.fake_me
@FakeResourceAccess.fake_me
@FakeResourceAccessAttempt.fake_me
class UserAccessTestCase(AbstractTestCase, TestCase):
    """User access test case."""

    authorize, allow, deny, forget = control.get_controls()

    def setUp(self):
        """Setup users and resources."""
        self.entity_name = 'user'
        self.model = FakeUser
        self.access_model = FakeResourceAccess
        self.entities = [
            FakeUser.objects.create_user(
                username='user 1', email='', password='password 1'),
            FakeUser.objects.create_user(
                username='user 2', email='', password='password 2'),
            FakeUser.objects.create_user(
                username='user 3', email='', password='password 3'),
            FakeUser.objects.create_user(
                username='user 4', email='', password='password 4'),
            FakeUser.objects.create_user(
                username='user 5', email='', password='password 5'),
        ]
        self.resources = [
            FakeResource.objects.create(name='resource 1'),
            FakeResource.objects.create(name='resource 2'),
            FakeResource.objects.create(name='resource 3'),
            FakeResource.objects.create(name='resource 4'),
            FakeResource.objects.create(name='resource 5'),
        ]


@FakeGroup.fake_me
@FakeResource.fake_me
@FakeResourceGroupAccess.fake_me
@FakeResourceAccessAttempt.fake_me
class GroupAccessTestCase(AbstractTestCase, TestCase):
    """Group access test case."""

    authorize, allow, deny, forget = control.get_controls(for_group=True)

    def setUp(self):
        """Setup groups and resources."""
        self.entity_name = 'group'
        self.model = FakeGroup
        self.access_model = FakeResourceGroupAccess
        self.entities = [
            FakeGroup.objects.create(name='group 1'),
            FakeGroup.objects.create(name='group 2'),
            FakeGroup.objects.create(name='group 3'),
            FakeGroup.objects.create(name='group 4'),
            FakeGroup.objects.create(name='group 5'),
        ]
        self.resources = [
            FakeResource.objects.create(name='resource 1'),
            FakeResource.objects.create(name='resource 2'),
            FakeResource.objects.create(name='resource 3'),
            FakeResource.objects.create(name='resource 4'),
            FakeResource.objects.create(name='resource 5'),
        ]
