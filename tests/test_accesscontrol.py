# -*- coding: utf-8 -*-

"""Main test script."""

from django.contrib.auth.models import Group, User
from django.db import models
from django.test import TestCase, override_settings
from django.utils import timezone

import pytest

from django_fake_model import models as f

from accesscontrol import (
    AppSettings, Control, DummyAttempt, Permission,
    allowed, denied, is_allowed, is_denied)
from accesscontrol.dsm import DSM
from accesscontrol.models import Access, AccessAttempt, GroupAccess, UserAccess


def implicit_perms(cls, entity, resource=None):
    """
    Implicit permissions based on IDs.

    If the entity has the same id than the resource, then we assume he has
    all permissions on the resource.

    If resource is None, then the entity has permission to create this
    type of resource.

    Else, he has no permissions at all.
    """
    entity_id, resource_id = cls.entity_resource_id(entity, resource)
    if entity_id == resource_id:
        return Permission.ALLOW_ALL
    elif resource is None:
        return allowed(Permission.CREATE),
    return ()


class DummyAccess(Access):
    """Dummy class."""

    @classmethod
    def authorize(cls, user, perm, resource=None, save=True,
                  skip_implicit=False, attempt_model=DummyAttempt,
                  group_access_model=None):
        """Authorize implementation: always return False."""
        return False

    @classmethod
    def implicit_perms(cls, entity, resource=None):
        """Always return some perms."""
        return allowed(Permission.SEE), denied(Permission.CHANGE)


class FakeUser(f.FakeModel, User):
    """Fake user model."""


class FakeGroup(f.FakeModel, Group):
    """Fake group model."""


class FakeResource(f.FakeModel, models.Model):
    """Fake resource model."""

    name = models.CharField(max_length=100)


class FakeResourceAccess(f.FakeModel, UserAccess):
    """Fake resource access model with implicit_perms method."""


class FakeResourceGroupAccess(f.FakeModel, GroupAccess):
    """Fake resource group access model with same implicit_perms method."""


class FakeResourceAccessAttempt(f.FakeModel, AccessAttempt):
    """Fake resource access attempt model."""


FakeResourceAccess.implicit_perms = classmethod(implicit_perms)
FakeResourceGroupAccess.implicit_perms = classmethod(implicit_perms)


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

    def test_wrong_resource(self):
        with pytest.raises(ValueError) as e:
            control.authorize(0, 'whatever', 'NotToBe')
        assert 'not a correct value' in str(e.value)

        with pytest.raises(ValueError) as e:
            control.authorize(0, 'whatever', int)
        assert 'does not match any mapping' in str(e.value)

    @override_settings(ACCESS_CONTROL_IMPLICIT=False)
    def test_disabled_implicit(self):
        """Test implicit check with implicit setting set to False."""
        assert DummyAccess.authorize_implicit(0, Permission.SEE) is None

    def test_ignored_perms(self):
        """Check that ignored perm is really ignored."""
        class DA(DummyAccess):
            ignored_perms = (Permission.SEE, )

        assert DA.authorize_implicit(0, Permission.SEE) is None

    def test_allowed_or_denied_implicit_perms(self):
        """Check that permission type is respected (allowed/denied)."""
        assert DummyAccess.authorize_implicit(0, Permission.SEE)
        assert not DummyAccess.authorize_implicit(0, Permission.CHANGE)

    def test_default_implicit_perms_are_empty(self):
        """Assert no permissions is implicitly given by default."""
        assert Access.implicit_perms(0) == ()

    def test_settings_are_correctly_loaded(self):
        """Assert settings are correctly loaded."""
        app_settings = AppSettings()
        app_settings.load()

        assert app_settings.ACCESS_CONTROL_APP_LABEL == AppSettings.get_app_label()  # noqa
        assert app_settings.ACCESS_CONTROL_PERMISSION_CLASS == AppSettings.get_permission_class()  # noqa
        assert app_settings.ACCESS_CONTROL_IMPLICIT == AppSettings.get_implicit()  # noqa
        assert app_settings.ACCESS_CONTROL_DEFAULT_RESPONSE == AppSettings.get_default_response()  # noqa
        assert app_settings.ACCESS_CONTROL_INHERIT_GROUP_PERMS == AppSettings.get_inherit_group_perms()  # noqa
        assert app_settings.allowed == AppSettings.get_allowed()
        assert app_settings.denied == AppSettings.get_denied()
        assert app_settings.is_allowed == AppSettings.get_is_allowed()
        assert app_settings.is_denied == AppSettings.get_is_denied()

    @override_settings(
        ACCESS_CONTROL_PERMISSION='accesscontrol.permission.Permission',
        ACCESS_CONTROL_ALLOWED='accesscontrol.permission.allowed',
        ACCESS_CONTROL_DENIED='accesscontrol.permission.denied',
        ACCESS_CONTROL_IS_ALLOWED='accesscontrol.permission.is_allowed',
        ACCESS_CONTROL_IS_DENIED='accesscontrol.permission.is_denied')
    def test_settings_objects_are_correctly_imported(self):
        """Assert that Python object is correctly imported given its path."""
        app_settings = AppSettings()
        app_settings.load()

        assert isinstance(app_settings.ACCESS_CONTROL_PERMISSION_CLASS, type)
        assert callable(app_settings.allowed)
        assert callable(app_settings.is_allowed)
        assert callable(app_settings.denied)
        assert callable(app_settings.is_denied)


def dummy(*args, **kwargs):
    """Dummy function, print given args."""
    print(args, kwargs)


def _create_users():
    return [
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


def _create_groups():
    return [
        FakeGroup.objects.create(name='group 1'),
        FakeGroup.objects.create(name='group 2'),
        FakeGroup.objects.create(name='group 3'),
        FakeGroup.objects.create(name='group 4'),
        FakeGroup.objects.create(name='group 5'),
    ]


def _create_resources():
    return [
        FakeResource.objects.create(name='resource 1'),
        FakeResource.objects.create(name='resource 2'),
        FakeResource.objects.create(name='resource 3'),
        FakeResource.objects.create(name='resource 4'),
        FakeResource.objects.create(name='resource 5'),
    ]


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
                    assert not self.authorize(entity, Permission.SEE,
                                              resource)
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

        self.test_explicit_rights()
        heatmap_reverse = matrix.to_highcharts_heatmap(
            reverse=True, filters={'id__in': (1, 2)}, orders=['-id'])
        assert heatmap_reverse['series'][0]['data'] != []

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

    def test_overwrite_and_delete_permissions(self):
        """Assert same objects are used when overwriting permissions."""
        # Allow
        self.allow(self.entities[0], Permission.SEE, self.resources[0])
        access_rule_allow = self.access_model.objects.get(
            entity=self.entities[0].id, perm=allowed(Permission.SEE),
            resource=self.resources[0].id)
        assert access_rule_allow

        # Deny
        self.deny(self.entities[0], Permission.SEE, self.resources[0])
        access_rule_deny = self.access_model.objects.get(
            entity=self.entities[0].id, perm=denied(Permission.SEE),
            resource=self.resources[0].id)
        assert access_rule_deny

        # Allow again
        self.allow(self.entities[0], Permission.SEE, self.resources[0])
        access_rule_allow_again = self.access_model.objects.get(
            entity=self.entities[0].id, perm=allowed(Permission.SEE),
            resource=self.resources[0].id)
        assert access_rule_allow_again

        assert access_rule_allow == access_rule_deny == access_rule_allow_again

        # Forget
        self.forget(self.entities[0], Permission.SEE, self.resources[0])
        with pytest.raises(self.access_model.DoesNotExist) as e:
            self.access_model.objects.get(
                entity=self.entities[0].id, perm=denied(Permission.SEE),
                resource=self.resources[0].id)
        assert 'matching query does not exist' in str(e.value)

    def test_attempt_methods(self):
        """Just run through the code."""
        # FIXME: actually test the code, don't just run it
        self.test_explicit_rights()

        import random
        attempt = random.choice(FakeResourceAccessAttempt.objects.all())
        attempt.like_this(response=False, implicit=False,
                          datetime__lt=timezone.now())
        assert attempt.total() > 0


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
        self.entities = _create_users()
        self.resources = _create_resources()


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
        self.entities = _create_groups()
        self.resources = _create_resources()


@FakeUser.fake_me
@FakeGroup.fake_me
@FakeResource.fake_me
@FakeResourceAccess.fake_me
@FakeResourceGroupAccess.fake_me
@FakeResourceAccessAttempt.fake_me
class PermissionInheritanceTestCase(TestCase):
    """Case to test user permission inheritance from groups."""

    def setUp(self):
        """Setup users, groups and resources."""
        self.users = _create_users()
        self.groups = _create_groups()
        self.resources = _create_resources()
        self._patch_implicit_perms_methods()
        self._set_users_groups()
        self._set_users_explicit_perms()
        self._set_groups_explicit_perms()

    def _patch_implicit_perms_methods(self):
        def _group_implicit_perms(cls, group, resource=None):
            group_id, resource_id = cls.entity_resource_id(group, resource)
            if group_id == resource_id:
                return allowed(Permission.SEE)  # Only return SEE, not ALL.
            elif resource is None:
                return allowed(Permission.CREATE),
            return ()

        def _user_implicit_perms(cls, user, resource=None):
            return ()  # No implicit perms for users.

        FakeResourceAccess.implicit_perms = classmethod(_user_implicit_perms)
        FakeResourceGroupAccess.implicit_perms = classmethod(_group_implicit_perms)  # noqa

    def _set_users_groups(self):
        self.users[0].groups.add(self.groups[1])

    def _set_users_explicit_perms(self):
        control.allow(self.users[0], Permission.CHANGE, self.resources[1])
        control.deny(self.users[0], Permission.DELETE, self.resources[2])

    def _set_groups_explicit_perms(self):
        control.allow_group(self.groups[1], Permission.DELETE,
                            self.resources[2])
        control.allow_group(self.groups[1], Permission.CHANGE,
                            self.resources[3])

    def test_implicit_inheritance(self):
        """Assert implicit permissions are correctly inherited."""
        # Inherited from group 1.
        assert control.authorize(self.users[0], Permission.SEE,
                                 self.resources[0])

        assert control.authorize(self.users[0], Permission.CREATE,
                                 FakeResource)
        # Not inherited.
        assert not control.authorize(self.users[0], Permission.SEE,
                                     self.resources[1])

    def test_explicit_inheritance(self):
        """Assert explicit permissions are correctly inherited."""
        # Inherited from group 1.
        assert control.authorize(self.users[0], Permission.CHANGE,
                                 self.resources[3])

        # Should be inherited from group 1, but denied to user 0.
        assert not control.authorize(self.users[0], Permission.DELETE,
                                     self.resources[2])

    def test_attempts(self):
        """Assert attempts are correctly created."""
        self.test_implicit_inheritance()
        self.test_explicit_inheritance()

        assert FakeResourceAccessAttempt.objects.get(
            user=self.users[0].id, perm=Permission.SEE,
            resource=self.resources[0].id, response=True, implicit=True,
            group_inherited=True, group=self.groups[1].id)

        assert FakeResourceAccessAttempt.objects.get(
            user=self.users[0].id, perm=Permission.CREATE,
            resource=None, response=True, implicit=True,
            group_inherited=True, group=self.groups[1].id)

        assert FakeResourceAccessAttempt.objects.get(
            user=self.users[0].id, perm=Permission.SEE,
            resource=self.resources[1].id, response=False, implicit=False,
            group_inherited=False, default=True)

        assert FakeResourceAccessAttempt.objects.get(
            user=self.users[0].id, perm=Permission.CHANGE,
            resource=self.resources[3].id, response=True, implicit=False,
            group_inherited=True, group=self.groups[1].id)

        assert FakeResourceAccessAttempt.objects.get(
            user=self.users[0].id, perm=Permission.DELETE,
            resource=self.resources[2].id, response=False, implicit=False,
            group_inherited=False)

    def test_casting_up_id_to_user(self):
        """Assert cast from id to User model is OK."""
        assert control.authorize(self.users[0].id, Permission.CHANGE,
                                 self.resources[3])

    def test_print_access_attempt(self):
        """Assert printing access attempts is OK."""
        self.test_implicit_inheritance()
        self.test_explicit_inheritance()

        for attempt in FakeResourceAccessAttempt.objects.all():
            print(attempt)

    @override_settings(ACCESS_CONTROL_INHERIT_GROUP_PERMS=False)
    def test_disabled_inheritance(self):
        """Test inheritance is disabled with inherit setting set to False."""
        assert not control.authorize(self.users[0], Permission.CHANGE,
                                     self.resources[3])
