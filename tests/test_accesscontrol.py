# -*- coding: utf-8 -*-

"""Main test script."""

from django.contrib.auth.models import User
from django.db import models

from django.test import TestCase

from django_fake_model import models as f

from accesscontrol import Control, Permission
from accesscontrol.dsm import DSM
from accesscontrol.models import Access, AccessAttempt


class FakeUser(f.FakeModel, User):
    pass


class FakeResource(f.FakeModel, models.Model):
    name = models.CharField(max_length=100)


class FakeResourceAccess(f.FakeModel, Access):
    @classmethod
    def implicit_perms(cls, user, resource=None):
        user_id, resource_id = Access._user_resource_id(user, resource)
        if user_id == resource_id:
            return Permission.ALL
        elif resource is None:
            return Permission.CREATE,
        return ()


class FakeResourceAccessAttempt(f.FakeModel, AccessAttempt):
    pass


authorize, allow, deny, forget = Control({
    FakeResource: (FakeResourceAccess, FakeResourceAccessAttempt)
}).get_controls()


@FakeUser.fake_me
@FakeResource.fake_me
@FakeResourceAccess.fake_me
@FakeResourceAccessAttempt.fake_me
class MainTestCase(TestCase):
    """Main Django test case"""
    def setUp(self):
        self.users = [
            User.objects.create_user(username='user 1', email='', password='password 1'),
            User.objects.create_user(username='user 2', email='', password='password 2'),
            User.objects.create_user(username='user 3', email='', password='password 3'),
            User.objects.create_user(username='user 4', email='', password='password 4'),
            User.objects.create_user(username='user 5', email='', password='password 5'),
        ]
        self.resources = [
            FakeResource.objects.create(name='resource 1'),
            FakeResource.objects.create(name='resource 2'),
            FakeResource.objects.create(name='resource 3'),
            FakeResource.objects.create(name='resource 4'),
            FakeResource.objects.create(name='resource 5'),
        ]

    def test_implicit_rights(self):
        for u, user in enumerate(self.users):
            for r, resource in enumerate(self.resources):
                if u == r:
                    assert authorize(user, Permission.SEE, resource)
                    assert authorize(user, Permission.CHANGE, resource)
                    assert authorize(user, Permission.DELETE, resource)
                    assert authorize(user, Permission.CREATE, resource)
                else:
                    assert not authorize(user, Permission.SEE, resource)
                    assert not authorize(user, Permission.CHANGE, resource)
                    assert not authorize(user, Permission.DELETE, resource)
                    assert not authorize(user, Permission.CREATE, resource)

        for user in self.users:
            assert authorize(user, Permission.CREATE, FakeResource)

    def test_implicit_access_attempts(self):
        self.test_implicit_rights()

        for u, user in enumerate(self.users):
            for r, resource in enumerate(self.resources):
                if u == r:
                    for perm in Permission.GENERAL_PERMS:
                        assert FakeResourceAccessAttempt.objects.get(
                            usr=user.id, res=resource.id, val=perm, response=True, implicit=True
                        )
                else:
                    for perm in Permission.GENERAL_PERMS:
                        assert FakeResourceAccessAttempt.objects.get(
                            usr=user.id, res=resource.id, val=perm, response=False, implicit=True
                        )

        for user in self.users:
            assert FakeResourceAccessAttempt.objects.get(
                usr=user.id, res=None, val=Permission.CREATE, response=True, implicit=True)

    def test_explicit_rights(self):
        for resource in self.resources:
            allow(self.users[0], Permission.SEE, resource)
            allow(self.users[0], Permission.CHANGE, resource)
            allow(self.users[0], Permission.DELETE, resource)

        allow(self.users[0], Permission.CREATE, FakeResource)

        for resource in self.resources:
            assert authorize(self.users[0], Permission.SEE, resource)
            assert authorize(self.users[0], Permission.CHANGE, resource)
            assert authorize(self.users[0], Permission.DELETE, resource)

        assert authorize(self.users[0], Permission.CREATE, 'FakeResource')

        forget(self.users[0], Permission.DELETE, self.resources[-1])
        assert not authorize(self.users[0], Permission.DELETE, self.resources[-1])

        for resource in self.resources:
            deny(self.users[-1], Permission.SEE, resource)
            deny(self.users[-1], Permission.CHANGE, resource)
            deny(self.users[-1], Permission.DELETE, resource)

        deny(self.users[-1], Permission.CREATE, 'FakeResource')

        for resource in self.resources:
            assert not authorize(self.users[-1], Permission.SEE, resource)
            assert not authorize(self.users[-1], Permission.CHANGE, resource)
            assert not authorize(self.users[-1], Permission.DELETE, resource)

        assert not authorize(self.users[-1], Permission.CREATE, FakeResource)

        forget(self.users[-1], Permission.CREATE, FakeResource)
        assert authorize(self.users[-1], Permission.CREATE, FakeResource)

    def test_explicit_access_attempts(self):
        self.test_explicit_rights()

        for resource in self.resources:
            assert FakeResourceAccessAttempt.objects.get(
                usr=self.users[0].id, val=Permission.SEE, res=resource.id,
                response=True, implicit=False)
            assert FakeResourceAccessAttempt.objects.get(
                usr=self.users[0].id, val=Permission.CHANGE, res=resource.id,
                response=True, implicit=False)
            assert FakeResourceAccessAttempt.objects.get(
                usr=self.users[0].id, val=Permission.DELETE, res=resource.id,
                response=True, implicit=False)

        assert FakeResourceAccessAttempt.objects.get(
            usr=self.users[0].id, val=Permission.CREATE, res=None,
            response=True, implicit=False)

        assert FakeResourceAccessAttempt.objects.get(
            usr=self.users[0].id, val=Permission.DELETE, res=self.resources[-1].id,
            response=False, implicit=True)

        for resource in self.resources:
            assert FakeResourceAccessAttempt.objects.get(
                usr=self.users[-1].id, val=Permission.SEE, res=resource.id,
                response=False, implicit=False)
            assert FakeResourceAccessAttempt.objects.get(
                usr=self.users[-1].id, val=Permission.CHANGE, res=resource.id,
                response=False, implicit=False)
            assert FakeResourceAccessAttempt.objects.get(
                usr=self.users[-1].id, val=Permission.DELETE, res=resource.id,
                response=False, implicit=False)

        assert FakeResourceAccessAttempt.objects.get(
            usr=self.users[-1].id, val=Permission.CREATE, res=None,
            response=False, implicit=False)

        assert FakeResourceAccessAttempt.objects.get(
            usr=self.users[-1].id, val=Permission.CREATE, res=None,
            response=True, implicit=True)

    def test_implicit_rights_again(self):
        self.test_explicit_rights()

        access_attempts_number = FakeResourceAccessAttempt.objects.all().count()

        assert FakeResourceAccess.authorize_implicit(
            self.users[-1], Permission.SEE, self.resources[-1])
        assert FakeResourceAccess.authorize_implicit(
            self.users[-1], Permission.CHANGE, self.resources[-1])
        assert FakeResourceAccess.authorize_implicit(
            self.users[-1], Permission.DELETE, self.resources[-1])

        assert FakeResourceAccessAttempt.objects.all().count() == access_attempts_number

    def test_matrix(self):
        matrix = DSM(FakeResource, FakeResourceAccess)
        heatmap = matrix.to_highcharts_heatmap()
        heatmap_implicit = matrix.to_highcharts_heatmap(implicit=True)
        return True
