# -*- coding: utf-8 -*-

from django.utils.translation import ugettext_lazy as _


def allowed(perm):
    return 'allow_' + perm


def is_allowed(perm):
    return perm.startswith('allow_')


def denied(perm):
    return 'deny_' + perm


def is_denied(perm):
    return perm.startswith('deny_')


class Permission(object):
    SEE = 'see'
    CHANGE = 'change'
    DELETE = 'delete'
    CREATE = 'create'

    GENERAL_PERMS = (SEE, CHANGE, DELETE, CREATE)

    ALL = GENERAL_PERMS

    CHOICES = ((_('General'), (
        (SEE, _('Can see')),
        (CHANGE, _('Can change')),
        (DELETE, _('Can delete')),
        (CREATE, _('Can create')), )), )

    CHOICES_ALLOW_DENY = (
        (_('Allow: General'), (
            (allowed(SEE), _('Can see')),
            (allowed(CHANGE), _('Can change')),
            (allowed(DELETE), _('Can delete')),
            (allowed(CREATE), _('Can create')), )),
        (_('Deny: General'), (
            (denied(SEE), _('Can see')),
            (denied(CHANGE), _('Can change')),
            (denied(DELETE), _('Can delete')),
            (denied(CREATE), _('Can create')), )), )
