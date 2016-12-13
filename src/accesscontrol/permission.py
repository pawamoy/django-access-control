# -*- coding: utf-8 -*-

"""
Permission module with Permission class.

You can specify your own permission class (which is just an enumeration)
and your own corresponding ``allowed``, ``is_allowed``, ``denied`` and
``is_denied`` functions in Django settings.
"""

from django.utils.translation import ugettext_lazy as _


def allowed(perm):
    """
    Return the allowed version of a permission.

    Args:
        perm (str): a permission.

    Returns:
        str: the allowed version of a permission.
    """
    return 'allow_' + perm


def is_allowed(perm):
    """
    Check if the permission is the allowed version of itself.

    Args:
        perm (str): a permission.

    Returns:
        bool: the permission is the allowed version of itself.
    """
    return perm.startswith('allow_')


def denied(perm):
    """
    Return the denied version of a permission.

    Args:
        perm (str): a permission.

    Returns:
        str: the allowed version of a permission.
    """
    return 'deny_' + perm


def is_denied(perm):
    """
    Check if the permission is the denied version of itself.

    Args:
        perm (str): a permission.

    Returns:
        bool: the permission is the denied version of itself.
    """
    return perm.startswith('deny_')


class Permission(object):
    """
    Permission class.

    This is concretely just an enumeration of constants.

    How to write your own:

    - Create a class,
    - Add your own permissions as class variables,
    - Maybe regroup permissions by genre in additional tuples,
    - Add a CHOICES tuple (with groups or not),
    - Add a CHOICES_ALLOW_DENY tuple that combines the two versions of each
        permission: allowed and denied.
    """

    SEE = 'see'
    CHANGE = 'change'
    DELETE = 'delete'
    CREATE = 'create'

    GENERAL_PERMS = (SEE, CHANGE, DELETE, CREATE)

    ALL = GENERAL_PERMS

    ALLOW_ALL = [allowed(p) for p in ALL]
    DENY_ALL = [denied(p) for p in ALL]

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
