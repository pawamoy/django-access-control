# -*- coding: utf-8 -*-

"""Main test script."""



from django.test import TestCase

import accesscontrol


class MainTestCase(TestCase):
    """Main Django test case"""
    def setUp(self):
        pass

    def test_main(self):
        assert accesscontrol

    def tearDown(self):
        pass
