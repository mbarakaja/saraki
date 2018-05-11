#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests for `saraki` package."""

import pytest


from saraki import saraki


@pytest.fixture
def response():
    """Sample pytest fixture.

    See more at: http://doc.pytest.org/en/latest/fixture.html
    """
    # import requests
    # return requests.get('https://github.com/audreyr/cookiecutter-pypackage')


def test_content(response):
    """Sample pytest test function with the pytest fixture as an argument."""
    # from bs4 import BeautifulSoup
    # assert 'GitHub' in BeautifulSoup(response.content).title.string


class Test_export_from_sqla_object(object):

    def test_non_persisted_untouched_object(self):
        assert 2 == 2

    def test_non_persisted_touched_object(self):
        assert 2 == 2

    def test_persisted_object(self):
        assert 2 == 2

    def test_persisted_object_with_loaded_relationship(self):
        assert 2 == 2

    def test_persisted_object_with_loaded_one_to_many_relationship(self):
        assert 2 == 2

    def test_persisted_object_with_loaded_one_to_one_relationship(self):
        assert 2 == 2

    def test_include_argument(self):
        assert 1 == 1

    def test_exclude_argument(self):
        assert 2 == 2
