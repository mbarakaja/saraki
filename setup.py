#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""The setup script."""

from configparser import ConfigParser
from setuptools import setup, find_packages

with open("README.rst") as readme_file:
    readme = readme_file.read()

with open("HISTORY.rst") as history_file:
    history = history_file.read()


def clean(k, v):
    rk = k[1:-1] if k[0] == '"' else k
    rv = v[1:-1] if v[0] == '"' else v
    return rk, rv


# Pipfile is in toml format and the only parser available in installation time
# is ConfigParser from the standar library. It can sort of parse it with some
# help.


pipfile = ConfigParser()
pipfile.read("Pipfile")
packages = dict(pipfile["packages"])

requirements = ["".join(clean(key, value)) for key, value in packages.items()]

setup_requirements = ["pytest-runner"]

test_requirements = ["pytest"]

setup(
    author="José María Domínguez Moreno",
    author_email="miso.0b11@gmail.com",
    classifiers=[
        "Development Status :: 2 - Pre-Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Natural Language :: English",
        "Programming Language :: Python :: 3.6",
    ],
    description="A web application helper",
    install_requires=requirements,
    license="MIT license",
    long_description=readme + "\n\n" + history,
    include_package_data=True,
    keywords="saraki",
    name="saraki",
    packages=find_packages(include=["saraki"]),
    setup_requires=setup_requirements,
    test_suite="tests",
    tests_require=test_requirements,
    url="https://github.com/mbarakaja/saraki",
    version="0.1.0a0",
    zip_safe=False,
)
