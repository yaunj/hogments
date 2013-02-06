#!/usr/bin/env python
from setuptools import setup

entry_points = """
[pygments.lexers]
snort = hogments.hog:SnortLexer
"""

setup(
    name = 'hogments',
    version = '0.1',
    description = __doc__,
    author = "Rune Hammersland",
    packages = ['hogments'],
    entry_points = entry_points
)
