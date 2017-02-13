#!/usr/bin/env python
# Copyright 2016 Peter Goodman (peter@trailofbits.com), all rights reserved.

import os
os.chdir(os.path.dirname(os.path.abspath(__file__)))

from setuptools import setup, find_packages

setup(name="remill-disass",
      description="Binary program disassembler for Remill.",
      version="0.0.1",
      url="https://github.com/trailofbits/remill",
      author="Peter Goodman",
      author_email="peter@trailofbits.com",
      license="Apache-2.0",
      packages=['remill_disass', 'remill_disass.ida'],
      entry_points={
        "console_scripts": [
          "remill-disass = remill_disass.__main__:main"
        ]})
