#!/usr/bin/env python

from distutils.core import setup, Extension

setup(
    name = "rcsparse",
    version = "0.1",
    ext_modules = [
        Extension("rcsparse", ["py-rcsparse.c", "rcsparse.c"])
    ]
)
