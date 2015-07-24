#!/usr/bin/env python
 
from distutils.core import setup
from distutils.extension import Extension

# setup and compile the C++ class as a python compatabile module
# for import using the boost library and distutils
setup(name="PackageName",
    ext_modules=[
        Extension("get_the_time", ["get_the_time.cpp"],
        libraries = ["boost_python"])
    ])
