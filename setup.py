#! /usr/bin/env python

from distutils.core import setup
  
setup(
    name = 'MiasmX', 
    version = '0.1',    
    packages = ['miasmx', 'miasmx/arch', 'miasmx/core', 'miasmx/expression', 'miasmx/tools', 'ply'],
    requires = ['python (>= 2.3)'],
    scripts = [], 
    # Metadata
    author = 'Louis Granboulan', 
    author_email = 'Louis.Granboulan(at)airbus.com',
    description = 'MiasmX: heavily patched subset of the first version of miasm',
    license = 'GPLv2.0',
    url = 'https://github.com/LRGH/miasmX',
    # keywords = '',
)   
