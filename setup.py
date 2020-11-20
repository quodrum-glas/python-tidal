#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup
import sys

required = ['requests']
if sys.version_info < (3, 4):
    required.append('enum34')

long_description = ""
with open('README.md') as f:
    long_description += f.read()

with open('HISTORY.md') as f:
    long_description += '\n\n'
    long_description += f.read()

setup(
    name='tidaloauth4mopidy',
    version='0.2.0',
    description='Unofficial API for TIDAL music streaming service.',
    long_description=long_description,
    long_description_content_type="text/markdown",
    author='Thomas Amland',
    author_email='thomas.amland@googlemail.com',
    maintainer='quodrumglas',
    maintainer_email='quodrumglas@email.com',
    url='https://github.com/quodrum-glas/python-tidal',
    license='LGPL',
    packages=['tidaloauth4mopidy'],
    install_requires=required,
    keywords='',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)',
        "Programming Language :: Python :: 2",
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
    ],
)
