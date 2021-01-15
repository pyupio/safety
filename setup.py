#!/usr/bin/env python
# -*- coding: utf-8 -*-
from io import open  # Python 2 compatibility

from setuptools import setup

# There are problems running setup.py on Windows if the encoding is not set
with open('README.md', encoding='utf8') as readme_file:
    readme = readme_file.read()
with open('HISTORY.rst', encoding='utf8') as history_file:
    history = history_file.read()


setup(
    name='safety',
    version='1.10.3',
    description="Checks installed dependencies for known vulnerabilities.",
    long_description=readme + '\n\n' + history,
    long_description_content_type="text/markdown",
    author="pyup.io",
    author_email='support@pyup.io',
    url='https://github.com/pyupio/safety',
    packages=[
        'safety',
    ],
    package_dir={'safety': 'safety'},
    entry_points={
        'console_scripts': [
            'safety=safety.cli:cli'
        ]
    },
    include_package_data=True,
    install_requires=[
        'setuptools',
        'Click>=6.0',
        'requests',
        'packaging',
        'dparse>=0.5.1'
    ],
    python_requires=">=3.5",
    license="MIT license",
    zip_safe=False,
    keywords='safety',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
    ]
)
