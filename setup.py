#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

from platform import python_implementation
from sys import version_info
from setuptools import setup

__author__ = 'Sander Maijers <sander@clarin.eu>'
__version__ = '1.0.dev0'

required_python_version = (3, 4,)
python_implementation_str = python_implementation()

if not (python_implementation_str == 'CPython' and (version_info.major, version_info.minor) == required_python_version):
    raise RuntimeError('ERROR: running under unsupported {python_implementation:s} version '
                       '{major_version:d}.{minor_version:d}. Please consult the documentation for supported platforms. '
                       .format(python_implementation=python_implementation,
                               major_version=version_info.major,
                               minor_version=version_info.minor))

install_requires = ['lxml>3.4,<3.5']  # TODO: version

setup(author=__author__,
      author_email=__author__,
      classifiers=('Natural Language :: English', 'Programming Language :: Python',),
      data_files=[('static', ['SPF_SAML_metadata_processor/static/remove_key_whitespace.xsl',
                              'SPF_SAML_metadata_processor/static/remove_namespace_prefixes.xsl'])],
      # TODO: redundant?
      description='Collects, filters, splits/aggregates, SAML metadata about CLARIN SPF SPs across identity federations'
                  ' to assess its current state. Results are shown by the Centre Registry.',
      include_package_data=True,
      install_requires=install_requires,
      license='GPLv3',
      name='SPF_SAML_metadata_processor',
      packages=['SPF_SAML_metadata_processor'],
      url='https://github.com/clarin-eric/',  # TODO: complete
      version=__version__,
      )
