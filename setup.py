#!/usr/bin/env python3
from setuptools import setup

__author__ = 'Sander Maijers <sander@clarin.eu>'
__version__ = '1.0.dev0'

INSTALL_REQUIRES = ['lxml>=4.0']  # TODO: version

setup(author=__author__,
      author_email=__author__,
      classifiers=('Natural Language :: English',
                   'Programming Language :: Python',),
      data_files=[('static', ['SPF_SAML_metadata_processor/static/'
                              'remove_key_whitespace.xsl',
                              'SPF_SAML_metadata_processor/static/'
                              'remove_namespace_prefixes.xsl'])],
      # TODO: redundant?
      description='Collects, filters, splits/aggregates, SAML metadata about '
                  'CLARIN SPF SPs across identity federations to assess its '
                  'current state. Results are shown by the Centre Registry.',
      include_package_data=True,
      install_requires=INSTALL_REQUIRES,
      license='GPLv3',
      name='SPF_SAML_metadata_processor',
      packages=['SPF_SAML_metadata_processor'],
      url='https://github.com/clarin-eric/',  # TODO: complete
      version=__version__,
      )
