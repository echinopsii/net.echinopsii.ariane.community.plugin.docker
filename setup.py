# ***** BEGIN LICENSE BLOCK *****
#
# For copyright and licensing please refer to LICENSE.
#
# ***** END LICENSE BLOCK *****
from setuptools import setup

long_description = ('Ariane Plugin Docker map your docker containers and more.'
                    'Where you can get more informations : '
                    '   + http://ariane.echinopsii.net'
                    '   + http://confluence.echinopsii.net/confluence/display/AD/Ariane+Documentation+Home'
                    '   + IRC on freenode #ariane.echinopsii')

setup(name='ariane_docker',
      version='0.1.4-b01',
      description='Ariane Plugin Docker',
      long_description=long_description,
      author='Mathilde Ffrench',
      author_email='mathilde.ffrench@echinopsii.net',
      maintainer='Mathilde Ffrench',
      maintainer_email='mathilde.ffrench@echinopsii.net',
      url='https://github.com/echinopsii/net.echinopsii.ariane.community.plugin.docker.git',
      download_url='https://github.com/echinopsii/net.echinopsii.ariane.community.plugin.docker.git/tarball/0.1.4-b01',
      packages=['ariane_docker'],
      license='AGPLv3',
      install_requires=['docker-py>=1.6.0', 'nsenter>=0.2',
                        'pykka>=1.2.1', 'ariane_clip3==0.1.6-b01', 'ariane_procos==0.1.5-b01'],
      package_data={'': ['LICENSE', 'README.md']},
      classifiers=[
          'Development Status :: 4 - Beta',
          'Intended Audience :: Developers',
          'License :: OSI Approved :: GNU Affero General Public License v3',
          'License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)',
          'Natural Language :: English',
          'Operating System :: OS Independent',
          'Programming Language :: Python :: 3.4',
          'Programming Language :: Python :: Implementation :: CPython',
          'Topic :: Communications',
          'Topic :: Internet',
          'Topic :: Software Development :: Libraries',
          'Topic :: Software Development :: Libraries :: Python Modules',
          'Topic :: System :: Monitoring',
          'Topic :: System :: Networking'],
      zip_safe=True)
