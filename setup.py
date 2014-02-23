from setuptools import setup

setup(name='python-keepasshttp',
      version='0.1',
      description='KeePassHTTP server for v3 databases',
      author='Dan Smith',
      author_email='dsmith@danplanet.com',
      url='http://github.com/kk7ds/python-keepasshttp',
      license='GPLv3',
      scripts=['keepass_server'],
      install_requires=['python-keepass'],
     )
