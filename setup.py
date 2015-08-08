from setuptools import setup

setup(name='syzacz',
      version='0.7',
      packages=('syzacz',),
      scripts=('syzacz-cli',),
      install_requires=('prettytable', 'ldap3', 'randstr', ),
      )
