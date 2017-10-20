from standardfile import __version__
from setuptools import setup, find_packages


setup(
    name='standardfile',
    version=__version__,
    author='Matthias Vogelgesang',
    author_email='matthias.vogelgesang@gmail.com',
    url='http://github.com/matze/python-standardfile',
    license='LGPL',
    packages=find_packages(),
    scripts=[
        'bin/sf-test',
        'bin/sf-mount',
    ],
    install_requires=[
        'fusepy',
        'pycrypto',
        'requests',
    ],
    description="Standardfile client and tools",
)
