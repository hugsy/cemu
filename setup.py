from setuptools import setup, find_packages

def readme():
    with open('README.rst') as f:
        return f.read()

PROGNAME = 'cemu'
AUTHOR = 'hugsy'
EMAIL = 'hugsy@blah.cat'
VERSION = '0.2'
URL = 'https://github.com/{}/{}'.format(AUTHOR, PROGNAME)
RELEASE_LINK = '{}/archive/{}.tar.gz'.format(URL, VERSION)
LICENSE = 'MIT'

setup(
    name=PROGNAME,
    description='''Cemu is a Cheap EMUlator, that combines all the advantages of a basic assembly IDE, compilation and execution environment by relying on the great libraries Keystone, Unicorn and Capstone engines in a Qt powered GUI.''',
    long_description=readme(),
    url=URL,
    download_url=RELEASE_LINK,
    classifiers=[
        'Development Status :: 4 - Beta',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Topic :: Software Development :: Assemblers',
        'Natural Language :: English',
    ],
    author=AUTHOR,
    author_email=EMAIL,
    version=VERSION,
    license=LICENSE,
    include_package_data=True,
    packages=find_packages(),
    install_requires=[
        'capstone>=3.0.4',
        'keystone-engine>=0.9',
        'unicorn>=1.0',
        'PyQt5',
        'enum34',
        'Pygments>=2.0'
    ],
    entry_points={
        'console_scripts': ['cemu=cemu.__main__:main'],
    },
    keywords = ['assembly', 'disassembly', 'emulation', 'x86', 'arm', 'mips', 'powerpc', 'sparc'],
)
