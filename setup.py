from setuptools import setup, find_packages

import cemu

def readme():
    import io
    with io.open('README.rst', "r", encoding="utf-8") as f:
        long_description = f.read()

    return long_description


setup(
    name = cemu.PROGNAME,
    description='''Cemu is a simple assembly/dissembly/emulation IDE that provides an easy Plug-n-Play environment to start playing with many architectures (currently supports x86-{32,64}, ARM, AARCH64, MIPS, SPARC).''',
    long_description=readme(),
    url = cemu.URL,
    download_url = cemu.RELEASE_LINK,
    classifiers=[
        'Development Status :: 4 - Beta',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Topic :: Software Development :: Assemblers',
        'Natural Language :: English',
    ],
    author = cemu.AUTHOR,
    author_email = cemu.EMAIL,
    version = cemu.VERSION,
    license = cemu.LICENSE,
    include_package_data=True,
    packages=find_packages(),
    install_requires=[
        'capstone>=3.0.4',
        'keystone-engine>=0.9',
        'unicorn>=1.0',
        'PyQt5',
        'Pygments>=2.0'
    ],
    entry_points={
        'console_scripts': ['cemu=cemu.__main__:main'],
    },
    keywords = ['assembly', 'disassembly', 'emulation', 'x86', 'x64', 'arm', 'mips', 'powerpc', 'sparc'],
)
