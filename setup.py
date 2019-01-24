from setuptools import setup, find_packages
import platform
import cemu.const as cemu

def readme():
    import io
    with io.open('README.rst', "r", encoding="utf-8") as f:
        long_description = f.read()

    return long_description

def get_required_packages():
    r = [
        'capstone>=3.0.4',
        'unicorn>=1.0',
        'PyQt5',
        'Pygments>=2.0'
    ]

    if platform.system() != "Windows":
        # Keystone installer on Windows is declared as `keystone` on pip, but on PyPI `keystone`
        # is a webapp framework (instead of `keystone-engine`). So we fix this locally.
        r.append('keystone-engine>=0.9')

    return r

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
    python_requires=">=3.4.0",
    author = cemu.AUTHOR,
    author_email = cemu.EMAIL,
    version = cemu.VERSION,
    license = cemu.LICENSE,
    include_package_data=True,
    packages=find_packages(),
    install_requires=get_required_packages(),
    entry_points={
        'console_scripts': ['cemu=cemu.__main__:main'],
    },
    keywords = ['assembly', 'disassembly', 'emulation', 'x86', 'x64', 'arm', 'mips', 'powerpc', 'sparc'],
)
