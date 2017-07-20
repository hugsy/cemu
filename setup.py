from setuptools import setup, find_packages

def readme():
    with open('README.md') as f:
        return f.read()

setup(
    name='cemu',
    description='''Cemu is a Cheap EMUlator, that combines all the advantages of a basic assembly IDE,
    compilation and execution environment by relying on the great libraries Keystone, Unicorn and
    Capstone engines in a Qt powered GUI.''',
    long_description=readme(),
    url='https://github.com/hugsy/cemu',
    classifiers=[
        'Development Status :: 4 - Beta',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Topic :: Software Development :: Assemblers',
        'Natural Language :: English',
    ],
    author='hugsy',
    author_email='hugsy@blah.cat',
    version='0.2',
    license='MIT',
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
