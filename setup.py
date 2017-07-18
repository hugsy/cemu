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
    author='_hugsy_',
    version='0.1',
    license='MIT',
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
    }
)
