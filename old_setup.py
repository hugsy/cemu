from pathlib import Path

from setuptools import find_packages, setup

import cemu.const as const


def readme():
    import io

    with io.open("README.md", "r", encoding="utf-8") as f:
        return f.read()


def get_required_packages():
    return [x.strip() for x in Path("./requirements.txt").open("r").readlines()]


setup(
    name=const.PROGNAME,
    description=const.DESCRIPTION,
    long_description=(Path(__file__).parent / "README.md").read_text(),
    long_description_content_type="text/markdown",
    url=const.URL,
    download_url=const.RELEASE_LINK,
    classifiers=[
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Topic :: Software Development :: Assemblers",
        "Natural Language :: English",
    ],
    python_requires=">=3.10.0",
    author=const.AUTHOR,
    author_email=const.EMAIL,
    version=const.VERSION,
    license=const.LICENSE,
    include_package_data=True,
    packages=find_packages(),
    install_requires=(Path(__file__).parent / "requirements.txt").open().readlines(),
    entry_points={
        "console_scripts": ["cemu=cemu.__main__:main"],
    },
    keywords=[
        "assembly",
        "disassembly",
        "emulation",
        "x86",
        "x64",
        "arm",
        "aarch64",
        "mips",
        "powerpc",
        "sparc",
    ],
)
