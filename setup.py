#!/usr/bin/env python3

from setuptools import setup, find_packages

VERSION = "1.0"

setup(
    name="sentinel-ca",
    version=VERSION,
    description="Automated certification authority to issue certificates for authenticated devices",
    long_description=open("README.md").read(),
    author="CZ.NIC, z.s.p.o.",
    author_email="packaging@turris.cz",
    url="https://gitlab.nic.cz/turris/sentinel/ca/",
    license="GPLv3",
    packages=find_packages(exclude=("tests*",)),
    install_requires=[
        "cryptography",
        "redis",
        "sn@git+https://gitlab.nic.cz/turris/sentinel/sn.git",
    ],
    extras_require={
        "tests": [
            "black",
            "coverage",
            "pytest",
            "pytest-cov",
        ],
    },
    entry_points={
        "console_scripts": [
            "sentinel-ca = sentinel_ca.__main__:main",
        ]
    },
)
