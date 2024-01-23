# SPDX-License-Identifier: MIT

from setuptools import setup

with open("requirements.txt", "r") as f:
    requirements = f.read().splitlines()

setup(
    name="talos-bootstrap",
    version="0.1.0",
    py_modules=["bootstrap"],
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "bootstrap = bootstrap:main",
        ],
    },
)
