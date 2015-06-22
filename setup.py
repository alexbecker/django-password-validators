from setuptools import setup

import os

os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

setup(
    name = "django_password_validators",
    version = "0.1",
    packages = ["password_validators"],
    include_package_data = True,
    install_requires = [
        "pyparsing>=2.0",
    ],
)
