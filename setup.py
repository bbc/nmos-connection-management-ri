#!/usr/bin/python
#
# Copyright 2017 British Broadcasting Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


from setuptools import setup
import os


def is_package(path):
    return (
        os.path.isdir(path) and os.path.isfile(os.path.join(path, '__init__.py'))
    )


def find_packages(path, base=""):
    """ Find all packages in path """
    packages = {}
    for item in os.listdir(path):
        dir = os.path.join(path, item)
        if is_package(dir):
            if base:
                module_name = "%(base)s.%(item)s" % vars()
            else:
                module_name = item
            packages[module_name] = dir
            packages.update(find_packages(dir, module_name))
    return packages


packages = find_packages(".")
package_names = packages.keys()

packages_required = [
    "netifaces",
    "flask",
    "jsonschema",
    "gevent",
    "mediatimestamp<2.0.0",
    "requests",
    "nmoscommon>=0.20.0",
    "six",
    "nodefacade>=0.10.1",
    "werkzeug>=0.14.1,<1.0.0"  # Echo pin from nmos-common to avoid Flask overriding it
]

setup(
    name="connectionmanagement",
    version="2.2.9",
    description="Connection Management API implementation",
    url='https://github.com/bbc/nmos-device-connection-management-ri/',
    author='BBC R&D',
    author_email='peter.brightwell@bbc.co.uk',
    license='Apache 2',
    packages=package_names,
    package_dir=packages,
    install_requires=packages_required,
    package_data={'': ['templates/*']},
    scripts=[],
    data_files=[
        ('/usr/bin', ['bin/connectionmanagement'])
    ],
    long_description="Implementation of NMOS connection management API"
)
