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

import socket
import re


def isValidAutoIp(ip):
    """Checks an IPv4 or IPv6 address where "auto" is a valid value"""
    if ip != "auto":
        try:
            isValidIpv4(ip)
        except TypeError:
            isValidIpv6(ip)
    return True


def isValidIp(address):
    """Checks if address is EITHER IPv4 or IPv6"""
    try:
        isValidIpv4(address)
    except TypeError:
        isValidIpv6(address)
    return True


def isValidIpv4(address):
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:  # make function work on systems without pton
        try:
            socket.inet_aton(address)
        except socket.error:
            raise TypeError('Invalid IP Address')
            # address differences in parsing of addresses between aton and pton
        if address.count('.') == 3:
            return True
        else:
            raise TypeError('Invalid IP Address')
    except socket.error:
        raise TypeError('Invalid IP Address')
    return True


def isValidIpv6(address):
    try:
        socket.inet_pton(socket.AF_INET6, address)
    except socket.error:
        raise TypeError('Invalid IP Address')
    return True


def isValidPort(port):
    try:
        val = int(port)
    except Exception:
        raise TypeError('Port number must be an integer')
    if val < 5000 or val > 49151:
        raise TypeError('Port number must be in range 5000-49151 inclusive')
    return True


def isValidAutoPort(port):
    """Validation for ports where "auto" is an acceptable value"""
    if(port != "auto"):
        try:
            isValidPort(port)
        except TypeError:
            raise TypeError("Must be 'auto' or in range 5000 to 49151")
    return True


def isValidEnum(value, validDict):
    if value in validDict:
        return True
    raise TypeError('Invalid option, must be one ' + str(validDict))


def isInRange(value, maximum, minimum):
    try:
        float(value)
    except TypeError:
        raise TypeError('Must be numeric')
    if value < minimum or value > maximum:
        msg = 'Value must in range ' + str(minimum) + ' to ' + str(maximum)
        raise TypeError(msg)
    return True


def isInt(value):
    try:
        int(value)
    except TypeError:
        raise TypeError('Must be an integer')
    return True


def isUUID(value):
    expression = r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
    if re.match(expression, value):
        return True
    else:
        raise TypeError('Invalid UUID')


def isTypeString(value):
    expression = r"^[^\s\/]+\/[^\s\/]+$"
    if re.match(expression, value):
        return True
    else:
        raise TypeError('Properties do not conform to pattern')
