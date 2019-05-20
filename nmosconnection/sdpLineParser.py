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

from __future__ import absolute_import

import re
from collections import namedtuple
from .cmExceptions import SdpParseError


ConnectionLine = namedtuple("ConnectionLine", "ntype, atype, addr, groupsize, ttl")
MediaLine = namedtuple("MediaLine", "media, port, numports, protocol, fmt")
AttributeLine = namedtuple("AttributeLine", "ntype, atype, dest, source")


def parseLine(line):

    type = _get_line_type(line)
    value = _get_line_value(line)

    if type == "c":
        return _parseConnectionLine(value)
    elif type == "a":
        return _parseAttributeLine(value)
    elif type == "m":
        return _parseMediaLine(value)
    else:
        return None


def _get_line_type(line):
    match = re.match("^(.)=.*", line)
    return match.group(1)


def _get_line_value(line):
    match = re.match("^.=(.*)", line)
    return match.group(1)


def _parseConnectionLine(value):
    # Look for connection information - sadly sdp connection field
    # doesn't accomodate SSMC so we have to find the destination IP
    # from an source filter attribute instead
    if re.match(r"^ *IN +IP4 +.*$", value):
        return _parseIPv4ConnectionLine(value)
    elif re.match(r"^ *IN +IP6 +.*$", value):
        return _parseIPv6ConnectionLine(value)
    else:
        raise SdpParseError("Could not parse SDP line: {}".format(value))


def _parseIPv6ConnectionLine(value):
    match = re.match(r"^ *IN +IP6 +([^/]+) *$", value)
    ntype, atype = "IN", "IP6"
    addr = match.groups()[0]
    groupsize = 1
    ttl = 1
    return ConnectionLine(ntype, atype, addr, groupsize, ttl)


def _parseIPv4ConnectionLine(value):
    match = re.match(r"^ *IN +IP4 +([^/]+)(?:/(\d+)(?:/(\d+))?)? *$", value)
    ntype, atype = "IN", "IP4"
    addr, ttl, groupsize = match.groups()
    if ttl is None:
        ttl = 127
    if groupsize is None:
        groupsize = 1
    return ConnectionLine(ntype, atype, addr, groupsize, ttl)


def _parseAttributeLine(value):
    # Looks for media attributes - I'm only interested in finding
    # source filters (RFC4570) to work out the SSMC destination address
    if re.match(r"^.*source-filter: +incl +IN +IP4 +.*", value):
        return _parseIPv4AttributeLine(value)
    elif re.match(r"^.*source-filter: +incl +IN +IP6 +.*", value):
        return _parseIPv6AttributeLine(value)
    else:
        return None


def _parseIPv4AttributeLine(value):
    # IPV4 Source filter
    ntype, atype = "IN", "IP4"
    match = re.match(r"^.*IN +IP4+ (?:((?:\d+\.?)+)) (?:((?:\d+\.?)+))", value)
    dest, source = match.groups(match)
    return AttributeLine(ntype, atype, dest, source)


def _parseIPv6AttributeLine(value):
    # IPV6 Source filter
    ntype, atype = "IN", "IP6"
    regexp = (r"^.*source-filter: +incl +IN +IP6 +"
              r"((?:[\dabcdefABCDEF]{1,4}:*)+) +((?:[\dabcdefABCDEF]"
              r"{1,4}:*)+)")
    match = re.match(regexp, value)
    dest, source = match.groups(match)
    return AttributeLine(ntype, atype, dest, source)


def _parseMediaLine(value):
    # We need to look at the media tag to get the port number to use...
    regexp = (r"^(audio|video|text|application|message) +"
              r"(\d+)(?:[/](\d+))? +([^ ]+) +(.+)$")
    media, port, numports, protocol, fmt = re.match(regexp, value).groups()
    port = int(port)
    if numports is None:
        numports = 1
    else:
        numports = int(numports)
    return MediaLine(media, port, numports, protocol, fmt)
