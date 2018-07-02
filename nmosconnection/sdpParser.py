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

from sdpLineParser import parseLine, ConnectionLine, MediaLine, AttributeLine


class SdpParser:

    def __init__(self, logger):
        self.sources = []
        self.source = {}
        self.logger = logger

    def parseFile(self, sdp):
        lines = sdp.splitlines()
        for line in lines:
            if line != "":
                self._getLineData(line)

    def _getLineData(self, line):
        result = parseLine(line)
        if type(result) is ConnectionLine:
            self._extractConnectionInfo(result)
        elif type(result) is MediaLine:
            self._extractMediaInfo(result)
        elif type(result) is AttributeLine:
            self._extractAttributeInfo(result)

    def _extractConnectionInfo(self, result):
        self.sources[-1]['dest'] = result.addr

    def _extractMediaInfo(self, result):
        self.source = {}
        self.sources.append(self.source)
        self.source['port'] = result.port

    def _extractAttributeInfo(self, result):
        self.sources[-1]['source'] = result.source
