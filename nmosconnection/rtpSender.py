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

import os
import json
import copy
from .abstractDevice import AbstractDevice
from .constants import SCHEMA_LOCAL

__location__ = os.path.realpath(
    os.path.join(os.getcwd(), os.path.dirname(__file__)))

__tp__ = 'transport_params'


class RtpSender(AbstractDevice):

    def __init__(self, logger, legs=1):
        """All IP and Port parameters should be tuples containing one
        entry for each leg. In single leg mode the second entry of each
        tuple may be set to 'None'"""
        super(RtpSender, self).__init__(logger)

        if int(legs) < 1 or int(legs) > 2:
            raise ValueError("Reciever may only support 1 or 2 legs")

        self.schemaPath = SCHEMA_LOCAL

        self.sourceSelector = self.defaultSourceSelector
        self.destinationSelector = self.defaultDestinationSelector

        self.legs = legs
        self.staged[__tp__] = list(range(legs))
        self.staged[__tp__][0] = {}
        if legs == 2:
            self.staged[__tp__][1] = {}

        # Set collections of parameters
        self.generalParams = [
            'source_ip', 'destination_ip', 'destination_port', 'source_port', 'rtp_enabled'
        ]
        self.fecParams = [
            'fec_enabled', 'fec_destination_ip', 'fec_mode', 'fec_type',
            'fec_block_width', 'fec_block_height', 'fec1D_destination_port',
            'fec1D_source_port', 'fec2D_destination_port', 'fec2D_source_port'
        ]
        self.rtcpParams = [
            'rtcp_enabled', 'rtcp_destination_ip', 'rtcp_destination_port', 'rtcp_source_port'
        ]

        # Set up default values as per spec.
        for leg in range(0, legs):
            self.staged[__tp__][leg]['source_ip'] = "auto"
            self.staged[__tp__][leg]['destination_ip'] = "auto"
            self.staged[__tp__][leg]['destination_port'] = 5004
            self.staged[__tp__][leg]['source_port'] = "auto"
            self.staged[__tp__][leg]['fec_enabled'] = False
            self.staged[__tp__][leg]['fec_destination_ip'] = "auto"
            self.staged[__tp__][leg]['fec_mode'] = "1D"
            self.staged[__tp__][leg]['fec_type'] = "XOR"
            self.staged[__tp__][leg]['fec_block_width'] = 4
            self.staged[__tp__][leg]['fec_block_height'] = 4
            self.staged[__tp__][leg]['fec1D_destination_port'] = "auto"
            self.staged[__tp__][leg]['fec2D_destination_port'] = "auto"
            self.staged[__tp__][leg]['fec1D_source_port'] = "auto"
            self.staged[__tp__][leg]['fec2D_source_port'] = "auto"
            self.staged[__tp__][leg]['rtcp_enabled'] = False
            self.staged[__tp__][leg]['rtcp_destination_ip'] = "auto"
            self.staged[__tp__][leg]['rtcp_destination_port'] = "auto"
            self.staged[__tp__][leg]['rtcp_source_port'] = "auto"
            self.staged[__tp__][leg]['rtp_enabled'] = True
        self.staged['receiver_id'] = None
        self.staged['master_enable'] = False
        self.transportFile = ""

        self._enableRtcp = True
        self._enableFec = True
        self._initConstraints()
        self.activateStaged()

    def supportRtcp(self, support=True):
        self._enableRtcp = support

    def supportFec(self, support=True):
        self._enableFec = support

    def _initConstraints(self):
        self.constraints = []
        for leg in range(0, self.legs):
            self.constraints.append({})
            for param in self.generalParams:
                self.constraints[leg][param] = {}
            for param in self.fecParams:
                self.constraints[leg][param] = {}
            for param in self.rtcpParams:
                self.constraints[leg][param] = {}
        self._initSourceConstraints()

    def _initSourceConstraints(self):
        for leg in range(0, self.legs):
            self.constraints[leg]['source_ip']['enum'] = ["auto"]

    def addInterface(self, addr, leg=0):
        """Used to add allowed source IPs"""
        # Check supplied IP is valid
        if self._checkIsIpv4(addr) or self._checkIsIpv6(addr):
            self.constraints[leg]['source_ip']['enum'].append(addr)
        else:
            self.logger.writeWarning("Driver tried to provide an invalid source IP: {}".format(addr))
            raise ValueError("Invalid source IP added by driver")

    def setDestinationSelector(self, selector):
        """Set the method used to select the destination IP
        address. The method must accept two parameters, which are
        the staged parameter set and the 0 based leg number."""
        self.destinationSelector = selector

    def setSourceSelector(self, selector):
        """Set the method used to select the source IP address.
        The method must accept two parameters, which are
        the staged parameter set and the 0 based leg number."""
        self.sourceSelector = selector

    def defaultDestinationSelector(self, parameterSet, leg):
        """This method provides a 'dummy' loopback destination
        address in the absense of a method being supplied by the driver.
        It should only ever be used for testing purposes, drivers should
        always provide their own method. As such this method will always log
        a warning when it runs"""
        self.logger.writeWarning("No destination selector has been provided by \
        the driver to the RTP Sender. The loopback will be used. This is a bug \
        in anything other than a test or example system")
        return "127.0.0.1"

    def defaultSourceSelector(self, parameterSet, leg):
        """In the absense of the driver having supplied an source
        resolution method this method just returns the first source IP
        on the list"""
        try:
            return self.constraints[leg]['source_ip']['enum'][1]
        except IndexError:
            self.logger.writeError("Driver has not supplied a source for the receiver, cannot resolve source ip")
            return None

    def resolveParameters(self, parameterSet):
        """For all parameters that may be set to auto run through and resolve
        their actual values"""
        toReturn = copy.deepcopy(parameterSet)
        resolveLookup = {
            "source_ip": self.sourceSelector,
            "destination_ip": self.destinationSelector,
            "source_port": self._resolveSourcePort,
            "destination_port": self._resolveDestinationPort,
            "fec_destination_ip": self._resolveFecIp,
            "fec1D_destination_port": self._resolveFec1DDestPort,
            "fec2D_destination_port": self._resolveFec2DDestPort,
            "fec1D_source_port": self._resolveFec1DSrcPort,
            "fec2D_source_port": self._resolveFec2DSrcPort,
            "rtcp_destination_ip": self._resolveRtcpDestIp,
            "rtcp_source_port": self._resolveRtcpSrcPort,
            "rtcp_destination_port": self._resolveRtcpDestPort
        }
        order = ["source_ip", "destination_ip", "source_port",
                 "destination_port", "fec_destination_ip",
                 "fec1D_destination_port", "fec2D_destination_port",
                 "fec1D_source_port", "fec2D_source_port", "rtcp_source_port",
                 "rtcp_destination_ip", "rtcp_destination_port"]
        for leg in range(0, len(toReturn[__tp__])):
            for key in order:
                if parameterSet[__tp__][leg][key] == "auto":
                    toReturn[__tp__][leg][key] = resolveLookup[key](toReturn[__tp__], leg)
        return toReturn

    def _resolveRtcpDestPort(self, parameterSet, leg):
        return parameterSet[leg]['destination_port'] + 1

    def _resolveRtcpSrcPort(self, parameterSet, leg):
        return parameterSet[leg]['source_port'] + 1

    def _resolveRtcpDestIp(self, parameterSet, leg):
        return parameterSet[leg]['destination_ip']

    def _resolveFec1DDestPort(self, parameterSet, leg):
        return parameterSet[leg]['destination_port'] + 2

    def _resolveFec2DDestPort(self, parmaeterSet, leg):
        return parmaeterSet[leg]['destination_port'] + 4

    def _resolveFec1DSrcPort(self, parameterSet, leg):
        return parameterSet[leg]['source_port'] + 2

    def _resolveFec2DSrcPort(self, parmaeterSet, leg):
        return parmaeterSet[leg]['source_port'] + 4

    def _resolveFecIp(self, parameterSet, leg):
        return parameterSet[leg]['destination_ip']

    def _resolveSourcePort(self, parameterSet, keg):
        return 5004

    def _resolveDestinationPort(self, parameterSet, leg):
        return 5004

    def _assembleJsonDescription(self, params):
        """Assemble a dictionary only of parameters required currently"""
        toReturn = copy.deepcopy(params)
        for leg in range(0, self.legs):
            if not self._enableFec:
                for param in self.fecParams:
                    toReturn[__tp__][leg].pop(param)
            if not self._enableRtcp:
                for param in self.rtcpParams:
                    toReturn[__tp__][leg].pop(param)
        toReturn.pop('sender_id')
        return toReturn

    def getParamsSchema(self, leg=0):
        """Get the schema of the transport params"""
        schema = self.schemaPath + 'v1.0_sender_transport_params_rtp.json'
        try:
            schemaPath = os.path.join(__location__, schema)
            with open(schemaPath) as json_data:
                obj = json.loads(json_data.read())
        except EnvironmentError:
            raise IOError('failed to load schema file')
        params = obj['items']['properties']
        if not self._enableFec:
            for key in self.fecParams:
                if key in params:
                    params.pop(key)
        if not self._enableRtcp:
            for key in self.rtcpParams:
                if key in params:
                    params.pop(key)
        # Merge in extra requirements required by constraints
        for key, entry in params.items():
            if key in self.constraints[leg]:
                entry.update(self.constraints[leg][key])
        obj['items']['properties'] = params
        return obj

    def getConstraints(self):
        toReturn = copy.deepcopy(self.constraints)
        for leg in range(0, self.legs):
            for key, value in self.constraints[leg].items():
                if not self._enableFec:
                    if key in self.fecParams:
                        toReturn[leg].pop(key)
                if not self._enableRtcp:
                    if key in self.rtcpParams:
                        toReturn[leg].pop(key)
                if value == "auto":
                    toReturn[leg].pop(key)
            toReturn[leg]['source_ip']['enum'].remove("auto")
        return toReturn

    def getActiveTransportFileURL(self):
        return self.transportFile

    def getTransportType(self):
        return "rtp"

    def _setTp(self, value, field, leg):
        q = {__tp__: [{}, {}]}
        q[__tp__][leg][field] = value
        return self.patch(q)
