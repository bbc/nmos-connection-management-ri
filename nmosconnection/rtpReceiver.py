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
__sd__ = 'session_description'


class RtpReceiver(AbstractDevice):

    def __init__(self, logger, transportManagerClass, legs=1):
        """All IP and Port parameters should be tuples containing one
        entry for each leg. In single leg mode the second entry of each
        tuple may be set to 'None'"""

        super(RtpReceiver, self).__init__(logger)

        if int(legs) < 1 or int(legs) > 2:
            raise ValueError("Reciever may only support 1 or 2 legs")

        self.schemaPath = SCHEMA_LOCAL

        self.legs = legs
        self.transportManagers = []
        self.staged[__tp__] = list(range(legs))
        self.staged[__tp__][0] = {}
        if legs == 2:
            self.staged[__tp__][1] = {}

        # Set collections of parameters
        self.generalParams = ['source_ip', 'multicast_ip', 'interface_ip', 'destination_port', 'rtp_enabled']
        self.fecParams = ['fec_enabled', 'fec_destination_ip', 'fec_mode',
                          'fec1D_destination_port', 'fec2D_destination_port']
        self.rtcpParams = ['rtcp_enabled', 'rtcp_destination_ip', 'rtcp_destination_port']

        self.interfaceSelector = self.defaultInterfaceSelector

        # Set up default values as per spec.
        for leg in range(0, legs):
            self.transportManagers.append(
                transportManagerClass(self.logger, self)
            )
            self.staged[__tp__][leg]['source_ip'] = None
            self.staged[__tp__][leg]['interface_ip'] = "auto"
            self.staged[__tp__][leg]['multicast_ip'] = None
            self.staged[__tp__][leg]['destination_port'] = 5004
            self.staged[__tp__][leg]['fec_enabled'] = False
            self.staged[__tp__][leg]['fec_destination_ip'] = "auto"
            self.staged[__tp__][leg]['fec_mode'] = "1D"
            self.staged[__tp__][leg]['fec1D_destination_port'] = "auto"
            self.staged[__tp__][leg]['fec2D_destination_port'] = "auto"
            self.staged[__tp__][leg]['rtcp_enabled'] = False
            self.staged[__tp__][leg]['rtcp_destination_ip'] = "auto"
            self.staged[__tp__][leg]['rtcp_destination_port'] = "auto"
            self.staged[__tp__][leg]['rtp_enabled'] = True
        self.staged['sender_id'] = None

        self._enableRtcp = True
        self._enableFec = True
        self._initConstraints()

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
        self._initInterfaceConstraints()

    def _initInterfaceConstraints(self):
        for leg in range(0, self.legs):
            self.constraints[leg]['interface_ip']['enum'] = ["auto"]

    def addInterface(self, addr, leg=0):
        """Used to add allowed revieve interfaces"""
        # Check supplied IP is valid
        if self._checkIsIpv4(addr) or self._checkIsIpv6(addr):
            self.constraints[leg]['interface_ip']['enum'].append(addr)
        else:
            self.logger.writeWarning("Driver tried to add an interface with an invalid IP: {}".format(addr))
            raise ValueError("Invalid IP added by driver")

    def setInterfaceResoltionMethod(self, method):
        """May be used by the driver to insert a custom
        method that can be called during parameter resolution
        to automatically select the correct interface to use
        for a given set of parameters"""
        self.interfaceSelector = method

    def defaultInterfaceSelector(self, parameterSet, leg):
        """In the absense of the driver having supplied an interface
        resolution method this method just returns the first interface
        on the list"""
        try:
            return self.constraints[leg]['interface_ip']['enum'][1]
        except IndexError:
            self.logger.writeError("Driver has not supplied an interface for the receiver, cannot resolve interface ip")
            return None

    def resolveParameters(self, parameterSet):
        """For all parameters that may be set to auto run through and resolve
        their actual values"""
        self.logger.writeDebug("Starting receiver parameter resolution")
        toReturn = copy.deepcopy(parameterSet)
        resolveLookup = {
            "interface_ip": self.interfaceSelector,
            "destination_port": self._resolveInterfacePort,
            "fec_destination_ip": self._resolveFecIp,
            "fec1D_destination_port": self._resolveFec1DDestPort,
            "fec2D_destination_port": self._resolveFec2DDestPort,
            "rtcp_destination_ip": self._resolveRtcpDestIp,
            "rtcp_destination_port": self._resolveRtcpDestPort
        }
        order = ["interface_ip", "destination_port", "fec_destination_ip",
                 "fec1D_destination_port", "fec2D_destination_port",
                 "rtcp_destination_ip", "rtcp_destination_port"]
        for leg in range(0, len(toReturn[__tp__])):
            for key in order:
                if parameterSet[__tp__][leg][key] == "auto":
                    toReturn[__tp__][leg][key] = resolveLookup[key](toReturn[__tp__], leg)
        return toReturn

    def _resolveRtcpDestPort(self, parameterSet, leg):
        return parameterSet[leg]['destination_port'] + 1

    def _resolveRtcpDestIp(self, parameterSet, leg):
        if parameterSet[leg]['multicast_ip'] is None:
            # Unicast operation
            return parameterSet[leg]['interface_ip']
        else:
            # Multicast operation
            return parameterSet[leg]['multicast_ip']

    def _resolveFec1DDestPort(self, parameterSet, leg):
        return parameterSet[leg]['destination_port'] + 2

    def _resolveFec2DDestPort(self, parmaeterSet, leg):
        return parmaeterSet[leg]['destination_port'] + 4

    def _resolveFecIp(self, parameterSet, leg):
        if parameterSet[leg]['multicast_ip'] is None:
            # Unicast operation
            return parameterSet[leg]['interface_ip']
        else:
            # Multicast operation
            return parameterSet[leg]['multicast_ip']

    def _resolveInterfacePort(self, parameterSet, leg):
        return 5004

    def supportRtcp(self, support=True):
        self._enableRtcp = support

    def supportFec(self, support=True):
        self._enableFec = support

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
        toReturn.pop('receiver_id')
        return toReturn

    def getParamsSchema(self, leg):
        """Get the schema of the transport params"""
        schema = self.schemaPath + 'v1.0_receiver_transport_params_rtp.json'
        try:
            schemaPath = os.path.join(__location__, schema)
            with open(schemaPath) as json_data:
                obj = json.loads(json_data.read())
        except EnvironmentError:
            raise IOError('failed to load schema file at: {}'.format(schemaPath))
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
            toReturn[leg]['interface_ip']['enum'].remove("auto")
        return toReturn

    def getActiveSenderID(self):
        return self.active['sender_id']

    def getTransportType(self):
        return "rtp"

    def _setTp(self, value, field, leg):
        q = [{}, {}]
        q[leg][field] = value
        return self.patch(q)
