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

import time
from abstractDevice import StagedLockedException
from sdpParser import SdpParser
from exceptions import SdpParseError


class SdpManager():

    def __init__(self, logger, receiver):
        self.stagedSdp = ""
        self.activeSdp = ""
        self.stagedSources = []
        self.activeSources = []
        self.logger = logger
        self.lastUpdated = 0
        self.stageLocked = False
        self.receiver = receiver
        self.senderId = None

        self.stagedRequest = {
            "type": "application/sdp",
            "data": ""
        }
        self.activeRequest = self.stagedRequest

    def getStagedSdp(self):
        return self.stagedSdp

    def getActiveSdp(self):
        return self.activeSdp

    def getStagedRequest(self):
        return self.stagedRequest

    def getActiveRequest(self):
        return self.activeRequest

    def lock(self):
        """Prevents any updates to staged parameters"""
        self.stageLocked = True

    def unLock(self):
        """Allows updates to staged parameters"""
        self.stageLocked = False

    def update(self, updateObject):
        """Update staged SDP if not locked"""
        if not self.stageLocked:
            try:
                data = updateObject['data']
                type = updateObject['type']
            except KeyError as err:
                # Something wrong with the request JSON
                errMessage = ("Missing field in "
                              "PUT request to transport file:".format(str(err)))
                self.logger.writeError(errMessage)
                raise KeyError(errMessage)
            if type != 'application/sdp':
                # Asked to process a transport file other than SDP
                errMessage = ("This implementation of the CM API "
                              "cannot handle transport files of type {}:".format(type))
                self.logger.writeError(errMessage)
                raise ValueError(errMessage)
            self.stagedRequest = updateObject
            self.addSdpByAssignment(data)
            self.applyParamsToInterface()
        else:
            errMessage = ("Attempted to updated parameters "
                          "while staged is locked")
            self.logger.writeError(errMessage)
            raise StagedLockedException(errMessage)

    def activateStaged(self):
        self.activeSdp = self.stagedSdp
        self.activeRequest = self.stagedRequest
        self.activeSources = self.stagedSources
        self.unLock()

    def applyParamsToInterface(self):
        """Apply the parameters from the
        sdp onto the interface class"""
        self.receiver._setTp(
            self.stagedSources[0]['dest'],
            'multicast_ip',
            0
        )
        self.receiver._setTp(
            self.stagedSources[0]['port'],
            'destination_port',
            0
        )
        self.receiver._setTp(
            True,
            'rtp_enabled',
            0
        )
        if 'source' in self.stagedSources[0]:
            # May not be present if not using source specific multicast
            self.receiver._setTp(
                self.stagedSources[0]['source'],
                'source_ip',
                0
            )

    def addSdpByAssignment(self, sdp):
        # Add an SDP directly
        parser = SdpParser(self.logger)
        parser.parseFile(sdp)
        if parser.sources:
            self.stagedSources = parser.sources
            self.lastUpdated = time.time()
            self.stagedSdp = sdp
            return True
        errMessage = "Could not extract sources form SDP file"
        self.logger.writeError(errMessage)
        raise SdpParseError(errMessage)
