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

import copy
import socket
from jsonschema import validate, FormatChecker, ValidationError
from abc import ABCMeta, abstractmethod
import re
import six

__tp__ = 'transport_params'


@six.add_metaclass(ABCMeta)
class AbstractDevice:
    def __init__(self, logger):
        self.staged = {}
        self.active = {}
        self.callback = None
        self.stageLocked = False
        self.logger = logger
        self.staged['master_enable'] = False
        self.staged['receiver_id'] = None
        self.staged['sender_id'] = None

    def lock(self):
        """Prevents any updates to staged parameters"""
        self.stageLocked = True

    def unLock(self):
        """Allows updates to staged parameters"""
        self.stageLocked = False

    def setActivateCallback(self, callback):
        self.callback = callback

    def activateStaged(self):
        oldParams = copy.deepcopy(self.active)
        self.active = copy.deepcopy(self.resolveParameters(self.staged))
        self.unLock()
        if self.callback is not None:
            try:
                self.logger.writeDebug("Activation suceeded")
                self.callback()
            except Exception as e:
                self.logger.writeWarning("Activation failed, reverting to old params. {}".format(e))
                self.active = copy.deepcopy(oldParams)
                raise

    def setMasterEnable(self, masterEnable):
        if self.stageLocked:
            raise StagedLockedException()
        self.staged['master_enable'] = masterEnable

    def setSenderId(self, senderId):
        if self.stageLocked:
            raise StagedLockedException()
        if senderId is None:
            self.staged['sender_id'] = None
        else:
            pattern = "^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
            if re.match(pattern, senderId):
                self.staged['sender_id'] = senderId
            else:
                raise ValidationError("Invalid sender id")

    def setReceiverId(self, receiverId):
        if self.stageLocked:
            raise StagedLockedException()
        if receiverId is None:
            self.staged['receiver_id'] = None
        else:
            pattern = "^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
            if re.match(pattern, receiverId):
                self.staged['receiver_id'] = receiverId
            else:
                raise ValidationError("Invalid sender id")

    def patch(self, updateObject):
        """Update based on a patch object"""
        for leg in range(0, self.legs):
            if not self.stageLocked:
                toCheck = []
                toCheck.append(updateObject[leg])
                schema = self.getParamsSchema(leg)
                checker = FormatChecker(["ipv4", "ipv6"])
                validate(updateObject, schema, format_checker=checker)
                self._updateTransportParamerters(updateObject, self.staged)
                return True
            else:
                raise StagedLockedException()

    def stagedToJson(self):
        return self._assembleJsonDescription(self.staged)

    def activeToJson(self):
        return self._assembleJsonDescription(self.active)

    def setStagedParameter(self, value, parameter, leg=0):
        """Set the value of a staged parameter"""
        if parameter in self.staged[__tp__][leg]:
            self.staged[__tp__][leg][parameter] = value
        else:
            raise ValueError

    def getStagedParameter(self, parameter, leg=0):
        """Get the value of a staged parameter"""
        return self.staged[__tp__][leg][parameter]

    def setActiveParameter(self, value, parameter, leg=0):
        """Set the value of an active parameter"""
        if parameter in self.active[__tp__][leg]:
            self.active[__tp__][leg][parameter] = value
        else:
            raise ValueError

    def getActiveParameter(self, parameter, leg=0):
        """Get the value of an active parameter"""
        return self.active[__tp__][leg][parameter]

    def _updateTransportParamerters(self, updateObject, dest):
        """Merge in transport parameters"""
        leg = 0
        for tp in updateObject:
            for key, value in tp.items():
                if key in dest[__tp__][leg]:
                    dest[__tp__][leg][key] = updateObject[leg][key]
            leg += 1

    def _checkIsIpv4(self, addr):
        """Checks a given address is ipv4"""
        try:
            # Check if it's IPv4
            socket.inet_pton(socket.AF_INET, addr)
            return True
        except AttributeError:
            # Looks like we can't use pton here...
            try:
                socket.inet_aton(addr)
            except socket.error:
                return False
        except socket.error:
            return False
        return True

    def _checkIsIpv6(self, addr):
        """Checks a given address is ipv6. Not win friendly. Sorry..."""
        try:
            socket.inet_pton(socket.AF_INET6, addr)
        except socket.error:
            return False
        except AttributeError:
            """If you're finding this program returning here your system does
            not support inet_pton (is probably running windows). In Python 2.7
            about the only way round this is to use a bunch of regex..."""
            return False
        return True

    @abstractmethod
    def getConstraints(self):
        pass

    @abstractmethod
    def getParamsSchema(self):
        pass

    @abstractmethod
    def getTransportType(self):
        pass


class StagedLockedException(Exception):
    pass
