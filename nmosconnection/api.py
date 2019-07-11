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
from flask import request, abort, Response
from jsonschema import validate, FormatChecker, ValidationError
import traceback
import json
from nmoscommon.auth.nmos_auth import RequiresAuth
from nmoscommon.webapi import WebAPI, route, basic_route

from .activator import Activator
from .constants import SCHEMA_LOCAL
from .abstractDevice import StagedLockedException

__location__ = os.path.realpath(
    os.path.join(os.getcwd(), os.path.dirname(__file__)))

CONN_APINAMESPACE = "x-nmos"
CONN_APINAME = "connection"
CONN_APIVERSIONS = ["v1.0", "v1.1"]

CONN_ROOT = '/' + CONN_APINAMESPACE + '/' + CONN_APINAME + '/'
SINGLE_ROOT = "single/"
BULK_ROOT = "bulk/"

TRANSPORT_URN = "urn:x-nmos:transport:"
VALID_TRANSPORTS = {
    "v1.0": ["rtp"],
    "v1.1": ["rtp", "mqtt", "websocket"]
}


class NotSupportedError(Exception):
    """Raised when the request uses functionality from a later version of the API"""
    pass


class ConnectionManagementAPI(WebAPI):

    def __init__(self, logger):
        super(ConnectionManagementAPI, self).__init__()
        self.logger = logger
        self.senders = {}
        self.receivers = {}
        self.activators = {}
        self.transportManagers = {}
        self.schemaPath = SCHEMA_LOCAL
        self.useValidation = True  # Used for unit testing

    def addSender(self, sender, uuid):
        if uuid in self.senders:
            raise DuplicateRegistrationException(
                "Sender already registered with uuid " + uuid
            )
        self.senders[uuid] = sender
        self.activators[uuid] = Activator([sender])
        return self.activators[uuid]

    def addReceiver(self, receiver, uuid):
        if uuid in self.receivers:
            raise DuplicateRegistrationException(
                "Receiver already registered with uuid " + uuid
            )
        self.receivers[uuid] = receiver
        # Note the transport managers must be listed first so that they activate first
        # This ensures that SDP files are available via the API before any interactions with the driver
        if receiver.legs == 1:
            self.activators[uuid] = Activator([
                receiver.transportManagers[0],
                receiver
            ])
        else:
            self.activators[uuid] = Activator([
                receiver.transportManagers[0],
                receiver.transportManagers[1],
                receiver
            ])
        self.transportManagers[uuid] = receiver.transportManagers[0]
        return self.activators[uuid]

    def getTransceiver(self, api_version, sr, srID):
        if sr == "receivers":
            if self.receivers[srID].getTransportType() not in VALID_TRANSPORTS[api_version]:
                raise NotSupportedError
            else:
                return self.receivers[srID]
        elif sr == "senders":
            if self.senders[srID].getTransportType() not in VALID_TRANSPORTS[api_version]:
                raise NotSupportedError
            else:
                return self.senders[srID]
        else:
            raise LookupError

    def validateAPIVersion(self, api_version, sr=None, srID=None):
        if api_version not in CONN_APIVERSIONS:
            abort(404)
        if sr is not None and srID is not None:
            try:
                sr_object = self.getTransceiver(api_version, sr, srID)
                return sr_object
            except NotSupportedError:
                self.logger.writeWARNING("Request for transport type {} not available in api version {}".format(
                        self.getattr(sr)[srID].getTransportType(), api_version
                ))
                highest_api_version = CONN_APIVERSIONS[-1]
                headers = {"location": request.url.replace(api_version, highest_api_version)}
                return (409, headers)
            except Exception:
                abort(404)

    def removeSender(self, uuid):
        del self.senders[uuid]
        del self.activators[uuid]

    def removeReceiver(self, uuid):
        del self.receivers[uuid]
        del self.activators[uuid]

    def getActivator(self, srID):
        return self.activators[srID]

    def getTransportManager(self, srID):
        return self.transportManagers[srID]

    def errorResponse(self, code, message, id=None):
        response = {
            "code": code,
            "error": message,
            "debug": traceback.extract_stack()
        }
        if id is not None:
            response['id'] = id
        return response

    @route('/')
    def __index(self):
        return (200, [CONN_APINAMESPACE + "/"])

    @route('/' + CONN_APINAMESPACE + "/")
    def __namespaceindex(self):
        return (200, [CONN_APINAME + "/"])

    @route(CONN_ROOT)
    def __nameindex(self):
        return (200, [api_version + "/" for api_version in CONN_APIVERSIONS])

    @route(CONN_ROOT + "<api_version>/")
    def __versionindex(self, api_version):
        self.validateAPIVersion(api_version)
        obj = ["bulk/", "single/"]
        return (200, obj)

    @route(CONN_ROOT + "<api_version>/" + SINGLE_ROOT)
    def __singleRoot(self, api_version):
        self.validateAPIVersion(api_version)
        obj = ["senders/", "receivers/"]
        return (200, obj)

    @route(CONN_ROOT + "<api_version>/" + SINGLE_ROOT + '<sr>/')
    def __connRoot(self, api_version, sr):
        self.validateAPIVersion(api_version)
        if sr == "receivers":
            keys = list()
            for receiver_id in self.receivers.keys():
                if self.receivers[receiver_id].getTransportType() not in VALID_TRANSPORTS[api_version]:
                    continue
                keys.append(receiver_id)
        elif sr == "senders":
            keys = list()
            for sender_id in self.senders.keys():
                if self.senders[sender_id].getTransportType() not in VALID_TRANSPORTS[api_version]:
                    continue
                keys.append(sender_id)
        else:
            return 404
        toReturn = []
        for key in keys:
            toReturn.append(key + "/")
        return toReturn

    @route(CONN_ROOT + "<api_version>/" + SINGLE_ROOT + '<sr>/<srID>/', methods=['GET'])
    def __connIndex(self, api_version, srID, sr):
        self.validateAPIVersion(api_version, sr, srID)
        endpoints = ['constraints/', 'staged/', 'active/']
        if sr == 'senders':
            endpoints.append('transportfile/')
        if api_version != "v1.0":
            endpoints.append('transporttype/')
        return(200, endpoints)

    @route(CONN_ROOT + "<api_version>/" + SINGLE_ROOT + '<sr>/<srID>/constraints/', methods=['GET'])
    def __constraints(self, api_version, sr, srID):
        srObject = self.validateAPIVersion(api_version, sr, srID)
        return srObject.getConstraints()

    @route(CONN_ROOT + "<api_version>/" + SINGLE_ROOT + '<sr>/<srID>/staged/',
           methods=['GET'])
    def __staged_get(self, api_version, sr, srID):
        srObject = self.validateAPIVersion(api_version, sr, srID)
        toReturn = srObject.stagedToJson()
        toReturn['activation'] = self.getActivator(srID).getLastRequest()
        if sr == "receivers":
            transportManager = self.getTransportManager(srID)
            toReturn['transport_file'] = transportManager.getStagedRequest()
        return toReturn

    @route(CONN_ROOT + "<api_version>/" + SINGLE_ROOT + '<sr>/<srID>/staged',
           methods=['PATCH'])
    @RequiresAuth()
    def single_staged_patch(self, api_version, sr, srID):
        req = request.get_json()
        return self.staged_patch(api_version, sr, srID, req)

    def staged_patch(self, api_version, sr, srID, params):
        toReturn = {}
        srObject = self.validateAPIVersion(api_version, sr, srID)
        try:
            self.validateAgainstSchema(params, 'v1.0-{}-stage-schema.json'.format(sr[:-1]))
        except ValidationError as e:
            return (400, self.errorResponse(400, str(e)))
        # If reciever check if transport file must be applied
        if 'transport_file' in params and sr == "receivers":
            ret = self.applyTransportFile(params.pop('transport_file'), srID)
            if ret[0] != 200:
                return ret
        # If transport params are present apply those next
        if 'transport_params' in params:
            ret = self.applyTransportParams(params['transport_params'], srObject)
            if ret[0] != 200:
                return ret
        # S/R IDs come next, depending on sender/receiver
        if 'receiver_id' in params and sr == "senders":
            ret = self.applyReceiverId(params['receiver_id'], srObject)
            if ret[0] != 200:
                return ret
        if 'sender_id' in params and sr == "receivers":
            ret = self.applySenderId(params['sender_id'], srObject)
            if ret[0] != 200:
                return ret
        # Set master enable
        if 'master_enable' in params:
            try:
                srObject.setMasterEnable(params['master_enable'])
            except StagedLockedException:
                return (423, self.errorResponse(423, "Resource is locked due to a pending activation"))
        # Finally carry out activation if requested
        if 'activation' in params:
            activationRet = self.applyActivation(params['activation'], srID)
            if activationRet[0] != 200 and activationRet[0] != 202:
                return activationRet
            toReturn = self.assembleResponse(sr, srObject, srID, activationRet)
        else:
            toReturn = (200, self.__staged_get(api_version, sr, srID))
        return toReturn

    def validateAgainstSchema(self, request, schemaFile):
        """Check a request against the sender patch schema"""
        # Validation may be disabled for unit testing purposes
        if self.useValidation:
            schema = self.schemaPath + schemaFile
            try:
                schemaPath = os.path.join(__location__, schema)
                with open(schemaPath) as json_data:
                    schema = json.loads(json_data.read())
            except EnvironmentError:
                raise IOError('failed to load schema file at:{}'.format(schemaPath))
            checker = FormatChecker(["ipv4", "ipv6"])
            validate(request, schema, format_checker=checker)

    def assembleResponse(self, sr, srObject, srID, activationRet):
        toReturn = srObject.stagedToJson()
        toReturn['activation'] = {}
        toReturn['activation'] = activationRet[1]
        if sr == "receivers":
            try:
                transportManager = self.getTransportManager(srID)
            except Exception:
                return (500, self.errorResponse(500, "Could not find transport manager"))
            toReturn['transport_file'] = transportManager.getStagedRequest()
        return (activationRet[0], toReturn)

    def applyReceiverId(self, id, srID):
        try:
            srID.setReceiverId(id)
        except ValidationError as e:
            return self.errorResponse(400, str(e))
        except StagedLockedException:
            return (423, self.errorResponse(423, "Resource is locked due to a pending activation"))
        return (200, {})

    def applySenderId(self, srID, srObject):
        try:
            srObject.setSenderId(srID)
        except ValidationError as e:
            return (400, self.errorResponse(400, str(e)))
        except StagedLockedException:
            return (423, self.errorResponse(423, "Resource is locked due to a pending activation"))
        return (200, {})

    def applyTransportParams(self, request, srObject):
        try:
            srObject.patch(request)
        except ValidationError as err:
            return (400, {"code": 400, "error": str(err),
                          "debug": str(traceback.format_exc())})
        except StagedLockedException:
            return (423, self.errorResponse(423, "Resource is locked due to a pending activation"))
        return (200, {})

    def applyTransportFile(self, request, srID):
        transportManager = self.getTransportManager(srID)
        try:
            transportManager.update(request)
        except KeyError as err:
            return (400, self.errorResponse(400, str(err)))
        except ValueError as err:
            return (400, self.errorResponse(400, str(err)))
        except ValidationError as err:
            return (400, self.errorResponse(400, str(err)))
        except StagedLockedException as e:
            return (423, self.errorResponse(423, "{}. Resource is locked due to a pending activation".format(e)))
        return (200, {})

    def applyActivation(self, request, uuid):
        try:
            activator = self.getActivator(uuid)
            toReturn = activator.parseActivationObject(request)
        except ValidationError as err:
            return (400, self.errorResponse(400, str(err)))
        except TypeError as err:
            return (500, self.errorResponse(500, str(err)))
        return toReturn

    @route(CONN_ROOT + "<api_version>/" + SINGLE_ROOT + '<sr>/<srID>/active/', methods=['GET'])
    def __activeReceiver(self, api_version, sr, srID):
        srObject = self.validateAgainstSchema(api_version, sr, srID)
        toReturn = {}
        toReturn = srObject.activeToJson()
        toReturn['activation'] = self.getActivator(srID).getActiveRequest()
        if sr == "receivers":
            transportManager = self.getTransportManager(srID)
            toReturn['transport_file'] = transportManager.getActiveRequest()
        return toReturn

    @basic_route(CONN_ROOT + "<api_version>/" + SINGLE_ROOT + 'senders/<srID>/transportfile/')
    def __transportFileRedirect(self, api_version, srID):
        srObject = self.validateAgainstSchema(api_version, 'senders', srID)
        resp = Response(srObject.transportFile)
        resp.headers['content-type'] = 'application/sdp'
        return resp

    @route(CONN_ROOT + "<api_version>/" + SINGLE_ROOT + '<sr>/<srID>/transporttype/', methods=['GET'])
    def __transportType(self, api_version, sr, srID):
        if api_version == "v1.0":
            # This resource doesn't exist before v1.1
            abort(404)
        srObject = self.validateAPIVersion(api_version, sr, srID)
        toReturn = {}
        toReturn = json.dumps(TRANSPORT_URN + srObject.getTransportType())
        return toReturn

    """Begin bulk API routes"""

    @route(CONN_ROOT + "<api_version>/" + BULK_ROOT)
    def __bulk_root(self, api_version):
        self.validateAgainstSchema(api_version)
        return ['senders/', 'receivers/']

    @route(CONN_ROOT + "<api_version>/" + BULK_ROOT + '<sr>',
           methods=['POST'])
    def __bulk_senders_staged_patch(self, api_version, sr):
        """Process a bulk staging object and sindicate it out to individual
        senders/receivers"""
        self.validateAPIVersion(api_version)
        req = request.get_json()
        statuses = []
        try:
            for entry in req:
                try:
                    id = entry['id']
                except KeyError as e:
                    message = "{}. Failed to find field 'id' in one or more objects".format(e)
                    return (400, self.errorResponse(400, message))
                try:
                    params = entry['params']
                except KeyError as e:
                    message = "{}. Failed to find field 'params' in one or more objects".format(e)
                    return (400, self.errorResponse(400, message))
                res = self.staged_patch(api_version, sr, id, params)
                statuses.append({"id": id, "code": res[0]})
        except TypeError as err:
            return (400, {"code": 400, "error": str(err),
                          "debug": str(traceback.format_exc())})
        return (200, statuses)

    # The below is not part of the API - it is used to make the active
    # SDP file available over HTTP to BBC R&D RTP Receivers
    @basic_route(CONN_ROOT + "<api_version>/" + SINGLE_ROOT + 'receivers/<srID>/active/sdp/')
    def __active_sdp(self, api_version, srID):
        receiver = self.validateAPIVersion(api_version, 'receivers', srID)
        try:
            manager = receiver.transportManagers[0]
        except Exception:
            abort(404)
        resp = Response(manager.getActiveSdp())
        resp.headers['content-type'] = 'application/sdp'
        return resp


class DuplicateRegistrationException(BaseException):
    pass
