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

import unittest
import requests
import os
import json
import uuid
from jsonschema import ValidationError, validate

from nmoscommon.httpserver import HttpServer
from nmoscommon.logger import Logger
from nmosconnection.abstractDevice import StagedLockedException
from nmosconnection.api import ConnectionManagementAPI

SENDER_WS_PORT = 8857

HEADERS = {'Content-Type': 'application/json'}
__location__ = os.path.realpath(
    os.path.join(os.getcwd(), os.path.dirname(__file__)))

EXAMPLE_PATH = "./examples/"
RECIEVER_EXAMPLES = [
    "v1.0-receiver-patch-absolute.json",
    "v1.0-receiver-patch.json",
    "v1.0-receiver-patch-relative.json",
    "v1.0-receiver-patch-transportfile.json"
]
SENDER_EXAMPLES = [
    "v1.0-sender-patch-absolute.json",
    "v1.0-sender-patch.json",
    "v1.0-sender-patch-relative.json"
]

CONN_APINAMESPACE = "x-nmos"
CONN_APINAME = "connection"
CONN_APIVERSION = "v1.0"


DEVICE_ROOT = CONN_APINAMESPACE + '/' + CONN_APINAME + '/' + CONN_APIVERSION + '/'

__location__ = os.path.realpath(
    os.path.join(os.getcwd(), os.path.dirname(__file__)))


class MockActivator():

    def __init__(self):
        self.updated = False

    def parseActivationObject(self, obj):
        if obj['test'] == "ok":
            self.updated = True
            return (200, {"status": "OK"})
        elif obj['test'] == "fail":
            raise TypeError("Error")
        else:
            raise ValidationError("Debug output")

    def getLastRequest(self):
        return {"request": "last"}

    def getActiveRequest(self):
        return {"request": "active"}


class MockSdpParser():

    def __init__(self):
        self.locked = False
        self.updated = False
        self.toReturn = None

    def lock(self):
        self.locked = True

    def unLock(self):
        self.locked = False

    def update(self, obj):
        if self.locked:
            raise StagedLockedException
        if obj['test'] == "ok":
            self.updated = True
            if self.toReturn is None:
                return {"status": "OK"}
            else:
                return self.toReturn
        else:
            raise ValidationError("Debug output")

    def getActiveRequest(self):
        return {"activefile": "yes"}

    def getLastRequest(self):
        return {"lastfile": "yes"}

    def getStagedRequest(self):
        return {"stagedfile": "yes"}

    def getActiveSdp(self):
        return "sdp"


class MockSenderAPI():
    """Mock up of a sender backend API for testing the sender routes"""

    def __init__(self):
        self.uuid = uuid.uuid4()
        self.locked = False
        self.legs = 1
        self.transportManagers = []
        self.transportManagers.append(MockSdpParser())
        self.senderId = ""
        self.receiverId = ""
        self.staged = {
            "transport_params": {
                "param": True
            },
            "master_enable": True,
            "receiver_id": "baf75b16-5a5c-11e7-907b-a6006ad3dba0"
        }
        self.active = {
            "transport_params": {
                "param": False
            },
            "master_enable": True,
            "receiver_id": "baf75b16-5a5c-11e7-907b-a6006ad3dba0"
        }
        self.updated = False
        self.toReturn = None
        self.masterEnable = True

    def setReceiverId(self, id):
        self.receiverId = id

    def setSenderId(self, id):
        self.senderId = id

    def setMasterEnable(self, state):
        self.masterEnable = state

    def getConstraints(self):
        return json.dumps({'constraints': 'constraints'})

    def stagedToJson(self):
        return self.staged

    def activeToJson(self):
        return {'active': 'yes'}

    def patch(self, obj):
        if self.locked:
            raise StagedLockedException
        if obj['test'] == "ok":
            self.updated = True
            if self.toReturn is None:
                return {"status": "OK"}
            else:
                return self.toReturn
        else:
            raise ValidationError("Debug output")

    def lock(self):
        self.locked = True

    def unLock(self):
        self.locked = False

    def getTransportType(self):
        return "rtp"


class TestRoutes(unittest.TestCase):
    """Test the routes class"""

    @classmethod
    def setUpClass(cls):
        """Runs before each test"""
        cls.logger = Logger("conmanage")
        cls.mockApi = MockSenderAPI()
        cls.mockReceiver = MockSenderAPI()
        cls.activator = MockActivator()
        cls.sdpManager = cls.mockReceiver.transportManagers[0]
        cls.httpServer = HttpServer(ConnectionManagementAPI, SENDER_WS_PORT,
                                    '0.0.0.0',
                                    api_args=[cls.logger])
        cls.httpServer.start()

        while not cls.httpServer.started.is_set():
            cls.httpServer.started.wait()

        cls.dut = cls.httpServer.api
        cls.senderUUID = "8358af5c-6d82-4ef8-b992-13ed40a7246d"
        cls.receiverUUID = "076f7e9d-8a93-42cc-9506-fd57505ccc89"
        cls.dut.addSender(cls.mockApi, cls.senderUUID)
        cls.dut.addReceiver(cls.mockReceiver, cls.receiverUUID)

        cls.baseUrl = "http://127.0.0.1:" + str(SENDER_WS_PORT)
        cls.deviceRoot = cls.baseUrl + '/' + DEVICE_ROOT
        cls.senderRoot = cls.deviceRoot + "single/senders/" + cls.senderUUID
        cls.receiverRoot = cls.deviceRoot + "single/receivers/" + cls.receiverUUID
        cls.maxDiff = None

    @classmethod
    def tearDownClass(cls):
        """Shuts down the HTTP Server"""
        cls.httpServer.stop()

    def setUp(self):
        self.callbackCalled = False
        self.callbackData = []
        self.callbackReturn = None
        self.sdpManager.toReturn = None
        self.mockApi.updated = False
        self.mockReceiver.updated = False
        self.activator.updated = False
        self.dut.schemaPath = "../share/ipp-connectionmanagement/schemas/"
        self.dut.useValidation = True

    def mockCallback(self, *args):
        self.callbackCalled = True
        self.callbackData = args
        return self.callbackReturn

    def verify_against_activate_schema(self, toCheck):
        path = "../share/ipp-connectionmanagement/schemas/v1.0-activate-confirm-schema.json"
        try:
            schemaPath = os.path.join(__location__, path)
            with open(schemaPath) as json_data:
                obj = json_data.read()
                schema = json.loads(obj)
        except EnvironmentError:
            raise IOError('failed to load schema file')
        validate(toCheck, schema)

    """Tests for API structure"""

    def test_api_stub(self):
        """Checks that the base url for the API is in the right place"""
        r = requests.get(self.baseUrl, headers=HEADERS)
        expected = ["x-nmos/"]
        actual = json.loads(r.text)
        self.assertEqual(expected, actual)

    def test_api_location(self):
        """Checks that the API is in x-nmos/connection"""
        r = requests.get(self.baseUrl + "/x-nmos", headers=HEADERS)
        expected = ["connection/"]
        actual = json.loads(r.text)
        self.assertEqual(expected, actual)

    def test_correct_version(self):
        """Checks that the API is served as version 1.0 and 1.1"""
        r = requests.get(self.baseUrl + "/x-nmos/connection/", headers=HEADERS)
        expected = ["v1.0/", "v1.1/"]
        actual = json.loads(r.text)
        self.assertEqual(expected, actual)

    def test_version_index(self):
        """Checks that the API is served as version 1.0"""
        r = requests.get(self.baseUrl + "/x-nmos/connection/v1.0/",
                         headers=HEADERS)
        expected = ["bulk/", "single/"]
        actual = json.loads(r.text)
        self.assertEqual(expected, actual)

    def test_single_index(self):
        """Checks the root of the single branch of the API"""
        r = requests.get(self.baseUrl + "/x-nmos/connection/v1.0/single/",
                         headers=HEADERS)
        expected = ["senders/", "receivers/"]
        actual = json.loads(r.text)
        self.assertEqual(expected, actual)

    def test_device_index(self):
        """Checks that the root of the sender meets spec"""
        url = self.senderRoot + "/"
        r = requests.get(url,
                         headers=HEADERS)
        expected = ["constraints/", "staged/", "active/", "transportfile/"]
        actual = json.loads(r.text)
        self.assertEqual(expected, actual)

    def test_device_index_404(self):
        """Check the root of the sender returns 404 if sender not found"""
        url = self.deviceRoot + "/12345/"
        r = requests.get(url,
                         headers=HEADERS)
        self.assertEqual(404, r.status_code)

    """Tests for /constraints"""

    def test_constraints(self):
        """Checks that the constraints route exists
        and calls the correct API function"""
        r = requests.get(self.senderRoot + "/constraints/",
                         headers=HEADERS)
        expected = {"constraints": "constraints"}
        actual = json.loads(r.text)
        self.assertEqual(expected, actual)

    """Tests for /staged"""

    def test_sender_staged_params_json_get(self):
        """Checks that the JSON get route exists for /staged/
        for senders"""
        self.dut.activators[self.senderUUID] = self.activator
        r = requests.get(self.senderRoot + "/staged/",
                         headers=HEADERS)
        expected = self.mockApi.staged
        expected['activation'] = {"request": "last"}
        actual = json.loads(r.text)
        self.assertEqual(expected, actual)

    def test_receiver_staged_params_json_get(self):
        """Checks that the JSON get route exists for /staged/
        for receivers"""
        self.dut.activators[self.receiverUUID] = self.activator
        self.dut.transportManagers[self.receiverUUID] = self.sdpManager
        r = requests.get(self.receiverRoot + "/staged/",
                         headers=HEADERS)
        expected = self.mockReceiver.staged
        expected['activation'] = {"request": "last"}
        expected['transport_file'] = {"stagedfile": "yes"}
        actual = json.loads(r.text)
        self.assertEqual(expected, actual)

    def test_apply_receiver_id(self):
        """Test the method for applying receiver IDs to senders"""
        id = "806ae41e-5a79-11e7-907b-a6006ad3dba0"
        self.dut.applyReceiverId(id, self.mockReceiver)
        self.assertEqual(self.mockReceiver.receiverId, id)

    def test_apply_sender_id(self):
        """Test the method for applying sender IDs to receivers"""
        id = "c2940e06-5a79-11e7-907b-a6006ad3dba0"
        self.dut.applySenderId(id, self.mockApi)
        self.assertEqual(self.mockApi.senderId, id)

    def test_apply_transport_params(self):
        """Test the method for applying transprt parameters"""
        params = {"test": "ok"}
        ret = self.dut.applyTransportParams(params, self.mockApi)
        self.assertEqual(ret[0], 200)
        self.mockApi.lock()
        ret = self.dut.applyTransportParams(params, self.mockApi)
        self.assertEqual(ret[0], 423)
        self.mockApi.unLock()
        params = {"test": "fail"}
        ret = self.dut.applyTransportParams(params, self.mockApi)
        self.assertEqual(ret[0], 400)

    def test_apply_transport_file(self):
        """Test the method for applying transport files"""
        self.dut.transportManagers[self.receiverUUID] = self.sdpManager
        request = {"test": "ok"}
        ret = self.dut.applyTransportFile(request, self.receiverUUID)
        self.assertEqual(ret[0], 200)
        self.sdpManager.lock()
        ret = self.dut.applyTransportFile(request, self.receiverUUID)
        self.assertEqual(ret[0], 423)
        self.sdpManager.unLock()
        request = {"test": "fail"}
        ret = self.dut.applyTransportFile(request, self.receiverUUID)
        self.assertEqual(ret[0], 400)

    def test_apply_activation(self):
        """Test the method for applying activations"""
        self.dut.activators[self.receiverUUID] = self.activator
        request = {"test": "ok"}
        ret = self.dut.applyActivation(request, self.receiverUUID)
        self.assertEqual(ret[0], 200)
        request = {"test": "fail"}
        ret = self.dut.applyActivation(request, self.receiverUUID)
        self.assertEqual(ret[0], 500)
        request = {"test": "bad"}
        ret = self.dut.applyActivation(request, self.receiverUUID)
        self.assertEqual(ret[0], 400)

    def test_assemble_response(self):
        """Tests the assmebly of staging respones"""
        self.dut.transportManagers[self.receiverUUID] = self.sdpManager
        activationResponse = (200, {"activation", "yes"})
        self.dut.assembleResponse("recievers", self.mockReceiver, self.receiverUUID, activationResponse)

    def test_staged_exists_json_patch(self):
        """Checks that the route exists for putting to
        /staged/"""
        data = {}
        self.dut.transportManagers[self.receiverUUID] = self.sdpManager
        r = requests.patch(self.receiverRoot + "/staged",
                           headers=HEADERS, data=json.dumps(data))
        self.assertEqual(r.status_code, 200)

    def test_staged_file_json_get(self):
        """Checks that transport files can be staged through
        /staged for receivers"""
        self.dut.useValidation = False
        data = {"transport_file": {"test": "ok"}}
        self.dut.transportManagers[self.receiverUUID] = self.sdpManager
        self.sdpManager.toReturn = (200, {"test": "ok"})
        r = requests.patch(self.receiverRoot + "/staged",
                           headers=HEADERS, data=json.dumps(data))
        self.assertTrue(self.sdpManager.updated)
        self.assertEqual(r.status_code, 200)

    def test_staged_params_json_patch(self):
        """Checks that transport params can be staged through
        /staged"""
        self.dut.useValidation = False
        data = {"transport_params": {"test": "ok"}}
        self.dut.transportManagers[self.receiverUUID] = self.sdpManager
        r = requests.patch(self.receiverRoot + "/staged",
                           headers=HEADERS, data=json.dumps(data))
        self.assertEqual(r.status_code, 200)
        self.assertTrue(self.mockReceiver.updated)

    def test_receiver_id_json_patch(self):
        """Checks that receiver IDs can be staged through
        /staged"""
        self.dut.useValidation = False
        data = {"receiver_id": "3c35f936-5b24-11e7-907b-a6006ad3dba0"}
        self.dut.transportManagers[self.senderUUID] = self.sdpManager
        r = requests.patch(self.senderRoot + "/staged",
                           headers=HEADERS, data=json.dumps(data))
        self.assertEqual(self.mockApi.receiverId, data['receiver_id'])
        self.assertEqual(r.status_code, 200)

    def test_sender_id_json_patch(self):
        """Checks that sender IDs can be staged through
        /staged"""
        self.dut.useValidation = False
        data = {"sender_id": "135e1a9c-5b25-11e7-907b-a6006ad3dba0"}
        self.dut.transportManagers[self.receiverUUID] = self.sdpManager
        r = requests.patch(self.receiverRoot + "/staged",
                           headers=HEADERS, data=json.dumps(data))
        self.assertEqual(self.mockReceiver.senderId, data['sender_id'])
        self.assertEqual(r.status_code, 200)

    def test_master_enable_json_patch(self):
        """Checks that master_enable can be staged through
        /staged"""
        data = {"master_enable": True}
        self.dut.transportManagers[self.receiverUUID] = self.sdpManager
        r = requests.patch(self.receiverRoot + "/staged",
                           headers=HEADERS, data=json.dumps(data))
        self.assertEqual(self.mockReceiver.masterEnable, data['master_enable'])
        self.assertEqual(r.status_code, 200)

    def test_activation_json_patch(self):
        """Checks that activations can be staged through /staged"""
        data = {"activation": {"test": "ok"}}
        self.dut.useValidation = False
        self.dut.transportManagers[self.receiverUUID] = self.sdpManager
        self.dut.activators[self.receiverUUID] = self.activator
        r = requests.patch(self.receiverRoot + "/staged",
                           headers=HEADERS, data=json.dumps(data))
        self.assertTrue(self.activator.updated)
        self.assertEqual(r.status_code, 200)

    """Tests for /active"""

    def test_active_file_get(self):
        """Checks that the get route exists for
        /active/sdp/ for receivers"""
        uuid = self.receiverUUID
        self.dut.transportManagers[uuid] = self.sdpManager
        r = requests.get(self.receiverRoot + "/active/sdp/")
        expected = 'sdp'
        actual = r.text
        self.assertEqual(actual, expected)
        actual = r.headers['content-type']
        expected = 'application/sdp'
        self.assertEqual(actual, expected)

    def test_sender_active_params_json_get(self):
        """Checks that the JSON get route exists for /active/
        for senders"""
        self.dut.activators[self.senderUUID] = self.activator
        self.activator.activeRequest = {"request": "active"}
        r = requests.get(self.senderRoot + "/active/",
                         headers=HEADERS)
        expected = {}
        expected = self.dut.senders[self.senderUUID].activeToJson()
        expected['activation'] = {"request": "active"}
        actual = json.loads(r.text)
        self.assertEqual(expected, actual)

    def test_receiver_active_params_json_get(self):
        """Checks that the JSON get route exists for /active/
        for receivers"""
        self.dut.activators[self.receiverUUID] = self.activator
        self.dut.transportManagers[self.receiverUUID] = self.sdpManager
        self.activator.activeRequest = {"request": "active"}
        r = requests.get(self.receiverRoot + "/active/",
                         headers=HEADERS)
        expected = {}
        expected = self.mockReceiver.activeToJson()
        expected['activation'] = {"request": "active"}
        expected['transport_file'] = {"activefile": "yes"}
        actual = json.loads(r.text)
        self.assertEqual(expected, actual)

    """Bulk interface tests"""

    def test_bulk_route_get(self):
        """Checks the GET route for /bulk/"""
        r = requests.get(self.deviceRoot + "bulk/")
        actual = json.loads(r.text)
        expected = ["senders/", "receivers/"]
        self.assertEqual(expected, actual)

    def test_bulk_sender_no_put(self):
        """Check that the bulk sender api does not
        allow puts"""
        r = requests.put(
            self.deviceRoot + "bulk/senders",
            headers=HEADERS,
        )
        self.assertEqual(r.status_code, 405)

    def test_bulk_post(self):
        """Check that the bulk interface syndicates requests properly"""
        self.callbackReturn = (200, {})
        self.dut.addSender(self.mockApi, "cdfe565e-5c02-11e7-907b-a6006ad3dba0")
        self.dut.addSender(self.mockApi, "cdfe5910-5c02-11e7-907b-a6006ad3dba0")
        self.dut.addSender(self.mockApi, "cdfe5a1e-5c02-11e7-907b-a6006ad3dba0")

        data = [
            {
                "id": "cdfe565e-5c02-11e7-907b-a6006ad3dba0",
                "params": {"test": 1}
            },
            {
                "id": "cdfe5910-5c02-11e7-907b-a6006ad3dba0",
                "params": {"test": 2}
            },
            {
                "id": "cdfe5a1e-5c02-11e7-907b-a6006ad3dba0",
                "params": {"test": 3}
            }
        ]
        r = requests.post(
            self.deviceRoot + "bulk/senders",
            headers=HEADERS,
            data=json.dumps(data)
        )
        self.assertEqual(r.status_code, 200)

    def loadExample(self, exampleFile):
        """Load in an example request from file"""
        resolvedPath = __location__ + "/" + EXAMPLE_PATH + exampleFile
        try:
            with open(resolvedPath) as example_data:
                obj = example_data.read()
                example = json.loads(obj)
        except EnvironmentError:
            raise IOError('failed to load example file')
        return example

    def example_set_test(self, set, schema):
        self.dut.useValidation = True
        for examplePath in set:
            example = self.loadExample(examplePath)
            self.dut.validateAgainstSchema(example, schema)

    def test_receiver_examples(self):
        """Check that the receiver examples from the spec pass validation"""
        self.example_set_test(RECIEVER_EXAMPLES, 'v1.0-receiver-stage-schema.json')

    def test_sender_examples(self):
        """Check that the sender examples from the spec pass validation"""
        self.example_set_test(SENDER_EXAMPLES, 'v1.0-sender-stage-schema.json')

    def test_receiver_validation_fails(self):
        """Check that receivers fail when given an invalid patch request"""
        self.dut.useValidation = True
        data = [
            {
                "transport_params": {
                    "rtp_enabled": "yellow"
                }
            }
        ]
        r = requests.patch(
            self.receiverRoot + '/staged',
            headers=HEADERS,
            data=json.dumps(data)
        )
        self.assertEqual(r.status_code, 400)
