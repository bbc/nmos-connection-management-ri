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

from __future__ import print_function

import unittest
import requests
import uuid
import json
import copy
import argparse
import re
import time
from nmoscommon import timestamp
from jsonschema import validate, FormatChecker, ValidationError
from random import randint

SCHEMA_LOCAL = "schemas/"
HEADERS = {'Content-Type': 'application/json'}

testSenders = True
testReceivers = True


class TestIS05(unittest.TestCase):
    """Test an instance of the IS-05 Connection Management API"""

    URI = "http://localhost:8080"
    skipSenders = False
    skipReceivers = False
    skipBlocking = False
    skipBulk = False
    ibcOnly = False

    @classmethod
    def setUpClass(cls):
        cls.senders = cls.get_senders()
        cls.receivers = cls.get_receivers()
        if len(cls.senders) == 0:
            print("No senders are configured on the API, the senders part of the API will not be tested")
            global testSenders
            testSenders = False
        if len(cls.receivers) == 0:
            print("No receivers are configure on the API, the receivers part of the API will not be tested")
            global testReceivers
            testReceivers = False

    @classmethod
    def get_senders(cls):
        """Gets a list of the available senders on the API"""
        r = requests.get(URI + "/v1.0/single/senders/")
        toReturn = []
        for value in r.json():
            toReturn.append(value[:-1])
        return toReturn

    @classmethod
    def get_receivers(cls):
        """Gets a list of the available receivers on the API"""
        r = requests.get(URI + "/v1.0/single/receivers/")
        toReturn = []
        for value in r.json():
            toReturn.append(value[:-1])
        return toReturn

    def getTAITime(self, offset=0):
        """Get the current TAI time as a colon seperated string"""
        myTime = time.time() + offset
        secs = int(myTime)
        nanos = int((myTime - secs) * 1e9)
        ippTime = timestamp.Timestamp.from_utc(secs, nanos)
        return str(ippTime)

    def load_schema(self, path):
        """Used to load in schemas"""
        f = open(path, "r")
        return f.read()

    def get_num_paths(self, port, portType):
        """Returns the number or redundant paths on a port"""
        url = URI + "/v1.0/single/"+portType+"s/"+port+"/constraints/"
        r = requests.get(url)
        return len(r.json())

    def compare_to_schema(self, schema, endpoint, status_code=200):
        """Compares the response form an endpoint to a schema"""
        schema = self.load_schema(SCHEMA_LOCAL + schema)
        r = requests.get(endpoint)
        self.assertEqual(r.status_code, status_code)
        response = r.json()
        checker = FormatChecker(["ipv4", "ipv6"])
        validate(response, json.loads(schema), format_checker=checker)

    def rxOnly(func):
        def toReturn(self):
            if len(self.receivers) == 0 or self.skipReceivers:
                self.skipTest("No receivers available, skipping receiver test")
            else:
                func(self)
        return toReturn

    def txOnly(func):
        def toReturn(self):
            if len(self.senders) == 0 or self.skipSenders:
                self.skipTest("No senders available, skipping sender test")
            else:
                func(self)
        return toReturn

    def blocking(func):
        def toReturn(self):
            if self.skipBlocking:
                self.skipTest("Skipping a blocking test")
            else:
                func(self)
        return toReturn

    def bulk(func):
        def toReturn(self):
            if self.skipBulk:
                self.skipTest("Skipping a bulk test")
            else:
                func(self)
        return toReturn

    def noibc(func):
        def toReturn(self):
            if self.ibcOnly:
                self.skipTest("Skipping a test not needed for ibc")
            else:
                func(self)
        return toReturn

    @noibc
    def test_api_root(self):
        """Test the very root of the API meets the schema"""
        expected = ["single/", "bulk/"]
        r = requests.get(URI + "/v1.0/")
        self.assertEqual(r.status_code, 200)
        actual = r.json()
        self.assertItemsEqual(expected, actual)

    def test_single_root(self):
        """Test the root of the single endpoint of the API"""
        expected = ["receivers/", "senders/"]
        r = requests.get(URI + "/v1.0/single/")
        self.assertEqual(r.status_code, 200)
        actual = r.json()
        self.assertItemsEqual(expected, actual)

    def test_single_receiver_root(self):
        """Test the root of /single/receivers"""
        r = requests.get(URI + "/v1.0/single/receivers/")
        response = r.json()
        for value in response:
            self.assertEqual(value[-1], "/")
            uuid.UUID(value[:-1])

    def test_single_sender_root(self):
        """Test the root of /single/senders"""
        r = requests.get(URI + "/v1.0/single/senders/")
        response = r.json()
        for value in response:
            self.assertEqual(value[-1], "/")
            uuid.UUID(value[:-1])

    @txOnly
    def test_single_sender_root_uuid_index(self):
        """Test the index at /single/senders/<uuid>/"""
        r = requests.get(URI + "/v1.0/single/senders/"+self.senders[0]+"/")
        expected = [
            "constraints/",
            "staged/",
            "active/",
            "transportfile/"
        ]
        actual = r.json()
        self.assertItemsEqual(expected, actual)

    @rxOnly
    def test_single_receiver_root_uuid_index(self):
        """Test the index at /single/receivers/<uuid>/"""
        r = requests.get(URI + "/v1.0/single/receivers/"+self.receivers[0]+"/")
        expected = [
            "constraints/",
            "staged/",
            "active/"
        ]
        actual = r.json()
        self.assertItemsEqual(expected, actual)

    @rxOnly
    def test_receiver_constraints_against_schema(self):
        """Test the receiver constraints endpoint to make sure what
        it returns meets the schema"""
        r = requests.get(URI + "/v1.0/single/receivers/"+self.receivers[0]+"/constraints/")
        schema = self.load_schema("schemas/v1.0-constraints-schema.json")
        jschema = json.loads(schema)
        validate(r.json(), jschema)

    @txOnly
    def test_sender_constraints_against_schema(self):
        """Test the sender constraints endpoint to make sure what
        it returns meets the schema"""
        r = requests.get(URI + "/v1.0/single/senders/"+self.senders[0]+"/constraints/")
        schema = self.load_schema("schemas/v1.0-constraints-schema.json")
        jschema = json.loads(schema)
        validate(r.json(), jschema)

    def check_params_match(self, port, portList):
        """Generic test for checking params listed in the /constraints endpoint
        are listed in in the /staged and /active endpoints"""
        r = requests.get(URI + "/v1.0/single/"+port+"/"+portList[0]+"/constraints/")
        s = requests.get(URI + "/v1.0/single/"+port+"/"+portList[0]+"/staged/")
        a = requests.get(URI + "/v1.0/single/"+port+"/"+portList[0]+"/active/")

        count = 0
        for entry in r.json():
            constraintParams = entry.keys()
            stagedParams = s.json()['transport_params'][count].keys()
            activeParams = a.json()['transport_params'][count].keys()
            self.assertItemsEqual(constraintParams, stagedParams)
            self.assertItemsEqual(constraintParams, activeParams)
            count = count + 1

    @rxOnly
    def test_receiver_transport_params_match(self):
        """Test that all the params listed in the receiver /constraints endpoint
        are listed in in the /staged and /active endpoints"""
        self.check_params_match("receivers", self.receivers)

    @txOnly
    def test_sender_transport_params_match(self):
        """Test that all the params listed in the sender /constraints endpoint
        are listed in in the /staged and /active endpoints"""
        self.check_params_match("senders", self.senders)

    @txOnly
    def test_sender_uses_valid_parameter_set(self):
        """Check that the sender is using a valid combination of parameters"""
        generalParams = ['source_ip', 'destination_ip', 'destination_port', 'source_port', 'rtp_enabled']
        fecParams = ['fec_enabled', 'fec_destination_ip', 'fec_mode', 'fec_type',
                          'fec_block_width', 'fec_block_height', 'fec1D_destination_port',
                          'fec1D_source_port', 'fec2D_destination_port', 'fec2D_source_port']
        fecParams = fecParams + generalParams
        rtcpParams = ['rtcp_enabled', 'rtcp_destination_ip', 'rtcp_destination_port',
                          'rtcp_source_port']
        combinedParams = rtcpParams + fecParams
        rtcpParams = rtcpParams + generalParams

        r = requests.get(URI + "/v1.0/single/senders/"+self.senders[0]+"/constraints/")
        params = r.json()[0].keys()
        if sorted(params) == sorted(generalParams):
            return True
        if sorted(params) == sorted(fecParams):
            return True
        if sorted(params) == sorted(rtcpParams):
            return True
        if sorted(params) == sorted(combinedParams):
            return True
        else:
            self.fail("Invalid combination of parameters on constraints endpoint")

    @rxOnly
    def test_receiver_uses_valid_parameter_set(self):
        """Check that the receiver is using a valid combination of parmaeters"""
        generalParams = ['source_ip', 'multicast_ip', 'interface_ip', 'destination_port', 'rtp_enabled']
        fecParams = ['fec_enabled', 'fec_destination_ip', 'fec_mode',
                          'fec1D_destination_port', 'fec2D_destination_port']
        fecParams = fecParams + generalParams
        rtcpParams = ['rtcp_enabled', 'rtcp_destination_ip', 'rtcp_destination_port']
        combinedParams = rtcpParams + fecParams
        rtcpParams = rtcpParams + generalParams

        r = requests.get(URI + "/v1.0/single/receivers/"+self.receivers[0]+"/constraints/")
        params = r.json()[0].keys()
        if sorted(params) == sorted(generalParams):
            return True
        if sorted(params) == sorted(fecParams):
            return True
        if sorted(params) == sorted(rtcpParams):
            return True
        if sorted(params) == sorted(combinedParams):
            return True
        else:
            self.fail("Invalid combination of parameters on constraints endpoint")

    @txOnly
    def test_sender_staged_schema_valid(self):
        """Check that the response from the staged schema endpoint complies with the schema"""
        r = requests.get(URI + "/v1.0/single/senders/"+self.senders[0]+"/staged/")
        schema = self.load_schema("schemas/v1.0-sender-response-schema.json")
        checker = FormatChecker(["ipv4", "ipv6"])
        validate(r.json(), json.loads(schema), format_checker = checker)

    @rxOnly
    def test_receiver_staged_schema_valid(self):
        """Check that the response from the staged schema endpoint complies with the schema"""
        r = requests.get(URI + "/v1.0/single/receivers/"+self.receivers[0]+"/staged/")
        schema = self.load_schema("schemas/v1.0-receiver-response-schema.json")
        checker = FormatChecker(["ipv4", "ipv6"])
        validate(r.json(), json.loads(schema), format_checker = checker)

    def check_staged_complies_with_constraints(self, port, portList):
        """Check that the staged endpoint is using parameters that meet
        the constents of the /constraints endpoint"""
        r = requests.get(URI + "/v1.0/single/"+port+"s/"+portList[0]+"/staged/")
        schema = self.load_schema("schemas/v1.0_"+port+"_transport_params_rtp.json")
        constraints = requests.get(URI + "/v1.0/single/"+port+"s/"+portList[0]+"/constraints/").json()
        checker = FormatChecker(["ipv4", "ipv6"])
        count = 0
        for params in r.json()['transport_params']:
            combinedSchema = json.loads(schema)
            combinedSchema.update(constraints[count])
            validate(params, combinedSchema['items']['properties'], format_checker = checker)
            count = count + 1

    @rxOnly
    def test_receiver_staged_complies_with_constraints(self):
        self.check_staged_complies_with_constraints("receiver", self.receivers)

    @txOnly
    def test_sender_staged_complies_with_constraints(self):
        self.check_staged_complies_with_constraints("sender", self.senders)

    def check_patch_response_schema_valid(self, port, portList):
        """Check the response to an empty patch request complies with the schema"""
        url = URI + "/v1.0/single/"+port+"s/"+portList[0]+"/staged"
        r = requests.patch(url, headers=HEADERS, data="{}")
        schema = self.load_schema("schemas/v1.0-"+port+"-response-schema.json")
        checker = FormatChecker(["ipv4","ipv6"])
        validate(r.json(), json.loads(schema), format_checker = checker)

    @rxOnly
    def test_receiver_patch_response_schema_valid(self):
        self.check_patch_response_schema_valid("receiver", self.receivers)

    @txOnly
    def test_sender_patch_response_schema_valid(self):
        self.check_patch_response_schema_valid("sender", self.senders)

    def check_refuses_invalid_patch(self, port, portList):
        """Check that invalid patch requests to /staged are met with an HTTP 400"""
        data = {"bad": "data"}
        url = URI + "/v1.0/single/"+port+"s/"+portList[0]+"/staged"
        r = requests.patch(url, headers=HEADERS, data=data)
        self.assertEqual(r.status_code, 400)

    @rxOnly
    def test_receiver_invalid_patch(self):
        self.check_refuses_invalid_patch("receiver", self.receivers)

    @txOnly
    def test_sender_invalid_patch(self):
        self.check_refuses_invalid_patch("sender", self.senders)

    @rxOnly
    def test_change_sender_id(self):
        """Check that we can change the sender id on a receiver"""
        url = URI + "/v1.0/single/receivers/"+self.receivers[0]+"/staged"
        id = str(uuid.uuid4())
        data = {"sender_id": id}
        r = requests.patch(url, headers=HEADERS, data=json.dumps(data))
        s = requests.get(url + "/")
        self.assertEqual(s.json()['sender_id'], id)

    @txOnly
    def test_change_recevier_id(self):
        """Check that we can change the receiver id on a sender"""
        url = URI + "/v1.0/single/senders/"+self.senders[0]+"/staged"
        id = str(uuid.uuid4())
        data = {"receiver_id": id}
        r = requests.patch(url, headers=HEADERS, data=json.dumps(data))
        s = requests.get(url + "/")
        self.assertEqual(s.json()['receiver_id'], id)

    def check_change_transport_param(self, port, portList, paramName, paramValues):
        url = URI + "/v1.0/single/"+port+"s/"+portList[0]+"/staged"
        data = {}
        data['transport_params'] = []
        paths = self.get_num_paths(portList[0], port)
        for i in range(0, paths):
            data['transport_params'].append({})
            data['transport_params'][i][paramName] = paramValues[i]
        r = requests.patch(url, headers=HEADERS, data=json.dumps(data))
        s = requests.get(url + "/")
        response = s.json()['transport_params']
        count = 0
        for item in response:
            self.assertEqual(item[paramName], paramValues[count])
            count = count + 1

    def generate_destination_ports(self, port, portId):
        """Uses a port's constraints to generate an allowable destination
        ports for it"""
        url = URI + "/v1.0/single/"+port+"s/"+portId+"/constraints/"
        r = requests.get(url)
        constraints = r.json()
        toReturn = []
        for entry in constraints:
            if "maximum" in entry['destination_port']:
                max = entry['destination_port']['maximum']
            else:
                max = 49151
            if "minimum" in entry['destination_port']:
                min = entry['destination_port']['minimum']
            else:
                min = 5000
            toReturn.append(randint(min, max))
        return toReturn

    @txOnly
    def test_sender_check_set_transport_param(self):
        values = self.generate_destination_ports("sender", self.senders[0])
        self.check_change_transport_param("sender", self.senders, "destination_port", values)

    @rxOnly
    def test_receiver_check_set_transport_param(self):
        values = self.generate_destination_ports("receiver", self.receivers[0])
        self.check_change_transport_param("receiver", self.receivers, "destination_port", values)

    def check_staged_activation_params_default(self, port, portId):
        # Check that the staged activation parameters have returned to their default values
        stagedUrl = URI + "/v1.0/single/"+port+"s/"+portId+"/staged"
        r = requests.get(stagedUrl)
        self.assertEqual(r.status_code, 200)
        expected = {"mode": None, "requested_time": None, "activation_time": None}
        self.assertEqual(r.json()['activation'], expected)

    def check_perform_immediate_activation(self, port, portId, stagedParams):
        # Request an immediate activation
        stagedUrl = URI + "/v1.0/single/"+port+"s/"+portId+"/staged"
        activeUrl = URI + "/v1.0/single/"+port+"s/"+portId+"/active"
        data = { "activation": {"mode": "activate_immediate"}}
        s = requests.patch(stagedUrl, data=json.dumps(data), headers=HEADERS)
        self.assertEqual(s.status_code, 200)
        self.assertEqual(s.json()['activation']['mode'], "activate_immediate")
        self.assertEqual(s.json()['activation']['requested_time'], None)
        self.assertTrue(re.match("^[0-9]+:[0-9]+$", s.json()['activation']['activation_time']) is not None)
        self.check_staged_activation_params_default(port, portId)
        # Check the values now on /active
        t = requests.get(activeUrl)
        self.assertEqual(t.status_code, 200)
        activeParams = t.json()
        for i in range(0, self.get_num_paths(portId, port)):
            self.assertEqual(stagedParams[i]['destination_port'], activeParams['transport_params'][i]['destination_port'])
        self.assertEqual(activeParams['activation']['mode'], "activate_immediate")

    def check_perform_relative_activation(self, port, portId, stagedParams):
        # Request an relative activation
        stagedUrl = URI + "/v1.0/single/"+port+"s/"+portId+"/staged"
        activeUrl = URI + "/v1.0/single/"+port+"s/"+portId+"/active"
        data = { "activation": {"mode": "activate_scheduled_relative", "requested_time": "0:2"}}
        s = requests.patch(stagedUrl, data=json.dumps(data), headers=HEADERS)
        self.assertEqual(s.status_code, 202)
        self.assertEqual(s.json()['activation']['mode'], "activate_scheduled_relative")
        self.assertEqual(s.json()['activation']['requested_time'], "0:2")
        self.assertTrue(re.match("^[0-9]+:[0-9]+$", s.json()['activation']['activation_time']) is not None)
        time.sleep(0.2)
        # Check the values now on /active
        t = requests.get(activeUrl)
        self.assertEqual(t.status_code, 200)
        activeParams = t.json()
        for i in range(0, self.get_num_paths(portId, port)):
            self.assertEqual(stagedParams[i]['destination_port'], activeParams['transport_params'][i]['destination_port'])
        self.assertEqual(activeParams['activation']['mode'], "activate_scheduled_relative")

    def check_perform_absolute_activation(self, port, portId, stagedParams):
        # request an absolute activation
        stagedUrl = URI + "/v1.0/single/"+port+"s/"+portId+"/staged"
        activeUrl = URI + "/v1.0/single/"+port+"s/"+portId+"/active"
        TAItime = self.getTAITime(0.1)
        data = { "activation": {"mode": "activate_scheduled_absolute", "requested_time": TAItime}}
        s = requests.patch(stagedUrl, data=json.dumps(data), headers=HEADERS)
        self.assertEqual(s.status_code, 202)
        self.assertEqual(s.json()['activation']['mode'], "activate_scheduled_absolute")
        self.assertEqual(s.json()['activation']['requested_time'], TAItime)
        self.assertTrue(re.match("^[0-9]+:[0-9]+$", s.json()['activation']['activation_time']) is not None)
        # Allow extra time for processing between getting time and making request
        time.sleep(2)
        # Check the values now on /active
        t = requests.get(activeUrl)
        self.assertEqual(t.status_code, 200)
        activeParams = t.json()
        for i in range(0, self.get_num_paths(portId, port)):
            self.assertEqual(stagedParams[i]['destination_port'], activeParams['transport_params'][i]['destination_port'])
        self.assertEqual(activeParams['activation']['mode'], "activate_scheduled_absolute")

    def check_activation(self, port, portId, activationMethod):
        """Checks that when an immediate activation is called staged parameters are moved
        to active and the activation is correctly displayed in the /active endpoint"""
        # Set a new destination port in staged
        destinationPort = self.generate_destination_ports(port, portId)
        stagedUrl = URI + "/v1.0/single/"+port+"s/"+portId+"/staged"
        data = { "transport_params": []}
        for i in range(0, self.get_num_paths(portId, port)):
            data['transport_params'].append({"destination_port": destinationPort[i]})
        r = requests.patch(stagedUrl, data=json.dumps(data), headers=HEADERS)
        self.assertEqual(r.status_code, 200)
        stagedParams = r.json()['transport_params']
        activationMethod(port, portId, stagedParams)

    @txOnly
    def test_sender_immediate_activation(self):
        self.check_activation("sender", self.senders[0], self.check_perform_immediate_activation)

    @rxOnly
    def test_receiver_immediate_activation(self):
        self.check_activation("receiver", self.receivers[0], self.check_perform_immediate_activation)

    @noibc
    @blocking
    @txOnly
    def test_sender_relative_activation(self):
        self.check_activation("sender", self.senders[0], self.check_perform_relative_activation)

    @noibc
    @blocking
    @rxOnly
    def test_receiver_relative_activation(self):
        self.check_activation("receiver", self.receivers[0], self.check_perform_relative_activation)

    @noibc
    @blocking
    @txOnly
    def test_sender_absolute_activation(self):
        self.check_activation("sender", self.senders[0], self.check_perform_absolute_activation)

    @noibc
    @blocking
    @rxOnly
    def test_receiver_absolute_activation(self):
        self.check_activation("receiver", self.receivers[0], self.check_perform_absolute_activation)

    @rxOnly
    def test_active_receiver(self):
        """Check the response from the receiver /active endpoint matches the schema"""
        activeUrl = URI + "/v1.0/single/receivers/"+self.receivers[0]+"/active"
        self.compare_to_schema("v1.0-receiver-active-schema.json", activeUrl)

    @txOnly
    def test_active_sender(self):
        """Check the response form the sender /active endpoint matches the schema"""
        activeUrl = URI + "/v1.0/single/senders/"+self.senders[0]+"/active"
        self.compare_to_schema("v1.0-sender-active-schema.json", activeUrl)

    @noibc
    @bulk
    def test_bulk_root(self):
        """Check the /bulk endpoint returns the correct JSON"""
        url = URI + "/v1.0/bulk/"
        r = requests.get(url)
        expected = ['senders/', 'receivers/']
        self.assertItemsEqual(expected, r.json())

    @noibc
    @bulk
    def test_bulk_receiver_405(self):
        """Check the receiver returns a 405 status code if  a GET is called on the /bulk/receivers endpoint"""
        url = URI + "/v1.0/bulk/receivers"
        r = requests.get(url)
        self.assertEqual(r.status_code, 405)

    def check_bulk_stage(self, port, portList):
        """Test changing staged parameters on the bulk interface"""
        url = URI + "/v1.0/bulk/"+port+"s"
        data = []
        ports = {}
        for portInst in portList:
            ports[portInst] = self.generate_destination_ports(port, portInst)
            toAdd = {}
            toAdd['id'] = portInst
            toAdd['params'] = {}
            toAdd['params']['transport_params'] = []
            for portNum in ports[portInst]:
                toAdd['params']['transport_params'].append({"destination_port": portNum})
            data.append(toAdd)
        r = requests.post(url, data=json.dumps(data), headers=HEADERS)
        self.assertEqual(r.status_code, 200)
        schema = self.load_schema("schemas/v1.0-bulk-stage-confirm.json")
        validate(r.json(), json.loads(schema))
        # Check the parameters have actually changed
        for portInst in portList:
            activeUrl = URI + "/v1.0/single/"+port+"s/"+portInst+"/staged/"
            r = requests.get(activeUrl)
            for i in range(0, self.get_num_paths(portInst, port)):
                value = r.json()['transport_params'][i]['destination_port']
                portNum = ports[portInst][i]
                self.assertEqual(value, portNum)

    @noibc
    @bulk
    @rxOnly
    def test_bulk_sender_stage(self):
        """Use the bulk interface to change the destination port on all receivers"""
        self.check_bulk_stage("receiver", self.receivers)

    @noibc
    @bulk
    @txOnly
    def test_bulk_sender_stage(self):
        """Use the bulk interface to change the destination port on all receivers"""
        self.check_bulk_stage("sender", self.senders)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IS-05 automated testing suite")
    parser.add_argument('url', nargs=1, type=str, help="URL the api is hosted at e.g http://localhost:8080/x-nmos/connection")
    parser.add_argument('--nosenders', action='store_const', const=True, default=False,
                       help="Suppress testing of senders")
    parser.add_argument('--noreceivers', action='store_const', const=True, default=False,
                       help="Suppress testing of receivers")
    parser.add_argument('--noblock', action='store_const', const=True, default=False,
                       help="Suppress blocking tests")
    parser.add_argument('--nobulk', action='store_const', const=True, default=False,
                        help="Suppress testing of the bulk interface")
    parser.add_argument('--ibc', action='store_const', const=True, default=False,
                        help="Only run tests required for the IBC 2017 IS-05 IP Showcase")
    args = parser.parse_args()

    URI = args.url[0]
    TestIS05.URI = URI
    TestIS05.skipSenders = args.nosenders
    TestIS05.skipReceiver = args.noreceivers
    TestIS05.skipBlocking = args.noblock
    TestIS05.skipBulk = args.nobulk
    TestIS05.ibcOnly = args.ibc
    r = requests.get(URI)
    if r.status_code == 200:
        suite = unittest.TestLoader().loadTestsFromTestCase(TestIS05)
        unittest.TextTestRunner().run(suite)
    else:
        print("Supplied URI does not appear to be valid, response code was {}".format(r.status_code))
