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

import json
import unittest
import os
import copy
from nmoscommon.logger import Logger

from nmosconnection.rtpReceiver import RtpReceiver
from nmosconnection.fieldException import FieldException

SENDER_WS_PORT = 8857
HEADERS = {'Content-Type': 'application/json'}

__location__ = os.path.realpath(
    os.path.join(os.getcwd(), os.path.dirname(__file__)))

__tp__ = "transport_params"
__sd__ = "session_description"


class TestRtpReceiverBackend(unittest.TestCase):
    """Test the RTP receiver backend"""

    def setUp(self):
        self.logger = Logger("Connection Management Tests")
        self.dut = RtpReceiver(
            self.logger,
            self.mockTransportManager,
            2
        )
        self.hadCallback = False
        self.callbackArgs = None
        self.dut.schemaPath = "../share/ipp-connectionmanagement/schemas/"

    def _mockCallback(self, *args):
        self.hadCallback = True
        self.callbackArgs = args

    class mockTransportManager():

        def __init__(self, logger, receiver):
            self.logger = logger,
            self.receiver = receiver

    def _getExampleObject(self, fec=True, rtcp=True):
        testObj = {}
        testObj['src_ip'] = "192.168.0.1"
        testObj['destination_ip'] = "192.168.0.2"
        testObj['destination_port'] = 9090
        testObj['rtp_enabled'] = True
        if fec:
            testObj['fec_enabled'] = True
            testObj['fec_destination_ip'] = "auto"
            testObj['fec_mode'] = "2D"
            testObj['fec1D_destination_port'] = 8080
            testObj['fec2D_destination_port'] = 9090
        if rtcp:
            testObj['rtcp_enabled'] = True
            testObj['rtcp_destination_ip'] = "192.168.0.1"
            testObj['rtcp_destination_port'] = 8080
        session = {}
        session['type'] = "application/sdp"
        session['data'] = None
        session['by_reference'] = False
        expected = {}
        expected[__tp__] = [{}, {}]
        expected[__tp__][0] = dict(testObj)
        expected[__tp__][1] = dict(testObj)
        expected['sender_id'] = "0a174530-e3cf-11e6-bf01-fe55135034f3"
        expected['receiver_id'] = None
        return expected

    def _compare_schema(self, path):
        """Used by schema checking method to itterate through
        different schemas"""
        schemaPath = os.path.join(__location__, path)
        with open(schemaPath) as json_data:
            expected = json.load(json_data)
        actual = self.dut.getSchema()
        self.assertEqual(expected, actual)

    def test_schema_filtering(self):
        """Checks that the correct JSON schema is returned"""
        for x in range(0, 1):
            for y in range(0, 1):
                fec = (x == 0)
                rtcp = (y == 0)
            self.dut._enableFec = fec
            self.dut._enableRtcp = rtcp
            schema = self.dut.getParamsSchema(0)['items']['properties']
            for key, value in schema.items():
                if not fec:
                    self.assertNotEqual(key[0:2], "fec")
                if not rtcp:
                    self.assertNotEqual(key[0:3], "rtcp")

    def test_schema_merging(self):
        """Checks that constraints get merged into the schema properly"""
        self.dut._enableFec = False
        self.dut._enableRtcp = False
        srcIpEnum = [
            "192.168.0.1",
            "10.0.0.2"
        ]
        self.dut.constraints = [{
            "interface_ip": {
                "enum": []
            },
            "destination_port":{
                "minimum": 5000,
                "maximum": 6000
            }
        }]
        self.dut.constraints[0]['interface_ip']['enum'] = srcIpEnum
        schema = self.dut.getParamsSchema(0)['items']['properties']
        self.assertEqual(schema['interface_ip']['enum'], srcIpEnum)
        self.assertEqual(schema['destination_port']['maximum'], 6000)
        self.assertEqual(schema['destination_port']['minimum'], 5000)

    def test_staged_get_json(self):
        """Test all parameters make it to json object"""
        expected = self._getExampleObject()
        self.dut.staged = copy.deepcopy(expected)
        actual = self.dut.stagedToJson()
        self.maxDiff = None
        expected.pop('receiver_id')
        self.assertEqual(actual, expected)

    def test_disable_fec_json(self):
        """Test that disabling fec prevents FEC being returned in JSON"""
        expected = self._getExampleObject(False)
        self.dut.staged = copy.deepcopy(expected)
        for leg in range(0, 2):
            self.dut.staged[__tp__][leg]['fec_destination_ip'] = "auto"
            self.dut.staged[__tp__][leg]['fec_enabled'] = True
            self.dut.staged[__tp__][leg]['fec_mode'] = "2D"
            self.dut.staged[__tp__][leg]['fec1D_destination_port'] = 8080
            self.dut.staged[__tp__][leg]['fec2D_destination_port'] = 8080
        self.dut._enableFec = False
        self.dut._enableRtcp = True
        actual = self.dut._assembleJsonDescription(self.dut.staged)
        self.maxDiff = None
        expected.pop('receiver_id')
        self.assertEqual(actual, expected)

    def test_disable_rtcp_json(self):
        """Test that disabling rtcp prevents RTCP being returned in JSON"""
        expected = self._getExampleObject(True, False)
        self.dut.staged = copy.deepcopy(expected)
        for leg in range(0, 2):
            self.dut.staged[__tp__][leg]['rtcp_enabled'] = True
            self.dut.staged[__tp__][leg]['rtcp_destination_ip'] = "192.168.0.1"
            self.dut.staged[__tp__][leg]['rtcp_destination_port'] = 5000
        self.dut._enableFec = True
        self.dut._enableRtcp = False
        actual = self.dut._assembleJsonDescription(self.dut.staged)
        self.maxDiff = None
        expected.pop('receiver_id')
        self.assertEqual(actual, expected)

    def test_check_sets_callback(self):
        """Test setting the active callback"""
        self.dut.setActivateCallback(self._mockCallback)
        self.dut.callback()
        self.assertTrue(self.hadCallback)

    def test_enable_rtcp(self):
        """Test setting and un-setting rtcp"""
        self.dut._enableRtcp = False
        self.dut.supportRtcp()
        self.assertTrue(self.dut._enableRtcp)
        self.dut.supportRtcp(False)
        self.assertFalse(self.dut._enableRtcp)

    def test_enable_fec(self):
        """Test enabling and disabling FEC"""
        self.dut._enableFec = False
        self.dut.supportFec()
        self.assertTrue(self.dut._enableFec)
        self.dut.supportFec(False)
        self.assertFalse(self.dut._enableFec)

    def test_patching(self):
        """Check that updates can be applied to
        single fields using the patch function"""
        self.dut._enableFec = True
        testObj = [{}, {"fec1D_destination_port": 8888}]
        self.dut.patch(testObj)
        self.assertEqual(self.dut.staged[__tp__][1]["fec1D_destination_port"], 8888)

    def test_get_constraints(self):
        """Test getting and filtering of constraints"""
        data = [
            {
                "src_port": {
                    "maximum": 90000,
                    "minimum": 500
                },
                "interface_ip": {
                    "enum": ["auto"]
                },
                "fec1D_destination_port":{
                    "miniumum": 4,
                    "maximum": 2000
                },
                "rtcp_destination_port": {
                    "maximum": 90000,
                    "minimum": 500
                }
            },
            {}
        ]
        data[1] = copy.deepcopy(data[0])
        self.dut.constraints = data
        self.dut._enableFec = False
        self.dut._enableRtcp = False
        res = self.dut.getConstraints()[0]
        self.assertTrue("src_port" in res)
        self.assertFalse("fec1D_destination_port" in res)
        self.assertFalse("rtcp_destination_port" in res)
        self.dut._enableFec = True
        self.dut._enableRtcp = False
        res = self.dut.getConstraints()[0]
        self.assertTrue("src_port" in res)
        self.assertTrue("fec1D_destination_port" in res)
        self.assertFalse("rtcp_destination_port" in res)
        self.dut._enableFec = False
        self.dut._enableRtcp = True
        res = self.dut.getConstraints()[0]
        self.assertTrue("src_port" in res)
        self.assertFalse("fec1D_destination_port" in res)
        self.assertTrue("rtcp_destination_port" in res)

    def test_ipv4_checking(self):
        """Test the ipv4 checking method"""
        self.assertTrue(self.dut._checkIsIpv4("192.168.0.1"))
        self.assertTrue(self.dut._checkIsIpv4("127.0.0.1"))
        self.assertFalse(self.dut._checkIsIpv4("2001:db8::211:22ff:fe33:4455"))
        self.assertFalse(self.dut._checkIsIpv4("cat"))

    def test_ipv6_checking(self):
        """Test the ipv6 checking method (doesn't work on windows)"""
        self.assertTrue(self.dut._checkIsIpv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334"))
        self.assertTrue(self.dut._checkIsIpv6("::1"))
        self.assertFalse(self.dut._checkIsIpv6("127.0.0.1"))
        self.assertFalse(self.dut._checkIsIpv6("duck"))

    def test_adding_interface_ip(self):
        """Test adding new interfaces ips to constraints"""
        self.dut.addInterface("192.168.0.1")
        expected = ["192.168.0.1"]
        constraints = self.dut.getConstraints()
        actual = constraints[0]['interface_ip']['enum']
        self.assertEqual(expected, actual)

    def test_resolve_interface_ip(self):
        self.dut.constraints[0]['interface_ip']['enum'].append("192.168.0.50")
        expected = "192.168.0.50"
        actual = self.dut.defaultInterfaceSelector({}, 0)
        self.assertEqual(expected, actual)

    def test_resolve_rtcp_dest_port(self):
        """Test automatic resolution of rtcp dest port"""
        data = [{"destination_port": 5000}]
        expected = 5001
        actual = self.dut._resolveRtcpDestPort(data, 0)
        self.assertEqual(expected, actual)

    def test_resolve_rtcp_dest_ip(self):
        """Test automatic resolution of rtcp dest ip"""
        # unicast
        data = [{'multicast_ip': None, 'interface_ip': "192.168.0.1"}]
        expected = "192.168.0.1"
        actual = self.dut._resolveRtcpDestIp(data, 0)
        self.assertEqual(actual, expected)
        # multicast
        data[0]['multicast_ip'] = "232.158.113.169"
        expected = "232.158.113.169"
        actual = self.dut._resolveRtcpDestIp(data, 0)
        self.assertEqual(actual, expected)

    def test_resolve_fec1d_dest_port(self):
        """Test automatic resolution of fec1d destination port"""
        data = [{"destination_port": 5000}]
        expected = 5002
        actual = self.dut._resolveFec1DDestPort(data, 0)
        self.assertEqual(expected, actual)

    def test_resolve_fec2d_dest_port(self):
        """Test automatic resolution of fec2d destination port"""
        data = [{"destination_port": 5000}]
        expected = 5004
        actual = self.dut._resolveFec2DDestPort(data, 0)
        self.assertEqual(expected, actual)

    def test_resolve_fecIp(self):
        """Test automatic resolution of fec ip address"""
        # unicast
        data = [{'multicast_ip': None, 'interface_ip': "192.168.0.1"}]
        expected = "192.168.0.1"
        actual = self.dut._resolveFecIp(data, 0)
        self.assertEqual(actual, expected)
        # multicast
        data[0]['multicast_ip'] = "232.158.113.169"
        expected = "232.158.113.169"
        actual = self.dut._resolveFecIp(data, 0)
        self.assertEqual(actual, expected)

    def test_resolve_interface_port(self):
        """Test automatic resolution of interface port"""
        expected = 5004
        actual = self.dut._resolveInterfacePort({}, 0)
        self.assertEqual(expected, actual)

    def test_resolve_parameters(self):
        """Test resolve parameters"""
        self.dut.constraints[0]['interface_ip']['enum'].append("192.168.0.50")
        data = {"transport_params": [{
            "source_ip": "192.168.0.1",
            "multicast_ip": "232.158.113.169",
            "interface_ip": "auto",
            "destination_port": "auto",
            "fec_enabled": True,
            "fec_destination_ip": "auto",
            "fec_mode": "1D",
            "fec1D_destination_port": "auto",
            "fec2D_destination_port": "auto",
            "rtcp_destination_ip": "auto",
            "rtcp_enabled": True,
            "rtcp_destination_port": "auto",
            "rtp_enabled": True
        }]}
        expected = copy.deepcopy(data)
        expected["transport_params"][0]['interface_ip'] = "192.168.0.50"
        expected["transport_params"][0]['destination_port'] = 5004
        expected["transport_params"][0]['fec_destination_ip'] = "232.158.113.169"
        expected["transport_params"][0]['fec1D_destination_port'] = 5006
        expected["transport_params"][0]['fec2D_destination_port'] = 5008
        expected["transport_params"][0]['rtcp_destination_ip'] = "232.158.113.169"
        expected["transport_params"][0]['rtcp_destination_port'] = 5005
        actual = self.dut.resolveParameters(data)
        self.assertEqual(actual, expected)


class testFieldException(unittest.TestCase):

    def test_raises(self):
        def x(self):
            raise FieldException("Test", "Field")
        self.assertRaises(FieldException, x, [])

    def test_json_field(self):
        expected = {"status": "Error", "field": "Field",
                    "transport_param_index": 1, "message": "Test"}
        try:
            raise FieldException("Test", "Field", 1)
        except FieldException as e:
            actual = e.getJson()
        self.assertEqual(actual, expected)

    def test_json(self):
        expected = {"status": "Error",
                    "transport_param_index": 0, "message": "Test"}
        try:
            raise FieldException("Test")
        except FieldException as e:
            actual = e.getJson()
        self.assertEqual(actual, expected)
