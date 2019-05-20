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
import json
import os
import copy
from jsonschema import ValidationError
from nmoscommon.logger import Logger

from .abstractDevice import StagedLockedException
from .rtpSender import RtpSender

API_WS_PORT = 8856
SENDER_WS_PORT = 8857
HEADERS = {'Content-Type': 'application/json'}

__location__ = os.path.realpath(
    os.path.join(os.getcwd(), os.path.dirname(__file__)))

__tp__ = "transport_params"


class MockSenderAPI():
    """Mock up of a sender backend API for testing the sender routes"""

    def getSchema(self):
        return json.dumps({'schema': 'schema'})

    def stagedToJson(self):
        return json.dumps({'staged': 'yes'})

    def activeToJson(self):
        return json.dumps({'active': 'yes'})


class TestRtpSenderBackend(unittest.TestCase):
    """Test the RTP sender backend"""

    def setUp(self):
        self.logger = Logger("Connection Management Tests")
        self.dut = RtpSender(self.logger, 2)
        self.dut.supportedSourceIPs = ['127.0.0.1', "::1", "192.168.1.1", "192.168.0.1"]
        self.dut.schemaPath = "../share/ipp-connectionmanagement/schemas/"
        self.hadCallback = False
        self.callbackArgs = None
        self.callbackReturn = None
        self.maxDiff = None

    def _mockCallback(self, *args):
        self.hadCallback = True
        self.callbackArgs = args
        return self.callbackReturn

    def _deadlyCallback(self, *args):
        # This callback will always fail
        raise BaseException

    def _getExampleObject(self, fec=True, rtcp=True):
        testObj = {}
        testObj['source_ip'] = "192.168.0.1"
        testObj['destination_ip'] = "192.168.1.1"
        testObj['source_port'] = 8080
        testObj['destination_port'] = 9090
        testObj['rtp_enabled'] = True
        if fec:
            testObj['fec_enabled'] = True
            testObj['fec_destination_ip'] = "auto"
            testObj['fec_type'] = "XOR"
            testObj['fec_mode'] = "2D"
            testObj['fec_block_width'] = 10
            testObj['fec_block_height'] = 10
            testObj['fec1D_destination_port'] = 6060
            testObj['fec2D_destination_port'] = 7070
            testObj['fec1D_source_port'] = 6161
            testObj['fec2D_source_port'] = 6161
        if rtcp:
            testObj['rtcp_enabled'] = True
            testObj['rtcp_destination_ip'] = "192.168.0.1"
            testObj['rtcp_destination_port'] = 6262
            testObj['rtcp_source_port'] = 6363
        expected = {}
        expected['receiver_id'] = "0a174530-e3cf-11e6-bf01-fe55135034f3"
        expected['master_enable'] = False
        expected['sender_id'] = None
        expected[__tp__] = [{}, {}]
        expected[__tp__][0] = copy.deepcopy(testObj)
        expected[__tp__][1] = copy.deepcopy(testObj)
        return expected

    def test_schema_filtering(self):
        """Checks that the correct JSON schema is returned"""
        for x in range(0, 1):
            for y in range(0, 1):
                fec = (x == 0)
                rtcp = (y == 0)
            self.dut._enableFec = fec
            self.dut._enableRtcp = rtcp
            schema = self.dut.getParamsSchema()['items']['properties']
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
            "source_ip": {
                "enum": []
            },
            "source_port":{
                "minimum": 5000,
                "maximum": 6000
            }
        }]
        self.dut.constraints[0]['source_ip']['enum'] = srcIpEnum
        schema = self.dut.getParamsSchema()['items']['properties']
        self.assertEqual(schema['source_ip']['enum'], srcIpEnum)
        self.assertEqual(schema['source_port']['maximum'], 6000)
        self.assertEqual(schema['source_port']['minimum'], 5000)

    def test_staged_get_json(self):
        """Test all parameters make it to json object"""
        expected = self._getExampleObject()
        self.dut.staged = copy.deepcopy(expected)
        expected.pop('sender_id')
        actual = self.dut.stagedToJson()
        self.maxDiff = None
        self.assertEqual(actual, expected)

    def test_disable_fec_json(self):
        """Test that disabling fec prevents FEC being returned in JSON"""
        expected = self._getExampleObject(False)
        self.dut.staged = copy.deepcopy(expected)
        expected.pop('sender_id')
        for leg in range(0, 2):
            self.dut.staged[__tp__][leg]['fec_enabled'] = True
            self.dut.staged[__tp__][leg]['fec_destination_ip'] = "auto"
            self.dut.staged[__tp__][leg]['fec_block_width'] = 10
            self.dut.staged[__tp__][leg]['fec_block_height'] = 10
            self.dut.staged[__tp__][leg]['fec1D_source_port'] = 8081
            self.dut.staged[__tp__][leg]['fec2D_source_port'] = 8081
            self.dut.staged[__tp__][leg]['fec_mode'] = "2D"
            self.dut.staged[__tp__][leg]['fec_type'] = "XOR"
            self.dut.staged[__tp__][leg]['fec1D_destination_port'] = 8080
            self.dut.staged[__tp__][leg]['fec2D_destination_port'] = 8080
        self.dut._enableFec = False
        self.dut._enableRtcp = True
        actual = self.dut._assembleJsonDescription(self.dut.staged)
        self.maxDiff = None
        self.assertEqual(actual, expected)

    def test_disable_rtcp_json(self):
        """Test that disabling rtcp prevents RTCP being returned in JSON"""
        expected = self._getExampleObject(True, False)
        self.dut.staged = copy.deepcopy(expected)
        expected.pop('sender_id')
        for leg in range(0, 2):
            self.dut.staged[__tp__][leg]['rtcp_enabled'] = True
            self.dut.staged[__tp__][leg]['rtcp_destination_ip'] = "192.168.0.1"
            self.dut.staged[__tp__][leg]['rtcp_destination_port'] = 5000
            self.dut.staged[__tp__][leg]['rtcp_source_port'] = 5000
        self.dut._enableFec = True
        self.dut._enableRtcp = False
        actual = self.dut._assembleJsonDescription(self.dut.staged)
        self.maxDiff = None
        self.assertEqual(actual, expected)

    def test_patching(self):
        """Check that updates can be applied to
        single fields using the patch function"""
        testObj = [{}, {"fec1D_destination_port": 8888}]
        self.dut.patch(testObj)
        self.assertEqual(self.dut.staged[__tp__][1]['fec1D_destination_port'], 8888)

    def test_reject_extra_feilds(self):
        """Make sure patching will reject extral fields"""
        testObj = [{}, {"fec3D_destination_port": 8888}]
        self.assertRaises(ValidationError, self.dut.patch, testObj)

    def test_check_sets_callback(self):
        """Test setting the active callback"""
        self.dut.setActivateCallback(self._mockCallback)
        self.dut.activateStaged()
        self.assertTrue(self.hadCallback)

    def test_patch_locking(self):
        """Test that patch updates cannot be made when the sender is locked"""
        testObj = [{"source_ip": "192.168.1.1"}]
        self.dut.constraints[0]['source_ip']['enum'].append("192.168.1.1")
        self.dut.lock()
        self.assertRaises(StagedLockedException, self.dut.patch, testObj)
        self.dut.unLock()
        self.assertTrue(self.dut.patch(testObj))

    def test_failed_activation_recovery(self):
        """Checks to see that the active parameters fail
        in the event that activation raises an error"""
        preActivationParams = copy.deepcopy(self.dut.active)
        self.dut.setActivateCallback(self._deadlyCallback)
        self.dut.staged[__tp__][0]['destination_ip'] = "192.168.0.1"
        self.dut.staged[__tp__][1]['rtp_enabled'] = False
        self.dut.staged[__tp__][0]['destination_ip'] = "192.168.0.1"
        self.dut.staged[__tp__][1]['rtp_enabled'] = False
        try:
            self.dut.activateStaged()
        except Exception:
            # We would expect this to throw
            pass
        self.assertEqual(self.dut.active, preActivationParams)

    def test_set_master_enable(self):
        """Checks that setting master enable on the abstract works"""
        self.dut.setMasterEnable(True)
        self.assertTrue(self.dut.staged['master_enable'])

    def test_set_receiver_id(self):
        """Checks receiver ID gets passed through to the JSON representation"""
        expected = "fbc9abbd-e76e-42eb-80e2-1120a5295ae9"
        self.dut.setReceiverId("fbc9abbd-e76e-42eb-80e2-1120a5295ae9")
        json = self.dut.stagedToJson()
        uuid = json['receiver_id']
        self.assertEqual(uuid, expected)

    def test_check_rejects_bad_id(self):
        """Checks that bad UUIDs are rejected by the abstract class"""
        data = "BAD"
        self.assertRaises(ValidationError, self.dut.setReceiverId, data)
        self.assertRaises(ValidationError, self.dut.setSenderId, data)

    def test_adding_source_ip(self):
        """Test adding new interfaces ips to constraints"""
        self.dut.addInterface("192.168.0.1")
        expected = ["192.168.0.1"]
        constraints = self.dut.getConstraints()
        actual = constraints[0]['source_ip']['enum']
        self.assertEqual(expected, actual)

    def test_resolve_default_source_ip(self):
        self.dut.constraints['source_ip']['enum'].append("192.168.0.50")
        expected = "192.168.0.50"
        actual = self.dut.defaultSourceSelector({})
        self.assertEqual(expected, actual)

    def test_resolve_destination_ip(self):
        expected = "127.0.0.1"
        actual = self.dut.destinationSelector({}, 0)
        self.assertEqual(expected, actual)
        self.dut.setDestinationSelector(self._mockCallback)
        expected = "192.168.2.2"
        self.callbackReturn = expected
        actual = self.dut.destinationSelector({}, 0)
        self.assertEqual(actual, expected)

    def test_resolve_source_ip(self):
        """Test resolving the source IP"""
        expected = "192.168.1.40"
        self.dut.addInterface(expected)
        actual = self.dut.sourceSelector({}, 0)
        self.assertEqual(actual, expected)
        self.dut.setSourceSelector(self._mockCallback)
        expected = "10.0.1.2"
        self.callbackReturn = expected
        actual = self.dut.sourceSelector({}, 0)

    def test_resolve_rtcp_dest_port(self):
        """Test automatic resolution of rtcp dest port"""
        data = [{"destination_port": 5000}]
        expected = 5001
        actual = self.dut._resolveRtcpDestPort(data, 0)
        self.assertEqual(expected, actual)

    def test_resolve_rtcp_src_port(self):
        """Test automatic resolution of rtcp source port"""
        data = [{"source_port": 5000}]
        expected = 5001
        actual = self.dut._resolveRtcpSrcPort(data, 0)
        self.assertEqual(expected, actual)

    def test_resolve_rtcp_dest_ip(self):
        """Test automatic resolution of rtcp dest ip"""
        data = [{'destination_ip': "192.168.0.1"}]
        expected = "192.168.0.1"
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

    def test_resolve_fec1d_src_port(self):
        """Test automatic resolution of fec1d source port"""
        data = [{"source_port": 5000}]
        expected = 5002
        actual = self.dut._resolveFec1DSrcPort(data, 0)
        self.assertEqual(expected, actual)

    def test_resolve_fec2d_src_port(self):
        """Test automatic resolution of fec2d source port"""
        data = [{"source_port": 5000}]
        expected = 5004
        actual = self.dut._resolveFec2DSrcPort(data, 0)
        self.assertEqual(expected, actual)

    def test_resolve_fecIp(self):
        """Test automatic resolution of fec ip address"""
        data = [{'destination_ip': "192.168.0.1"}]
        expected = "192.168.0.1"
        actual = self.dut._resolveFecIp(data, 0)
        self.assertEqual(actual, expected)

    def test_resolve_destination_port(self):
        """Test automatic resolution of destination port"""
        expected = 5004
        actual = self.dut._resolveDestinationPort({}, 0)
        self.assertEqual(expected, actual)

    def test_resolve_source_port(self):
        """Test automatic resolution of source port"""
        expected = 5004
        actual = self.dut._resolveSourcePort({}, 0)
        self.assertEqual(expected, actual)
