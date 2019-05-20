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
import copy
from flask import Response

from nmoscommon.webapi import WebAPI, basic_route
from nmoscommon.logger import Logger
from nmosconnection.sdpManager import SdpManager

TESTING_HTTP_PORT = 8080


class MockSenderAPI():
    """Mock up of a sender backend API for testing the sender routes"""

    def __init__(self):
        self.locked = False
        self.srcIp = ""
        self.destIp = ""
        self.destPort = ""
        self.enabled = True

    def lock(self):
        self.locked = True

    def unLock(self):
        self.locked = False

    def getStagedDestIp(self):
        return self.destIp

    def getStagedSrcIp(self):
        return self.sourceIp

    def getStagedDestPort(self):
        return self.destPort

    def getStagedMulticastIp(self):
        return self.multicastIp

    def _setTp(self, value, field, leg):
        if field == "source_ip":
            self.sourceIp = value
        elif field == "destination_port":
            self.destPort = value
        elif field == "rtp_enabled":
            self.Enabled = value
        elif field == "multicast_ip":
            self.multicastIp = value
        else:
            print(field)
            raise KeyError


class TestSdpManager(unittest.TestCase):

    def setUp(self):
        self.logger = Logger("Connection Management Tests")
        self.interface = MockSenderAPI()
        self.dut = SdpManager(self.logger, self.interface)
        self.callbackCalled = False
        self.callbackParams = []
        self.callbackReturn = None

    def mockCallback(self, *args):
        self.callbackCalled = True
        self.callbackParams = args
        return self.callbackReturn

    def test_update_wrong_type(self):
        """Test we get an exception when an object with
        un-supported type is used"""
        testObj = copy.deepcopy(TEST_REQUEST)
        testObj["type"] = "application/dash+xml"
        testObj['data'] = "test"
        self.assertRaises(ValueError, self.dut.update, testObj)

    def test_activate(self):
        """Test the moving of paramers from staged to active"""
        self.dut.stagedSdp = EXAMPLE_SDP
        self.dut.stagedRequest = TEST_REQUEST
        self.dut.stagedSources = ["source1", "source2"]
        self.dut.activateStaged()
        self.assertEqual(EXAMPLE_SDP, self.dut.activeSdp)
        self.assertEqual(TEST_REQUEST, self.dut.activeRequest)
        self.assertEqual(["source1", "source2"], self.dut.activeSources)

    def test_apply_params_to_interface(self):
        """Test parameters are applied correctly to
        the interface during updates"""
        self.dut.stagedSources = [
            {
                "source": "192.168.0.1",
                "dest": "192.168.0.5",
                "port": "8080"
            }
        ]
        self.dut.senderId = "217b3089-af57-3eb6-9c3d-829cb12cb3df"
        self.dut.applyParamsToInterface()
        self.assertEqual(
            self.interface.getStagedSrcIp(),
            "192.168.0.1"
        )
        self.assertEqual(
            self.interface.getStagedMulticastIp(),
            "192.168.0.5"
        )
        self.assertEqual(
            self.interface.getStagedDestPort(),
            "8080"
        )

    def test_get_staged(self):
        self.dut.stagedSdp = EXAMPLE_SDP
        self.assertEqual(EXAMPLE_SDP, self.dut.getStagedSdp())

    def test_get_active(self):
        self.dut.activeSdp = EXAMPLE_SDP
        self.assertEqual(EXAMPLE_SDP, self.dut.getActiveSdp())

    class sdpServer(WebAPI):

        @basic_route('/')
        def serve_sdp(self):
            resp = Response(EXAMPLE_SDP)
            resp.headers['content-type'] = 'application/sdp'
            return


EXAMPLE_SDP = """v=0
o=- 1472821477 1472821477 IN IP4 172.29.226.31
s=NMOS Stream
t=0 0
m=video 5000 RTP/AVP 103
c=IN IP4 232.25.176.223/32
a=source-filter: incl IN IP4 232.25.176.223 172.29.226.31
a=rtpmap:103 raw/90000
a=fmtp:103 sampling=YCbCr-4:2:2; width=1920; height=1080; depth=10; interlace=1; colorimetry=BT709-2
a=extmap:1 urn:x-nmos:rtp-hdrext:sync-timestamp
a=extmap:2 urn:x-nmos:rtp-hdrext:origin-timestamp
a=extmap:4 urn:x-nmos:rtp-hdrext:flow-id
a=extmap:5 urn:x-nmos:rtp-hdrext:source-id
a=extmap:7 urn:x-nmos:rtp-hdrext:grain-flags
a=extmap:6 urn:x-nmos:rtp-hdrext:grain-duration
"""

TEST_REQUEST = {
    "sender_id": "217b3089-af57-3eb6-9c3d-829cb12cb3df",
    "session_description": {
        "data": EXAMPLE_SDP,
        "type": "application/sdp"
    }
}
