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
from nmoscommon.logger import Logger

from nmosconnection.sdpParser import SdpParser

TESTING_HTTP_PORT = 8080


class TestSdpParser(unittest.TestCase):

    def setUp(self):
        self.logger = Logger("Connection Management Tests")
        self.dut = SdpParser(self.logger)

    def checkSdpResult(self, sources):
        self.assertEqual(len(sources), 1)
        source = sources[0]
        self.assertEqual(source['dest'], "232.25.176.223")
        self.assertEqual(source['source'], "172.29.226.31")
        self.assertEqual(source['port'], 5000)

    def test_sdp_parsing(self):
        self.dut.parseFile(EXAMPLE_SDP)
        self.checkSdpResult(self.dut.sources)

    def test_sdp_parsing_blank_line(self):
        """Test the parser can deal with blank lines in the SDP"""
        self.dut.parseFile(EXAMPLE_SDP_BLANKS)
        self.checkSdpResult(self.dut.sources)


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

EXAMPLE_SDP_BLANKS = """v=0
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
