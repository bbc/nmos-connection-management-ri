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
# limitations under the License

import unittest
from mock import MagicMock
from sdpFactory import senderFileFactory


class TestSdpFactory(unittest.TestCase):

    def setUp(self):
        interface = MagicMock(name='interface')
        self.UUT = senderFileFactory(interface)

    def test_multicast_block_substitution(self):
        """Check details from interface get substituted into the multicast part of the
        SDP template correctly"""
        self.UUT.checkMulticast = MagicMock()
        self.UUT.checkMulticast.return_value = True

        def sideEffect(name, leg): return name
        self.UUT.interface.getActiveParameter.side_effect = sideEffect
        actual = self.UUT.generateMulticastBlock()
        expected = (
             '\nm=video destination_port RTP/AVP 103\nc=IN IP4 destination_ip/32\n'
             'a=source-filter: incl IN IP4 destination_ip source_ip' + RTP_POST_ADDR
        )
        self.assertEqual(expected, actual)

    def test_multicast_block_ignores_when_unicast(self):
        """Test to make sure the multicast part of the SDP file is not added when the
        address is unicast"""
        self.UUT.checkMulticast = MagicMock()
        self.UUT.checkMulticast.return_value = False
        expected = ""
        actual = self.UUT.generateMulticastBlock()
        self.assertEqual(expected, actual)

    def test_unicast_block_substituation(self):
        """Check details from interface get substituted into the unicast part of the
        SDP template correctly"""
        self.UUT.checkMulticast = MagicMock()
        self.UUT.checkMulticast.return_value = False

        def sideEffect(name, leg): return name
        self.UUT.interface.getActiveParameter.side_effect = sideEffect
        actual = self.UUT.generateUnicastBlock()
        expected = (
            "\nm=video {} RTP/AVP 103\nc=IN IP4 {}" + RTP_POST_ADDR
        ).format('destination_port', 'destination_ip')
        self.assertEqual(expected, actual)

    def test_unicast_block_ignores_when_multicast(self):
        """Test to make sure the unicast part of the SDP file is not added when the
        address is multicast"""
        self.UUT.checkMulticast = MagicMock()
        self.UUT.checkMulticast.return_value = True
        expected = ""
        actual = self.UUT.generateUnicastBlock()
        self.assertEqual(expected, actual)

RTP_POST_ADDR = """
a=ts-refclk:ptp=IEEE1588-2008:08-00-11-ff-fe-21-e1-b0
a=rtpmap:103 raw/90000
a=fmtp:103 sampling=YCbCr-4:2:2; width=1920; height=1080; depth=10; colorimetry=BT709-2
a=mediaclk:direct=1595650436 rate=90000
a=framerate:25
a=extmap:1 urn:x-nmos:rtp-hdrext:origin-timestamp
a=extmap:2 urn:ietf:params:rtp-hdrext:smpte-tc 3.6e+03@90000/25
a=extmap:3 urn:x-nmos:rtp-hdrext:flow-id
a=extmap:4 urn:x-nmos:rtp-hdrext:source-id
a=extmap:5 urn:x-nmos:rtp-hdrext:grain-flags
a=extmap:7 urn:x-nmos:rtp-hdrext:sync-timestamp
a=extmap:9 urn:x-nmos:rtp-hdrext:grain-duration"""
