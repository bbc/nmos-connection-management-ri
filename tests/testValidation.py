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
import validation


class TestValidation(unittest.TestCase):
    """Test generic validation functions"""

    def test_auto_ip_validation(self):
        """Check general validation of IP addresses (both types)
        where "auto" is a valid value"""
        exampleAddress = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        self.assertTrue(validation.isValidAutoIp("127.0.0.1"))
        self.assertTrue(validation.isValidAutoIp("192.168.0.1"))
        self.assertTrue(validation.isValidAutoIp("::1"))
        self.assertTrue(validation.isValidAutoIp(exampleAddress))
        self.assertTrue(validation.isValidAutoIp("auto"))
        self.assertRaises(TypeError, validation.isValidAutoIp, ["127.1"])
        self.assertRaises(TypeError, validation.isValidAutoIp, ["Test"])
        self.assertRaises(TypeError, validation.isValidAutoIp, ["300.0.0.1"])
        self.assertRaises(TypeError, validation.isValidAutoIp, [""])

    def test_ip_validation(self):
        """Check general validation of IP addresses (both types)"""
        exampleAddress = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        self.assertTrue(validation.isValidIp("127.0.0.1"))
        self.assertTrue(validation.isValidIp("192.168.0.1"))
        self.assertTrue(validation.isValidIp("::1"))
        self.assertTrue(validation.isValidIp(exampleAddress))
        self.assertRaises(TypeError, validation.isValidIp, ["127.1"])
        self.assertRaises(TypeError, validation.isValidIp, ["Test"])
        self.assertRaises(TypeError, validation.isValidIp, ["300.0.0.1"])
        self.assertRaises(TypeError, validation.isValidIp, [""])
        self.assertRaises(TypeError, validation.isValidIp, ["auto"])

    def test_ipv4_validation(self):
        """Check ipv4 addresses are validated properly"""
        self.assertTrue(validation.isValidIpv4("127.0.0.1"))
        self.assertTrue(validation.isValidIpv4("192.168.0.1"))
        self.assertRaises(TypeError, validation.isValidIpv4, ["127.1"])
        self.assertRaises(TypeError, validation.isValidIpv4, ["Test"])
        self.assertRaises(TypeError, validation.isValidIpv4, ["300.0.0.1"])
        self.assertRaises(TypeError, validation.isValidIpv4, [""])
        self.assertRaises(TypeError, validation.isValidIpv4, ["::1"])

    def test_ipv6_validation(self):
        """Check ipv6 addresses are validated properly"""
        exampleAddress = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        badAddress = "2001:0gb8:85a3:0000:0000:8a2e:0370:7334"
        self.assertTrue(validation.isValidIpv6("::1"))
        self.assertTrue(validation.isValidIpv6(exampleAddress))
        self.assertRaises(TypeError, validation.isValidIpv6, [badAddress])
        self.assertRaises(TypeError, validation.isValidIpv6, ["192.168.0.1"])
        self.assertRaises(TypeError, validation.isValidIpv6, ["Test"])

    def test_port_validation(self):
        """Check port validation"""
        self.assertTrue(validation.isValidPort(5000))
        self.assertTrue(validation.isValidPort(49151))
        self.assertTrue(validation.isValidPort(10000))
        self.assertRaises(TypeError, validation.isValidPort, ["port"])
        self.assertRaises(TypeError, validation.isValidPort, [-10])
        self.assertRaises(TypeError, validation.isValidPort, [1.123])
        self.assertRaises(TypeError, validation.isValidPort, [4999])
        self.assertRaises(TypeError, validation.isValidPort, [49152])

    def test_enum_validation(self):
        """Check validation of enumerated types"""
        validDict = [1, 2, 3, 4, 5]
        self.assertTrue(validation.isValidEnum(2, validDict))
        self.assertRaises(TypeError, validation.isValidEnum, [10, validDict])

    def test_range_validation(self):
        """Check validation of ranges"""
        maximum = 2000
        minimum = 1000
        self.assertTrue(validation.isInRange(1500, maximum, minimum))
        self.assertTrue(validation.isInRange(1000, maximum, minimum))
        self.assertTrue(validation.isInRange(2000, maximum, minimum))
        self.assertRaises(TypeError, validation.isInRange,
                          [999, maximum, minimum])
        self.assertRaises(TypeError, validation.isInRange,
                          [2001, maximum, minimum])

    def test_int_validation(self):
        """Check validation of integers"""
        self.assertTrue(validation.isInt(10))
        self.assertTrue(validation.isInt(-2))
        self.assertRaises(TypeError, validation.isInt, [10.2])
        self.assertRaises(TypeError, validation.isInt, ["Test"])

    def test_uuid_validation(self):
        """Check validation of UUIDs"""
        uuid = "0a174530-e3cf-11e6-bf01-fe55135034f3"
        self.assertTrue(validation.isUUID(uuid))
        self.assertRaises(TypeError, validation.isUUID, ["test"])

    def test_type_string_validation(self):
        """Check validation of type strings"""
        testString = "application/sdp"
        self.assertTrue(validation.isTypeString(testString))
        self.assertRaises(TypeError, validation.isTypeString, ["test"])
