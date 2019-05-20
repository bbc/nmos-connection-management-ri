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

import os
import unittest
import time
import json
from mediatimestamp import Timestamp, TimeOffset
from nmosconnection.activator import Activator
from nmosconnection.fieldException import FieldException
from jsonschema import validate, ValidationError

__location__ = os.path.realpath(
    os.path.join(os.getcwd(), os.path.dirname(__file__)))


class MockApi():
    """A mock API for the activator module to talk to"""
    def __init__(self, callbackFunc):
        self.callback = callbackFunc
        self.locked = False

    def activateStaged(self):
        self.callback("activateStaged")

    def lock(self):
        self.locked = True

    def unLock(self):
        self.locked = False


class MockTimer():
    """A mock timer"""
    def __init__(self):
        self.cancelled = False

    def cancel(self):
        self.cancelled = True


class TestActivatorModule(unittest.TestCase):
    """Test the Activator Module"""

    def setUp(self):
        self.api = MockApi(self.mockApiCallback)
        self.dut = Activator([self.api])
        self.hadCallback = False
        self.dut.schemaPath = "share/ipp-connectionmanagement/schemas/"

    def mockApiCallback(self, *args):
        self.hadCallback = True
        if len(args) > 0:
            self.callbackCaller = args[0]
        self.callbackTime = time.time()

    def mockCallback(self, *args):
        self.hadCallback = True
        self.callbackArgs = args
        self.callbackTime = time.time()
        return {"test": "ok"}

    def verify_against_schema(self, toCheck):
        path = "../share/ipp-connectionmanagement/schemas/v1.0-activate-confirm-schema.json"
        try:
            schemaPath = os.path.join(__location__, path)
            with open(schemaPath) as json_data:
                obj = json_data.read()
                schema = json.loads(obj)
        except EnvironmentError:
            raise IOError('failed to load schema file')
        validate(toCheck, schema)

    def check_last_is_null(self, toCheck=None):
        """Check that all fields in the last request are null"""
        if toCheck is None:
            toCheck = self.dut.getLastRequest()
        last = toCheck
        self.assertEqual(last["mode"], None)
        self.assertEqual(last["requested_time"], None)
        self.assertEqual(last["activation_time"], None)

    def test_init(self):
        """Test the starting state"""
        self.check_last_is_null()
        actual = self.dut.activeRequest
        expected = {
            "mode": None,
            "requested_time": None,
            "activation_time": None
        }
        self.assertEqual(actual, expected)

    def test_get_active_request(self):
        """Test current activation object returns correctly"""
        active = self.dut.getActiveRequest()
        self.assertEqual(active['requested_time'], None)
        self.assertEqual(active['activation_time'], None)
        self.assertEqual(active['mode'], None)

    def test_activation_object_parsing_no_mode(self):
        """Test activation object parser with missing mode param"""
        testFunc = self.dut.parseActivationObject
        self.assertRaises(ValidationError, testFunc, [])
        testDict = {'hello': 'world', 'tom': 'jerry'}
        self.assertRaises(ValidationError, testFunc, [testDict])
        self.check_last_is_null()

    def test_activation_object_parsing_illegal_mode(self):
        """Test activation object parser with illegal mode param"""
        testFunc = self.dut.parseActivationObject
        testDict = {'mode': 'activate_very_immediate'}
        self.assertRaises(ValidationError, testFunc, testDict)
        self.check_last_is_null()

    def test_activation_object_parsing_okay_immediate(self):
        """Test activation object for immediate activation"""
        testFunc = self.dut.parseActivationObject
        testDict = {'mode': 'activate_immediate'}
        currentTime = self.dut._getCurrentTime()
        returned = testFunc(testDict)
        self.verify_against_schema(returned[1])
        returnedTime = Timestamp.from_sec_nsec(returned[1]['activation_time'])
        self.assertAlmostEqual(float(currentTime.to_sec_frac()),
                               float(returnedTime.to_sec_frac()), 2)
        self.assertEqual(returned[1]['requested_time'], None)
        self.assertEqual(returned[1]['mode'], "activate_immediate")
        self.assertTrue(self.hadCallback)
        self.assertEqual(self.callbackCaller, "activateStaged")
        self.check_last_is_null()

    def test_activation_object_parsing_okay_immediate_null_time(self):
        """Test activation object for immediate activation"""
        testFunc = self.dut.parseActivationObject
        testDict = {'mode': 'activate_immediate', 'requested_time': None}
        currentTime = self.dut._getCurrentTime()
        returned = testFunc(testDict)
        self.verify_against_schema(returned[1])
        returnedTime = Timestamp.from_sec_nsec(returned[1]['activation_time'])
        self.assertAlmostEqual(float(currentTime.to_sec_frac()),
                               float(returnedTime.to_sec_frac()), 2)
        self.assertEqual(returned[1]['requested_time'], None)
        self.assertEqual(returned[1]['mode'], "activate_immediate")
        self.assertTrue(self.hadCallback)
        self.assertEqual(self.callbackCaller, "activateStaged")
        self.check_last_is_null()

    def test_activation_object_parsing_missing_time(self):
        """Test activation object parser when time is missing"""
        testFunc = self.dut.parseActivationObject
        testDict = {'mode': 'activate_scheduled_absolute'}
        self.assertRaises(ValidationError, testFunc, [testDict])
        testDict = {'mode': 'activate_scheduled_relative'}
        self.assertRaises(ValidationError, testFunc, [testDict])

    def test_activation_object_parsing_scheduled_relative(self):
        """Test activation object parser for OK relative scheduling"""
        testFunc = self.dut.parseActivationObject
        testDict = {'mode': 'activate_scheduled_relative',
                    'requested_time': '12345:12345'}
        # monkey patch in a test function
        self.dut._scheduleRelative = self.mockCallback
        okay = {"test": "ok"}
        self.assertEqual(testFunc(testDict), okay)
        self.assertTrue(self.hadCallback)
        self.assertEqual(self.callbackArgs[0], "12345:12345")
        self.check_last_is_null()

    def test_activation_object_parsing_scheduled_absolute(self):
        """Test activation object parser for OK absolute scheduling"""
        testFunc = self.dut.parseActivationObject
        testDict = {'mode': 'activate_scheduled_absolute',
                    'requested_time': '12345:12345'}
        # monkey patch in test function
        self.dut._scheduleAbsolute = self.mockCallback
        okay = {"test": "ok"}
        self.assertEqual(testFunc(testDict), okay)
        self.assertTrue(self.hadCallback)
        self.assertEqual(self.callbackArgs[0], "12345:12345")
        self.check_last_is_null()

    def test_time_string_parser(self):
        """Test the TAI time string parser"""
        testFunc = self.dut._parseTimeString
        # Test string with no :
        testString = "Thishasnocolon"
        self.assertRaises(FieldException, testFunc, testString)
        # Test string with : but no ints
        testString = "has:colon"
        self.assertRaises(FieldException, testFunc, testString)
        # Test with valid time stamp
        testString = "12345:12345"
        expected = [12345, 12345]
        actual = testFunc(testString)
        self.assertEqual(expected, actual)

    # Note: Some of the following tests rely on time().time() being
    # called repeatedly in quick succession. On slow systems it may
    # be nesisarry to reduce the precision of assertAlmostEqual before
    # the test can pass

    def test_get_current_time(self):
        """Test the classes ability to work out the time"""
        # This test should not be run during a leap second...
        testFunc = self.dut._getCurrentTime
        expected = time.time()
        response = testFunc().to_utc()
        actual = float(str(response[0]) + "." + str(response[1]).zfill(9))
        self.assertAlmostEqual(actual, expected, 0)

    def test_schedule_absolute(self):
        """Test absolute scheduling function"""
        testFunc = self.dut._scheduleAbsolute
        offset = 7
        myTime = time.time() + offset
        secs = int(myTime)
        nanos = int((myTime - secs) * 1e9)
        ippTime = Timestamp.from_utc(secs, nanos)
        # monkey patch in test function
        self.dut._scheduleActivation = self.mockCallback
        ret = testFunc(str(ippTime))
        self.verify_against_schema(ret[1])
        mode = ret[1]['mode']
        sched = Timestamp.from_sec_nsec(
            ret[1]['activation_time'])
        self.verify_against_schema(ret[1])
        self.assertEqual(202, ret[0])
        self.assertEqual(mode, "activate_scheduled_absolute")
        self.assertAlmostEqual(float(sched.to_sec_frac()),
                               float(ippTime.to_sec_frac()), 2)
        self.assertTrue(self.hadCallback)
        self.assertAlmostEqual(offset,
                               float(self.callbackArgs[0].to_sec_frac()), 2)
        self.assertEqual(self.dut.getLastRequest(), ret[1])

    def test_schedule_relative_callback(self):
        """Test relative scheduling function"""
        testFunc = self.dut._scheduleRelative
        # monkey patch in test function
        self.dut._scheduleActivation = self.mockCallback
        testFunc("2:0")
        self.assertTrue(self.hadCallback)
        self.assertEqual(2, float(self.callbackArgs[0].to_sec_frac()))

    def test_schedule_relative_return(self):
        """Test relative scheduling function"""
        testFunc = self.dut._scheduleRelative
        ret = testFunc("2:0")
        utc = time.time() + 2.0
        secs = int(utc)
        nanos = (utc - secs) * 1e9
        ippTime = Timestamp.from_utc(secs, nanos)
        sched = Timestamp.from_sec_nsec(
            ret[1]['activation_time'])
        mode = ret[1]['mode']
        code = ret[0]
        self.verify_against_schema(ret[1])
        self.assertEqual(202, ret[0])
        self.assertEqual(mode, "activate_scheduled_relative")
        self.assertAlmostEqual(float(sched.to_sec_frac()),
                               float(ippTime.to_sec_frac()), 2)
        self.assertEqual(code, 202)
        self.assertEqual(ret[1], self.dut.getLastRequest())

    def test_activate_none(self):
        """Test cancelling scheduled activations"""
        testFunc = self.dut._scheduleNone
        self.dut.timer = MockTimer()
        self.dut.scheduled = True
        ret = testFunc()
        self.assertEqual(ret[0], 200)
        self.verify_against_schema(ret[1])
        self.assertFalse(self.dut.scheduled)
        self.assertTrue(self.dut.timer.cancelled)
        self.check_last_is_null()

    def test_schedule_activation(self):
        """Test setting up a delayed activation -
        this test will block for two seconds"""
        testFunc = self.dut._scheduleRelative
        testTime = TimeOffset(1, 0)
        # monkey patch in test function
        self.api.activateStaged = self.mockApiCallback
        ret = testFunc(testTime)
        self.assertTrue(self.api.locked)
        startTime = time.time()
        print("Sleeping for 1.1 seconds")
        time.sleep(1.1)
        self.assertTrue(self.hadCallback)
        diff = self.callbackTime - startTime
        self.assertAlmostEqual(1, diff, 2)
        self.assertFalse(self.api.locked)
        self.assertEqual(ret[0], 202)
        self.verify_against_schema(ret[1])
        self.check_last_is_null()

    def test_schema(self):
        """Checks that the correct JSON schema is returned"""
        schema = '../share/ipp-connectionmanagement/schemas/v1.0-activate-schema.json'
        schemaPath = os.path.join(__location__,
                                  schema)
        with open(schemaPath) as test:
            expected = json.loads(test.read())
            actual = self.dut._getSchema()
            self.assertEqual(expected, actual)

    def test_get_last_request(self):
        """Checks that the last request function returns the
        correct property"""
        testObj = {"test": "test"}
        self.dut.lastRequest = testObj
        self.assertEqual(self.dut.getLastRequest(), testObj)

    def test_move_to_active(self):
        """Checks that requests are moved to active from lastRequest
        on activation"""
        self.dut.lastRequest['mode'] = "testMode"
        self.dut.lastRequest['activation_time'] = "5:0"
        self.dut.moveToActive()
        self.assertEqual(self.dut.activeRequest['mode'], "testMode")
        self.assertEqual(self.dut.activeRequest['activation_time'], "5:0")
        self.check_last_is_null()
