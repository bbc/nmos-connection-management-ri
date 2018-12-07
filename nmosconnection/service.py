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

"""@package service

Top level for the connection management API when running in stand-alone mode.
Starts an instance of the HTTP server and loads the API into it.
Manages a graceful shutdown on SIGINT, SIGTERM
"""

import signal
import gevent

from nmoscommon.httpserver import HttpServer
from api import ConnectionManagementAPI, QUERY_APINAME, QUERY_APIVERSION, DEVICE_ROOT
from nmosDriver import NmosDriver
from constants import WS_PORT


class ConnectionManagementService:

    def __init__(self, logger=None):
        self.running = False
        from nmoscommon.logger import Logger
        from nmoscommon.facade import Facade
        self.logger = Logger("conmanage")
        self.logger.writeWarning("Could not find ipppython facade")
        self.facade = Facade("{}/{}".format(QUERY_APINAME, QUERY_APIVERSION),
                             address="ipc:///tmp/ips-nodefacade", logger=self.logger)
        self.logger.writeDebug("Running Connection Management Service")
        self.httpServer = HttpServer(ConnectionManagementAPI, WS_PORT,
                                     '0.0.0.0', api_args=[self.logger])

    def start(self):
        '''Call this to run the API without blocking'''
        if self.running:
            gevent.signal(signal.SIGINT, self.sig_handler)
            gevent.signal(signal.SIGTERM, self.sig_handler)

        self.running = True

        self.httpServer.start()

        while not self.httpServer.started.is_set():
            self.logger.writeDebug('Waiting for httpserver to start...')
            self.httpServer.started.wait()

        if self.httpServer.failed is not None:
            raise self.httpServer.failed

        self.logger.writeDebug("Running on port: {}"
                               .format(self.httpServer.port))

        self.facade.register_service("http://127.0.0.1:{}".format(self.httpServer.port), DEVICE_ROOT[1:])
        try:
            from nmosconnectiondriver.httpIpstudioDriver import httpIpstudioDriver
            self.logger.writeInfo("Using ipstudio driver")
            # Start the IPStudio driver
            self.driver = httpIpstudioDriver(
                self.httpServer.api,
                self.logger,
                self.facade
            )
        except ImportError:
            # Start the mock driver
            self.driver = NmosDriver(
                self.httpServer.api,
                self.logger,
                self.facade
            )

    def run(self):
        '''Call this to run the API in keep-alive (blocking) mode'''
        self.running = True
        self.start()
        itercount = 0
        while self.running:
            gevent.sleep(1)
            itercount += 1
            if itercount == 5:
                self.facade.heartbeat_service()
                itercount = 0
        self._cleanup()

    def _cleanup(self):
        self.httpServer.stop()
        self.facade.unregister_service()

    def sig_handler(self):
        self.stop()

    def stop(self):
        '''Gracefully shut down the API'''
        self._cleanup()
        self.running = False


if __name__ == '__main__':
    Service = ConnectionManagementService()
    Service.run()
