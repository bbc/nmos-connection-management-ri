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


class FieldException(Exception):

    def __init__(self, message, field="", tpIndex=0):
        super(FieldException, self).__init__(message)
        self.field = field
        self.tpIndex = tpIndex

    def getJson(self, tp=True, status=True, message=True):
        toReturn = {}
        if self.field != "":
            toReturn['field'] = self.field
        if tp:
            toReturn['transport_param_index'] = self.tpIndex
        if status:
            toReturn['status'] = "Error"
        if message:
            toReturn['message'] = str(self)
        return toReturn
