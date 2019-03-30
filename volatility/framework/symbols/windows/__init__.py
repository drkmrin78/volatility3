# This file was contributed to the Volatility Framework Version 3.
# Copyright (C) 2018 Volatility Foundation.
#
# THE LICENSED WORK IS PROVIDED UNDER THE TERMS OF THE Volatility Contributors
# Public License V1.0("LICENSE") AS FIRST COMPLETED BY: Volatility Foundation,
# Inc. ANY USE, PUBLIC DISPLAY, PUBLIC PERFORMANCE, REPRODUCTION OR DISTRIBUTION
# OF, OR PREPARATION OF SUBSEQUENT WORKS, DERIVATIVE WORKS OR DERIVED WORKS BASED
# ON, THE LICENSED WORK CONSTITUTES RECIPIENT'S ACCEPTANCE OF THIS LICENSE AND ITS
# TERMS, WHETHER OR NOT SUCH RECIPIENT READS THE TERMS OF THE LICENSE. "LICENSED
# WORK,” “RECIPIENT" AND “DISTRIBUTOR" ARE DEFINED IN THE LICENSE. A COPY OF THE
# LICENSE IS LOCATED IN THE TEXT FILE ENTITLED "LICENSE.txt" ACCOMPANYING THE
# CONTENTS OF THIS FILE. IF A COPY OF THE LICENSE DOES NOT ACCOMPANY THIS FILE, A
# COPY OF THE LICENSE MAY ALSO BE OBTAINED AT THE FOLLOWING WEB SITE:
# https://www.volatilityfoundation.org/license/vcpl_v1.0
#
# Software distributed under the License is distributed on an "AS IS" basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License for the
# specific language governing rights and limitations under the License.
#

from volatility.framework import interfaces
from volatility.framework.symbols import intermed
from volatility.framework.symbols.windows import extensions
from volatility.framework.symbols.windows.extensions import registry


class WindowsKernelIntermedSymbols(intermed.IntermediateSymbolTable):

    def __init__(self, context: interfaces.context.ContextInterface, config_path: str, name: str, isf_url: str) -> None:
        super().__init__(context = context, config_path = config_path, name = name, isf_url = isf_url)

        # Set-up windows specific types
        self.set_type_class('_ETHREAD', extensions._ETHREAD)
        self.set_type_class('_LIST_ENTRY', extensions._LIST_ENTRY)
        self.set_type_class('_EPROCESS', extensions._EPROCESS)
        self.set_type_class('_UNICODE_STRING', extensions._UNICODE_STRING)
        self.set_type_class('_EX_FAST_REF', extensions._EX_FAST_REF)
        self.set_type_class('_OBJECT_HEADER', extensions._OBJECT_HEADER)
        self.set_type_class('_FILE_OBJECT', extensions._FILE_OBJECT)
        self.set_type_class('_DEVICE_OBJECT', extensions._DEVICE_OBJECT)
        self.set_type_class('_CM_KEY_BODY', registry._CM_KEY_BODY)
        self.set_type_class('_CMHIVE', registry._CMHIVE)
        self.set_type_class('_CM_KEY_NODE', registry._CM_KEY_NODE)
        self.set_type_class('_CM_KEY_VALUE', registry._CM_KEY_VALUE)
        self.set_type_class('_HMAP_ENTRY', registry._HMAP_ENTRY)
        self.set_type_class('_MMVAD_SHORT', extensions._MMVAD_SHORT)
        self.set_type_class('_MMVAD', extensions._MMVAD)
        self.set_type_class('_KSYSTEM_TIME', extensions._KSYSTEM_TIME)
        self.set_type_class('_KMUTANT', extensions._KMUTANT)
        self.set_type_class('_DRIVER_OBJECT', extensions._DRIVER_OBJECT)
        self.set_type_class('_OBJECT_SYMBOLIC_LINK', extensions._OBJECT_SYMBOLIC_LINK)

        # This doesn't exist in very specific versions of windows
        try:
            self.set_type_class('_POOL_HEADER', extensions._POOL_HEADER)
        except ValueError:
            pass

        # these don't exist in windows XP
        try:
            self.set_type_class('_MMADDRESS_NODE', extensions._MMVAD_SHORT)
        except ValueError:
            pass

        # these were introduced starting in windows 8
        try:
            self.set_type_class('_MM_AVL_NODE', extensions._MMVAD_SHORT)
        except ValueError:
            pass

        # these were introduced starting in windows 7
        try:
            self.set_type_class('_RTL_BALANCED_NODE', extensions._MMVAD_SHORT)
        except ValueError:
            pass
