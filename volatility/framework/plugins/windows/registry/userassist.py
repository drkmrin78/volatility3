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

import codecs
import datetime
import json
import logging
import os
from typing import Any, List, Tuple

from volatility.framework import exceptions, renderers, constants, interfaces
from volatility.framework.configuration import requirements
from volatility.framework.layers.physical import BufferDataLayer
from volatility.framework.layers.registry import RegistryHive
from volatility.framework.renderers import format_hints, conversion
from volatility.framework.symbols import intermed

vollog = logging.getLogger(__name__)


class UserAssist(interfaces.plugins.PluginInterface):
    """Print userassist registry keys and information"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._userassist_size = 0
        self._userassist_type_name = "_VOL_USERASSIST_TYPES_7"
        self._reg_table_name = None
        self._win7 = None
        # taken from http://msdn.microsoft.com/en-us/library/dd378457%28v=vs.85%29.aspx
        self._folder_guids = json.load(open(os.path.join(os.path.dirname(__file__), "userassist.json"), "rb"))

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.TranslationLayerRequirement(
                name = 'primary', description = 'Memory layer for the kernel', architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "nt_symbols", description = "Windows kernel symbols"),
            requirements.IntRequirement(name = 'offset', description = "Hive Offset", default = None, optional = True)
        ]

    def parse_userassist_data(self, reg_val):
        """Reads the raw data of a _CM_KEY_VALUE and returns a dict of userassist fields"""

        item = {
            "id": renderers.UnparsableValue(),
            "count": renderers.UnparsableValue(),
            "focus": renderers.UnparsableValue(),
            "time": renderers.UnparsableValue(),
            "lastupdated": renderers.UnparsableValue(),
            "rawdata": renderers.UnparsableValue(),
        }

        userassist_data = reg_val.decode_data()

        if userassist_data is None:
            return item

        item["rawdata"] = userassist_data

        if self._win7 is None:
            # if OS is still unknown at this point, return the default item which just has the rawdata
            return item

        if len(userassist_data) < self._userassist_size:
            return item

        userassist_layer_name = self.context.memory.free_layer_name("userassist_buffer")
        buffer = BufferDataLayer(self.context, self._config_path, userassist_layer_name, userassist_data)
        self.context.add_layer(buffer)
        userassist_obj = self.context.object(
            symbol = self._reg_table_name + constants.BANG + self._userassist_type_name,
            layer_name = userassist_layer_name,
            offset = 0)

        if self._win7:
            item["id"] = renderers.NotApplicableValue()
            item["count"] = int(userassist_obj.Count)

            seconds = (userassist_obj.FocusTime + 500) / 1000.0
            time = datetime.timedelta(seconds = seconds) if seconds > 0 else userassist_obj.FocusTime
            item["focus"] = int(userassist_obj.FocusCount)
            item["time"] = str(time)

        else:
            item["id"] = int(userassist_obj.ID)
            item["count"] = int(userassist_obj.CountStartingAtFive
                                if userassist_obj.CountStartingAtFive < 5 else userassist_obj.CountStartingAtFive - 5)
            item["focus"] = renderers.NotApplicableValue()
            item["time"] = renderers.NotApplicableValue()

        item["lastupdated"] = conversion.wintime_to_datetime(userassist_obj.LastUpdated.QuadPart)

        return item

    def _determine_userassist_type(self) -> None:
        """Determine the userassist type and size depending on the OS version"""

        if self._win7 is True:
            self._userassist_type_name = "_VOL_USERASSIST_TYPES_7"
        elif self._win7 is False:
            self._userassist_type_name = "_VOL_USERASSIST_TYPES_XP"

        self._userassist_size = self.context.symbol_space.get_type(self._reg_table_name + constants.BANG +
                                                                   self._userassist_type_name).size

    def _win7_or_later(self) -> bool:
        # TODO: change this if there is a better way of determining the OS version
        # _KUSER_SHARED_DATA.CookiePad is in Windows 6.1 (Win7) and later
        return self.context.symbol_space.get_type(self.config['nt_symbols'] + constants.BANG +
                                                  "_KUSER_SHARED_DATA").has_member('CookiePad')

    def list_userassist(self, hive: RegistryHive):
        """Generate userassist data for a registry hive."""

        hive_name = hive.hive.cast(self.config["nt_symbols"] + constants.BANG + "_CMHIVE").get_name()

        if self._win7 is None:
            try:
                self._win7 = self._win7_or_later()
            except exceptions.SymbolError:
                # self._win7 will be None and only registry value rawdata will be output
                pass

        self._determine_userassist_type()

        userassist_node_path = hive.get_key(
            "software\\microsoft\\windows\\currentversion\\explorer\\userassist", return_list = True)

        if not userassist_node_path:
            vollog.warning("list_userassist did not find a valid node_path (or None)")
            return

        userassist_node = userassist_node_path[-1]
        # iterate through the GUIDs under the userassist key
        for guidkey in userassist_node.get_subkeys():
            # each guid key should have a Count key in it
            for countkey in guidkey.get_subkeys():
                countkey_path = countkey.get_key_path()
                countkey_last_write_time = conversion.wintime_to_datetime(countkey.LastWriteTime.QuadPart)

                # output the parent Count key
                result = (
                    0, (renderers.format_hints.Hex(hive.hive_offset), hive_name, countkey_path,
                        countkey_last_write_time, "Key", renderers.NotApplicableValue(), renderers.NotApplicableValue(),
                        renderers.NotApplicableValue(), renderers.NotApplicableValue(), renderers.NotApplicableValue(),
                        renderers.NotApplicableValue(), renderers.NotApplicableValue())
                )  # type: Tuple[int, Tuple[format_hints.Hex, Any, Any, Any, Any, Any, Any, Any, Any, Any, Any, Any]]
                yield result

                # output any subkeys under Count
                for subkey in countkey.get_subkeys():

                    subkey_name = subkey.get_name()
                    result = (1, (
                        renderers.format_hints.Hex(hive.hive_offset),
                        hive_name,
                        countkey_path,
                        countkey_last_write_time,
                        "Subkey",
                        subkey_name,
                        renderers.NotApplicableValue(),
                        renderers.NotApplicableValue(),
                        renderers.NotApplicableValue(),
                        renderers.NotApplicableValue(),
                        renderers.NotApplicableValue(),
                        renderers.NotApplicableValue(),
                    ))
                    yield result

                # output any values under Count
                for value in countkey.get_values():

                    value_name = value.get_name()
                    try:
                        value_name = codecs.encode(value_name, "rot_13")
                    except UnicodeDecodeError:
                        pass

                    if self._win7:
                        guid = value_name.split("\\")[0]
                        if guid in self._folder_guids:
                            value_name = value_name.replace(guid, self._folder_guids[guid])

                    userassist_data_dict = self.parse_userassist_data(value)
                    result = (1, (
                        renderers.format_hints.Hex(hive.hive_offset),
                        hive_name,
                        countkey_path,
                        countkey_last_write_time,
                        "Value",
                        value_name,
                        userassist_data_dict["id"],
                        userassist_data_dict["count"],
                        userassist_data_dict["focus"],
                        userassist_data_dict["time"],
                        userassist_data_dict["lastupdated"],
                        format_hints.HexBytes(userassist_data_dict["rawdata"]),
                    ))
                    yield result

    def _generator(self):

        # get all the user hive offsets or use the one specified
        if self.config.get('offset', None) is None:
            try:
                import volatility.plugins.windows.registry.hivelist as hivelist
                hive_offsets = [
                    hive.vol.offset for hive in hivelist.HiveList.list_hives(
                        context = self.context,
                        layer_name = self.config['primary'],
                        symbol_table = self.config['nt_symbols'],
                        filter_string = "ntuser.dat")
                ]
            except ImportError:
                vollog.warning("Unable to import windows.hivelist plugin, please provide a hive offset")
                raise ValueError("Unable to import windows.hivelist plugin, please provide a hive offset")
        else:
            hive_offsets = [self.config['offset']]

        self._reg_table_name = intermed.IntermediateSymbolTable.create(self.context, self._config_path, 'windows',
                                                                       'registry')

        for hive_offset in hive_offsets:
            # Construct the hive
            reg_config_path = self.make_subconfig(
                hive_offset = hive_offset, base_layer = self.config['primary'], nt_symbols = self.config['nt_symbols'])

            hive_name = None
            try:
                hive = RegistryHive(self.context, reg_config_path, name = 'hive' + hex(hive_offset))
                hive_name = hive.hive.cast(self.config["nt_symbols"] + constants.BANG + "_CMHIVE").get_name()
                self.context.memory.add_layer(hive)
                yield from self.list_userassist(hive)
                continue
            except exceptions.PagedInvalidAddressException as excp:
                vollog.debug("Invalid address identified in Hive: {}".format(hex(excp.invalid_address)))
            except KeyError:
                vollog.debug("Key '{}' not found in Hive at offset {}.".format(
                    "software\\microsoft\\windows\\currentversion\\explorer\\userassist", hex(hive_offset)))

            # yield UnreadableValues when an exception occurs for a given hive_offset
            result = (0, (renderers.format_hints.Hex(hive_offset),
                          hive_name if hive_name else renderers.UnreadableValue(), renderers.UnreadableValue(),
                          renderers.UnreadableValue(), renderers.UnreadableValue(), renderers.UnreadableValue(),
                          renderers.UnreadableValue(), renderers.UnreadableValue(), renderers.UnreadableValue(),
                          renderers.UnreadableValue(), renderers.UnreadableValue(), renderers.UnreadableValue()))
            yield result

    def run(self):

        return renderers.TreeGrid([("Hive Offset", renderers.format_hints.Hex), ("Hive Name", str), ("Path", str),
                                   ("Last Write Time", datetime.datetime), ("Type", str), ("Name", str), ("ID", int),
                                   ("Count", int), ("Focus Count", int), ("Time Focused", str),
                                   ("Last Updated", datetime.datetime), ("Raw Data", format_hints.HexBytes)],
                                  self._generator())
