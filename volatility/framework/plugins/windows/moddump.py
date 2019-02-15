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

import logging
from typing import List, Generator, Iterable

import volatility.framework.constants as constants
import volatility.framework.exceptions as exceptions
import volatility.framework.interfaces.plugins as interfaces_plugins
import volatility.framework.renderers as renderers
import volatility.plugins.windows.modules as modules
import volatility.plugins.windows.pslist as pslist
from volatility.framework import interfaces
from volatility.framework.configuration import requirements
from volatility.framework.renderers import format_hints
from volatility.framework.symbols.windows.pe import PEIntermedSymbols

vollog = logging.getLogger(__name__)


class ModDump(interfaces_plugins.PluginInterface):
    """Dumps kernel modules"""

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # Reuse the requirements from the plugins we use
        return [
            requirements.TranslationLayerRequirement(
                name = 'primary', description = 'Memory layer for the kernel', architectures = ["Intel32", "Intel64"]),
            requirements.SymbolTableRequirement(name = "nt_symbols", description = "Windows kernel symbols")
        ]

    @classmethod
    def get_session_layers(cls,
                           context: interfaces.context.ContextInterface,
                           layer_name: str,
                           symbol_table: str,
                           pids: List[int] = None) -> Generator[str, None, None]:
        """Build a cache of possible virtual layers, in priority starting with
        the primary/kernel layer. Then keep one layer per session by cycling
        through the process list.

        Returns:
            <list> of layer names
        """
        seen_ids = []  # type: List[interfaces.objects.ObjectInterface]
        filter_func = pslist.PsList.create_filter(pids or [])

        for proc in pslist.PsList.list_processes(
                context = context, layer_name = layer_name, symbol_table = symbol_table, filter_func = filter_func):
            proc_layer_name = proc.add_process_layer()

            try:
                # create the session space object in the process' own layer.
                # not all processes have a valid session pointer.
                session_space = context.object(
                    symbol_table + constants.BANG + "_MM_SESSION_SPACE", layer_name = layer_name, offset = proc.Session)

                if session_space.SessionId in seen_ids:
                    continue

            except exceptions.InvalidAddressException:
                vollog.log(constants.LOGLEVEL_VVV,
                           "Process {} does not have a valid Session".format(proc.UniqueProcessId))
                continue

            # save the layer if we haven't seen the session yet
            seen_ids.append(session_space.SessionId)
            yield proc_layer_name

    @classmethod
    def find_session_layer(cls, context: interfaces.context.ContextInterface, session_layers: Iterable[str],
                           base_address: int):
        """Given a base address and a list of layer names, find a
        layer that can access the specified address.

        Args:
            session_layers: <list> of layer names
            base_address: <int> the base address

        Returns:
            layer name (or None)
        """

        for layer_name in session_layers:
            if context.memory[layer_name].is_valid(base_address):
                return layer_name

        return None

    def _generator(self, mods):

        session_layers = list(self.get_session_layers(self.context, self.config['primary'], self.config['nt_symbols']))
        pe_table_name = PEIntermedSymbols.create(self.context, self.config_path, "windows", "pe")

        for mod in mods:
            try:
                BaseDllName = mod.BaseDllName.get_string()
            except exceptions.InvalidAddressException:
                BaseDllName = renderers.UnreadableValue()

            session_layer_name = self.find_session_layer(self.context, session_layers, mod.DllBase)
            if session_layer_name is None:
                result_text = "Cannot find a viable session layer for {0:#x}".format(mod.DllBase)
            else:
                try:
                    dos_header = self.context.object(
                        pe_table_name + constants.BANG + "_IMAGE_DOS_HEADER",
                        offset = mod.DllBase,
                        layer_name = session_layer_name)

                    filedata = interfaces_plugins.FileInterface("module.{0:#x}.dmp".format(mod.DllBase))

                    for offset, data in dos_header.reconstruct():
                        filedata.data.seek(offset)
                        filedata.data.write(data)

                    self.produce_file(filedata)
                    result_text = "Stored {}".format(filedata.preferred_filename)

                except ValueError:
                    result_text = "PE parsing error"

                except exceptions.SwappedInvalidAddressException as exp:
                    result_text = "Required memory at {0:#x} is inaccessible (swapped)".format(exp.invalid_address)

                except exceptions.InvalidAddressException as exp:
                    result_text = "Required memory at {0:#x} is not valid".format(exp.invalid_address)

            yield (0, (format_hints.Hex(mod.DllBase), BaseDllName, result_text))

    def run(self):

        return renderers.TreeGrid([("Base", format_hints.Hex), ("Name", str), ("Result", str)],
                                  self._generator(
                                      modules.Modules.list_modules(
                                          context = self.context,
                                          layer_name = self.config['primary'],
                                          symbol_table = self.config['nt_symbols'])))
