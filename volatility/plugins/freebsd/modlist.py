# This file was contributed to the Volatility Framework Version 2.
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

from typing import Callable, Iterable, List

import volatility.framework.interfaces.plugins as interfaces_plugins
from volatility.framework import renderers, interfaces, contexts
from volatility.framework.automagic import freebsd #FreeBSD automagic not implemented
from volatility.framework.configuration import requirements
from volatility.framework.objects import utility

class ModList(interfaces_plugins.PluginInterface):
    """Lists the modules present in a FreeBSD memory image"""

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        """Returns a list of requirement to satisfy executing the plugin"""
        return [requirements.TranslationLayerRequirement(
                    name = 'primary',
                    description = "Memory layer for the kernel",
                    architectures = ['Intel32', 'Intel64']),
                requirements.SymbolTableRequirement(
                   name = 'freebsd',
                   description = "FreeBSD kernel Symbols")
            ]

    @classmethod
    def list_modules(cls,
                     context: interfaces.context.ContextInterface,
                     layer_name: str,
                     freebsd_symbols: str)\
                     -> Iterable[interfaces.objects.ObjectInterface]:
        """List all Modules in primary layer"""

        view = contexts.Module(context,
                               freebsd_symbols,
                               layer_name,
                               0,
                               absolute_symbol_addresses=True)

        modules = view.object(symbol_name = "modules").cast("modulelist")
        module = modules.tqh_first.dereference()

        while module is not None and module.vol.offset != 0:
            yield module.cast("module")
            module = module.link.tqe_next.dereference()

    def _generator(self):
        for mod in self.list_modules(
                self.context,
                self.config['primary'],
                self.config['freebsd']):

            name = utility.pointer_to_string(mod.name, 40)
            idnum = mod.id
            filepath = utility.pointer_to_string(mod.file.dereference().filename, 80)
            refs = mod.refs

            yield (0, (idnum, name, refs, filepath))

    def run(self):
        """Entry point for plugin"""
        return renderers.TreeGrid([("ID", int), ("MODULE",str), 
            ("REFS", int), ("FILEPATH", str)], self._generator())
