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

class Net_Conns(interfaces_plugins.PluginInterface):
    """Lists the network connections present in a FreeBSD memory image"""

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

    @classmethod # create_filter should be built in? 
    def create_filter(cls, f_list: List[int] = None) -> Callable[[int], bool]:
        # FIXME: mypy #4973 or #2608
        f_list = f_list or []
        filter_list = [x for x in f_list if x is not None]
        if filter_list:
            def filter_func(x):
                return x not in filter_list

            return filter_func
        else:
            return lambda _: False

    @classmethod
    def list_conns(cls,
                   context: interfaces.context.ContextInterface,
                   layer_name: str,
                   freebsd_symbols: str,
                   filter: Callable[[int],bool] = lambda _:False) \
                   -> Iterable[interfaces.objects.ObjectInterface]:
        """List all connections in primary layer"""
        view = contexts.Module(context,
                            freebsd_symbols,
                            layer_name,
                            0,
                            absolute_symbol_addresses=True)
        #probably going to need other symbols too
        ripcbinfo = view.object(symbol_name = "ripcbinfo").cast("inpcbinfo")
        inpcb = ripcbinfo.ipi_listhead.dereference().lh_first.dereference()
        
        while inpcb is not None and inpcb.vol.offset != 0:
            yield inpcb.cast("inpcb")
            inpcb = inpcb.inp_list.le_next.dereference()



    def _generator(self):
        """Produces all connections after filtering"""
        for conn in self.list_conns(
                self.context,
                self.config['primary'],
                self.config['freebsd'],
                #TODO: change pid
                filter = self.create_filter([self.config.get('pid', None)])):
            proto = 'TEST'
            l_host = conn.inp_inc.inc_ie.ie_dependladdr.ie46_local.ia46_addr4.s_addr
            l_port = conn.inp_inc.inc_ie.ie_lport
            r_host = conn.inp_inc.inc_ie.ie_dependfaddr.ie46_foreign.ia46_addr4.s_addr
            r_port = conn.inp_inc.inc_ie.ie_fport
            yield (0,(proto, l_host, l_port, r_host, r_port))


    def run(self):
        """Entry point for plugin"""
        #TODO: PPID of processes that own the connection?
        return renderers.TreeGrid(
                [("PROT", str), ("L_IP", int), ("LPORT", int),
                    ("R_IP", int),("RPORT", int)], 
                self._generator())
