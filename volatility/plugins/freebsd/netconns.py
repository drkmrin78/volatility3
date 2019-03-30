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

class NetConns(interfaces_plugins.PluginInterface):
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

    @classmethod
    def list_conns(cls,
                   context: interfaces.context.ContextInterface,
                   layer_name: str,
                   freebsd_symbols: str)\
                   -> Iterable[interfaces.objects.ObjectInterface]:
        """List all connections in primary layer"""
        view = contexts.Module(context,
                            freebsd_symbols,
                            layer_name,
                            0,
                            absolute_symbol_addresses=True)

        ripcbinfo = view.object(symbol_name = "ripcbinfo").cast("inpcbinfo")
        tcbinfo = view.object(symbol_name = "tcbinfo").cast("inpcbinfo")
        udbinfo = view.object(symbol_name = "udbinfo").cast("inpcbinfo")
        
        for inpcbinfo in [tcbinfo, udbinfo, ripcbinfo]: 
            inpcb = inpcbinfo.ipi_listhead.dereference().lh_first.dereference()
            
            if inpcbinfo is tcbinfo:
                proto = "TCP"
            elif inpcbinfo is udbinfo:
                proto = "UDP"
            else:
                proto = "RAW"

            while inpcb is not None and inpcb.vol.offset != 0:        
                yield (inpcb.cast("inpcb"),proto)
                inpcb = inpcb.inp_list.le_next.dereference()
    
    def _itoip(self,ip):
        return '.'.join( [ str((ip >> 8*i) % 256)  for i in range(0,4) ])

    def _bigToLittle(self, x, size):
        return int.from_bytes(((x).to_bytes(size, byteorder='big')), byteorder='little')
    
    def _flagsToString(self, bits, pairs):
        ret = ""
        for bit,value in pairs.items():
            if bits & bit > 0:
                ret += value + ", "
        return ret[:len(ret)-2]

    def _getSocketOptions(self, socket):
        options = {
                    0x1: "DEBUG",
                    0x2: "ACCEPTCONN",
                    0x4: "REUSEADDR",
                    0x8: "KEEPALIVE",
                   0x10: "DONTROUTE",
                   0x20: "BROADCAST",
                   0x40: "USELOOPBACK",
                   0x80: "LINGER",
                  0x100: "OOBINLINE",
                  0x200: "REUSEPORT",
                  0x400: "TIMESTAMP",
                  0x800: "NOSIGPIPE",
                 0x1000: "ACCEPTFILTER",
                 0x2000: "BINTIME",
                 0x4000: "NO_OFFLOAD",
                 0x8000: "NO_DDP",
                0x10000: "REUSEPORT_LB"
                }
        return self._flagsToString(socket.so_options, options)
    
    def _getSocketState(self, socket):
        states = {
                    0x1: "NOFDREF",
                    0x2: "ISCONNECTED",
                    0x4: "ISCONNECTING",
                    0x8: "ISDISCONNECTING",
                   0x10: "UNK(0x10)",
                   0x20: "UNK(0x20)",
                   0x40: "UNK(0x40)",
                   0x80: "UNK(0x80)",
                  0x100: "NBIO",
                  0x200: "ASYNC",
                  0x400: "ISCONFIRMING",
                  0x800: "ISDISCONNECTED",
                 0x1000: "UNK(0x1000)",
                 0x2000: "UNK(0x2000)",
                 0x4000: "UNK(0x2000)"
                }
        return self._flagsToString(socket.so_state, states)


    def _generator(self):
        """Produces all connections after filtering"""
        for (conn,proto) in self.list_conns(
                self.context,
                self.config['primary'],
                self.config['freebsd']):

            #FreeBSD 11.2 
            l_host = conn.inp_inc.inc_ie.ie_dependladdr.ie46_local.ia46_addr4.s_addr
            l_port = self._bigToLittle(conn.inp_inc.inc_ie.ie_lport,2)
            r_host = conn.inp_inc.inc_ie.ie_dependfaddr.ie46_foreign.ia46_addr4.s_addr
            r_port = self._bigToLittle(conn.inp_inc.inc_ie.ie_fport, 2)
           
            options = ""
            state = ""
            #Find State information
            if proto is "TCP" and conn.inp_socket != 0:
                sock = conn.inp_socket.dereference()
                options = self._getSocketOptions(sock);
                state = self._getSocketState(sock);

            yield (0,(proto, self._itoip(l_host), l_port, 
                             self._itoip(r_host), r_port, state, options))

    def run(self):
        """Entry point for plugin"""
        return renderers.TreeGrid(
                [("PROT", str), ("L_HOST", str), ("LPORT", int),
                    ("R_HOST", str),("RPORT", int), 
                    ("STATE", str), ("OPTIONS", str)], 
                self._generator())
