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

import struct
from typing import Any, Dict, List, Optional

from volatility.framework import interfaces, constants
from volatility.framework.configuration import requirements
from volatility.framework.layers import physical, segmented, resources
from volatility.framework.symbols import native


class VmwareLayer(segmented.SegmentedLayer):
    priority = 22

    header_structure = "<4sII"
    group_structure = "64sQQ"

    def __init__(self,
                 context: interfaces.context.ContextInterface,
                 config_path: str,
                 name: str,
                 metadata: Optional[Dict[str, Any]] = None) -> None:
        # Construct these so we can use self.config
        self._context = context
        self._config_path = config_path
        self._page_size = 0x1000
        self._base_layer, self._meta_layer = self.config["base_layer"], self.config["meta_layer"]
        # Then call the super, which will call load_segments (which needs the base_layer before it'll work)
        super().__init__(context, config_path = config_path, name = name, metadata = metadata)

    def _load_segments(self) -> None:
        """Loads up the segments from the meta_layer"""
        self._read_header()

    def _read_header(self) -> None:
        """Checks the vmware header to make sure it's valid"""
        if "vmware" not in self._context.symbol_space:
            self._context.symbol_space.append(native.NativeTable("vmware", native.std_ctypes))

        meta_layer = self.context.memory.get(self._meta_layer, None)
        header_size = struct.calcsize(self.header_structure)
        data = meta_layer.read(0, header_size)
        magic, unknown, groupCount = struct.unpack(self.header_structure, data)
        if magic not in [b"\xD2\xBE\xD2\xBE"]:
            raise ValueError("Wrong magic bytes for Vmware layer: {}".format(repr(magic)))

        # TODO: Change certain structure sizes based on the version
        version = magic[1] & 0xf

        group_size = struct.calcsize(self.group_structure)

        groups = {}
        for group in range(groupCount):
            name, tag_location, _unknown = struct.unpack(
                self.group_structure, meta_layer.read(header_size + (group * group_size), group_size))
            name = name.rstrip(b"\x00")
            groups[name] = tag_location
        memory = groups[b"memory"]

        tags_read = False
        offset = memory
        tags = {}
        index_len = self._context.symbol_space.get_type("vmware!unsigned int").size
        while not tags_read:
            flags = ord(meta_layer.read(offset, 1))
            name_len = ord(meta_layer.read(offset + 1, 1))
            tags_read = (flags == 0) and (name_len == 0)
            if not tags_read:
                name = self._context.object(
                    "vmware!string", layer_name = self._meta_layer, offset = offset + 2, max_length = name_len)
                indicies_len = (flags >> 6) & 3
                indicies = []
                for index in range(indicies_len):
                    indicies.append(
                        self._context.object(
                            "vmware!unsigned int",
                            offset = offset + name_len + 2 + (index * index_len),
                            layer_name = self._meta_layer))
                data = self._context.object(
                    "vmware!unsigned int",
                    layer_name = self._meta_layer,
                    offset = offset + 2 + name_len + (indicies_len * index_len))
                tags[(name, tuple(indicies))] = (flags, data)
                offset += 2 + name_len + (
                    indicies_len * index_len) + self._context.symbol_space.get_type("vmware!unsigned int").size

        if tags[("regionsCount", ())][1] == 0:
            raise ValueError("VMware VMEM is not split into regions")
        for region in range(tags[("regionsCount", ())][1]):
            offset = tags[("regionPPN", (region, ))][1] * self._page_size
            mapped_offset = tags[("regionPageNum", (region, ))][1] * self._page_size
            length = tags[("regionSize", (region, ))][1] * self._page_size
            self._segments.append((offset, mapped_offset, length))

    @property
    def dependencies(self) -> List[str]:
        return [self._base_layer, self._meta_layer]

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        """This vmware translation layer always requires a separate metadata layer"""
        return [
            requirements.TranslationLayerRequirement(name = 'base_layer', optional = False),
            requirements.TranslationLayerRequirement(name = 'meta_layer', optional = False)
        ]


class VmwareStacker(interfaces.automagic.StackerLayerInterface):

    @classmethod
    def stack(cls,
              context: interfaces.context.ContextInterface,
              layer_name: str,
              progress_callback: constants.ProgressCallback = None) -> Optional[interfaces.layers.DataLayerInterface]:
        """Attempt to stack this based on the starting information"""
        memlayer = context.memory[layer_name]
        if not isinstance(memlayer, physical.FileLayer):
            return None
        location = memlayer.location
        if location.endswith(".vmem"):
            vmss = location[:-5] + ".vmss"
            vmsn = location[:-5] + ".vmsn"
            current_layer_name = context.memory.free_layer_name("VmwareMetaLayer")
            current_config_path = interfaces.configuration.path_join("automagic", "layer_stacker", "stack",
                                                                     current_layer_name)

            try:
                _ = resources.ResourceAccessor().open(vmss).read(10)
                context.config[interfaces.configuration.path_join(current_config_path, "location")] = vmss
                context.memory.add_layer(physical.FileLayer(context, current_config_path, current_layer_name))
                vmss_success = True
            except IOError:
                vmss_success = False

            if not vmss_success:
                try:
                    _ = resources.ResourceAccessor().open(vmsn).read(10)
                    context.config[interfaces.configuration.path_join(current_config_path, "location")] = vmsn
                    context.memory.add_layer(physical.FileLayer(context, current_config_path, current_layer_name))
                    vmsn_success = True
                except IOError:
                    vmsn_success = False

            if not vmss_success and not vmsn_success:
                return None
            new_layer_name = context.memory.free_layer_name("VmwareLayer")
            context.config[interfaces.configuration.path_join(current_config_path, "base_layer")] = layer_name
            context.config[interfaces.configuration.path_join(current_config_path, "meta_layer")] = current_layer_name
            new_layer = VmwareLayer(context, current_config_path, new_layer_name)
            return new_layer
        return None
