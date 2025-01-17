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
"""Contains standard Requirement types that all adhere to the :class:`~volatility.framework.interfaces.configuration.RequirementInterface`.

These requirement types allow plugins to request simple information types (such as strings, integers,
etc) as well as indicating what they expect to be in the context (such as particular layers or symboltables).

"""
import abc
import logging
from typing import Any, ClassVar, List, Optional, Type, Dict

from volatility.framework import constants, interfaces
from volatility.framework.interfaces import configuration

vollog = logging.getLogger(__name__)


class MultiRequirement(configuration.RequirementInterface):
    """Class to hold multiple requirements.

       Technically the Interface could handle this, but it's an interface, so this is a concrete implementation.
    """

    def unsatisfied(self, context: configuration.ContextInterface,
                    config_path: str) -> Dict[str, configuration.RequirementInterface]:
        return self.unsatisfied_children(context, config_path)


class BooleanRequirement(configuration.SimpleTypeRequirement):
    """A requirement type that contains a boolean value"""
    # Note, this must be a separate class in order to differentiate between Booleans and other instance requirements


class IntRequirement(configuration.SimpleTypeRequirement):
    """A requirement type that contains a single integer"""
    instance_type = int  # type: ClassVar[Type]


class StringRequirement(configuration.SimpleTypeRequirement):
    """A requirement type that contains a single unicode string"""
    # TODO: Maybe add string length limits?
    instance_type = str  # type: ClassVar[Type]


class URIRequirement(StringRequirement):
    """A requirement type that contains a single unicode string that is a valid URI"""
    # TODO: Maybe a a check that to unsatisfied that the path really is a URL?


class BytesRequirement(configuration.SimpleTypeRequirement):
    """A requirement type that contains a byte string"""
    instance_type = bytes  # type: ClassVar[Type]


class ListRequirement(configuration.RequirementInterface):
    """Allows for a list of a specific type of requirement (all of which must be met for this requirement to be met) to be specified

    This roughly correlates to allowing a number of arguments to follow a command line parameter,
    such as a list of integers or a list of strings.

    It is distinct from a multi-requirement which stores the subrequirements in a dictionary, not a list,
    and does not allow for a dynamic number of values.
    """

    def __init__(self,
                 element_type: Type[configuration.SimpleTypes] = str,
                 max_elements: Optional[int] = 0,
                 min_elements: Optional[int] = None,
                 *args,
                 **kwargs) -> None:
        """Constructs the object

        Args:
            element_type: The (requirement) type of each element within the list
            max_elements; The maximum number of acceptable elements this list can contain
            min_elements: The minimum number of acceptable elements this list can contain
        """
        super().__init__(*args, **kwargs)
        if not issubclass(element_type, configuration.BasicTypes):
            raise TypeError("ListRequirements can only be populated with simple InstanceRequirements")
        self.element_type = element_type  # type: Type
        self.min_elements = min_elements or 0  # type: int
        self.max_elements = max_elements  # type: Optional[int]

    def unsatisfied(self, context: interfaces.context.ContextInterface,
                    config_path: str) -> Dict[str, configuration.RequirementInterface]:
        """Check the types on each of the returned values and their number and then call the element type's check for each one"""
        config_path = configuration.path_join(config_path, self.name)
        default = None
        value = self.config_value(context, config_path, default)
        if not value and self.min_elements > 0:
            vollog.log(constants.LOGLEVEL_V, "ListRequirement Unsatisfied - ListRequirement has non-zero min_elements")
            return {config_path: self}
        if value == default:
            # We need to differentiate between no value and an empty list
            vollog.log(constants.LOGLEVEL_V, "ListRequirement Unsatisfied - Value was not specified")
            return {config_path: self}
        if not isinstance(value, list):
            # TODO: Check this is the correct response for an error
            raise ValueError("Unexpected config value found: {}".format(repr(value)))
        if not (self.min_elements <= len(value)):
            vollog.log(constants.LOGLEVEL_V, "TypeError - Too few values provided to list option.")
            return {config_path: self}
        if self.max_elements and not (len(value) < self.max_elements):
            vollog.log(constants.LOGLEVEL_V, "TypeError - Too many values provided to list option.")
            return {config_path: self}
        if not all([isinstance(element, self.element_type) for element in value]):
            vollog.log(constants.LOGLEVEL_V, "TypeError - At least one element in the list is not of the correct type.")
            return {config_path: self}
        return {}


class ChoiceRequirement(configuration.RequirementInterface):
    """Allows one from a choice of strings"""

    def __init__(self, choices: List[str], *args, **kwargs) -> None:
        """Constructs the object

        Args:
            choices: A list of possible string options that can be chosen from
        """
        super().__init__(*args, **kwargs)
        if not isinstance(choices, list) or any([not isinstance(choice, str) for choice in choices]):
            raise TypeError("ChoiceRequirement takes a list of strings as choices")
        self.choices = choices

    def unsatisfied(self, context: interfaces.context.ContextInterface,
                    config_path: str) -> Dict[str, configuration.RequirementInterface]:
        """Validates the provided value to ensure it is one of the available choices"""
        config_path = configuration.path_join(config_path, self.name)
        value = self.config_value(context, config_path)
        if value not in self.choices:
            vollog.log(constants.LOGLEVEL_V, "ValueError - Value is not within the set of available choices")
            return {config_path: self}
        return {}


class ComplexListRequirement(MultiRequirement, configuration.ConfigurableRequirementInterface, metaclass = abc.ABCMeta):
    """Allows a variable length list of requirements"""

    def unsatisfied(self, context: interfaces.context.ContextInterface,
                    config_path: str) -> Dict[str, configuration.RequirementInterface]:
        """Validates the provided value to ensure it is one of the available choices"""
        config_path = configuration.path_join(config_path, self.name)
        ret_list = super().unsatisfied(context, config_path)
        if ret_list:
            return ret_list
        if (self.config_value(context, config_path, None) is None
                or self.config_value(context, configuration.path_join(config_path, 'number_of_elements'))):
            return {config_path: self}
        return {}

    @classmethod
    def get_requirements(cls) -> List[configuration.RequirementInterface]:
        # This is not optional for the stacker to run, so optional must be marked as False
        return [
            IntRequirement(
                "number_of_elements", description = "Determines how many layers are in this list", optional = False)
        ]

    @abc.abstractmethod
    def construct(self, context: interfaces.context.ContextInterface, config_path: str) -> None:
        """Method for constructing within the context any required elements from subrequirements"""

    @abc.abstractmethod
    def new_requirement(self, index) -> configuration.RequirementInterface:
        """Builds a new requirement based on the specified index"""

    def build_configuration(self, context: interfaces.context.ContextInterface, config_path: str,
                            _: Any) -> configuration.HierarchicalDict:
        result = configuration.HierarchicalDict()
        num_elem_config_path = configuration.path_join(config_path, self.name, 'number_of_elements')
        num_elements = context.config.get(num_elem_config_path, None)
        if num_elements is not None:
            result["number_of_elements"] = num_elements
            for i in range(num_elements):
                req = self.new_requirement(i)
                self.add_requirement(req)
                value_path = configuration.path_join(config_path, self.name, req.name)
                value = context.config.get(value_path, None)
                if value is not None:
                    result.splice(req.name, context.memory[value].build_configuration())
                    result[req.name] = value
        return result


class LayerListRequirement(ComplexListRequirement):
    """Allows a variable length list of layers that must exist """

    def construct(self, context: interfaces.context.ContextInterface, config_path: str) -> None:
        """Method for constructing within the context any required elements from subrequirements"""
        new_config_path = configuration.path_join(config_path, self.name)
        num_layers_path = configuration.path_join(new_config_path, "number_of_elements")
        number_of_layers = context.config[num_layers_path]

        # Build all the layers that can be built
        for i in range(number_of_layers):
            layer_req = self.requirements.get(self.name + str(i), None)
            if layer_req is not None and isinstance(layer_req, TranslationLayerRequirement):
                layer_req.construct(context, new_config_path)

    def new_requirement(self, index) -> configuration.RequirementInterface:
        """Constructs a new requirement based on the specified index"""
        return TranslationLayerRequirement(
            name = self.name + str(index), description = "Layer for swap space", optional = False)


class TranslationLayerRequirement(configuration.ConstructableRequirementInterface,
                                  configuration.ConfigurableRequirementInterface):
    """Class maintaining the limitations on what sort of translation layers are acceptable"""

    def __init__(self,
                 name: str,
                 description: str = None,
                 default: configuration.ConfigSimpleType = None,
                 optional: bool = False,
                 oses: List = None,
                 architectures: List = None) -> None:
        """Constructs a Translation Layer Requirement

        The configuration option's value will be the name of the layer once it exists in the store

        Args:
            name: Name of the configuration requirement
            description: Description of the configuration requirement
            default: A default value (should not be used for TranslationLayers)
            optional: Whether the translation layer is required or not
            oses: A list of valid operating systems which can satisfy this requirement
            architectures: A list of valid architectures which can satisfy this requirement
        """
        if oses is None:
            oses = []
        if architectures is None:
            architectures = []
        self.oses = oses
        self.architectures = architectures
        super().__init__(name, description, default, optional)

    def unsatisfied(self, context: interfaces.context.ContextInterface,
                    config_path: str) -> Dict[str, configuration.RequirementInterface]:
        """Validate that the value is a valid layer name and that the layer adheres to the requirements"""
        config_path = configuration.path_join(config_path, self.name)
        value = self.config_value(context, config_path, None)
        if isinstance(value, str):
            if value not in context.memory:
                vollog.log(constants.LOGLEVEL_V, "IndexError - Layer not found in memory space: {}".format(value))
                return {config_path: self}
            if self.oses and context.memory[value].metadata.get('os', None) not in self.oses:
                vollog.log(constants.LOGLEVEL_V, "TypeError - Layer is not the required OS: {}".format(value))
                return {config_path: self}
            if (self.architectures
                    and context.memory[value].metadata.get('architecture', None) not in self.architectures):
                vollog.log(constants.LOGLEVEL_V, "TypeError - Layer is not the required Architecture: {}".format(value))
                return {config_path: self}
            return {}

        if value is not None:
            vollog.log(constants.LOGLEVEL_V,
                       "TypeError - Translation Layer Requirement only accepts string labels: {}".format(value))
            return {config_path: self}

        # TODO: check that the space in the context lives up to the requirements for arch/os etc

        ### NOTE: This validate method has side effects (the dependencies can change)!!!

        self._validate_class(context, configuration.parent_path(config_path))
        vollog.log(constants.LOGLEVEL_V, "IndexError - No configuration provided: {}".format(config_path))
        return {config_path: self}

    def construct(self, context: interfaces.context.ContextInterface, config_path: str) -> None:
        """Constructs the appropriate layer and adds it based on the class parameter"""
        config_path = configuration.path_join(config_path, self.name)

        # Determine the layer name
        name = self.name
        counter = 2
        while name in context.memory:
            name = self.name + str(counter)
            counter += 1

        args = {"context": context, "config_path": config_path, "name": name}

        if any(
            [subreq.unsatisfied(context, config_path) for subreq in self.requirements.values() if not subreq.optional]):
            return None

        obj = self._construct_class(context, config_path, args)
        if obj is not None and isinstance(obj, interfaces.layers.DataLayerInterface):
            context.add_layer(obj)
            # This should already be done by the _construct_class method
            # context.config[config_path] = obj.name
        return None

    def build_configuration(self, context: interfaces.context.ContextInterface, _: str,
                            value: Any) -> configuration.HierarchicalDict:
        """Builds the appropriate configuration for the specified requirement"""
        return context.memory[value].build_configuration()


class SymbolTableRequirement(configuration.ConstructableRequirementInterface,
                             configuration.ConfigurableRequirementInterface):
    """Class maintaining the limitations on what sort of symbol spaces are acceptable"""

    def unsatisfied(self, context: interfaces.context.ContextInterface,
                    config_path: str) -> Dict[str, configuration.RequirementInterface]:
        """Validate that the value is a valid within the symbol space of the provided context"""
        config_path = configuration.path_join(config_path, self.name)
        value = self.config_value(context, config_path, None)
        if not isinstance(value, str):
            vollog.log(constants.LOGLEVEL_V,
                       "TypeError - SymbolTableRequirement only accepts string labels: {}".format(value))
            return {config_path: self}
        if value not in context.symbol_space:
            # This is an expected situation, so return False rather than raise
            vollog.log(constants.LOGLEVEL_V, "IndexError - Value not present in the symbol space: {}".format(value
                                                                                                             or ""))
            return {config_path: self}
        return {}

    def construct(self, context: interfaces.context.ContextInterface, config_path: str) -> None:
        """Constructs the symbol space within the context based on the subrequirements"""
        config_path = configuration.path_join(config_path, self.name)
        # Determine the space name
        name = context.symbol_space.free_table_name(self.name)

        args = {"context": context, "config_path": config_path, "name": name}

        if any(
            [subreq.unsatisfied(context, config_path) for subreq in self.requirements.values() if not subreq.optional]):
            return None

        # Fill out the parameter for class creation
        if not isinstance(self.requirements["class"], configuration.ClassRequirement):
            raise ValueError("Class requirement is not of type ClassRequirement: {}".format(
                repr(self.requirements["class"])))
        cls = self.requirements["class"].cls
        node_config = context.config.branch(config_path)
        for req in cls.get_requirements():
            if req.name in node_config.data and req.name != "class":
                args[req.name] = node_config.data[req.name]

        obj = self._construct_class(context, config_path, args)
        if obj is not None and isinstance(obj, interfaces.symbols.SymbolTableInterface):
            context.symbol_space.append(obj)
        return None

    def build_configuration(self, context: interfaces.context.ContextInterface, _: str,
                            value: Any) -> configuration.HierarchicalDict:
        """Builds the appropriate configuration for the specified requirement"""
        return context.symbol_space[value].build_configuration()
