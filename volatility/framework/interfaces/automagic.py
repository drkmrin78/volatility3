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
"""Defines the automagic interfaces for populating the context before a plugin runs

Automagic objects attempt to automatically fill configuration values that a user has not filled.
"""
from abc import ABCMeta
from typing import Any, List, Optional, Tuple, Union, Type

from volatility.framework import interfaces, constants
from volatility.framework.configuration import requirements


class AutomagicInterface(interfaces.configuration.ConfigurableInterface, metaclass = ABCMeta):
    """Class that defines an automagic component that can help fulfill a Requirement

    These classes are callable with the following parameters:

    Args:
        context: The context in which to store configuration data that the automagic might populate
        config_path: Configuration path where the configurable's data under the context's config lives
        configurable: The top level configurable whose requirements may need statisfying
        progress_callback: An optional function accepting a percentage and optional description to indicate
            progress during long calculations

    .. note::

        The `context` provided here may be different to that provided during initialization.  The `context` provided at
        initialization should be used for local configuration of the automagic itself, the `context` provided during
        the call is to be populated by the automagic.
    """

    priority = 10
    """An ordering to indicate how soon this automagic should be run"""

    def __init__(self, context: interfaces.context.ContextInterface, config_path: str, *args, **kwargs) -> None:
        super().__init__(context, config_path)
        for requirement in self.get_requirements():
            if not isinstance(requirement, (interfaces.configuration.SimpleTypeRequirement,
                                            requirements.ChoiceRequirement, requirements.ListRequirement)):
                raise ValueError(
                    "Automagic requirements must be a SimpleTypeRequirement, ChoiceRequirement or ListRequirement")

    def __call__(self,
                 context: interfaces.context.ContextInterface,
                 config_path: str,
                 requirement: interfaces.configuration.RequirementInterface,
                 progress_callback: constants.ProgressCallback = None) -> Optional[List[Any]]:
        """Runs the automagic over the configurable"""
        return []

    # TODO: requirement_type can be made UnionType[Type[T], Tuple[Type[T], ...]]
    #       once mypy properly supports Tuples in instance

    def find_requirements(self,
                          context: interfaces.context.ContextInterface,
                          config_path: str,
                          requirement_root: interfaces.configuration.RequirementInterface,
                          requirement_type: Union[Tuple[Type[interfaces.configuration.RequirementInterface], ...], Type[
                              interfaces.configuration.RequirementInterface]],
                          shortcut: bool = True) -> List[Tuple[str, interfaces.configuration.RequirementInterface]]:
        """Determines if there is actually an unfulfilled requirement waiting

        This ensures we do not carry out an expensive search when there is no requirement for a particular requirement

        Args:
            context: Context on which to operate
            config_path: Configuration path of the top-level requirement
            requirement_root: Top-level requirement whose subrequirements will all be searched
            requirement_type: Type of requirement to find
            shortcut: Only returns requirements that live under unsatisfied requirements

        Returns:
            A list of tuples containing the config_path, sub_config_path and requirement identifying the SymbolTableRequirements
        """
        sub_config_path = interfaces.configuration.path_join(config_path, requirement_root.name)
        results = []  # type: List[Tuple[str, interfaces.configuration.RequirementInterface]]
        recurse = not shortcut
        if isinstance(requirement_root, requirement_type):
            if recurse or requirement_root.unsatisfied(context, config_path):
                results.append((sub_config_path, requirement_root))
        else:
            recurse = True
        if recurse:
            for subreq in requirement_root.requirements.values():
                results += self.find_requirements(context, sub_config_path, subreq, requirement_type, shortcut)
        return results


class StackerLayerInterface(metaclass = ABCMeta):
    """Class that takes a lower layer and attempts to build on it

       stack_order determines the order (from low to high) that stacking layers
       should be attempted lower levels should have lower stack_orders
    """

    stack_order = 0

    @classmethod
    def stack(self,
              context: interfaces.context.ContextInterface,
              layer_name: str,
              progress_callback: constants.ProgressCallback = None) -> Optional[interfaces.layers.DataLayerInterface]:
        """
        Method to determine whether this builder can operate on the named layer.  If so, modify the context appropriately.

        Returns the name of any new_layer stacked on top of this layer or None.  The stacking is therefore strictly
        linear rather than tree driven.

        Configuration options provided by the context are ignored, and defaults are to be used by this method
        to build a space where possible.

        Args:
           context: Context in which to construct the higher layer
           layer_name: Name of the layer to stack on top of
           progress_callback: A callback function to indicate progress through a scan (if one is necessary)
        """
