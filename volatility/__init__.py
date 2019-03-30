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
"""Volatility 3 - An open-source memory forensics framework"""
import sys
from importlib import abc


class WarningFindSpec(abc.MetaPathFinder):
    """Checks import attempts and throws a warning if the name shouldn't be used"""

    def find_spec(name: str, _p, _t):
        """Mock find_spec method that just checks the name, this must go first"""
        if name.startswith("volatility.framework.plugins."):
            raise Warning("Please do not use the volatility.framework.plugins namespace, only use volatility.plugins")


if WarningFindSpec not in sys.meta_path:
    sys.meta_path = [WarningFindSpec] + sys.meta_path

# We point the volatility.plugins __path__ variable at BOTH
#   volatility/plugins
#   volatility/framework/plugins
# in that order.
#
# This will allow our users to override any component of any plugin without monkey patching,
# but it also allows us to clear out the plugins directory to get back to proper functionality.
# This offered the greatest flexibility for users whilst allowing us to keep the core separate and clean.
#
# This means that all plugins should be imported as volatility.plugins (otherwise they'll be imported twice,
# once as volatility.plugins.NAME and once as volatility.framework.plugins.NAME).  We therefore throw an error
# if anyone tries to import anything under the volatility.framework.plugins.* namespace
#
# The remediation is to only ever import form volatility.plugins instead.
