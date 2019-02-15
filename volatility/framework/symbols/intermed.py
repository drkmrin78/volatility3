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

import base64
import codecs
import copy
import json
import logging
import os
import pathlib
import zipfile
from abc import ABCMeta
from typing import Any, Dict, Generator, Iterable, List, Optional, Type, Tuple

import volatility
import volatility.framework.layers.resources
from volatility import schemas, symbols
from volatility.framework import class_subclasses, constants, exceptions, interfaces, objects
from volatility.framework.layers import physical
from volatility.framework.configuration import requirements
from volatility.framework.symbols import native, metadata

vollog = logging.getLogger(__name__)

# ## TODO
#
# All symbol tables should take a label to an object template
#
# Templates for subtypes etc should be looked up recursively just like anything else
# We therefore need a way to unroll rolled-up types
# Generate mangled names on the fly (prohibits external calling)
#
# Symbol list could be a dict with knowledge of its parent?
# Class split is arbitrary, it's an extension for developers
# Object template should contain both class and initial parameters
#
#
# *** Resolution should not happen in the resolve function
# It should only happen on access of contained types ***
#
# Recursive objects can be fixed by having caching the objects
# (however, they have to be built first!)
#
# Single hop resolution is probably the solution
# Could probably deal with it by having a property that caches
# for container types
#


def _construct_delegate_function(name: str, is_property: bool = False) -> Any:

    def _delegate_function(self, *args, **kwargs):
        if is_property:
            return getattr(self._delegate, name)
        return getattr(self._delegate, name)(*args, **kwargs)

    if is_property:
        return property(_delegate_function)
    return _delegate_function


class IntermediateSymbolTable(interfaces.symbols.SymbolTableInterface):

    def __init__(self,
                 context: interfaces.context.ContextInterface,
                 config_path: str,
                 name: str,
                 isf_url: str,
                 native_types: interfaces.symbols.NativeTableInterface = None,
                 table_mapping: Optional[Dict[str, str]] = None,
                 validate: bool = True) -> None:
        """Instantiates an SymbolTable based on an IntermediateSymbolFormat JSON file.  This is validated against the
        appropriate schema.  The validation can be disabled by passing validate = False, but this should almost never be
        done.

        Args:
            context: The volatility context for the symbol table
            config_path: The configuration path for the symbol table
            name: The name for the symbol table (this is used in symbols e.g. table!symbol )
            isf_url: The URL pointing to the ISF file location
            native_types: The NativeSymbolTable that contains the native types for this symbol table
            validate: Determines whether the ISF file will be validated against the appropriate schema
        """
        # Check there are no obvious errors
        # Open the file and test the version
        self._versions = dict([(x.version, x) for x in class_subclasses(ISFormatTable)])
        fp = volatility.framework.layers.resources.ResourceAccessor().open(isf_url)
        reader = codecs.getreader("utf-8")
        json_object = json.load(reader(fp))  # type: ignore
        fp.close()

        # Validation is expensive, but we cache to store the hashes of successfully validated json objects
        if validate and not schemas.validate(json_object):
            raise exceptions.SymbolSpaceError("File does not pass version validation: {}".format(isf_url))

        metadata = json_object.get('metadata', None)

        # Determine the delegate or throw an exception
        self._delegate = self._closest_version(metadata.get('format', "0.0.0"),
                                               self._versions)(context, config_path, name, json_object, native_types,
                                                               table_mapping)

        # Inherit
        super().__init__(
            context, config_path, name, native_types or self._delegate.natives, table_mapping = table_mapping)

    @staticmethod
    def _closest_version(version: str, versions: Dict[Tuple[int, int, int], Type['ISFormatTable']]) \
            -> Type['ISFormatTable']:
        """Determines the highest suitable handler for specified version format

        An interface version such as (Current-Age).Age.Revision means that (Current - Age) of the provider must be equal to that of the
          consumer, and the provider (the JSON in this instance) must have a greater age (indicating that only additive
          changes have been made) than the consumer (in this case, the file reader).
        """
        supported, age, revision = [int(x) for x in version.split(".")]
        supported_versions = [x for x in versions if x[0] == supported and x[1] >= age]
        if not supported_versions:
            raise ValueError(
                "No Intermediate Format interface versions support file interface version: {}".format(version))
        return versions[max(supported_versions)]

    symbols = _construct_delegate_function('symbols', True)
    types = _construct_delegate_function('types', True)
    enumerations = _construct_delegate_function('enumerations', True)
    metadata = _construct_delegate_function('metadata', True)
    get_type = _construct_delegate_function('get_type')
    get_symbol = _construct_delegate_function('get_symbol')
    get_enumeration = _construct_delegate_function('get_enumeration')
    get_type_class = _construct_delegate_function('get_type_class')
    set_type_class = _construct_delegate_function('set_type_class')
    del_type_class = _construct_delegate_function('del_type_class')

    @classmethod
    def file_symbol_url(cls, sub_path: str, filename: Optional[str] = None) -> Generator[str, None, None]:
        """Returns an iterator of appropriate file-scheme symbol URLs that can be opened by a ResourceAccessor class

        Filter reduces the number of results returned to only those URLs containing that string
        """

        # Check user-modifiable files first, then compressed ones
        extensions = ['.json', '.json.xz', '.json.gz', '.json.bz2']
        if filename is None:
            filename = "*"
            zip_match = filename
        else:
            # For zipfiles, the path separator is always "/", so we need to change the path
            zip_match = "/".join(os.path.split(filename))

        # Check user symbol directory first, then fallback to the framework's library to allow for overloading
        vollog.log(constants.LOGLEVEL_VVVV,
                   "Searching for symbols in {}".format(", ".join(volatility.symbols.__path__)))
        for path in volatility.symbols.__path__:
            if not os.path.isabs(path):
                path = os.path.abspath(os.path.join(__file__, path))
            for extension in extensions:
                # Hopefully these will not be large lists, otherwise this might be slow
                try:
                    for found in pathlib.Path(path).joinpath(sub_path).resolve().rglob(filename + extension):
                        yield found.as_uri()
                except FileNotFoundError:
                    # If there's no linux symbols, don't cry about it
                    pass

            # Finally try looking in zip files
            zip_path = os.path.join(path, sub_path + ".zip")
            if os.path.exists(zip_path):
                # We have a zipfile, so run through it and look for sub files that match the filename
                with zipfile.ZipFile(zip_path) as zfile:
                    for name in zfile.namelist():
                        for extension in extensions:
                            # By ending with an extension (and therefore, not /), we should not return any directories
                            if name.endswith(zip_match + extension) or (zip_match == "*" and name.endswith(extension)):
                                yield "jar:file:" + str(pathlib.Path(zip_path)) + "!" + name

    @classmethod
    def create(cls,
               context: interfaces.context.ContextInterface,
               config_path: str,
               sub_path: str,
               filename: str,
               native_types: Optional[interfaces.symbols.NativeTableInterface] = None,
               table_mapping: Optional[Dict[str, str]] = None) -> str:
        """Takes a context and loads an intermediate symbol table based on a filename.

        Args:
            context: The context that the current plugin is being run within
            config_path: The configuration path for reading/storing configuration information this symbol table may use
            sub_path: The path under a suitable symbol path (defaults to volatility/symbols and volatility/framework/symbols) to check
            filename: Basename of the file to find under the sub_path
            native_types: Set of native types, defaults to native types read from the intermediate symbol format file
            table_mapping: a dictionary of table names mentioned within the ISF file, and the tables within the context which they map to

        Returns:
             the name of the added symbol table"""
        urls = list(cls.file_symbol_url(sub_path, filename))
        if not urls:
            raise ValueError("No symbol files found at provided filename: {}", filename)
        table_name = context.symbol_space.free_table_name(filename)
        table = cls(
            context = context,
            config_path = config_path,
            name = table_name,
            isf_url = urls[0],
            native_types = native_types,
            table_mapping = table_mapping)
        context.symbol_space.append(table)
        return table_name

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.StringRequirement(
                "isf_url", description = "JSON file containing the symbols encoded in the Intermediate Symbol Format")
        ]


class ISFormatTable(interfaces.symbols.SymbolTableInterface, metaclass = ABCMeta):
    """Provide a base class to identify all subclasses"""
    version = (0, 0, 0)

    def __init__(self,
                 context: interfaces.context.ContextInterface,
                 config_path: str,
                 name: str,
                 json_object: Any,
                 native_types: interfaces.symbols.NativeTableInterface = None,
                 table_mapping: Optional[Dict[str, str]] = None) -> None:
        self._json_object = json_object
        self._validate_json()
        self.name = name
        nt = native_types or self._get_natives()
        if nt is None:
            raise ValueError("Native table not provided")
        nt.name = name + "_natives"
        super().__init__(context, config_path, name, nt, table_mapping = table_mapping)
        self._overrides = {}  # type: Dict[str, Type[interfaces.objects.ObjectInterface]]
        self._symbol_cache = {}  # type: Dict[str, interfaces.symbols.SymbolInterface]

    def _get_natives(self) -> Optional[interfaces.symbols.NativeTableInterface]:
        """Determines the appropriate native_types to use from the JSON data"""
        # TODO: Consider how to generate the natives entirely from the ISF
        classes = {"x64": native.x64NativeTable, "x86": native.x86NativeTable}
        for nc in sorted(classes):
            native_class = classes[nc]
            for base_type in self._json_object['base_types']:
                try:
                    if self._json_object['base_types'][base_type]['length'] != native_class.get_type(base_type).size:
                        break
                except TypeError:
                    # TODO: determine whether we should give voids a size - We don't give voids a length, whereas microsoft seemingly do
                    pass
            else:
                vollog.debug("Choosing appropriate natives for symbol library: {}".format(nc))
                return native_class.natives
        return None

    # TODO: Check the format and make use of the other metadata

    def _validate_json(self) -> None:
        if ('user_types' not in self._json_object or 'base_types' not in self._json_object
                or 'metadata' not in self._json_object or 'symbols' not in self._json_object
                or 'enums' not in self._json_object):
            raise exceptions.SymbolSpaceError("Malformed JSON file provided")

    @property
    def metadata(self) -> Optional[interfaces.symbols.MetadataInterface]:
        """Returns a metadata object containing information about the symbol table"""
        return None


class Version1Format(ISFormatTable):
    """Class for storing intermediate debugging data as objects and classes"""
    current = 1
    revision = 0
    age = 1
    version = (current - age, age, revision)

    def get_symbol(self, name: str) -> interfaces.symbols.SymbolInterface:
        """Returns the location offset given by the symbol name"""
        # TODO: Add the ability to add/remove/change symbols after creation
        # note that this should invalidate/update the cache
        if self._symbol_cache.get(name, None):
            return self._symbol_cache[name]
        symbol = self._json_object['symbols'].get(name, None)
        if not symbol:
            raise exceptions.SymbolError("Unknown symbol: {}".format(name))
        self._symbol_cache[name] = interfaces.symbols.SymbolInterface(name = name, address = symbol['address'])
        return self._symbol_cache[name]

    @property
    def symbols(self) -> Iterable[str]:
        """Returns an iterator of the symbol names"""
        return list(self._json_object.get('symbols', {}))

    @property
    def enumerations(self) -> Iterable[str]:
        """Returns an iterator of the available enumerations"""
        return list(self._json_object.get('enums', {}))

    @property
    def types(self) -> Iterable[str]:
        """Returns an iterator of the symbol type names"""
        return list(self._json_object.get('user_types', {})) + list(self.natives.types)

    def get_type_class(self, name: str) -> Type[interfaces.objects.ObjectInterface]:
        return self._overrides.get(name, objects.Struct)

    def set_type_class(self, name: str, clazz: Type[interfaces.objects.ObjectInterface]) -> None:
        if name not in self.types:
            raise ValueError("Symbol type not in {} SymbolTable: {}".format(self.name, name))
        self._overrides[name] = clazz

    def del_type_class(self, name: str) -> None:
        if name in self._overrides:
            del self._overrides[name]

    def _interdict_to_template(self, dictionary: Dict[str, Any]) -> interfaces.objects.Template:
        """Converts an intermediate format dict into an object template"""
        if not dictionary:
            raise exceptions.SymbolSpaceError("Invalid intermediate dictionary: {}".format(dictionary))

        type_name = dictionary['kind']
        if type_name == 'base':
            type_name = dictionary['name']

        if type_name in self.natives.types:
            # The symbol is a native type
            native_template = self.natives.get_type(self.name + constants.BANG + type_name)

            # Add specific additional parameters, etc
            update = {}
            if type_name == 'array':
                update['count'] = dictionary['count']
                update['subtype'] = self._interdict_to_template(dictionary['subtype'])
            elif type_name == 'pointer':
                update['subtype'] = self._interdict_to_template(dictionary['subtype'])
            elif type_name == 'enum':
                update = self._lookup_enum(dictionary['name'])
            elif type_name == 'bitfield':
                update = {'start_bit': dictionary['bit_position'], 'end_bit': dictionary['bit_length']}
                update['base_type'] = self._interdict_to_template(dictionary['type'])
            # We do *not* call native_template.clone(), since it slows everything down a lot
            # We require that the native.get_type method always returns a newly constructed python object
            native_template.update_vol(**update)
            return native_template

        # Otherwise
        if dictionary['kind'] not in ['struct', 'union', 'CPPObject']:
            raise exceptions.SymbolSpaceError("Unknown Intermediate format: {}".format(dictionary))

        reference_name = dictionary['name']
        if constants.BANG not in reference_name:
            reference_name = self.name + constants.BANG + reference_name
        else:
            reference_parts = reference_name.split(constants.BANG)
            reference_name = (self.table_mapping.get(reference_parts[0], reference_parts[0]) + constants.BANG +
                              constants.BANG.join(reference_parts[1:]))

        return objects.templates.ReferenceTemplate(type_name = reference_name)

    def _lookup_enum(self, name: str) -> Dict[str, Any]:
        """Looks up an enumeration and returns a dictionary of __init__ parameters for an Enum"""
        lookup = self._json_object['enums'].get(name, None)
        if not lookup:
            raise exceptions.SymbolSpaceError("Unknown enumeration: {}".format(name))
        result = {"choices": copy.deepcopy(lookup['constants']), "base_type": self.natives.get_type(lookup['base'])}
        return result

    def get_enumeration(self, enum_name: str) -> interfaces.objects.Template:
        """Resolves an individual enumeration"""
        if constants.BANG in enum_name:
            raise exceptions.SymbolError("Enumeration for a different table requested: {}".format(enum_name))
        if enum_name not in self._json_object['enums']:
            # Fall back to the natives table
            raise exceptions.SymbolError("Enumeration not found in {} table: {}".format(self.name, enum_name))
        curdict = self._json_object['enums'][enum_name]
        base_type = self.natives.get_type(curdict['base'])
        return objects.templates.ObjectTemplate(
            type_name = 'Enumeration',
            object_class = objects.Enumeration,
            base_type = base_type,
            size = curdict['size'],
            choices = curdict['constants'])

    def get_type(self, type_name: str) -> interfaces.objects.Template:
        """Resolves an individual symbol"""
        if constants.BANG in type_name:
            raise exceptions.SymbolError("Symbol for a different table requested: {}".format(type_name))
        if type_name not in self._json_object['user_types']:
            # Fall back to the natives table
            return self.natives.get_type(self.name + constants.BANG + type_name)
        curdict = self._json_object['user_types'][type_name]
        members = {}
        for member_name in curdict['fields']:
            interdict = curdict['fields'][member_name]
            member = (interdict['offset'], self._interdict_to_template(interdict['type']))
            members[member_name] = member
        object_class = self.get_type_class(type_name)
        return objects.templates.ObjectTemplate(
            type_name = self.name + constants.BANG + type_name,
            object_class = object_class,
            size = curdict['length'],
            members = members)


class Version2Format(Version1Format):
    """Class for storing intermediate debugging data as objects and classes"""
    current = 2
    revision = 0
    age = 0
    version = (current - age, age, revision)

    def _get_natives(self) -> Optional[interfaces.symbols.NativeTableInterface]:
        """Determines the appropriate native_types to use from the JSON data"""
        classes = {"x64": native.x64NativeTable, "x86": native.x86NativeTable}
        for nc in sorted(classes):
            native_class = classes[nc]
            for base_type in self._json_object['base_types']:
                try:
                    if self._json_object['base_types'][base_type]['size'] != native_class.get_type(base_type).size:
                        break
                except TypeError:
                    # TODO: determine whether we should give voids a size - We don't give voids a length, whereas microsoft seemingly do
                    pass
            else:
                vollog.debug("Choosing appropriate natives for symbol library: {}".format(nc))
                return native_class.natives
        return None

    def get_type(self, type_name: str) -> interfaces.objects.Template:
        """Resolves an individual symbol"""
        if constants.BANG in type_name:
            raise exceptions.SymbolError("Symbol for a different table requested: {}".format(type_name))
        if type_name not in self._json_object['user_types']:
            # Fall back to the natives table
            if type_name in self.natives.types:
                return self.natives.get_type(self.name + constants.BANG + type_name)
            else:
                raise exceptions.SymbolError("Unknown symbol: {}".format(type_name))
        curdict = self._json_object['user_types'][type_name]
        members = {}
        for member_name in curdict['fields']:
            interdict = curdict['fields'][member_name]
            member = (interdict['offset'], self._interdict_to_template(interdict['type']))
            members[member_name] = member
        object_class = self.get_type_class(type_name)
        return objects.templates.ObjectTemplate(
            type_name = self.name + constants.BANG + type_name,
            object_class = object_class,
            size = curdict['size'],
            members = members)


class Version3Format(Version2Format):
    """Class for storing intermediate debugging data as objects and classes"""
    current = 3
    revision = 0
    age = 1
    version = (current - age, age, revision)

    def get_symbol(self, name: str) -> interfaces.symbols.SymbolInterface:
        """Returns the symbol given by the symbol name"""
        if self._symbol_cache.get(name, None):
            return self._symbol_cache[name]
        symbol = self._json_object['symbols'].get(name, None)
        if not symbol:
            raise exceptions.SymbolError("Unknown symbol: {}".format(name))
        symbol_type = None
        if 'type' in symbol:
            symbol_type = self._interdict_to_template(symbol['type'])
        self._symbol_cache[name] = interfaces.symbols.SymbolInterface(
            name = name, address = symbol['address'], type = symbol_type)
        return self._symbol_cache[name]


class Version4Format(Version3Format):
    """Class for storing intermediate debugging data as objects and classes"""
    current = 4
    revision = 0
    age = 0
    version = (current - age, age, revision)

    format_mapping = {
        'int': objects.Integer,
        'float': objects.Float,
        'void': objects.Integer,
        'bool': objects.Boolean,
        'char': objects.Char
    }

    def _get_natives(self) -> Optional[interfaces.symbols.NativeTableInterface]:
        """Determines the appropriate native_types to use from the JSON data"""
        native_dict = {}
        base_types = self._json_object['base_types']
        for base_type in base_types:
            # Void are ignored because voids are not a volatility primitive, they are a specific Volatility object
            if base_type != 'void':
                current = base_types[base_type]
                # TODO: Fix up the typing of this, it bugs out because of the tuple assignment
                if current['kind'] not in self.format_mapping:
                    raise ValueError("Unsupported base kind")
                format_val = (current['size'], current['endian'], current['signed'])
                object_type = self.format_mapping[current['kind']]
                if base_type == 'pointer':
                    object_type = objects.Pointer
                native_dict[base_type] = (object_type, format_val)
        return native.NativeTable(name = "native", native_dictionary = native_dict)


class Version5Format(Version4Format):
    """Class for storing intermediate debugging data as objects and classes"""
    current = 5
    revision = 0
    age = 1
    version = (current - age, age, revision)

    def get_symbol(self, name: str) -> interfaces.symbols.SymbolInterface:
        """Returns the symbol given by the symbol name"""
        if self._symbol_cache.get(name, None):
            return self._symbol_cache[name]
        symbol = self._json_object['symbols'].get(name, None)
        if not symbol:
            raise exceptions.SymbolError("Unknown symbol: {}".format(name))
        symbol_type = None
        if 'type' in symbol:
            symbol_type = self._interdict_to_template(symbol['type'])
        symbol_constant_data = None
        if 'constant_data' in symbol:
            symbol_constant_data = base64.b64decode(symbol.get('constant_data'))
        self._symbol_cache[name] = interfaces.symbols.SymbolInterface(
            name = name, address = symbol['address'], type = symbol_type, constant_data = symbol_constant_data)
        return self._symbol_cache[name]


class Version6Format(Version5Format):
    """Class for storing intermediate debugging data as objects and classes"""
    current = 6
    revision = 0
    age = 0
    version = (current - age, age, revision)

    @property
    def metadata(self) -> Optional[interfaces.symbols.MetadataInterface]:
        """Returns a MetadataInterface object"""
        if self._json_object.get('metadata', {}).get('windows'):
            return metadata.WindowsMetadata(self._json_object['metadata']['windows'])
        if self._json_object.get('metadata', {}).get('linux'):
            return metadata.LinuxMetadata(self._json_object['metadata']['linux'])
        return None
