"""XML Encoding Rules (XER) codec.

"""

import time
import sys
import re
from typing import NamedTuple
from xml.etree import ElementTree
import binascii
import datetime

from ..parser import EXTENSION_MARKER
from . import BaseType, format_bytes, ErrorWithLocation
from . import EncodeError
from . import DecodeError
from . import compiler
from . import format_or
from . import utc_time_to_datetime
from . import utc_time_from_datetime
from . import generalized_time_to_datetime
from . import generalized_time_from_datetime
from .compiler import enum_values_as_dict


def indent_xml(element, indent, level=0):
    i = "\n" + level * indent

    if len(element):
        if not element.text or not element.text.strip():
            element.text = i + indent

        if not element.tail or not element.tail.strip():
            element.tail = i

        for element in element:
            indent_xml(element, indent, level + 1)

        if not element.tail or not element.tail.strip():
            element.tail = i
    else:
        if level and (not element.tail or not element.tail.strip()):
            element.tail = i

def _to_qname(namespace: str | None, local_name: str) -> str:
    if namespace:
        return '{' + namespace + '}' + local_name
    return local_name

class QName(NamedTuple):
    namespace: str | None
    local_name: str

def from_qnamestr(qnamestr: str) -> QName:
    m = re.search('(?:{(.)})?(.)', qnamestr)
    if not m:
        raise ValueError
    return QName(m.group(1), m.group(2))

class Type(BaseType):

    def __init__(self, name, namespace, type_name):
        super().__init__(name.replace(' ', '_'), type_name)
        self.namespace = namespace

    def set_size_range(self, minimum, maximum, has_extension_marker):
        pass

    def encode_of(self, data):
        # Used by ArrayType
        return self.encode(data)

    def decode_of(self, element):
        # Used by ArrayType
        return self.decode(element)


class StringType(Type):

    def __init__(self, name, namespace, type_name=None):
        if type_name is None:
            type_name = self.__class__.__name__

        super(StringType, self).__init__(name, namespace, type_name)

    def encode(self, data):
        element = ElementTree.Element(_to_qname(self.namespace, self.name))

        if len(data) > 0:
            element.text = data

        return element

    def decode(self, element):
        if element.text is None:
            return u''
        else:
            if sys.version_info[0] > 2:
                return element.text
            else:
                return unicode(element.text)

    def __repr__(self):
        return '{}({})'.format(self.__class__.__name__,
                               self.name)


class MembersType(Type):

    def __init__(self, name, namespace, members, type_name):
        super(MembersType, self).__init__(name, namespace, type_name)
        self.members = members

    def encode(self, data):
        element = ElementTree.Element(_to_qname(self.namespace, self.name))

        for member in self.members:
            name = member.name

            if name in data:
                try:
                    member_element = member.encode(data[name])
                except ErrorWithLocation as e:
                    # Add member location
                    e.add_location(member)
                    raise e

            elif member.optional or member.has_default():
                continue
            else:
                raise EncodeError(
                    "{} member '{}' not found in {}.".format(
                        self.__class__.__name__,
                        name,
                        data))

            element.append(member_element)

        return element

    def decode(self, element):
        values = {}

        for member in self.members:
            name = member.name
            member_element = element.find(_to_qname(member.namespace, name))

            if member_element is not None:
                try:
                    value = member.decode(member_element)
                except ErrorWithLocation as e:
                    # Add member location
                    e.add_location(member)
                    raise e
                values[name] = value
            elif member.optional:
                pass
            elif member.has_default():
                values[name] = member.get_default()

        return values

    def __repr__(self):
        return '{}({}, [{}])'.format(
            self.__class__.__name__,
            self.name,
            ', '.join([repr(member) for member in self.members]))


class ArrayType(Type):

    def __init__(self, name, namespace, element_type, type_name):
        super(ArrayType, self).__init__(name, namespace, type_name)
        self.element_type = element_type

    def encode(self, data):
        element = ElementTree.Element(_to_qname(self.namespace, self.name))

        for entry in data:
            element.append(self.element_type.encode_of(entry))

        return element

    def decode(self, element):
        values = []

        for member_element in list(element):
            value = self.element_type.decode_of(member_element)
            values.append(value)

        return values

    def __repr__(self):
        return '{}({}, {})'.format(self.__class__.__name__,
                                   self.name,
                                   self.element_type)


class Boolean(Type):

    def __init__(self, name, namespace):
        super(Boolean, self).__init__(name, namespace, 'BOOLEAN')

    def encode(self, data):
        element = ElementTree.Element(_to_qname(self.namespace, self.name))
        ElementTree.SubElement(element, 'true' if data else 'false')

        return element

    def decode(self, element):
        return element.find('true') is not None

    def encode_of(self, data):
        return ElementTree.Element('true' if data else 'false')

    def decode_of(self, element):
        return element.tag == 'true'


class Integer(Type):

    def __init__(self, name, namespace):
        super(Integer, self).__init__(name, namespace, 'INTEGER')

    def encode(self, data):
        element = ElementTree.Element(_to_qname(self.namespace, self.name))
        element.text = str(data)

        return element

    def decode(self, element):
        return int(element.text)


class Real(Type):

    def __init__(self, name, namespace):
        super(Real, self).__init__(name, namespace, 'REAL')

    def encode(self, data):
        data = float(data)
        exponent = 0

        while abs(data) >= 10:
            data /= 10
            exponent += 1

        element = ElementTree.Element(_to_qname(self.namespace, self.name))
        element.text = '{}E{}'.format(data, exponent)

        return element

    def decode(self, element):
        return float(element.text)


class Null(Type):

    def __init__(self, name, namespace):
        super(Null, self).__init__(name, namespace, 'NULL')

    def encode(self, data):
        return ElementTree.Element(_to_qname(self.namespace, self.name))

    def decode(self, element):
        return None


class BitString(Type):

    def __init__(self, name, namespace):
        super(BitString, self).__init__(name, namespace, 'BIT STRING')

    def encode(self, data):
        element = ElementTree.Element(_to_qname(self.namespace, self.name))

        if data[1] > 0:
            encoded = int(binascii.hexlify(data[0]), 16)
            encoded |= (0x80 << (8 * len(data[0])))
            element.text = bin(encoded)[10:10 + data[1]].upper()

        return element

    def decode(self, element):
        encoded = element.text

        if encoded is None:
            number_of_bits = 0
            decoded = b''
        else:
            number_of_bits = len(encoded)
            decoded = int(encoded, 2)
            decoded |= (0x80 << number_of_bits)
            rest = (number_of_bits % 8)

            if rest != 0:
                decoded <<= (8 - rest)

            decoded = binascii.unhexlify(hex(decoded).rstrip('L')[4:])

        return (decoded, number_of_bits)


class OctetString(Type):

    def __init__(self, name, namespace):
        super(OctetString, self).__init__(name, namespace, 'OCTET STRING')

    def encode(self, data):
        element = ElementTree.Element(_to_qname(self.namespace, self.name))

        if len(data) > 0:
            element.text = format_bytes(data).upper()

        return element

    def decode(self, element):
        if element.text is None:
            return b''
        else:
            if len(element.text) % 2:
                return binascii.unhexlify(element.text.zfill(len(element.text)+1))
            return binascii.unhexlify(element.text)


class ObjectIdentifier(StringType):

    def __init__(self, name, namespace):
        super(ObjectIdentifier, self).__init__(name, namespace, 'OBJECT IDENTIFIER')

    def decode(self, element):
        if element.text is None:
            raise DecodeError("Expected an OBJECT IDENTIFIER, but got ''.")

        return element.text


class Enumerated(Type):

    def __init__(self, name, namespace, values, numeric):
        super(Enumerated, self).__init__(name, namespace, 'ENUMERATED')

        if numeric:
            self.data_to_value = enum_values_as_dict(values)
            self.value_to_data = {v: k for k, v in self.data_to_value.items()}
        else:
            self.value_to_data = {
                k: k for k in enum_values_as_dict(values).values()
            }
            self.data_to_value = self.value_to_data

        self.has_extension_marker = (EXTENSION_MARKER in values)

    def format_names(self):
        return format_or(sorted(list(self.value_to_data.values())))

    def format_values(self):
        return format_or(sorted(list(self.value_to_data)))

    def encode(self, data):
        try:
            value = self.data_to_value[data]
        except KeyError:
            raise EncodeError(
                "Expected enumeration value {}, but got '{}'.".format(
                    self.format_names(),
                    data))

        element = ElementTree.Element(_to_qname(self.namespace, self.name))
        element.append(ElementTree.Element(value))

        return element

    def decode(self, element):
        value = element[0].tag

        if value in self.value_to_data:
            return self.value_to_data[value]
        elif self.has_extension_marker:
            return None
        else:
            raise DecodeError(
                "Expected enumeration value {}, but got '{}'.".format(
                    self.format_values(), value))

    def encode_of(self, data):
        try:
            value = self.data_to_value[data]
        except KeyError:
            raise EncodeError(
                "Expected enumeration value {}, but got '{}'.".format(
                    self.format_names(),
                    data))

        return ElementTree.Element(value)

    def decode_of(self, element):
        value = element.tag

        try:
            return self.value_to_data[value]
        except KeyError:
            raise DecodeError(
                "Expected enumeration value {}, but got '{}'.".format(
                    self.format_values(), value))


class Sequence(MembersType):

    def __init__(self, name, namespace, members):
        super(Sequence, self).__init__(name, namespace, members, 'SEQUENCE')


class SequenceOf(ArrayType):

    def __init__(self, name, namespace, element_type):
        super(SequenceOf, self).__init__(name,
                                         namespace,
                                         element_type,
                                         'SEQUENCE OF')


class Set(MembersType):

    def __init__(self, name, namespace, members):
        super(Set, self).__init__(name, namespace, members, 'SET')


class SetOf(ArrayType):

    def __init__(self, name, namespace, element_type):
        super(SetOf, self).__init__(name,
                                    namespace,
                                    element_type,
                                    'SET OF')


class Choice(Type):

    def __init__(self, name, namespace, members, has_extension_marker):
        super(Choice, self).__init__(name, namespace, 'CHOICE')
        self.members = members
        self.name_to_member = {member.name: member for member in self.members}
        self.has_extension_marker = has_extension_marker

    def format_names(self):
        return format_or(sorted([member.name for member in self.members]))

    def format_qnames(self):
        return format_or(sorted([_to_qname(member.namespace, member.name) for member in self.members]))

    def encode(self, data):
        try:
            member = self.name_to_member[data[0]]
        except KeyError:
            raise EncodeError(
                "Expected choice {}, but got '{}'.".format(
                    self.format_names(),
                    data[0]))

        element = ElementTree.Element(_to_qname(self.namespace, self.name))

        try:
            element.append(member.encode(data[1]))
        except ErrorWithLocation as e:
            # Add member location
            e.add_location(member)
            raise e

        return element

    def decode(self, element):
        member_element = element[0]
        qnamestr = member_element.tag
        qname : QName = from_qnamestr(qnamestr)

        if qname.local_name in self.name_to_member and qname.namespace == self.namespace:
            member = self.name_to_member[qname.local_name]
        elif self.has_extension_marker:
            return (None, None)
        else:
            raise DecodeError(
                "Expected choice {}, but got '{}'.".format(
                    self.format_qnames(), qnamestr))
        try:
            return (qnamestr, member.decode(member_element))
        except ErrorWithLocation as e:
            # Add member location
            e.add_location(member)
            raise e

    def encode_of(self, data):
        try:
            member = self.name_to_member[data[0]]
        except KeyError:
            e = EncodeError(
                "Expected choice {}, but got '{}'.".format(
                    self.format_names(),
                    data[0]))
            # e.add_location(self.name)
            raise e
        try:
            return member.encode(data[1])
        except ErrorWithLocation as e:
            # Add member location
            e.add_location(member)
            raise e

    def decode_of(self, element):
        qnamestr = element.tag
        qname : QName = from_qnamestr(qnamestr)

        try:
            member = self.name_to_member[qname.local_name]
        except KeyError:
            raise DecodeError(
                "Expected choice {}, but got '{}'.".format(
                    self.format_qnames(), qnamestr))
        if qname.namespace != self.namespace:
            raise DecodeError(
                "Expected choice {}, but got '{}'.".format(
                    self.format_qnames(), qnamestr))
        try:
            return (qnamestr, member.decode(element))
        except ErrorWithLocation as e:
            # Add member location
            e.add_location(member)
            raise e

    def __repr__(self):
        return 'Choice({}, [{}])'.format(
            self.name,
            ', '.join([repr(member) for member in self.members]))


class UTF8String(StringType):
    pass


class NumericString(StringType):
    pass


class PrintableString(StringType):
    pass


class IA5String(StringType):
    pass


class VisibleString(StringType):
    pass


class GeneralString(StringType):
    pass


class BMPString(StringType):
    pass


class GraphicString(StringType):
    pass


class UniversalString(StringType):
    pass


class TeletexString(StringType):
    pass


class ObjectDescriptor(GraphicString):
    pass


class UTCTime(Type):

    def __init__(self, name, namespace):
        super(UTCTime, self).__init__(name, namespace, 'UTCTime')

    def encode(self, data):
        element = ElementTree.Element(_to_qname(self.namespace, self.name))
        element.text = utc_time_from_datetime(data)

        return element

    def decode(self, element):
        return utc_time_to_datetime(element.text)


class GeneralizedTime(Type):

    def __init__(self, name, namespace):
        super(GeneralizedTime, self).__init__(name, namespace, 'GeneralizedTime')

    def encode(self, data):
        element = ElementTree.Element(_to_qname(self.namespace, self.name))
        element.text = generalized_time_from_datetime(data)

        return element

    def decode(self, element):
        return generalized_time_to_datetime(element.text)


class Date(StringType):

    def encode(self, data):
        element = ElementTree.Element(_to_qname(self.namespace, self.name))
        element.text = str(data)

        return element

    def decode(self, element):
        return datetime.date(*time.strptime(element.text, '%Y-%m-%d')[:3])


class TimeOfDay(StringType):

    def encode(self, data):
        element = ElementTree.Element(_to_qname(self.namespace, self.name))
        element.text = str(data)

        return element

    def decode(self, element):
        return datetime.time(*time.strptime(element.text, '%H:%M:%S')[3:6])


class DateTime(StringType):

    def encode(self, data):
        element = ElementTree.Element(_to_qname(self.namespace, self.name))
        element.text = str(data).replace(' ', 'T')

        return element

    def decode(self, element):
        return datetime.datetime(*time.strptime(element.text,
                                                '%Y-%m-%dT%H:%M:%S')[:6])


class Any(Type):

    def __init__(self, namespace, name):
        super(Any, self).__init__(name, namespace, 'ANY')

    def encode(self, data):
        raise NotImplementedError('ANY is not yet implemented.')

    def decode(self, element):
        raise NotImplementedError('ANY is not yet implemented.')


class Recursive(compiler.Recursive, Type):

    def __init__(self, name, namespace, type_name, module_name):
        super(Recursive, self).__init__(name, namespace, 'RECURSIVE')
        self.type_name = type_name
        self.module_name = module_name
        self._inner = None

    def set_inner_type(self, inner):
        self._inner = inner

    def encode(self, data):
        encoded = self._inner.encode(data)
        encoded.tag = self.name

        return encoded

    def decode(self, element):
        return self._inner.decode(element)


class CompiledType(compiler.CompiledType):

    def __init__(self, type_, namespace):
        super(CompiledType, self).__init__(type_)
        self.namespace = namespace

    def encode(self, data, indent=None):
        try:
            element = self._type.encode(data)
        except ErrorWithLocation as e:
            # Add member location
            e.add_location(self._type)
            raise e

        if indent is not None:
            indent_xml(element, indent * " ")

        return ElementTree.tostring(element, encoding='utf-8', default_namespace=self.namespace)

    def decode(self, data):
        element = ElementTree.fromstring(data.decode('utf-8'))
        try:
            return self._type.decode(element)
        except ErrorWithLocation as e:
            # Add member location
            e.add_location(self._type)
            raise e

class Compiler(compiler.Compiler):

    def _get_namespace(self, type_descriptor, module_name):
        xer_ext = type_descriptor.get('xer')
        if xer_ext:
            return xer_ext.get('namespace')
        module = self._specification.get(module_name)
        if module:
            mod_xer_ext = module.get('xer')
            if mod_xer_ext:
                return mod_xer_ext.get('namespace')
        return None

    def compile_member(self, member, module_name):
        # module_name is the name of the module the MembersType is declared in
        compiled_member = super().compile_member(member, module_name)

        namespace = self._get_namespace(member, module_name)
        if (namespace and ('namespace' not in member or namespace != member.namespace)):
            compiled_member = self.copy(compiled_member)
            compiled_member.namespace = namespace

        return compiled_member

    def process_type(self, type_name, type_descriptor, module_name):
        compiled_type = self.compile_type(type_name,
                                          type_descriptor,
                                          module_name)

        return CompiledType(compiled_type, self._get_namespace(type_descriptor, module_name))

    def compile_type(self, name, type_descriptor, module_name):
        namespace = self._get_namespace(type_descriptor, module_name)
        module_name = self.get_module_name(type_descriptor, module_name)
        type_name = type_descriptor['type']

        if type_name == 'SEQUENCE':
            members, _ = self.compile_members(
                type_descriptor['members'],
                module_name)
            compiled = Sequence(name, namespace, members)
        elif type_name == 'SEQUENCE OF':
            element = type_descriptor['element']
            compiled = SequenceOf(name, namespace,
                                  self.compile_type(type_descriptor.get('element_name') or element['type'],
                                                    element,
                                                    module_name))
        elif type_name == 'SET':
            members, _ = self.compile_members(
                type_descriptor['members'],
                module_name)
            compiled = Set(name, namespace, members)
        elif type_name == 'SET OF':
            element = type_descriptor['element']
            compiled = SetOf(name, namespace,
                             self.compile_type(type_descriptor.get('element_name') or element['type'],
                                               element,
                                               module_name))
        elif type_name == 'CHOICE':
            compiled = Choice(name, namespace,
                              *self.compile_members(
                                  type_descriptor['members'],
                                  module_name))
        elif type_name == 'INTEGER':
            compiled = Integer(name, namespace)
        elif type_name == 'REAL':
            compiled = Real(name, namespace)
        elif type_name == 'ENUMERATED':
            compiled = Enumerated(name, namespace,
                                  self.get_enum_values(type_descriptor,
                                                       module_name),
                                  self._numeric_enums)
        elif type_name == 'BOOLEAN':
            compiled = Boolean(name, namespace)
        elif type_name == 'OBJECT IDENTIFIER':
            compiled = ObjectIdentifier(name, namespace)
        elif type_name == 'OCTET STRING':
            compiled = OctetString(name, namespace)
        elif type_name == 'TeletexString':
            compiled = TeletexString(name, namespace)
        elif type_name == 'NumericString':
            compiled = NumericString(name, namespace)
        elif type_name == 'PrintableString':
            compiled = PrintableString(name, namespace)
        elif type_name == 'IA5String':
            compiled = IA5String(name, namespace)
        elif type_name == 'VisibleString':
            compiled = VisibleString(name, namespace)
        elif type_name == 'GeneralString':
            compiled = GeneralString(name, namespace)
        elif type_name == 'UTF8String':
            compiled = UTF8String(name, namespace)
        elif type_name == 'BMPString':
            compiled = BMPString(name, namespace)
        elif type_name == 'GraphicString':
            compiled = GraphicString(name, namespace)
        elif type_name == 'UTCTime':
            compiled = UTCTime(name, namespace)
        elif type_name == 'UniversalString':
            compiled = UniversalString(name, namespace)
        elif type_name == 'GeneralizedTime':
            compiled = GeneralizedTime(name, namespace)
        elif type_name == 'DATE':
            compiled = Date(name, namespace)
        elif type_name == 'TIME-OF-DAY':
            compiled = TimeOfDay(name, namespace)
        elif type_name == 'DATE-TIME':
            compiled = DateTime(name, namespace)
        elif type_name == 'BIT STRING':
            compiled = BitString(name, namespace)
        elif type_name == 'ANY':
            compiled = Any(name, namespace)
        elif type_name == 'ANY DEFINED BY':
            compiled = Any(name, namespace)
        elif type_name == 'NULL':
            compiled = Null(name, namespace)
        elif type_name == 'EXTERNAL':
            members, _ = self.compile_members(self.external_type_descriptor()['members'],
                                              module_name)
            compiled = Sequence(name, namespace, members)
        elif type_name == 'ObjectDescriptor':
            compiled = ObjectDescriptor(name, namespace)
        else:
            if type_name in self.types_backtrace:
                compiled = Recursive(name, namespace,
                                     type_name,
                                     module_name)
                self.recursive_types.append(compiled)
            else:
                compiled = self.compile_user_type(name,
                                                  type_name,
                                                  module_name)

        return compiled


def compile_dict(specification, numeric_enums):
    return Compiler(specification, numeric_enums).process()


def decode_full_length(_data):
    raise DecodeError('Decode length is not supported for this codec.')
