import enum
import struct
from typing import Tuple


class Type(enum.IntEnum):
    A = 1
    NS = 2
    AAAA = 28
    PTR = 12


class Class(enum.IntEnum):
    IN = 1


SUPPORTED_TYPES = set(Type)
SUPPORTED_CLASSES = set(Class)


class Query:
    def __init__(self, type_: Type, name):
        self.type = type_
        self.name = name


class Answer:
    def __init__(self, type_: Type, name, ttl, data):
        self.type = type_
        self.name = name
        self.ttl = ttl
        self.data = data

    @property
    def name_server(self):
        if self.type == Type.NS:
            return self.data

        raise ValueError('Not an NS answer')


class Flags:
    def __init__(self, is_response, opcode,
                 authoritative, truncated, recursion_desired,
                 recursion_available, z, answer_authenticated,
                 non_auth, reply_code):
        self.authoritative = authoritative
        self.truncated = truncated
        self.recursion_desired = recursion_desired
        self.recursion_available = recursion_available
        self.z = z
        self.answer_authenticated = answer_authenticated
        self.non_auth = non_auth
        self.reply_code = reply_code
        self.opcode = opcode
        self.is_response = is_response


class Package:
    def __init__(self, flags: Flags, queries: [Query], answers: [Answer], authorities: [Answer], additional: [Answer]):
        self.flags = flags
        self.queries = queries
        self.answers = answers
        self.authorities = authorities
        self.additional = additional


class ParserError(Exception):
    def __init__(self, msg):
        super().__init__(msg)


class _ParsingSession:
    def __init__(self, bytes_: bytes):
        self.bytes = bytes_

    def parse(self) -> Package:
        (id_, flags, queries_rrs, ans_rrs, auth_rrs, add_rss), records = \
            struct.unpack('! H H H H H H', self.bytes[:12]), self.bytes[12:]

        flags = self._parse_flags(flags)

        queries = []
        answers = []
        authoritative = []
        additional = []

        offset = 12

        for i in range(queries_rrs):
            offset, query = self._read_query(offset)
            queries.append(query)

        for i in range(ans_rrs):
            offset, answer = self._read_answer(offset)
            answers.append(answer)

        for i in range(auth_rrs):
            offset, auth = self._read_answer(offset)
            authoritative.append(auth)

        for i in range(add_rss):
            offset, add = self._read_answer(offset)
            additional.append(add)

        return Package(flags, queries, answers, authoritative, additional)

    def _read_query(self, offset) -> Tuple[int, Query]:
        offset, name = self._read_string(offset)
        type_, class_ = struct.unpack('! H H', self.bytes[offset: offset + 4])
        offset += 4

        if type_ not in SUPPORTED_TYPES:
            raise ParserError(f'Unsupported type in query: {type_}')

        if class_ not in SUPPORTED_CLASSES:
            raise ParserError(f'Unsupported class in query: {class_}')

        return offset, Query(type_, name)

    def _read_answer(self, offset) -> Tuple[int, Answer]:
        offset, name = self._read_string(offset)
        type_, class_, ttl, data_length = struct.unpack('! H H I H', self.bytes[offset: offset + 10])
        offset += 10

        if type_ not in SUPPORTED_TYPES:
            raise ParserError(f'Unsupported type in answer: {type_}')

        if class_ not in SUPPORTED_CLASSES:
            raise ParserError(f'Unsupported class in answer: {class_}')

        if type_ == Type.A or type_ == Type.AAAA:
            data = self.bytes[offset: offset + data_length]
            offset += data_length
        elif type_ == Type.NS or type_ == Type.PTR:
            offset, data = self._read_string(offset)
        else:
            raise NotImplementedError(f'Not implemented read answer for type: {type_}')

        return offset, Answer(type_, name, ttl, data)

    def _read_string(self, offset) -> Tuple[int, str]:
        parts = []

        while True:
            length = self.bytes[offset]

            if length == 0:
                offset += 1
                break

            if length & 0xC0 == 0xC0:
                pointer = ((length & 0x3f) << 8) | self.bytes[offset + 1]
                _, ending = self._read_string(pointer)
                parts.append(ending)
                offset += 2

                break

            part = ''
            offset += 1

            for _ in range(length):
                part += self.bytes[offset].decode()
                offset += 1

        return offset, '.'.join(parts)

    def _parse_flags(self, flags) -> Flags:
        is_response = (flags & 0x8000) >> 15
        opcode = (flags & 0x7800) >> 11
        authoritative = (flags & 0x0400) >> 10
        truncated = (flags & 0x0200) >> 9
        recursion_desired = (flags & 0x0100) >> 8
        recursion_available = (flags & 0x0080) >> 7
        z = (flags & 0x0040) >> 6
        answer_authenticated = (flags & 0x0020) >> 5
        non_auth = (flags & 0x0010) >> 4
        reply_code = flags & 0x000F

        return Flags(is_response, opcode, authoritative,
                     truncated, recursion_desired, recursion_available,
                     z, answer_authenticated, non_auth, reply_code)


class Parser:
    def parse(self, bytes_: bytes) -> Package:
        session = _ParsingSession(bytes_)

        return session.parse()


class Serializer:
    def serialize(self, package: Package) -> bytes:
        raise NotImplementedError
