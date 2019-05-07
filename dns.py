import enum
import struct
import byteprint
import itertools

from typing import Tuple, List


class Type(enum.IntEnum):
    A = 1
    NS = 2
    AAAA = 28
    PTR = 12


class Class(enum.IntEnum):
    IN = 1


SUPPORTED_TYPES = set(Type)
SUPPORTED_CLASSES = set(Class)


def _name_to_bytes(name) -> bytes:
    b = bytearray()

    for p in name.split('.'):
        b.append(len(p))
        b.extend(p.encode())

    b.append(0)

    return bytes(b)


class Query:
    def __init__(self, type_: Type, name):
        self.type = type_
        self.name = name

    def __str__(self):
        return f'{Type(self.type).name}, {self.name}'

    def to_bytes(self) -> bytes:
        b = bytearray()

        b.extend(_name_to_bytes(self.name))
        b.extend(struct.pack('! H H', self.type, Class.IN))

        return bytes(b)


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

    def __str__(self):
        return f'{Type(self.type).name} {self.name} {self.ttl} {self.data}'

    def to_bytes(self) -> bytes:
        b = bytearray()

        b.extend(_name_to_bytes(self.name))

        if self.type == Type.A:
            data_length = 4
            data = bytes(map(lambda x: int(x), self.data.split('.')))
        elif self.type == Type.AAAA:
            data_length = 16
            data = bytes(map(lambda x: int(x), self.data.split(':')))
        elif self.type == Type.PTR or self.type == Type.NS:
            data = _name_to_bytes(self.data)
            data_length = len(data)
        else:
            raise NotImplementedError

        b.extend(struct.pack('! H H I H', self.type, Class.IN, self.ttl, data_length))
        b.extend(data)

        return bytes(b)


class Flags:
    def __init__(self, is_response=0, opcode=0,
                 authoritative=0, truncated=0, recursion_desired=0,
                 recursion_available=0, z=0, answer_authenticated=0,
                 non_auth=0, reply_code=0):
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

    def to_int(self):
        b = 0

        b |= self.is_response << 15
        b |= self.opcode << 11
        b |= self.authoritative << 10
        b |= self.truncated << 9
        b |= self.recursion_desired << 8
        b |= self.recursion_available << 7
        b |= self.z << 6
        b |= self.answer_authenticated << 5
        b |= self.non_auth << 4
        b |= self.reply_code

        return b

    def __str__(self):
        p = []

        if self.is_response:
            p.append('r')

        if self.authoritative:
            p.append('a')

        if self.truncated:
            p.append('t')

        if self.recursion_desired:
            p.append('rd')

        if self.recursion_available:
            p.append('ra')

        return ' '.join(p)
        #
        # return \
        #     f'Is response: {self.is_response}\n' \
        #         f'Opcode: {self.opcode}\n' \
        #         f'Authoritative: {self.authoritative}\n' \
        #         f'Truncated: {self.truncated}\n' \
        #         f'Recursion desired: {self.recursion_desired}\n' \
        #         f'Recursion available: {self.recursion_available}\n' \
        #         f'Z: {self.z}\n' \
        #         f'Answer authenticated: {self.answer_authenticated}\n' \
        #         f'Non-authenticated data: {self.non_auth}\n' \
        #         f'Reply code: {self.reply_code}'


class Package:
    def __init__(self, id_, flags: Flags, queries: List[Query], answers: List[Answer],
                 authorities: List[Answer], additional: List[Answer]):
        self.id = id_
        self.flags = flags
        self.queries = queries
        self.answers = answers
        self.authorities = authorities
        self.additional = additional

    def __str__(self):
        s = f'id: {self.id} flags: {self.flags}\n'

        if len(self.queries) != 0:
            s += 'Queries:\n  '
            s += '\n  '.join(map(str, self.queries))

        if len(self.answers) != 0:
            s += '\nAnswers:\n  '
            s += '\n  '.join(map(str, self.answers))

        if len(self.authorities) != 0:
            s += '\nAuthorities:\n  '
            s += '\n  '.join(map(str, self.authorities))

        if len(self.additional) != 0:
            s += '\nAdditional:\n  '
            s += '\n  '.join(map(str, self.additional))

        return s

    def to_bytes(self) -> bytes:
        b = bytearray()

        b.extend(struct.pack('! H H H H H H', self.id, self.flags.to_int(), len(self.queries), len(self.answers),
                             len(self.authorities), len(self.additional)))

        for q in itertools.chain(self.queries, self.answers, self.authorities, self.additional):
            b.extend(q.to_bytes())

        return bytes(b)


class ParserError(Exception):
    def __init__(self, msg):
        super().__init__(msg)
        self.__msg = msg

    @property
    def message(self):
        return self.__msg


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

        return Package(id_, flags, queries, answers, authoritative, additional)

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
            data = self._to_address(self.bytes[offset: offset + data_length])
            offset += data_length
        elif type_ == Type.NS or type_ == Type.PTR:
            offset, data = self._read_string(offset)
        else:
            raise NotImplementedError(f'Not implemented read answer for type: {type_}')

        return offset, Answer(type_, name, ttl, data)

    def _to_address(self, bytes_):
        if len(bytes_) == 4:
            return byteprint.to_ipv4_address(bytes_)

        if len(bytes_) == 16:
            return byteprint.to_ipv6_address(bytes_)

        raise NotImplementedError(f"Unexpected bytes to parse address: {len(bytes_)}")

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

            offset += 1
            part = self.bytes[offset: offset + length].decode()
            offset += length
            parts.append(part)

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
