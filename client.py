from random import randint
from typing import List

import cache
import dns
import socket
import errno


class ClientError(Exception):
    def __init__(self, msg):
        self.__msg = msg

    @property
    def message(self):
        return self.__msg


class Client:
    def __init__(self, cache_: cache.Cache):
        self.cache = cache_
        self.__parser = dns.Parser()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def resolve_query(self, query: dns.Query, parent_server) -> List[dns.Answer]:
        records = self.cache.get(query.type, query.name)

        if records is None:
            print(f'There is no records for: {dns.Type(query.type).name} {query.name}. Resolving at {parent_server}...')
            self._resolve_query(query, parent_server)
            records = self.cache.get(query.type, query.name)

        answers = []

        for record in records:
            answers.append(dns.Answer(query.type, query.name, record.ttl, record.value))

        return answers

    def resolve(self, bytes_: bytes, parent_server) -> List[dns.Answer]:
        package = self.__parser.parse(bytes_)
        query = package.queries[0]

        records = self.cache.get(query.type, query.name)

        if records is None:
            self._resolve_bytes(bytes_, parent_server)
            records = self.cache.get(query.type, query.name)

        answers = []

        for record in records:
            answers.append(dns.Answer(query.type, query.name, record.ttl, record.value))

        return answers

    def _resolve_query(self, q: dns.Query, parent_server):
        p = dns.Package(randint(1, 2**16 - 1), dns.Flags(recursion_desired=1), [q], [], [], [])

        self._resolve_bytes(p.to_bytes(), parent_server)

    def _resolve_bytes(self, bytes_, parent_server):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(1)
            s.sendto(bytes_, parent_server)

            ans = s.recv(2048)

            p = self.__parser.parse(ans)

            print('Resolved. Now we know:')

            for answer in p.answers:
                self.cache.put(answer.type, answer.name, answer.ttl, answer.data)
                print(answer)

            for answer in p.authorities:
                self.cache.put(answer.type, answer.name, answer.ttl, answer.data)
                print(answer)

            for answer in p.additional:
                self.cache.put(answer.type, answer.name, answer.ttl, answer.data)
                print(answer)

        except socket.timeout:
            raise ClientError('Cant resolve request: is network unreachable?')
        except OSError as e:
            if e.errno == errno.ENETUNREACH:
                raise ClientError('Cant resolve: network is unreachable')
            raise e
