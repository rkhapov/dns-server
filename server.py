import argparse
import socket
import dns

from cache import Cache


def parse_args():
    parser = argparse.ArgumentParser(description='simple dns server')
    parser.add_argument('--cache-file', required=False, default='cache.bin')

    return parser.parse_args()


class Client:
    pass


class Server:
    def __init__(self, cache: Cache):
        self.__cache = cache
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(('127.0.0.1', 53))
        self.__parser = dns.Parser()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.socket.close()

    def run(self):
        try:
            print('Server started')

            while True:
                bytes_, address = self.socket.recvfrom(2048)

                answer = self._handle_request(bytes_, address)

                self.socket.sendto(answer.to_bytes(), address)
        except KeyboardInterrupt:
            print('\nServer stopping...')

    def _handle_request(self, bytes_, address):
        try:
            package = self.__parser.parse(bytes_)
            query = package.queries[0]

            records = self.__cache.get(query.type, query.name)

            if records is None:
                self._resolve_query(query, bytes_)
                records = self.__cache.get(query.type, query.name)

            answers = []

            for record in records:
                answers.append(dns.Answer(query.type, query.name, record.ttl, record.value))

            return dns.Package(package.id,
                               dns.Flags(is_response=1, recursion_available=1, recursion_desired=1),
                               package.queries,
                               answers, [], [])

        except dns.ParserError as e:
            print(f'The package will be ignored: {e.message}')

    def _resolve_query(self, query: dns.Query, bytes_):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(bytes_, ('8.8.8.8', 53))

        ans = s.recv(2048)

        p = self.__parser.parse(ans)

        for answer in p.answers:
            self.__cache.put(answer.type, answer.name, answer.ttl, answer.data)

        for answer in p.authorities:
            self.__cache.put(answer.type, answer.name, answer.ttl, answer.data)

        for answer in p.additional:
            self.__cache.put(answer.type, answer.name, answer.ttl, answer.data)


def main():
    args = parse_args()

    with Cache(args.cache_file) as cache, Server(cache) as server:
        server.run()


if __name__ == '__main__':
    main()
