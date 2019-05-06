import argparse
import socket

from cache import Cache
from dns import Parser, ParserError, Package, Flags, Answer, Type


def parse_args():
    parser = argparse.ArgumentParser(description='simple dns server')
    parser.add_argument('--cache-file', required=False, default='cache.bin')

    return parser.parse_args()


class Server:
    def __init__(self, cache: Cache):
        self.__cache = cache
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(('127.0.0.1', 53))
        self.__parser = Parser()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.socket.close()

    def run(self):
        try:
            print('Server started')

            while True:
                bytes_, address = self.socket.recvfrom(2048)

                self._handle_request(bytes_, address)
        except KeyboardInterrupt:
            print('\nServer stopped')

    def _handle_request(self, bytes_, address):
        try:
            package = self.__parser.parse(bytes_)

            flags = Flags(is_response=1, opcode=0, authoritative=0, truncated=0, recursion_desired=1, recursion_available=1, z=0, answer_authenticated=0, non_auth=0, reply_code=0)
            ans = Package(flags, [], [Answer(Type.A, package.queries[0].name, 1488, '8.9.10.11')], [], [])

            self.socket.sendto(ans.to_bytes(), address)

        except ParserError as e:
            print(f'The package will be ignored: {e.message}')


def main():
    args = parse_args()

    with Cache(args.cache_file) as cache, Server(cache) as server:
        server.run()


if __name__ == '__main__':
    main()
