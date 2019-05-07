import argparse
import socket
import dns

from client import Client, ClientError
from cache import Cache


def parse_args():
    parser = argparse.ArgumentParser(description='simple dns server')
    parser.add_argument('--cache-file', required=False, default='cache.bin')

    return parser.parse_args()


class Server:
    def __init__(self, client: Client):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(('127.0.0.1', 53))
        self.client = client
        self.__parser = dns.Parser()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.socket.close()

    def run(self):
        try:
            print('Server started')

            while True:
                id_ = 0
                address = ('127.0.0.1', 1488)
                try:
                    bytes_, address = self.socket.recvfrom(2048)
                    id_ = int.from_bytes(bytes_[0:2], byteorder='big')

                    package = self.__parser.parse(bytes_)

                    print(f'Request: {package}\n>>>>>>>>>>>>>>>>>>')

                    if self.client.cache.get(package.queries[0].type, package.queries[0].name) is not None:
                        answers = []
                        for record in self.client.cache.get(package.queries[0].type, package.queries[0].name):
                            answers.append(
                                dns.Answer(package.queries[0].type, package.queries[0].name, record.ttl, record.value))
                    elif package.queries[0].type == dns.Type.A or package.queries[0].type == dns.Type.AAAA:
                        ns_answers = self.client.resolve_query(dns.Query(dns.Type.NS, package.queries[0].name),
                                                               ('8.8.8.8', 53))

                        answers = self.client.resolve_query(package.queries[0], (ns_answers[0].name_server, 53))
                    else:
                        answers = self.client.resolve_query(package.queries[0], ('8.8.8.8', 53))

                    answer_package = dns.Package(package.id,
                                                 dns.Flags(is_response=1, recursion_available=1, recursion_desired=1),
                                                 package.queries, answers, [], [])

                    print(f'\nAnswer to {package.id}:\n{answer_package}\n<<<<<<<<<<<<<<<<<')

                    self.socket.sendto(answer_package.to_bytes(), address)

                except ClientError as e:
                    print(f'Resolving error: {e}\nRequest will be ignored')
                    self.socket.sendto(
                        dns.Package(id_, dns.Flags(is_response=1, recursion_desired=1), [], [], [], []).to_bytes(),
                        address)
                except dns.ParserError as e:
                    print(f'Parser error: {e}\nRequest will be ignored')
                    self.socket.sendto(
                        dns.Package(id_, dns.Flags(is_response=1, recursion_desired=1), [], [], [], []).to_bytes(),
                        address)
        except KeyboardInterrupt:
            print('\nStopping server...')


def main():
    args = parse_args()

    with Cache(args.cache_file) as cache, \
            Client(cache) as client, \
            Server(client) as server:
        server.run()


if __name__ == '__main__':
    main()
