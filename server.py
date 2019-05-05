import argparse
import socket
import dns


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('127.0.0.1', 53))

    parser = dns.Parser()

    while True:
        query, client = sock.recvfrom(2048)

        s2.sendto(query, ('8.8.8.8', 53))

        answer, _ = s2.recvfrom(2048)

        print(parser.parse(answer))

        sock.sendto(answer, client)


if __name__ == '__main__':
    main()
