import argparse
import socket
import dns


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', 53))

    parser = dns.Parser()

    while True:
        bytes_, address = sock.recvfrom(2048)
        print(bytes_)


if __name__ == '__main__':
    main()
