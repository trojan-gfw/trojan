#!/usr/bin/env python3

import socket
import sys

from OpenSSL import crypto, SSL

def input_with_default(prompt, default):
    print('{} [{}]: '.format(prompt, default), file=sys.stderr, end='')
    line = input()
    return line if line else default

def main(argc, argv):
    if argc == 1:
        hostname = input_with_default('Enter hostname', 'example.com')
        port = int(input_with_default('Enter port number', '443'))
    elif argc == 2:
        hostname = argv[1]
        port = 443
    elif argc == 3:
        hostname = argv[1]
        port = int(argv[2])
    else:
        print('usage: {} [hostname] [port]'.format(argv[0]), file=sys.stderr)
        exit(1)
    with socket.create_connection((hostname, port)) as sock:
        ctx = SSL.Context(SSL.SSLv23_METHOD)
        ctx.set_verify(SSL.VERIFY_NONE, lambda *_: True)
        conn = SSL.Connection(ctx, sock)
        conn.set_connect_state()
        conn.set_tlsext_host_name(hostname.encode())
        conn.do_handshake()
        for cert in conn.get_peer_cert_chain():
            print(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode(), end='')
        conn.shutdown()

if __name__ == '__main__':
    main(len(sys.argv), sys.argv)
