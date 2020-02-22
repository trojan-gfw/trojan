#!/usr/bin/env python3

# This file is part of the trojan project.
# Trojan is an unidentifiable mechanism that helps you bypass GFW.
# Copyright (C) 2017-2020  The Trojan Authors.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

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
