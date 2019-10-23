#!/usr/bin/env python3

from argparse import ArgumentParser
import logging
import socket
import ssl
import sys

import OpenSSL.SSL as ssl

DEFAULT_HOSTNAME = 'www.example.com'
DEFAULT_PORT     = 443

BUFFER_SIZE      = 1024
REQUEST_TEMPLATE = (
        "GET / HTTP/1.1\r\n"
        "Host: {host}\r\n"
        "Connection: close\r\n"
        "\r\n")

from pprint import pprint

def verify_certificate(_tunnel, _cert, _error, _depth, ret):
    return ret

if __name__ == '__main__':
    parser = ArgumentParser(description='Simple HTTPS client.')
    parser.add_argument('host', metavar='HOST', default=DEFAULT_HOSTNAME, nargs='?',
            help='Address of the host to connect to. (Default: %(default)s)')
    parser.add_argument('-p', '--port', default=DEFAULT_PORT, type=int,
            help='The host\'s TCP port to connect to.')
    args = parser.parse_args()

    logging.basicConfig(stream=sys.stderr)
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)

    hostname, port = args.host, args.port

    with socket.create_connection((hostname, port)) as sock:
        logger.info('Socket connection established.')

        # Only allow TLS 1.2 or better.
        context = ssl.Context(ssl.TLSv1_2_METHOD)
        # Verify the server certificate during handshake. This should check for
        # possible expiration and validity of chain (trusted root and valid
        # intermediates).
        # NOTE: Does not check for hostname and IP match by default in current
        # version.
        context.set_verify(ssl.VERIFY_PEER | ssl.VERIFY_FAIL_IF_NO_PEER_CERT,
                verify_certificate)
        context.set_default_verify_paths()

        tunnel = ssl.Connection(context, sock)
        # SNI: Let the web server know which domain we inted to connect to.
        tunnel.set_tlsext_host_name(hostname.encode('ascii'))

        # Activate the TLS connection. This by itself does not initiate the
        # handshake.
        tunnel.set_connect_state()
        logger.info('TLS activated.')

        # We can perform the handshake manually if we choose to, but it's
        # unnecessary.
        try:
            tunnel.do_handshake()
        except ssl.Error:
            logger.error('Handshake failed.')
            sys.exit(1)

        logger.info('Negotiated TLS version: %s', tunnel.get_protocol_version_name())
        logger.info('Negotiated ciphersuite: %s', tunnel.get_cipher_name())

        # Send the HTTP request inside the tunnel. The handshake is now performed
        # behind the scenes.
        request = REQUEST_TEMPLATE.format(host=hostname).encode('ascii')
        tunnel.sendall(request)

        while True:
            try:
                bb = tunnel.recv(BUFFER_SIZE)
                if not bb:
                    break
                logger.info('Read %d bytes from server.', len(bb))
            except ssl.ZeroReturnError:
                logger.info('Server closed connection.')
                break

        tunnel.shutdown()
        logger.info('TLS shut down.')

    logger.info('Socket connection closed.')
