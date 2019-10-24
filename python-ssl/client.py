#!/usr/bin/env python3
from argparse import ArgumentParser
import logging
import socket
import ssl
import sys

DEFAULT_HOSTNAME = 'www.example.com'
DEFAULT_PORT     = 443

BUFFER_SIZE      = 1024
REQUEST_TEMPLATE = (
        "GET / HTTP/1.1\r\n"
        "Host: {host}\r\n"
        "Connection: close\r\n"
        "\r\n")

if __name__ == '__main__':
    parser = ArgumentParser(description='Simple HTTPS client.')
    parser.add_argument('host', metavar='HOST', default=DEFAULT_HOSTNAME, nargs='?',
            help='Address of the host to connect to. (Default: %(default)s)')
    parser.add_argument('-p', '--port', default=DEFAULT_PORT, type=int,
            help='The host\'s TCP port to connect to.')
    args = parser.parse_args()

    logging.basicConfig(stream=sys.stderr)
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)

    hostname, port = args.host, args.port

    # Create a context for the TLS tunnel context.
    context = ssl.create_default_context()
    # Disallow SSL and TLS < 1.2.
    context.options |= (ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 |
                        ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1)

    # Connect to the server via a simple TCP socket.
    with socket.create_connection((hostname, port)) as sock:
        logger.info('Socket connection established.')

        try:
            # Establish a TLS tunnel inside the pure socket. The underlying OpenSSL
            # performs hostname checking and certificate validation by default.
            # Revocation status is not checked.
            with context.wrap_socket(sock, server_hostname=hostname) as tunnel:
                logger.info('TLS tunnel established.')
                # Print negotiated TLS version.
                negotiated = tunnel.cipher()
                logger.info('Negotiated TLS version: %s', negotiated[1])
                logger.info('Negotiated ciphersuite: %s', negotiated[0])

                # Create the HTTP from the template and send it to the server.
                request = REQUEST_TEMPLATE.format(host=hostname).encode('ascii')
                try:
                    # Note: We have to use sendall() in order to send the whole
                    # request in on go rather than send() which may (or may not) send
                    # the request in chunks.
                    tunnel.sendall(request)
                    # NOTE: read() and write() are deprecated in favour of recv() and
                    # send() which are native to sockets.
                except:
                    # TODO: Which specific exception is raised? No info in doc or
                    # direct source code.
                    logger.error('Could not send HTTPS request.')
                    sys.exit(1)

                # Read data from the tunnel until EOF
                while True:
                    #print(tunnel.recv(BUFFER_SIZE).decode('utf-8'))
                    bb = tunnel.recv(BUFFER_SIZE)
                    if not bb:
                        break
                    logger.info('Read %d bytes from server.', len(bb))

            logger.info('TLS tunnel closed.')
        except ssl.SSLCertVerificationError as e:
            logger.error('Certificate verification failed: %s', e)
            sys.exit(1)

    logger.info('Socket connection closed.')

