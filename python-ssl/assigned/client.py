#!/usr/bin/env python3
from argparse import ArgumentParser
import logging
import socket
import ssl
import sys

BUFFER_SIZE      = 1024
DEFAULT_HOSTNAME = 'www.example.com'
DEFAULT_PORT     = 443
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

    # Connect to the server via a simple TCP socket.
    with socket.create_connection((hostname, port)) as sock:
        logger.info('Socket connection established.')

        try:
            # Establish a TLS tunnel inside the pure socket. The underlying OpenSSL
            # performs hostname checking and certificate validation by default.
            # Revocation status is not checked.
            with ssl.wrap_socket(sock) as tunnel:
                logger.info('TLS tunnel established.')
                # Print negotiated TLS version.
                negotiated = tunnel.cipher()
                logger.info('Negotiated TLS version: %s', negotiated[1])
                logger.info('Negotiated ciphersuite: %s', negotiated[0])

                # Create the HTTP from the template and send it to the server.
                request = REQUEST_TEMPLATE.format(host=hostname).encode('ascii')
                try:
                    tunnel.sendall(request)
                except:
                    logger.error('Could not send HTTPS request.')
                    sys.exit(1)

                # Read data from the tunnel until EOF
                while True:
                    bytes_read = tunnel.recv(BUFFER_SIZE)
                    if not bytes_read:
                        break
                    logger.info('Read %d bytes from server.', len(bytes_read))
                    sys.stdout.buffer.write(bytes_read)

            logger.info('TLS tunnel closed.')
        except ssl.SSLCertVerificationError as e:
            logger.error('Certificate verification failed: %s', e)
            sys.exit(1)

    logger.info('Socket connection closed.')

