/**
 * A simple HTTPS client using GnuTLS 3.6.10.
 *
 * Handles SNI, basic certificate validation (hostname match, expiration, trusted CA).
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netdb.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include <gnutls/gnutls.h>

#define BUFFER_SIZE  1024
#define DEFAULT_HOST "www.example.com"
#define DEFAULT_PORT "443"
#define REQUEST_TEMPLATE    \
    "GET / HTTP/1.1\r\n"    \
    "Host: %s\r\n"          \
    "Connection: close\r\n" \
    "\r\n"

/* This enforces at least 128-bit security level for the ciphersuite/algorithms, and
 * TLS version 1.3 or 1.2.
 *
 * This allows the use of SHA-1 and some other weak choices, but apparently some
 * servers still can't handle more security at once.
 */
#define PRIORITY_STRING "SECURE256:+SECURE128:-VERS-ALL:+VERS-TLS1.3:+VERS-TLS1.2"

/* Rudimentary error handling. */
#define GNUTLS_FAIL(x) do { \
        gnutls_perror(x); \
        if (x == GNUTLS_E_FATAL_ALERT_RECEIVED) { \
            int alert_code = gnutls_alert_get(session); \
            fprintf(stderr, "Received fatal alert (%d): %s\n", \
                    alert_code, gnutls_alert_get_name(alert_code)); \
        } \
        ret = 1; \
        goto cleanup; \
    } while (0)
#define GNUTLS_CHECK(x) if ((ret = (x)) < 0) { \
        GNUTLS_FAIL(ret); \
    }
#define CUSTOM_FAIL(error) do { \
        ret = 1; \
        fprintf(stderr, "Error: %s\n", error); \
        goto cleanup; \
    } while (0)


int main(int argc, char **argv) {
    /* Final return value of the program. */
    int ret = 0;

    /* The HTTP request string. */
    char *request = NULL;

    /* Name of the host and port number we're connecting to. */
    const char *hostname = DEFAULT_HOST;
    const char *port     = DEFAULT_PORT;

    /* TCP/IP socket descriptor. */
    int sock = -1;

    gnutls_certificate_credentials_t creds   = NULL;
    gnutls_session_t                 session = NULL;

    /* Parse command line options. */
    int opt;
    while ((opt = getopt(argc, argv, "p:")) != -1) {
        switch (opt) {
        case 'p':
            port = optarg;
            break;
        default:
            fprintf(stderr, "Usage: %s [-p port] [hostname]\n", argv[0]);
            return 1;
        }
    }

    if (optind == argc - 1) {
        hostname = argv[optind];
    } else if (optind < argc - 1) {
        fprintf(stderr, "Error: Too many arguments.\n");
        return 1;
    }

    /* Build the request string from the template and supplied (or default) hostname. */
    if (asprintf(&request, REQUEST_TEMPLATE, hostname) < 0) {
        request = NULL;
        CUSTOM_FAIL("Failed to allocate memory for request.");
    }

    GNUTLS_CHECK(gnutls_global_init());

    /* Initialize the SSL/TLS channel. */
    GNUTLS_CHECK(gnutls_init(&session, GNUTLS_CLIENT));
    
    /* Set requested server name for virtualized servers (SNI). */
    GNUTLS_CHECK(gnutls_server_name_set(session, GNUTLS_NAME_DNS, hostname, strlen(hostname)));

    /* Verify server certificate with default certificate authorities. */
    GNUTLS_CHECK(gnutls_certificate_allocate_credentials(&creds));
    GNUTLS_CHECK(gnutls_certificate_set_x509_system_trust(creds));
    GNUTLS_CHECK(gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, creds));
    gnutls_session_set_verify_cert(session, hostname, 0);

    /* Set default cipher suite priorities. */
    GNUTLS_CHECK(gnutls_priority_set_direct(session, PRIORITY_STRING, NULL));

    /* Connect to the server. */
    {
        struct addrinfo hints = { 0 };
        hints.ai_family   = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags    = AI_ADDRCONFIG | AI_NUMERICSERV;
        hints.ai_protocol = IPPROTO_TCP;

        struct addrinfo *result = NULL;

        if (getaddrinfo(hostname, port, &hints, &result) != 0 ||
                result == NULL)
        {
            CUSTOM_FAIL("Could not connect to the server.");
        }

        struct addrinfo *rr = result;
        while (rr != NULL) {
            sock = socket(rr->ai_family, rr->ai_socktype, rr->ai_protocol);
            if (sock >= 0) {
                break;
            }
            rr = rr->ai_next;
        }

        if (sock < 0) {
            CUSTOM_FAIL("Could not connect to the server.");
        }

        if (connect(sock, rr->ai_addr, rr->ai_addrlen) != 0) {
            CUSTOM_FAIL("Could not connect to the server.");
        }
    }

    /* Connect the socket and TLS channel. */
    gnutls_transport_set_int(session, sock);
    /* Set default timeout for the handshake. */
    gnutls_handshake_set_timeout(session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

    /* Attempt the TLS handshake. Some non-fatal errors are expected during the
     * process. We'll just ignore these and try again. */
    do {
        ret = gnutls_handshake(session);
    } while (ret < 0 && !gnutls_error_is_fatal(ret));

    if (ret < 0) {
        /* Print the specific error which occurred during certificate verification. */
        if (ret == GNUTLS_E_CERTIFICATE_VERIFICATION_ERROR) {
            gnutls_certificate_type_t cert_type = gnutls_certificate_type_get(session);
            unsigned status = gnutls_session_get_verify_cert_status(session);
            gnutls_datum_t out = { 0 };
            gnutls_certificate_verification_status_print(status, cert_type, &out, 0);
            fprintf(stderr, "Certificate verification failed: %s\n", out.data);
            gnutls_free(out.data);
        }
        GNUTLS_FAIL(ret);
    }

    GNUTLS_CHECK(gnutls_record_send(session, request, strlen(request)));

    /* Read the HTTP response and output it onto the standard output. */
    char buffer[BUFFER_SIZE + 1] = { 0 };
    while ((ret = gnutls_record_recv(session, buffer, BUFFER_SIZE)) > 0
            || ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED)
    {
        if (ret > 0) {
            fprintf(stderr, "Read %d bytes from server.\n", ret);
            /* fwrite(buffer, 1, ret, stdout); */
        }
    }

    assert(ret <= 0 && ret != GNUTLS_E_AGAIN && ret != GNUTLS_E_AGAIN);

    if (ret == 0) {
        fprintf(stderr, "EOF received from server.\n");
        GNUTLS_CHECK(gnutls_bye(session, GNUTLS_SHUT_RDWR));
    } else if (ret != GNUTLS_E_PREMATURE_TERMINATION) {
        /* We ignore premature termination as many servers optimise for performance
         * and seem not to care too much about standards. Moreover, all the data has
         * been transferred already.
         */
        GNUTLS_FAIL(ret);
    }

cleanup:
    if (sock >= 0) {
        close(sock);
    }
    if (creds != NULL) {
        gnutls_certificate_free_credentials(creds);
    }
    if (session != NULL) {
        gnutls_deinit(session);
    }
    if (request != NULL) {
        free(request);
    }
    gnutls_global_deinit();

    return ret;
}

