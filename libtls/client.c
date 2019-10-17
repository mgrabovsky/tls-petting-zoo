/**
 * A simple HTTPS client using LibreSSL 2.9.2.
 */
#include <stdio.h>
#include <stdlib.h>

#include <tls.h>

#define BUFFER_SIZE  1024
#define CA_FILE      "/etc/ssl/certs/ca-bundle.crt"
#define DEFAULT_HOST "www.example.com"
#define PORT         "443"
#define REQUEST_TEMPLATE    \
    "GET / HTTP/1.1\r\n"    \
    "Host: %s\r\n"          \
    "Connection: close\r\n" \
    "\r\n"

/* Convenience macros for error handling. */
#define LIBRESSL_CHECK(x) if ((x) != 0) { \
        fprintf(stderr, "Error on line %d: %s\n", __LINE__, tls_error(ctx)); \
        ret = 1; \
        goto cleanup; \
    }
#define LIBRESSL_CHECK_NULL(x) if ((x) == NULL) { \
        fprintf(stderr, "Error on line %d: %s\n", __LINE__, tls_error(ctx)); \
        ret = 1; \
        goto cleanup; \
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
    int request_len = 0;

    /* Name of the host we're connecting to. */
    const char *hostname = DEFAULT_HOST;

    /* TLS channel and socket connection structures. */
    struct tls        *ctx    = NULL;
    struct tls_config *config = NULL;

    /* Check number of arguments. Print usage message if they're wrong. */
    if (argc == 2) {
        hostname = argv[1];
    } else if (argc > 2) {
        fprintf(stderr, "Invalid number of arguments. Expected zero or one.\n");
        fprintf(stderr, "Usage: %s [hostname]\n", argv[0]);
        return 1;
    }

    /* Build the request string from the template and supplied (or default) hostname. */
    request_len = asprintf(&request, REQUEST_TEMPLATE, hostname);
    if (request_len < 0) {
        request = NULL;
        CUSTOM_FAIL("Failed to allocate memory for request.");
    }

    /* Create a configuration object using defualt settings. Among other things, this
     * enforces TLS 1.2 and certificate verification.
     */
    LIBRESSL_CHECK_NULL(config = tls_config_new());

    LIBRESSL_CHECK(tls_config_set_ca_file(config, CA_FILE));

    /* Initialise a TLS tunnel client-side context. */
    LIBRESSL_CHECK_NULL(ctx = tls_client());

    /* Apply the configuration settings to the object. */
    LIBRESSL_CHECK(tls_configure(ctx, config));

    /* Require a stapled OCSP response from the server (must-staple TLS extension).
     * Most servers don't send this.
     */
    /* tls_config_ocsp_require_stapling(config); */

    fprintf(stderr, "Attempting to connect to %s:%s...\n", hostname, PORT);
    LIBRESSL_CHECK(tls_connect(ctx, hostname, PORT));

    {
        /* Send the request to the server inside the TLS tunnel. */
        char *buffer = request;
        while (request_len > 0) {
            ret = tls_write(ctx, buffer, request_len);

            if (ret == TLS_WANT_POLLIN || ret == TLS_WANT_POLLOUT) {
                /* Try again. */
                continue;
            }
            if (ret == -1) {
                CUSTOM_FAIL(tls_error(ctx));
            }

            buffer += ret;
            request_len -= ret;
        }
    }

    {
        /* Receive server's response. */
        char buffer[BUFFER_SIZE + 1] = { 0 };
        while (1) {
            ret = tls_read(ctx, buffer, BUFFER_SIZE);

            if (ret == TLS_WANT_POLLIN || ret == TLS_WANT_POLLOUT) {
                /* Try again. */
                continue;
            }
            if (ret == -1) {
                CUSTOM_FAIL(tls_error(ctx));
            }
            if (ret == 0) {
                break;
            }

            fprintf(stderr, "Read %d bytes from server.\n", ret);
            /* fwrite(buffer, 1, ret, stdout); */
        }
    }

    do {
        ret = tls_close(ctx);
    } while (ret == TLS_WANT_POLLIN || ret == TLS_WANT_POLLOUT);

    LIBRESSL_CHECK(ret);

cleanup:
    if (ctx != NULL) {
        tls_free(ctx);
    }
    if (config != NULL) {
        tls_config_free(config);
    }
    if (request != NULL) {
        free(request);
    }

    return ret;
}

