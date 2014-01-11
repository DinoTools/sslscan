#ifndef _PROBE_H
#define _PROBE_H

#include "main.h"
int testRenegotiation(struct sslCheckOptions *options, const SSL_METHOD *sslMethod);
int test_default_cipher(struct sslCheckOptions *options, const const SSL_METHOD *ssl_method);
int test_cipher(struct sslCheckOptions *options, struct sslCipher *sslCipherPointer);
int get_certificate(struct sslCheckOptions *options);
int testHost(struct sslCheckOptions *options);
int outputRenegotiation( struct sslCheckOptions *options, struct renegotiationOutput *outputData);
int freeRenegotiationOutput( struct renegotiationOutput *myRenOut );
void tls_reneg_init(struct sslCheckOptions *options);
int run_tests(struct sslCheckOptions *options);

#endif // ifndef _PROBE_H
