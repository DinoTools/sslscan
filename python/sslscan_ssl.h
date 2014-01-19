#ifndef _SSLSCAN_SSL_H
#define _SSLSCAN_SSL_H
#include <Python.h>
#include <openssl/ssl.h>

typedef struct {
	PyObject_HEAD
	X509 *x509;
	EVP_PKEY *key;
} sslscan_ssl_pkey_obj;

typedef struct {
	PyObject_HEAD
	X509 *x509;
} sslscan_ssl_x509_obj;

typedef struct {
	PyObject_HEAD
	X509_EXTENSION *extension;
} sslscan_ssl_x509ext_obj;

extern PyTypeObject sslscan_ssl_pkey_Type;
extern PyTypeObject sslscan_ssl_x509_Type;
extern PyTypeObject sslscan_ssl_x509ext_Type;

#endif
