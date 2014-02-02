#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#ifndef _SSLSCAN_H
#define _SSLSCAN_H

// http://msdn.microsoft.com/en-us/library/b0084kay.aspx
#if defined(_WIN32) || defined(WIN32) || defined(__WIN32__) || defined(ming)
#define PLAT_WINDOWS 1
#endif

#if defined(__FreeBSD__)
#define PLAT_FREEBSD 1
#endif

#define SSLSCAN_CIPHER_STATUS_UNKNOWN  0
#define SSLSCAN_CIPHER_STATUS_FAILED   1
#define SSLSCAN_CIPHER_STATUS_REJECTED 2
#define SSLSCAN_CIPHER_STATUS_ACCEPTED 3

struct ssl_alert_info {
	int ret;
	struct ssl_alert_info *next;
};

struct sslCipher
{
	// Cipher Properties...
	const char *name;
	char *version;
	int bits;
	int alg_bits;
	char description[512];
	const SSL_METHOD *sslMethod;
	struct sslCipher *next;
};

int get_ssl_method_name(const SSL_METHOD *ssl_method, char *name, size_t len);

#endif