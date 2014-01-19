#ifndef MAIN_H
#define MAIN_H

// Includes...
#include <string.h>

// http://msdn.microsoft.com/en-us/library/b0084kay.aspx
#if defined(_WIN32) || defined(WIN32) || defined(__WIN32__) || defined(ming)
#define PLAT_WINDOWS 1
#endif

#if defined(__FreeBSD__)
#define PLAT_FREEBSD 1
#endif

// ToDo: check platform support
#include <sys/time.h>

#if defined(PLAT_WINDOWS)
#include <stdio.h>
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <basetsd.h>
#define snprintf(...) _snprintf(__VA_ARGS__)
#define close(s) closesocket(s)
DWORD dwError;
#else
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <fcntl.h>
#endif //PLAT_WINDOWS

#include <sys/stat.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#if defined(PLAT_WINDOWS)
#include <openssl/applink.c>
#endif //PLAT_WINDOWS

#ifdef PLAT_FREEBSD
#include <netinet/in.h>
#endif

#define PYTHON_SUPPORT
#ifdef PYTHON_SUPPORT
#include <Python.h>
#endif

// Defines...
#define false 0
#define true 1

#define mode_help 0
#define mode_version 1
#define mode_single 2
#define mode_multiple 3

#define BUFFERSIZE 1024

#define ssl_all 255
#define ssl_v2  1
#define ssl_v3  2
#define tls_v10 4
#define tls_v11 8
#define tls_v12 16

// force address family
#define FORCE_AF_UNSPEC 0
#define FORCE_AF_INET4 1
#define FORCE_AF_INET6 2


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

struct sslCheckOptions
{
	// Program Options...
	char host[512];
	char service[128];
	char localAddress[512];
	int bindLocalAddress;
	int forceAddressFamily;
	int noFailed;
	int reneg;
	int starttls_ftp;
	int starttls_imap;
	int starttls_pop3;
	int starttls_smtp;
	int starttls_xmpp;
	char *xmpp_domain;
	long int connection_delay;
	struct timeval connection_time;
	uint_fast8_t ssl_versions;
	char *targets;
	int pout;
	int sslbugs;
	int http;
	int verbose;

	// File Handles...
	FILE *xmlOutput;

	// TCP Connection Variables...
	struct addrinfo *addrList; // list of addresses found
	struct addrinfo *addrSelected; // address used
	struct addrinfo *localAddrList;
	struct addrinfo *localAddrSelected;

	// SSL Variables...
	SSL_CTX *ctx;
	struct sslCipher *ciphers;
	char *clientCertsFile;
	char *privateKeyFile;
	char *privateKeyPassword;
#ifdef PYTHON_SUPPORT
	PyObject *host_result;
	PyObject *py_output_handler;
	PyObject *py_service_handler;
#endif
};

// store renegotiation test data
struct renegotiationOutput
{
	int supported;
	int secure;
};

// Global comments:
// The comment style:
//   // Call foo()
//   foo()
// is crappy, but I haven't removed them unless I was otherwise reworking the
// code.

extern const char *RESET;
extern const char *COL_RED;
extern const char *COL_BLUE;
extern const char *COL_GREEN;

int run_tests(struct sslCheckOptions *options);

// from helper.c
void delay_connection(struct sslCheckOptions *options);
int fileExists(char *fileName);
int get_ssl_method_name(const SSL_METHOD *ssl_method, char *name, size_t len);
PyObject *new_client_result(struct sslCheckOptions *options);
PyObject *new_host_result();
int parseHostString(char *host, struct sslCheckOptions *options);
int populate_ciphers(struct sslCheckOptions *options, const SSL_METHOD *ssl_method);
int py_call_function(PyObject *py_obj, const char *name, PyObject *py_args, PyObject **py_result);
void readLine(FILE *input, char *lineFromFile, int maxSize);
int readOrLogAndClose(int fd, void* buffer, size_t len, const struct sslCheckOptions *options);
int timeval_substract(struct timeval *t1, struct timeval *t2, struct timeval *result);

#endif /* MAIN_H */
