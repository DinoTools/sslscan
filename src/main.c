/***************************************************************************
 *   sslscan - A SSL cipher scanning tool                                  *
 *   Copyright 2007-2009 by Ian Ventura-Whiting (Fizz)                     *
 *   fizz@titania.co.uk                                                    *
 *   Copyright 2010 by Michael Boman (michael@michaelboman.org)            *
 *   Copyleft 2010 by Jacob Appelbaum <jacob@appelbaum.net>                *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 3 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program. If not, see <http://www.gnu.org/licenses/>.  *
 *                                                                         *
 *   In addition, as a special exception, the copyright holders give       *
 *   permission to link the code of portions of this program with the      *
 *   OpenSSL library under certain conditions as described in each         *
 *   individual source file, and distribute linked combinations            *
 *   including the two.                                                    *
 *   You must obey the GNU General Public License in all respects          *
 *   for all of the code used other than OpenSSL.  If you modify           *
 *   file(s) with this exception, you may extend this exception to your    *
 *   version of the file(s), but you are not obligated to do so.  If you   *
 *   do not wish to do so, delete this exception statement from your       *
 *   version.  If you delete this exception statement from all source      *
 *   files in the program, then also delete it here.                       *
 ***************************************************************************/

/*
 * OpenSSL features: http://www.openssl.org/news/changelog.html
 *
 * Initial TLS 1.1 and 1.2 support
 * - 1.0.0h -> 1000008fL
 * - 1.0.1  -> 1000100fL
 */

#include "main.h"

// Colour Console Output...
#if !defined(PLAT_WINDOWS)
// Always better to do "const char RESET[] = " because it saves relocation records.
const char *RESET = "[0m";            // DEFAULT
const char *COL_RED = "[31m";     // RED
const char *COL_BLUE = "[34m";        // BLUE
const char *COL_GREEN = "[32m";   // GREEN
#else
const char *RESET = "";
const char *COL_RED = "";
const char *COL_BLUE = "";
const char *COL_GREEN = "";
#endif

const char *program_banner = 	"                   _\n"
				"           ___ ___| |___  ___ __ _ _ __\n"
				"          / __/ __| / __|/ __/ _` | '_ \\\n"
				"          \\__ \\__ \\ \\__ \\ (_| (_| | | | |\n"
				"          |___/___/_|___/\\___\\__,_|_| |_|\n\n";
const char *program_version = "sslscan version 1.10.0 ";
const char *xml_version = "1.10.0";

/**
 * Print the help text.
 */
void print_help(char *prog_name)
{
	// Program version banner...
	printf("%s%s%s\n", COL_BLUE, program_banner, RESET);
	printf("SSLScan is a fast SSL port scanner. SSLScan connects to SSL\n");
	printf("ports and determines what  ciphers are supported, which are\n");
	printf("the servers  preferred  ciphers,  which  SSL  protocols  are\n");
	printf("supported  and   returns  the   SSL   certificate.   Client\n");
	printf("certificates /  private key can be configured and output is\n");
	printf("to text / XML.\n\n");
	printf("%sCommand:%s\n", COL_BLUE, RESET);
	printf("  %s%s [Options] [host:port | host]%s\n\n", COL_GREEN, prog_name, RESET);
	printf("%sOptions:%s\n", COL_BLUE, RESET);
	printf("  %s--targets=<file>%s     A file containing a list of hosts to\n", COL_GREEN, RESET);
	printf("                       check.  Hosts can  be supplied  with\n");
	printf("                       ports (i.e. host:port).\n");
	printf("  %s--ipv4%s               Force IPv4\n", COL_GREEN, RESET);
	printf("  %s--ipv6%s               Force IPv6\n", COL_GREEN, RESET);
	printf("  %s--localip=<ip>%s       Local IP from which connection should be made\n", COL_GREEN, RESET);
	printf("  %s--connection_delay=<N>%s\n", COL_GREEN, RESET);
	printf("                       Wait N milliseconds between each connection.\n");
	printf("  %s--no-failed%s          List only accepted ciphers  (default\n", COL_GREEN, RESET);
	printf("                       is to listing all ciphers).\n");
#ifndef OPENSSL_NO_SSL2
	printf("  %s--ssl2%s               Only check SSLv2 ciphers.\n", COL_GREEN, RESET);
#endif // #ifndef OPENSSL_NO_SSL2
	printf("  %s--ssl3%s               Only check SSLv3 ciphers.\n", COL_GREEN, RESET);
	printf("  %s--tls1%s               Only check TLSv1 ciphers.\n", COL_GREEN, RESET);
#if OPENSSL_VERSION_NUMBER >= 0x1000008fL || OPENSSL_VERSION_NUMBER >= 0x1000100fL
	printf("  %s--tls11%s              Only check TLSv11 ciphers.\n", COL_GREEN, RESET);
	printf("  %s--tls12%s              Only check TLSv12 ciphers.\n", COL_GREEN, RESET);
#endif // #if OPENSSL_VERSION_NUMBER >= 0x1000008fL || OPENSSL_VERSION_NUMBER >= 0x1000100fL
	printf("  %s--no_ssl2%s            Exclude SSLv2 chiphers.\n", COL_GREEN, RESET);
	printf("  %s--no_ssl3%s            Exclude SSLv3 chiphers.\n", COL_GREEN, RESET);
	printf("  %s--no_tls1%s            Exclude TLSv1 chiphers.\n", COL_GREEN, RESET);
	printf("  %s--no_tls11%s           Exclude TLSv11 chiphers.\n", COL_GREEN, RESET);
	printf("  %s--no_tls12%s           Exclude TLSv12 chiphers.\n", COL_GREEN, RESET);
	printf("  %s--pk=<file>%s          A file containing the private key or\n", COL_GREEN, RESET);
	printf("                       a PKCS#12  file containing a private\n");
	printf("                       key/certificate pair (as produced by\n");
	printf("                       MSIE and Netscape).\n");
	printf("  %s--pkpass=<password>%s  The password for the private  key or\n", COL_GREEN, RESET);
	printf("                       PKCS#12 file.\n");
	printf("  %s--certs=<file>%s       A file containing PEM/ASN1 formatted\n", COL_GREEN, RESET);
	printf("                       client certificates.\n");
	printf("  %s--renegotiation%s      Attempt TLS renegotiation\n", COL_GREEN, RESET);
	printf("  %s--starttls-ftp%s       STARTTLS setup for FTP\n", COL_GREEN, RESET);
	printf("  %s--starttls-imap%s      STARTTLS setup for IMAP\n", COL_GREEN, RESET);
	printf("  %s--starttls-pop3%s      STARTTLS setup for POP3\n", COL_GREEN, RESET);
	printf("  %s--starttls-smtp%s      STARTTLS setup for SMTP\n", COL_GREEN, RESET);
	printf("  %s--starttls-xmpp%s      STARTTLS setup for XMPP\n", COL_GREEN, RESET);
	printf("  %s--xmpp-domain=<domain>%s Specify this if the XMPP domain is different from the hostname\n", COL_GREEN, RESET);
	printf("  %s--http%s               Test a HTTP connection.\n", COL_GREEN, RESET);
	printf("  %s--bugs%s               Enable SSL implementation  bug work-\n", COL_GREEN, RESET);
	printf("                       arounds.\n");
	printf("  %s--xml=<file>%s         Output results to an XML file.\n", COL_GREEN, RESET);
	printf("  %s--version%s            Display the program version.\n", COL_GREEN, RESET);
	printf("  %s--verbose%s            Display verbose output.\n", COL_GREEN, RESET);
	printf("  %s--help%s               Display the  help text  you are  now\n", COL_GREEN, RESET);
	printf("                       reading.\n");
	printf("  %s--help-output=<name>%s Print help for a single output handler and exit\n", COL_GREEN, RESET);
	printf("  %s--help-outputs%s       Print help for all output handlers and exit\n", COL_GREEN, RESET);
	printf("  %s--help-output-list%s   List all output handlers with a short description\n", COL_GREEN, RESET);
	printf("\n");
	printf("%sExamples:%s\n", COL_BLUE, RESET);
	printf("  %s%s 127.0.0.1%s\n", COL_GREEN, prog_name, RESET);
	printf("  %s%s 127.0.0.1:443%s\n", COL_GREEN, prog_name, RESET);
	printf("  %s%s [::1]%s\n", COL_GREEN, prog_name, RESET);
	printf("  %s%s [::1]:443%s\n\n", COL_GREEN, prog_name, RESET);
}

/**
 * Print the version.
 */
void print_version()
{
	printf("%s\t\t%s\n\t\t%s\n%s\n", COL_BLUE, program_version, SSLeay_version(SSLEAY_VERSION), RESET);
}

/**
 * Adds Ciphers to the Cipher List structure
 *
 * @param options Options for this run
 * @param ssl_method SSL method to populate ciphers for.
 * @return Boolean: true = success | false = error
 */
int populate_ciphers(struct sslCheckOptions *options, const SSL_METHOD *ssl_method)
{
	struct sslCipher *cipher_ptr;
	int tmp_int;
	int i;
	// STACK_OF is a sign that you should be using C++ :)
	STACK_OF(SSL_CIPHER) *cipher_list;
	SSL_CTX *ctx;
	SSL *ssl = NULL;

	ctx = SSL_CTX_new(ssl_method);
	if (ctx == NULL) {
		printf("%sERROR: Could not create CTX object.%s\n", COL_RED, RESET);
		return false;
	}

	SSL_CTX_set_cipher_list(ctx, "ALL:COMPLEMENTOFALL");

	ssl = SSL_new(ctx);
	if (ssl == NULL) {
		printf("%sERROR: Could not create SSL object.%s\n", COL_RED, RESET);
		SSL_CTX_free(ctx);
		return false;
	}

	cipher_list = SSL_get_ciphers(ssl);

	if (options->ciphers != NULL) {
		cipher_ptr = options->ciphers;
		while (cipher_ptr->next != NULL)
			cipher_ptr = cipher_ptr->next;
	}

	// Create Cipher Struct Entries...
	for (i = 0; i < sk_SSL_CIPHER_num(cipher_list); i++) {
		if (options->ciphers == NULL) {
			options->ciphers = malloc(sizeof(struct sslCipher));
			cipher_ptr = options->ciphers;
		} else {
			cipher_ptr->next = malloc(sizeof(struct sslCipher));
			cipher_ptr = cipher_ptr->next;
		}

		memset(cipher_ptr, 0, sizeof(struct sslCipher));
		cipher_ptr->next = NULL;

		// Add cipher information...
		cipher_ptr->sslMethod = ssl_method;
		cipher_ptr->name = SSL_CIPHER_get_name(sk_SSL_CIPHER_value(cipher_list, i));
		cipher_ptr->version = SSL_CIPHER_get_version(sk_SSL_CIPHER_value(cipher_list, i));
		SSL_CIPHER_description(sk_SSL_CIPHER_value(cipher_list, i), cipher_ptr->description, sizeof(cipher_ptr->description) - 1);
		cipher_ptr->bits = SSL_CIPHER_get_bits(sk_SSL_CIPHER_value(cipher_list, i), &tmp_int);
	}

	SSL_free(ssl);
	SSL_CTX_free(ctx);

	return true;
}

/**
 * Initialize OpenSSL
 * - Add algorithms
 * - Load strings
 * - populate ciphers
 */
void init_ssl(struct sslCheckOptions *options)
{
	SSLeay_add_all_algorithms();
	ERR_load_crypto_strings();

	// Build a list of ciphers...
#ifndef OPENSSL_NO_SSL2
	if (options->ssl_versions & ssl_v2)
		populate_ciphers(options, SSLv2_client_method());
#endif
	if (options->ssl_versions & ssl_v3)
		populate_ciphers(options, SSLv3_client_method());

	if (options->ssl_versions & tls_v10)
		populate_ciphers(options, TLSv1_client_method());

#if OPENSSL_VERSION_NUMBER >= 0x1000008fL || OPENSSL_VERSION_NUMBER >= 0x1000100fL
	if (options->ssl_versions & tls_v11)
		populate_ciphers(options, TLSv1_1_client_method());
	if (options->ssl_versions & tls_v12)
		populate_ciphers(options, TLSv1_2_client_method());
#endif // #if OPENSSL_VERSION_NUMBER >= 0x1000008fL || OPENSSL_VERSION_NUMBER >= 0x1000100fL
}

int main(int argc, char *argv[])
{
	// Variables...
	struct sslCheckOptions options;
	struct sslCipher *sslCipherPointer;
	int status=0;
	int argLoop;
	int xmlArg;
	int mode = mode_help;

	// Init...
	memset(&options, 0, sizeof(struct sslCheckOptions));
	xmlArg = 0;
	strcpy(options.host, "127.0.0.1");
	options.service[0] = '\0';
	options.bindLocalAddress = false;
	options.forceAddressFamily = FORCE_AF_UNSPEC;
	options.noFailed = false;
	options.reneg = false;
	options.starttls_ftp = false;
	options.starttls_imap = false;
	options.starttls_pop3 = false;
	options.starttls_smtp = false;
	options.starttls_xmpp = false;
	options.verbose = false;
	options.targets = NULL;
	options.connection_delay = 0;
	options.connection_time.tv_sec = 0;
	options.connection_time.tv_usec = 0;

	options.ssl_versions = ssl_all;
	options.pout = false;
	SSL_library_init();

#ifdef PYTHON_SUPPORT
	wchar_t progname[255 + 1];
	mbstowcs(progname, argv[0], strlen(argv[0]) + 1);
	Py_SetProgramName(progname);
	Py_Initialize();
	PyObject *py_tmp = PySys_GetObject("path");
	//PyList_Append(py_tmp, PyUnicode_FromString("./python"));
	PyObject *py_module = PyImport_ImportModule("sslscan");
	if (py_module == NULL) {
		PyErr_Print();
		// ToDo:
		return 1;
	}

	PyObject *py_func = PyObject_GetAttrString(py_module, "load_handlers");
	if(py_func == NULL) {
		PyErr_Print();
		// ToDo:
		return 1;
	}
	PyObject *py_args = PyTuple_New(0);
	PyObject *py_result = PyObject_CallObject(py_func, py_args);

	if(py_result == NULL) {
		PyErr_Print();
		// ToDo:
		return 1;
	}
	options.py_output_handler = PyObject_GetAttrString(py_module, "output");
	options.py_service_handler = PyObject_GetAttrString(py_module, "service");
#endif

	// Get program parameters
	for (argLoop = 1; argLoop < argc; argLoop++)
	{
		if (strcmp("--help", argv[argLoop]) == 0) {
			print_help(argv[0]);
			return 0;
		} else if ((strncmp("--help-output=", argv[argLoop], 14) == 0) && (strlen(argv[argLoop]) > 14)) {
			py_tmp = Py_BuildValue("(s)", argv[argLoop] + 14);
			return py_call_function(options.py_output_handler, "print_help", py_tmp, NULL);
		} else if (strcmp("--help-outputs", argv[argLoop]) == 0) {
			return py_call_function(options.py_output_handler, "print_help", NULL, NULL);
		} else if (strcmp("--help-output-list", argv[argLoop]) == 0) {
			return py_call_function(options.py_output_handler, "print_list", NULL, NULL);
		} else if ((strncmp("--targets=", argv[argLoop], 10) == 0) && (strlen(argv[argLoop]) > 10)) {
			options.targets = argv[argLoop] + 10;
		}

		// force IPv4 or IPv6
		else if ((strcmp("--ipv4", argv[argLoop]) == 0))
			options.forceAddressFamily = FORCE_AF_INET4;

		else if ((strcmp("--ipv6", argv[argLoop]) == 0))
			options.forceAddressFamily = FORCE_AF_INET6;

		// localip
		else if ((strncmp("--localip=", argv[argLoop], 10) == 0) && (strlen(argv[argLoop]) > 10))
		{
			options.bindLocalAddress = true;
			strncpy(options.localAddress, argv[argLoop] + 10, sizeof(options.localAddress));
		} else if ((strncmp("--connection_delay=", argv[argLoop], 19) == 0) && (strlen(argv[argLoop]) > 19)) {
			options.connection_delay = strtol(argv[argLoop] + 19, NULL, 10);
		}

		// Show only supported
		else if (strcmp("--no-failed", argv[argLoop]) == 0)
			options.noFailed = true;

		// Version
		else if (strcmp("--version", argv[argLoop]) == 0) {
			print_version();
			return 0;
		}

		// XML Output
		else if (strncmp("--xml=", argv[argLoop], 6) == 0)
			xmlArg = argLoop;

		// Verbose
		else if (strcmp("--verbose", argv[argLoop]) == 0)
			options.verbose = true;

		// P Output
		else if (strcmp("-p", argv[argLoop]) == 0)
			options.pout = true;

		// Client Certificates
		else if (strncmp("--certs=", argv[argLoop], 8) == 0)
			options.clientCertsFile = argv[argLoop] +8;

		// Private Key File
		else if (strncmp("--pk=", argv[argLoop], 5) == 0)
			options.privateKeyFile = argv[argLoop] +5;

		// Private Key Password
		else if (strncmp("--pkpass=", argv[argLoop], 9) == 0)
			options.privateKeyPassword = argv[argLoop] +9;

		// Should we check for TLS renegotiation?
		else if (strcmp("--renegotiation", argv[argLoop]) == 0)
		{
			options.reneg = true;
		}

		// StartTLS... FTP
		else if (strcmp("--starttls-ftp", argv[argLoop]) == 0)
		{
			options.ssl_versions = tls_v10;
			options.starttls_ftp = true;
		}
		// StartTLS... IMAP
		else if (strcmp("--starttls-imap", argv[argLoop]) == 0)
		{
			options.ssl_versions = tls_v10;
			options.starttls_imap = true;
		}
		// StartTLS... POP3
		else if (strcmp("--starttls-pop3", argv[argLoop]) == 0)
		{
			options.ssl_versions = tls_v10;
			options.starttls_pop3 = true;
		}
		// StartTLS... SMTP
		else if (strcmp("--starttls-smtp", argv[argLoop]) == 0)
		{
			options.ssl_versions = tls_v10;
			options.starttls_smtp = true;
		}
		// StartTLS... XMPP
		else if (strcmp("--starttls-xmpp", argv[argLoop]) == 0)
		{
			options.ssl_versions = tls_v10;
			options.starttls_xmpp = true;
		}
		// XMPP... Domain
		else if (strncmp("--xmpp-domain=", argv[argLoop], 14) == 0)
		{
			options.xmpp_domain = argv[argLoop] +14;

#ifndef OPENSSL_NO_SSL2
		} else if (strcmp("--ssl2", argv[argLoop]) == 0) {
			options.ssl_versions = ssl_v2;
#endif // #ifndef OPENSSL_NO_SSL2

		} else if (strcmp("--ssl3", argv[argLoop]) == 0) {
			options.ssl_versions = ssl_v3;
		} else if (strcmp("--tls1", argv[argLoop]) == 0) {
			options.ssl_versions = tls_v10;

#if OPENSSL_VERSION_NUMBER >= 0x1000008fL || OPENSSL_VERSION_NUMBER >= 0x1000100fL
		} else if (strcmp("--tls11", argv[argLoop]) == 0) {
			options.ssl_versions = tls_v11;
		} else if (strcmp("--tls12", argv[argLoop]) == 0) {
			options.ssl_versions = tls_v12;
#endif // #if OPENSSL_VERSION_NUMBER >= 0x1000008fL || OPENSSL_VERSION_NUMBER >= 0x1000100fL

		} else if (strcmp("--no_ssl2", argv[argLoop]) == 0) {
			options.ssl_versions &= ~ssl_v2;
		} else if (strcmp("--no_ssl3", argv[argLoop]) == 0) {
			options.ssl_versions &= ~ssl_v3;
		} else if (strcmp("--no_tls1", argv[argLoop]) == 0) {
			options.ssl_versions &= ~tls_v10;
		} else if (strcmp("--no_tls11", argv[argLoop]) == 0) {
			options.ssl_versions &= ~tls_v11;
		} else if (strcmp("--no_tls12", argv[argLoop]) == 0) {
			options.ssl_versions &= ~tls_v12;

		} else if (strcmp("--bugs", argv[argLoop]) == 0)
			options.sslbugs = 1;

		// SSL HTTP Get...
		else if (strcmp("--http", argv[argLoop]) == 0) {
			options.http = 1;

#ifdef PYTHON_SUPPORT
		} else if (strncmp("--output=", argv[argLoop], 9) == 0) {
			if(options.py_output_handler == NULL) {
				printf("No output handler");
				continue;
			}

			PyObject *py_func = PyObject_GetAttrString(options.py_output_handler, "load_from_string");
			PyObject *py_args = PyTuple_New(1);
			PyTuple_SetItem(py_args, 0, PyUnicode_FromString(argv[argLoop] + 9));
			PyObject *py_result = PyObject_CallObject(py_func, py_args);
			if(py_result == NULL) {
				PyErr_Print();
			}

#endif
		// Host (maybe port too)...
		} else if (argLoop + 1 == argc) {
			mode = mode_single;

			// Get host...
			parseHostString(argv[argLoop], &options);
		} else {
			print_help(argv[0]);
			// ToDo: define error codes
			return 1;
		}
	}

	printf("%s%s\t\t%s\n\t\t%s\n%s\n", COL_BLUE, program_banner, program_version,
			SSLeay_version(SSLEAY_VERSION), RESET);

	init_ssl(&options);

	status = run_tests(&options);

	// Free Structures
	while (options.ciphers != 0)
	{
		sslCipherPointer = options.ciphers->next;
		free(options.ciphers);
		options.ciphers = sslCipherPointer;
	}

#ifdef PYTHON_SUPPORT
	Py_Finalize();
#endif

	return status;
}
