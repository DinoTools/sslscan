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
void print_help(char *prog_name, struct sslCheckOptions *options)
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
	printf("  %s--heartbleed%s         Test for heartbleed\n", COL_GREEN, RESET);
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
	printf("  %s--output=handler-name[:option1=value1[:option2=value2[:...]]]%s\n", COL_GREEN, RESET);
	printf("                       Enable output handler. Can be specified multiple times. (Default: legacy)\n");
	printf("  %s--version%s            Display the program version.\n", COL_GREEN, RESET);
	printf("  %s--verbose%s            Display verbose output.\n", COL_GREEN, RESET);
	printf("  %s--help%s               Display the  help text  you are  now\n", COL_GREEN, RESET);
	printf("                       reading.\n");
	printf("  %s--help-output=<name>%s Print help for a single output handler and exit\n", COL_GREEN, RESET);
	printf("  %s--help-outputs%s       Print help for all output handlers and exit\n", COL_GREEN, RESET);
	printf("  %s--help-output-list%s   List all output handlers with a short description\n", COL_GREEN, RESET);
	printf("\n");
	py_call_function(options->py_config, "print_help", NULL, NULL);
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

int init(int argc, char *argv[], struct sslCheckOptions *options)
{
	SSLeay_add_all_algorithms();
	ERR_load_crypto_strings();
	// Init...
	memset(options, 0, sizeof(struct sslCheckOptions));
	// ToDo:
	//xmlArg = 0;
	strcpy(options->host, "127.0.0.1");
	options->service[0] = '\0';
	options->bindLocalAddress = false;
	options->forceAddressFamily = FORCE_AF_UNSPEC;
	options->noFailed = false;
	options->reneg = false;
	options->heartbleed = false;
	options->starttls_ftp = false;
	options->starttls_imap = false;
	options->starttls_pop3 = false;
	options->starttls_smtp = false;
	options->starttls_xmpp = false;
	options->verbose = false;
	options->targets = NULL;
	options->connection_delay = 0;
	options->connection_time.tv_sec = 0;
	options->connection_time.tv_usec = 0;

	options->ssl_versions = ssl_all;
	options->pout = false;
	options->scan_mode = SSLSCAN_SCAN_MODE_FAST;
	SSL_library_init();

#ifdef IS_PY3K
	wchar_t progname[255 + 1];
	mbstowcs(progname, argv[0], strlen(argv[0]) + 1);
	Py_SetProgramName(progname);
#else /* IS_PY3K */
	Py_SetProgramName(argv[0]);
#endif /* IS_PY3K */

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
	options->py_config = PyObject_GetAttrString(py_module, "config");
	options->py_output_handler = PyObject_GetAttrString(py_module, "output");
	options->py_service_handler = PyObject_GetAttrString(py_module, "service");
	return 0;
}

/**
 * Try to free all alloceted  memory
 */
int finalize(struct sslCheckOptions *options)
{
	Py_Finalize();
	return 0;
}

/**
 * Parse commandline args
 */
int parse_args(int argc, char *argv[], struct sslCheckOptions *options)
{
	PyObject *py_tmp;
	int i;

	PyObject *py_config_set = PyObject_GetAttrString(options->py_config, "set_value");

	// Get program parameters
	for (i = 1; i < argc; i++)
	{
		if (strcmp("--help", argv[i]) == 0) {
			print_help(argv[0], options);
			return 0;
		}

		if ((strncmp("--help-output=", argv[i], 14) == 0) && (strlen(argv[i]) > 14)) {
			py_tmp = Py_BuildValue("(s)", argv[i] + 14);
			return py_call_function(options->py_output_handler, "print_help_verbose", py_tmp, NULL);
		}

		if (strcmp("--help-outputs", argv[i]) == 0) {
			return py_call_function(options->py_output_handler, "print_help", NULL, NULL);
		}

		if (strcmp("--help-output-list", argv[i]) == 0) {
			return py_call_function(options->py_output_handler, "print_list", NULL, NULL);
		}

		if ((strncmp("--targets=", argv[i], 10) == 0) && (strlen(argv[i]) > 10)) {
			options->targets = argv[i] + 10;
			continue;
		}

		if ((strcmp("--ipv4", argv[i]) == 0)) {
			options->forceAddressFamily = FORCE_AF_INET4;
			continue;
		}

		if ((strcmp("--ipv6", argv[i]) == 0)) {
			options->forceAddressFamily = FORCE_AF_INET6;
			continue;
		}

		if ((strncmp("--localip=", argv[i], 10) == 0) && (strlen(argv[i]) > 10)) {
			options->bindLocalAddress = true;
			strncpy(options->localAddress, argv[i] + 10, sizeof(options->localAddress));
			continue;
		}

		if ((strncmp("--connection_delay=", argv[i], 19) == 0) && (strlen(argv[i]) > 19)) {
			options->connection_delay = strtol(argv[i] + 19, NULL, 10);
			continue;
		}

		if (strcmp("--no-failed", argv[i]) == 0) {
			options->noFailed = true;
			continue;
		}

		if (strcmp("--version", argv[i]) == 0) {
			print_version();
			return 0;
		}

		if (strncmp("--xml=", argv[i], 6) == 0) {
			//ToDo
			//xmlArg = i;
			continue;
		}

		if (strcmp("--verbose", argv[i]) == 0) {
			options->verbose = true;
			continue;
		}

		if (strcmp("-p", argv[i]) == 0) {
			options->pout = true;
			continue;
		}

		// Client Certificates
		if (strncmp("--certs=", argv[i], 8) == 0) {
			options->clientCertsFile = argv[i] +8;
			continue;
		}

		// Private Key File
		if (strncmp("--pk=", argv[i], 5) == 0) {
			options->privateKeyFile = argv[i] +5;
			continue;
		}

		// Private Key Password
		if (strncmp("--pkpass=", argv[i], 9) == 0) {
			options->privateKeyPassword = argv[i] +9;
			continue;
		}

		// Should we check for TLS renegotiation?
		if (strcmp("--renegotiation", argv[i]) == 0) {
			options->reneg = true;
			continue;
		}

		// Should we check for Heartbleed?
		if (strcmp("--heartbleed", argv[i]) == 0) {
			options->heartbleed = true;
			continue;
		}

		// StartTLS... FTP
		if (strcmp("--starttls-ftp", argv[i]) == 0) {
			options->ssl_versions = tls_v10;
			options->starttls_ftp = true;
			continue;
		}

		// StartTLS... IMAP
		if (strcmp("--starttls-imap", argv[i]) == 0) {
			options->ssl_versions = tls_v10;
			options->starttls_imap = true;
			continue;
		}

		// StartTLS... POP3
		if (strcmp("--starttls-pop3", argv[i]) == 0) {
			options->ssl_versions = tls_v10;
			options->starttls_pop3 = true;
			continue;
		}

		// StartTLS... SMTP
		if (strcmp("--starttls-smtp", argv[i]) == 0) {
			options->ssl_versions = tls_v10;
			options->starttls_smtp = true;
			continue;
		}

		// StartTLS... XMPP
		if (strcmp("--starttls-xmpp", argv[i]) == 0) {
			options->ssl_versions = tls_v10;
			options->starttls_xmpp = true;
			continue;
		}

		// XMPP... Domain
		if (strncmp("--xmpp-domain=", argv[i], 14) == 0) {
			options->xmpp_domain = argv[i] +14;
			continue;
		}

#ifndef OPENSSL_NO_SSL2
		if (strcmp("--ssl2", argv[i]) == 0) {
			options->ssl_versions = ssl_v2;
			continue;
		}
#endif // #ifndef OPENSSL_NO_SSL2

		if (strcmp("--ssl3", argv[i]) == 0) {
			options->ssl_versions = ssl_v3;
			continue;
		}

		if (strcmp("--tls1", argv[i]) == 0) {
			options->ssl_versions = tls_v10;
			continue;
		}

#if OPENSSL_VERSION_NUMBER >= 0x1000008fL || OPENSSL_VERSION_NUMBER >= 0x1000100fL
		if (strcmp("--tls11", argv[i]) == 0) {
			options->ssl_versions = tls_v11;
			continue;
		}

		if (strcmp("--tls12", argv[i]) == 0) {
			options->ssl_versions = tls_v12;
			continue;
		}
#endif // #if OPENSSL_VERSION_NUMBER >= 0x1000008fL || OPENSSL_VERSION_NUMBER >= 0x1000100fL

		if (strcmp("--no_ssl2", argv[i]) == 0) {
			options->ssl_versions &= ~ssl_v2;
			continue;
		}

		if (strcmp("--no_ssl3", argv[i]) == 0) {
			options->ssl_versions &= ~ssl_v3;
			continue;
		}

		if (strcmp("--no_tls1", argv[i]) == 0) {
			options->ssl_versions &= ~tls_v10;
			continue;
		}

		if (strcmp("--no_tls11", argv[i]) == 0) {
			options->ssl_versions &= ~tls_v11;
			continue;
		}

		if (strcmp("--no_tls12", argv[i]) == 0) {
			options->ssl_versions &= ~tls_v12;
			continue;
		}

		if (strcmp("--bugs", argv[i]) == 0) {
			options->sslbugs = 1;
			continue;
		}

		else if (strncmp("--scan_mode=", argv[i], 12) == 0) {
			if (strcmp("fast", argv[i] + 12) == 0) {
				options->scan_mode = SSLSCAN_SCAN_MODE_FAST;
				continue;
			}

			if (strcmp("full", argv[i] + 12) == 0) {
				options->scan_mode = SSLSCAN_SCAN_MODE_FULL;
				continue;
			}

			// ToDo: print error msg
			print_help(argv[0], options);
			return 0;
		}

		// SSL HTTP Get...
		else if (strcmp("--http", argv[i]) == 0) {
			options->http = 1;
			continue;
		}

		if (strncmp("--output=", argv[i], 9) == 0) {
			if(options->py_output_handler == NULL) {
				printf("No output handler");
				continue;
			}

			PyObject *py_func = PyObject_GetAttrString(options->py_output_handler, "load_from_string");
			PyObject *py_args = PyTuple_New(1);
			PyTuple_SetItem(py_args, 0, PyUnicode_FromString(argv[i] + 9));
			PyObject *py_result = PyObject_CallObject(py_func, py_args);
			if(py_result == NULL) {
				PyErr_Print();
			}
			continue;
		}

		if (strncmp("--", argv[i], 2) == 0) {
			PyObject *py_result;
			PyObject *py_args = PyTuple_New(1);
			PyTuple_SetItem(py_args, 0, PyUnicode_FromString(argv[i] + 2));
			py_call_function(options->py_config, "set_value_from_string", py_args, &py_result);
			if (PyObject_RichCompareBool(py_result, PyBool_FromLong(1), Py_EQ) == 1)
				continue;
		}

		// Host
		if (strncmp("--", argv[i], 2) != 0) {
			// Get host...
			parseHostString(argv[i], options);
			continue;
		}

		printf("Unknown option: '%s'\n", argv[i]);
		print_help(argv[0], options);
		// ToDo: define error codes
		return 1;
	}
	return 0;
}

int main(int argc, char *argv[])
{
	// Variables...
	struct sslCheckOptions options;
	int status=0;

	status = init(argc, argv, &options);
	if (status != 0)
		return status;

	status = parse_args(argc, argv, &options);

	printf("%s%s\t\t%s\n\t\t%s\n%s\n", COL_BLUE, program_banner, program_version,
			SSLeay_version(SSLEAY_VERSION), RESET);

	status = run_tests(&options);
	if (status != 0)
		return status;

	status = finalize(&options);
	if (status != 0)
		return status;

	return status;
}
