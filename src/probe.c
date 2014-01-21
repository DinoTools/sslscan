#include "main.h"

/* Borrowed from tortls.c to dance with OpenSSL on many platforms, with
 * many versions and releases of OpenSSL. */
/** Does the run-time openssl version look like we need
 * SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION? */
static int use_unsafe_renegotiation_op = 0;
/** Does the run-time openssl version look like we need
 * SSL3_FLAGS_ALLOW_UNSAFE_LEGACY_RENEGOTIATION? */
static int use_unsafe_renegotiation_flag = 0;

/* We redefine these so that we can run correctly even if the vendor gives us
 * a version of OpenSSL that does not match its header files.  (Apple: I am
 * looking at you.)
 */
#ifndef SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
#define SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION 0x00040000L
#endif
#ifndef SSL3_FLAGS_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
#define SSL3_FLAGS_ALLOW_UNSAFE_LEGACY_RENEGOTIATION 0x0010
#endif

int get_certificate(struct sslCheckOptions *options);
int loadCerts(struct sslCheckOptions *options);
static int password_callback(char *buf, int size, int rwflag, void *userdata);
int test_cipher(struct sslCheckOptions *options, struct sslCipher *sslCipherPointer);
int test_default_cipher(struct sslCheckOptions *options, const const SSL_METHOD *ssl_method);
int test_renegotiation(struct sslCheckOptions *options, const SSL_METHOD *sslMethod);
int test_renegotiation_process_result( struct sslCheckOptions *options, struct renegotiationOutput result);
int test_host(struct sslCheckOptions *options);
int tcpConnect(struct sslCheckOptions *options);
void tls_reneg_init(struct sslCheckOptions *options);

// Create a TCP socket
int tcpConnect(struct sslCheckOptions *options)
{
	// Variables...
	int socketDescriptor;
	int tlsStarted = 0;
	char buffer[BUFFERSIZE];
	int status;

	struct addrinfo *bindAddress;
	struct addrinfo *p = options->addrList;
	if(options->addrSelected != NULL)
		p = options->addrSelected;

	for(; p != NULL; p = p->ai_next) {
		// Create Socket
		if ((socketDescriptor = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
		{
			printf("%s    ERROR: Could not open a socket.%s\n", COL_RED, RESET);
			if(options->addrSelected == NULL)
				continue;
			printf("Exit\n");
			return 0;
		}

		// bind to local ip if requested
		if( options->bindLocalAddress == true )
		{
			bindAddress = options->localAddrList;
			if(options->localAddrSelected != NULL)
				bindAddress = options->localAddrSelected;

			for(; bindAddress != NULL; bindAddress = bindAddress->ai_next)
			{
				if(bindAddress->ai_family != p->ai_family)
					continue;

				if(bind(socketDescriptor, bindAddress->ai_addr, bindAddress->ai_addrlen) == -1)
				{
					if(options->localAddrSelected == NULL)
						continue;
					printf("%s    ERROR: Could not rebind to previously selected local interface.%s\n",COL_RED, RESET);
					return 0;
				}
				break;
			}
			if(bindAddress == NULL)
			{
				printf("%s    ERROR: Could not bind to local interface.%s\n",COL_RED, RESET);
				return 0;
			}
			options->localAddrSelected = bindAddress;
		}

		/*struct sockaddr_in* saddr = (struct sockaddr_in*)p->ai_addr;
		printf("hostname: %s\n", inet_ntoa(saddr->sin_addr));
		printf("port %d\n", (int)saddr->sin_port);*/
		// Connect
		delay_connection(options);
		if(( status = connect(socketDescriptor, p->ai_addr, p->ai_addrlen)) == -1) {
			close(socketDescriptor);
			perror("connect");
			if(options->addrSelected == NULL)
				continue;
			printf("Exit\n");
			return 0;
		}
		break;
	}
	if (p == NULL)
	{
		printf("failed to connect\n");
		return 0;
	}
	options->addrSelected = p;
/*
	if(status < 0)
	{
		printf("%s    ERROR: Could not open a connection to host %s on port %d.%s\n", COL_RED, options->host, options->service, RESET);
		return 0;
	}*/

	// If STARTTLS is required...
	if (options->starttls_smtp == true && tlsStarted == false)
	{
		tlsStarted = 1;
		if (!readOrLogAndClose(socketDescriptor, buffer, BUFFERSIZE, options))
			return 0;

		if (strncmp(buffer, "220", 3) != 0)
		{
			close(socketDescriptor);
			printf("%s    ERROR: The host %s on port %s did not appear to be an SMTP service.%s\n", COL_RED, options->host, options->service, RESET);
			return 0;
		}
		send(socketDescriptor, "EHLO titania.co.uk\r\n", 20, 0);
		if (!readOrLogAndClose(socketDescriptor, buffer, BUFFERSIZE, options))
			return 0;
		if (strncmp(buffer, "250", 3) != 0)
		{
			close(socketDescriptor);
			printf("%s    ERROR: The SMTP service on %s port %s did not respond with status 250 to our HELO.%s\n", COL_RED, options->host, options->service, RESET);
			return 0;
		}
		send(socketDescriptor, "STARTTLS\r\n", 10, 0);
		if (!readOrLogAndClose(socketDescriptor, buffer, BUFFERSIZE, options))
			return 0;
		if (strncmp(buffer, "220", 3) != 0)
		{
			close(socketDescriptor);
			printf("%s    ERROR: The SMTP service on %s port %s did not appear to support STARTTLS.%s\n", COL_RED, options->host, options->service, RESET);
			return 0;
		}
	}

	// We could use an XML parser but frankly it seems like a security disaster
	if (options->starttls_xmpp == true && tlsStarted == false)
	{

		/* This is so ghetto, you cannot release it! */
		char xmpp_setup[1024]; // options->host is 512 bytes long
		char xmpp_to[512];
		// use hostname if not defined explicitly
		if( options->xmpp_domain == 0) {
			strncpy(xmpp_to, options->host, sizeof(xmpp_to));
		} else {
			strncpy(xmpp_to, options->xmpp_domain, sizeof(xmpp_to));
		}

		if (snprintf(xmpp_setup, sizeof(xmpp_setup), "<?xml version='1.0' ?>\r\n"
			   "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='%s' version='1.0'>\r\n", xmpp_to) >= sizeof(xmpp_setup)) {
			printf("(internal error: xmpp_setup buffer too small)\n");
			abort();
		}
		tlsStarted = 1;
		send(socketDescriptor, xmpp_setup, strlen(xmpp_setup), 0);
		if (!readOrLogAndClose(socketDescriptor, buffer, BUFFERSIZE, options))
			return 0;
		if (options->verbose)
		{
			printf("Server reported: %s\n", buffer);
			printf("Attempting to STARTTLS\n");
		}

		send(socketDescriptor, "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>\r\n", 53, 0);
		if (!readOrLogAndClose(socketDescriptor, buffer, BUFFERSIZE, options))
			return 0;

		/* We're looking for something like:
		<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'
		If we find the end of the stream features before we find tls, we may
		not have STARTTLS support. */
		if (strstr(buffer, "urn:ietf:params:xml:ns:xmpp-tls")) {
			if (options->verbose) {
				printf("It appears that xmpp-tls was detected.\n");
			}
		} else if (strstr(buffer, "/stream:features")) {
				if (options->verbose) {
				printf("It appears that xmpp-tls was not detected.\n");
				}
		}

		if (options->verbose)
			printf("Server reported: %s\n", buffer);

		if (!readOrLogAndClose(socketDescriptor, buffer, BUFFERSIZE, options))
			return 0;
		if (strstr(buffer, "<proceed")) {
			if (options->verbose) {
				printf("It appears that xmpp-tls is ready for TLS.\n");
			}
		if (options->verbose)
			printf("Server reported: %s\n", buffer);
		}

	}

	// Setup a POP3 STARTTLS socket
	if (options->starttls_pop3 == true && tlsStarted == false)
	{
		tlsStarted = 1;
		if (!readOrLogAndClose(socketDescriptor, buffer, BUFFERSIZE, options))
			return 0;
		if (options->verbose)
			printf("Server reported: %s\n", buffer);
		send(socketDescriptor, "STLS\r\n", 6, 0);
		if (!readOrLogAndClose(socketDescriptor, buffer, BUFFERSIZE, options))
			return 0;
		// We probably want to confirm that we see something like:
		// '+OK Begin SSL/TLS negotiation now.'
		// Or
		// '+OK Begin TLS negotiation, mate'
		if (strstr(buffer, "+OK Begin")) {
			if (options->verbose) {
				printf("It appears that the POP3 server is ready for TLS.\n");
			}
		}
		if (options->verbose)
			printf("Server reported: %s\n", buffer);
	}

	// Setup an IMAP STARTTLS socket
	if (options->starttls_imap == true && tlsStarted == false)
	{
		tlsStarted = 1;
		memset(buffer, 0, BUFFERSIZE);

		// Fetch the IMAP banner
		if (!readOrLogAndClose(socketDescriptor, buffer, BUFFERSIZE, options))
			return 0;
		if (options->verbose)
			printf("Server banner: %s\n", buffer);
		// Attempt to STARTTLS
		send(socketDescriptor, ". STARTTLS\r\n", 12, 0);
		if (!readOrLogAndClose(socketDescriptor, buffer, BUFFERSIZE, options))
			return 0;
		if (strstr(buffer, ". OK") || strstr(buffer, " . OK")) {
			if (options->verbose) {
				printf("STARTLS IMAP setup complete.\n");
				printf("Server reported: %s\n", buffer);
			}
		} else {
			if (options->verbose) {
				printf("STARTLS IMAP setup not complete.\n");
				printf("Server reported: %s\n", buffer);
			}
		}
	}

	// Setup a FTP STARTTLS socket
	if (options->starttls_ftp == true && tlsStarted == false)
	{
		tlsStarted = 1;

		// Fetch the server banner
		if (!readOrLogAndClose(socketDescriptor, buffer, BUFFERSIZE, options))
			return 0;
		if (options->verbose)
			printf("Server banner: %s\n", buffer);

		// Send TLS request
		send(socketDescriptor, "AUTH TLS\r\n", 10, 0);
		if (!readOrLogAndClose(socketDescriptor, buffer, BUFFERSIZE, options))
			return 0;
		if (strstr(buffer, "234 AUTH TLS successful")) {
			if (options->verbose)
				printf("STARTLS FTP setup complete.\n");
		} else {
			if (options->verbose)
				printf("STARTLS FTP setup possibly not complete.\n");
		}
		if (options->verbose)
			printf("Server reported: %s\n", buffer);
	}

	// Return
	return socketDescriptor;
}

/**
 * Try to free all alloceted  memory
 */
int finalize_probe(struct sslCheckOptions *options)
{
	struct sslCipher *cipher;

	// Free Structures
	while (options->ciphers != NULL) {
		cipher = options->ciphers->next;
		free(options->ciphers);
		options->ciphers = cipher;
	}
	return true;
}

// Get certificate...
int get_certificate(struct sslCheckOptions *options)
{
	// Variables...
	int cipherStatus = 0;
	int status = true;
	int socketDescriptor = 0;
	SSL *ssl = NULL;
	BIO *cipherConnectionBio = NULL;
	X509 *x509Cert = NULL;
	EVP_PKEY *publicKey = NULL;
	const SSL_METHOD *sslMethod = NULL;
	ASN1_OBJECT *asn1Object = NULL;
	X509_EXTENSION *extension = NULL;
	char buffer[1024];
	long tempLong = 0;
	int tmp_int;
	long tmp_long;
	char *tmp_buffer_ptr = NULL;
	int tempInt = 0;
	int tempInt2 = 0;
	long verify_status = 0;

	// Connect to host
	socketDescriptor = tcpConnect(options);
	if (socketDescriptor == 0)
		return false;

	// Setup Context Object...
	if( options->ssl_versions & tls_v10) {
		if (options->verbose)
			printf("sslMethod = TLSv1_method()");
		sslMethod = TLSv1_method();
	} else {
		if (options->verbose)
			printf("sslMethod = SSLv23_method()");
		sslMethod = SSLv23_method();
	}
	options->ctx = SSL_CTX_new(sslMethod);

	if (options->ctx == NULL) {
		// Error Creating Context Object
		printf("%sERROR: Could not create CTX object.%s\n", COL_RED, RESET);
		// Disconnect from host
		close(socketDescriptor);
	}


	if (SSL_CTX_set_cipher_list(options->ctx, "ALL:COMPLEMENTOFALL") == 0) {
		printf("%s    ERROR: Could set cipher.%s\n", COL_RED, RESET);
		// Free CTX Object
		SSL_CTX_free(options->ctx);

		// Disconnect from host
		close(socketDescriptor);
		return false;
	}

	// Load Certs if required...
	if ((options->clientCertsFile != 0) || (options->privateKeyFile != 0))
		if( loadCerts(options) == false) {
			// Free CTX Object
			SSL_CTX_free(options->ctx);

			// Disconnect from host
			close(socketDescriptor);
			return false;
		}

	// Create SSL object...
	ssl = SSL_new(options->ctx);
	if (ssl == NULL) {
		printf("%s    ERROR: Could create SSL object.%s\n", COL_RED, RESET);
		// Free CTX Object
		SSL_CTX_free(options->ctx);

		// Disconnect from host
		close(socketDescriptor);
		return false;
	}

	// Connect socket and BIO
	cipherConnectionBio = BIO_new_socket(socketDescriptor, BIO_NOCLOSE);

	// Connect SSL and BIO
	SSL_set_bio(ssl, cipherConnectionBio, cipherConnectionBio);

#if OPENSSL_VERSION_NUMBER >= 0x0090806fL && !defined(OPENSSL_NO_TLSEXT)
	// Based on http://does-not-exist.org/mail-archives/mutt-dev/msg13045.html
	// TLS Virtual-hosting requires that the server present the correct
	// certificate; to do this, the ServerNameIndication TLS extension is used.
	// If TLS is negotiated, and OpenSSL is recent enough that it might have
	// support, and support was enabled when OpenSSL was built, mutt supports
	// sending the hostname we think we're connecting to, so a server can send
	// back the correct certificate.
	// NB: finding a server which uses this for IMAP is problematic, so this is
	// untested.  Please report success or failure!  However, this code change
	// has worked fine in other projects to which the contributor has added it,
	// or HTTP usage.
	SSL_set_tlsext_host_name (ssl, options->host);
#endif

	// Connect SSL over socket
	cipherStatus = SSL_connect(ssl);
	if (cipherStatus < 1) {
		// Free SSL object
		SSL_free(ssl);

		// Free CTX Object
		SSL_CTX_free(options->ctx);

		// Disconnect from host
		close(socketDescriptor);
		return true;
	}

	// Get Certificate...
	x509Cert = SSL_get_peer_certificate(ssl);
	if (x509Cert == NULL) {
		printf("    Unable to parse certificate\n");

		// Disconnect SSL over socket
		SSL_shutdown(ssl);

		// Free SSL object
		SSL_free(ssl);

		// Free CTX Object
		SSL_CTX_free(options->ctx);

		// Disconnect from host
		close(socketDescriptor);

		return true;
	}

	PyObject *py_module = PyImport_ImportModule("sslscan.ssl");
	if (py_module == NULL) {
		PyErr_Print();
		// ToDo:
		return 1;
	}
	PyObject *py_func = PyObject_GetAttrString(py_module, "X509");
	if(py_func == NULL) {
		PyErr_Print();
		// ToDo:
		return 1;
	}
	PyObject *py_args = PyTuple_New(1);
	PyTuple_SetItem(py_args, 0, PyCapsule_New((void*) x509Cert, "x509", NULL));
	PyObject *py_result = PyObject_CallObject(py_func, py_args);
	if(py_result == NULL) {
		PyErr_Print();
		// ToDo:
		return 1;
	}
	PyDict_SetItemString(options->host_result, "certificate.x509", py_result);

	// Verify Certificate...
	verify_status = SSL_get_verify_result(ssl);
	if (verify_status == X509_V_OK) {
		PyDict_SetItemString(options->host_result, "certificate.verify.status", PyLong_FromLong(true));
		PyDict_SetItemString(options->host_result, "certificate.verify.error_message", PyUnicode_FromString(""));
	} else {
		PyDict_SetItemString(options->host_result, "certificate.verify.status", PyLong_FromLong(false));
		PyDict_SetItemString(options->host_result, "certificate.verify.error_message", PyUnicode_FromString(X509_verify_cert_error_string(verify_status)));
	}

	// Free X509 Certificate...
	//X509_free(x509Cert);

	// Disconnect SSL over socket
	SSL_shutdown(ssl);

	// Free SSL object
	SSL_free(ssl);

	// Free CTX Object
	SSL_CTX_free(options->ctx);

	// Disconnect from host
	close(socketDescriptor);

	return status;
}

/**
 * Initialize OpenSSL
 * - Add algorithms
 * - Load strings
 * - populate ciphers
 */
int init_probe(struct sslCheckOptions *options)
{
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
	return true;
}

// Load client certificates/private keys...
int loadCerts(struct sslCheckOptions *options)
{
	// Variables...
	int status = 1;
	PKCS12 *pk12 = NULL;
	FILE *pk12File = NULL;
	X509 *cert = NULL;
	EVP_PKEY *pkey = NULL;
	STACK_OF(X509) *ca = NULL;

	// Configure PKey password...
	if (options->privateKeyPassword != 0)
	{
		SSL_CTX_set_default_passwd_cb_userdata(options->ctx, (void *)options->privateKeyPassword);
		SSL_CTX_set_default_passwd_cb(options->ctx, password_callback);
	}

	// Seperate Certs and PKey Files...
	if ((options->clientCertsFile != 0) && (options->privateKeyFile != 0))
	{
		// Load Cert...
		if (!SSL_CTX_use_certificate_file(options->ctx, options->clientCertsFile, SSL_FILETYPE_PEM))
		{
			if (!SSL_CTX_use_certificate_file(options->ctx, options->clientCertsFile, SSL_FILETYPE_ASN1))
			{
				if (!SSL_CTX_use_certificate_chain_file(options->ctx, options->clientCertsFile))
				{
					printf("%s    Could not configure certificate(s).%s\n", COL_RED, RESET);
					status = 0;
				}
			}
		}

		// Load PKey...
		if (status != 0)
		{
			if (!SSL_CTX_use_PrivateKey_file(options->ctx, options->privateKeyFile, SSL_FILETYPE_PEM))
			{
				if (!SSL_CTX_use_PrivateKey_file(options->ctx, options->privateKeyFile, SSL_FILETYPE_ASN1))
				{
					// Why would the more specific functions succeed if the generic functions failed?
					// -- I'm guessing that the original author was hopeful? - io
					if (!SSL_CTX_use_RSAPrivateKey_file(options->ctx, options->privateKeyFile, SSL_FILETYPE_PEM))
					{
						if (!SSL_CTX_use_RSAPrivateKey_file(options->ctx, options->privateKeyFile, SSL_FILETYPE_ASN1))
						{
							printf("%s    Could not configure private key.%s\n", COL_RED, RESET);
							status = 0;
						}
					}
				}
			}
		}
	}

	// PKCS Cert and PKey File...
	else if (options->privateKeyFile != 0)
	{
		pk12File = fopen(options->privateKeyFile, "rb");
		if (pk12File != NULL)
		{
			pk12 = d2i_PKCS12_fp(pk12File, NULL);
			if (!pk12)
			{
				status = 0;
				printf("%s    Could not read PKCS#12 file.%s\n", COL_RED, RESET);
			}
			else
			{
				if (!PKCS12_parse(pk12, options->privateKeyPassword, &pkey, &cert, &ca))
				{
					status = 0;
					printf("%s    Error parsing PKCS#12. Are you sure that password was correct?%s\n", COL_RED, RESET);
				}
				else
				{
					if (!SSL_CTX_use_certificate(options->ctx, cert))
					{
						status = 0;
						printf("%s    Could not configure certificate.%s\n", COL_RED, RESET);
					}
					if (!SSL_CTX_use_PrivateKey(options->ctx, pkey))
					{
						status = 0;
						printf("%s    Could not configure private key.%s\n", COL_RED, RESET);
					}
				}
				PKCS12_free(pk12);
			}
			fclose(pk12File);
		}
		else
		{
			printf("%s    Could not open PKCS#12 file.%s\n", COL_RED, RESET);
			status = 0;
		}
	}

	// Check Cert/Key...
	if (status != 0)
	{
		if (!SSL_CTX_check_private_key(options->ctx))
		{
			printf("%s    Prvate key does not match certificate.%s\n", COL_RED, RESET);
			return false;
		}
		else
			return true;
	}
	else
		return false;
}

// Private Key Password Callback...
static int password_callback(char *buf, int size, int rwflag, void *userdata)
{
	strncpy(buf, (char *)userdata, size);
	// I don't know the semantics of these arguments, but it looks like this
	// could go badly wrong if userdata is too long.
	buf[strlen(userdata)] = 0;
	return strlen(userdata);
}

/**
 * Run all tests
 */
int run_tests(struct sslCheckOptions *options)
{
	FILE *fp;
	char line[1024];
	int status = 0;

	if(!init_probe(options))
		return false;

#ifdef PYTHON_SUPPORT
	PyObject *result_list = PyList_New(0);
#endif

	if (options->targets != NULL) {
		if (fileExists(options->targets) == false) {
			printf("%sERROR: Targets file %s does not exist.%s\n", COL_RED, options->targets, RESET);
			// ToDo:
			return 1;
		}

		fp = fopen(options->targets, "r");
		if (fp == NULL) {
			printf("%sERROR: Could not open targets file %s.%s\n", COL_RED, options->targets, RESET);
			// ToDo:
			return 1;
		}

		readLine(fp, line, sizeof(line));
		while (feof(fp) == 0) {
			if (strlen(line) != 0) {
				// Get host...
				parseHostString(line, options);

				// Test the host...
#ifdef PYTHON_SUPPORT
				options->host_result = new_host_result();
#endif
				status = test_host(options);
				if(!status) {
					// print error and continue
					printf("%sERROR: Scan has failed for host %s\n%s", COL_RED, options->host, RESET);
				} else {
#ifdef PYTHON_SUPPORT
					PyList_Append(result_list, options->host_result);
#endif
				}
			}
			readLine(fp, line, sizeof(line));
		}

	} else {
#ifdef PYTHON_SUPPORT
		options->host_result = new_host_result();
#endif
		status = test_host(options);
		if(!status) {
			printf("%sERROR: Scan has failed for host %s\n%s", COL_RED, options->host, RESET);
			// ToDo:
			return 1;
		} else {
#ifdef PYTHON_SUPPORT
			PyList_Append(result_list, options->host_result);
#endif
		}
	}
#ifdef PYTHON_SUPPORT
	// ToDo: Clean up
	PyObject *client_result = new_client_result(options);
	if (options->py_output_handler == NULL) {
		printf("Error: No python output handler found");
		// ToDo:
		return 1;
	}
	PyObject *py_func = PyObject_GetAttrString(options->py_output_handler, "run");
	PyObject *py_args = PyTuple_New(2);
	PyTuple_SetItem(py_args, 0, client_result);
	PyTuple_SetItem(py_args, 1, result_list);
	PyObject *py_result = PyObject_CallObject(py_func, py_args);
	if(py_result == NULL) {
		PyErr_Print();
	}
#endif

	if(!finalize_probe(options))
		return false;

	return 0;
}

/**
 * Test a cipher.
 */
int test_cipher(struct sslCheckOptions *options, struct sslCipher *sslCipherPointer)
{
	// Variables...
	int cipherStatus;
	int socketDescriptor = 0;
	SSL *ssl = NULL;
	BIO *cipherConnectionBio;
	BIO *stdoutBIO = NULL;
	int tempInt;
	char requestBuffer[200];
	char buffer[50];
	int resultSize = 0;

	// Create request buffer...
	memset(requestBuffer, 0, 200);
	snprintf(requestBuffer, 199, "GET / HTTP/1.0\r\nUser-Agent: SSLScan\r\nHost: %s\r\n\r\n", options->host);

	socketDescriptor = tcpConnect(options);
	if (socketDescriptor == 0)
		// ToDo: error code
		return 1;

	if (SSL_CTX_set_cipher_list(options->ctx, sslCipherPointer->name) == 0) {
		printf("%s    ERROR: Could set cipher %s.%s\n", COL_RED, sslCipherPointer->name, RESET);
		close(socketDescriptor);
		// ToDo: error code
		return 1;
	}

	ssl = SSL_new(options->ctx);
	if (ssl == NULL) {
		printf("%s    ERROR: Could create SSL object.%s\n", COL_RED, RESET);
		close(socketDescriptor);
		// ToDo: error code
		return 1;
	}

	// Connect socket and BIO
	cipherConnectionBio = BIO_new_socket(socketDescriptor, BIO_NOCLOSE);

	// Connect SSL and BIO
	SSL_set_bio(ssl, cipherConnectionBio, cipherConnectionBio);

#if OPENSSL_VERSION_NUMBER >= 0x0090806fL && !defined(OPENSSL_NO_TLSEXT)
	// This enables TLS SNI
	SSL_set_tlsext_host_name (ssl, options->host);
#endif

	// Connect SSL over socket
	cipherStatus = SSL_connect(ssl);

	char method_name[32];
	int method_id = get_ssl_method_name(sslCipherPointer->sslMethod, method_name, sizeof(method_name));

#ifdef PYTHON_SUPPORT
	PyObject *py_tmp;
	PyObject *py_ciphers;

	py_tmp = Py_BuildValue("{sisiszsssz}",
		"bits", sslCipherPointer->bits,
		"method.id", method_id,
		"method.name", NULL,
		"name", sslCipherPointer->name,
		"status", NULL
	);

	if(method_id > 0)
		PyDict_SetItemString(py_tmp, "method.name", PyUnicode_FromString(method_name));

	if (cipherStatus == 0)
		PyDict_SetItemString(py_tmp, "status", PyUnicode_FromString("rejected"));
	else if(cipherStatus == 1)
		PyDict_SetItemString(py_tmp, "status", PyUnicode_FromString("accepted"));
	else
		PyDict_SetItemString(py_tmp, "status", PyUnicode_FromString("failed"));

	py_ciphers = PyDict_GetItemString(options->host_result, "ciphers");
	PyList_Append(py_ciphers, py_tmp);
#endif

	// Disconnect SSL over socket
	if (cipherStatus == 1)
		SSL_shutdown(ssl);

	// Free SSL object
	SSL_free(ssl);

	close(socketDescriptor);

	return 0;
}

// Test for preferred ciphers
int test_default_cipher(struct sslCheckOptions *options, const const SSL_METHOD *ssl_method)
{
	// Variables...
	int cipherStatus;
	int status = true;
	int socketDescriptor = 0;
	SSL *ssl = NULL;
	BIO *cipherConnectionBio;
	int tempInt;
	int tempInt2;

	// Connect to host
	socketDescriptor = tcpConnect(options);
	if (socketDescriptor == 0)
		return false;

	// Setup Context Object...
	options->ctx = SSL_CTX_new(ssl_method);
	if (options->ctx == NULL) {
		printf("%sERROR: Could not create CTX object.%s\n", COL_RED, RESET);
		close(socketDescriptor);
		return false;
	}

	if (SSL_CTX_set_cipher_list(options->ctx, "ALL:COMPLEMENTOFALL") == 0) {
		printf("%s    ERROR: Could set cipher.%s\n", COL_RED, RESET);

		// Free CTX Object
		SSL_CTX_free(options->ctx);
		close(socketDescriptor);
		return false;
	}

	// Load Certs if required...
	if ((options->clientCertsFile != 0) || (options->privateKeyFile != 0)) {
		if(loadCerts(options) == false) {
			SSL_CTX_free(options->ctx);
			close(socketDescriptor);
			return false;
		}
	}

	// Create SSL object...
	ssl = SSL_new(options->ctx);
	if (ssl == NULL) {
		status = false;
		printf("%s    ERROR: Could create SSL object.%s\n", COL_RED, RESET);

		// Free CTX Object
		SSL_CTX_free(options->ctx);
		close(socketDescriptor);
		return false;
	}

	// Connect socket and BIO
	cipherConnectionBio = BIO_new_socket(socketDescriptor, BIO_NOCLOSE);

	// Connect SSL and BIO
	SSL_set_bio(ssl, cipherConnectionBio, cipherConnectionBio);

#if OPENSSL_VERSION_NUMBER >= 0x0090806fL && !defined(OPENSSL_NO_TLSEXT)
	// TLS SNI
	SSL_set_tlsext_host_name (ssl, options->host);
#endif

	// Connect SSL over socket
	cipherStatus = SSL_connect(ssl);

	char method_name[32];
	int method_id = get_ssl_method_name(ssl_method, method_name, sizeof(method_name));

	PyObject *py_tmp;
	PyObject *py_ciphers;

	int tmp_bits;
	SSL_get_cipher_bits(ssl, &tmp_bits);

	if (cipherStatus == 1) {
		py_tmp = Py_BuildValue("{sisiszss}",
			"bits", tmp_bits,
			"method.id", method_id,
			"method.name", NULL,
			"name", SSL_get_cipher_name(ssl)
		);

		if(method_id > 0) {
			PyDict_SetItemString(py_tmp, "method.name", PyUnicode_FromString(method_name));
		}
	} else {
		// portable None
		py_tmp = Py_BuildValue("");
	}
	py_ciphers = PyDict_GetItemString(options->host_result, "ciphers.default");
	PyDict_SetItemString(py_ciphers, method_name, py_tmp);

	if (cipherStatus == 1) {
		// Disconnect SSL over socket
		SSL_shutdown(ssl);
	}

	// Free SSL object
	SSL_free(ssl);

	// Free CTX Object
	SSL_CTX_free(options->ctx);

	close(socketDescriptor);

	return status;
}
/**
 * Check if the server supports renegotiation
 *
 */
int test_renegotiation(struct sslCheckOptions *options, const SSL_METHOD *ssl_method)
{
	// Variables...
	int cipherStatus;
	int status = true;
	//int secure = false;
	int socketDescriptor = 0;
	int res;
	SSL *ssl = NULL;
	BIO *cipherConnectionBio;
	struct renegotiationOutput result;

	result.supported = false;
	result.secure = false;

	options->ctx = SSL_CTX_new(ssl_method);
	tls_reneg_init(options);

	// Connect to host
	socketDescriptor = tcpConnect(options);
	if (socketDescriptor == 0) {
		// Could not connect
		fprintf(stderr, "%sERROR: Could not connect.%s\n", COL_RED, RESET);
		result.supported = false;
		return false;
	}

	// Setup Context Object...
	options->ctx = SSL_CTX_new(ssl_method);
	if (options->ctx == NULL) {
		result.supported = false;
		fprintf(stderr, "%sERROR: Could not create CTX object.%s\n", COL_RED, RESET);
		close(socketDescriptor);

		test_renegotiation_process_result(options, result);
		return false;
	}
	if (SSL_CTX_set_cipher_list(options->ctx, "ALL:COMPLEMENTOFALL") == 0) {
		result.supported = false;
		fprintf(stderr, "%s    ERROR: Could set cipher.%s\n", COL_RED, RESET);
		// Free CTX Object
		SSL_CTX_free(options->ctx);

		// Disconnect from host
		close(socketDescriptor);

		test_renegotiation_process_result(options, result);
		return false;
	}

	// Load Certs if required...
	if ((options->clientCertsFile != 0) || (options->privateKeyFile != 0)) {
		if (loadCerts(options) == false) {
			// Free CTX Object
			SSL_CTX_free(options->ctx);

			// Disconnect from host
			close(socketDescriptor);

			test_renegotiation_process_result(options, result);
			return false;
		}
	}

	// Create SSL object...
	ssl = SSL_new(options->ctx);

#if ( OPENSSL_VERSION_NUMBER > 0x009080cfL )
	// Make sure we can connect to insecure servers
	// OpenSSL is going to change the default at a later date
	SSL_set_options(ssl, SSL_OP_LEGACY_SERVER_CONNECT);
#endif

	if (ssl == NULL) {
		result.supported = false;
		fprintf(stderr, "%s    ERROR: Could create SSL object.%s\n", COL_RED, RESET);

		// Free CTX Object
		SSL_CTX_free(options->ctx);

		// Disconnect from host
		close(socketDescriptor);

		test_renegotiation_process_result(options, result);
		return false;
	}

	// Connect socket and BIO
	cipherConnectionBio = BIO_new_socket(socketDescriptor, BIO_NOCLOSE);

	// Connect SSL and BIO
	SSL_set_bio(ssl, cipherConnectionBio, cipherConnectionBio);

#if OPENSSL_VERSION_NUMBER >= 0x0090806fL && !defined(OPENSSL_NO_TLSEXT)
	// This enables TLS SNI
	// Based on http://does-not-exist.org/mail-archives/mutt-dev/msg13045.html
	// TLS Virtual-hosting requires that the server present the correct
	// certificate; to do this, the ServerNameIndication TLS extension is used.
	// If TLS is negotiated, and OpenSSL is recent enough that it might have
	// support, and support was enabled when OpenSSL was built, mutt supports
	// sending the hostname we think we're connecting to, so a server can send
	// back the correct certificate.
	// NB: finding a server which uses this for IMAP is problematic, so this is
	// untested.  Please report success or failure!  However, this code change
	// has worked fine in other projects to which the contributor has added it,
	// or HTTP usage.
	SSL_set_tlsext_host_name(ssl, options->host);
#endif

	// Connect SSL over socket
	cipherStatus = SSL_connect(ssl);

	/* Yes, we know what we are doing here.  No, we do not treat a renegotiation
	 * as authenticating any earlier-received data. */
	if (use_unsafe_renegotiation_flag) {
		if(options->verbose)
			printf("use_unsafe_renegotiation_flag\n");
		ssl->s3->flags |= SSL3_FLAGS_ALLOW_UNSAFE_LEGACY_RENEGOTIATION;
	}

	if (use_unsafe_renegotiation_op) {
		if(options->verbose)
			printf("use_unsafe_renegotiation_op\n");
		SSL_set_options(ssl, SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION);
	}


	if (cipherStatus == 0) {
		// Free SSL object
		SSL_free(ssl);

		// Free CTX Object
		SSL_CTX_free(options->ctx);

		// Disconnect from host
		close(socketDescriptor);

		test_renegotiation_process_result(options, result);
		return false;
	}

#if ( OPENSSL_VERSION_NUMBER > 0x009080cfL )
	// SSL_get_secure_renegotiation_support() appeared first in OpenSSL 0.9.8m
	if(options->verbose)
		printf("Attempting secure_renegotiation_support()");

	result.secure = SSL_get_secure_renegotiation_support(ssl);
	if( result.secure ) {
		// If it supports secure renegotiations,
		// it should have renegotioation support in general
		result.supported = true;
		status = true;
	} else {
#endif
		// We can't assume that just because the secure renegotiation
		// support failed the server doesn't support insecure renegotiations·

		// assume ssl is connected and error free up to here
		//setBlocking(ssl); // this is unnecessary if it is already blocking·
		if(options->verbose)
			printf("Attempting SSL_renegotiate(ssl)\n");

		SSL_renegotiate(ssl); // Ask to renegotiate the connection

		// This hangs when an 'encrypted alert' is sent by the server
		if(options->verbose)
			printf("Attempting SSL_do_handshake(ssl)\n");

		SSL_do_handshake(ssl); // Send renegotiation request to server //TODO :: XXX hanging here

		if (ssl->state == SSL_ST_OK) {
			res = SSL_do_handshake(ssl); // Send renegotiation request to server
			if( res != 1 ) {
				fprintf(stderr, "\n\nSSL_do_handshake() call failed\n");
			}
			if (ssl->state == SSL_ST_OK) {
				/* our renegotiation is complete */
				result.supported = true;
				status = true;
			} else {
				result.supported = false;
				status = false;
				fprintf(stderr, "\n\nFailed to complete renegotiation\n");
			}
		} else {
			status = false;
			result.secure = false;
		}
#if ( OPENSSL_VERSION_NUMBER > 0x009080cfL )
	}
#endif
	// Disconnect SSL over socket
	SSL_shutdown(ssl);

	// Free SSL object
	SSL_free(ssl);

	// Free CTX Object
	SSL_CTX_free(options->ctx);

	// Disconnect from host
	close(socketDescriptor);

	test_renegotiation_process_result(options, result);
	return status;
}

/**
 *  Test renegotiation
 */
int test_renegotiation_process_result( struct sslCheckOptions *options, struct renegotiationOutput result)
{
	PyDict_SetItemString(options->host_result, "renegotiation.supported", (PyObject *)PyLong_FromLong(result.supported));
	PyDict_SetItemString(options->host_result, "renegotiation.secure", (PyObject *)PyLong_FromLong(result.secure));
	return true;
}

/**
 * Test a single host and port for ciphers...
 *
 * @param options Connection options
 */
int test_host(struct sslCheckOptions *options)
{
	// Variables...
	struct sslCipher *cipher;
	int tmp_int;

	// set default port if service is not given
	if (strlen(options->service) == 0)
	{
		if (options->starttls_ftp)
			strcpy(options->service, "21");
		else if (options->starttls_smtp)
			strcpy(options->service, "25");
		else if (options->starttls_pop3)
			strcpy(options->service, "110");
		else if (options->starttls_imap)
			strcpy(options->service, "143");
		else if (options->starttls_xmpp)
			strcpy(options->service, "5222");
		else
			strcpy(options->service, "443");
	}

	// Reset address selection
	options->addrSelected = NULL;

	// Resolve Host Name
	struct addrinfo hints;
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	if (options->forceAddressFamily == FORCE_AF_INET4)
		hints.ai_family = AF_INET;
	else if (options->forceAddressFamily == FORCE_AF_INET6)
		hints.ai_family = AF_INET6;

	hints.ai_socktype = SOCK_STREAM;

	tmp_int = getaddrinfo(options->host, options->service, &hints, &options->addrList);

	if (tmp_int != 0) {
		fprintf(stderr, "error in getaddrinfo remote: %s\n", gai_strerror(tmp_int));
		return false;
	}

	if (strcmp(options->localAddress, "") != 0) {
		// find local address
		memset(&hints, 0, sizeof(struct addrinfo));
		hints.ai_family = AF_UNSPEC;
		if (options->forceAddressFamily == FORCE_AF_INET4)
			hints.ai_family = AF_INET;
		else if (options->forceAddressFamily == FORCE_AF_INET6)
			hints.ai_family = AF_INET6;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_flags = AI_PASSIVE;

		tmp_int = getaddrinfo(options->localAddress, NULL, &hints, &options->localAddrList);
		if (tmp_int != 0) {
			fprintf(stderr, "error in getaddrinfo local: %s\n", gai_strerror(tmp_int));
			return false;
		}
	}

	// Test renegotiation
	printf("\n%sTesting SSL server %s on port %s%s\n\n", COL_GREEN, options->host, options->service, RESET);

	if (options->reneg)
		test_renegotiation(options, TLSv1_client_method());

	// Test supported ciphers...
	cipher = options->ciphers;
	while (cipher != NULL) {
		// Setup Context Object...
		options->ctx = SSL_CTX_new(cipher->sslMethod);
		if (options->ctx == NULL) {
			printf("%sERROR: Could not create CTX object.%s\n", COL_RED, RESET);
			return false;
		}
		// SSL implementation bugs/workaround
		if (options->sslbugs)
			SSL_CTX_set_options(options->ctx, SSL_OP_ALL | 0);
		else
			SSL_CTX_set_options(options->ctx, 0);

		// Load Certs if required...
		if ((options->clientCertsFile != 0) || (options->privateKeyFile != 0))
			if(loadCerts(options) == false)
				return false;

		// Test
		if (test_cipher(options, cipher) > 0)
			return false;

		// Free CTX Object
		SSL_CTX_free(options->ctx);

		cipher = cipher->next;
	}

	// Test preferred ciphers...
#ifndef OPENSSL_NO_SSL2
	if (options->ssl_versions & ssl_v2)
		if(test_default_cipher(options, SSLv2_client_method()) == false)
			return false;
#endif

	if (options->ssl_versions & ssl_v3)
		if (test_default_cipher(options, SSLv3_client_method()) == false)
			return false;
	if (options->ssl_versions & tls_v10)
		if (test_default_cipher(options, TLSv1_client_method()) == false)
			return false;

#if OPENSSL_VERSION_NUMBER >= 0x1000008fL || OPENSSL_VERSION_NUMBER >= 0x1000100fL
	if (options->ssl_versions & tls_v11)
		if (test_default_cipher(options, TLSv1_1_client_method()) == false)
			return false;
	if (options->ssl_versions & tls_v12)
		if (test_default_cipher(options, TLSv1_2_client_method()) == false)
			return false;
#endif // #if OPENSSL_VERSION_NUMBER >= 0x1000008fL || OPENSSL_VERSION_NUMBER >= 0x1000100fL


	if (get_certificate(options) == false)
		return false;

	// Return status...
	return true;
}

void tls_reneg_init(struct sslCheckOptions *options)
{
	/* Borrowed from tortls.c to dance with OpenSSL on many platforms, with
	 * many versions and release of OpenSSL. */
	SSL_library_init();
	SSL_load_error_strings();

	long version = SSLeay();
	if (version >= 0x009080c0L && version < 0x009080d0L) {
		if (options->verbose)
			printf("OpenSSL %s looks like version 0.9.8l; I will try SSL3_FLAGS to enable renegotation.\n",
				SSLeay_version(SSLEAY_VERSION));
		use_unsafe_renegotiation_flag = 1;
		use_unsafe_renegotiation_op = 1;
	} else if (version >= 0x009080d0L) {
		if (options->verbose)
			printf("OpenSSL %s looks like version 0.9.8m or later; "
			"I will try SSL_OP to enable renegotiation\n",
		SSLeay_version(SSLEAY_VERSION));
		use_unsafe_renegotiation_op = 1;
	} else if (version < 0x009080c0L) {
		if (options->verbose)
			printf("OpenSSL %s [%lx] looks like it's older than "
				 "0.9.8l, but some vendors have backported 0.9.8l's "
				 "renegotiation code to earlier versions, and some have "
				 "backported the code from 0.9.8m or 0.9.8n.  I'll set both "
				 "SSL3_FLAGS and SSL_OP just to be safe.\n",
				 SSLeay_version(SSLEAY_VERSION), version);
		use_unsafe_renegotiation_flag = 1;
		use_unsafe_renegotiation_op = 1;
	} else {
		if (options->verbose)
			printf("OpenSSL %s has version %lx\n",
			   SSLeay_version(SSLEAY_VERSION), version);
	}

#ifdef SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION
  SSL_CTX_set_options(options->ctx,
					  SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
#endif

}
