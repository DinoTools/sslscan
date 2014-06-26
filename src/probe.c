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

struct ssl_alert_info *g_ssl_alert_queue = NULL;

void callback_ssl_info(const SSL *s, int where, int ret);
int get_certificate(struct sslCheckOptions *options, const SSL *ssl);
int loadCerts(struct sslCheckOptions *options);
static int password_callback(char *buf, int size, int rwflag, void *userdata);
int test_cipher(struct sslCheckOptions *options, struct sslCipher *sslCipherPointer);
int test_default_cipher(struct sslCheckOptions *options, const const SSL_METHOD *ssl_method);
int test_renegotiation(struct sslCheckOptions *options, const SSL_METHOD *sslMethod);
int test_renegotiation_process_result( struct sslCheckOptions *options, struct renegotiationOutput result);
int test_host(struct sslCheckOptions *options);
int tcpConnect(struct sslCheckOptions *options);
void tls_reneg_init(struct sslCheckOptions *options);


/**
 * Free alert queue. Must be called before setting a callback function.
 */
int alert_queue_free()
{
	struct ssl_alert_info *p1, *p2;
	p1 = g_ssl_alert_queue;
	while (p1 != NULL) {
		p2 = p1->next;
		free(p1);
		p1 = p2;
	}
	g_ssl_alert_queue = NULL;
}

/**
 * Callback to capture SSL alerts
 */
void callback_ssl_info(const SSL *s, int where, int ret)
{
	if (!(where & SSL_CB_ALERT))
		return;
	struct ssl_alert_info *p = malloc(sizeof(struct ssl_alert_info));
	p->ret = ret;
	p->next = NULL;
	if (g_ssl_alert_queue == NULL) {
		g_ssl_alert_queue = p;
		return;
	}
	struct ssl_alert_info *t = g_ssl_alert_queue;
	while (t->next != NULL)
		t = t->next;
	t->next = p;
}

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
int get_certificate(struct sslCheckOptions *options, const SSL *ssl)
{
	if (options->host_state.extracted_information & SSLSCAN_HOST_INFO_CERTIFICATE)
		return true;

	// Variables...
	X509 *x509Cert = NULL;
	long verify_status = 0;

	// Get Certificate...
	x509Cert = SSL_get_peer_certificate(ssl);
	if (x509Cert == NULL) {
		printf("    Unable to parse certificate\n");
		return false;
	}

	PyObject *py_module = PyImport_ImportModule("sslscan.ssl");
	if (py_module == NULL) {
		PyErr_Print();
		// ToDo:
		return false;
	}

	PyObject *py_func = PyObject_GetAttrString(py_module, "X509");
	if(py_func == NULL) {
		PyErr_Print();
		// ToDo:
		return false;
	}

	PyObject *py_args = PyTuple_New(1);
	PyTuple_SetItem(py_args, 0, PyCapsule_New((void*) x509Cert, "x509", NULL));
	PyObject *py_result = PyObject_CallObject(py_func, py_args);
	if(py_result == NULL) {
		PyErr_Print();
		// ToDo:
		return false;
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

	options->host_state.extracted_information |= SSLSCAN_HOST_INFO_CERTIFICATE;

	return true;
}

/**
 * Get compression information from ssl session.
 */
int get_compression(struct sslCheckOptions *options, SSL *ssl)
{
	if (options->host_state.extracted_information & SSLSCAN_HOST_INFO_COMPRESSION)
		return true;

#ifndef OPENSSL_NO_COMP
	PyObject *py_obj;
	const COMP_METHOD *compression, *expansion;

	compression = SSL_get_current_compression(ssl);
	expansion = SSL_get_current_expansion(ssl);

	if (compression)
		py_obj = PyUnicode_FromString(SSL_COMP_get_name(compression));
	else
		py_obj = Py_BuildValue("");

	PyDict_SetItemString(options->host_result, "session.compression", py_obj);

	if (expansion)
		py_obj = PyUnicode_FromString(SSL_COMP_get_name(expansion));
	else
		py_obj = Py_BuildValue("");

	PyDict_SetItemString(options->host_result, "session.expansion", py_obj);
#endif

	options->host_state.extracted_information |= SSLSCAN_HOST_INFO_COMPRESSION;
	return true;
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

	PyObject *result_list = PyList_New(0);

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
				options->host_result = new_host_result();
				status = test_host(options);
				if(!status) {
					// print error and continue
					printf("%sERROR: Scan has failed for host %s\n%s", COL_RED, options->host, RESET);
				} else {
					PyList_Append(result_list, options->host_result);
				}
			}
			readLine(fp, line, sizeof(line));
		}

	} else {
		options->host_result = new_host_result();
		status = test_host(options);
		if(!status) {
			printf("%sERROR: Scan has failed for host %s\n%s", COL_RED, options->host, RESET);
			// ToDo:
			return 1;
		} else {
			PyList_Append(result_list, options->host_result);
		}
	}

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
	int tmp_int = 0;

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

	alert_queue_free();
	SSL_set_info_callback(ssl, callback_ssl_info);
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

	PyObject *py_tmp;
	PyObject *py_ciphers;
	PyObject *py_result;

	PyObject *py_module = PyImport_ImportModule("sslscan.ssl");
	if (py_module == NULL) {
		PyErr_Print();
		// ToDo:
		return 1;
	}

	if (cipherStatus < 0)
		tmp_int = SSLSCAN_CIPHER_STATUS_FAILED;
	else if (cipherStatus == 0)
		tmp_int = SSLSCAN_CIPHER_STATUS_REJECTED;
	else if(cipherStatus == 1)
		tmp_int = SSLSCAN_CIPHER_STATUS_ACCEPTED;
	else
		tmp_int = SSLSCAN_CIPHER_STATUS_UNKNOWN;

	PyObject *py_args = PyTuple_New(3);
	PyTuple_SetItem(py_args, 0, PyCapsule_New((void*) sslCipherPointer, "cipher", NULL));
	if (g_ssl_alert_queue != NULL)
		PyTuple_SetItem(py_args, 1, PyCapsule_New((void*) g_ssl_alert_queue, "alerts", NULL));
	PyTuple_SetItem(py_args, 2, PyCapsule_New((void*) &tmp_int, "status", NULL));
	py_call_function(py_module, "Cipher", py_args, &py_result);

	// reset queue, ToDo:
	g_ssl_alert_queue = NULL;

	py_ciphers = PyDict_GetItemString(options->host_result, "ciphers");
	PyList_Append(py_ciphers, py_result);

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

	alert_queue_free();
	SSL_set_info_callback(ssl, callback_ssl_info);
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

	get_certificate(options, ssl);
	get_compression(options, ssl);
	char method_name[32];
	int method_id = get_ssl_method_name(ssl_method, method_name, sizeof(method_name));

	struct sslCipher *cipher;
	cipher = malloc(sizeof(struct sslCipher));
	memset(cipher, 0, sizeof(struct sslCipher));
	cipher->next = NULL;
	const SSL_CIPHER *c = SSL_get_current_cipher(ssl);

	// Add cipher information...
	cipher->sslMethod = ssl_method;
	cipher->name = SSL_CIPHER_get_name(c);
	cipher->version = SSL_CIPHER_get_version(c);
	cipher->bits = SSL_CIPHER_get_bits(c, &cipher->alg_bits);
	//SSL_CIPHER_description(c, &cipher->description, sizeof(cipher->description) - 1);

	PyObject *py_tmp;
	PyObject *py_ciphers;
	PyObject *py_result;

	PyObject *py_module = PyImport_ImportModule("sslscan.ssl");
	if (py_module == NULL) {
		PyErr_Print();
		// ToDo:
		return 1;
	}

	int tmp_int;

	if (cipherStatus < 0) {
		tmp_int = SSLSCAN_CIPHER_STATUS_FAILED;
		status = false;
	} else if (cipherStatus == 0) {
		tmp_int = SSLSCAN_CIPHER_STATUS_REJECTED;
		status = true;
		if (g_ssl_alert_queue != NULL) {
			// rejected + first alert type is fatal -> failed internal (info used for fast scan mode)
			if (strcmp("F", SSL_alert_type_string(g_ssl_alert_queue->ret)) == 0)
				status = false;
		}
	} else if(cipherStatus == 1) {
		tmp_int = SSLSCAN_CIPHER_STATUS_ACCEPTED;
		status = true;
	} else {
		tmp_int = SSLSCAN_CIPHER_STATUS_UNKNOWN;
		status = false;
	}

	PyObject *py_args = PyTuple_New(3);
	PyTuple_SetItem(py_args, 0, PyCapsule_New((void*) cipher, "cipher", NULL));
	PyTuple_SetItem(py_args, 1, PyCapsule_New((void*) g_ssl_alert_queue, "alerts", NULL));
	PyTuple_SetItem(py_args, 2, PyCapsule_New((void*) &tmp_int, "status", NULL));
	py_call_function(py_module, "Cipher", py_args, &py_result);

	// reset queue, ToDo:
	g_ssl_alert_queue = NULL;

	py_ciphers = PyDict_GetItemString(options->host_result, "ciphers.default");
	PyDict_SetItemString(py_ciphers, method_name, py_result);

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

int test_heartbleed(struct sslCheckOptions *options)
{
	// Inspired by rbsec
	int socketDescriptor = 0;
	PyObject *py_vuln;

	// Connect to host
	socketDescriptor = tcpConnect(options);

	// Set a 3 second socket timeout
	struct timeval tv;
	tv.tv_sec = 3;
	tv.tv_usec = 0;
	setsockopt(socketDescriptor, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv,sizeof(struct timeval));

	if (socketDescriptor == 0) {
		// Could not connect
		fprintf(stderr, "%sERROR: Could not connect.%s\n", COL_RED, RESET);
		return false;
	}

	// Credit to Jared Stafford (jspenguin@jspenguin.org)

	char hello[] = {
		0x16, 0x03, 0x02, 0x00, 0xdc, 0x01, 0x00, 0x00, 0xd8, 0x03,
		0x02, 0x53, 0x43, 0x5b, 0x90, 0x9d, 0x9b, 0x72, 0x0b, 0xbc,
		0x0c, 0xbc, 0x2b, 0x92, 0xa8, 0x48, 0x97, 0xcf, 0xbd, 0x39,
		0x04, 0xcc, 0x16, 0x0a, 0x85, 0x03, 0x90, 0x9f, 0x77, 0x04,
		0x33, 0xd4, 0xde, 0x00, 0x00, 0x66, 0xc0, 0x14, 0xc0, 0x0a,
		0xc0, 0x22, 0xc0, 0x21, 0x00, 0x39, 0x00, 0x38, 0x00, 0x88,
		0x00, 0x87, 0xc0, 0x0f, 0xc0, 0x05, 0x00, 0x35, 0x00, 0x84,
		0xc0, 0x12, 0xc0, 0x08, 0xc0, 0x1c, 0xc0, 0x1b, 0x00, 0x16,
		0x00, 0x13, 0xc0, 0x0d, 0xc0, 0x03, 0x00, 0x0a, 0xc0, 0x13,
		0xc0, 0x09, 0xc0, 0x1f, 0xc0, 0x1e, 0x00, 0x33, 0x00, 0x32,
		0x00, 0x9a, 0x00, 0x99, 0x00, 0x45, 0x00, 0x44, 0xc0, 0x0e,
		0xc0, 0x04, 0x00, 0x2f, 0x00, 0x96, 0x00, 0x41, 0xc0, 0x11,
		0xc0, 0x07, 0xc0, 0x0c, 0xc0, 0x02, 0x00, 0x05, 0x00, 0x04,
		0x00, 0x15, 0x00, 0x12, 0x00, 0x09, 0x00, 0x14, 0x00, 0x11,
		0x00, 0x08, 0x00, 0x06, 0x00, 0x03, 0x00, 0xff, 0x01, 0x00,
		0x00, 0x49, 0x00, 0x0b, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02,
		0x00, 0x0a, 0x00, 0x34, 0x00, 0x32, 0x00, 0x0e, 0x00, 0x0d,
		0x00, 0x19, 0x00, 0x0b, 0x00, 0x0c, 0x00, 0x18, 0x00, 0x09,
		0x00, 0x0a, 0x00, 0x16, 0x00, 0x17, 0x00, 0x08, 0x00, 0x06,
		0x00, 0x07, 0x00, 0x14, 0x00, 0x15, 0x00, 0x04, 0x00, 0x05,
		0x00, 0x12, 0x00, 0x13, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03,
		0x00, 0x0f, 0x00, 0x10, 0x00, 0x11, 0x00, 0x23, 0x00, 0x00,
		0x00, 0x0f, 0x00, 0x01, 0x01
	};

	write(socketDescriptor, hello, sizeof(hello));

	// Send the heartbeat
	char hb[8] = {0x18, 0x03, 0x02, 0x00, 0x03, 0x01, 0x40, 0x00};
	write(socketDescriptor, hb, sizeof(hb));

	char hbbuf[65536];

	while(1) {
		memset(hbbuf, 0, sizeof(hbbuf));

		// Read 5 byte header
		int readResult = read(socketDescriptor, hbbuf, 5);
		if (readResult == 0) {
			break;
		}

		char typ = hbbuf[0];

		// Combine 2 bytes to get payload length
		uint16_t ln = hbbuf[4] | hbbuf[3] << 8;

		memset(hbbuf, 0, sizeof(hbbuf));

		// Read rest of record
		readResult = read(socketDescriptor, hbbuf, ln);
		if (readResult == 0) {
			break;
		}

		// Server returned error
		if (typ == 21) {
			break;
		} else if (typ == 24 && ln > 3) {
			// Sucessful response
			PyDict_SetItemString(options->host_result, "vulnerability.heartbleed", (PyObject *)PyLong_FromLong(1));
			close(socketDescriptor);
			return true;
		}
	}
	PyDict_SetItemString(options->host_result, "vulnerability.heartbleed", (PyObject *)PyLong_FromLong(0));

	// Disconnect from host
	close(socketDescriptor);

	return true;
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

	// Test heartbleed
	if (options->heartbleed)
		test_heartbleed(options);

	// Test preferred ciphers...
#ifndef OPENSSL_NO_SSL2
	if (options->ssl_versions & ssl_v2)
		if (test_default_cipher(options, SSLv2_client_method()))
			options->host_state.supported_ssl_versions |= ssl_v2;
#endif

	if (options->ssl_versions & ssl_v3)
		if (test_default_cipher(options, SSLv3_client_method()))
			options->host_state.supported_ssl_versions |= ssl_v3;

	if (options->ssl_versions & tls_v10)
		if (test_default_cipher(options, TLSv1_client_method()))
			options->host_state.supported_ssl_versions |= tls_v10;

#if OPENSSL_VERSION_NUMBER >= 0x1000008fL || OPENSSL_VERSION_NUMBER >= 0x1000100fL
	if (options->ssl_versions & tls_v11)
		if (test_default_cipher(options, TLSv1_1_client_method()))
			options->host_state.supported_ssl_versions |= tls_v11;

	if (options->ssl_versions & tls_v12)
		if (test_default_cipher(options, TLSv1_2_client_method()))
			options->host_state.supported_ssl_versions |= tls_v12;;
#endif // #if OPENSSL_VERSION_NUMBER >= 0x1000008fL || OPENSSL_VERSION_NUMBER >= 0x1000100fL

	// Test supported ciphers...
	cipher = options->ciphers;
	while (cipher != NULL) {
		if (options->scan_mode == SSLSCAN_SCAN_MODE_FAST && (options->host_state.supported_ssl_versions & get_ssl_method_id(cipher->sslMethod)) == 0) {
			// ToDo: add cipher to result list and mark as skipped
			cipher = cipher->next;
			continue;
		}
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

	/*if (get_certificate(options) == false)
		return false;*/

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
