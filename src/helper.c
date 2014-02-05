#include "main.h"

/**
 * Wait at least the specified number of milliseconds. This function is used
 * to limit the number of connections per second.
 */
void delay_connection(struct sslCheckOptions *options)
{
	struct timeval next;
	struct timeval result;
	struct timeval cur_time;
	struct timespec delay;

	if (options->connection_delay <= 0)
		return;

	next = options->connection_time;
	next.tv_sec += options->connection_delay / 1000;
	next.tv_usec += options->connection_delay % 1000 * 1000;

	while (next.tv_usec > 999999) {
		next.tv_sec++;
		next.tv_usec -= 1000000;
	}

	gettimeofday(&cur_time, NULL);

	while(timeval_substract(&next, &cur_time, &result) >= 0) {
		delay.tv_sec = result.tv_sec;
		delay.tv_nsec = result.tv_usec * 1000;
		nanosleep(&delay, NULL);
		gettimeofday(&cur_time, NULL);
	}
	options->connection_time = cur_time;
}

// File Exists
int fileExists(char *fileName)
{
#if PLAT_WINDOWS
	return _access(fileName, 0) == 0;
#else
	return access(fileName, R_OK) == 0;
#endif
}

/**
 * Get a ssl method pointer by internal ID
 * @param id Internal ID
 * @return SSL method pointer
 */
const SSL_METHOD *get_ssl_method_by_id(uint_fast8_t id)
{
#ifndef OPENSSL_NO_SSL2
	if (id == ssl_v2)
		return SSLv2_client_method();
#endif // #ifndef OPENSSL_NO_SSL2
	if (id == ssl_v3)
		return SSLv3_client_method();

	if (id == tls_v10)
		return TLSv1_client_method();

#if OPENSSL_VERSION_NUMBER >= 0x1000008fL || OPENSSL_VERSION_NUMBER >= 0x1000100fL
	if (id == tls_v11)
		return TLSv1_1_client_method();

	if (id == tls_v12)
		return TLSv1_2_client_method();
#endif // #if OPENSSL_VERSION_NUMBER >= 0x1000008fL || OPENSSL_VERSION_NUMBER >= 0x1000100fL

	return NULL;
}

/**
 * Get internal ssl method ID
 * @param SSL method pointer
 * @return Internal ID or 0 if unknown
 */
uint_fast8_t get_ssl_method_id(const SSL_METHOD *method)
{
#ifndef OPENSSL_NO_SSL2
	if (method == SSLv2_client_method())
		return ssl_v2;
#endif // #ifndef OPENSSL_NO_SSL2
	if (method == SSLv3_client_method())
		return ssl_v3;

	if (method == TLSv1_client_method())
		return tls_v10;

#if OPENSSL_VERSION_NUMBER >= 0x1000008fL || OPENSSL_VERSION_NUMBER >= 0x1000100fL
	if (method == TLSv1_1_client_method())
		return tls_v11;

	if (method == TLSv1_2_client_method())
		return tls_v12;
#endif // #if OPENSSL_VERSION_NUMBER >= 0x1000008fL || OPENSSL_VERSION_NUMBER >= 0x1000100fL

	return 0;
}

/**
 * Get the name of the ssl method
 * @param ssl_method The SSL method
 * @param name Pointer to store the name
 * @param len Max length in bytes to store name
 * @return Internal method ID or 0 on failure
 */

int get_ssl_method_name(const SSL_METHOD *ssl_method, char *name, size_t len)
{
	len--;
	name[len] = '\0';
#ifndef OPENSSL_NO_SSL2
	if (ssl_method == SSLv2_client_method()) {
		strncpy(name, "SSLv2", len);
		return 1;
	}
#endif // #ifndef OPENSSL_NO_SSL2
	if (ssl_method == SSLv3_client_method()) {
		strncpy(name, "SSLv3", len);
		return 2;
	}

	if (ssl_method == TLSv1_client_method()) {
		strncpy(name, "TLSv1", len);
		return 3;
	}

#if OPENSSL_VERSION_NUMBER >= 0x1000008fL || OPENSSL_VERSION_NUMBER >= 0x1000100fL
	if (ssl_method == TLSv1_1_client_method()) {
		strncpy(name, "TLS11", len);
		return 4;
	}

	if (ssl_method == TLSv1_2_client_method())
	{
		strncpy(name, "TLS12", len);
		return 5;
	}
#endif // #if OPENSSL_VERSION_NUMBER >= 0x1000008fL || OPENSSL_VERSION_NUMBER >= 0x1000100fL

	return 0;
}

/**
 * Create python client result object
 */
PyObject *new_client_result(struct sslCheckOptions *options) {
	PyObject *result;
	PyObject *tmp;
	PyObject *tmp2;
	char method_name[32];
	int method_id;

	result = PyDict_New();

	// Add cipher list
	tmp = PyList_New(0);
	struct sslCipher *cipher;
	cipher = options->ciphers;
	while (cipher != NULL) {
		// ToDo: add more information
		method_id = get_ssl_method_name(cipher->sslMethod, method_name, sizeof(method_name));
		tmp2 = Py_BuildValue("{sisisiszss}",
			"bits", cipher->bits,
			"algorithm_bits", cipher->alg_bits,
			"method.id", method_id,
			"method.name", NULL,
			"name", cipher->name
		);
		if(method_id > 0)
			PyDict_SetItemString(tmp2, "method.name", PyUnicode_FromString(method_name));

		PyList_Append(tmp, tmp2);
		cipher = cipher->next;
	}
	PyDict_SetItemString(result, "ciphers", tmp);

	return result;
}

/**
 * Create python server result object
 */
PyObject *new_host_result() {
	PyObject *tmp;
	tmp = PyDict_New();
	PyDict_SetItemString(tmp, "ciphers", (PyObject *)PyList_New(0));
	PyDict_SetItemString(tmp, "ciphers.default", (PyObject *)PyDict_New());
	PyDict_SetItemString(tmp, "certificate.blob", (PyObject *)Py_None);
	return tmp;
}

int parseHostString(char *host, struct sslCheckOptions *options)
{
	int tempInt = 0;
	int maxSize = strlen(host);

	/**
	 * extract IP address and remove square brackets
	 * - IPv4: 127.0.0.1 or 127.0.0.1:443
	 * - IPv6: [::1] or [::1]:443
	 */
	int squareBrackets = false;
	if (host[0] == '[')
	{
		squareBrackets = true;
		// skip the square bracket
		host++;
	}

	while ((host[tempInt] != 0) && ((squareBrackets == true && host[tempInt] != ']') || (squareBrackets == false && host[tempInt] != ':')))
		tempInt++;

	if (squareBrackets == true && host[tempInt] == ']')
	{
		host[tempInt] = 0;
		if (tempInt < maxSize && host[tempInt + 1] == ':')
		{
			tempInt++;
			host[tempInt] = 0;
		}
	}
	else
		host[tempInt] = 0;

	strncpy(options->host, host, sizeof(options->host) -1);

	// Get service (if it exists)...
	tempInt++;
	if (tempInt < maxSize)
		strncpy(options->service, host + tempInt, sizeof(options->service) - 1);

	return 0;
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
		cipher_ptr->bits = SSL_CIPHER_get_bits(sk_SSL_CIPHER_value(cipher_list, i), &cipher_ptr->alg_bits);
	}

	SSL_free(ssl);
	SSL_CTX_free(ctx);

	return true;
}

/**
 * Wrapper to call a python function. It prepares all required objects and handles errors.
 *
 * @param py_object The object
 * @param name The name of the function to call
 * @param py_args Arguments to pass to the python function. NULL if nothing to pass.
 * @param py_result Pointer to a result object. NULL if not used.
 * @return 0 = no errors; 1 = an error occurred
 */
int py_call_function(PyObject *py_obj, const char *name, PyObject *py_args, PyObject **py_result)
{
	PyObject *py_func;
	PyObject *py_tmp;

	py_func = PyObject_GetAttrString(py_obj, name);
	if (py_func == NULL) {
		PyErr_Print();
		return 1;
	}

	if (py_args == NULL)
		py_args = PyTuple_New(0);

	py_tmp = PyObject_CallObject(py_func, py_args);

	if (py_tmp == NULL) {
		PyErr_Print();
		return 1;
	}

	if (py_result != NULL) {
		*py_result = py_tmp;
	}

	return 0;
}

// Read a line from the input...
void readLine(FILE *input, char *lineFromFile, int maxSize)
{
	// Variables...
	int stripPointer;

	// Read line from file...
	fgets(lineFromFile, maxSize, input);

	// Clear the end-of-line stuff...
	stripPointer = strlen(lineFromFile) -1;
	while (stripPointer >= 0 && ((lineFromFile[stripPointer] == '\r') || (lineFromFile[stripPointer] == '\n') || (lineFromFile[stripPointer] == ' ')))
	{
		lineFromFile[stripPointer] = 0;
		stripPointer--;
	}
}

int readOrLogAndClose(int fd, void* buffer, size_t len, const struct sslCheckOptions *options)
{
	ssize_t n;

	if (len < 2)
		return 1;

	n = recv(fd, buffer, len - 1, 0);

	if (n < 0) {
		printf("%s    ERROR: error reading from %s:%s: %s%s\n", COL_RED, options->host, options->service, strerror(errno), RESET);
		close(fd);
		return 0;
	} else if (n == 0) {
		printf("%s    ERROR: unexpected EOF reading from %s:%s%s\n", COL_RED, options->host, options->service, RESET);
		close(fd);
		return 0;
	} else {
		((unsigned char *)buffer)[n] = 0;
	}

	return 1;
}

/**
 * Subtract two time values and return the result.
 * Result:
 * - 1 t1 > t2
 * - 0 t1 = t2
 * - -1 t1 < t2
 */
int timeval_substract(struct timeval *t1, struct timeval *t2, struct timeval *result)
{
	  while (t1->tv_usec > 999999) {
		t1->tv_sec += t1->tv_usec / 1000000;
		t1->tv_usec %= 1000000;
	  }

	  while (t2->tv_usec > 999999) {
		t2->tv_sec += t2->tv_usec / 1000000;
		t2->tv_usec %= 1000000;
	  }

	  result->tv_sec = t1->tv_sec - t2->tv_sec;

	  if ((result->tv_usec = t1->tv_usec - t2->tv_usec) < 0) {
		result->tv_usec += 1000000;
		result->tv_sec--;
	  }

	  if (result->tv_sec == 0 && result->tv_usec == 0)
		  return 0;

	  if (result->tv_sec >= 0)
		  return 1;

	  return -1;
}

