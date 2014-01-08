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

// Includes...
#include <string.h>

// http://msdn.microsoft.com/en-us/library/b0084kay.aspx
#if defined(_WIN32) || defined(WIN32) || defined(__WIN32__) || defined(ming)
#define PLAT_WINDOWS 1
#endif

#if defined(__FreeBSD__)
#define PLAT_FREEBSD 1
#endif

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

// Defines...
#define false 0
#define true 1

#define mode_help 0
#define mode_version 1
#define mode_single 2
#define mode_multiple 3

#define BUFFERSIZE 1024

#define ssl_all 0
#define ssl_v2 1
#define ssl_v3 2
#define tls_v1 3
#define tls_v11 4
#define tls_v12 5

// force address family
#define FORCE_AF_UNSPEC 0
#define FORCE_AF_INET4 1
#define FORCE_AF_INET6 2

// Global comments:
// The comment style:
//   // Call foo()
//   foo()
// is crappy, but I haven't removed them unless I was otherwise reworking the
// code.

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


const char *program_banner = "                   _\n"
                             "           ___ ___| |___  ___ __ _ _ __\n"
                             "          / __/ __| / __|/ __/ _` | '_ \\\n"
                             "          \\__ \\__ \\ \\__ \\ (_| (_| | | | |\n"
                             "          |___/___/_|___/\\___\\__,_|_| |_|\n\n";
const char *program_version = "sslscan version 1.10.1 ";
const char *xml_version = "1.10.1";


struct sslCipher
{
    // Cipher Properties...
    const char *name;
    char *version;
    int bits;
    char description[512];
    const SSL_METHOD *sslMethod;
    const char *sslMethodName;
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
    int sslVersion;
    int targets;
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
};

// store renegotiation test data
struct renegotiationOutput
{
    int supported;
    int secure;
};

// Adds Ciphers to the Cipher List structure
int populateCipherList(struct sslCheckOptions *options, const SSL_METHOD *sslMethod)
{
    // Variables...
    int returnCode = true;
    struct sslCipher *sslCipherPointer;
    int tempInt;
    int loop;
    // STACK_OF is a sign that you should be using C++ :)
    STACK_OF(SSL_CIPHER) *cipherList;
    SSL *ssl = NULL;

    options->ctx = SSL_CTX_new(sslMethod);
    if (options->ctx == NULL) {
        printf("%sERROR: Could not create CTX object.%s\n", COL_RED, RESET);
        return false;
    }

    SSL_CTX_set_cipher_list(options->ctx, "ALL:COMPLEMENTOFALL");

    ssl = SSL_new(options->ctx);
    if (ssl == NULL) {
        printf("%sERROR: Could not create SSL object.%s\n", COL_RED, RESET);
        SSL_CTX_free(options->ctx);
        return false;
    }

    cipherList = SSL_get_ciphers(ssl);

    // Create Cipher Struct Entries...
    for (loop = 0; loop < sk_SSL_CIPHER_num(cipherList); loop++)
    {
        if (options->ciphers == 0)
        {
            options->ciphers = malloc(sizeof(struct sslCipher));
            sslCipherPointer = options->ciphers;
        }
        else
        {
            sslCipherPointer = options->ciphers;
            while (sslCipherPointer->next != 0)
                sslCipherPointer = sslCipherPointer->next;
            sslCipherPointer->next = malloc(sizeof(struct sslCipher));
            sslCipherPointer = sslCipherPointer->next;
        }

        // Init
        memset(sslCipherPointer, 0, sizeof(struct sslCipher));

        // Add cipher information...
        sslCipherPointer->sslMethod = sslMethod;

#ifndef OPENSSL_NO_SSL2
        if (sslCipherPointer->sslMethod == SSLv2_client_method())
        {
            sslCipherPointer->sslMethodName = "SSLv2";
        }
        else if (sslCipherPointer->sslMethod == SSLv3_client_method())
#else
        if (sslCipherPointer->sslMethod == SSLv3_client_method())
#endif
        {
            sslCipherPointer->sslMethodName = "SSLv3";
        }
        else if (sslCipherPointer->sslMethod == TLSv1_client_method())
        {
            sslCipherPointer->sslMethodName = "TLSv1";
        }
#if OPENSSL_VERSION_NUMBER >= 0x1000008fL || OPENSSL_VERSION_NUMBER >= 0x1000100fL
        else if (sslCipherPointer->sslMethod == TLSv1_1_client_method())
        {
            sslCipherPointer->sslMethodName = "TLS11";
        }
        else if (sslCipherPointer->sslMethod == TLSv1_2_client_method())
        {
            sslCipherPointer->sslMethodName = "TLS12";
        }
#endif // #if OPENSSL_VERSION_NUMBER >= 0x1000008fL || OPENSSL_VERSION_NUMBER >= 0x1000100fL
        sslCipherPointer->name = SSL_CIPHER_get_name(sk_SSL_CIPHER_value(cipherList, loop));
        sslCipherPointer->version = SSL_CIPHER_get_version(sk_SSL_CIPHER_value(cipherList, loop));
        SSL_CIPHER_description(sk_SSL_CIPHER_value(cipherList, loop), sslCipherPointer->description, sizeof(sslCipherPointer->description) - 1);
        sslCipherPointer->bits = SSL_CIPHER_get_bits(sk_SSL_CIPHER_value(cipherList, loop), &tempInt);
    }

    SSL_free(ssl);
    SSL_CTX_free(options->ctx);

    return returnCode;
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

// Private Key Password Callback...
static int password_callback(char *buf, int size, int rwflag, void *userdata)
{
    strncpy(buf, (char *)userdata, size);
    // I don't know the semantics of these arguments, but it looks like this
    // could go badly wrong if userdata is too long.
    buf[strlen(userdata)] = 0;
    return strlen(userdata);
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


// Test renegotiation
int outputRenegotiation( struct sslCheckOptions *options, struct renegotiationOutput *outputData)
{

    if (options->xmlOutput != 0)
    {
        fprintf(options->xmlOutput, "  <renegotiation supported=\"%d\" secure=\"%d\" />\n",
               outputData->supported, outputData->secure);
    }

    if (outputData->secure)
        printf("    Secure session renegotiation supported\n\n");
    else if (outputData->supported)
        printf("    Insecure session renegotiation supported\n\n");
    else
       printf("    Session renegotiation not supported\n\n");

    return true;
}

struct renegotiationOutput * newRenegotiationOutput( void )
{
    struct renegotiationOutput *myRenOut;
    myRenOut = calloc(1,sizeof(struct renegotiationOutput));
    return( myRenOut );
}

int freeRenegotiationOutput( struct renegotiationOutput *myRenOut )
{
    if ( myRenOut != NULL) {
        free(myRenOut);
    }
    return true;
}

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


// Check if the server supports renegotiation
int testRenegotiation(struct sslCheckOptions *options, const SSL_METHOD *sslMethod)
{
    // Variables...
    int cipherStatus;
    int status = true;
    //int secure = false;
    int socketDescriptor = 0;
    int res;
    SSL *ssl = NULL;
    BIO *cipherConnectionBio;
    struct renegotiationOutput *renOut = newRenegotiationOutput();

    tls_reneg_init(options);

    // Connect to host
    socketDescriptor = tcpConnect(options);
    if (socketDescriptor != 0)
    {

        // Setup Context Object...
        options->ctx = SSL_CTX_new(sslMethod);
        if (options->ctx != NULL)
        {
            if (SSL_CTX_set_cipher_list(options->ctx, "ALL:COMPLEMENTOFALL") != 0)
            {

                // Load Certs if required...
                if ((options->clientCertsFile != 0) || (options->privateKeyFile != 0))
                    status = loadCerts(options);

                if (status == true)
                {
                    // Create SSL object...
                    ssl = SSL_new(options->ctx);

#if ( OPENSSL_VERSION_NUMBER > 0x009080cfL )
                    // Make sure we can connect to insecure servers
                    // OpenSSL is going to change the default at a later date
                    SSL_set_options(ssl, SSL_OP_LEGACY_SERVER_CONNECT);
#endif

                   if (ssl != NULL)
                    {
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
                        SSL_set_options(ssl,
                                        SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION);
                      }


                        if (cipherStatus == 1)
                        {

#if ( OPENSSL_VERSION_NUMBER > 0x009080cfL )
                            // SSL_get_secure_renegotiation_support() appeared first in OpenSSL 0.9.8m
                            if(options->verbose)
                                printf("Attempting secure_renegotiation_support()");
                            renOut->secure = SSL_get_secure_renegotiation_support(ssl);
                            if( renOut->secure )
                            {
                                // If it supports secure renegotiations,
                                // it should have renegotioation support in general
                                renOut->supported = true;
                                status = true;
                            }
                            else
                            {
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

                                if (ssl->state == SSL_ST_OK)
                                {
                                    res = SSL_do_handshake(ssl); // Send renegotiation request to server
                                    if( res != 1 )
                                    {
                                        fprintf(stderr, "\n\nSSL_do_handshake() call failed\n");
                                    }
                                    if (ssl->state == SSL_ST_OK)
                                    {
                                        /* our renegotiation is complete */
                                        renOut->supported = true;
                                        status = true;
                                    } else {
                                        renOut->supported = false;
                                        status = false;
                                        fprintf(stderr, "\n\nFailed to complete renegotiation\n");
                                    }
                                } else {
                                    status = false;
                                    renOut->secure = false;
                                }
#if ( OPENSSL_VERSION_NUMBER > 0x009080cfL )
                            }
#endif
                            // Disconnect SSL over socket
                            SSL_shutdown(ssl);
                        }

                        // Free SSL object
                        SSL_free(ssl);
                    }
                    else
                    {
                        status = false;
                        renOut->supported = false;
                        fprintf(stderr, "%s    ERROR: Could create SSL object.%s\n", COL_RED, RESET);
                    }
                }
            }
            else
            {
                status = false;
                renOut->supported = false;
                fprintf(stderr, "%s    ERROR: Could set cipher.%s\n", COL_RED, RESET);
            }
            // Free CTX Object
            SSL_CTX_free(options->ctx);
        }
        // Error Creating Context Object
        else
        {
            status = false;
            renOut->supported = false;
            fprintf(stderr, "%sERROR: Could not create CTX object.%s\n", COL_RED, RESET);
        }

        // Disconnect from host
        close(socketDescriptor);
    }
    else
    {
        // Could not connect
        fprintf(stderr, "%sERROR: Could not connect.%s\n", COL_RED, RESET);
        renOut->supported = false;
        status = false;
        freeRenegotiationOutput( renOut );
        exit(status);
    }
    outputRenegotiation(options, renOut);
    freeRenegotiationOutput( renOut );

    return status;

}

// Test a cipher...
int testCipher(struct sslCheckOptions *options, struct sslCipher *sslCipherPointer)
{
    // Variables...
    int cipherStatus;
    int status = true;
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

    // Connect to host
    socketDescriptor = tcpConnect(options);
    if (socketDescriptor != 0)
    {
        if (SSL_CTX_set_cipher_list(options->ctx, sslCipherPointer->name) != 0)
        {

            // Create SSL object...
            ssl = SSL_new(options->ctx);
            if (ssl != NULL)
            {
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

                // Show Cipher Status
                if (!((options->noFailed == true) && (cipherStatus != 1)))
                {
                    if (options->xmlOutput != 0)
                        fprintf(options->xmlOutput, "  <cipher status=\"");
                    if (cipherStatus == 1)
                    {
                        if (options->xmlOutput != 0)
                            fprintf(options->xmlOutput, "accepted\"");
                        if (options->pout == true)
                            printf("|| Accepted || ");
                        else
                            printf("    Accepted  ");
                        if (options->http == true)
                        {

                            // Stdout BIO...
                            stdoutBIO = BIO_new(BIO_s_file());
                            BIO_set_fp(stdoutBIO, stdout, BIO_NOCLOSE);

                            // HTTP Get...
                            SSL_write(ssl, requestBuffer, sizeof(requestBuffer));
                            memset(buffer ,0 , 50);
                            resultSize = SSL_read(ssl, buffer, 49);
                            if (resultSize > 9)
                            {
                                int loop = 0;
                                for (loop = 9; (loop < 49) && (buffer[loop] != 0) && (buffer[loop] != '\r') && (buffer[loop] != '\n'); loop++)
                                { }
                                buffer[loop] = 0;

                                // Output HTTP code...
                                if (options->pout == true)
                                    printf("%s || ", buffer + 9);
                                else
                                {
                                    printf("%s", buffer + 9);
                                    loop = strlen(buffer + 9);
                                    while (loop < 17)
                                    {
                                        loop++;
                                        printf(" ");
                                    }
                                }
                                if (options->xmlOutput != 0)
                                    fprintf(options->xmlOutput, " http=\"%s\"", buffer + 9);
                            }
                            else
                            {
                                // Output HTTP code...
                                if (options->pout == true)
                                    printf("|| || ");
                                else
                                    printf("                 ");
                            }
                        }
                    }
                    else if (cipherStatus == 0)
                    {
                        if (options->xmlOutput != 0)
                            fprintf(options->xmlOutput, "rejected\"");
                        if (options->http == true)
                        {
                            if (options->pout == true)
                                printf("|| Rejected || N/A || ");
                            else
                                printf("    Rejected  N/A              ");
                        }
                        else
                        {
                            if (options->pout == true)
                                printf("|| Rejected || ");
                            else
                                printf("    Rejected  ");
                        }
                    }
                    else
                    {
                        if (options->verbose == true)
                            printf("SSL_get_error(ssl, cipherStatus) said: %d\n", SSL_get_error(ssl, cipherStatus));
                        if (options->xmlOutput != 0)
                            fprintf(options->xmlOutput, "failed\"");
                        if (options->http == true)
                        {
                            if (options->pout == true)
                                printf("|| Failed || N/A || ");
                            else
                                printf("    Failed    N/A              ");
                        }
                        else
                        {
                            if (options->pout == true)
                                printf("|| Failed || ");
                            else
                                printf("    Failed    ");
                        }
                    }
                    if (options->xmlOutput != 0)
                    {
                        fprintf(options->xmlOutput, " sslversion=\"");
                        fprintf(options->xmlOutput, "%s\" bits=\"", sslCipherPointer->sslMethodName);
                    }
                    if (options->pout == true)
                        printf("%s || ", sslCipherPointer->sslMethodName);
                    else
                        printf("%s  ", sslCipherPointer->sslMethodName);

                    if (sslCipherPointer->bits < 10)
                        tempInt = 2;
                    else if (sslCipherPointer->bits < 100)
                        tempInt = 1;
                    else
                        tempInt = 0;
                    if (options->pout == true)
                        printf("%d || ", sslCipherPointer->bits);
                    else
                        printf("%d bits  ", sslCipherPointer->bits);
                    while (tempInt != 0)
                    {
                        tempInt--;
                        printf(" ");
                    }
                    if (options->xmlOutput != 0)
                        fprintf(options->xmlOutput, "%d\" cipher=\"%s\" />\n", sslCipherPointer->bits, sslCipherPointer->name);
                    if (options->pout == true)
                        printf("%s ||\n", sslCipherPointer->name);
                    else
                        printf("%s\n", sslCipherPointer->name);
                }

                // Disconnect SSL over socket
                if (cipherStatus == 1)
                    SSL_shutdown(ssl);

                // Free SSL object
                SSL_free(ssl);
            }
            else
            {
                status = false;
                printf("%s    ERROR: Could create SSL object.%s\n", COL_RED, RESET);
            }
        }
        else
        {
            status = false;
            printf("%s    ERROR: Could set cipher %s.%s\n", COL_RED, sslCipherPointer->name, RESET);
        }

        // Disconnect from host
        close(socketDescriptor);
    }

    // Could not connect
    else
        status = false;

    return status;
}


// Test for preferred ciphers
int defaultCipher(struct sslCheckOptions *options, const const SSL_METHOD *sslMethod)
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
    if (socketDescriptor != 0)
    {

        // Setup Context Object...
        options->ctx = SSL_CTX_new(sslMethod);
        if (options->ctx != NULL)
        {
            if (SSL_CTX_set_cipher_list(options->ctx, "ALL:COMPLEMENTOFALL") != 0)
            {

                // Load Certs if required...
                if ((options->clientCertsFile != 0) || (options->privateKeyFile != 0))
                    status = loadCerts(options);

                if (status == true)
                {
                    // Create SSL object...
                    ssl = SSL_new(options->ctx);
                    if (ssl != NULL)
                    {
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
                        if (cipherStatus == 1)
                        {
#ifndef OPENSSL_NO_SSL2
                            if (sslMethod == SSLv2_client_method())
                            {
                                if (options->xmlOutput != 0)
                                    fprintf(options->xmlOutput, "  <defaultcipher sslversion=\"SSLv2\" bits=\"");
                                if (options->pout == true)
                                    printf("|| SSLv2 || ");
                                else
                                    printf("    SSLv2  ");
                            }
                            else if (sslMethod == SSLv3_client_method())
#else
                            if (sslMethod == SSLv3_client_method())
#endif
                            {
                                if (options->xmlOutput != 0)
                                    fprintf(options->xmlOutput, "  <defaultcipher sslversion=\"SSLv3\" bits=\"");
                                if (options->pout == true)
                                    printf("|| SSLv3 || ");
                                else
                                    printf("    SSLv3  ");
                            }
                            else if (sslMethod == TLSv1_client_method())
                            {
                                if (options->xmlOutput != 0)
                                    fprintf(options->xmlOutput, "  <defaultcipher sslversion=\"TLSv1\" bits=\"");
                                if (options->pout == true)
                                    printf("|| TLSv1 || ");
                                else
                                    printf("    TLSv1  ");
                            }
#if OPENSSL_VERSION_NUMBER >= 0x1000008fL || OPENSSL_VERSION_NUMBER >= 0x1000100fL
                            else if (sslMethod == TLSv1_1_client_method())
                            {
                                if (options->xmlOutput != 0)
                                    fprintf(options->xmlOutput, "  <defaultcipher sslversion=\"TLS11\" bits=\"");
                                if (options->pout == true)
                                    printf("|| TLS11 || ");
                                else
                                    printf("    TLS11  ");
                            }
                            else if (sslMethod == TLSv1_2_client_method())
                            {
                                if (options->xmlOutput != 0)
                                    fprintf(options->xmlOutput, "  <defaultcipher sslversion=\"TLSv2\" bits=\"");
                                if (options->pout == true)
                                    printf("|| TLS12 || ");
                                else
                                    printf("    TLS12  ");
                            }
#endif // #if OPENSSL_VERSION_NUMBER >= 0x1000008fL || OPENSSL_VERSION_NUMBER >= 0x1000100fL

                            if (SSL_get_cipher_bits(ssl, &tempInt2) < 10)
                                tempInt = 2;
                            else if (SSL_get_cipher_bits(ssl, &tempInt2) < 100)
                                tempInt = 1;
                            else
                                tempInt = 0;
                            if (options->pout == true)
                                printf("%d bits || ", SSL_get_cipher_bits(ssl, &tempInt2));
                            else
                                printf("%d bits  ", SSL_get_cipher_bits(ssl, &tempInt2));
                            while (tempInt != 0)
                            {
                                tempInt--;
                                printf(" ");
                            }
                            if (options->xmlOutput != 0)
                                fprintf(options->xmlOutput, "%d\" cipher=\"%s\" />\n", SSL_get_cipher_bits(ssl, &tempInt2), SSL_get_cipher_name(ssl));
                            if (options->pout == true)
                                printf("%s ||\n", SSL_get_cipher_name(ssl));
                            else
                                printf("%s\n", SSL_get_cipher_name(ssl));

                            // Disconnect SSL over socket
                            SSL_shutdown(ssl);
                        }

                        // Free SSL object
                        SSL_free(ssl);
                    }
                    else
                    {
                        status = false;
                        printf("%s    ERROR: Could create SSL object.%s\n", COL_RED, RESET);
                    }
                }
            }
            else
            {
                status = false;
                printf("%s    ERROR: Could set cipher.%s\n", COL_RED, RESET);
            }

            // Free CTX Object
            SSL_CTX_free(options->ctx);
        }

        // Error Creating Context Object
        else
        {
            status = false;
            printf("%sERROR: Could not create CTX object.%s\n", COL_RED, RESET);
        }

        // Disconnect from host
        close(socketDescriptor);
    }

    // Could not connect
    else
        status = false;

    return status;
}


// Get certificate...
int getCertificate(struct sslCheckOptions *options)
{
    // Variables...
    int cipherStatus = 0;
    int status = true;
    int socketDescriptor = 0;
    SSL *ssl = NULL;
    BIO *cipherConnectionBio = NULL;
    BIO *stdoutBIO = NULL;
    BIO *fileBIO = NULL;
    X509 *x509Cert = NULL;
    EVP_PKEY *publicKey = NULL;
    const SSL_METHOD *sslMethod = NULL;
    ASN1_OBJECT *asn1Object = NULL;
    X509_EXTENSION *extension = NULL;
    char buffer[1024];
    long tempLong = 0;
    int tempInt = 0;
    int tempInt2 = 0;
    long verifyError = 0;

    // Connect to host
    socketDescriptor = tcpConnect(options);
    if (socketDescriptor != 0)
    {

        // Setup Context Object...
        if( options->sslVersion == tls_v1) {
            if (options->verbose)
                printf("sslMethod = TLSv1_method()");
            sslMethod = TLSv1_method();
        } else {
            if (options->verbose)
                printf("sslMethod = SSLv23_method()");
            sslMethod = SSLv23_method();
        }
        options->ctx = SSL_CTX_new(sslMethod);
        if (options->ctx != NULL)
        {

            if (SSL_CTX_set_cipher_list(options->ctx, "ALL:COMPLEMENTOFALL") != 0)
            {

                // Load Certs if required...
                if ((options->clientCertsFile != 0) || (options->privateKeyFile != 0))
                    status = loadCerts(options);

                if (status == true)
                {
                    // Create SSL object...
                    ssl = SSL_new(options->ctx);
                    if (ssl != NULL)
                    {

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
                        if (cipherStatus == 1)
                        {

                            // Setup BIO's
                            stdoutBIO = BIO_new(BIO_s_file());
                            BIO_set_fp(stdoutBIO, stdout, BIO_NOCLOSE);
                            if (options->xmlOutput != 0)
                            {
                                fileBIO = BIO_new(BIO_s_file());
                                BIO_set_fp(fileBIO, options->xmlOutput, BIO_NOCLOSE);
                            }

                            // Get Certificate...
                            printf("\n  %sSSL Certificate:%s\n", COL_BLUE, RESET);
                            if (options->xmlOutput != 0)
                                fprintf(options->xmlOutput, "  <certificate>\n");
                            x509Cert = SSL_get_peer_certificate(ssl);
                            if (x509Cert != NULL)
                            {

                                // Print a base64 blob version of the cert
                                printf("    Certificate blob:\n");
                                PEM_write_bio_X509(stdoutBIO,x509Cert);
                                if (options->xmlOutput != 0)
                                {
                                    fprintf(options->xmlOutput, "   <certificate-blob>\n");
                                    PEM_write_bio_X509(fileBIO,x509Cert);
                                    fprintf(options->xmlOutput, "   </certificate-blob>\n");
                                }

                                //SSL_set_verify(ssl, SSL_VERIFY_NONE|SSL_VERIFY_CLIENT_ONCE, NULL);

                                // Cert Version
                                if (!(X509_FLAG_COMPAT & X509_FLAG_NO_VERSION))
                                {
                                    tempLong = X509_get_version(x509Cert);
                                    printf("    Version: %lu\n", tempLong);
                                    if (options->xmlOutput != 0)
                                        fprintf(options->xmlOutput, "   <version>%lu</version>\n", tempLong);
                                }

                                // Cert Serial No. - Code adapted from OpenSSL's crypto/asn1/t_x509.c
                                if (!(X509_FLAG_COMPAT & X509_FLAG_NO_SERIAL))
                                {
                                    ASN1_INTEGER *bs;
                                    BIO *bp;
                                    BIO *xml_bp;
                                    bp = BIO_new_fp(stdout, BIO_NOCLOSE);
                                    if (options->xmlOutput != 0)
                                        xml_bp = BIO_new_fp(options->xmlOutput, BIO_NOCLOSE);
                                    long l;
                                    int i;
                                    const char *neg;
                                    bs=X509_get_serialNumber(x509Cert);

                                    if (BIO_write(bp,"    Serial Number:",18) <= 0)
                                        return(1);

                                    if (bs->length <= 4)
                                    {
                                        l=ASN1_INTEGER_get(bs);
                                        if (l < 0)
                                        {
                                            l= -l;
                                            neg="-";
                                        }
                                        else
                                            neg="";
                                        if (BIO_printf(bp," %s%lu (%s0x%lx)\n",neg,l,neg,l) <= 0)
                                            return(1);
                                        if (options->xmlOutput != 0)
                                            if (BIO_printf(xml_bp,"   <serial>%s%lu (%s0x%lx)</serial>\n",neg,l,neg,l) <= 0)
                                                return(1);
                                    }
                                    else
                                    {
                                        neg=(bs->type == V_ASN1_NEG_INTEGER)?" (Negative)":"";
                                        if (BIO_printf(bp,"%1s%s","",neg) <= 0)
                                            return(1);

                                        if (options->xmlOutput != 0)
                                            if (BIO_printf(xml_bp,"   <serial>") <= 0)
                                                return(1);

                                        for (i=0; i<bs->length; i++)
                                        {
                                            if (BIO_printf(bp,"%02x%c",bs->data[i],
                                                        ((i+1 == bs->length)?'\n':':')) <= 0)
                                                return(1);
                                            if (options->xmlOutput != 0) {
                                                if (i+1 == bs->length)
                                                {
                                                    if (BIO_printf(xml_bp,"%02x",bs->data[i]) <= 0)
                                                        return(1);
                                                }
                                                else
                                                {
                                                    if (BIO_printf(xml_bp,"%02x%c",bs->data[i], ':') <= 0)
                                                        return(1);
                                                }
                                            }
                                        }

                                        if (options->xmlOutput != 0)
                                            if (BIO_printf(xml_bp,"</serial>\n") <= 0)
                                                return(1);

                                    }
                                    if(NULL != bp)
                                        BIO_free(bp);
                                    // We don't free the xml_bp because it will be used in the future
                                }

                                // Signature Algo...
                                if (!(X509_FLAG_COMPAT & X509_FLAG_NO_SIGNAME))
                                {
                                    printf("    Signature Algorithm: ");
                                    i2a_ASN1_OBJECT(stdoutBIO, x509Cert->cert_info->signature->algorithm);
                                    printf("\n");
                                    if (options->xmlOutput != 0)
                                    {
                                        fprintf(options->xmlOutput, "   <signature-algorithm>");
                                        i2a_ASN1_OBJECT(fileBIO, x509Cert->cert_info->signature->algorithm);
                                        fprintf(options->xmlOutput, "</signature-algorithm>\n");
                                    }
                                }

                                // SSL Certificate Issuer...
                                if (!(X509_FLAG_COMPAT & X509_FLAG_NO_ISSUER))
                                {
                                    X509_NAME_oneline(X509_get_issuer_name(x509Cert), buffer, sizeof(buffer) - 1);
                                    printf("    Issuer: %s\n", buffer);
                                    if (options->xmlOutput != 0)
                                        fprintf(options->xmlOutput, "   <issuer>%s</issuer>\n", buffer);
                                }

                                // Validity...
                                if (!(X509_FLAG_COMPAT & X509_FLAG_NO_VALIDITY))
                                {
                                    printf("    Not valid before: ");
                                    ASN1_TIME_print(stdoutBIO, X509_get_notBefore(x509Cert));
                                    if (options->xmlOutput != 0)
                                    {
                                        fprintf(options->xmlOutput, "   <not-valid-before>");
                                        ASN1_TIME_print(fileBIO, X509_get_notBefore(x509Cert));
                                        fprintf(options->xmlOutput, "</not-valid-before>\n");
                                    }
                                    printf("\n    Not valid after: ");
                                    ASN1_TIME_print(stdoutBIO, X509_get_notAfter(x509Cert));
                                    printf("\n");
                                    if (options->xmlOutput != 0)
                                    {
                                        fprintf(options->xmlOutput, "   <not-valid-after>");
                                        ASN1_TIME_print(fileBIO, X509_get_notAfter(x509Cert));
                                        fprintf(options->xmlOutput, "</not-valid-after>\n");
                                    }
                                }

                                // SSL Certificate Subject...
                                if (!(X509_FLAG_COMPAT & X509_FLAG_NO_SUBJECT))
                                {
                                    X509_NAME_oneline(X509_get_subject_name(x509Cert), buffer, sizeof(buffer) - 1);
                                    printf("    Subject: %s\n", buffer);
                                    if (options->xmlOutput != 0)
                                        fprintf(options->xmlOutput, "   <subject>%s</subject>\n", buffer);
                                }

                                // Public Key Algo...
                                if (!(X509_FLAG_COMPAT & X509_FLAG_NO_PUBKEY))
                                {
                                    printf("    Public Key Algorithm: ");
                                    i2a_ASN1_OBJECT(stdoutBIO, x509Cert->cert_info->key->algor->algorithm);
                                    printf("\n");
                                    if (options->xmlOutput != 0)
                                    {
                                        fprintf(options->xmlOutput, "   <pk-algorithm>");
                                        i2a_ASN1_OBJECT(fileBIO, x509Cert->cert_info->key->algor->algorithm);
                                        fprintf(options->xmlOutput, "</pk-algorithm>\n");
                                    }

                                    // Public Key...
                                    publicKey = X509_get_pubkey(x509Cert);
                                    if (publicKey == NULL)
                                    {
                                        printf("    Public Key: Could not load\n");
                                        if (options->xmlOutput != 0)
                                            fprintf(options->xmlOutput, "   <pk error=\"true\" />\n");
                                    }
                                    else
                                    {
                                        switch (publicKey->type)
                                        {
                                            case EVP_PKEY_RSA:
                                                if (publicKey->pkey.rsa)
                                                {
                                                    printf("    RSA Public Key: (%d bit)\n", BN_num_bits(publicKey->pkey.rsa->n));
                                                    if (options->xmlOutput != 0)
                                                        fprintf(options->xmlOutput, "   <pk error=\"false\" type=\"RSA\" bits=\"%d\">\n", BN_num_bits(publicKey->pkey.rsa->n));
                                                    RSA_print(stdoutBIO, publicKey->pkey.rsa, 6);
                                                    if (options->xmlOutput != 0)
                                                    {
                                                        RSA_print(fileBIO, publicKey->pkey.rsa, 4);
                                                        fprintf(options->xmlOutput, "   </pk>\n");
                                                    }
                                                }
                                                else
                                                {
                                                    printf("    RSA Public Key: NULL\n");
                                                }
                                                break;
                                            case EVP_PKEY_DSA:
                                                if (publicKey->pkey.dsa)
                                                {
                                                    printf("    DSA Public Key:\n");
                                                    if (options->xmlOutput != 0)
                                                        fprintf(options->xmlOutput, "   <pk error=\"false\" type=\"DSA\">\n");
                                                    DSA_print(stdoutBIO, publicKey->pkey.dsa, 6);
                                                    if (options->xmlOutput != 0)
                                                    {
                                                        DSA_print(fileBIO, publicKey->pkey.dsa, 4);
                                                        fprintf(options->xmlOutput, "   </pk>\n");
                                                    }
                                                }
                                                else
                                                {
                                                    printf("    DSA Public Key: NULL\n");
                                                }
                                                break;
// EC_KEY_print() is only available if OPENSSL_NO_EC and OPENSSL_NO_BIO are defined
#if defined(EVP_PKEY_EC) && !defined(OPENSSL_NO_BIO) && !defined(OPENSSL_NO_EC)
                                            case EVP_PKEY_EC:
                                                if (publicKey->pkey.ec)
                                                {
                                                    printf("    EC Public Key:\n");
                                                    if (options->xmlOutput != 0)
                                                        fprintf(options->xmlOutput, "   <pk error=\"false\" type=\"EC\">\n");
                                                    EC_KEY_print(stdoutBIO, publicKey->pkey.ec, 6);
                                                    if (options->xmlOutput != 0)
                                                    {
                                                        EC_KEY_print(fileBIO, publicKey->pkey.ec, 4);
                                                        fprintf(options->xmlOutput, "   </pk>\n");
                                                    }
                                                }
                                                else
                                                {
                                                    printf("    EC Public Key: NULL\n");
                                                }
                                                break;
#endif // #if defined(EVP_PKEY_EC) && !defined(OPENSSL_NO_BIO)
                                            default:
                                                printf("    Public Key: Unknown\n");
                                                if (options->xmlOutput != 0)
                                                    fprintf(options->xmlOutput, "   <pk error=\"true\" type=\"unknown\" />\n");
                                                break;
                                        }

                                        EVP_PKEY_free(publicKey);
                                    }
                                }

                                // X509 v3...
                                if (!(X509_FLAG_COMPAT & X509_FLAG_NO_EXTENSIONS))
                                {
                                    if (sk_X509_EXTENSION_num(x509Cert->cert_info->extensions) > 0)
                                    {
                                        printf("    X509v3 Extensions:\n");
                                        if (options->xmlOutput != 0)
                                            fprintf(options->xmlOutput, "   <X509v3-Extensions>\n");
                                        for (tempInt = 0; tempInt < sk_X509_EXTENSION_num(x509Cert->cert_info->extensions); tempInt++)
                                        {
                                            // Get Extension...
                                            extension = sk_X509_EXTENSION_value(x509Cert->cert_info->extensions, tempInt);

                                            // Print Extension name...
                                            printf("      ");
                                            asn1Object = X509_EXTENSION_get_object(extension);
                                            i2a_ASN1_OBJECT(stdoutBIO, asn1Object);
                                            tempInt2 = X509_EXTENSION_get_critical(extension);
                                            BIO_printf(stdoutBIO, ": %s\n", tempInt2 ? "critical" : "");
                                            if (options->xmlOutput != 0)
                                            {
                                                fprintf(options->xmlOutput, "    <extension name=\"");
                                                i2a_ASN1_OBJECT(fileBIO, asn1Object);
                                                BIO_printf(fileBIO, "\"%s>", tempInt2 ? " level=\"critical\"" : "");
                                            }

                                            // Print Extension value...
                                            if (!X509V3_EXT_print(stdoutBIO, extension, X509_FLAG_COMPAT, 8))
                                            {
                                                printf("        ");
                                                M_ASN1_OCTET_STRING_print(stdoutBIO, extension->value);
                                            }
                                            if (options->xmlOutput != 0)
                                            {
                                                if (!X509V3_EXT_print(fileBIO, extension, X509_FLAG_COMPAT, 0))
                                                    M_ASN1_OCTET_STRING_print(fileBIO, extension->value);
                                                fprintf(options->xmlOutput, "</extension>\n");
                                            }
                                            printf("\n");
                                        }
                                        if (options->xmlOutput != 0)
                                            fprintf(options->xmlOutput, "   </X509v3-Extensions>\n");
                                    }
                                }

                                // Verify Certificate...
                                printf("  Verify Certificate:\n");
                                verifyError = SSL_get_verify_result(ssl);
                                if (verifyError == X509_V_OK)
                                    printf("    Certificate passed verification\n");
                                else
                                    printf("    %s\n", X509_verify_cert_error_string(verifyError));

                                // Free X509 Certificate...
                                X509_free(x509Cert);
                            }

                       else {
                                printf("    Unable to parse certificate\n");
                       }

                            if (options->xmlOutput != 0)
                                fprintf(options->xmlOutput, "  </certificate>\n");

                            // Free BIO
                            BIO_free(stdoutBIO);
                            if (options->xmlOutput != 0)
                                BIO_free(fileBIO);

                            // Disconnect SSL over socket
                            SSL_shutdown(ssl);
                        }

                        // Free SSL object
                        SSL_free(ssl);
                    }
                    else
                    {
                        status = false;
                        printf("%s    ERROR: Could create SSL object.%s\n", COL_RED, RESET);
                    }
                }
            }
            else
            {
                status = false;
                printf("%s    ERROR: Could set cipher.%s\n", COL_RED, RESET);
            }

            // Free CTX Object
            SSL_CTX_free(options->ctx);
        }

        // Error Creating Context Object
        else
        {
            status = false;
            printf("%sERROR: Could not create CTX object.%s\n", COL_RED, RESET);
        }

        // Disconnect from host
        close(socketDescriptor);
    }

    // Could not connect
    else
        status = false;

    return status;
}


// Test a single host and port for ciphers...
int testHost(struct sslCheckOptions *options)
{
    // Variables...
    struct sslCipher *sslCipherPointer;
    int status = true;
    const SSL_METHOD *sslMethod = NULL;

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

    int status_; // ToDo: clean up
    status_ = getaddrinfo(options->host, options->service, &hints, &options->addrList);

    if (status_ != 0)
    {
        if (status_ == EAI_SYSTEM)
        {
            perror("getaddrinfo");
        }
        else
        {
            fprintf(stderr, "error in getaddrinfo: %s\n", gai_strerror(status));
        }
        //printf("%sERROR: Could not resolve hostname %s.%s\n", COL_RED, options->host, RESET);
        return false;
    }

    // find local address
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    if (options->forceAddressFamily == FORCE_AF_INET4)
        hints.ai_family = AF_INET;
    else if (options->forceAddressFamily == FORCE_AF_INET6)
        hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    status_ = getaddrinfo(options->localAddress, NULL, &hints, &options->localAddrList);


    // XML Output...
    if (options->xmlOutput != 0)
        fprintf(options->xmlOutput, " <ssltest host=\"%s\" port=\"%s\">\n", options->host, options->service);

    // Test renegotiation
    printf("\n%sTesting SSL server %s on port %s%s\n\n", COL_GREEN, options->host, options->service, RESET);

    sslCipherPointer = options->ciphers;
    printf("  %sSupported Client Cipher(s):%s\n", COL_BLUE, RESET);
    while ((sslCipherPointer != 0) && (status == true))
    {
        if (sslCipherPointer->sslMethod != sslMethod)
        {
            printf("%s:\n", sslCipherPointer->sslMethodName);
            sslMethod = sslCipherPointer->sslMethod;
        }
        printf("    %s\n",sslCipherPointer->name);

        if (options->xmlOutput != 0)
            fprintf(options->xmlOutput, " <client-cipher cipher=\"%s\" />\n", sslCipherPointer->name);

        sslCipherPointer = sslCipherPointer->next;
    }

    if (status == true && options->reneg )
    {
        printf("\n  %sTLS renegotiation:%s\n", COL_BLUE, RESET);
        testRenegotiation(options, TLSv1_client_method());
    }

    // Test supported ciphers...
    printf("  %sSupported Server Cipher(s):%s\n", COL_BLUE, RESET);
    if ((options->http == true) && (options->pout == true))
        printf("|| Status || HTTP Code || Version || Bits || Cipher ||\n");
    else if (options->pout == true)
        printf("|| Status || Version || Bits || Cipher ||\n");
    sslCipherPointer = options->ciphers;
    while ((sslCipherPointer != 0) && (status == true))
    {

        // Setup Context Object...
        options->ctx = SSL_CTX_new(sslCipherPointer->sslMethod);
        if (options->ctx != NULL)
        {

            // SSL implementation bugs/workaround
            if (options->sslbugs)
                SSL_CTX_set_options(options->ctx, SSL_OP_ALL | 0);
            else
                SSL_CTX_set_options(options->ctx, 0);

            // Load Certs if required...
            if ((options->clientCertsFile != 0) || (options->privateKeyFile != 0))
                status = loadCerts(options);

            // Test
            if (status == true)
                status = testCipher(options, sslCipherPointer);

            // Free CTX Object
            SSL_CTX_free(options->ctx);
        }

        // Error Creating Context Object
        else
        {
            status = false;
            printf("%sERROR: Could not create CTX object.%s\n", COL_RED, RESET);
        }

        sslCipherPointer = sslCipherPointer->next;
    }

    if (status == true)
    {
        // Test preferred ciphers...
        printf("\n  %sPreferred Server Cipher(s):%s\n", COL_BLUE, RESET);
        if (options->pout == true)
            printf("|| Version || Bits || Cipher ||\n");
        switch (options->sslVersion)
        {
            case ssl_all:
                status = true;
#ifndef OPENSSL_NO_SSL2
                if (status != false)
                    status = defaultCipher(options, SSLv2_client_method());
#endif
                if (status != false)
                    status = defaultCipher(options, SSLv3_client_method());
                if (status != false)
                    status = defaultCipher(options, TLSv1_client_method());

#if OPENSSL_VERSION_NUMBER >= 0x1000008fL || OPENSSL_VERSION_NUMBER >= 0x1000100fL
                if (status != false)
                    status = defaultCipher(options, TLSv1_1_client_method());
                if (status != false)
                    status = defaultCipher(options, TLSv1_2_client_method());
#endif // #if OPENSSL_VERSION_NUMBER >= 0x1000008fL || OPENSSL_VERSION_NUMBER >= 0x1000100fL

                break;
            case ssl_v2:
#ifndef OPENSSL_NO_SSL2
                // ToDo: Display error?
                status = defaultCipher(options, SSLv2_client_method());
#endif
                break;
            case ssl_v3:
                status = defaultCipher(options, SSLv3_client_method());
                break;
            case tls_v1:
                status = defaultCipher(options, TLSv1_client_method());
                break;

#if OPENSSL_VERSION_NUMBER >= 0x1000008fL || OPENSSL_VERSION_NUMBER >= 0x1000100fL
            case tls_v11:
                status = defaultCipher(options, TLSv1_1_client_method());
                break;
            case tls_v12:
                status = defaultCipher(options, TLSv1_2_client_method());
                break;
#endif // #if OPENSSL_VERSION_NUMBER >= 0x1000008fL || OPENSSL_VERSION_NUMBER >= 0x1000100fL

        }
    }

    if (status == true)
    {
        status = getCertificate(options);
    }

    // XML Output...
    if (options->xmlOutput != 0)
        fprintf(options->xmlOutput, " </ssltest>\n");

    // Return status...
    return status;
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

int main(int argc, char *argv[])
{
    // Variables...
    struct sslCheckOptions options;
    struct sslCipher *sslCipherPointer;
    int status=0;
    int argLoop;
    int xmlArg;
    int mode = mode_help;
    FILE *targetsFile;
    char line[1024];

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

    options.sslVersion = ssl_all;
    options.pout = false;
    SSL_library_init();

    // Get program parameters
    for (argLoop = 1; argLoop < argc; argLoop++)
    {
        // Help
        if (strcmp("--help", argv[argLoop]) == 0)
            mode = mode_help;

        // targets
        else if ((strncmp("--targets=", argv[argLoop], 10) == 0) && (strlen(argv[argLoop]) > 10))
        {
            mode = mode_multiple;
            options.targets = argLoop;
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
        }

        // Show only supported
        else if (strcmp("--no-failed", argv[argLoop]) == 0)
            options.noFailed = true;

        // Version
        else if (strcmp("--version", argv[argLoop]) == 0)
            mode = mode_version;

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
            options.sslVersion = tls_v1;
            options.starttls_ftp = true;
        }
        // StartTLS... IMAP
        else if (strcmp("--starttls-imap", argv[argLoop]) == 0)
        {
            options.sslVersion = tls_v1;
            options.starttls_imap = true;
        }
        // StartTLS... POP3
        else if (strcmp("--starttls-pop3", argv[argLoop]) == 0)
        {
            options.sslVersion = tls_v1;
            options.starttls_pop3 = true;
        }
        // StartTLS... SMTP
        else if (strcmp("--starttls-smtp", argv[argLoop]) == 0)
        {
            options.sslVersion = tls_v1;
            options.starttls_smtp = true;
        }
        // StartTLS... XMPP
        else if (strcmp("--starttls-xmpp", argv[argLoop]) == 0)
        {
            options.sslVersion = tls_v1;
            options.starttls_xmpp = true;
        }
        // XMPP... Domain
        else if (strncmp("--xmpp-domain=", argv[argLoop], 14) == 0)
        {
            options.xmpp_domain = argv[argLoop] +14;
        }

#ifndef OPENSSL_NO_SSL2
        // SSL v2 only...
        else if (strcmp("--ssl2", argv[argLoop]) == 0)
            options.sslVersion = ssl_v2;
#endif // #ifndef OPENSSL_NO_SSL2

        // SSL v3 only...
        else if (strcmp("--ssl3", argv[argLoop]) == 0)
            options.sslVersion = ssl_v3;

        // TLS v1 only...
        else if (strcmp("--tls1", argv[argLoop]) == 0)
            options.sslVersion = tls_v1;

#if OPENSSL_VERSION_NUMBER >= 0x1000008fL || OPENSSL_VERSION_NUMBER >= 0x1000100fL
        // TLS v11 only...
        else if (strcmp("--tls11", argv[argLoop]) == 0)
            options.sslVersion = tls_v11;

        // TLS v12 only...
        else if (strcmp("--tls12", argv[argLoop]) == 0)
            options.sslVersion = tls_v12;
#endif // #if OPENSSL_VERSION_NUMBER >= 0x1000008fL || OPENSSL_VERSION_NUMBER >= 0x1000100fL

        // SSL Bugs...
        else if (strcmp("--bugs", argv[argLoop]) == 0)
            options.sslbugs = 1;

        // SSL HTTP Get...
        else if (strcmp("--http", argv[argLoop]) == 0)
            options.http = 1;

        // Host (maybe port too)...
        else if (argLoop + 1 == argc)
        {
            mode = mode_single;

            // Get host...
            parseHostString(argv[argLoop], &options);
        }

        // Not too sure what the user is doing...
        else
            mode = mode_help;
    }

    // Open XML file output...
    if ((xmlArg > 0) && (mode != mode_help))
    {
        options.xmlOutput = fopen(argv[xmlArg] + 6, "w");
        if (options.xmlOutput == NULL)
        {
            printf("%sERROR: Could not open XML output file %s.%s\n", COL_RED, argv[xmlArg] + 6, RESET);
            exit(0);
        }

        // Output file header...
        fprintf(options.xmlOutput, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<document title=\"SSLScan Results\" version=\"%s\" web=\"http://www.titania.co.uk\">\n", xml_version);
    }

    switch (mode)
    {
        case mode_version:
            printf("%s\t\t%s\n\t\t%s\n%s\n", COL_BLUE, program_version,
                    SSLeay_version(SSLEAY_VERSION), RESET);

            break;

        case mode_help:
            // Program version banner...
            printf("%s%s%s\n", COL_BLUE, program_banner, RESET);
            printf("SSLScan is a fast SSL port scanner. SSLScan connects to SSL\n");
            printf("ports and determines what  ciphers are supported, which are\n");
            printf("the servers  preferred  ciphers,  which  SSL  protocols  are\n");
            printf("supported  and   returns  the   SSL   certificate.   Client\n");
            printf("certificates /  private key can be configured and output is\n");
            printf("to text / XML.\n\n");
            printf("%sCommand:%s\n", COL_BLUE, RESET);
            printf("  %s%s [Options] [host:port | host]%s\n\n", COL_GREEN, argv[0], RESET);
            printf("%sOptions:%s\n", COL_BLUE, RESET);
            printf("  %s--targets=<file>%s     A file containing a list of hosts to\n", COL_GREEN, RESET);
            printf("                       check.  Hosts can  be supplied  with\n");
            printf("                       ports (i.e. host:port).\n");
            printf("  %s--ipv4%s               Force IPv4\n", COL_GREEN, RESET);
            printf("  %s--ipv6%s               Force IPv6\n", COL_GREEN, RESET);
            printf("  %s--localip=<ip>%s       Local IP from which connection should be made\n", COL_GREEN, RESET);
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
            printf("%sExamples:%s\n", COL_BLUE, RESET);
            printf("  %s%s 127.0.0.1%s\n", COL_GREEN, argv[0], RESET);
            printf("  %s%s 127.0.0.1:443%s\n", COL_GREEN, argv[0], RESET);
            printf("  %s%s [::1]%s\n", COL_GREEN, argv[0], RESET);
            printf("  %s%s [::1]:443%s\n\n", COL_GREEN, argv[0], RESET);
            break;

        // Check a single host/port ciphers...
        case mode_single:
        case mode_multiple:
            printf("%s%s\t\t%s\n\t\t%s\n%s\n", COL_BLUE, program_banner, program_version,
                    SSLeay_version(SSLEAY_VERSION), RESET);

            SSLeay_add_all_algorithms();
            ERR_load_crypto_strings();

            // Build a list of ciphers...
            switch (options.sslVersion)
            {
                case ssl_all:

#ifndef OPENSSL_NO_SSL2
                    populateCipherList(&options, SSLv2_client_method());
#endif

                    populateCipherList(&options, SSLv3_client_method());
                    populateCipherList(&options, TLSv1_client_method());

#if OPENSSL_VERSION_NUMBER >= 0x1000008fL || OPENSSL_VERSION_NUMBER >= 0x1000100fL
                    populateCipherList(&options, TLSv1_1_client_method());
                    populateCipherList(&options, TLSv1_2_client_method());
#endif // #if OPENSSL_VERSION_NUMBER >= 0x1000008fL || OPENSSL_VERSION_NUMBER >= 0x1000100fL

                    break;
#ifndef OPENSSL_NO_SSL2
                case ssl_v2:
                    populateCipherList(&options, SSLv2_client_method());
                    break;
#endif
                case ssl_v3:
                    populateCipherList(&options, SSLv3_client_method());
                    break;
                case tls_v1:
                    populateCipherList(&options, TLSv1_client_method());
                    break;

#if OPENSSL_VERSION_NUMBER >= 0x1000008fL || OPENSSL_VERSION_NUMBER >= 0x1000100fL
                case tls_v11:
                    populateCipherList(&options, TLSv1_1_client_method());
                    break;
                case tls_v12:
                    populateCipherList(&options, TLSv1_2_client_method());
                    break;
#endif // #if OPENSSL_VERSION_NUMBER >= 0x1000008fL || OPENSSL_VERSION_NUMBER >= 0x1000100fL

            }

            // Do the testing...
            if (mode == mode_single)
            {
                status = testHost(&options);
                if(!status)
                    printf("%sERROR: Scan has failed for host %s\n%s", COL_RED, options.host, RESET);
            }
            else
            {
                if (fileExists(argv[options.targets] + 10) == true)
                {
                    // Open targets file...
                    targetsFile = fopen(argv[options.targets] + 10, "r");
                    if (targetsFile == NULL)
                        printf("%sERROR: Could not open targets file %s.%s\n", COL_RED, argv[options.targets] + 10, RESET);
                    else
                    {
                        readLine(targetsFile, line, sizeof(line));
                        while (feof(targetsFile) == 0)
                        {
                            if (strlen(line) != 0)
                            {
                                // Get host...
                                parseHostString(line, &options);

                                // Test the host...
                                status = testHost(&options);
                                if(!status)
                                {
                                    // print error and continue
                                    printf("%sERROR: Scan has failed for host %s\n%s", COL_RED, options.host, RESET);
                                }
                            }
                            readLine(targetsFile, line, sizeof(line));
                        }
                    }
                }
                else
                    printf("%sERROR: Targets file %s does not exist.%s\n", COL_RED, argv[options.targets] + 10, RESET);
            }

            // Free Structures
            while (options.ciphers != 0)
            {
                sslCipherPointer = options.ciphers->next;
                free(options.ciphers);
                options.ciphers = sslCipherPointer;
            }
            break;
    }

    // Close XML file, if required...
    if ((xmlArg > 0) && (mode != mode_help))
    {
        fprintf(options.xmlOutput, "</document>\n");
        fclose(options.xmlOutput);
    }

    return 0;
}
