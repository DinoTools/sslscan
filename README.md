SSLScan
=======

SSLScan queries SSL services, such as HTTPS, in order to determine the ciphers
that are supported. SSLScan is designed to be easy, lean and fast.
The output includes preferred ciphers of the SSL service, the certificate
and is in Text and XML formats.


Features
--------

* Query SSL services
* Supported cryptographic protocols: SSLv2, SSLv3, TLS 1.0, TLS 1.1 and TLS 1.2 (depends on used OpenSSL library)
* STARTTLS support with FTP, IMAP, POP3, SMTP and XMPP
* Perform a HTTP connect
* IPv4 and IPv6
* Bind to local IP address
* Python extensions
* Text and XML output


Install
-------

Requirements:

* OpenSSL 1.0.0 or better
* gcc
* make
* cmake
* openssl-devel
* python-devel (2.6, 2.7, 3.2 or 3.3 - Python 3.x preferred)

Makefile build:

    mkdir build
    cd build
    cmake ..
    make
    make install        (as root)


Usage
-----

To scan a HTTPS service:

    sslscan example.org


To display more information:

    sslscan --help


History
-------

* 2007-2009 SSLScan was originally written by Ian Ventura-Whiting. (http://www.titania.co.uk http://sourceforge.net/projects/sslscan/)
* 2010-2011 The project has been forked by Jacob Appelbaum to better support STARTTLS. (http://www.github.com/ioerror/sslscan)
* 2013-     The project has been forked by DinoTools to add TLS 1.1 and 1.2 support, apply available patches and add new features. (https://github.com/DinoTools/sslscan)


License
-------

Published under the GPLv3 (see LICENSE for more information)

Most of the pre-TLS protocol setup was inspired by the OpenSSL s_client.c program.

Some of the OpenSSL setup code was borrowed from The Tor Project's Tor program.
Thus it is likely proper to comply with the BSD license by saying:
Copyright (c) 2007-2010, The Tor Project, Inc.


Projects using SSLScan
----------------------

* [TLSSLed](http://www.taddong.com/en/lab.html)

