SRCS = sslscan.c
DESTDIR ?=
PREFIX ?= /usr/local
BINPATH ?= $(PREFIX)/bin/
MANPATH ?= $(PREFIX)/share/man/
CFLAGS ?= -I$(PREFIX)/ssl/include/ -I$(PREFIX)/ssl/include/openssl/
LDFLAGS ?= -L$(PREFIX)/ssl/lib/

CFLAGS_CUSTOM ?= -g -Wall -static-libgcc
OPENSSL_CUSTOM ?= /home/flowher/openssl-1.0.1e
INC_CUSTOM ?= -I$(OPENSSL_CUSTOM)/include

all:
	gcc -g -Wall -lssl -lcrypto -o sslscan $(SRCS) $(LDFLAGS) $(CFLAGS)

install:
	install -D -m 755 sslscan $(DESTDIR)$(BINPATH)sslscan
	install -D -m 644 sslscan.1 $(DESTDIR)$(MANPATH)man1/sslscan.1

uninstall:
	rm -f $(DESTDIR)$(BINPATH)sslscan
	rm -f $(DESTDIR)$(MANPATH)man1/sslscan.1

clean:
	rm -f sslscan

custom_build:
	gcc $(CFLAGS_CUSTOM) -o sslscan sslscan.c $(INC_CUSTOM) $(OPENSSL_CUSTOM)/libssl.a $(OPENSSL_CUSTOM)/libcrypto.a -ldl

demo: demo-https demo-xmpp demo-pop3 demo-imap demo-sni
	echo "See above!"

demo-https: all
	LD_LIBRARY_PATH=/usr/local/ssl/lib ./sslscan --renegotiation encrypted.google.com

demo-xmpp: all
	LD_LIBRARY_PATH=/usr/local/ssl/lib ./sslscan --renegotiation --starttls-xmpp jabber.ccc.de

demo-pop3: all
	LD_LIBRARY_PATH=/usr/local/ssl/lib ./sslscan --renegotiation --starttls-pop3 pop3.sonic.net

demo-imap: all
	LD_LIBRARY_PATH=/usr/local/ssl/lib ./sslscan --renegotiation --starttls-imap imap.sonic.net

# Please see this website for information on the TLS SNI extension: https://www.sni.velox.ch/
# Also it may be of interest to read this: http://wiki.cacert.org/VhostTaskForce
demo-sni: all
	LD_LIBRARY_PATH=/usr/local/ssl/lib ./sslscan --renegotiation --http dave.sni.velox.ch
