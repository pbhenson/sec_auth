#
# sec_auth
#
# Copyright (c) 1999 Paul Henson <henson@acm.org>
#

CC = gcc
CFLAGS = -O2 -D_REENTRANT -I../idl
LDFLAGS =
LIBS = -ldce -ldes
KRB5_ROOT = /usr/local/opt/krb5-1.2.1
KRB5_CFLAGS = -I$(KRB5_ROOT)/include
KRB5_LDFLAGS = -L$(KRB5_ROOT)/lib -R$(KRB5_ROOT)/lib
KRB5_LIBS = -lkrb5 -lk5crypto -lcom_err

all: build-idl build-samba build-pwd_strengthd build-sec_authd

build-idl:
	cd idl; make CC="$(CC)" CFLAGS="$(CFLAGS)" KRB5_CFLAGS="$(KRB5_CFLAGS)" \
                                      LDFLAGS="$(LDFLAGS)" KRB5_LDFLAGS="$(KRB5_LDFLAGS)" \
                                      LIBS="$(LIBS)" KRB5_LIBS="$(KRB5_LIBS)" idl

build-samba:
	cd samba; make CC="$(CC)" CFLAGS="$(CFLAGS)" KRB5_CFLAGS="$(KRB5_CFLAGS)" \
                                      LDFLAGS="$(LDFLAGS)" KRB5_LDFLAGS="$(KRB5_LDFLAGS)" \
                                      LIBS="$(LIBS)" KRB5_LIBS="$(KRB5_LIBS)" samba

build-pwd_strengthd:
	cd pwd_strengthd; make CC="$(CC)" CFLAGS="$(CFLAGS)" KRB5_CFLAGS="$(KRB5_CFLAGS)" \
                                      LDFLAGS="$(LDFLAGS)" KRB5_LDFLAGS="$(KRB5_LDFLAGS)" \
                                      LIBS="$(LIBS)" KRB5_LIBS="$(KRB5_LIBS)" pwd_strengthd

build-sec_authd:
	cd sec_authd; make CC="$(CC)" CFLAGS="$(CFLAGS)" KRB5_CFLAGS="$(KRB5_CFLAGS)" \
                                      LDFLAGS="$(LDFLAGS)" KRB5_LDFLAGS="$(KRB5_LDFLAGS)" \
                                      LIBS="$(LIBS)" KRB5_LIBS="$(KRB5_LIBS)" sec_authd

clean:
	cd idl; make clean
	cd samba; make clean
	cd pwd_strengthd; make clean
	cd sec_authd; make clean
	rm -f *~
