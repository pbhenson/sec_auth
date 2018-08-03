#
# sec_auth
#
# Copyright (c) 1999 Paul Henson <henson@acm.org>
#

all:
	cd ..; make build-sec_authd


sec_authd: sec_authd_main.o sec_authd.o
	$(CC) -o sec_authd sec_authd_main.o sec_authd.o ../idl/sec_auth_sstub.o ../samba/samba.o $(LDFLAGS) $(KRB5_LDFLAGS) $(LIBS) $(KRB5_LIBS)

sec_authd_main.o: sec_authd_main.c
	$(CC) $(CFLAGS) $(KRB5_CFLAGS) -c sec_authd_main.c

sec_authd.o: sec_authd.c
	$(CC) $(CFLAGS) $(KRB5_CFLAGS) -c sec_authd.c

clean:
	rm -f sec_authd *.o *~
