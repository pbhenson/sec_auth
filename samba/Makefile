#
# sec_auth
#
# Copyright (c) 1999 Paul Henson <henson@acm.org>
#

all:
	cd ..; make build-samba

samba: samba.o
	@echo

samba.o: samba.c
	$(CC) $(CFLAGS) -c samba.c

clean:
	rm -f samba.o *~
