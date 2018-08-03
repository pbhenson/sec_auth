#
# sec_auth
#
# Copyright (c) 1999 Paul Henson <henson@acm.org>
#

all:
	cd ..; make build-idl


idl: sec_auth.timestamp sec_auth.h

sec_auth.timestamp: sec_auth.idl
	idl -keep c_source sec_auth.idl
	$(CC) $(CFLAGS) -c sec_auth_sstub.c
	$(CC) $(CFLAGS) -c sec_auth_cstub.c
	ar -r libsec_auth.a sec_auth_cstub.o
	mv sec_auth.h sec_auth.h.in
	touch sec_auth.timestamp

sec_auth.h: sec_auth.h.in
	head -4 sec_auth.h.in > sec_auth.h; \
          echo `grep SEC_AUTH_RPC_GROUP ../config.h` >> sec_auth.h; \
          echo "#define SEC_AUTH_C_IFSPEC sec_auth_v2_0_c_ifspec" >> sec_auth.h; \
          tail +5 sec_auth.h.in >> sec_auth.h

clean:
	rm -f sec_auth_sstub.* sec_auth_cstub.* sec_auth.h sec_auth.h.in sec_auth.timestamp libsec_auth.a *~
