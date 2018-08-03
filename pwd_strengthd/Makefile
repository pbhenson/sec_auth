#
# sec_auth
#
# Copyright (c) 1999 Paul Henson <henson@acm.org>
#

all:
	cd ..; make build-pwd_strengthd

pwd_strengthd: pwd_strengthd_main.o pwd_strengthd.o sec_auth_gen_eras.o rsec_pwd_mgmt_sstub.o
	$(CC) -o pwd_strengthd pwd_strengthd_main.o pwd_strengthd.o sec_auth_gen_eras.o rsec_pwd_mgmt_sstub.o ../samba/samba.o $(LDFLAGS) $(KRB5_LDFLAGS) $(LIBS) $(KRB5_LIBS)

pwd_strengthd_main.o: pwd_strengthd_main.c
	$(CC) $(CFLAGS) $(KRB5_CFLAGS) -c pwd_strengthd_main.c

pwd_strengthd.o: pwd_strengthd.c
	$(CC) $(CFLAGS) $(KRB5_CFLAGS) -c pwd_strengthd.c

sec_auth_gen_eras.o: sec_auth_gen_eras.c
	$(CC) $(CFLAGS) $(KRB5_CFLAGS) -c sec_auth_gen_eras.c

rsec_pwd_mgmt_sstub.o: rsec_pwd_mgmt_sstub.c
	$(CC) $(CFLAGS) -I. -c rsec_pwd_mgmt_sstub.c

rsec_pwd_mgmt_sstub.c: /usr/include/dce/rsec_pwd_mgmt.idl
	idl -client none -keep c_source /usr/include/dce/rsec_pwd_mgmt.idl

clean:
	rm -f pwd_strengthd rsec_pwd_mgmt_sstub.c rsec_pwd_mgmt.h *.o *~
