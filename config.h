/*
 * sec_auth
 *
 * Copyright (c) 1999 Paul Henson <henson@acm.org>
 *
 */

#ifndef CONFIG_H
#define CONFIG_H

#define SEC_AUTH_MS_NTHASH
#define SEC_AUTH_MS_LMHASH
#define SEC_AUTH_APPLE_RANDNUM
#define SEC_AUTH_APPLE_RAND2NUM

#define SEC_AUTH_RPC_ENTRY_PREFIX "/.:/subsys/dce/sec_auth"
#define SEC_AUTH_RPC_GROUP_NAME   "/.:/sec_auth"

#define SEC_AUTH_KEY_SALT         ""
#define SEC_AUTH_KEY_STRING       ""
#define SEC_AUTH_GOD_GROUP        "dceadmin"

#define SEC_AUTHD_PIDFILE         "/var/run/sec_authd.pid"

#define PWD_STRENGTHD_PRINCIPAL "pwd_strengthd"
#define PWD_STRENGTHD_KEYTAB "FILE:/krb5/pwd_strengthd.keytab"
#define PWD_STRENGTHD_RPC_ENTRY "/.:/subsys/dce/pwd_mgmt/pwd_strengthd"

#endif
