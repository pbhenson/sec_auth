/*
 * sec_auth
 *
 * Copyright (c) 1999 Paul Henson <henson@acm.org>
 *
 */

#ifndef SEC_AUTH_GEN_ERAS_H

#define SEC_AUTH_GEN_ERAS_H

int sec_auth_gen_eras_init();
int sec_auth_gen_eras_enqueue(char *username, char *password);

#endif
