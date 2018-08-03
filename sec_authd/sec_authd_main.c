/*
 * sec_auth
 *
 * Copyright (c) 1999 Paul Henson <henson@acm.org>
 *
 */

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <syslog.h>
#include <netdb.h>
#include <dce/rpc.h>
#include <dce/dce_error.h>
#include <dce/dce_cf.h>
#include <krb5.h>
#include <sec_auth.h>
#include "../config.h"

extern krb5_context context;
extern krb5_encrypt_block encblock;
extern krb5_keyblock keyblock;
extern char *local_cell;

int main(int argc, char **argv)
{
  char hostname[MAXHOSTNAMELEN+1];
  rpc_binding_vector_t *binding_vector;
  char entry_name[strlen(SEC_AUTH_RPC_ENTRY_PREFIX)+1+MAXHOSTNAMELEN+1];
  char server_name[strlen("hosts//self")+MAXHOSTNAMELEN+1];
  dce_error_string_t dce_error;
  error_status_t dce_st;
  int dce_error_st;
  krb5_data salt, key;
  long krb5_status;
  
  openlog("sec_authd", LOG_PID, LOG_DAEMON);
  
  switch(fork())
    {
    case 0:
      break;
      
    case -1:
      syslog(LOG_ERR, "fork failed - %m.");
      exit(1);
      break;
      
    default:
      exit(0);
      break;
    }
  
  if (setsid() == -1)
    {
      syslog(LOG_ERR, "setsid failed - %m.");
      exit(1);
    }

  if (gethostname(hostname, MAXHOSTNAMELEN+1))
    {
      syslog(LOG_ERR, "gethostname failed - %m");
      exit(1);
    }

  sprintf(entry_name, "%s/%s", SEC_AUTH_RPC_ENTRY_PREFIX, hostname);
  sprintf(server_name, "hosts/%s/self", hostname);
  
  if (krb5_status = krb5_init_context(&context)) {
    syslog(LOG_ERR, "krb5_init_context failed - %s", error_message(krb5_status));
    exit(1);
  }

  keyblock.enctype = ENCTYPE_DES_CBC_CRC;
  krb5_use_enctype(context, &encblock, keyblock.enctype);

  salt.length = strlen(SEC_AUTH_KEY_SALT);
  salt.data = SEC_AUTH_KEY_SALT;
  key.length = strlen(SEC_AUTH_KEY_STRING);
  key.data = SEC_AUTH_KEY_STRING;

  if (krb5_status = krb5_string_to_key(context, &encblock, &keyblock, &key, &salt)) {
    syslog(LOG_ERR, "krb5_string_to_key failed - %s", error_message(krb5_status));
    exit(1);
  }
  
  if (krb5_status = krb5_process_key(context, &encblock, &keyblock)) {
    syslog(LOG_ERR, "krb5_process_key failed - %s", error_message(krb5_status));
    exit(1);
  }

  dce_cf_get_cell_name (&local_cell, &dce_st);

  if (dce_st) {
    dce_error_inq_text(dce_st, dce_error, &dce_error_st);
    syslog(LOG_ERR, "dce_cf_get_cell_name failed - %s", dce_error); 
    exit(1);
  }
 
  rpc_server_register_if(sec_auth_v1_0_s_ifspec,
			 NULL,
			 NULL,
			 &dce_st);
  if (dce_st)
    {
      dce_error_inq_text(dce_st, dce_error, &dce_error_st);
      syslog(LOG_ERR, "rpc_server_register_if failed - %s", dce_error);
      exit(1);
    }

  rpc_server_use_all_protseqs(rpc_c_protseq_max_reqs_default,
			      &dce_st);
  if (dce_st)
    {
      dce_error_inq_text(dce_st, dce_error, &dce_error_st);
      syslog(LOG_ERR, "rpc_server_use_all_protseqs failed - %s", dce_error);
      exit(1);
    }

  rpc_server_inq_bindings(&binding_vector, &dce_st);
  if (dce_st)
    {
      dce_error_inq_text(dce_st, dce_error, &dce_error_st);
      syslog(LOG_ERR, "rpc_server_inq_bindings failed - %s", dce_error);
      exit(1);
    }
 
  rpc_server_register_auth_info(server_name,
				rpc_c_authn_dce_secret,
				NULL,
				NULL,
				&dce_st);
  if (dce_st)
    {
      dce_error_inq_text(dce_st, dce_error, &dce_error_st);
      syslog(LOG_ERR, "rpc_server_register_auth_info failed - %s", dce_error);
      exit(1);
    }
 

  rpc_ep_register(sec_auth_v1_0_s_ifspec, binding_vector, NULL, NULL, &dce_st);
  if (dce_st)
    {
      dce_error_inq_text(dce_st, dce_error, &dce_error_st);
      syslog(LOG_ERR, "rpc_ep_register failed - %s", dce_error);
      exit(1);
    }

  rpc_ns_binding_export(rpc_c_ns_syntax_dce, entry_name, sec_auth_v1_0_s_ifspec,
			binding_vector, NULL, &dce_st);
  if (dce_st)
    {
      dce_error_inq_text(dce_st, dce_error, &dce_error_st);
      syslog(LOG_ERR, "rpc_ns_binding_export failed - %s", dce_error);
      exit(1);
    }

  rpc_ns_group_mbr_add(rpc_c_ns_syntax_default,
		       SEC_AUTH_RPC_GROUP_NAME,
		       rpc_c_ns_syntax_default,
		       entry_name,
		       &dce_st);
  if (dce_st)
    {
      dce_error_inq_text(dce_st, dce_error, &dce_error_st);
      syslog(LOG_ERR, "rpc_ns_group_mbr_add failed - %s", dce_error);
      exit(1);
    }

  rpc_binding_vector_free(&binding_vector, &dce_st);
  if (dce_st)
    {
      dce_error_inq_text(dce_st, dce_error, &dce_error_st);
      syslog(LOG_ERR, "rpc_binding_vector_free failed - %s", dce_error);
      exit(1);
    }

  rpc_server_listen(rpc_c_listen_max_calls_default, &dce_st);
  if (dce_st)
    {
      dce_error_inq_text(dce_st, dce_error, &dce_error_st);
      syslog(LOG_ERR, "rpc_server_listen failed - %s", dce_error);
      exit(1);
    }

}
