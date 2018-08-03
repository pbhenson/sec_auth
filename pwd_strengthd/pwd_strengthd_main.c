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
#include <dce/rpc.h>
#include <dce/dce_error.h>
#include <dce/dce_cf.h>
#include <dce/pthread.h>
#include <dce/sec_login.h>
#include <dce/rsec_pwd_mgmt.h>
#include "../config.h"

static sec_login_handle_t server_context;

extern char *local_cell;

static pthread_addr_t refresh_context(pthread_addr_t arg) {
  
  signed32 expiration_time;
  struct timeval now;
  struct timespec sleep_interval;
  dce_error_string_t dce_error;
  error_status_t dce_st;
  int dce_error_st;
  sec_login_auth_src_t auth_src;
  unsigned32 kvno_worked;
  boolean32 reset_passwd;
 
  while (1) {
    
    sec_login_get_expiration(server_context, &expiration_time, &dce_st);
    
    gettimeofday(&now, 0);
    
    sleep_interval.tv_sec = expiration_time - now.tv_sec - 10 * 60;
    sleep_interval.tv_nsec = 0;
    
    pthread_delay_np(&sleep_interval);
    
    sec_login_refresh_identity(server_context, &dce_st);
    
    if (dce_st) {
      dce_error_inq_text(dce_st, dce_error, &dce_error_st);
      syslog(LOG_ERR, "sec_login_refresh_identity failed - %s", dce_error);
      exit(1);
    }
      
    sec_login_valid_from_keytable(server_context, rpc_c_authn_dce_secret, PWD_STRENGTHD_KEYTAB, (unsigned32) NULL, &kvno_worked,
				  &reset_passwd, &auth_src, &dce_st);

    if (dce_st) {
      dce_error_inq_text(dce_st, dce_error, &dce_error_st);
      syslog(LOG_ERR, "sec_login_valid_from_keytable failed - %s", dce_error);
      exit(1);
    }
  }                              
}

int main(int argc, char **argv) {
  
  rpc_binding_vector_t *binding_vector;
  dce_error_string_t dce_error;
  error_status_t dce_st;
  int dce_error_st;
  sec_login_auth_src_t auth_src;
  boolean32 reset_passwd;
  unsigned32 kvno_worked;
  pthread_t refresh_thread;
  
  openlog("pwd_strengthd", LOG_PID, LOG_DAEMON);
  
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
  
  if (setsid() == -1) {
    syslog(LOG_ERR, "setsid failed - %m.");
    exit(1);
  }

  dce_cf_get_cell_name (&local_cell, &dce_st);
  if (dce_st) {
    dce_error_inq_text(dce_st, dce_error, &dce_error_st);
    syslog(LOG_ERR, "dce_cf_get_cell_name failed - %s", dce_error); 
    exit(1);
  }

  if (!sec_login_setup_identity (PWD_STRENGTHD_PRINCIPAL, sec_login_no_flags, &server_context, &dce_st)) {
    dce_error_inq_text(dce_st, dce_error, &dce_error_st);
    syslog(LOG_ERR, "sec_login_setup_identity failed - %s", dce_error);
    exit(1);
  }

  sec_login_valid_from_keytable(server_context, rpc_c_authn_dce_secret, PWD_STRENGTHD_KEYTAB, (unsigned32) NULL, &kvno_worked, &reset_passwd, &auth_src, &dce_st);
  if (dce_st) {
    dce_error_inq_text(dce_st, dce_error, &dce_error_st);
    syslog(LOG_ERR, "sec_login_valid_from_keytable failed - %s", dce_error);
    sec_login_purge_context(&server_context, &dce_st);
    exit(1);
  }

  if (!sec_login_certify_identity(server_context, &dce_st)) {
    dce_error_inq_text(dce_st, dce_error, &dce_error_st);
    syslog(LOG_ERR, "sec_login_certify_identity failed - %s", dce_error);
    sec_login_purge_context(&server_context, &dce_st);
    exit(1);
  }

  if (auth_src != sec_login_auth_src_network){
    syslog(LOG_ERR, "no network credentials");
    sec_login_purge_context(&server_context, &dce_st);
    exit(1);
  }

  sec_login_set_context(server_context, &dce_st);

  if (dce_st) {
    dce_error_inq_text(dce_st, dce_error, &dce_error_st);
    syslog(LOG_ERR, "sec_login_set_context failed - %s", dce_error);
    sec_login_purge_context(&server_context, &dce_st);
    exit(1);
  }

  if (pthread_create(&refresh_thread, pthread_attr_default, refresh_context, (pthread_addr_t) NULL)) {
    syslog(LOG_ERR, "pthread_create failed - %m");
    exit(1);
  }
        
  pthread_detach(&refresh_thread);

  if (!sec_auth_gen_eras_init()) {
    syslog(LOG_ERR, "sec_auth_gen_eras_init failed");
    exit(1);
  } 

  rpc_server_register_if(rsec_pwd_mgmt_v1_0_s_ifspec, NULL, NULL, &dce_st);
  if (dce_st)
    {
      dce_error_inq_text(dce_st, dce_error, &dce_error_st);
      syslog(LOG_ERR, "rpc_server_register_if failed - %s", dce_error);
      exit(1);
    }

  rpc_server_use_all_protseqs(rpc_c_protseq_max_reqs_default, &dce_st);
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

  rpc_server_register_auth_info(PWD_STRENGTHD_PRINCIPAL, rpc_c_authn_dce_secret, NULL, PWD_STRENGTHD_KEYTAB, &dce_st);
  if (dce_st)
    {
      dce_error_inq_text(dce_st, dce_error, &dce_error_st);
      syslog(LOG_ERR, "rpc_server_register_auth_info failed - %s", dce_error);
      exit(1);
    }

  rpc_ep_register(rsec_pwd_mgmt_v1_0_s_ifspec, binding_vector, NULL, NULL, &dce_st);
  if (dce_st)
    {
      dce_error_inq_text(dce_st, dce_error, &dce_error_st);
      syslog(LOG_ERR, "rpc_ep_register failed - %s", dce_error);
      exit(1);
    }

  rpc_ns_binding_export(rpc_c_ns_syntax_dce, PWD_STRENGTHD_RPC_ENTRY, rsec_pwd_mgmt_v1_0_s_ifspec, binding_vector, NULL, &dce_st);
  if (dce_st)
    {
      dce_error_inq_text(dce_st, dce_error, &dce_error_st);
      syslog(LOG_ERR, "rpc_ns_binding_export failed - %s", dce_error);
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
