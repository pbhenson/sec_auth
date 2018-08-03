/*
 * sec_auth
 *
 * Copyright (c) 1999 Paul Henson <henson@acm.org>
 *
 */

#include <stdio.h>
#include <syslog.h>
#include <strings.h>
#include <dce/dce_error.h>
#include <dce/rpc.h>
#include <dce/id_base.h>
#include <dce/sec_cred.h>
#include <dce/secidmap.h>
#include "sec_auth_gen_eras.h"

char *local_cell;

int validate_client(rpc_binding_handle_t handle)
{
  rpc_authz_cred_handle_t client_creds;
  unsigned32 protect_level;
  unsigned32 authn_svc;
  unsigned32 authz_svc;
  unsigned32 dce_st;
  unsigned_char_p_t client_princ_name;
  sec_rgy_name_t princ_cell;
  sec_rgy_name_t princ_name;
  dce_error_string_t dce_error;
  int dce_error_st;
  
  
  rpc_binding_inq_auth_caller(handle, &client_creds, NULL, &protect_level, &authn_svc, &authz_svc, &dce_st);
  if (dce_st) {
    dce_error_inq_text(dce_st, dce_error, &dce_error_st);
    syslog(LOG_ERR, "rpc_binding_inq_auth_caller failed - %s", dce_error);
    return 0;
  }
  
  sec_cred_get_client_princ_name(client_creds, &client_princ_name, &dce_st);
  if (dce_st) {
    dce_error_inq_text(dce_st, dce_error, &dce_error_st);
    syslog(LOG_ERR, "sec_cred_get_client_princ_name failed - %s", dce_error);
    return 0;
  }
  
  sec_id_parse_name(sec_rgy_default_handle, client_princ_name, princ_cell, NULL, princ_name, NULL, &dce_st);
  if (dce_st) {
    dce_error_inq_text(dce_st, dce_error, &dce_error_st);
    syslog(LOG_ERR, "sec_id_parse_name failed - %s", dce_error);
    return 0;
  }

  if (strcmp(local_cell, princ_cell)) {
    syslog(LOG_ERR, "attempted access from foreign cell %s", princ_cell);
    return 0;
  }
      
  if (protect_level != rpc_c_protect_level_pkt_privacy) {
    syslog(LOG_ERR, "wrong protection level - %d", protect_level);
    return 0;
  }
  
  if (authn_svc != rpc_c_authn_dce_secret) {
    syslog(LOG_ERR, "wrong authentication type - %d", authn_svc);
    return 0;
  }
  
  if (authz_svc != rpc_c_authz_name) {
    syslog(LOG_ERR, "wrong authorization type - %d", authz_svc);
    return 0;
  }
  
  if (strcmp(princ_name, SEC_RGY_SERVER_NAME)) {
    syslog(LOG_ERR, "unauthorized principal - %s", princ_name);
    return 0;
  }
  
  return 1;
}

								       
boolean32 rsec_pwd_mgmt_str_chk(handle_t handle, sec_rgy_name_t princ, sec_passwd_rec_t *pwd, signed32 pwd_val_type, unsigned32 plcy_args,
				sec_attr_t plcy[], sec_bytes_t str_info_in, sec_bytes_t *str_info_out, error_status_t *stp)
{
  
  signed32 pwd_min_len = plcy[0].attr_value.tagged_union.signed_int;
  sec_rgy_plcy_pwd_flags_t pwd_flags = plcy[1].attr_value.tagged_union.signed_int;
  int pwd_len, pwd_index;
  int pwd_all_spaces, pwd_all_alphanum;
  char *pwd_string;
  
  str_info_out->num_bytes = 0;
  str_info_out->bytes = NULL;

  if (!validate_client(handle)) {
    *stp = sec_pwd_mgmt_not_authorized;
    return 0;
  }
  
  if (pwd->key.key_type == sec_passwd_des) {
    syslog(LOG_ERR, "DES password change for %s", princ);
    *stp = error_status_ok;
    return 1;
  }

  pwd_string = (char *)pwd->key.tagged_union.plain;
  pwd_len = strlen(pwd_string);

  if (pwd_len < pwd_min_len) {
    syslog(LOG_ERR, "password length %d too short for %s", pwd_len, princ);
    *stp = sec_pwd_mgmt_str_check_failed;
    return 0;
  }

  pwd_all_spaces = (pwd_flags & sec_rgy_plcy_pwd_no_spaces) ? 1 : 0;
  pwd_all_alphanum = (pwd_flags & sec_rgy_plcy_pwd_non_alpha) ? 1 : 0;

  for (pwd_index = 0; (pwd_index < pwd_len) && (pwd_all_spaces || pwd_all_alphanum); pwd_index++) {

    if (!isdcepcs(pwd_string[pwd_index]) || !isalnum(pwd_string[pwd_index]))
      pwd_all_alphanum = 0;
    if (pwd_string[pwd_index] != ' ')
      pwd_all_spaces = 0;
  }

  if (pwd_all_spaces) {
    syslog(LOG_ERR, "password all spaces for %s", princ);
    *stp = sec_pwd_mgmt_str_check_failed;
    return 0;
  }

  if (pwd_all_alphanum) {
    syslog(LOG_ERR, "password all alphanumeric for %s", princ);
    *stp = sec_pwd_mgmt_str_check_failed;
    return 0;
  }

  if (!sec_auth_gen_eras_enqueue(princ, pwd_string)) {
    syslog(LOG_ERR, "failed to enqueue eras for %s", princ);
    *stp = sec_pwd_mgmt_svr_error;
    return 0;
  }

  *stp = error_status_ok;
  return 1;
}

void rsec_pwd_mgmt_gen_pwd(handle_t pwd_mgmt_svr_h, sec_rgy_name_t princ_name, unsigned32 plcy_args, sec_attr_t plcy[],
			   sec_bytes_t gen_info_in, unsigned32 num_pwds, unsigned32 *num_returned, sec_passwd_rec_t gen_pwd_set[],
			   sec_bytes_t *gen_info_out, error_status_t *stp)
{
  *num_returned = 0;
  gen_info_out->num_bytes = 0;
  gen_info_out->bytes = NULL;
  *stp = sec_pwd_mgmt_svr_error;
  syslog(LOG_ERR, "rsec_pwd_mgmt_gen_pwd called for %s", princ_name);
}
