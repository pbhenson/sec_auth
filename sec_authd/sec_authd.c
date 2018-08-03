/*
 * sec_auth
 *
 * Copyright (c) 1999 Paul Henson <henson@acm.org>
 *
 */

#include <stdio.h>
#include <syslog.h>
#include <dce/rpc.h>
#include <dce/id_base.h>
#include <dce/binding.h>
#include <dce/sec_rgy_attr.h>
#include <dce/sec_cred.h>
#include <dce/dce_error.h>
#include <sec_auth.h>
#include "../config.h"
#include <krb5.h>

krb5_context context;
krb5_encrypt_block encblock;
krb5_keyblock keyblock;
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

  sec_cred_get_client_princ_name(client_creds,
				 &client_princ_name,
				 &dce_st);

  if (dce_st) {
      dce_error_inq_text(dce_st, dce_error, &dce_error_st);
      syslog(LOG_ERR, "sec_cred_get_client_princ_name failed - %s", dce_error);
      return 0;
  }

  sec_id_parse_name(sec_rgy_default_handle, client_princ_name, princ_cell, NULL,
		    princ_name, NULL, &dce_st);

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

  if (strncmp(princ_name, "hosts/", 6)) {

      int is_member = sec_rgy_pgo_is_member(sec_rgy_default_handle, sec_rgy_domain_group, SEC_AUTH_GOD_GROUP, princ_name, &dce_st);

      if (dce_st) {
        dce_error_inq_text(dce_st, dce_error, &dce_error_st);
        syslog(LOG_ERR, "sec_rgy_pgo_is_member failed - %s", dce_error);
        return 0;
      }

      if (!is_member) {
        syslog(LOG_ERR, "unauthorized principal - %s", princ_name);
        return 0;
      }
  }

  return 1;
}
  
 


int decrypt_era(idl_char *principal, idl_char *era_name, idl_byte *buffer, unsigned32 buffer_size)
{
  sec_attr_t attr;
  error_status_t dce_st;
  dce_error_string_t dce_error;
  int dce_error_st;
  int era_length = krb5_encrypt_size(buffer_size, encblock.crypto_entry);
  
  sec_rgy_attr_lookup_by_name(sec_rgy_default_handle, sec_rgy_domain_principal, principal, era_name, &attr, &dce_st);

  if (dce_st) {
      dce_error_inq_text(dce_st, dce_error, &dce_error_st);
      syslog(LOG_ERR, "sec_rgy_attr_lookup_by_name failed - %s", dce_error);
      return 0;
  }

  if (attr.attr_value.attr_encoding != sec_attr_enc_bytes)
    {
      syslog(LOG_ERR, "decrypt era - wrong encoding for era %s", era_name);
      return 0;
    }

  if (attr.attr_value.tagged_union.bytes->length != era_length)
    {
      syslog(LOG_ERR, "decrypt era - wrong length for era %s", era_name);
      return 0;
    }

  krb5_decrypt(context, attr.attr_value.tagged_union.bytes->data, (krb5_pointer) buffer, era_length, &encblock, 0);
   
  sec_attr_util_inst_free_ptrs(&attr);

  return 1;
}
      

void sec_auth_ms_hash(handle_t handle, idl_char *hash_type, idl_char *principal, idl_byte challenge[8], idl_byte response[24], sec_passwd_rec_t *pw_entry, error_status_t *status)
{
  idl_byte hash[16];
  idl_byte key[21];
  idl_byte correct_response[24];
 
  if (!decrypt_era(principal, hash_type, hash, 16)) {
    syslog(LOG_ERR, "failed to decrypt era %s", hash_type);
    *status = sec_rgy_passwd_invalid;
    return;
  }
  
  memset(key, 0, 21);
  memcpy(key, hash, 16);

  samba_E_P24(key, challenge, correct_response);

  if (memcmp(response, correct_response, 24) == 0)
    {
      pw_entry->version_number = sec_passwd_c_version_none;
      pw_entry->pepper = NULL;
      pw_entry->key.key_type = sec_passwd_des;

      if(!decrypt_era(principal, "auth_dce_deskey", pw_entry->key.tagged_union.des_key, 8)) {
	syslog(LOG_ERR, "failed to decrypt era auth_dce_deskey");
	*status = sec_rgy_passwd_invalid;
	return;
      }

      *status = error_status_ok;
    }
  else
    {
      syslog(LOG_ERR, "failed auth_ms_hash attempt for %s", principal);
      *status = sec_rgy_passwd_invalid;
    }
  
}

void sec_auth_ms_nthash(handle_t handle, idl_char *principal, idl_byte challenge[8], idl_byte response[24], sec_passwd_rec_t *pw_entry, error_status_t *status)
{
  pw_entry->key.key_type = sec_passwd_des;

  if (!validate_client(handle))
    *status = sec_rgy_not_authorized;
  else
    sec_auth_ms_hash(handle, "auth_ms_nthash", principal, challenge, response, pw_entry, status);
}


void sec_auth_ms_lmhash(handle_t handle, idl_char *principal, idl_byte challenge[8], idl_byte response[24], sec_passwd_rec_t *pw_entry, error_status_t *status)
{
  pw_entry->key.key_type = sec_passwd_des;
  
  if (!validate_client(handle))
    *status = sec_rgy_not_authorized;
  else
    sec_auth_ms_hash(handle, "auth_ms_lmhash", principal, challenge, response, pw_entry, status);
}
