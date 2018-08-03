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
#include <des.h>
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
  idl_byte temp_buffer[era_length];
  
  sec_rgy_attr_lookup_by_name(sec_rgy_default_handle, sec_rgy_domain_person, principal, era_name, &attr, &dce_st);

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

  krb5_decrypt(context, attr.attr_value.tagged_union.bytes->data, (krb5_pointer) temp_buffer, era_length, &encblock, 0);

  memcpy(buffer, temp_buffer, buffer_size);
   
  sec_attr_util_inst_free_ptrs(&attr);

  return 1;
}
      

void sec_auth_ms_hash(handle_t handle, idl_char *hash_type, idl_char *principal, idl_byte challenge[8], idl_byte response[24], idl_byte dce_deskey[8], error_status_t *status)
{
  idl_byte hash[16];
  idl_byte key[21];
  idl_byte correct_response[24];
 
  if (!decrypt_era(principal, hash_type, hash, 16)) {
    syslog(LOG_ERR, "sec_auth_ms_hash: failed to decrypt era %s for %s", hash_type, principal);
    *status = sec_rgy_passwd_invalid;
    return;
  }
  
  memset(key, 0, 21);
  memcpy(key, hash, 16);

  samba_E_P24(key, challenge, correct_response);

  if (memcmp(response, correct_response, 24) == 0)
    {
      if(!decrypt_era(principal, "auth_dce_deskey", dce_deskey, 8)) {
	syslog(LOG_ERR, "sec_auth_ms_hash: failed to decrypt era auth_dce_deskey for %s", principal);
	*status = sec_rgy_passwd_invalid;
	return;
      }

      *status = error_status_ok;
    }
  else
    {
      syslog(LOG_ERR, "sec_auth_ms_hash: failed attempt for %s", principal);
      *status = sec_rgy_passwd_invalid;
    }
  
}

void sec_auth_ms_nthash(handle_t handle, idl_char *principal, idl_byte challenge[8], idl_byte response[24], idl_byte dce_deskey[8], error_status_t *status)
{
  if (!validate_client(handle))
    *status = sec_rgy_not_authorized;
  else
#ifdef SEC_AUTH_MS_NTHASH
    sec_auth_ms_hash(handle, "auth_ms_nthash", principal, challenge, response, dce_deskey, status);
#else
    *status = sec_rgy_not_implemented;
#endif
}


void sec_auth_ms_lmhash(handle_t handle, idl_char *principal, idl_byte challenge[8], idl_byte response[24], idl_byte dce_deskey[8], error_status_t *status)
{
  if (!validate_client(handle))
    *status = sec_rgy_not_authorized;
  else
#ifdef SEC_AUTH_MS_LMHASH
    sec_auth_ms_hash(handle, "auth_ms_lmhash", principal, challenge, response, dce_deskey, status);
#else
    *status = sec_rgy_not_implemented;
#endif
}


void sec_auth_apple_randnum(handle_t handle, idl_char *principal, idl_byte challenge[8], idl_byte response[24], idl_byte dce_deskey[8], error_status_t *status)
{
  if (!validate_client(handle))
    *status = sec_rgy_not_authorized;
  else
#ifdef SEC_AUTH_APPLE_RANDNUM
    {
      idl_byte apple_deskey[8];
      idl_byte correct_response[8];
      Key_schedule key_schedule;
      
      if (!decrypt_era(principal, "auth_apple_deskey", apple_deskey, 8)) {
	syslog(LOG_ERR, "sec_auth_apple_randnum: failed to decrypt era auth_apple_deskey for %s", principal);
	*status = sec_rgy_passwd_invalid;
	return;
      }

      key_sched((C_Block *) apple_deskey, key_schedule);
      ecb_encrypt((C_Block *) challenge, (C_Block *) correct_response, key_schedule, DES_ENCRYPT);
  
      if (memcmp(response, correct_response, 8) == 0)
	{
	  if(!decrypt_era(principal, "auth_dce_deskey", dce_deskey, 8)) {
	    syslog(LOG_ERR, "sec_auth_apple_randnum: failed to decrypt era auth_dce_deskey for %s", principal);
	    *status = sec_rgy_passwd_invalid;
	    return;
	  }

	  *status = error_status_ok;
	}
      else
	{
	  syslog(LOG_ERR, "sec_auth_apple_randnum: failed auth_apple_deskey attempt for %s", principal);
	  *status = sec_rgy_passwd_invalid;
	}
    }
#else
    *status = sec_rgy_not_implemented;
#endif
}

void sec_auth_apple_rand2num(handle_t handle, idl_char *principal, idl_byte s_challenge[8], idl_byte c_response[8], idl_byte c_challenge[8], idl_byte s_response[8], idl_byte dce_deskey[8], error_status_t *status)
{
  if (!validate_client(handle))
    *status = sec_rgy_not_authorized;
  else
#ifdef SEC_AUTH_APPLE_RAND2NUM
    {
      idl_byte apple_deskey[8];
      idl_byte correct_response[8];
      Key_schedule key_schedule;
      int index;

      if (!decrypt_era(principal, "auth_apple_deskey", apple_deskey, 8)) {
	syslog(LOG_ERR, "sec_auth_apple_rand2num: failed to decrypt era auth_apple_deskey for %s", principal);
	*status = sec_rgy_passwd_invalid;
	return;
      }

      for (index = 0; index < 8; index++)
	apple_deskey[index] <<= 1;
	
      key_sched((C_Block *) apple_deskey, key_schedule);
      ecb_encrypt((C_Block *) s_challenge, (C_Block *) correct_response, key_schedule, DES_ENCRYPT);
  
      if (memcmp(c_response, correct_response, 8) == 0)
	{
	  if(!decrypt_era(principal, "auth_dce_deskey", dce_deskey, 8)) {
	    syslog(LOG_ERR, "sec_auth_apple_rand2num: failed to decrypt era auth_dce_deskey for %s", principal);
	    *status = sec_rgy_passwd_invalid;
	    return;
	  }

	  ecb_encrypt((C_Block *) c_challenge, (C_Block *) s_response, key_schedule, DES_ENCRYPT);
	  *status = error_status_ok;
	}
      else
	{
	  syslog(LOG_ERR, "sec_auth_apple_rand2num: failed auth_apple_deskey attempt for %s", principal);
	  *status = sec_rgy_passwd_invalid;
	}
    }
#else
    *status = sec_rgy_not_implemented;
#endif
}
