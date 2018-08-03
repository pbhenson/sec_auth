/*
 * sec_auth
 *
 * Copyright (c) 1999 Paul Henson <henson@acm.org>
 *
 */

#include <stdio.h>
#include <syslog.h>
#include <krb5.h>
#include <dce/sec_rgy_attr_sch.h>
#include <dce/dce_error.h>
#include <dce/dce_cf.h>
#include <dce/pthread.h>
#include "../config.h"
#include "../samba/samba.h"

static krb5_context context;
static char *local_cell_name = NULL;
static int initialized = 0;
static sec_attr_schema_entry_t sec_auth_dce_deskey_schema;
static sec_attr_schema_entry_t sec_auth_ms_nthash_schema;
static sec_attr_schema_entry_t sec_auth_ms_lmhash_schema;
static krb5_encrypt_block global_encblock;
static krb5_keyblock global_keyblock;
static sec_rgy_handle_t rgy_handle;

#define QUEUE_SIZE 10

typedef struct {
  sec_rgy_name_t username;
  sec_passwd_str_t password;
} queue_entry_t;

static int queue_head = 0;
static int queue_tail = 0;
static int queue_size = 0;

static queue_entry_t queue[QUEUE_SIZE];
static pthread_mutex_t queue_mutex;
static pthread_cond_t queue_cond;


static pthread_addr_t era_update(pthread_addr_t arg) {

  sec_rgy_name_t username;
  sec_passwd_str_t password;

  pthread_mutex_lock(&queue_mutex);

  while (1) {

    if (queue_size > 0) {

      strcpy(username, queue[queue_head].username);
      strcpy(password, queue[queue_head].password);
      queue_head = (queue_head+1) % QUEUE_SIZE;
      queue_size--;

      pthread_mutex_unlock(&queue_mutex);
      sec_auth_gen_eras(username, password);
      pthread_mutex_lock(&queue_mutex);
    }
    else {

      pthread_cond_wait(&queue_cond, &queue_mutex);
    }
  }
}


int sec_auth_gen_eras_enqueue(char *username, char *password) {

  int tries;
  struct timespec sleep_interval;

  sleep_interval.tv_sec = 0;
  sleep_interval.tv_nsec = 100000000; /* 1/10 second */
  
  for (tries = 0; tries < 5; tries++) {

    if (pthread_mutex_trylock(&queue_mutex)) {

      if (queue_size < QUEUE_SIZE) {

	strcpy(queue[queue_tail].username, username);
	strcpy(queue[queue_tail].password, password);
	queue_tail = (queue_tail+1) % QUEUE_SIZE;
	queue_size++;

	pthread_cond_signal(&queue_cond);
	pthread_mutex_unlock(&queue_mutex);
	return 1;
      }
    }
    pthread_delay_np(&sleep_interval);
  }

  syslog(LOG_ERR, "unable to enqueue era change for %s", username);
  return 0;
}

int sec_auth_gen_eras_init() {

  error_status_t dce_st;
  dce_error_string_t dce_error;
  int dce_error_st;
  long krb5_status;
  krb5_data salt, key;
  pthread_t era_update_thread;
  pthread_mutexattr_t mutexattr;
  pthread_condattr_t condattr;
  
  sec_rgy_attr_sch_lookup_by_name(sec_rgy_default_handle, NULL, "auth_dce_deskey", &sec_auth_dce_deskey_schema, &dce_st);

  if (dce_st) {
    dce_error_inq_text(dce_st, dce_error, &dce_error_st);
    syslog(LOG_ERR, "sec_rgy_attr_sch_lookup_by_name for auth_dce_deskey failed - %s", dce_error);
    return 0;
  }

  sec_rgy_attr_sch_lookup_by_name(sec_rgy_default_handle, NULL, "auth_ms_nthash", &sec_auth_ms_nthash_schema, &dce_st);

  if (dce_st) {
    dce_error_inq_text(dce_st, dce_error, &dce_error_st);
    syslog(LOG_ERR, "sec_rgy_attr_sch_lookup_by_name for auth_ms_nthash failed - %s", dce_error);
    return 0;
  }

  sec_rgy_attr_sch_lookup_by_name(sec_rgy_default_handle, NULL, "auth_ms_lmhash", &sec_auth_ms_lmhash_schema, &dce_st);

  if (dce_st) {
    dce_error_inq_text(dce_st, dce_error, &dce_error_st);
    syslog(LOG_ERR, "sec_rgy_attr_sch_lookup_by_name for auth_ms_lmhash failed - %s", dce_error);
    return 0;
  }

  if (krb5_status = krb5_init_context(&context)) {
    syslog(LOG_ERR, "krb5_init_context failed - %s", error_message(krb5_status));
    return 0;
  }

  global_keyblock.enctype = ENCTYPE_DES_CBC_CRC;
  krb5_use_enctype(context, &global_encblock, global_keyblock.enctype);

  salt.length = strlen(SEC_AUTH_KEY_SALT);
  salt.data = SEC_AUTH_KEY_SALT;
  key.length = strlen(SEC_AUTH_KEY_STRING);
  key.data = SEC_AUTH_KEY_STRING;

  if (krb5_status = krb5_string_to_key(context, &global_encblock, &global_keyblock, &key, &salt)) {
    syslog(LOG_ERR, "krb5_string_to_key failed - %s", error_message(krb5_status));
    return 0;
  }
  
  if (krb5_status = krb5_process_key(context, &global_encblock, &global_keyblock)) {
    syslog(LOG_ERR, "krb5_process_key failed - %s", error_message(krb5_status));
    return 0;
  }

  dce_cf_get_cell_name (&local_cell_name, &dce_st);

  if (dce_st) {
    dce_error_inq_text(dce_st, dce_error, &dce_error_st);
    syslog(LOG_ERR, "dce_cf_get_cell_name failed - %s", dce_error); 
    return 0;
  }

  sec_rgy_site_open_update(NULL, &rgy_handle, &dce_st);

  if (dce_st) {
    dce_error_inq_text(dce_st, dce_error, &dce_error_st);
    syslog(LOG_ERR, "sec_rgy_site_open_update failed - %s", dce_error); 
    return 0;
  }

  pthread_mutexattr_create(&mutexattr);
  pthread_mutex_init(&queue_mutex, mutexattr);
  pthread_mutexattr_delete(&mutexattr);
  pthread_condattr_create(&condattr);
  pthread_cond_init(&queue_cond, condattr);
  pthread_condattr_delete(&condattr);
  
  if (pthread_create(&era_update_thread, pthread_attr_default, era_update, (pthread_addr_t) NULL)) {
    syslog(LOG_ERR, "pthread_create failed - %m");
    return 0;
  }
  
  pthread_detach(&era_update_thread);

  return (initialized = 1);
}


static int sec_auth_gen_ms_hash(char *username, char *password) {

  error_status_t dce_st;
  dce_error_string_t dce_error;
  int dce_error_st;
  sec_attr_t attr;
  int encrypted_length;
  char nthash[16], lmhash[16];
  unsigned32 num_returned;
  sec_attr_t out_attr;
  unsigned32 num_left;
  signed32 failure_index;
   
  samba_nt_lm_owf_gen(password, nthash, lmhash);
  
  encrypted_length = krb5_encrypt_size(16, global_encblock.crypto_entry);
  
  attr.attr_id = sec_auth_ms_nthash_schema.attr_id;
  attr.attr_value.attr_encoding = sec_attr_enc_bytes;

  attr.attr_value.tagged_union.bytes = (sec_attr_enc_bytes_t *)
    malloc(sizeof(sec_attr_enc_bytes_t) + ((encrypted_length + 1) * sizeof(idl_byte)));

  if (!attr.attr_value.tagged_union.bytes) {
    syslog(LOG_ERR, "sec_auth_gen_ms_hash malloc failed - %m");
    return 0;
  }
  
  attr.attr_value.tagged_union.bytes->length = encrypted_length;

  krb5_encrypt(context, (krb5_pointer) nthash, attr.attr_value.tagged_union.bytes->data, 16, &global_encblock, 0);

  sec_rgy_attr_update(rgy_handle, sec_rgy_domain_person, username, 1, 0, &attr, &num_returned, &out_attr, &num_left, &failure_index, &dce_st);

  if (dce_st) {
    dce_error_inq_text(dce_st, dce_error, &dce_error_st);
    syslog(LOG_ERR, "sec_auth_gen_ms_hash sec_rgy_attr_update failed - %s", dce_error);
    free(attr.attr_value.tagged_union.bytes);
    return 0;
  }

  attr.attr_id = sec_auth_ms_lmhash_schema.attr_id;

  krb5_encrypt(context, (krb5_pointer) lmhash, attr.attr_value.tagged_union.bytes->data, 16, &global_encblock, 0);

  sec_rgy_attr_update(rgy_handle, sec_rgy_domain_person, username, 1, 0, &attr, &num_returned, &out_attr, &num_left, &failure_index, &dce_st);

  free(attr.attr_value.tagged_union.bytes);

  if (dce_st) {
    dce_error_inq_text(dce_st, dce_error, &dce_error_st);
    syslog(LOG_ERR, "sec_auth_gen_mshash sec_rgy_attr_update failed - %s", dce_error);
    return 0;
  }
  
  return 1;
}


static int sec_auth_gen_dce_deskey(char *username, char *password) {

  krb5_keyblock keyblock;
  error_status_t dce_st;
  dce_error_string_t dce_error;
  int dce_error_st;
  long krb5_status;
  char principal_buf[2*sec_rgy_name_t_size];
  krb5_principal principal;
  krb5_encrypt_block encblock;
  krb5_data salt, key_string;
  sec_attr_t attr;
  int encrypted_length;
  unsigned32 num_returned;
  sec_attr_t out_attr;
  unsigned32 num_left;
  signed32 failure_index;
  
  keyblock.enctype = ENCTYPE_DES_CBC_CRC;
  krb5_use_enctype(context, &encblock, keyblock.enctype);

  sprintf(principal_buf, "%s@%s", username, local_cell_name+5);

  if (krb5_status = krb5_parse_name(context, principal_buf, &principal)) {
    syslog(LOG_ERR, "sec_auth_gen_dce_deskey krb5_parse_name failed - %s", error_message(krb5_status));
    return 0;
  }

  if (krb5_status = krb5_principal2salt(context, principal, &salt)) {
    syslog(LOG_ERR, "sec_auth_gen_dce_deskey krb5_principal2salt failed - %s", error_message(krb5_status));
    return 0;
  }

  key_string.length = strlen(password);
  key_string.data = password;

  if (krb5_status = krb5_string_to_key(context, &encblock, &keyblock, &key_string, &salt)) {
    syslog(LOG_ERR, "sec_auth_gen_dce_deskey krb5_string_to_key failed - %s", error_message(krb5_status));
    return 0;
  }

  krb5_free_principal(context, principal);

  encrypted_length = krb5_encrypt_size(keyblock.length, global_encblock.crypto_entry);
  
  attr.attr_id = sec_auth_dce_deskey_schema.attr_id;
  attr.attr_value.attr_encoding = sec_attr_enc_bytes;

  attr.attr_value.tagged_union.bytes = (sec_attr_enc_bytes_t *)
    malloc(sizeof(sec_attr_enc_bytes_t) + ((encrypted_length + 1) * sizeof(idl_byte)));

  if (!attr.attr_value.tagged_union.bytes) {
    syslog(LOG_ERR, "sec_auth_gen_dce_deskey malloc failed - %m");
    return 0;
  }

  attr.attr_value.tagged_union.bytes->length = encrypted_length;

  krb5_encrypt(context, (krb5_pointer) keyblock.contents, attr.attr_value.tagged_union.bytes->data, keyblock.length, &global_encblock, 0);

  sec_rgy_attr_update(rgy_handle, sec_rgy_domain_person, username, 1, 0, &attr, &num_returned, &out_attr, &num_left, &failure_index, &dce_st);

  free(attr.attr_value.tagged_union.bytes);
  
  if (dce_st) {
    dce_error_inq_text(dce_st, dce_error, &dce_error_st);
    syslog(LOG_ERR, "sec_auth_gen_dce_deskey sec_rgy_attr_update failed - %s", dce_error);
    return 0;
  }
  
  return 1;
}

int sec_auth_gen_eras(char *username, char *password) {

  int status = 1;
  
  status = status && sec_auth_gen_ms_hash(username, password);
  status = status && sec_auth_gen_dce_deskey(username, password);
  
  return status;
}
