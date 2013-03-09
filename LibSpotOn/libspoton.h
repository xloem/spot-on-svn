#ifndef LIBSPOTON_H
#define LIBSPOTON_H

#ifdef LIBSPOTON_OS_WINDOWS
#include "errno.h"
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include "gcrypt.h"
#pragma GCC diagnostic warning "-Wdeprecated-declarations"
#include "pthread.h"
#include "sqlite3.h"
#else
#include <errno.h>
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include <gcrypt.h>
#pragma GCC diagnostic warning "-Wdeprecated-declarations"
#include <pthread.h>
#include <sqlite3.h>
#endif
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C"
{
#endif

typedef enum
  {
    LIBSPOTON_ERROR_NONE = 0,
    LIBSPOTON_ERROR_GCRY_CALLOC,
    LIBSPOTON_ERROR_GCRY_CHECK_VERSION,
    LIBSPOTON_ERROR_GCRY_CIPHER_ENCRYPT,
    LIBSPOTON_ERROR_GCRY_CIPHER_GET_ALGO_BLKLEN,
    LIBSPOTON_ERROR_GCRY_CIPHER_GET_ALGO_KEYLEN,
    LIBSPOTON_ERROR_GCRY_CIPHER_MAP_NAME,
    LIBSPOTON_ERROR_GCRY_CIPHER_OPEN,
    LIBSPOTON_ERROR_GCRY_CIPHER_SETIV,
    LIBSPOTON_ERROR_GCRY_CIPHER_SETKEY,
    LIBSPOTON_ERROR_GCRY_CONTROL,
    LIBSPOTON_ERROR_GCRY_PK_ENCRYPT_DESCRIPTION,
    LIBSPOTON_ERROR_GCRY_PK_ENCRYPT_TITLE,
    LIBSPOTON_ERROR_GCRY_PK_ENCRYPT_URL,
    LIBSPOTON_ERROR_GCRY_PK_GENKEY,
    LIBSPOTON_ERROR_GCRY_SEXP_FIND_TOKEN_PRIVATE_KEY,
    LIBSPOTON_ERROR_GCRY_SEXP_FIND_TOKEN_PUBLIC_KEY,
    LIBSPOTON_ERROR_GCRY_SEXP_BUILD,
    LIBSPOTON_ERROR_GCRY_SEXP_BUILD_DESCRIPTION,
    LIBSPOTON_ERROR_GCRY_SEXP_BUILD_TITLE,
    LIBSPOTON_ERROR_GCRY_SEXP_BUILD_URL,
    LIBSPOTON_ERROR_GCRY_SEXP_NEW,
    LIBSPOTON_ERROR_GCRY_SEXP_SPRINT_DESCRIPTION,
    LIBSPOTON_ERROR_GCRY_SEXP_SPRINT_PRIVATE_KEY,
    LIBSPOTON_ERROR_GCRY_SEXP_SPRINT_PUBLIC_KEY,
    LIBSPOTON_ERROR_GCRY_SEXP_SPRINT_TITLE,
    LIBSPOTON_ERROR_GCRY_SEXP_SPRINT_URL,
    LIBSPOTON_ERROR_INVALID_LENGTH,
    LIBSPOTON_ERROR_INVALID_PUBLIC_KEY,
    LIBSPOTON_ERROR_KERNEL_PROCESS_ALREADY_REGISTERED,
    LIBSPOTON_ERROR_MALLOC,
    LIBSPOTON_ERROR_NOT_CONNECTED_TO_SQLITE_DATABASE,
    LIBSPOTON_ERROR_NULL_LIBSPOTON_HANDLE,
    LIBSPOTON_ERROR_NULL_PASSPHRASE,
    LIBSPOTON_ERROR_SQLITE_BIND_BLOB,
    LIBSPOTON_ERROR_SQLITE_BIND_BLOB_DESCRIPTION,
    LIBSPOTON_ERROR_SQLITE_BIND_BLOB_TITLE,
    LIBSPOTON_ERROR_SQLITE_BIND_BLOB_URL,
    LIBSPOTON_ERROR_SQLITE_BIND_INT64,
    LIBSPOTON_ERROR_SQLITE_BIND_TEXT,
    LIBSPOTON_ERROR_SQLITE_COLUMN_TEXT,
    LIBSPOTON_ERROR_SQLITE_CREATE_KERNEL_REGISTRATION_TABLE,
    LIBSPOTON_ERROR_SQLITE_CREATE_KERNEL_REGISTRATION_TRIGGER,
    LIBSPOTON_ERROR_SQLITE_CREATE_KEYS_TABLE,
    LIBSPOTON_ERROR_SQLITE_CREATE_KEYS_TRIGGER,
    LIBSPOTON_ERROR_SQLITE_CREATE_URLS_TABLE,
    LIBSPOTON_ERROR_SQLITE_DELETE_FROM_KERNEL_REGISTRATION,
    LIBSPOTON_ERROR_SQLITE_OPEN_V2,
    LIBSPOTON_ERROR_SQLITE_PREPARE_V2,
    LIBSPOTON_ERROR_SQLITE_STEP
  }
  libspoton_error_code_t;

struct libspoton_handle_struct_t
{
  gcry_sexp_t publicKey;
  sqlite3 *sqliteHandle;
};

typedef libspoton_error_code_t libspoton_error_t;
typedef struct libspoton_handle_struct_t libspoton_handle_t;

/*
** Is a kernel process registered?
*/

bool libspoton_is_kernel_registered(libspoton_handle_t *libspotonHandle);

/*
** Return a user-friendly string representation of error.
*/

const char *libspoton_strerror(const libspoton_error_t error);

/*
** Deregister the kernel process.
*/

libspoton_error_t libspoton_deregister_kernel
(const pid_t pid, libspoton_handle_t *libspotonHandle);

/*
** Generate a new private and public key pair. Please note that
** publicKey is destroyed if it is non-zero before being populated
** with a new value.
*/

libspoton_error_t libspoton_generate_private_public_keys
(const char *passphrase,
 const char *cipher,
 const int nbits,
 libspoton_handle_t *libspotonHandle);

/*
** Create shared.db. Initialize publicKey to zero.
*/

libspoton_error_t libspoton_init(const char *databasePath,
				 libspoton_handle_t *libspotonHandle);

/*
** Extract the public_key from the keys table and place the S-expression
** into the publicKey container.
*/

libspoton_error_t libspoton_populate_public_key
(libspoton_handle_t *libspotonHandle);

/*
** Register the kernel process.
*/

libspoton_error_t libspoton_register_kernel
(const pid_t pid,
 const bool forceRegistration,
 libspoton_handle_t *libspotonHandle);

/*
** Encode the description, title, and url and place the encoded
** values into the urls table. The url field is required while
** title and description may be 0.
*/

libspoton_error_t libspoton_save_url(const char *url,
				     const size_t urlSize,
				     const char *title,
				     const size_t titleSize,
				     const char *description,
				     const size_t descriptionSize,
				     libspoton_handle_t *libspotonHandle);

/*
** Retrieve the registered kernel's PID.
*/

pid_t libspoton_registered_kernel_pid(libspoton_handle_t *libspotonHandle);

/*
** Release resources and reset the publicKey variable to zero.
*/

void libspoton_close(libspoton_handle_t *libspotonHandle);

#ifdef __cplusplus
}
#endif
#endif
