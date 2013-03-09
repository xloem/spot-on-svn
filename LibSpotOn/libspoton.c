/*
** Copyright (c) 2012, 2013 Alexis Megas
** All rights reserved.
**
** Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions
** are met:
** 1. Redistributions of source code must retain the above copyright
**    notice, this list of conditions and the following disclaimer.
** 2. Redistributions in binary form must reproduce the above copyright
**    notice, this list of conditions and the following disclaimer in the
**    documentation and/or other materials provided with the distribution.
** 3. The name of the author may not be used to endorse or promote products
**    derived from Spot-On without specific prior written permission.
**
** SPOT-ON IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
** IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
** OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
** IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
** INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
** NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
** DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
** THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
** (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
** SPOT-ON, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef LIBSPOTON_OS_WINDOWS
#include <arpa/inet.h>
#endif
#include "libspoton.h"

static char *libspoton_error_strings[] =
  {
    "LIBSPOTON_ERROR_NONE",
    "LIBSPOTON_ERROR_GCRY_CALLOC",
    "LIBSPOTON_ERROR_GCRY_CHECK_VERSION",
    "LIBSPOTON_ERROR_GCRY_CIPHER_ENCRYPT",
    "LIBSPOTON_ERROR_GCRY_CIPHER_GET_ALGO_BLKLEN",
    "LIBSPOTON_ERROR_GCRY_CIPHER_GET_ALGO_KEYLEN",
    "LIBSPOTON_ERROR_GCRY_CIPHER_MAP_NAME",
    "LIBSPOTON_ERROR_GCRY_CIPHER_OPEN",
    "LIBSPOTON_ERROR_GCRY_CIPHER_SETIV",
    "LIBSPOTON_ERROR_GCRY_CIPHER_SETKEY",
    "LIBSPOTON_ERROR_GCRY_CONTROL",
    "LIBSPOTON_ERROR_GCRY_PK_ENCRYPT_DESCRIPTION",
    "LIBSPOTON_ERROR_GCRY_PK_ENCRYPT_TITLE",
    "LIBSPOTON_ERROR_GCRY_PK_ENCRYPT_URL",
    "LIBSPOTON_ERROR_GCRY_PK_GENKEY",
    "LIBSPOTON_ERROR_GCRY_SEXP_FIND_TOKEN_PRIVATE_KEY",
    "LIBSPOTON_ERROR_GCRY_SEXP_FIND_TOKEN_PUBLIC_KEY",
    "LIBSPOTON_ERROR_GCRY_SEXP_BUILD",
    "LIBSPOTON_ERROR_GCRY_SEXP_BUILD_DESCRIPTION",
    "LIBSPOTON_ERROR_GCRY_SEXP_BUILD_TITLE",
    "LIBSPOTON_ERROR_GCRY_SEXP_BUILD_URL",
    "LIBSPOTON_ERROR_GCRY_SEXP_NEW",
    "LIBSPOTON_ERROR_GCRY_SEXP_SPRINT_DESCRIPTION",
    "LIBSPOTON_ERROR_GCRY_SEXP_SPRINT_PRIVATE_KEY",
    "LIBSPOTON_ERROR_GCRY_SEXP_SPRINT_PUBLIC_KEY",
    "LIBSPOTON_ERROR_GCRY_SEXP_SPRINT_TITLE",
    "LIBSPOTON_ERROR_GCRY_SEXP_SPRINT_URL",
    "LIBSPOTON_ERROR_INVALID_LENGTH",
    "LIBSPOTON_ERROR_INVALID_PUBLIC_KEY",
    "LIBSPOTON_ERROR_KERNEL_PROCESS_ALREADY_REGISTERED",
    "LIBSPOTON_ERROR_MALLOC",
    "LIBSPOTON_ERROR_NOT_CONNECTED_TO_SQLITE_DATABASE",
    "LIBSPOTON_ERROR_NULL_LIBSPOTON_HANDLE",
    "LIBSPOTON_ERROR_NULL_PASSPHRASE",
    "LIBSPOTON_ERROR_SQLITE_BIND_BLOB",
    "LIBSPOTON_ERROR_SQLITE_BIND_BLOB_DESCRIPTION",
    "LIBSPOTON_ERROR_SQLITE_BIND_BLOB_TITLE",
    "LIBSPOTON_ERROR_SQLITE_BIND_BLOB_URL",
    "LIBSPOTON_ERROR_SQLITE_BIND_INT64",
    "LIBSPOTON_ERROR_SQLITE_BIND_TEXT",
    "LIBSPOTON_ERROR_SQLITE_COLUMN_TEXT",
    "LIBSPOTON_ERROR_SQLITE_CREATE_KERNEL_REGISTRATION_TABLE",
    "LIBSPOTON_ERROR_SQLITE_CREATE_KERNEL_REGISTRATION_TRIGGER",
    "LIBSPOTON_ERROR_SQLITE_CREATE_KEYS_TABLE",
    "LIBSPOTON_ERROR_SQLITE_CREATE_KEYS_TRIGGER",
    "LIBSPOTON_ERROR_SQLITE_CREATE_URLS_TABLE",
    "LIBSPOTON_ERROR_SQLITE_DELETE_FROM_KERNEL_REGISTRATION",
    "LIBSPOTON_ERROR_SQLITE_OPEN_V2",
    "LIBSPOTON_ERROR_SQLITE_PREPARE_V2",
    "LIBSPOTON_ERROR_SQLITE_STEP"
  };
static libspoton_error_t libspoton_error_maximum_error =
  LIBSPOTON_ERROR_SQLITE_STEP;
static pthread_mutex_t sqlite_mutex = PTHREAD_MUTEX_INITIALIZER;

GCRY_THREAD_OPTION_PTHREAD_IMPL;

static libspoton_error_t initialize_libgcrypt(void)
{
  /*
  ** Initialize the gcrypt library if it has not yet been
  ** initialized.
  */

  libspoton_error_t rerr = LIBSPOTON_ERROR_NONE;

  if(!gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P))
    {
      gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread, 0);

      if(!gcry_check_version(GCRYPT_VERSION))
	rerr = LIBSPOTON_ERROR_GCRY_CHECK_VERSION;
      else
	{
	  gcry_control(GCRYCTL_ENABLE_M_GUARD);
	  gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);
#ifdef LIBSPOTON_IGNORE_GCRY_CONTROL_GCRYCTL_INIT_SECMEM_RETURN_VALUE
	  gcry_control(GCRYCTL_INIT_SECMEM, 16384, 0);
#else
	  if(gcry_control(GCRYCTL_INIT_SECMEM, 16384, 0) != 0)
	    rerr = LIBSPOTON_ERROR_GCRY_CONTROL;
#endif
	  gcry_control(GCRYCTL_RESUME_SECMEM_WARN);

	  if(rerr == LIBSPOTON_ERROR_NONE)
	    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
	}
    }

  return rerr;
}

bool libspoton_is_kernel_registered(libspoton_handle_t *libspotonHandle)
{
  return libspoton_registered_kernel_pid(libspotonHandle) > 0;
}

const char *libspoton_strerror(const libspoton_error_t error)
{
  if(error > libspoton_error_maximum_error)
    return "";
  else
    return libspoton_error_strings[error];
}

libspoton_error_t libspoton_deregister_kernel
(const pid_t pid, libspoton_handle_t *libspotonHandle)
{
  const char *sql = "DELETE FROM kernel_registration WHERE pid = ?";
  const char *tail = 0;
  int rv = 0;
  libspoton_error_t rerr = LIBSPOTON_ERROR_NONE;
  sqlite3_stmt *stmt = 0;

  if(!libspotonHandle)
    {
      rerr = LIBSPOTON_ERROR_NULL_LIBSPOTON_HANDLE;
      goto error_label;
    }
  else if(!libspotonHandle->sqliteHandle)
    {
      rerr = LIBSPOTON_ERROR_NOT_CONNECTED_TO_SQLITE_DATABASE;
      goto error_label;
    }

  pthread_mutex_lock(&sqlite_mutex);
  rv = sqlite3_prepare_v2(libspotonHandle->sqliteHandle,
			  sql,
			  strlen(sql),
			  &stmt,
			  &tail);
  pthread_mutex_unlock(&sqlite_mutex);

  if(rv != SQLITE_OK)
    {
      rerr = LIBSPOTON_ERROR_SQLITE_PREPARE_V2;
      goto error_label;
    }

  if(sqlite3_bind_int64(stmt, 1, pid) != SQLITE_OK)
    {
      rerr = LIBSPOTON_ERROR_SQLITE_BIND_INT64;
      goto error_label;
    }

  rv = sqlite3_step(stmt);

  if(!(rv == 0 || rv == SQLITE_DONE))
    {
      rerr = LIBSPOTON_ERROR_SQLITE_STEP;
      goto error_label;
    }

 error_label:
  sqlite3_finalize(stmt);
  return rerr;
}

libspoton_error_t libspoton_generate_private_public_keys
(const char *passphrase,
 const char *cipher,
 const int nbits,
 libspoton_handle_t *libspotonHandle)
{
  char *buffer1 = 0;
  char *buffer2 = 0;
  char *encodedBuffer = 0;
  char *encodedBufferAndIV = 0;
  char *iv = 0;
  char lengthArray[4];
  const char *sql = "INSERT OR REPLACE INTO keys (private_key, public_key) "
    "VALUES (?, ?)";
  const char *tail = 0;
  gcry_cipher_hd_t cipherCtx = 0;
  gcry_sexp_t keyPair = 0;
  gcry_sexp_t parameters = 0;
  gcry_sexp_t privateKey = 0;
  int algorithm = gcry_cipher_map_name(cipher);
  int rv = 0;
  libspoton_error_t rerr = LIBSPOTON_ERROR_NONE;
  size_t blockLength = 0;
  size_t buffer2Length = 0;
  size_t encodedBufferAndIVLength = 0;
  size_t encodedBufferLength = 0;
  size_t length = 0;
  sqlite3_stmt *stmt = 0;

  if(!libspotonHandle)
    {
      rerr = LIBSPOTON_ERROR_NULL_LIBSPOTON_HANDLE;
      goto error_label;
    }
  else if(!libspotonHandle->sqliteHandle)
    {
      rerr = LIBSPOTON_ERROR_NOT_CONNECTED_TO_SQLITE_DATABASE;
      goto error_label;
    }
  else if(!passphrase)
    {
      rerr = LIBSPOTON_ERROR_NULL_PASSPHRASE;
      goto error_label;
    }

  if(!algorithm)
    {
      rerr = LIBSPOTON_ERROR_GCRY_CIPHER_MAP_NAME;
      goto error_label;
    }

  if(gcry_cipher_open(&cipherCtx, algorithm, GCRY_CIPHER_MODE_CBC,
		      GCRY_CIPHER_SECURE | GCRY_CIPHER_CBC_CTS) != 0)
    {
      rerr = LIBSPOTON_ERROR_GCRY_CIPHER_OPEN;
      goto error_label;
    }

  if((length = gcry_cipher_get_algo_keylen(algorithm)) != 0)
    {
      if(gcry_cipher_setkey(cipherCtx, passphrase, length) != 0)
	{
	  rerr = LIBSPOTON_ERROR_GCRY_CIPHER_SETKEY;
	  goto error_label;
	}
    }
  else
    {
      rerr = LIBSPOTON_ERROR_GCRY_CIPHER_GET_ALGO_KEYLEN;
      goto error_label;
    }

  if((blockLength = gcry_cipher_get_algo_blklen(algorithm)) == 0)
    {
      rerr = LIBSPOTON_ERROR_GCRY_CIPHER_GET_ALGO_BLKLEN;
      goto error_label;
    }
  else
    {
      iv = (char *) gcry_calloc(blockLength, sizeof(char));

      if(iv)
	{
	  gcry_create_nonce(iv, blockLength);

	  if(gcry_cipher_setiv(cipherCtx, iv, blockLength) != 0)
	    {
	      rerr = LIBSPOTON_ERROR_GCRY_CIPHER_SETIV;
	      goto error_label;
	    }
	}
      else
	{
	  rerr = LIBSPOTON_ERROR_GCRY_CALLOC;
	  goto error_label;
	}
    }

  if(gcry_sexp_build(&parameters, 0, "(genkey (rsa (nbits %d)))", nbits) != 0)
    {
      rerr = LIBSPOTON_ERROR_GCRY_SEXP_BUILD;
      goto error_label;
    }

  if(gcry_pk_genkey(&keyPair, parameters) != 0)
    {
      rerr = LIBSPOTON_ERROR_GCRY_PK_GENKEY;
      goto error_label;
    }

  privateKey = gcry_sexp_find_token(keyPair, "private-key", 0);

  if(!privateKey)
    {
      rerr = LIBSPOTON_ERROR_GCRY_SEXP_FIND_TOKEN_PRIVATE_KEY;
      goto error_label;
    }

  length = gcry_sexp_sprint(privateKey, GCRYSEXP_FMT_ADVANCED, 0, 0);

  if(!length)
    {
      rerr = LIBSPOTON_ERROR_GCRY_SEXP_SPRINT_PRIVATE_KEY;
      goto error_label;
    }
  else
    {
      buffer1 = (char *) malloc(length);

      if(buffer1)
	gcry_sexp_sprint(privateKey, GCRYSEXP_FMT_ADVANCED, buffer1, length);
      else
	{
	  rerr = LIBSPOTON_ERROR_MALLOC;
	  goto error_label;
	}
    }

  /*
  ** The block cipher requires that the length of the buffer is a
  ** multiple of the cipher's block size. We increase the total length
  ** by one additional block size.
  */

  encodedBufferLength = blockLength * (length + 1);

  if(encodedBufferLength < 4)
    {
      rerr = LIBSPOTON_ERROR_INVALID_LENGTH;
      goto error_label;
    }

  encodedBuffer = (char *) calloc(encodedBufferLength, sizeof(char));

  if(!encodedBuffer)
    {
      rerr = LIBSPOTON_ERROR_MALLOC;
      goto error_label;
    }
  else
    memcpy(encodedBuffer, buffer1, length);

  /*
  ** Set the last four bytes to the length of the buffer. QDataStream
  ** objects will retrieve the length of the original message.
  */

#ifdef LIBSPOTON_OS_WINDOWS
  lengthArray[3] = length & 0xFF;
  lengthArray[2] = (length >> 8)  & 0xFF;
  lengthArray[1] = (length >> 16) & 0xFF;
  lengthArray[0] = (length >> 24) & 0xFF;
  encodedBuffer[encodedBufferLength - 4] = lengthArray[0];
  encodedBuffer[encodedBufferLength - 3] = lengthArray[1];
  encodedBuffer[encodedBufferLength - 2] = lengthArray[2];
  encodedBuffer[encodedBufferLength - 1] = lengthArray[3];
#else
  length = htonl(length);
  memcpy(lengthArray, &length, 4);
  memcpy(&encodedBuffer[encodedBufferLength - 4], lengthArray, 4);
#endif

  if(gcry_cipher_encrypt(cipherCtx, encodedBuffer, encodedBufferLength,
			 0, 0) == 0)
    {
      encodedBufferAndIVLength = blockLength + encodedBufferLength;
      encodedBufferAndIV = (char *) malloc(encodedBufferAndIVLength);

      if(encodedBufferAndIV)
	{
	  memcpy(encodedBufferAndIV, iv, blockLength);
	  memcpy(&encodedBufferAndIV[blockLength], encodedBuffer,
		 encodedBufferLength);
	}
      else
	{
	  rerr = LIBSPOTON_ERROR_MALLOC;
	  goto error_label;
	}
    }
  else
    {
      rerr = LIBSPOTON_ERROR_GCRY_CIPHER_ENCRYPT;
      goto error_label;
    }

  if(!encodedBuffer)
    {
      rerr = LIBSPOTON_ERROR_MALLOC;
      goto error_label;
    }

  if(libspotonHandle->publicKey)
    {
      gcry_sexp_release(libspotonHandle->publicKey);
      libspotonHandle->publicKey = 0;
    }

  libspotonHandle->publicKey = gcry_sexp_find_token(keyPair, "public-key", 0);

  if(!libspotonHandle->publicKey)
    {
      rerr = LIBSPOTON_ERROR_GCRY_SEXP_FIND_TOKEN_PUBLIC_KEY;
      goto error_label;
    }

  buffer2Length = gcry_sexp_sprint(libspotonHandle->publicKey,
				   GCRYSEXP_FMT_ADVANCED, 0, 0);

  if(!buffer2Length)
    {
      rerr = LIBSPOTON_ERROR_GCRY_SEXP_SPRINT_PUBLIC_KEY;
      goto error_label;
    }
  else
    {
      buffer2 = (char *) malloc(buffer2Length);

      if(buffer2)
	gcry_sexp_sprint(libspotonHandle->publicKey,
			 GCRYSEXP_FMT_ADVANCED, buffer2, buffer2Length);
      else
	{
	  rerr = LIBSPOTON_ERROR_MALLOC;
	  goto error_label;
	}
    }

  pthread_mutex_lock(&sqlite_mutex);
  rv = sqlite3_prepare_v2(libspotonHandle->sqliteHandle,
			  sql,
			  strlen(sql),
			  &stmt,
			  &tail);
  pthread_mutex_unlock(&sqlite_mutex);

  if(rv != SQLITE_OK)
    {
      rerr = LIBSPOTON_ERROR_SQLITE_PREPARE_V2;
      goto error_label;
    }

  if(sqlite3_bind_blob(stmt,
		       1,
		       encodedBufferAndIV,
		       encodedBufferAndIVLength,
		       SQLITE_STATIC) != 0)
    {
      rerr = LIBSPOTON_ERROR_SQLITE_BIND_BLOB;
      goto error_label;
    }

  if(sqlite3_bind_text(stmt,
		       2,
		       buffer2,
		       buffer2Length,
		       SQLITE_STATIC) != 0)
    {
      rerr = LIBSPOTON_ERROR_SQLITE_BIND_TEXT;
      goto error_label;
    }

  rv = sqlite3_step(stmt);

  if(!(rv == 0 || rv == SQLITE_DONE))
    {
      rerr = LIBSPOTON_ERROR_SQLITE_STEP;
      goto error_label;
    }

 error_label:
  free(buffer1);
  free(buffer2);
  free(encodedBuffer);
  free(encodedBufferAndIV);
  gcry_free(iv);
  gcry_sexp_release(keyPair);
  gcry_sexp_release(parameters);
  gcry_sexp_release(privateKey);
  gcry_cipher_close(cipherCtx);
  sqlite3_finalize(stmt);
  return rerr;
}

libspoton_error_t libspoton_init(const char *databasePath,
				 libspoton_handle_t *libspotonHandle)
{
  int rv = 0;
  libspoton_error_t rerr = LIBSPOTON_ERROR_NONE;

  if(!libspotonHandle)
    {
      rerr = LIBSPOTON_ERROR_NULL_LIBSPOTON_HANDLE;
      goto error_label;
    }

  libspotonHandle->publicKey = 0;
  libspotonHandle->sqliteHandle = 0;

  /*
  ** Initialize libgcrypt.
  */

  if((rerr = initialize_libgcrypt()) != LIBSPOTON_ERROR_NONE)
    goto error_label;

  /*
  ** Create the shared.db database.
  */

  pthread_mutex_lock(&sqlite_mutex);
  rv = sqlite3_open_v2(databasePath,
		       &libspotonHandle->sqliteHandle,
		       SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
		       0);
  pthread_mutex_unlock(&sqlite_mutex);

  if(rv != SQLITE_OK)
    {
      rerr = LIBSPOTON_ERROR_SQLITE_OPEN_V2;
      goto error_label;
    }

  /*
  ** Create some database tables.
  */

  pthread_mutex_lock(&sqlite_mutex);
  rv = sqlite3_exec(libspotonHandle->sqliteHandle,
		    "CREATE TABLE IF NOT EXISTS keys ("
		    "private_key BLOB NOT NULL, "
		    "public_key TEXT NOT NULL)",
		    0,
		    0,
		    0);
  pthread_mutex_unlock(&sqlite_mutex);

  if(rv != SQLITE_OK)
    {
      rerr = LIBSPOTON_ERROR_SQLITE_CREATE_KEYS_TABLE;
      goto error_label;
    }

  /*
  ** The keys table must contain only one entry.
  */

  pthread_mutex_lock(&sqlite_mutex);
  rv = sqlite3_exec(libspotonHandle->sqliteHandle,
		    "CREATE TRIGGER IF NOT EXISTS keys_trigger "
		    "BEFORE INSERT ON keys "
		    "BEGIN "
		    "DELETE FROM keys; "
		    "END",
		    0,
		    0,
		    0);
  pthread_mutex_unlock(&sqlite_mutex);

  if(rv != SQLITE_OK)
    {
      rerr = LIBSPOTON_ERROR_SQLITE_CREATE_KEYS_TRIGGER;
      goto error_label;
    }

 error_label:

  if(rerr != LIBSPOTON_ERROR_NONE)
    libspoton_close(libspotonHandle);

  return rerr;
}

libspoton_error_t libspoton_populate_public_key
(libspoton_handle_t *libspotonHandle)
{
  const char *buffer = 0;
  const char *sql = "SELECT public_key FROM keys";
  int rv = 0;
  libspoton_error_t rerr = LIBSPOTON_ERROR_NONE;
  sqlite3_stmt *stmt = 0;

  if(!libspotonHandle)
    {
      rerr = LIBSPOTON_ERROR_NULL_LIBSPOTON_HANDLE;
      goto error_label;
    }
  else if(!libspotonHandle->sqliteHandle)
    {
      rerr = LIBSPOTON_ERROR_NOT_CONNECTED_TO_SQLITE_DATABASE;
      goto error_label;
    }

  /*
  ** Attempt to create an S-expression object from public_key.
  */

  pthread_mutex_lock(&sqlite_mutex);
  rv = sqlite3_prepare_v2(libspotonHandle->sqliteHandle, sql, -1, &stmt, 0);
  pthread_mutex_unlock(&sqlite_mutex);

  if(rv == SQLITE_OK)
    {
      if(sqlite3_step(stmt) == SQLITE_ROW)
	{
	  buffer = (const char *) sqlite3_column_text(stmt, 0);

	  if(buffer)
	    {
	      if(libspotonHandle->publicKey)
		{
		  gcry_sexp_release(libspotonHandle->publicKey);
		  libspotonHandle->publicKey = 0;
		}

	      if(gcry_sexp_new(&libspotonHandle->publicKey,
			       buffer, strlen(buffer), 1) != 0)
		rerr = LIBSPOTON_ERROR_GCRY_SEXP_NEW;
	    }
	  else
	    rerr = LIBSPOTON_ERROR_SQLITE_COLUMN_TEXT;
	}
      else
	rerr = LIBSPOTON_ERROR_SQLITE_STEP;
    }
  else
    rerr = LIBSPOTON_ERROR_SQLITE_PREPARE_V2;

  sqlite3_finalize(stmt);

 error_label:
  return rerr;
}

libspoton_error_t libspoton_register_kernel
(const pid_t pid,
 const bool forceRegistration,
 libspoton_handle_t *libspotonHandle)
{
  const char *sql = "INSERT OR REPLACE INTO kernel_registration (pid) "
    "VALUES (?)";
  const char *tail = 0;
  int rv = 0;
  libspoton_error_t rerr = LIBSPOTON_ERROR_NONE;
  pid_t l_pid = 0;
  sqlite3_stmt *stmt = 0;

  if(!libspotonHandle)
    {
      rerr = LIBSPOTON_ERROR_NULL_LIBSPOTON_HANDLE;
      goto error_label;
    }
  else if(!libspotonHandle->sqliteHandle)
    {
      rerr = LIBSPOTON_ERROR_NOT_CONNECTED_TO_SQLITE_DATABASE;
      goto error_label;
    }

  pthread_mutex_lock(&sqlite_mutex);
  rv = sqlite3_exec(libspotonHandle->sqliteHandle,
		    "CREATE TABLE IF NOT EXISTS kernel_registration ("
		    "pid INTEGER PRIMARY KEY NOT NULL)",
		    0,
		    0,
		    0);
  pthread_mutex_unlock(&sqlite_mutex);

  if(rv != SQLITE_OK)
    {
      rerr = LIBSPOTON_ERROR_SQLITE_CREATE_KERNEL_REGISTRATION_TABLE;
      goto error_label;
    }

  /*
  ** The kernel_registration table must contain only one entry.
  */

  pthread_mutex_lock(&sqlite_mutex);
  rv = sqlite3_exec(libspotonHandle->sqliteHandle,
		    "CREATE TRIGGER IF NOT EXISTS kernel_registration_trigger "
		    "BEFORE INSERT ON kernel_registration "
		    "BEGIN "
		    "DELETE FROM kernel_registration; "
		    "END",
		    0,
		    0,
		    0);
  pthread_mutex_unlock(&sqlite_mutex);

  if(rv != SQLITE_OK)
    {
      rerr = LIBSPOTON_ERROR_SQLITE_CREATE_KERNEL_REGISTRATION_TRIGGER;
      goto error_label;
    }

  if((l_pid = libspoton_registered_kernel_pid(libspotonHandle)) > 0)
    if(pid != l_pid)
      if(!forceRegistration)
	{
	  rerr = LIBSPOTON_ERROR_KERNEL_PROCESS_ALREADY_REGISTERED;
	  goto error_label;
	}

  pthread_mutex_lock(&sqlite_mutex);
  rv = sqlite3_prepare_v2(libspotonHandle->sqliteHandle,
			  sql,
			  strlen(sql),
			  &stmt,
			  &tail);
  pthread_mutex_unlock(&sqlite_mutex);

  if(rv != SQLITE_OK)
    {
      rerr = LIBSPOTON_ERROR_SQLITE_PREPARE_V2;
      goto error_label;
    }

  if(sqlite3_bind_int64(stmt, 1, pid) != SQLITE_OK)
    {
      rerr = LIBSPOTON_ERROR_SQLITE_BIND_INT64;
      goto error_label;
    }

  rv = sqlite3_step(stmt);

  if(!(rv == 0 || rv == SQLITE_DONE))
    {
      rerr = LIBSPOTON_ERROR_SQLITE_STEP;
      goto error_label;
    }

 error_label:
  sqlite3_finalize(stmt);
  return rerr;
}

libspoton_error_t libspoton_save_url(const char *url,
				     const size_t urlSize,
				     const char *title,
				     const size_t titleSize,
				     const char *description,
				     const size_t descriptionSize,
				     libspoton_handle_t *libspotonHandle)
{
  char *buffer = 0;
  const char *sql = "INSERT OR REPLACE INTO urls (url, title, description) "
    "VALUES (?, ?, ?)";
  const char *tail = 0;
  gcry_sexp_t data = 0;
  gcry_sexp_t encodedData = 0;
  int rv = 0;
  libspoton_error_t rerr = LIBSPOTON_ERROR_NONE;
  size_t length = 0;
  sqlite3_stmt *stmt = 0;

  if(!libspotonHandle)
    {
      rerr = LIBSPOTON_ERROR_NULL_LIBSPOTON_HANDLE;
      goto error_label;
    }
  else if(!libspotonHandle->sqliteHandle)
    {
      rerr = LIBSPOTON_ERROR_NOT_CONNECTED_TO_SQLITE_DATABASE;
      goto error_label;
    }

  if(!libspotonHandle->publicKey)
    {
      rerr = LIBSPOTON_ERROR_INVALID_PUBLIC_KEY;
      goto error_label;
    }

  pthread_mutex_lock(&sqlite_mutex);
  rv = sqlite3_exec(libspotonHandle->sqliteHandle,
		    "CREATE TABLE IF NOT EXISTS urls ("
		    "url BLOB PRIMARY KEY NOT NULL, "
		    "title BLOB, "
		    "description BLOB)",
		    0,
		    0,
		    0);
  pthread_mutex_unlock(&sqlite_mutex);

  if(rv != SQLITE_OK)
    {
      rerr = LIBSPOTON_ERROR_SQLITE_CREATE_URLS_TABLE;
      goto error_label;
    }

  pthread_mutex_lock(&sqlite_mutex);
  rv = sqlite3_prepare_v2(libspotonHandle->sqliteHandle,
			  sql,
			  strlen(sql),
			  &stmt,
			  &tail);
  pthread_mutex_unlock(&sqlite_mutex);

  if(rv != SQLITE_OK)
    {
      rerr = LIBSPOTON_ERROR_SQLITE_PREPARE_V2;
      goto error_label;
    }

  /*
  ** Encode the URL.
  */

  if(gcry_sexp_build(&data, 0, "(data (flags oaep)(value %b))",
		     urlSize, url) != 0)
    {
      rerr = LIBSPOTON_ERROR_GCRY_SEXP_BUILD_URL;
      goto error_label;
    }

  if(gcry_pk_encrypt(&encodedData, data, libspotonHandle->publicKey) != 0)
    {
      rerr = LIBSPOTON_ERROR_GCRY_PK_ENCRYPT_URL;
      goto error_label;
    }

  length = gcry_sexp_sprint(encodedData, GCRYSEXP_FMT_ADVANCED, 0, 0);

  if(!length)
    {
      rerr = LIBSPOTON_ERROR_GCRY_SEXP_SPRINT_URL;
      goto error_label;
    }

  buffer = (char *) malloc(length);

  if(buffer)
    gcry_sexp_sprint(encodedData, GCRYSEXP_FMT_ADVANCED, buffer, length);
  else
    {
      rerr = LIBSPOTON_ERROR_MALLOC;
      goto error_label;
    }

  /*
  ** Please note the use of SQLITE_TRANSIENT.
  */

  if(sqlite3_bind_blob(stmt,
		       1,
		       buffer,
		       length,
		       SQLITE_TRANSIENT) != SQLITE_OK)
    {
      rerr = LIBSPOTON_ERROR_SQLITE_BIND_BLOB_URL;
      goto error_label;
    }

  free(buffer);
  buffer = 0;
  gcry_sexp_release(data);
  data = 0;
  gcry_sexp_release(encodedData);
  encodedData = 0;
  length = 0;

  /*
  ** Encode the title.
  */

  if(title && titleSize)
    {
      if(gcry_sexp_build(&data, 0, "(data (flags oaep)(value %b))",
			 titleSize, title) != 0)
	{
	  rerr = LIBSPOTON_ERROR_GCRY_SEXP_BUILD_TITLE;
	  goto error_label;
	}

      if(gcry_pk_encrypt(&encodedData, data, libspotonHandle->publicKey) != 0)
	{
	  rerr = LIBSPOTON_ERROR_GCRY_PK_ENCRYPT_TITLE;
	  goto error_label;
	}

      length = gcry_sexp_sprint(encodedData, GCRYSEXP_FMT_ADVANCED, 0, 0);

      if(!length)
	{
	  rerr = LIBSPOTON_ERROR_GCRY_SEXP_SPRINT_TITLE;
	  goto error_label;
	}

      buffer = (char *) malloc(length);

      if(buffer)
	gcry_sexp_sprint(encodedData, GCRYSEXP_FMT_ADVANCED, buffer, length);
      else
	{
	  rerr = LIBSPOTON_ERROR_MALLOC;
	  goto error_label;
	}
    }

  if(sqlite3_bind_blob(stmt,
		       2,
		       buffer,
		       length,
		       SQLITE_TRANSIENT) != SQLITE_OK)
    {
      rerr = LIBSPOTON_ERROR_SQLITE_BIND_BLOB_TITLE;
      goto error_label;
    }

  free(buffer);
  buffer = 0;
  gcry_sexp_release(data);
  data = 0;
  gcry_sexp_release(encodedData);
  encodedData = 0;
  length = 0;

  /*
  ** Encode the description.
  */

  if(description && descriptionSize)
    {
      if(gcry_sexp_build(&data, 0, "(data (flags oaep)(value %b))",
			 descriptionSize, description) != 0)
	{
	  rerr = LIBSPOTON_ERROR_GCRY_SEXP_BUILD_DESCRIPTION;
	  goto error_label;
	}

      if(gcry_pk_encrypt(&encodedData, data, libspotonHandle->publicKey) != 0)
	{
	  rerr = LIBSPOTON_ERROR_GCRY_PK_ENCRYPT_DESCRIPTION;
	  goto error_label;
	}

      length = gcry_sexp_sprint(encodedData, GCRYSEXP_FMT_ADVANCED, 0, 0);

      if(!length)
	{
	  rerr = LIBSPOTON_ERROR_GCRY_SEXP_SPRINT_DESCRIPTION;
	  goto error_label;
	}

      buffer = (char *) malloc(length);

      if(buffer)
	gcry_sexp_sprint(encodedData, GCRYSEXP_FMT_ADVANCED, buffer, length);
      else
	{
	  rerr = LIBSPOTON_ERROR_MALLOC;
	  goto error_label;
	}
    }

  if(sqlite3_bind_blob(stmt,
		       3,
		       buffer,
		       length,
		       SQLITE_TRANSIENT) != 0)
    {
      rerr = LIBSPOTON_ERROR_SQLITE_BIND_BLOB_DESCRIPTION;
      goto error_label;
    }

  free(buffer);
  buffer = 0;
  gcry_sexp_release(data);
  data = 0;
  gcry_sexp_release(encodedData);
  encodedData = 0;
  rv = sqlite3_step(stmt);

  if(!(rv == 0 || rv == SQLITE_DONE))
    {
      rerr = LIBSPOTON_ERROR_SQLITE_STEP;
      goto error_label;
    }

 error_label:
  free(buffer);
  gcry_sexp_release(data);
  gcry_sexp_release(encodedData);
  sqlite3_finalize(stmt);
  return rerr;
}

pid_t libspoton_registered_kernel_pid(libspoton_handle_t *libspotonHandle)
{
  int rv = 0;
  const char *sql = "SELECT pid FROM kernel_registration";
  sqlite3_stmt *stmt = 0;
  sqlite3_int64 pid = 0;

  if(!libspotonHandle)
    goto error_label;
  else if(!libspotonHandle->sqliteHandle)
    goto error_label;

  pthread_mutex_lock(&sqlite_mutex);
  rv = sqlite3_prepare_v2(libspotonHandle->sqliteHandle, sql, -1, &stmt, 0);
  pthread_mutex_unlock(&sqlite_mutex);

  if(rv == SQLITE_OK)
    if(sqlite3_step(stmt) == SQLITE_ROW)
      pid = sqlite3_column_int64(stmt, 0);

  sqlite3_finalize(stmt);

 error_label:
  return (pid_t) pid;
}

void libspoton_close(libspoton_handle_t *libspotonHandle)
{
  if(libspotonHandle)
    {
      pthread_mutex_lock(&sqlite_mutex);
      sqlite3_close(libspotonHandle->sqliteHandle);
      pthread_mutex_unlock(&sqlite_mutex);
      gcry_sexp_release(libspotonHandle->publicKey);
      libspotonHandle->publicKey = 0;
    }
}
