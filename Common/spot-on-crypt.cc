/*
** Copyright (c) 2011, 2012, 2013 Alexis Megas
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

#include <QDir>
#include <QSettings>
#include <QSqlDatabase>
#include <QSqlError>
#include <QSqlQuery>
#include <QtCore/qmath.h>

#include "spot-on-crypt.h"
#include "spot-on-misc.h"

extern "C"
{
#ifdef SPOTON_LINKED_WITH_LIBPTHREAD
  GCRY_THREAD_OPTION_PTHREAD_IMPL;
#endif

#include "libSpotOn/libspoton.h"
}

#ifndef SPOTON_LINKED_WITH_LIBPTHREAD
#include <QMutex>
extern "C"
{
  int gcry_qthread_init(void)
  {
    return 0;
  }

  int gcry_qmutex_init(void **mutex)
  {
    *mutex = static_cast<void *> (new QMutex());

    if(*mutex)
      return 0;
    else
      return -1;
  }

  int gcry_qmutex_destroy(void **mutex)
  {
    delete static_cast<QMutex *> (*mutex);
    return 0;
  }

  int gcry_qmutex_lock(void **mutex)
  {
    QMutex *m = static_cast<QMutex *> (*mutex);

    if(m)
      {
	m->lock();
	return 0;
      }
    else
      return -1;
  }

  int gcry_qmutex_unlock(void **mutex)
  {
    QMutex *m = static_cast<QMutex *> (*mutex);

    if(m)
      {
	m->unlock();
	return 0;
      }
    else
      return -1;
  }
}

struct gcry_thread_cbs gcry_threads_qt =
  {
    GCRY_THREAD_OPTION_USER, gcry_qthread_init, gcry_qmutex_init,
    gcry_qmutex_destroy, gcry_qmutex_lock, gcry_qmutex_unlock,
    0, 0, 0, 0, 0, 0, 0, 0
  };
#endif

static bool gcryctl_set_thread_cbs_set = false;

void spoton_crypt::init(const int secureMemorySize)
{
  if(!gcryctl_set_thread_cbs_set)
    {
      gcryctl_set_thread_cbs_set = true;
#ifdef SPOTON_LINKED_WITH_LIBPTHREAD
      gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread, 0);
#else
      gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_qt, 0);
#endif
    }

  if(!gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P))
    {
      gcry_control(GCRYCTL_ENABLE_M_GUARD);

      if(!gcry_check_version(GCRYPT_VERSION))
	spoton_misc::logError
	  ("spoton_crypt::init(): gcry_check_version() "
	   "failure. Perhaps you should verify some "
	   "settings.");
      else
	{
	  gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);
#ifdef Q_OS_FREEBSD
	  gcry_control(GCRYCTL_INIT_SECMEM, secureMemorySize, 0);
#else
	  gcry_error_t err = 0;

	  if((err = gcry_control(GCRYCTL_INIT_SECMEM, secureMemorySize,
				 0)) != 0)
	    {
	      QByteArray buffer(64, 0);

	      gpg_strerror_r(err, buffer.data(), buffer.length());
	      spoton_misc::logError
		(QString("spoton_crypt::init(): initializing "
			 "secure memory failure (%1).").
		 arg(buffer.constData()));
	    }
#endif

	  gcry_control(GCRYCTL_RESUME_SECMEM_WARN);
	  gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
	}
    }
  else
    spoton_misc::logError
      ("spoton_crypt::init(): libgcrypt is already initialized.");

  SSL_library_init();
}

QPair<QByteArray, QByteArray> spoton_crypt::derivedKeys
(const QString &cipherType,
 const QString &hashType,
 const unsigned long iterationCount,
 const QString &passphrase,
 const QByteArray &salt,
 QString &error)
{
  QByteArray key;
  QByteArray temporaryKey;
  QPair<QByteArray, QByteArray> keys;
  gcry_error_t err = 0;
  int cipherAlgorithm = gcry_cipher_map_name(cipherType.toLatin1().
					     constData());
  int hashAlgorithm = gcry_md_map_name(hashType.toLatin1().constData());
  size_t cipherKeyLength = 0;

  if(gcry_cipher_test_algo(cipherAlgorithm) != 0)
    {
      error = QObject::tr("gcry_cipher_test_algo() returned non-zero");
      spoton_misc::logError
	(QString("spoton_crypt::derivedKeys(): gcry_cipher_test_algo() "
		 "failure for %1.").arg(cipherType));
      goto done_label;
    }

  if(gcry_md_test_algo(hashAlgorithm) != 0)
    {
      error = QObject::tr("gcry_md_test_algo() returned non-zero");
      spoton_misc::logError
	(QString("spoton_crypt::derivedKeys(): gcry_md_test_algo() "
		 "failure for %1.").arg(hashType));
      goto done_label;
    }

  if((cipherKeyLength = gcry_cipher_get_algo_keylen(cipherAlgorithm)) == 0)
    {
      error = QObject::tr("gcry_cipher_get_algo_keylen() returned zero");
      spoton_misc::logError
	(QString("spoton_crypt::derivedKeys(): "
		 "gcry_cipher_get_algo_keylen() "
		 "failure for %1.").arg(cipherType));
      goto done_label;
    }

  key.resize(cipherKeyLength + 256);
  keys.first.resize(cipherKeyLength);
  keys.second.resize(key.length() - cipherKeyLength);
  temporaryKey.resize(key.length());

  for(int i = 1; i <= 2; i++)
    {
      gcry_fast_random_poll();

      if(i == 1)
	err = gcry_kdf_derive
	  (static_cast<const void *> (passphrase.toUtf8().constData()),
	   static_cast<size_t> (passphrase.toUtf8().length()),
	   GCRY_KDF_PBKDF2,
	   hashAlgorithm,
	   static_cast<const void *> (salt.constData()),
	   static_cast<size_t> (salt.length()),
	   iterationCount,
	   static_cast<size_t> (temporaryKey.length()),
	   static_cast<void *> (temporaryKey.data()));
      else if(i == 2)
	{
	  err = gcry_kdf_derive
	    (static_cast<const void *> (temporaryKey.constData()),
	     static_cast<size_t> (temporaryKey.length()),
	     GCRY_KDF_PBKDF2,
	     hashAlgorithm,
	     static_cast<const void *> (salt.constData()),
	     static_cast<size_t> (salt.length()),
	     iterationCount,
	     static_cast<size_t> (key.length()),
	     static_cast<void *> (key.data()));

	  if(err == 0)
	    {
	      keys.first = key.mid(0, keys.first.length());
	      keys.second = key.mid(keys.first.length());
	    }
	}

      if(err != 0)
	{
	  error = QObject::tr("gcry_kdf_derive() returned non-zero");

	  QByteArray buffer(64, 0);

	  gpg_strerror_r(err, buffer.data(), buffer.length());
	  spoton_misc::logError
	    (QString("spoton_crypt::derivedKeys(): gcry_kdf_derive() "
		     "returned non-zero (%1).").arg(buffer.constData()));
	  break;
	}
    }

 done_label:

  if(!error.isEmpty())
    {
      keys.first.clear();
      keys.second.clear();
    }

  return keys;
}

QByteArray spoton_crypt::saltedValue(const QString &hashType,
				     const QByteArray &data,
				     const QByteArray &salt,
				     bool *ok)
{
  QByteArray hash;
  QByteArray salted;
  int hashAlgorithm = gcry_md_map_name(hashType.toLatin1().constData());
  unsigned int length = 0;

  if(data.isEmpty())
    {
      if(ok)
	*ok = false;

      spoton_misc::logError("spoton_crypt::saltedValue(): "
			    "empty data.");
    }

  if(salt.isEmpty())
    {
      if(ok)
	*ok = false;

      spoton_misc::logError("spoton_crypt::saltedValue(): "
			    "empty salt.");
    }

  if(hashAlgorithm == 0)
    {
      if(ok)
	*ok = false;

      spoton_misc::logError
	(QString("spoton_crypt::saltedValue(): "
		 "gcry_md_map_name() "
		 "returned zero for %1.").arg(hashType));
      goto done_label;
    }

  length = gcry_md_get_algo_dlen(hashAlgorithm);

  if(length == 0)
    {
      if(ok)
	*ok = false;

      spoton_misc::logError
	(QString("spoton_crypt::saltedValue(): "
		 "gcry_md_get_algo_dlen() "
		 "returned zero for %1.").arg(hashType));
      goto done_label;
    }

  if(ok)
    *ok = true;

  hash.resize(length);
  salted.append(data).append(salt);
  gcry_md_hash_buffer(hashAlgorithm,
		      static_cast<void *> (hash.data()),
		      static_cast<const void *> (salted.constData()),
		      static_cast<size_t> (salted.length()));
 done_label:
  return hash;
}

QByteArray spoton_crypt::saltedPassphraseHash(const QString &hashType,
					      const QString &passphrase,
					      const QByteArray &salt,
					      QString &error)
{
  QByteArray saltedPassphraseHash;
  QByteArray saltedPassphrase("");
  int hashAlgorithm = gcry_md_map_name(hashType.toLatin1().constData());
  unsigned int length = 0;

  if(passphrase.trimmed().isEmpty())
    {
      error = QObject::tr("empty passphrase");
      spoton_misc::logError("spoton_crypt::saltedPassphrase(): "
			    "empty passphrase.");
    }

  if(salt.isEmpty())
    {
      error = QObject::tr("empty salt");
      spoton_misc::logError("spoton_crypt::saltedPassphrase(): "
			    "empty salt.");
    }

  if(hashAlgorithm == 0)
    {
      error = QObject::tr("gcry_md_map_name() returned zero");
      spoton_misc::logError
	(QString("spoton_crypt::saltedPassphraseHash(): "
		 "gcry_md_map_name() "
		 "returned zero for %1.").arg(hashType));
      goto done_label;
    }

  length = gcry_md_get_algo_dlen(hashAlgorithm);

  if(length == 0)
    {
      error = QObject::tr("gcry_md_get_algo_dlen() returned zero");
      spoton_misc::logError
	(QString("spoton_crypt::saltedPassphraseHash(): "
		 "gcry_md_get_algo_dlen() "
		 "returned zero for %1.").arg(hashType));
      goto done_label;
    }

  saltedPassphrase.append(passphrase).append(salt);
  saltedPassphraseHash.resize(length);
  gcry_md_hash_buffer(hashAlgorithm,
		      static_cast<void *> (saltedPassphraseHash.data()),
		      static_cast<const void *> (saltedPassphrase.
						 constData()),
		      static_cast<size_t> (saltedPassphrase.length()));
 done_label:
  return saltedPassphraseHash;
}

QStringList spoton_crypt::cipherTypes(void)
{
  QStringList types;

  types << "aes256"
	<< "camellia256"
	<< "gost28147"
	<< "serpent256"
	<< "twofish";

  for(int i = types.size() - 1; i >= 0; i--)
    {
      int algorithm = gcry_cipher_map_name(types.at(i).toLatin1().
					   constData());

      if(!(algorithm != 0 && gcry_cipher_test_algo(algorithm) == 0))
	types.removeAt(i);
    }

  return types;
}

QStringList spoton_crypt::hashTypes(void)
{
  QStringList types;

  types << "sha512"
	<< "stribog512"
	<< "tiger"
	<< "whirlpool";

  for(int i = types.size() - 1; i >= 0; i--)
    {
      int algorithm = gcry_md_map_name(types.at(i).toLatin1().constData());

      if(!(algorithm != 0 && gcry_md_test_algo(algorithm) == 0))
	types.removeAt(i);
    }

  return types;
}

bool spoton_crypt::passphraseSet(void)
{
  QSettings settings;

  return settings.contains("gui/saltedPassphraseHash") &&
    !settings.value("gui/saltedPassphraseHash",
		    "").toString().trimmed().isEmpty();
}

void spoton_crypt::reencodeKeys(const QString &newCipher,
				const QByteArray &newKey,
				const QString &oldCipher,
				const char *oldKey,
				const QString &id,
				QString &error)
{
  if(!oldKey)
    {
      error = QObject::tr("oldKey is 0");
      spoton_misc::logError("spoton_crypt::reencodeKeys(): "
			    "oldKey is 0.");
      return;
    }

  QList<QByteArray> data;
  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);
    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "idiotes.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);
	query.prepare("SELECT private_key, public_key "
		      "FROM idiotes WHERE id = ?");
	query.bindValue(0, id);

	if(query.exec())
	  if(query.next())
	    {
	      data.append(QByteArray::fromBase64(query.value(0).
						 toByteArray()));
	      data.append(QByteArray::fromBase64(query.value(1).
						 toByteArray()));
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(data.isEmpty())
    {
      error = QObject::tr("error retrieving data from the idiotes "
			  "table");
      spoton_misc::logError("spoton_crypt::reencodeKeys(): "
			    "error retrieving data from the idiotes "
			    "table.");
      return;
    }

  QList<QByteArray> encryptedData;
  char *iv = 0;
  gcry_cipher_hd_t cipherHandle = 0;
  gcry_sexp_t key_t = 0;

  for(int i = 0; i < data.size(); i++)
    {
      QByteArray d(data.at(i));
      QByteArray eData;
      QByteArray originalLength;
      QDataStream out(&originalLength, QIODevice::WriteOnly);
      gcry_error_t err = 0;
      int algorithm = gcry_cipher_map_name
	(oldCipher.toLatin1().constData());
      size_t blockLength = 0;
      size_t ivLength = 0;
      size_t keyLength = 0;

      if(algorithm == 0)
	{
	  error = QObject::tr("gcry_cipher_map_name() returned non-zero");
	  spoton_misc::logError
	    ("spoton_crypt::reencodeKeys(): "
	     "gcry_cipher_map_name() "
	     "failure.");
	  goto done_label;
	}

      if((err = gcry_cipher_open(&cipherHandle, algorithm,
				 GCRY_CIPHER_MODE_CBC,
				 GCRY_CIPHER_CBC_CTS |
				 GCRY_CIPHER_SECURE)) != 0 ||
	 !cipherHandle)
	{
	  if(err != 0)
	    {
	      error = QObject::tr("gcry_cipher_open() returned non-zero");

	      QByteArray buffer(64, 0);

	      gpg_strerror_r(err, buffer.data(), buffer.length());
	      spoton_misc::logError
		(QString("spoton_crypt::reencodeKeys(): "
			 "gcry_cipher_open() "
			 "failure (%1).").arg(buffer.constData()));
	    }
	  else
	    {
	      error = QObject::tr("gcry_cipher_open() failure");
	      spoton_misc::logError
		("spoton_crypt::reencodeKeys(): gcry_cipher_open() "
		 "failure.");
	    }

	  goto done_label;
	}

      if((ivLength = gcry_cipher_get_algo_blklen(algorithm)) == 0)
	{
	  error = QObject::tr("gcry_cipher_get_algo_blklen() returned zero");
	  spoton_misc::logError
	    (QString("spoton_crypt::reencodeKeys(): "
		     "gcry_cipher_get_algo_blklen() "
		     "failure for %1.").arg(oldCipher));
	  goto done_label;
	}

      if((err = gcry_cipher_setiv(cipherHandle,
				  static_cast<const void *> (d.
							     mid(0, ivLength).
							     constData()),
				  ivLength)) != 0)
	{
	  error = QObject::tr("gcry_cipher_setiv() returned non-zero");

	  QByteArray buffer(64, 0);

	  gpg_strerror_r(err, buffer.data(), buffer.length());
	  spoton_misc::logError(QString("spoton_crypt::reencodeKeys(): "
					"gcry_cipher_setiv() failure (%1).").
				arg(buffer.constData()));
	  goto done_label;
	}
      else
	d.remove(0, ivLength);

      if((keyLength = gcry_cipher_get_algo_keylen(algorithm)) == 0)
	{
	  error = QObject::tr("gcry_cipher_get_algo_keylen() returned zero");
	  spoton_misc::logError
	    (QString("spoton_crypt::reencodeKeys(): "
		     "gcry_cipher_get_algo_keylen() "
		     "failure for %1.").arg(oldCipher));
	  goto done_label;
	}

      if((err = gcry_cipher_setkey(cipherHandle,
				   static_cast<const void *> (oldKey),
				   keyLength)) != 0)
	{
	  error = QObject::tr("gcry_cipher_setkey() returned non-zero");

	  QByteArray buffer(64, 0);

	  gpg_strerror_r(err, buffer.data(), buffer.length());
	  spoton_misc::logError
	    (QString("spoton_crypt::reencodeKeys(): gcry_cipher_setkey() "
		     "failure (%1).").arg(buffer.constData()));
	  goto done_label;
	}

      if((err = gcry_cipher_decrypt(cipherHandle,
				    static_cast<void *> (d.data()),
				    static_cast<size_t> (d.length()),
				    static_cast<const void *> (0),
				    static_cast<size_t> (0))) == 0)
	{
	  int s = 0;
	  QByteArray originalLength;

	  if(d.length() >= 4)
	    originalLength = d.mid(d.length() - 4, 4);

	  if(!originalLength.isEmpty())
	    {
	      QDataStream in(&originalLength, QIODevice::ReadOnly);

	      in >> s;
	    }

	  if(s >= 0 && s <= d.length())
	    d = d.mid(0, s);
	  else
	    {
	      error = QObject::tr("The length of the decrypted data is "
				  "irregular");
	      spoton_misc::logError
		(QString("spoton_crypt::reencodeKeys(): The length (%1) "
			 "of the "
			 "decrypted data is irregular.").arg(s));
	      goto done_label;
	    }
	}
      else
	{
	  error = QObject::tr("gcry_cipher_decrypt() returned non-zero");

	  QByteArray buffer(64, 0);

	  gpg_strerror_r(err, buffer.data(), buffer.length());
	  spoton_misc::logError
	    (QString("spoton_crypt::reencodeKeys(): "
		     "gcry_cipher_decrypt() "
		     "failure (%1).").arg(buffer.constData()));
	  goto done_label;
	}

      if(i == 0)
	{
	  /*
	  ** Now let's see if we have a somewhat valid private key.
	  */

	  if((err = gcry_sexp_new(&key_t,
				  static_cast<const void *> (d.constData()),
				  static_cast<size_t> (d.length()),
				  1)) != 0 || !key_t)
	    {
	      if(err != 0)
		{
		  error = QObject::tr("gcry_sexp_new() returned non-zero");

		  QByteArray buffer(64, 0);

		  gpg_strerror_r(err, buffer.data(), buffer.length());
		  spoton_misc::logError
		    (QString("spoton_crypt::reencodeKeys(): "
			     "gcry_sexp_new() "
			     "failure (%1).").arg(buffer.constData()));
		}
	      else
		{
		  error = QObject::tr("gcry_sexp_new() failure");
		  spoton_misc::logError
		    ("spoton_crypt::reencodeKeys(): gcry_sexp_new() "
		     "failure.");
		}

	      goto done_label;
	    }

	  if((err = gcry_pk_testkey(key_t)) != 0)
	    {
	      error = QObject::tr("gcry_pk_testkey() returned non-zero");

	      QByteArray buffer(64, 0);

	      gpg_strerror_r(err, buffer.data(), buffer.length());
	      spoton_misc::logError
		(QString("spoton_crypt::reencodeKeys(): "
			 "gcry_pk_testkey() "
			 "failure (%1).").arg(buffer.constData()));
	      goto done_label;
	    }

	  gcry_sexp_release(key_t);
	  key_t = 0;
	}

      gcry_cipher_reset(cipherHandle);
      algorithm = gcry_cipher_map_name(newCipher.toLatin1().constData());

      if(algorithm == 0)
	{
	  error = QObject::tr("gcry_cipher_map_name() returned zero");
	  spoton_misc::logError
	    (QString("spoton_crypt::reencodeKeys(): "
		     "gcry_cipher_map_name() "
		     "failure for %1.").arg(newCipher));
	  goto done_label;
	}

      if((blockLength = gcry_cipher_get_algo_blklen(algorithm)) == 0)
	{
	  error = QObject::tr("gcry_cipher_get_algo_blklen() returned zero");
	  spoton_misc::logError
	    (QString("spoton_crypt::reencodeKeys(): "
		     "gcry_cipher_get_algo_blklen() "
		     "failure for %1.").arg(newCipher));
	  goto done_label;
	}

      if((ivLength = gcry_cipher_get_algo_blklen(algorithm)) == 0)
	{
	  error = QObject::tr("gcry_cipher_get_algo_blklen() returned zero");
	  spoton_misc::logError
	    (QString("spoton_crypt::reencodeKeys(): "
		     "gcry_cipher_get_algo_blklen() "
		     "failure for %1.").arg(newCipher));
	  goto done_label;
	}

      if(!(iv = static_cast<char *> (gcry_calloc(ivLength, sizeof(char)))))
	{
	  error = QObject::tr("gcry_calloc() returned zero");
	  spoton_misc::logError("spoton_crypt::reencodeKeys(): "
				"gcry_calloc() returned zero.");
	  goto done_label;
	}

      gcry_fast_random_poll();
      gcry_create_nonce(iv, ivLength);

      if(gcry_cipher_setiv(cipherHandle,
			   static_cast<const void *> (iv),
			   ivLength) != 0)
	{
	  error = QObject::tr("gcry_cipher_setiv() returned non-zero");
	  spoton_misc::logError("spoton_crypt::reencodeKeys(): "
				"gcry_cipher_setiv() returned non-zero.");
	  goto done_label;
	}

      if((keyLength = gcry_cipher_get_algo_keylen(algorithm)) == 0)
	{
	  error = QObject::tr("gcry_cipher_get_algo_keylen() returned zero");
	  spoton_misc::logError
	    (QString("spoton_crypt::reencodeKeys(): "
		     "gcry_cipher_get_algo_keylen() "
		     "failure for %1.").arg(newCipher));
	  goto done_label;
	}

      if((err = gcry_cipher_setkey(cipherHandle,
				   static_cast<const void *> (newKey.
							      constData()),
				   keyLength)) != 0)
	{
	  error = QObject::tr("gcry_cipher_setkey() returned non-zero");

	  QByteArray buffer(64, 0);

	  gpg_strerror_r(err, buffer.data(), buffer.length());
	  spoton_misc::logError
	    (QString("spoton_crypt::reencodeKeys(): gcry_cipher_setkey() "
		     "failure (%1).").arg(buffer.constData()));
	  goto done_label;
	}

      eData.append(d);

      if(eData.isEmpty())
	eData = eData.leftJustified(blockLength, 0);
      else if(static_cast<size_t> (eData.length()) < blockLength)
	eData = eData.leftJustified
	  (blockLength * qCeil(static_cast<qreal> (eData.length()) /
			       static_cast<qreal> (blockLength)), 0);

      out << eData.length();
      eData.append(originalLength);

      if((err = gcry_cipher_encrypt(cipherHandle,
				    static_cast<void *> (eData.data()),
				    static_cast<size_t> (eData.length()),
				    static_cast<const void *> (0),
				    static_cast<size_t> (0))) != 0)
	{
	  error = QObject::tr("gcry_cipher_encrypt() returned non-zero");

	  QByteArray buffer(64, 0);

	  gpg_strerror_r(err, buffer.data(), buffer.length());
	  spoton_misc::logError
	    (QString("spoton_crypt::reencodeKeys(): "
		     "gcry_cipher_encrypt() failure (%1).").
	     arg(buffer.constData()));
	  goto done_label;
	}
      else
	eData = QByteArray(iv, ivLength) + eData;

      encryptedData.append(eData);
      gcry_free(iv);
      iv = 0;
      gcry_cipher_close(cipherHandle);
      cipherHandle = 0;
      gcry_sexp_release(key_t);
      key_t = 0;
    }

  {
    QSqlDatabase db = spoton_misc::database(connectionName);
    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "idiotes.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.prepare("UPDATE idiotes SET private_key = ?, "
		      "public_key = ? WHERE id = ?");

	if(!data.value(0).isEmpty())
	  query.bindValue(0, encryptedData.value(0).toBase64());

	if(!data.value(1).isEmpty())
	  query.bindValue(1, encryptedData.value(1).toBase64());

	query.bindValue(2, id);

	if(!query.exec())
	  spoton_misc::logError
	    (QString("spoton_crypt::reencodeKeys(): "
		     "error (%1) updating private_key in the "
		     "idiotes table.").arg(query.lastError().text()));
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

 done_label:
  gcry_free(iv);
  gcry_cipher_close(cipherHandle);
  gcry_sexp_release(key_t);
}

spoton_crypt::spoton_crypt(const QString &cipherType,
			   const QString &hashType,
			   const QByteArray &passphrase,
			   const QByteArray &symmetricKey,
			   const int saltLength,
			   const unsigned long iterationCount,
			   const QString &id)
{
  init(cipherType, hashType, passphrase, symmetricKey, QByteArray(),
       saltLength, iterationCount, id);
}

spoton_crypt::spoton_crypt(const QString &cipherType,
			   const QString &hashType,
			   const QByteArray &passphrase,
			   const QByteArray &symmetricKey,
			   const QByteArray &hashKey,
			   const int saltLength,
			   const unsigned long iterationCount,
			   const QString &id)
{
  init(cipherType, hashType, passphrase, symmetricKey, hashKey,
       saltLength, iterationCount, id);
}

void spoton_crypt::init(const QString &cipherType,
			const QString &hashType,
			const QByteArray &passphrase,
			const QByteArray &symmetricKey,
			const QByteArray &hashKey,
			const int saltLength,
			const unsigned long iterationCount,
			const QString &id)
{
  Q_UNUSED(passphrase);
  m_cipherAlgorithm = gcry_cipher_map_name(cipherType.toLatin1().
					   constData());
  m_cipherHandle = 0;
  m_cipherType = cipherType;
  m_hashAlgorithm = gcry_md_map_name(hashType.toLatin1().constData());
  m_hashKey = 0;
  m_hashKeyLength = 0;
  m_hashType = hashType;
  m_id = id;
  m_iterationCount = iterationCount;
  m_privateKey = 0;
  m_privateKeyLength = 0;
  m_symmetricKey = 0;

  if(m_cipherAlgorithm)
    m_symmetricKeyLength = gcry_cipher_get_algo_keylen(m_cipherAlgorithm);
  else
    m_symmetricKeyLength = 0;

  m_saltLength = saltLength;
  setHashKey(hashKey);

  if(m_symmetricKeyLength)
    m_symmetricKey = static_cast<char *>
      (gcry_calloc_secure(m_symmetricKeyLength, sizeof(char)));
  else
    spoton_misc::logError("spoton_crypt::spoton_crypt(): "
			  "gcry_cipher_get_algo_keylen() returned zero.");

  if(m_symmetricKey)
    {
      memcpy(static_cast<void *> (m_symmetricKey),
	     static_cast<const void *> (symmetricKey.constData()),
	     qMin(m_symmetricKeyLength,
		  static_cast<size_t> (symmetricKey.length())));

      gcry_error_t err = 0;

      if(m_cipherAlgorithm)
	{
	  if((err = gcry_cipher_open(&m_cipherHandle, m_cipherAlgorithm,
				     GCRY_CIPHER_MODE_CBC,
				     GCRY_CIPHER_CBC_CTS |
				     GCRY_CIPHER_SECURE)) != 0 ||
	     !m_cipherAlgorithm)
	    {
	      if(err != 0)
		{
		  QByteArray buffer(64, 0);

		  gpg_strerror_r(err, buffer.data(), buffer.length());
		  spoton_misc::logError
		    (QString("spoton_crypt::spoton_crypt(): "
			     "gcry_cipher_open() failure (%1).").
		     arg(buffer.constData()));
		}
	      else
		spoton_misc::logError("spoton_crypt::spoton_crypt(): "
				      "gcry_cipher_open() failure.");
	    }
	}
      else
	spoton_misc::logError("spoton_crypt::spoton_crypt(): "
			      "m_cipherAlgorithm is 0.");

      if(err == 0)
	{
	  if(m_cipherHandle)
	    {
	      if((err =
		  gcry_cipher_setkey(m_cipherHandle,
				     static_cast
				     <const void *> (m_symmetricKey),
				     m_symmetricKeyLength)) != 0)
		{
		  QByteArray buffer(64, 0);

		  gpg_strerror_r(err, buffer.data(), buffer.length());
		  spoton_misc::logError
		    (QString("spoton_crypt::spoton_crypt(): "
			     "gcry_cipher_setkey() "
			     "failure (%1).").
		     arg(buffer.constData()));
		}
	    }
	  else
	    spoton_misc::logError("spoton_crypt::spoton_crypt(): "
				  "m_cipherHandle is 0.");
	}
    }
  else if(m_symmetricKeyLength > 0)
    {
      m_symmetricKeyLength = 0;
      spoton_misc::logError("spoton_crypt::spoton_crypt(): "
			    "gcry_calloc_secure() returned 0.");
    }
}

spoton_crypt::~spoton_crypt()
{
  gcry_cipher_close(m_cipherHandle);
  gcry_free(m_hashKey);
  gcry_free(m_privateKey);
  gcry_free(m_symmetricKey);
}

void spoton_crypt::terminate(void)
{
  gcry_control(GCRYCTL_TERM_SECMEM);
}

QByteArray spoton_crypt::decrypted(const QByteArray &data, bool *ok)
{
  if(data.isEmpty())
    {
      if(ok)
	*ok = true;

      return QByteArray();
    }

  if(m_cipherAlgorithm == 0)
    {
      if(ok)
	*ok = false;

      spoton_misc::logError("spoton_crypt::decrypted(): m_cipherAlgorithm "
			    "is 0.");
      return QByteArray();
    }

  if(!m_cipherHandle)
    {
      if(ok)
	*ok = false;

      spoton_misc::logError("spoton_crypt::decrypted(): m_cipherHandle "
			    "is 0.");
      return QByteArray();
    }

  QByteArray decrypted(data);
  QMutexLocker locker(&m_cipherMutex);

  if(!setInitializationVector(decrypted, m_cipherAlgorithm, m_cipherHandle))
    {
      if(ok)
	*ok = false;

      decrypted.clear();
      spoton_misc::logError
	("spoton_crypt::decrypted(): setInitializationVector() failure.");
    }
  else
    {
      gcry_error_t err = 0;

      if((err =
	  gcry_cipher_decrypt(m_cipherHandle,
			      static_cast<void *> (decrypted.data()),
			      static_cast<size_t> (decrypted.
						   length()),
			      static_cast<const void *> (0),
			      static_cast<size_t> (0))) == 0)
	{
	  int s = 0;
	  QByteArray originalLength;

	  if(decrypted.length() >= 4)
	    originalLength = decrypted.mid(decrypted.length() - 4, 4);

	  if(!originalLength.isEmpty())
	    {
	      QDataStream in(&originalLength, QIODevice::ReadOnly);

	      in >> s;
	    }

	  if(s >= 0 && s <= decrypted.length())
	    {
	      if(ok)
		*ok = true;

	      decrypted = decrypted.mid(0, s);
	    }
	  else
	    {
	      if(ok)
		*ok = false;

	      decrypted.clear();
	    }
	}
      else
	{
	  if(ok)
	    *ok = false;

	  decrypted.clear();
	}
    }

  return decrypted;
}

QByteArray spoton_crypt::encrypted(const QByteArray &data, bool *ok)
{
  if(m_cipherAlgorithm == 0)
    {
      if(ok)
	*ok = false;

      spoton_misc::logError
	("spoton_crypt::encrypted(): m_cipherAlgorithm is 0.");
      return QByteArray();
    }

  if(!m_cipherHandle)
    {
      if(ok)
	*ok = false;

      spoton_misc::logError
	("spoton_crypt::encrypted(): m_cipherHandle is 0.");
      return QByteArray();
    }

  QByteArray encrypted(data);
  QByteArray iv;
  QMutexLocker locker(&m_cipherMutex);

  if(!setInitializationVector(iv, m_cipherAlgorithm, m_cipherHandle))
    {
      if(ok)
	*ok = false;

      encrypted.clear();
      spoton_misc::logError
	("spoton_crypt::encrypted(): setInitializationVector() failure.");
    }
  else
    {
      size_t blockLength = gcry_cipher_get_algo_blklen(m_cipherAlgorithm);

      if(blockLength == 0)
	{
	  if(ok)
	    *ok = false;

	  encrypted.clear();
	  spoton_misc::logError
	    (QString("spoton_crypt::encrypted(): "
		     "gcry_cipher_get_algo_blklen() "
		     "failure for %1.").arg(m_cipherType));
	}
      else
	{
	  if(encrypted.isEmpty())
	    encrypted = encrypted.leftJustified(blockLength, 0);
	  else if(static_cast<size_t> (encrypted.length()) < blockLength)
	    encrypted = encrypted.leftJustified
	      (blockLength *
	       qCeil((qreal) encrypted.length() / (qreal) blockLength), 0);

	  QByteArray originalLength;
	  QDataStream out(&originalLength, QIODevice::WriteOnly);

	  out << data.length();
	  encrypted.append(originalLength);

	  gcry_error_t err = 0;

	  if((err =
	      gcry_cipher_encrypt(m_cipherHandle,
				  static_cast<void *> (encrypted.data()),
				  static_cast<size_t> (encrypted.
						       length()),
				  static_cast<const void *> (0),
				  static_cast<size_t> (0))) == 0)
	    {
	      if(ok)
		*ok = true;

	      encrypted = iv + encrypted;
	    }
	  else
	    {
	      if(ok)
		*ok = false;

	      encrypted.clear();

	      QByteArray buffer(64, 0);

	      gpg_strerror_r(err, buffer.data(), buffer.length());
	      spoton_misc::logError
		(QString("spoton_crypt::encrypted(): "
			 "gcry_cipher_encrypt() failure (%1).").
		 arg(buffer.constData()));
	    }
	}
    }

  return encrypted;
}

QByteArray spoton_crypt::symmetricKey(void) const
{
  if(m_symmetricKey)
    return QByteArray(m_symmetricKey, m_symmetricKeyLength);
  else
    return QByteArray();
}

bool spoton_crypt::setInitializationVector(QByteArray &bytes,
					   const int algorithm,
					   gcry_cipher_hd_t cipherHandle)
{
  if(algorithm == 0)
    {
      spoton_misc::logError("spoton_crypt::setInitializationVector(): "
			    "algorithm is 0.");
      return false;
    }

  if(!cipherHandle)
    {
      spoton_misc::logError("spoton_crypt::setInitializationVector(): "
			    "cipherHandle is 0.");
      return false;
    }

  bool ok = true;
  size_t ivLength = 0;

  if((ivLength = gcry_cipher_get_algo_blklen(algorithm)) == 0)
    {
      ok = false;
      spoton_misc::logError
	(QString("spoton_crypt::setInitializationVector(): "
		 "gcry_cipher_get_algo_blklen() "
		 "failure for cipher algorithm %1.").arg(algorithm));
    }
  else
    {
      char *iv = static_cast<char *> (gcry_calloc(ivLength, sizeof(char)));

      if(iv)
	{
	  if(bytes.isEmpty())
	    {
	      gcry_fast_random_poll();
	      gcry_create_nonce(static_cast<void *> (iv), ivLength);
	      bytes.append(iv, ivLength);
	    }
	  else
	    {
	      memcpy
		(static_cast<void *> (iv),
		 static_cast<const void *> (bytes.constData()),
		 qMin(ivLength, static_cast<size_t> (bytes.length())));
	      bytes.remove(0, ivLength);
	    }

	  gcry_cipher_reset(cipherHandle);

	  gcry_error_t err = 0;

	  if((err = gcry_cipher_setiv(cipherHandle,
				      static_cast<const void *> (iv),
				      ivLength)) != 0)
	    {
	      ok = false;

	      QByteArray buffer(64, 0);

	      gpg_strerror_r(err, buffer.data(), buffer.length());
	      spoton_misc::logError
		(QString("spoton_crypt::setInitializationVector(): "
			 "gcry_cipher_setiv() failure (%1).").
		 arg(buffer.constData()));
	    }

	  gcry_free(iv);
	}
      else
	{
	  ok = false;
	  spoton_misc::logError("spoton_crypt::setInitializationVector(): "
				"gcry_calloc() returned 0.");
	}
    }

  return ok;
}

QByteArray spoton_crypt::keyedHash(const QByteArray &data, bool *ok) const
{
  if(m_hashAlgorithm == 0)
    {
      if(ok)
	*ok = false;

      spoton_misc::logError
	("spoton_crypt::keyedHash(): m_hashAlgorithm is 0.");
      return QByteArray();
    }
  else if(!m_hashKey || m_hashKeyLength == 0)
    {
      if(ok)
	*ok = false;

      spoton_misc::logError
	("spoton_crypt::keyedHash(): m_hashKey is not defined.");
      return QByteArray();
    }

  QByteArray hash;
  gcry_error_t err = 0;
  gcry_md_hd_t hd;

  if((err = gcry_md_open(&hd, m_hashAlgorithm,
			 GCRY_MD_FLAG_HMAC)) != 0 || !hd)
    {
      if(ok)
	*ok = false;

      if(err != 0)
	{
	  QByteArray buffer(64, 0);

	  gpg_strerror_r(err, buffer.data(), buffer.length());
	  spoton_misc::logError
	    (QString("spoton_crypt::keyedHash(): "
		     "gcry_md_open() failure (%1).").
	     arg(buffer.constData()));
	}
      else
	spoton_misc::logError
	  ("spoton_crypt::keyedHash(): gcry_md_open() failure.");
    }
  else
    {
      if((err = gcry_md_setkey(hd,
			       static_cast<const void *> (m_hashKey),
			       m_hashKeyLength)) != 0)
	{
	  if(ok)
	    *ok = false;

	  QByteArray buffer(64, 0);

	  gpg_strerror_r(err, buffer.data(), buffer.length());
	  spoton_misc::logError
	    (QString("spoton_crypt::keyedHash(): gcry_md_setkey() "
		     "failure (%1).").arg(buffer.constData()));
	}
      else
	{
	  gcry_md_write
	    (hd,
	     static_cast<const void *> (data.constData()),
	     static_cast<size_t> (data.length()));

	  unsigned char *buffer = gcry_md_read(hd, m_hashAlgorithm);

	  if(buffer)
	    {
	      unsigned int length = gcry_md_get_algo_dlen(m_hashAlgorithm);

	      if(length > 0)
		{
		  hash.resize(length);
		  memcpy(static_cast<void *> (hash.data()),
			 static_cast<const void *> (buffer),
			 static_cast<size_t> (hash.length()));
		}
	      else
		{
		  if(ok)
		    *ok = false;

		  spoton_misc::logError
		    (QString("spoton_crypt::keyedHash(): "
			     "gcry_md_get_algo_dlen() "
			     "failure for %1.").arg(m_hashType));
		}
	    }
	  else
	    {
	      if(ok)
		*ok = false;

	      spoton_misc::logError("spoton_crypt::keyedHash(): "
				    "gcry_md_read() returned 0.");
	    }
	}
    }

  gcry_md_close(hd);
  return hash;
}

QByteArray spoton_crypt::sha1Hash(const QByteArray &data,
				  bool *ok)
{
  return shaXHash(GCRY_MD_SHA1, data, ok);
}

QByteArray spoton_crypt::sha512Hash(const QByteArray &data,
				    bool *ok)
{
  return shaXHash(GCRY_MD_SHA512, data, ok);
}

QByteArray spoton_crypt::shaXHash(const int algorithm,
				  const QByteArray &data,
				  bool *ok)
{
  QByteArray hash;
  unsigned int length = gcry_md_get_algo_dlen(algorithm);

  if(length > 0)
    {
      if(ok)
	*ok = true;

      hash.resize(length);
      gcry_md_hash_buffer
	(algorithm,
	 static_cast<void *> (hash.data()),
	 static_cast<const void *> (data.constData()),
	 static_cast<size_t> (data.length()));
    }
  else
    {
      if(ok)
	*ok = false;

      spoton_misc::logError
	(QString("spoton_crypt::shaXHash(): "
		 "gcry_md_get_algo_dlen() "
		 "failure for %1.").arg(algorithm));
    }

  return hash;
}

QByteArray spoton_crypt::publicKeyEncrypt(const QByteArray &data,
					  const QByteArray &publicKey,
					  bool *ok)
{
  QByteArray encrypted;
  gcry_error_t err = 0;
  gcry_sexp_t key_t = 0;

  if((err = gcry_sexp_new(&key_t,
			  static_cast<const void *> (publicKey.constData()),
			  static_cast<size_t> (publicKey.length()),
			  1)) == 0 && key_t)
    {
      QString keyType("");
      gcry_sexp_t data_t = 0;
      gcry_sexp_t encodedData_t = 0;
      gcry_sexp_t raw_t = 0;

      raw_t = gcry_sexp_find_token(key_t, "elg", 0);

      if(raw_t)
	keyType = "elg";
      else
	{
	  raw_t = gcry_sexp_find_token(key_t, "rsa", 0);

	  if(raw_t)
	    keyType = "rsa";
	}

      gcry_sexp_release(raw_t);

      if(keyType == "elg")
	err = gcry_sexp_build(&data_t, 0,
			      "(data (value %b))",
			      data.length(),
			      data.constData());
      else
	{
	  QByteArray random(64, 0); // Output size of SHA-512 divided by 8.

	  random = strongRandomBytes(random.length());
	  err = gcry_sexp_build(&data_t, 0,
				"(data (flags oaep)(hash-algo sha512)"
				"(value %b)(random-override %b))",
				data.length(),
				data.constData(),
				random.length(),
				random.constData());
	}

      if(err == 0 && data_t)
	{
	  if((err = gcry_pk_encrypt(&encodedData_t, data_t,
				    key_t)) == 0 && encodedData_t)
	    {
	      size_t length = gcry_sexp_sprint
		(encodedData_t, GCRYSEXP_FMT_ADVANCED, 0, 0);

	      if(length)
		{
		  char *buffer = (char *) malloc(length);

		  if(buffer)
		    {
		      if(gcry_sexp_sprint(encodedData_t,
					  GCRYSEXP_FMT_ADVANCED,
					  static_cast<void *> (buffer),
					  length) != 0)
			{
			  if(ok)
			    *ok = true;

			  encrypted.append(QByteArray(buffer, length));
			}
		      else
			{
			  if(ok)
			    *ok = false;

			  spoton_misc::logError
			    ("spoton_crypt()::publicKeyEncrypt(): "
			     "gcry_sexp_sprint() failure.");
			}
		    }
		  else
		    {
		      if(ok)
			*ok = false;

		      spoton_misc::logError
			("spoton_crypt()::publicKeyEncrypt(): malloc() "
			 "failure.");
		    }

		  free(buffer);
		}
	      else
		{
		  if(ok)
		    *ok = false;

		  spoton_misc::logError
		    ("spoton_crypt()::publicKeyEncrypt(): "
		     "gcry_sexp_sprint() failure.");
		}

	      gcry_sexp_release(encodedData_t);
	    }
	  else
	    {
	      if(ok)
		*ok = false;

	      if(err != 0)
		{
		  QByteArray buffer(64, 0);

		  gpg_strerror_r(err, buffer.data(), buffer.length());
		  spoton_misc::logError
		    (QString("spoton_crypt()::publicKeyEncrypt(): "
			     "gcry_pk_encrypt() "
			     "failure (%1).").arg(buffer.constData()));
		}
	      else
		spoton_misc::logError
		  ("spoton_crypt::publicKeyEncrypt(): "
		   "gcry_pk_encrypt() failure.");
	    }

	  gcry_sexp_release(data_t);
	  gcry_sexp_release(key_t);
	}
      else
	{
	  if(ok)
	    *ok = false;

	  if(err != 0)
	    {
	      QByteArray buffer(64, 0);

	      gpg_strerror_r(err, buffer.data(), buffer.length());
	      spoton_misc::logError
		(QString("spoton_crypt()::publicKeyEncrypt(): "
			 "gcry_sexp_build() "
			 "failure (%1).").arg(buffer.constData()));
	    }
	  else if(keyType.isEmpty())
	    spoton_misc::logError
	      ("spoton_crypt()::publicKeyEncrypt(): gcry_sexp_find_token() "
	       "failure.");
	  else
	    spoton_misc::logError
	      ("spoton_crypt()::publicKeyEncrypt(): gcry_sexp_build() "
	       "failure.");
	}
    }
  else
    {
      if(ok)
	*ok = false;

      if(err != 0)
	{
	  QByteArray buffer(64, 0);

	  gpg_strerror_r(err, buffer.data(), buffer.length());
	  spoton_misc::logError
	    (QString("spoton_crypt()::publicKeyEncrypt(): gcry_sexp_new() "
		     "failure (%1).").arg(buffer.constData()));
	}
      else
	spoton_misc::logError
	  ("spoton_crypt::publicKeyEncrypt(): gcry_sexp_new() failure.");
    }

  return encrypted;
}

void spoton_crypt::initializePrivateKeyContainer(bool *ok)
{
  if(m_privateKey || m_privateKeyLength > 0)
    {
      if(ok)
	*ok = true;

      return;
    }

  QByteArray keyData;
  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);
    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "idiotes.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);
	query.prepare("SELECT private_key FROM idiotes WHERE id = ?");
	query.bindValue(0, m_id);

	if(query.exec())
	  if(query.next())
	    keyData = QByteArray::fromBase64
	      (query.value(0).toByteArray());
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(keyData.isEmpty())
    {
      if(ok)
	*ok = false;

      spoton_misc::logError
	("spoton_crypt::initializePrivateKeyContainer(): "
	 "empty private key.");
      goto done_label;
    }

  {
    bool ok = true;

    keyData = this->decrypted(keyData, &ok);

    if(!ok)
      keyData.clear();
  }

  if(keyData.isEmpty())
    {
      if(ok)
	*ok = false;

      spoton_misc::logError
	("spoton_crypt::initializePrivateKeyContainer(): "
	 "decrypted() failure.");
      goto done_label;
    }

  m_privateKeyLength = keyData.length();

  if((m_privateKey =
      static_cast<char *> (gcry_calloc_secure(m_privateKeyLength,
					      sizeof(char)))) == 0)
    {
      if(ok)
	*ok = false;

      m_privateKeyLength = 0;
      spoton_misc::logError
	("spoton_crypt::initializePrivateKeyContainer(): "
	 "gcry_calloc_secure() "
	 "failure.");
      goto done_label;
    }
  else
    memcpy(static_cast<void *> (m_privateKey),
	   static_cast<const void *> (keyData.constData()),
	   m_privateKeyLength);

  if(ok)
    *ok = true;

 done_label:
  return;
}

QByteArray spoton_crypt::publicKeyDecrypt(const QByteArray &data, bool *ok)
{
  /*
  ** We need to decipher the private key.
  */

  QByteArray decrypted;
  QByteArray random(64, 0); // Output size of SHA-512 divided by 8.
  QString keyType("");
  const char *buffer = 0;
  gcry_error_t err = 0;
  gcry_sexp_t data_t = 0;
  gcry_sexp_t decrypted_t = 0;
  gcry_sexp_t key_t = 0;
  gcry_sexp_t raw_t = 0;
  size_t length = 0;

  {
    bool ok = true;

    initializePrivateKeyContainer(&ok);
  }

  if(!m_privateKey || m_privateKeyLength == 0)
    {
      if(ok)
	*ok = false;

      goto done_label;
    }

  if((err = gcry_sexp_new(&key_t,
			  static_cast<const void *> (m_privateKey),
			  m_privateKeyLength, 1)) != 0 || !key_t)
    {
      if(ok)
	*ok = false;

      gcry_free(m_privateKey);
      m_privateKey = 0;
      m_privateKeyLength = 0;

      if(err != 0)
	{
	  QByteArray buffer(64, 0);

	  gpg_strerror_r(err, buffer.data(), buffer.length());
	  spoton_misc::logError
	    (QString("spoton_crypt::publicKeyDecrypt(): gcry_sexp_new() "
		     "failure (%1).").arg(buffer.constData()));
	}
      else
	spoton_misc::logError
	  ("spoton_crypt::publicKeyDecrypt(): gcry_sexp_new() failure.");

      goto done_label;
    }

  /*
  ** We once tested the private key via gcry_pk_testkey() here.
  */

  if((err = gcry_sexp_new(&data_t,
			  static_cast<const void *> (data.constData()),
			  static_cast<size_t> (data.length()),
			  1)) != 0 || !data_t)
    {
      if(ok)
	*ok = false;

      goto done_label;
    }

  raw_t = gcry_sexp_find_token(key_t, "elg", 0);

  if(raw_t)
    keyType = "elg";
  else
    {
      raw_t = gcry_sexp_find_token(key_t, "rsa", 0);

      if(raw_t)
	keyType = "rsa";
    }

  if(!raw_t)
    {
      if(ok)
	*ok = false;

      goto done_label;
    }

  gcry_sexp_release(raw_t);
  raw_t = gcry_sexp_find_token(data_t, keyType.toLatin1().constData(), 0);
  gcry_sexp_release(data_t);
  data_t = 0;

  if(!raw_t)
    {
      if(ok)
	*ok = false;

      goto done_label;
    }

  if(keyType == "elg")
    err = gcry_sexp_build(&data_t, 0,
			  "(enc-val (flags) %S)",
			  raw_t);
  else
    err = gcry_sexp_build(&data_t, 0,
			  "(enc-val (flags oaep)"
			  "(hash-algo sha512)(random-override %b) %S)",
			  random.length(),
			  random.constData(),
			  raw_t);

  if(err != 0 || !data_t)
    {
      if(ok)
	*ok = false;

      goto done_label;
    }

  if((err = gcry_pk_decrypt(&decrypted_t,
			    data_t, key_t)) != 0 || !decrypted_t)
    {
      if(ok)
	*ok = false;

      goto done_label;
    }

  buffer = gcry_sexp_nth_data(decrypted_t, 1, &length);

  if(!buffer)
    {
      if(ok)
	*ok = false;

      goto done_label;
    }

  decrypted = QByteArray(buffer, length);

  if(ok)
    *ok = true;

 done_label:
  gcry_sexp_release(data_t);
  gcry_sexp_release(decrypted_t);
  gcry_sexp_release(key_t);
  gcry_sexp_release(raw_t);
  return decrypted;
}

QByteArray spoton_crypt::publicKey(bool *ok)
{
  if(!m_publicKey.isEmpty())
    {
      if(ok)
	*ok = true;

      return m_publicKey;
    }

  /*
  ** Returns the correct public key from idiotes.db.
  */

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);
    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "idiotes.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);
	query.prepare("SELECT public_key FROM idiotes WHERE id = ?");
	query.bindValue(0, m_id);

	if(query.exec())
	  if(query.next())
	    m_publicKey = QByteArray::fromBase64
	      (query.value(0).toByteArray());
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  {
    bool ok = true;

    m_publicKey = decrypted(m_publicKey, &ok);
  }

  if(m_publicKey.isEmpty())
    {
      if(ok)
	*ok = false;

      spoton_misc::logError
	("spoton_crypt::publicKey(): decrypted() failure.");
    }
  else if(ok)
    *ok = true;

  return m_publicKey;
}

QByteArray spoton_crypt::publicKeyHash(bool *ok)
{
  QByteArray hash;

  {
    bool ok = true;

    publicKey(&ok);
  }

  if(m_publicKey.isEmpty())
    {
      if(ok)
	*ok = false;
    }
  else
    {
      {
	bool ok = true;

	hash = shaXHash(m_hashAlgorithm, m_publicKey, &ok);
      }
    }

  if(hash.isEmpty())
    if(ok)
      *ok = false;

  return hash;
}

void spoton_crypt::generatePrivatePublicKeys(const int keySize,
					     const QString &keyType,
					     QString &error)
{
  QByteArray privateKey;
  QByteArray publicKey;
  QString connectionName("");
  QString genkey("");
  char *buffer = 0;
  gcry_error_t err = 0;
  gcry_sexp_t key_t = 0;
  gcry_sexp_t keyPair_t = 0;
  gcry_sexp_t parameters_t = 0;
  size_t length = 0;

  gcry_free(m_privateKey);
  m_privateKey = 0;
  m_privateKeyLength = 0;

  if(keyType == "dsa")
    genkey = QString("(genkey (dsa (nbits %1:%2)))").
      arg(qFloor(log10(keySize)) + 1).
      arg(keySize);
  else if(keyType == "elg")
    genkey = QString("(genkey (elg (nbits %1:%2)))").
      arg(qFloor(log10(keySize)) + 1).
      arg(keySize);
  else
    genkey = QString("(genkey (rsa (nbits %1:%2)))").
      arg(qFloor(log10(keySize)) + 1).
      arg(keySize);

  if((err = gcry_sexp_build(&parameters_t, 0,
			    genkey.toLatin1().constData()) != 0) ||
     !parameters_t)
    {
      error = QObject::tr("gcry_sexp_build() failure");

      if(err != 0)
	{
	  QByteArray buffer(64, 0);

	  gpg_strerror_r(err, buffer.data(), buffer.length());
	  spoton_misc::logError
	    (QString("spoton_crypt::generatePrivatePublicKeys(): "
		     "gcry_sexp_build() "
		     "failure (%1).").arg(buffer.constData()));
	}
      else
	spoton_misc::logError
	  ("spoton_crypt::generatePrivatePublicKeys(): gcry_sexp_build() "
	   "failure.");

      goto done_label;
    }

  gcry_fast_random_poll();

  if((err = gcry_pk_genkey(&keyPair_t, parameters_t)) != 0 || !keyPair_t)
    {
      error = QObject::tr("gcry_pk_genkey() failure");

      if(err != 0)
	{
	  QByteArray buffer(64, 0);

	  gpg_strerror_r(err, buffer.data(), buffer.length());
	  spoton_misc::logError
	    (QString("spoton_crypt::generatePrivatePublicKeys(): "
		     "gcry_pk_genkey() "
		     "failure (%1).").arg(buffer.constData()));
	}
      else
	spoton_misc::logError
	  ("spoton_crypt::generatePrivatePublicKeys(): gcry_pk_genkey() "
	   "failure.");
      goto done_label;
    }

  for(int i = 1; i <= 2; i++)
    {
      if(i == 1)
	key_t = gcry_sexp_find_token(keyPair_t, "private-key", 0);
      else
	key_t = gcry_sexp_find_token(keyPair_t, "public-key", 0);

      if(!key_t)
	{
	  error = QObject::tr("gcry_sexp_find_token() failure");
	  spoton_misc::logError
	    ("spoton_crypt::generatePrivatePublicKeys(): "
	     "gcry_sexp_find_token() failure.");
	  goto done_label;
	}

      length = gcry_sexp_sprint(key_t, GCRYSEXP_FMT_ADVANCED, 0, 0);

      if(!length)
	{
	  error = QObject::tr("gcry_sexp_sprint() failure");
	  spoton_misc::logError
	    ("spoton_crypt::generatePrivatePublicKeys(): gcry_sexp_sprint() "
	     "failure.");
	  goto done_label;
	}
      else
	{
	  buffer = (char *) malloc(length);

	  if(buffer)
	    {
	      if(gcry_sexp_sprint(key_t, GCRYSEXP_FMT_ADVANCED,
				  buffer, length) == 0)
		{
		  error = QObject::tr("gcry_sexp_sprint() failure");
		  spoton_misc::logError
		    ("spoton_crypt::generatePrivatePublicKeys(): "
		     "gcry_sexp_sprint() "
		     "failure.");
		  goto done_label;
		}

	      if(i == 1)
		privateKey = QByteArray(buffer, length);
	      else
		publicKey = QByteArray(buffer, length);

	      free(buffer);
	      buffer = 0;
	    }
	  else
	    {
	      error = QObject::tr("malloc() failure");
	      spoton_misc::logError
		("spoton_crypt::generatePrivatePublicKeys(): "
		 "malloc() failure.");
	      goto done_label;
	    }
	}

      gcry_free(key_t);
      key_t = 0;
    }

  {
    QSqlDatabase db = spoton_misc::database(connectionName);
    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "idiotes.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	query.prepare
	  ("INSERT OR REPLACE INTO idiotes (id, private_key, public_key) "
	   "VALUES (?, ?, ?)");
	query.bindValue(0, m_id);

	if(!privateKey.isEmpty())
	  query.bindValue(1, encrypted(privateKey, &ok).toBase64());

	if(ok)
	  if(!publicKey.isEmpty())
	    query.bindValue(2, encrypted(publicKey, &ok).toBase64());

	if(ok)
	  {
	    if(!query.exec())
	      {
		error = QObject::tr("QSqlQuery::exec() failure");
		spoton_misc::logError
		  (QString("spoton_crypt::generatePrivatePublicKeys(): "
			   "QSqlQuery::exec() failure (%1).").
		   arg(query.lastError().text()));
	      }
	  }
	else
	  {
	    error = QObject::tr("encrypted() failure");
	    spoton_misc::logError
	      ("spoton_crypt::generatePrivatePublicKeys(): "
	       "encrypted() failure.");
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

 done_label:
  free(buffer);
  gcry_free(key_t);
  gcry_free(keyPair_t);
  gcry_free(parameters_t);
}

QByteArray spoton_crypt::keyedHash(const QByteArray &data,
				   const QByteArray &key,
				   const QByteArray &hashType,
				   bool *ok)
{
  QByteArray hash;
  gcry_error_t err = 0;
  gcry_md_hd_t hd;
  int hashAlgorithm = gcry_md_map_name(hashType.constData());

  if(hashAlgorithm == 0)
    {
      if(ok)
	*ok = false;

      return hash;
    }
  else if(key.isEmpty())
    {
      if(ok)
	*ok = false;

      return hash;
    }

  if((err = gcry_md_open(&hd, hashAlgorithm,
			 GCRY_MD_FLAG_HMAC)) != 0 || !hd)
    {
      if(ok)
	*ok = false;

      if(err != 0)
	{
	  QByteArray buffer(64, 0);

	  gpg_strerror_r(err, buffer.data(), buffer.length());
	  spoton_misc::logError
	    (QString("spoton_crypt::keyedHash(): gcry_md_open() "
		     "failure (%1).").
	     arg(buffer.constData()));
	}
      else
	spoton_misc::logError
	  ("spoton_crypt::keyedHash(): gcry_md_open() failure.");
    }
  else
    {
      if((err = gcry_md_setkey(hd,
			       static_cast<const void *> (key.constData()),
			       static_cast<size_t> (key.length()))) != 0)
	{
	  if(ok)
	    *ok = false;

	  QByteArray buffer(64, 0);

	  gpg_strerror_r(err, buffer.data(), buffer.length());
	  spoton_misc::logError
	    (QString("spoton_crypt::keyedHash(): gcry_md_setkey() "
		     "failure (%1).").arg(buffer.constData()));
	}
      else
	{
	  gcry_md_write
	    (hd,
	     static_cast<const void *> (data.constData()),
	     static_cast<size_t> (data.length()));

	  unsigned char *buffer = gcry_md_read(hd, hashAlgorithm);

	  if(buffer)
	    {
	      unsigned int length = gcry_md_get_algo_dlen(hashAlgorithm);

	      if(length > 0)
		{
		  hash.resize(length);
		  memcpy(static_cast<void *> (hash.data()),
			 static_cast<const void *> (buffer),
			 static_cast<size_t> (hash.length()));
		}
	      else
		{
		  if(ok)
		    *ok = false;

		  spoton_misc::logError
		    (QString("spoton_crypt::keyedHash(): "
			     "gcry_md_get_algo_dlen() "
			     "failure for %1.").arg(hashType.constData()));
		}
	    }
	  else
	    {
	      if(ok)
		*ok = false;

	      spoton_misc::logError("spoton_crypt::keyedHash(): "
				    "gcry_md_read() returned 0.");
	    }
	}
    }

  gcry_md_close(hd);
  return hash;
}

QByteArray spoton_crypt::randomCipherType(void)
{
  QStringList types(cipherTypes());

  if(!types.isEmpty())
    return types.value(qrand() % types.size()).toLatin1();
  else
    return QByteArray();
}

QByteArray spoton_crypt::digitalSignature(const QByteArray &data, bool *ok)
{
  /*
  ** We need to decipher the private key.
  */

  QByteArray hash(64, 0); // Output size of SHA-512 divided by 8.
  QByteArray keyData;
  QByteArray random(20, 0);
  QByteArray signature;
  QString keyType("");
  QString connectionName("");
  gcry_error_t err = 0;
  gcry_mpi_t hash_t = 0;
  gcry_sexp_t data_t = 0;
  gcry_sexp_t key_t = 0;
  gcry_sexp_t raw_t = 0;
  gcry_sexp_t signature_t = 0;
  unsigned char *hash_p = 0;

  {
    QSqlDatabase db = spoton_misc::database(connectionName);
    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "idiotes.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);
	query.prepare("SELECT private_key FROM idiotes WHERE id = ?");
	query.bindValue(0, m_id);

	if(query.exec())
	  if(query.next())
	    keyData = QByteArray::fromBase64
	      (query.value(0).toByteArray());
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(keyData.isEmpty())
    {
      if(ok)
	*ok = false;

      spoton_misc::logError
	("spoton_crypt::digitalSignature(): empty private key.");
      goto done_label;
    }

  {
    bool ok = true;

    keyData = decrypted(keyData, &ok);

    if(!ok)
      keyData.clear();
  }

  if(keyData.isEmpty())
    {
      if(ok)
	*ok = false;

      spoton_misc::logError
	("spoton_crypt::digitalSignature(): decrypted() failure.");
      goto done_label;
    }

  /*
  ** Now let's see if we have a somewhat valid private key.
  */

  if((err = gcry_sexp_new(&key_t,
			  static_cast<const void *> (keyData.constData()),
			  static_cast<size_t> (keyData.length()),
			  1)) != 0 || !key_t)
    {
      if(ok)
	*ok = false;

      if(err != 0)
	{
	  QByteArray buffer(64, 0);

	  gpg_strerror_r(err, buffer.data(), buffer.length());
	  spoton_misc::logError
	    (QString("spoton_crypt::digitalSignature(): gcry_sexp_new() "
		     "failure (%1).").arg(buffer.constData()));
	}
      else
	spoton_misc::logError
	  ("spoton_crypt::digitalSignature(): gcry_sexp_new() failure.");

      goto done_label;
    }

  if((err = gcry_pk_testkey(key_t)) != 0)
    {
      if(ok)
	*ok = false;

      QByteArray buffer(64, 0);

      gpg_strerror_r(err, buffer.data(), buffer.length());
      spoton_misc::logError
	(QString("spoton_crypt::digitalSignature(): gcry_pk_testkey() "
		 "failure (%1).").arg(buffer.constData()));
      goto done_label;
    }

  raw_t = gcry_sexp_find_token(key_t, "dsa", 0);

  if(raw_t)
    keyType = "dsa";
  else
    {
      raw_t = gcry_sexp_find_token(key_t, "elg", 0);

      if(raw_t)
	keyType = "elg";
      else
	{
	  raw_t = gcry_sexp_find_token(key_t, "rsa", 0);

	  if(raw_t)
	    keyType = "rsa";
	}
    }

  if(!raw_t)
    {
      if(ok)
	*ok = false;

      spoton_misc::logError
	("spoton_crypt::digitalSignature(): gcry_sexp_find_token() failure.");
      goto done_label;
    }

  gcry_md_hash_buffer
    (GCRY_MD_SHA512,
     static_cast<void *> (hash.data()),
     static_cast<const void *> (data.constData()),
     static_cast<size_t> (data.length()));

  if(keyType == "dsa" || keyType == "elg")
    {
      hash_p = (unsigned char *) malloc(hash.length());

      if(!hash_p)
	{
	  if(ok)
	    *ok = false;

	  spoton_misc::logError("spoton_crypt::digitalSignature(): "
				"malloc() failure.");
	  goto done_label;
	}
      else
	memcpy
	  (hash_p, (const unsigned char *) hash.constData(), hash.length());

      err = gcry_mpi_scan
	(&hash_t, GCRYMPI_FMT_USG, hash_p, hash.length(), 0);

      if(err != 0 || !hash_t)
	{
	  if(ok)
	    *ok = false;

	  if(err != 0)
	    {
	      QByteArray buffer(64, 0);

	      gpg_strerror_r(err, buffer.data(), buffer.length());
	      spoton_misc::logError
		(QString("spoton_crypt()::digitalSignature(): "
			 "gcry_mpi_scan() "
			 "failure (%1).").arg(buffer.constData()));
	    }
	  else
	    spoton_misc::logError
	      ("spoton_crypt()::digitalSignature(): "
	       "gcry_mpi_scan() "
	       "failure.");

	  goto done_label;
	}

      err = gcry_sexp_build(&data_t, 0,
			    "(data (flags raw) (value %m))",
			    hash_t);
    }
  else
    {
      random = strongRandomBytes(random.length());
      err = gcry_sexp_build(&data_t, 0,
			    "(data (flags pss)(hash sha512 %b)"
			    "(random-override %b))",
			    hash.length(),
			    hash.constData(),
			    random.length(),
			    random.constData());
    }

  if(err == 0 && data_t)
    {
      if((err = gcry_pk_sign(&signature_t, data_t,
			     key_t)) == 0 && signature_t)
	{
	  size_t length = gcry_sexp_sprint
	    (signature_t, GCRYSEXP_FMT_ADVANCED, 0, 0);

	  if(length)
	    {
	      char *buffer = (char *) malloc(length);

	      if(buffer)
		{
		  if(gcry_sexp_sprint(signature_t,
				      GCRYSEXP_FMT_ADVANCED,
				      static_cast<void *> (buffer),
				      length) != 0)
		    {
		      if(ok)
			*ok = true;

		      signature.append(QByteArray(buffer, length));
		    }
		  else
		    {
		      if(ok)
			*ok = false;

		      spoton_misc::logError
			("spoton_crypt()::digitalSignature(): "
			 "gcry_sexp_sprint() failure.");
		    }
		}
	      else
		{
		  if(ok)
		    *ok = false;

		  spoton_misc::logError
		    ("spoton_crypt()::digitalSignature(): malloc() "
		     "failure.");
		}

	      free(buffer);
	    }
	  else
	    {
	      if(ok)
		*ok = false;

	      spoton_misc::logError
		("spoton_crypt()::digitalSignature(): "
		 "gcry_sexp_sprint() failure.");
	    }
	}
      else
	{
	  if(ok)
	    *ok = false;

	  if(err != 0)
	    {
	      QByteArray buffer(64, 0);

	      gpg_strerror_r(err, buffer.data(), buffer.length());
	      spoton_misc::logError
		(QString("spoton_crypt()::digitalSignature(): "
			 "gcry_pk_sign() "
			 "failure (%1).").arg(buffer.constData()));
	    }
	  else
	    spoton_misc::logError
	      ("spoton_crypt()::digitalSignature(): gcry_pk_sign() "
	       "failure.");

	  goto done_label;
	}
    }
  else
    {
      if(ok)
	*ok = false;

      if(err != 0)
	{
	  QByteArray buffer(64, 0);

	  gpg_strerror_r(err, buffer.data(), buffer.length());
	  spoton_misc::logError
	    (QString("spoton_crypt()::digitalSignature(): "
		     "gcry_sexp_build() "
		     "failure (%1).").arg(buffer.constData()));
	}
      else
	spoton_misc::logError
	  ("spoton_crypt()::digitalSignature(): gcry_sexp_build() "
	   "failure.");

      goto done_label;
    }

 done_label:
  free(hash_p);
  gcry_mpi_release(hash_t);
  gcry_sexp_release(data_t);
  gcry_sexp_release(key_t);
  gcry_sexp_release(raw_t);
  gcry_sexp_release(signature_t);
  return signature;
}

QString spoton_crypt::cipherType(void) const
{
  return m_cipherType;
}

QByteArray spoton_crypt::strongRandomBytes(const size_t size)
{
  QByteArray random(size, 0);

  gcry_fast_random_poll();
  gcry_randomize(static_cast<void *> (random.data()),
		 static_cast<size_t> (random.length()),
		 GCRY_STRONG_RANDOM);
  return random;
}

QByteArray spoton_crypt::veryStrongRandomBytes(const size_t size)
{
  QByteArray random(size, 0);

  gcry_fast_random_poll();
  gcry_randomize(static_cast<void *> (random.data()),
		 static_cast<size_t> (random.length()),
		 GCRY_VERY_STRONG_RANDOM);
  return random;
}

size_t spoton_crypt::cipherKeyLength(const QByteArray &cipherType)
{
  int cipherAlgorithm = gcry_cipher_map_name(cipherType.constData());
  size_t keyLength = 0;

  if(cipherAlgorithm)
    {
      if((keyLength = gcry_cipher_get_algo_keylen(cipherAlgorithm)) == 0)
	spoton_misc::logError("spoton_crypt::cipherKeyLength(): "
			      "gcry_cipher_get_algo_keylen() returned "
			      "zero.");
    }
  else
    spoton_misc::logError("spoton_crypt::cipherKeyLength(): "
			  "gcry_cipher_map_name() failure.");

  return keyLength;
}

QByteArray spoton_crypt::weakRandomBytes(const size_t size)
{
  QByteArray random(size, 0);

  gcry_fast_random_poll();
  gcry_randomize(static_cast<void *> (random.data()),
		 static_cast<size_t> (random.length()),
		 GCRY_WEAK_RANDOM);
  return random;
}

bool spoton_crypt::isValidSignature(const QByteArray &data,
				    const QByteArray &publicKey,
				    const QByteArray &signature)
{
  QByteArray hash(64, 0); // Output size of SHA-512 divided by 8.
  QByteArray random(20, 0);
  QString keyType("");
  bool ok = true;
  gcry_error_t err = 0;
  gcry_mpi_t hash_t = 0;
  gcry_sexp_t data_t = 0;
  gcry_sexp_t key_t = 0;
  gcry_sexp_t raw_t = 0;
  gcry_sexp_t signature_t = 0;
  unsigned char *hash_p = 0;

  if(data.isEmpty() || publicKey.isEmpty() || signature.isEmpty())
    {
      ok = false;
      spoton_misc::logError
	("spoton_crypt::isValidSignature(): data, publicKey, or "
	 "signature is empty.");
      goto done_label;
    }

  if((err = gcry_sexp_new(&key_t,
			  static_cast<const void *> (publicKey.constData()),
			  static_cast<size_t> (publicKey.length()),
			  1)) != 0 || !key_t)
    {
      ok = false;

      if(err != 0)
	{
	  QByteArray buffer(64, 0);

	  gpg_strerror_r(err, buffer.data(), buffer.length());
	  spoton_misc::logError
	    (QString("spoton_crypt::isValidSignature(): gcry_sexp_new() "
		     "failure (%1).").arg(buffer.constData()));
	}
      else
	spoton_misc::logError
	  ("spoton_crypt::isValidSignature(): gcry_sexp_new() failure.");

      goto done_label;
    }

  if((err = gcry_sexp_new(&signature_t,
			  static_cast<const void *> (signature.constData()),
			  static_cast<size_t> (signature.length()),
			  1)) != 0 || !signature_t)
    {
      ok = false;

      if(err != 0)
	{
	  QByteArray buffer(64, 0);

	  gpg_strerror_r(err, buffer.data(), buffer.length());
	  spoton_misc::logError
	    (QString("spoton_crypt()::isValidSignature(): "
		     "gcry_sexp_new() "
		     "failure (%1).").arg(buffer.constData()));
	}
      else
	spoton_misc::logError
	  ("spoton_crypt()::isValidSignature(): gcry_sexp_new() "
	   "failure.");

      goto done_label;
    }

  raw_t = gcry_sexp_find_token(key_t, "dsa", 0);

  if(raw_t)
    keyType = "dsa";
  else
    {
      raw_t = gcry_sexp_find_token(key_t, "elg", 0);

      if(raw_t)
	keyType = "elg";
      else
	{
	  raw_t = gcry_sexp_find_token(key_t, "rsa", 0);

	  if(raw_t)
	    keyType = "rsa";
	}
    }

  if(!raw_t)
    {
      ok = false;
      spoton_misc::logError
	("spoton_crypt()::isValidSignature(): gcry_sexp_find_token() "
	 "failure.");
      goto done_label;
    }

  gcry_md_hash_buffer
    (GCRY_MD_SHA512,
     static_cast<void *> (hash.data()),
     static_cast<const void *> (data.constData()),
     static_cast<size_t> (data.length()));

  if(keyType == "dsa" || keyType == "elg")
    {
      hash_p = (unsigned char *) malloc(hash.length());

      if(!hash_p)
	{
	  ok = false;
	  spoton_misc::logError("spoton_crypt::isValidSignature(): "
				"malloc() failure.");
	  goto done_label;
	}
      else
	memcpy
	  (hash_p, (const unsigned char *) hash.constData(), hash.length());

      err = gcry_mpi_scan
	(&hash_t, GCRYMPI_FMT_USG, hash_p, hash.length(), 0);

      if(err != 0 || !hash_t)
	{
	  ok = false;

	  if(err != 0)
	    {
	      QByteArray buffer(64, 0);

	      gpg_strerror_r(err, buffer.data(), buffer.length());
	      spoton_misc::logError
		(QString("spoton_crypt()::isValidSignature(): "
			 "gcry_mpi_scan() "
			 "failure (%1).").arg(buffer.constData()));
	    }
	  else
	    spoton_misc::logError
	      ("spoton_crypt()::isValidSignature(): "
	       "gcry_mpi_scan() "
	       "failure.");

	  goto done_label;
	}

      err = gcry_sexp_build(&data_t, 0,
			    "(data (flags raw) (value %m))",
			    hash_t);
    }
  else
    err = gcry_sexp_build(&data_t, 0,
			  "(data (flags pss)(hash sha512 %b)"
			  "(random-override %b))",
			  hash.length(),
			  hash.constData(),
			  random.length(),
			  random.constData());

  if(err != 0 || !data_t)
    {
      ok = false;

      if(err != 0)
	{
	  QByteArray buffer(64, 0);

	  gpg_strerror_r(err, buffer.data(), buffer.length());
	  spoton_misc::logError
	    (QString("spoton_crypt()::isValidSignature(): "
		     "gcry_sexp_build() "
		     "failure (%1).").arg(buffer.constData()));
	}
      else
	spoton_misc::logError
	  ("spoton_crypt()::isValidSignature(): gcry_sexp_build() "
	   "failure.");

      goto done_label;
    }

  if((err = gcry_pk_verify(signature_t, data_t, key_t)) != 0)
    {
      ok = false;

      QByteArray buffer(64, 0);

      gpg_strerror_r(err, buffer.data(), buffer.length());
      spoton_misc::logError
	(QString("spoton_crypt()::isValidSignature(): "
		 "gcry_pk_verify() "
		 "failure (%1).").arg(buffer.constData()));
    }

 done_label:
  free(hash_p);
  gcry_mpi_release(hash_t);
  gcry_sexp_release(data_t);
  gcry_sexp_release(key_t);
  gcry_sexp_release(raw_t);
  gcry_sexp_release(signature_t);
  return ok;
}

void spoton_crypt::generateSslKeys(const int rsaKeySize,
				   QByteArray &certificate,
				   QByteArray &privateKey,
				   QByteArray &publicKey,
				   const QHostAddress &address,
				   const long days,
				   QString &error)
{
  BIGNUM *f4 = 0;
  BIO *privateMemory = 0;
  BIO *publicMemory = 0;
  BUF_MEM *bptr;
  RSA *rsa = 0;
  char *privateBuffer = 0;
  char *publicBuffer = 0;

  if(!(f4 = BN_new()))
    {
      error = QObject::tr("BN_new() returned zero");
      spoton_misc::logError("spoton_crypt::generateSslKeys(): "
			    "BN_new() failure.");
      goto done_label;
    }

  if(BN_set_word(f4, RSA_F4) != 1)
    {
      error = QObject::tr("BN_set_word() returned zero");
      spoton_misc::logError("spoton_crypt::generateSslKeys(): "
			    "BN_set_word() failure.");
      goto done_label;
    }

  if(!(rsa = RSA_new()))
    {
      error = QObject::tr("RSA_new() returned zero");
      spoton_misc::logError("spoton_crypt::generateSslKeys(): "
			    "RSA_new() failure.");
      goto done_label;
    }

  if(RSA_generate_key_ex(rsa, rsaKeySize, f4, 0) == -1)
    {
      error = QObject::tr("RSA_generate_key_ex() returned negative one");
      spoton_misc::logError("spoton_crypt::generateSslKeys(): "
			    "RSA_generate_key_ex() failure.");
      goto done_label;
    }

  if(!(privateMemory = BIO_new(BIO_s_mem())))
    {
      error = QObject::tr("BIO_new() returned zero");
      spoton_misc::logError("spoton_crypt::generateSslKeys(): "
			    "BIO_new() failure.");
      goto done_label;
    }

  if(!(publicMemory = BIO_new(BIO_s_mem())))
    {
      error = QObject::tr("BIO_new() returned zero");
      spoton_misc::logError("spoton_crypt::generateSslKeys(): "
			    "BIO_new() failure.");
      goto done_label;
    }

  if(PEM_write_bio_RSAPrivateKey(privateMemory, rsa, 0, 0, 0, 0, 0) == 0)
    {
      error = QObject::tr("PEM_write_bio_RSAPrivateKey() returned zero");
      spoton_misc::logError("spoton_crypt::generateSslKeys(): "
			    "PEM_write_bio_RSAPrivateKey() failure.");
      goto done_label;
    }

  if(PEM_write_bio_RSAPublicKey(publicMemory, rsa) == 0)
    {
      error = QObject::tr("PEM_write_bio_RSAPublicKey() returned zero");
      spoton_misc::logError("spoton_crypt::generateSslKeys(): "
			    "PEM_write_bio_RSAPublicKey() failure.");
      goto done_label;
    }

  BIO_get_mem_ptr(privateMemory, &bptr);

  if(!(privateBuffer = (char *) calloc(bptr->length + 1, sizeof(char))))
    {
      error = QObject::tr("calloc() returned zero");
      spoton_misc::logError("spoton_crypt::generateSslKeys(): "
			    "calloc() failure.");
      goto done_label;
    }

  memcpy(static_cast<void *> (privateBuffer),
	 static_cast<const void *> (bptr->data), bptr->length);
  privateBuffer[bptr->length] = 0;
  privateKey = privateBuffer;
  BIO_get_mem_ptr(publicMemory, &bptr);

  if(!(publicBuffer = (char *) calloc(bptr->length + 1, sizeof(char))))
    {
      error = QObject::tr("calloc() returned zero");
      spoton_misc::logError("spoton_crypt::generateSslKeys(): "
			    "calloc() failure.");
      goto done_label;
    }

  memcpy(static_cast<void *> (publicBuffer),
	 static_cast<const void *> (bptr->data), bptr->length);
  publicBuffer[bptr->length] = 0;
  publicKey = publicBuffer;
  generateCertificate(rsa, certificate, address, days, error);

 done_label:
  BIO_free(privateMemory);
  BIO_free(publicMemory);
  BN_free(f4);
  RSA_free(rsa);
  free(privateBuffer);
  free(publicBuffer);
}

void spoton_crypt::purgeDatabases(void)
{
  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);
    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "idiotes.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("DELETE FROM idiotes");
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_crypt::generateCertificate(RSA *rsa,
				       QByteArray &certificate,
				       const QHostAddress &address,
				       const long days,
				       QString &error)
{
  BIO *memory = 0;
  BUF_MEM *bptr;
  EVP_PKEY *pk = 0;
  X509 *x509 = 0;
  X509_NAME *name = 0;
  X509_NAME *subject = 0;
  X509_NAME_ENTRY *commonNameEntry = 0;
  char *buffer = 0;
  int length = 0;
  unsigned char *commonName = 0;

  if(!error.isEmpty())
    goto done_label;

  if(!rsa)
    {
      error = QObject::tr("rsa container is zero");
      spoton_misc::logError("spoton_crypt::generateCertificate(): "
			    "rsa container is zero.");
      goto done_label;
    }

  if(!(pk = EVP_PKEY_new()))
    {
      error = QObject::tr("EVP_PKEY_new() failure");
      spoton_misc::logError
	("spoton_crypt::generateCertificate(): "
	 "EVP_PKEY_new() failure.");
      goto done_label;
    }

  if(!(x509 = X509_new()))
    {
      error = QObject::tr("X509_new() failure");
      spoton_misc::logError
	("spoton_crypt::generateCertificate(): "
	 "X509_new() failure.");
      goto done_label;
    }

  if(EVP_PKEY_assign_RSA(pk, rsa) == 0)
    {
      error = QObject::tr("EVP_PKEY_assign_RSA() returned zero");
      spoton_misc::logError("spoton_crypt::generateCertificate(): "
			    "EVP_PKEY_assign_RSA() failure.");
      goto done_label;
    }

  /*
  ** Set some attributes.
  */

  if(X509_set_version(x509, 3) == 0)
    {
      error = QObject::tr("X509_set_version() returned zero");
      spoton_misc::logError("spoton_crypt::generateCertificate(): "
			    "X509_set_version() failure.");
      goto done_label;
    }

  if(X509_gmtime_adj(X509_get_notBefore(x509), 0) == 0)
    {
      error = QObject::tr("X509_gmtime_adj() returned zero");
      spoton_misc::logError("spoton_crypt::generateCertificate(): "
			    "X509_gmtime_adj() failure.");
      goto done_label;
    }

  if(X509_gmtime_adj(X509_get_notAfter(x509), days) == 0)
    {
      error = QObject::tr("X509_gmtime_adj() returned zero");
      spoton_misc::logError("spoton_crypt::generateCertificate(): "
			    "X509_gmtime_adj() failure.");
      goto done_label;
    }

  commonName = (unsigned char *)
    calloc(address.toString().length() + 1,
	   sizeof(unsigned char));

  if(!commonName)
    {
      error = QObject::tr("calloc() returned zero");
      spoton_misc::logError("spoton_crypt::generateCertificate(): "
			    "calloc() failure.");
      goto done_label;
    }

  length = address.toString().length();
  memcpy(static_cast<void *> (commonName),
	 static_cast<const void *> (address.toString().toLatin1().
				    constData()),
	 length);
  commonNameEntry = X509_NAME_ENTRY_create_by_NID
    (0,
     NID_commonName, V_ASN1_PRINTABLESTRING,
     commonName, length);

  if(!commonNameEntry)
    {
      error = QObject::tr("X509_NAME_ENTRY_create_by_NID() returned zero");
      spoton_misc::logError("spoton_crypt::generateCertificate(): "
			    "X509_NAME_ENTRY_create_by_NID() failure.");
      goto done_label;
    }

  subject = X509_NAME_new();

  if(!subject)
    {
      error = QObject::tr("X509_NAME_new() returned zero");
      spoton_misc::logError("spoton_crypt::generateCertificate(): "
			    "X509_NAME_new() failure.");
      goto done_label;
    }

  if(X509_NAME_add_entry(subject, commonNameEntry, -1, 0) != 1)
    {
      error = QObject::tr("X509_NAME_add_entry() returned zero");
      spoton_misc::logError("spoton_crypt::generateCertificate(): "
			    "X509_NAME_add_entry() failure.");
      goto done_label;
    }

  if(X509_set_subject_name(x509, subject) != 1)
    {
      error = QObject::tr("X509_set_subject_name() returned zero");
      spoton_misc::logError("spoton_crypt::generateCertificate(): "
			    "X509_set_subject_name() failure.");
      goto done_label;
    }

  name = X509_get_subject_name(x509);

  if(X509_set_issuer_name(x509, name) == 0)
    {
      error = QObject::tr("X509_set_issuer_name() returned zero");
      spoton_misc::logError("spoton_crypt::generateCertificate(): "
			    "X509_set_issuer_name() failure.");
      goto done_label;
    }

  if(X509_set_pubkey(x509, pk) == 0)
    {
      error = QObject::tr("X509_set_pubkey() returned zero");
      spoton_misc::logError("spoton_crypt::generateCertificate(): "
			    "X509_set_pubkey() failure.");
      goto done_label;
    }

  if(X509_sign(x509, pk, EVP_sha512()) == 0)
    {
      error = QObject::tr("X509_sign() returned zero");
      spoton_misc::logError("spoton_crypt::generateCertificate(): "
			    "X509_sign() failure.");
      goto done_label;
    }

  /*
  ** Write the certificate to memory.
  */

  if(!(memory = BIO_new(BIO_s_mem())))
    {
      error = QObject::tr("BIO_new() returned zero");
      spoton_misc::logError("spoton_crypt::generateCertificate(): "
			    "BIO_new() failure.");
      goto done_label;
    }

  if(PEM_write_bio_X509(memory, x509) == 0)
    {
      error = QObject::tr("PEM_write_bio_X509() returned zero");
      spoton_misc::logError("spoton_crypt::generateCertificate(): "
			    "PEM_write_bio_X509() failure.");
      goto done_label;
    }

  BIO_get_mem_ptr(memory, &bptr);

  if(!(buffer = (char *) calloc(bptr->length + 1, sizeof(char))))
    {
      error = QObject::tr("calloc() returned zero");
      spoton_misc::logError("spoton_crypt::generateCertificate(): "
			    "calloc() failure.");
      goto done_label;
    }

  memcpy(buffer, bptr->data, bptr->length);
  buffer[bptr->length] = 0;
  certificate = buffer;

 done_label:
  BIO_free(memory);
  RSA_up_ref(rsa); // Reference counter.
  EVP_PKEY_free(pk);
  X509_NAME_ENTRY_free(commonNameEntry);
  X509_NAME_free(subject);
  X509_free(x509);
  free(buffer);
  free(commonName);
}

QList<QSslCipher> spoton_crypt::defaultSslCiphers(const QString &scs)
{
  /*
  ** Retrieve OpenSSL ciphers:
  ** "HIGH:!aNULL:!eNULL:!3DES:!EXPORT:@STRENGTH"
  */

  QList<QSslCipher> list;
  QSettings settings;
  QString controlString(scs);
  SSL *ssl = 0;
  SSL_CTX *ctx = 0;
  const char *next = 0;
  int index = 0;

  if(controlString.isEmpty())
    controlString = settings.value
      ("gui/sslControlString",
       "HIGH:!aNULL:!eNULL:!3DES:!EXPORT:@STRENGTH").toString();

  for(int i = 1; i <= 4; i++)
    {
      index = 0;
      next = 0;

      if(i == 1)
	{
#ifdef TLS1_2_VERSION
	  if(!(ctx = SSL_CTX_new(TLSv1_2_method())))
	    {
	      spoton_misc::logError("spoton_crypt::defaultSslCiphers(): "
				    "SSL_CTX_new() failure.");
	      goto done_label;
	    }
#endif
	}
      else if(i == 2)
	{
#ifdef TLS1_1_VERSION
	  if(!(ctx = SSL_CTX_new(TLSv1_1_method())))
	    {
	      spoton_misc::logError("spoton_crypt::defaultSslCiphers(): "
				    "SSL_CTX_new() failure.");
	      goto done_label;
	    }
#endif
	}
      else if(i == 3)
	{
	  if(!(ctx = SSL_CTX_new(TLSv1_method())))
	    {
	      spoton_misc::logError("spoton_crypt::defaultSslCiphers(): "
				    "SSL_CTX_new() failure.");
	      goto done_label;
	    }
	}
      else
	{
	  if(!(ctx = SSL_CTX_new(SSLv3_method())))
	    {
	      spoton_misc::logError("spoton_crypt::defaultSslCiphers(): "
				    "SSL_CTX_new() failure.");
	      goto done_label;
	    }
	}

      if(!ctx)
	continue;

      if(SSL_CTX_set_cipher_list(ctx,
				 controlString.toLatin1().constData()) == 0)
	{
	  spoton_misc::logError("spoton_crypt::defaultSslCiphers(): "
				"SSL_CTX_set_cipher_list() failure.");
	  goto done_label;
	}

      if(!(ssl = SSL_new(ctx)))
	{
	  spoton_misc::logError("spoton_crypt::defaultSslCiphers(): "
				"SSL_new() failure.");
	  goto done_label;
	}

      do
	{
	  if((next = SSL_get_cipher_list(ssl, index)))
	    {
	      if(i <= 3)
		{
		  QSslCipher cipher(next, QSsl::UnknownProtocol);

		  if(!cipher.isNull())
		    list.append(cipher);
		}
	      else
		{
		  QSslCipher cipher(next, QSsl::SslV3);

		  if(!cipher.isNull())
		    list.append(cipher);
		}
	    }

	  index += 1;
	}
      while(next);

    done_label:
      SSL_CTX_free(ctx);
      SSL_free(ssl);
      ctx = 0;
      ssl = 0;
    }

  if(list.isEmpty())
    spoton_misc::logError("spoton_crypt::defaultSslCiphers(): "
			  "empty cipher list.");

  return list;
}

void spoton_crypt::setSslCiphers(const QList<QSslCipher> &ciphers,
				 QSslConfiguration &configuration)
{
  QList<QSslCipher> preferred(defaultSslCiphers());

  for(int i = preferred.size() - 1; i >= 0; i--)
    if(!ciphers.contains(preferred.at(i)))
      preferred.removeAt(i);

  if(preferred.isEmpty())
    configuration.setCiphers(ciphers);
  else
    configuration.setCiphers(preferred);
}

QByteArray spoton_crypt::sha1FileHash(const QString &fileName)
{
  QByteArray buffer(4096, 0);
  QCryptographicHash hash(QCryptographicHash::Sha1);
  QFile file(fileName);
  qint64 rc = 0;

  if(file.open(QIODevice::ReadOnly))
    while((rc = file.read(buffer.data(), buffer.length())) > 0)
      hash.addData(buffer, rc);

  file.close();
  return hash.result();
}

void spoton_crypt::setHashKey(const QByteArray &hashKey)
{
  gcry_free(m_hashKey);
  m_hashKey = 0;
  m_hashKeyLength = hashKey.length();

  if((m_hashKey =
      static_cast<char *> (gcry_calloc_secure(m_hashKeyLength,
					      sizeof(char)))) != 0)
    memcpy(static_cast<void *> (m_hashKey),
	   static_cast<const void *> (hashKey.constData()),
	   m_hashKeyLength);
  else
    m_hashKeyLength = 0;
}

QByteArray spoton_crypt::hashKey(void) const
{
  if(m_hashKey)
    return QByteArray(m_hashKey, m_hashKeyLength);
  else
    return QByteArray();
}
