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

#include <QDir>
#include <QSettings>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QtCore/qmath.h>
#include <QtDebug>

#include "spot-on-gcrypt.h"
#include "spot-on-misc.h"

extern "C"
{
#if defined(PTHREAD_H) || defined(_PTHREAD_H) || defined(_PTHREAD_H_)
  GCRY_THREAD_OPTION_PTHREAD_IMPL;
#endif

#include "LibSpotOn/libspoton.h"
}

#if !(defined(PTHREAD_H) || defined(_PTHREAD_H) || defined(_PTHREAD_H_))
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
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
  };
#endif

void spoton_gcrypt::init(void)
{
  if(!gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P))
    {
#if defined(PTHREAD_H) || defined(_PTHREAD_H) || defined(_PTHREAD_H_)
      gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread, 0);
#else
      gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_qt, 0);
#endif

      if(!gcry_check_version(GCRYPT_VERSION))
	spoton_misc::logError
	  ("spoton_gcrypt::init(): gcry_check_version() "
	   "failure. Perhaps you should verify some "
	   "settings.");
      else
	{
	  gcry_error_t err = 0;

	  gcry_control(GCRYCTL_ENABLE_M_GUARD);
	  gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);

	  if((err = gcry_control(GCRYCTL_INIT_SECMEM, 65536, 0)) != 0)
	    spoton_misc::logError
	      (QString("spoton_gcrypt::init(): initializing "
		       "secure memory failure (%1).").
	       arg(gcry_strerror(err)));

	  gcry_control(GCRYCTL_RESUME_SECMEM_WARN);

	  if(err == 0)
	    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
	}
    }
  else
    {
    }
}

QByteArray spoton_gcrypt::derivedKey(const QString &cipherType,
				     const QString &hashType,
				     const unsigned long iterationCount,
				     const QString &passphrase,
				     const QByteArray &salt,
				     QString &error)
{
  init();

#if SPOTON_MINIMUM_GCRYPT_VERSION >= 0x010500
  QByteArray derivedKey;
  char *key = 0;
  gcry_error_t err = 0;
  int cipherAlgorithm = gcry_cipher_map_name(cipherType.toLatin1().
					     constData());
  int hashAlgorithm = gcry_md_map_name(hashType.toLatin1().constData());
  size_t keyLength = 0;

  if(gcry_cipher_test_algo(cipherAlgorithm) != 0)
    {
      error = QObject::tr("gcry_cipher_test_algo() returned non-zero");
      spoton_misc::logError
	(QString("spoton_gcrypt::derivedKey(): gcry_cipher_test_algo() "
		 "failure for %1.").arg(cipherType));
      goto error_label;
    }

  if(gcry_md_test_algo(hashAlgorithm) != 0)
    {
      error = QObject::tr("gcry_md_test_algo() returned non-zero");
      spoton_misc::logError
	(QString("spoton_gcrypt::derivedKey(): gcry_md_test_algo() "
		 "failure for %1.").arg(hashType));
      goto error_label;
    }

  if((keyLength = gcry_cipher_get_algo_keylen(cipherAlgorithm)) == 0)
    {
      error = QObject::tr("gcry_cipher_get_algo_keylen() returned zero");
      spoton_misc::logError
	(QString("spoton_gcrypt::derivedKey(): "
		 "gcry_cipher_get_algo_keylen() "
		 "failure for %1.").arg(cipherType));
      goto error_label;
    }

  if((key = static_cast<char *> (gcry_calloc_secure(keyLength,
						    sizeof(char)))) == 0)
    {
      error = QObject::tr("gcry_calloc_secure() returned zero");
      spoton_misc::logError
	("spoton_gcrypt::derivedKey(): gcry_calloc_secure() "
	 "failure.");
      goto error_label;
    }

  if((err = gcry_kdf_derive(static_cast<const void *> (passphrase.toUtf8().
						       constData()),
			    static_cast<size_t> (passphrase.toUtf8().
						 length()),
			    GCRY_KDF_PBKDF2,
			    hashAlgorithm,
			    static_cast<const void *> (salt.constData()),
			    static_cast<size_t> (salt.length()),
			    iterationCount,
			    keyLength,
			    static_cast<void *> (key))) == 0)
    derivedKey.append(key, keyLength);
  else
    {
      error = QObject::tr("gcry_kdf_derive() returned non-zero");
      spoton_misc::logError
	(QString("spoton_gcrypt::derivedKey(): gcry_kdf_derive() returned "
		 "non-zero (%1).").arg(gcry_strerror(err)));
      goto error_label;
    }

 error_label:
  gcry_free(key);
  return derivedKey;
#else
  Q_UNUSED(cipherType);
  Q_UNUSED(iterationCount);
  Q_UNUSED(salt);

  /*
  ** Retain the passphrase's hash. We'll use the hash as the key.
  ** We should really abandon old gcrypts.
  */

  QByteArray derivedKey;
  int hashAlgorithm = gcry_md_map_name(hashType.toLatin1().constData());
  unsigned int length = gcry_md_get_algo_dlen(hashAlgorithm);

  if(length == 0)
    {
      error = QObject::tr("gcry_md_get_algo_dlen() returned zero");
      spoton_misc::logError
	(QString("spoton_gcrypt::derivedKey(): gcry_md_get_algo_dlen() "
		 "returned zero for %1.").arg(hashType));
      goto error_label;
    }

  derivedKey.resize(length);
  gcry_md_hash_buffer(hashAlgorithm, static_cast<void *> (derivedKey.data()),
		      static_cast<const void *> (passphrase.toUtf8().
						 constData()),
		      static_cast<size_t> (passphrase.toUtf8().length()));
 error_label:
  return derivedKey;
#endif
}

QByteArray spoton_gcrypt::saltedPassphraseHash(const QString &hashType,
					       const QString &passphrase,
					       const QByteArray &salt,
					       QString &error)
{
  init();

  QByteArray saltedPassphraseHash;
  QString saltedPassphrase;
  int hashAlgorithm = gcry_md_map_name(hashType.toLatin1().constData());
  unsigned int length = gcry_md_get_algo_dlen(hashAlgorithm);

  if(length == 0)
    {
      error = QObject::tr("gcry_md_get_algo_dlen() returned zero");
      spoton_misc::logError
	(QString("spoton_gcrypt::saltedPassphraseHash(): "
		 "gcry_md_get_algo_dlen() "
		 "returned zero for %1.").arg(hashType));
      goto error_label;
    }

  saltedPassphrase.append(passphrase).append(salt);
  saltedPassphraseHash.resize(length);
  gcry_md_hash_buffer(hashAlgorithm,
		      static_cast<void *> (saltedPassphraseHash.data()),
		      static_cast<const void *> (saltedPassphrase.
						 toUtf8().constData()),
		      static_cast<size_t> (saltedPassphrase.toUtf8().
					   length()));
 error_label:
  return saltedPassphraseHash;
}

QStringList spoton_gcrypt::cipherTypes(void)
{
  init();

  QStringList types;

  types << "aes256"
	<< "camellia256"
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

QStringList spoton_gcrypt::hashTypes(void)
{
  init();

  QStringList types;

  types << "sha512"
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

bool spoton_gcrypt::passphraseSet(void)
{
  QSettings settings;

  return settings.contains("gui/saltedPassphraseHash") &&
    !settings.value("gui/saltedPassphraseHash",
		    "").toString().trimmed().isEmpty();
}

void spoton_gcrypt::reencodePrivateKey(const QString &newCipher,
				       const QByteArray &newPassphrase,
				       const QString &oldCipher,
				       const char *oldPassphrase,
				       const QString &id,
				       QString &error)
{
  init();

  if(!oldPassphrase)
    {
      error = QObject::tr("oldPassphrase is 0");
      spoton_misc::logError("spoton_gcrypt::reencodePrivateKey(): "
			    "oldPassphrase is 0.");
      return;
    }

  QByteArray data;

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton_gcrypt");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "idiotes.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);
	query.prepare("SELECT private_key FROM idiotes WHERE id = ?");
	query.bindValue(0, id);

	if(query.exec())
	  if(query.next())
	    data = QByteArray::fromBase64
	      (query.value(0).toByteArray());
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton_gcrypt");

  if(data.isEmpty())
    {
      error = QObject::tr("error retrieving private_key from the idiotes "
			  "table");
      spoton_misc::logError("spoton_gcrypt::reencodePrivateKey(): "
			    "error retrieving private_key from the idiotes "
			    "table.");
      return;
    }

  QByteArray encryptedData;
  QByteArray originalLength;
  QDataStream out(&originalLength, QIODevice::WriteOnly);
  char *iv = 0;
  gcry_cipher_hd_t cipherHandle = 0;
  gcry_error_t err = 0;
  gcry_sexp_t key_t = 0;
  int algorithm = gcry_cipher_map_name(oldCipher.toLatin1().constData());
  size_t blockLength = 0;
  size_t ivLength = 0;
  size_t keyLength = 0;

  if((err = gcry_cipher_open(&cipherHandle, algorithm,
			     GCRY_CIPHER_MODE_CBC,
			     GCRY_CIPHER_SECURE |
			     GCRY_CIPHER_CBC_CTS)) != 0 || !cipherHandle)
    {
      if(err != 0)
	{
	  error = QObject::tr("gcry_cipher_open() returned non-zero");
	  spoton_misc::logError
	    (QString("spoton_gcrypt::reencodePrivateKey(): "
		     "gcry_cipher_open() "
		     "failure (%1).").arg(gcry_strerror(err)));
	}
      else
	{
	  error = QObject::tr("gcry_cipher_open() failure");
	  spoton_misc::logError
	    ("spoton_gcrypt::reencodePrivateKey(): gcry_cipher_open() "
	     "failure.");
	}

      goto error_label;
    }

  if((ivLength = gcry_cipher_get_algo_blklen(algorithm)) == 0)
    {
      error = QObject::tr("gcry_cipher_get_algo_blklen() returned zero");
      spoton_misc::logError
	(QString("spoton_gcrypt::reencodePrivateKey(): "
		 "gcry_cipher_get_algo_blklen() "
		 "failure for %1.").arg(oldCipher));
      goto error_label;
    }

  if((err = gcry_cipher_setiv(cipherHandle,
			      static_cast<const void *> (data.
							 mid(0, ivLength).
							 constData()),
			      ivLength)) != 0)
    {
      error = QObject::tr("gcry_cipher_setiv() returned non-zero");
      spoton_misc::logError(QString("spoton_gcrypt::reencodePrivateKey(): "
				    "gcry_cipher_setiv() failure (%1).").
			    arg(gcry_strerror(err)));
      goto error_label;
    }
  else
    data.remove(0, ivLength);

  if((keyLength = gcry_cipher_get_algo_keylen(algorithm)) == 0)
    {
      error = QObject::tr("gcry_cipher_get_algo_keylen() returned zero");
      spoton_misc::logError
	(QString("spoton_gcrypt::reencodePrivateKey(): "
		 "gcry_cipher_get_algo_keylen() "
		 "failure for %1.").arg(oldCipher));
      goto error_label;
    }

  if((err = gcry_cipher_setkey(cipherHandle,
			       static_cast<const void *> (oldPassphrase),
			       keyLength)) != 0)
    {
      error = QObject::tr("gcry_cipher_setkey() returned non-zero");
      spoton_misc::logError
	(QString("spoton_gcrypt::reencodePrivateKey(): gcry_cipher_setkey() "
		 "failure (%1).").arg(gcry_strerror(err)));
      goto error_label;
    }

  if((err = gcry_cipher_decrypt(cipherHandle,
				static_cast<void *> (data.data()),
				static_cast<size_t> (data.length()),
				static_cast<const void *> (0),
				static_cast<size_t> (0))) == 0)
    {
      int s = 0;
      QByteArray originalLength(data.mid(data.length() - 4, 4));
      QDataStream in(&originalLength, QIODevice::ReadOnly);

      in >> s;

      if(s >= 0 && s <= data.length())
	data = data.mid(0, s);
      else
	{
	  error = QObject::tr("rhe length of the decrypted data is "
			      "irregular");
	  spoton_misc::logError
	    (QString("spoton_gcrypt::reencodePrivateKey(): The length (%1) "
		     "of the "
		     "decrypted data is irregular.").arg(s));
	  goto error_label;
	}
    }
  else
    {
      error = QObject::tr("gcry_cipher_decrypt() returned non-zero");
      spoton_misc::logError
	(QString("spoton_gcrypt::reencodePrivateKey(): "
		 "gcry_cipher_decrypt() "
		 "failure (%1).").arg(gcry_strerror(err)));
      goto error_label;
    }

  /*
  ** Now let's see if we have a somewhat valid private key.
  */

  if((err = gcry_sexp_new(&key_t,
			  static_cast<const void *> (data.constData()),
			  static_cast<size_t> (data.length()),
			  1)) != 0 || !key_t)
    {
      if(err != 0)
	{
	  error = QObject::tr("gcry_sexp_new() returned non-zero");
	  spoton_misc::logError
	    (QString("spoton_gcrypt::reencodePrivateKey(): gcry_sexp_new() "
		     "failure (%1).").arg(gcry_strerror(err)));
	}
      else
	{
	  error = QObject::tr("gcry_sexp_new() failure");
	  spoton_misc::logError
	    ("spoton_gcrypt::reencodePrivateKey(): gcry_sexp_new() "
	     "failure.");
	}

      goto error_label;
    }

  if((err = gcry_pk_testkey(key_t)) != 0)
    {
      error = QObject::tr("gcry_pk_testkey() returned non-zero");
      spoton_misc::logError
	(QString("spoton_gcrypt::reencodePrivateKey(): gcry_pk_testkey() "
		 "failure (%1).").arg(gcry_strerror(err)));
      goto error_label;
    }

  gcry_sexp_release(key_t);
  key_t = 0;
  gcry_cipher_reset(cipherHandle);
  algorithm = gcry_cipher_map_name(newCipher.toLatin1().constData());

  if((blockLength = gcry_cipher_get_algo_blklen(algorithm)) == 0)
    {
      error = QObject::tr("gcry_cipher_get_algo_blklen() returned zero");
      spoton_misc::logError
	(QString("spoton_gcrypt::reencodePrivateKey(): "
		 "gcry_cipher_get_algo_blklen() "
		 "failure for %1.").arg(newCipher));
      goto error_label;
    }

  if((ivLength = gcry_cipher_get_algo_blklen(algorithm)) == 0)
    {
      error = QObject::tr("gcry_cipher_get_algo_blklen() returned zero");
      spoton_misc::logError
	(QString("spoton_gcrypt::reencodePrivateKey(): "
		 "gcry_cipher_get_algo_blklen() "
		 "failure for %1.").arg(newCipher));
      goto error_label;
    }

  if(!(iv = static_cast<char *> (gcry_calloc(ivLength, sizeof(char)))))
    {
      error = QObject::tr("gcry_calloc() returned zero");
      spoton_misc::logError("spoton_gcrypt::reencodePrivateKey(): "
			    "gcry_calloc() returned zero.");
      goto error_label;
    }

  gcry_create_nonce(iv, ivLength);

  if(gcry_cipher_setiv(cipherHandle,
		       static_cast<const void *> (iv),
		       ivLength) != 0)
    {
      error = QObject::tr("gcry_cipher_setiv() returned non-zero");
      spoton_misc::logError("spoton_gcrypt::reencodePrivateKey(): "
			    "gcry_cipher_setiv() returned non-zero.");
      goto error_label;
    }

  if((keyLength = gcry_cipher_get_algo_keylen(algorithm)) == 0)
    {
      error = QObject::tr("gcry_cipher_get_algo_keylen() returned zero");
      spoton_misc::logError
	(QString("spoton_gcrypt::reencodePrivateKey(): "
		 "gcry_cipher_get_algo_keylen() "
		 "failure for %1.").arg(newCipher));
      goto error_label;
    }

  if((err = gcry_cipher_setkey(cipherHandle,
			       static_cast<const void *> (newPassphrase.
							  constData()),
			       keyLength)) != 0)
    {
      error = QObject::tr("gcry_cipher_setkey() returned non-zero");
      spoton_misc::logError
	(QString("spoton_gcrypt::reencodePrivateKey(): gcry_cipher_setkey() "
		 "failure (%1).").arg(gcry_strerror(err)));
      goto error_label;
    }

  /*
  ** Block ciphers require the length of the buffers
  ** to be multiples of the cipher's block size.
  */

  encryptedData.append(data);

  if(encryptedData.isEmpty())
    encryptedData = encryptedData.leftJustified(blockLength, 0);
  else
    encryptedData = encryptedData.leftJustified
      (blockLength * qCeil(static_cast<qreal> (encryptedData.length()) /
			   static_cast<qreal> (blockLength)), 0);

  out << encryptedData.length();
  encryptedData.append(QByteArray(blockLength, 0));
  encryptedData.remove(encryptedData.length() - 4, 4);
  encryptedData.append(originalLength);

  if((err = gcry_cipher_encrypt(cipherHandle,
				static_cast<void *> (encryptedData.data()),
				static_cast<size_t> (encryptedData.length()),
				static_cast<const void *> (0),
				static_cast<size_t> (0))) != 0)
    {
      error = QObject::tr("gcry_cipher_encrypt() returned non-zero");
      spoton_misc::logError
	(QString("spoton_gcrypt::reencodePrivateKey(): "
		 "gcry_cipher_encrypt() failure (%1).").
	 arg(gcry_strerror(err)));
      goto error_label;
    }
  else
    encryptedData = QByteArray(iv, ivLength) + encryptedData;

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton_gcrypt");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "idiotes.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.prepare("UPDATE idiotes SET private_key = ? "
		      "WHERE id = ?");
	query.bindValue(0, encryptedData.toBase64());
	query.bindValue(1, id);

	if(!query.exec())
	  spoton_misc::logError("spoton_gcrypt::reencodePrivateKey(): "
				"error updating private_key in the "
				"idiotes table.");
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton_gcrypt");

 error_label:
  gcry_free(iv);
  gcry_cipher_close(cipherHandle);
  gcry_sexp_release(key_t);
}

spoton_gcrypt::spoton_gcrypt(const QString &cipherType,
			     const QString &hashType,
			     const QByteArray &passphrase,
			     const QByteArray &symmetricKey,
			     const int saltLength,
			     const unsigned long iterationCount,
			     const QString &id)
{
  init();
  m_cipherAlgorithm = gcry_cipher_map_name(cipherType.toLatin1().
					   constData());
  m_cipherHandle = 0;
  m_cipherType = cipherType;
  m_hashAlgorithm = gcry_md_map_name(hashType.toLatin1().constData());
  m_hashType = hashType;
  m_id = id;
  m_iterationCount = iterationCount;
  m_passphrase = 0;
  m_passphraseLength = passphrase.length();
  m_symmetricKey = 0;
  m_symmetricKeyLength = gcry_cipher_get_algo_keylen(m_cipherAlgorithm);
  m_saltLength = saltLength;

  if(m_passphraseLength)
    m_passphrase = static_cast<char *>
      (gcry_calloc_secure(m_passphraseLength, sizeof(char)));

  if(m_symmetricKeyLength)
    m_symmetricKey = static_cast<char *>
      (gcry_calloc_secure(m_symmetricKeyLength, sizeof(char)));

  if(m_passphrase)
    memcpy(static_cast<void *> (m_passphrase),
	   static_cast<const void *> (passphrase.constData()),
	   qMin(m_passphraseLength,
		static_cast<size_t> (passphrase.length())));
  else if(m_passphraseLength > 0)
    {
      m_passphraseLength = 0;
      spoton_misc::logError("spoton_gcrypt::spoton_gcrypt(): "
			    "gcry_calloc_secure() returned 0.");
    }

  if(m_symmetricKey)
    {
      memcpy(static_cast<void *> (m_symmetricKey),
	     static_cast<const void *> (symmetricKey.constData()),
	     qMin(m_symmetricKeyLength,
		  static_cast<size_t> (symmetricKey.length())));

      gcry_error_t err = 0;

      if((err = gcry_cipher_open(&m_cipherHandle, m_cipherAlgorithm,
				 GCRY_CIPHER_MODE_CBC,
				 GCRY_CIPHER_SECURE |
				 GCRY_CIPHER_CBC_CTS))
	 != 0 || !m_cipherAlgorithm)
	{
	  if(err != 0)
	    spoton_misc::logError(QString("spoton_gcrypt::spoton_gcrypt(): "
					  "gcry_cipher_open() failure (%1).").
				  arg(gcry_strerror(err)));
	  else
	    spoton_misc::logError("spoton_gcrypt::spoton_gcrypt(): "
				  "gcry_cipher_open() failure.");
	}

      if(err == 0)
	{
	  if(m_cipherHandle)
	    {
	      if((err =
		  gcry_cipher_setkey(m_cipherHandle,
				     static_cast<const void *> (m_symmetricKey),
				     m_symmetricKeyLength)) != 0)
		spoton_misc::logError(QString("spoton_gcrypt::spoton_gcrypt(): "
					      "gcry_cipher_setkey() "
					      "failure (%1).").
				      arg(gcry_strerror(err)));
	    }
	  else
	    spoton_misc::logError("spoton_gcrypt::spoton_gcrypt(): "
				  "m_cipherHandle is 0.");
	}
      
    }
  else if(m_symmetricKeyLength > 0)
    {
      m_symmetricKeyLength = 0;
      spoton_misc::logError("spoton_gcrypt::spoton_gcrypt(): "
			    "gcry_calloc_secure() returned 0.");
    }
}

spoton_gcrypt::~spoton_gcrypt()
{
  gcry_cipher_close(m_cipherHandle);
  gcry_free(m_symmetricKey);
}

QByteArray spoton_gcrypt::decrypted(const QByteArray &data, bool *ok)
{
  if(!m_cipherHandle)
    {
      if(ok)
	*ok = false;

      return data;
    }

  QByteArray decrypted(data);

  if(!setInitializationVector(decrypted))
    {
      if(ok)
	*ok = false;

      spoton_misc::logError
	("spoton_gcrypt::decrypted(): setInitializationVector() failure.");
    }
  else
    {
      size_t blockLength = gcry_cipher_get_algo_blklen(m_cipherAlgorithm);

      if(blockLength == 0)
	{
	  if(ok)
	    *ok = false;

	  spoton_misc::logError
	    (QString("spoton_gcrypt::decrypted(): "
		     "gcry_cipher_get_algo_blklen() "
		     "failure for %1.").arg(m_cipherType));
	}
      else
	{
	  /*
	  ** Block ciphers require the length of the buffers
	  ** to be multiples of the cipher's block size.
	  */

	  if(decrypted.isEmpty())
	    decrypted = decrypted.leftJustified(blockLength, 0);
	  else
	    decrypted = decrypted.leftJustified
	      (blockLength *
	       qCeil((qreal) decrypted.length() / (qreal) blockLength), 0);

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
	      QByteArray originalLength
		(decrypted.mid(decrypted.length() - 4, 4));
	      QDataStream in(&originalLength, QIODevice::ReadOnly);

	      in >> s;

	      if(s >= 0 && s <= decrypted.length())
		{
		  if(ok)
		    *ok = true;

		  return decrypted.mid(0, s);
		}
	      else
		{
		  if(ok)
		    *ok = false;

		  spoton_misc::logError
		    (QString("spoton_gcrypt::decrypted(): The length (%1) "
			     "of the "
			     "decrypted data is irregular.").arg(s));
		}
	    }
	  else
	    {
	      if(ok)
		*ok = false;

	      spoton_misc::logError
		(QString("spoton_gcrypt::decrypted(): "
			 "gcry_cipher_decrypt() failure (%1).").
		 arg(gcry_strerror(err)));
	    }
	}
    }

  return decrypted;
}

QByteArray spoton_gcrypt::encrypted(const QByteArray &data, bool *ok)
{
  if(!m_cipherHandle)
    {
      if(ok)
	*ok = false;

      return data;
    }

  QByteArray encrypted(data);
  QByteArray iv;

  if(!setInitializationVector(iv))
    {
      if(ok)
	*ok = false;

      spoton_misc::logError
	("spoton_gcrypt::encrypted(): setInitializationVector() failure.");
    }
  else
    {
      size_t blockLength = gcry_cipher_get_algo_blklen(m_cipherAlgorithm);

      if(blockLength == 0)
	{
	  if(ok)
	    *ok = false;

	  spoton_misc::logError
	    (QString("spoton_gcrypt::encrypted(): "
		     "gcry_cipher_get_algo_blklen() "
		     "failure for %1.").arg(m_cipherType));
	}
      else
	{
	  if(encrypted.isEmpty())
	    encrypted = encrypted.leftJustified(blockLength, 0);
	  else
	    encrypted = encrypted.leftJustified
	      (blockLength *
	       qCeil((qreal) encrypted.length() / (qreal) blockLength), 0);

	  encrypted.append(QByteArray(blockLength, 0));

	  QByteArray originalLength;
	  QDataStream out(&originalLength, QIODevice::WriteOnly);

	  out << data.length();
	  encrypted.remove(encrypted.length() - 4, 4);
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

	      return iv + encrypted;
	    }
	  else
	    {
	      if(ok)
		*ok = false;

	      spoton_misc::logError
		(QString("spoton_gcrypt::encrypted(): "
			 "gcry_cipher_encrypt() failure (%1).").
		 arg(gcry_strerror(err)));
	    }
	}
    }

  return encrypted;
}

char *spoton_gcrypt::symmetricKey(void) const
{
  return m_symmetricKey;
}

size_t spoton_gcrypt::symmetricKeyLength(void) const
{
  return m_symmetricKeyLength;
}

bool spoton_gcrypt::setInitializationVector(QByteArray &bytes)
{
  if(!m_cipherHandle)
    return false;

  bool ok = true;
  size_t ivLength = 0;

  if((ivLength = gcry_cipher_get_algo_blklen(m_cipherAlgorithm)) == 0)
    {
      ok = false;

      spoton_misc::logError
	(QString("spoton_gcrypt::setInitializationVector(): "
		 "gcry_cipher_get_algo_blklen() "
		 "failure for %1.").arg(m_cipherType));
    }
  else
    {
      char *iv = static_cast<char *> (gcry_calloc(ivLength, sizeof(char)));

      if(iv)
	{
	  if(bytes.isEmpty())
	    {
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

	  gcry_cipher_reset(m_cipherHandle);

	  gcry_error_t err = 0;

	  if((err = gcry_cipher_setiv(m_cipherHandle,
				      static_cast<const void *> (iv),
				      ivLength)) != 0)
	    {
	      ok = false;

	      spoton_misc::logError
		(QString("spoton_gcrypt::setInitializationVector(): "
			 "gcry_cipher_setiv() failure (%1).").
		 arg(gcry_strerror(err)));
	    }

	  gcry_free(iv);
	}
      else
	{
	  ok = false;

	  spoton_misc::logError("spoton_gcrypt::setInitializationVector(): "
				"gcry_calloc() returned 0.");
	}
    }

  return ok;
}

QByteArray spoton_gcrypt::keyedHash(const QByteArray &data, bool *ok)
{
  QByteArray hash;
  gcry_error_t err = 0;
  gcry_md_hd_t hd;

  if((err = gcry_md_open(&hd, m_hashAlgorithm,
			 GCRY_MD_FLAG_SECURE |
			 GCRY_MD_FLAG_HMAC)) != 0 || !hd)
    {
      if(ok)
	*ok = false;

      if(err != 0)
	spoton_misc::logError
	  (QString("spoton_gcrypt::keyedHash(): "
		   "gcry_md_open() failure (%1).").
	   arg(gcry_strerror(err)));
      else
	spoton_misc::logError
	  ("spoton_gcrypt::keyedHash(): gcry_md_open() failure.");
    }
  else
    {
      if((err = gcry_md_setkey(hd,
			       static_cast<const void *> (m_symmetricKey),
			       m_symmetricKeyLength)) != 0)
	{
	  if(ok)
	    *ok = false;

	  spoton_misc::logError
	    (QString("spoton_gcrypt::keyedHash(): gcry_md_setkey() "
		     "failure (%1).").arg(gcry_strerror(err)));
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
		    (QString("spoton_gcrypt::keyedHash(): "
			     "gcry_md_get_algo_dlen() "
			     "failure for %1.").arg(m_hashType));
		}
	    }
	  else
	    {
	      if(ok)
		*ok = false;

	      spoton_misc::logError("spoton_gcrypt::keyedHash(): "
				    "gcry_md_read() returned 0.");
	    }
	}
    }

  gcry_md_close(hd);
  return hash;
}

QByteArray spoton_gcrypt::sha1Hash(const QByteArray &data,
				   bool *ok)
{
  init();
  return shaXHash(GCRY_MD_SHA1, data, ok);
}

QByteArray spoton_gcrypt::sha512Hash(const QByteArray &data,
				     bool *ok)
{
  init();
  return shaXHash(GCRY_MD_SHA512, data, ok);
}

QByteArray spoton_gcrypt::shaXHash(const int algorithm,
				   const QByteArray &data,
				   bool *ok)
{
  init();

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
  else if(ok)
    {
      *ok = false;

      spoton_misc::logError
	(QString("spoton_gcrypt::shaXHash(): "
		 "gcry_md_get_algo_dlen() "
		 "failure for %1.").arg(algorithm));
    }

  return hash;
}

QByteArray spoton_gcrypt::publicKeyEncrypt(const QByteArray &data,
					   const QByteArray &publicKey,
					   bool *ok)
{
  init();

  QByteArray encrypted;
  gcry_error_t err = 0;
  gcry_sexp_t key_t = 0;

  if((err = gcry_sexp_new(&key_t,
			  static_cast<const void *> (publicKey.constData()),
			  static_cast<size_t> (publicKey.length()),
			  1)) == 0 && key_t)
    {
#if SPOTON_MINIMUM_GCRYPT_VERSION >= 0x010500
      QByteArray random(64, 0); // Output size of Sha-512 divided by 8.
#endif
      gcry_sexp_t data_t = 0;
      gcry_sexp_t encodedData_t = 0;

#if SPOTON_MINIMUM_GCRYPT_VERSION >= 0x010500
      gcry_randomize(static_cast<void *> (random.data()),
		     static_cast<size_t> (random.length()),
		     GCRY_STRONG_RANDOM);
#endif

      if((err = gcry_sexp_build(&data_t, 0,
#if SPOTON_MINIMUM_GCRYPT_VERSION >= 0x010500
				"(data (flags oaep)(hash-algo sha512)"
				"(value %b)(random-override %b))",
#else
				"(data (flags pkcs1)"
				"(value %b))",
#endif
#if SPOTON_MINIMUM_GCRYPT_VERSION >= 0x010500
				data.length(),
				data.constData(),
				random.length(),
				random.constData()
#else
				data.length(),
				data.constData()
#endif
				)) == 0 && data_t)
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
			    ("spoton_gcrypt()::publicKeyEncrypt(): "
			     "gcry_sexp_sprint() failure.");
			}
		    }
		  else
		    {
		      if(ok)
			*ok = false;

		      spoton_misc::logError
			("spoton_gcrypt()::publicKeyEncrypt(): malloc() "
			 "failure.");
		    }

		  free(buffer);
		}
	      else
		{
		  if(ok)
		    *ok = false;

		  spoton_misc::logError
		    ("spoton_gcrypt()::publicKeyEncrypt(): "
		     "gcry_sexp_sprint() failure.");
		}

	      gcry_sexp_release(encodedData_t);
	    }
	  else
	    {
	      if(ok)
		*ok = false;

	      if(err != 0)
		spoton_misc::logError
		  (QString("spoton_gcrypt()::publicKeyEncrypt(): "
			   "gcry_pk_encrypt() "
			   "failure (%1).").arg(gcry_strerror(err)));
	      else
		spoton_misc::logError
		  ("spoton_gcrypt::publicKeyEncrypt(): "
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
	    spoton_misc::logError
	      (QString("spoton_gcrypt()::publicKeyEncrypt(): "
		       "gcry_sexp_build() "
		       "failure (%1).").arg(gcry_strerror(err)));
	  else
	    spoton_misc::logError
	      ("spoton_gcrypt()::publicKeyEncrypt(): gcry_sexp_build() "
	       "failure.");
	}
    }
  else
    {
      if(ok)
	*ok = false;

      if(err != 0)
	spoton_misc::logError
	  (QString("spoton_gcrypt()::publicKeyEncrypt(): gcry_sexp_new() "
		   "failure (%1).").arg(gcry_strerror(err)));
      else
	spoton_misc::logError
	  ("spoton_gcrypt::publicKeyEncrypt(): gcry_sexp_new() failure.");
    }

  return encrypted;
}

QByteArray spoton_gcrypt::publicKeyDecrypt(const QByteArray &data, bool *ok)
{
  /*
  ** We need to decipher the private key.
  */

  QByteArray decrypted;
  QByteArray keyData;
#if SPOTON_MINIMUM_GCRYPT_VERSION >= 0x010500
  QByteArray random(64, 0); // Output size of Sha-512 divided by 8.
#endif
  const char *buffer = 0;
  gcry_error_t err = 0;
  gcry_sexp_t data_t = 0;
  gcry_sexp_t decrypted_t = 0;
  gcry_sexp_t key_t = 0;
  gcry_sexp_t raw_t = 0;
  size_t length = 0;

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton_gcrypt");

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

  QSqlDatabase::removeDatabase("spoton_gcrypt");

  if(keyData.isEmpty())
    {
      if(ok)
	*ok = false;

      spoton_misc::logError
	("spoton_gcrypt::publicKeyDecrypt(): empty private_key.");
      goto error_label;
    }

  keyData = this->decrypted(keyData, ok);

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
	spoton_misc::logError
	  (QString("spoton_gcrypt::publicKeyDecrypt(): gcry_sexp_new() "
		   "failure (%1).").arg(gcry_strerror(err)));
      else
	spoton_misc::logError
	  ("spoton_gcrypt::publicKeyDecrypt(): gcry_sexp_new() failure.");

      goto error_label;
    }

  if((err = gcry_pk_testkey(key_t)) != 0)
    {
      if(ok)
	*ok = false;

      spoton_misc::logError
	(QString("spoton_gcrypt::publicKeyDecrypt(): gcry_pk_testkey() "
		 "failure (%1).").arg(gcry_strerror(err)));
      goto error_label;
    }

  if((err = gcry_sexp_new(&data_t,
			  static_cast<const void *> (data.constData()),
			  static_cast<size_t> (data.length()),
			  1)) != 0 || !data_t)
    {
      if(ok)
	*ok = false;

      if(err != 0)
	spoton_misc::logError
	  (QString("spoton_gcrypt::publicKeyDecrypt(): gcry_sexp_new() "
		   "failure (%1).").arg(gcry_strerror(err)));
      else
	spoton_misc::logError
	  ("spoton_gcrypt::publicKeyDecrypt(): gcry_sexp_new() failure.");

      goto error_label;
    }

  raw_t = gcry_sexp_find_token(data_t, "rsa", 0);
  gcry_sexp_release(data_t);

  if(!raw_t)
    {
      if(ok)
	*ok = false;

      spoton_misc::logError
	("spoton_gcrypt::publicKeyDecrypt(): gcry_sexp_find_token() "
	 "failure.");
    }

#if SPOTON_MINIMUM_GCRYPT_VERSION >= 0x010500
  gcry_randomize(static_cast<void *> (random.data()),
		 static_cast<size_t> (random.length()),
		 GCRY_STRONG_RANDOM);
#endif

  if((err = gcry_sexp_build(&data_t, 0,
#if SPOTON_MINIMUM_GCRYPT_VERSION >= 0x010500
			    "(enc-val (flags oaep)"
			    "(hash-algo sha512)(random-override %b) %S)",
			    random.length(),
			    random.constData(),
#else
			    "(enc-val (flags pkcs1) %S)",
#endif
			    raw_t)) !=0 || !data_t)
    {
      if(ok)
	*ok = false;

      if(err != 0)
	spoton_misc::logError
	  (QString("spoton_gcrypt::publicKeyDecrypt(): gcry_sexp_build() "
		   "failure (%1).").arg(gcry_strerror(err)));
      else
	spoton_misc::logError
	  ("spoton_gcrypt::publicKeyDecrypt(): gcry_sexp_build() failure.");

      goto error_label;
    }

  if((err = gcry_pk_decrypt(&decrypted_t, data_t,
			    key_t)) != 0 || !decrypted_t)
    {
      if(ok)
	*ok = false;

      if(err != 0)
	spoton_misc::logError
	  (QString("spoton_gcrypt::publicKeyDecrypt(): "
		   "gcry_pk_decrypt() failure (%1).").
	   arg(gcry_strerror(err)));
      else
	spoton_misc::logError
	  ("spoton_gcrypt::publicKeyDecrypt(): gcry_pk_decrypt() failure.");

      goto error_label;
    }

  buffer = gcry_sexp_nth_data(decrypted_t, 1, &length);

  if(!buffer)
    {
      if(ok)
	*ok = false;

      spoton_misc::logError
	("spoton_gcrypt::publicKeyDecrypt(): gcry_sexp_nth_data() "
	 "failure.");
      goto error_label;
    }

  decrypted = QByteArray(buffer, length);

  if(ok)
    *ok = true;

 error_label:
  gcry_sexp_release(data_t);
  gcry_sexp_release(decrypted_t);
  gcry_sexp_release(key_t);
  gcry_sexp_release(raw_t);
  return decrypted;
}

QByteArray spoton_gcrypt::publicKey(bool *ok)
{
  /*
  ** Returns the correct public key from idiotes.db.
  */

  QByteArray publicKey;

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton_gcrypt");

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
	    publicKey = query.value(0).toByteArray();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton_gcrypt");

  if(publicKey.isEmpty())
    {
      if(ok)
	*ok = false;

      spoton_misc::logError
	("spoton_gcrypt::publicKey(): "
	 "error retrieving public_key from idiotes.db.");
    }
  else if(ok)
    *ok = true;

  return publicKey;
}

void spoton_gcrypt::generatePrivatePublicKeys(const int rsaKeySize,
					      QString &error)
{
  QByteArray privateKey;
  QByteArray publicKey;
  char *buffer = 0;
  gcry_error_t err = 0;
  gcry_sexp_t key_t = 0;
  gcry_sexp_t keyPair_t = 0;
  gcry_sexp_t parameters_t = 0;
  size_t length = 0;

  if((err = gcry_sexp_build(&parameters_t, 0,
			    "(genkey (rsa (nbits %d)))",
			    rsaKeySize)) != 0 || !parameters_t)
    {
      error = QObject::tr("gcry_sexp_build() failure");

      if(err != 0)
	spoton_misc::logError
	  (QString("spoton_gcrypt::generatePrivatePublicKeys(): "
		   "gcry_sexp_build() "
		   "failure (%1).").arg(gcry_strerror(err)));
      else
	spoton_misc::logError
	  ("spoton_gcrypt::generatePrivatePublicKeys(): gcry_sexp_build() "
	   "failure.");

      goto error_label;
    }

  if((err = gcry_pk_genkey(&keyPair_t, parameters_t)) != 0 || !keyPair_t)
    {
      error = QObject::tr("gcry_pk_genkey() failure");

      if(err != 0)
	spoton_misc::logError
	  (QString("spoton_gcrypt::generatePrivatePublicKeys(): "
		   "gcry_pk_genkey() "
		   "failure (%1).").arg(gcry_strerror(err)));
      else
	spoton_misc::logError
	  ("spoton_gcrypt::generatePrivatePublicKeys(): gcry_pk_genkey() "
	   "failure.");
      goto error_label;
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
	    ("spoton_gcrypt::generatePrivatePublicKeys(): "
	     "gcry_sexp_find_token() failure.");
	  goto error_label;
	}

      length = gcry_sexp_sprint(key_t, GCRYSEXP_FMT_ADVANCED, 0, 0);

      if(!length)
	{
	  error = QObject::tr("gcry_sexp_sprint() failure");
	  spoton_misc::logError
	    ("spoton_gcrypt::generatePrivatePublicKeys(): gcry_sexp_sprint() "
	     "failure.");
	  goto error_label;
	}
      else
	{
	  buffer = (char *) malloc(length);

	  if(buffer)
	    {
	      gcry_sexp_sprint
		(key_t, GCRYSEXP_FMT_ADVANCED, buffer, length);

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
		("spoton_gcrypt::generatePrivatePublicKeys(): "
		 "malloc() failure.");
	      goto error_label;
	    }
	}

      gcry_free(key_t);
      key_t = 0;
    }

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton_gcrypt");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "idiotes.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	query.prepare("INSERT INTO idiotes (id, private_key, public_key) "
		      "VALUES (?, ?, ?)");
	query.bindValue(0, m_id);
	query.bindValue(1, encrypted(privateKey, &ok).toBase64());
	query.bindValue(2, publicKey);

	if(ok)
	  {
	    if(!query.exec())
	      {
		error = QObject::tr("QSqlQuery::exec() failure");
		spoton_misc::logError
		  ("spoton_gcrypt::generatePrivatePublicKeys(): "
		   "QSqlQuery::exec() failure.");
	      }
	  }
	else
	  {
	    error = QObject::tr("encrypted() failure");
	    spoton_misc::logError
	      ("spoton_gcrypt::generatePrivatePublicKeys(): "
	       "encrypted() failure.");
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton_gcrypt");

 error_label:
  free(buffer);
  gcry_free(key_t);
  gcry_free(keyPair_t);
  gcry_free(parameters_t);
}

QByteArray spoton_gcrypt::keyedHash(const QByteArray &data,
				    const QByteArray &key,
				    const QString &hashType,
				    bool *ok)
{
  QByteArray hash;
  gcry_error_t err = 0;
  gcry_md_hd_t hd;
  int hashAlgorithm = gcry_md_map_name(hashType.toLatin1().constData());

  if((err = gcry_md_open(&hd, hashAlgorithm,
			 GCRY_MD_FLAG_SECURE |
			 GCRY_MD_FLAG_HMAC)) != 0 || !hd)
    {
      if(ok)
	*ok = false;

      if(err != 0)
	spoton_misc::logError
	  (QString("spoton_gcrypt::keyedHash(): gcry_md_open() "
		   "failure (%1).").
	   arg(gcry_strerror(err)));
      else
	spoton_misc::logError
	  ("spoton_gcrypt::keyedHash(): gcry_md_open() failure.");
    }
  else
    {
      if((err = gcry_md_setkey(hd,
			       static_cast<const void *> (key.constData()),
			       static_cast<size_t> (key.length()))) != 0)
	{
	  if(ok)
	    *ok = false;

	  spoton_misc::logError
	    (QString("spoton_gcrypt::keyedHash(): gcry_md_setkey() "
		     "failure (%1).").arg(gcry_strerror(err)));
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
		    (QString("spoton_gcrypt::keyedHash(): "
			     "gcry_md_get_algo_dlen() "
			     "failure for %1.").arg(hashType));
		}
	    }
	  else
	    {
	      if(ok)
		*ok = false;

	      spoton_misc::logError("spoton_gcrypt::keyedHash(): "
				    "gcry_md_read() returned 0.");
	    }
	}
    }

  gcry_md_close(hd);
  return hash;
}

char *spoton_gcrypt::passphrase(void) const
{
  return m_passphrase;
}

size_t spoton_gcrypt::passphraseLength(void) const
{
  return m_passphraseLength;
}

QByteArray spoton_gcrypt::randomCipherType(void)
{
  QStringList types(cipherTypes());

  return types.value(qrand() % types.size()).toLatin1();
}
