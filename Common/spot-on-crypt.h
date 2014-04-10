/*
** Copyright (c) 2011 - 10^10^10 Alexis Megas
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

#ifndef _spoton_crypt_h_
#define _spoton_crypt_h_

extern "C"
{
  /*
  ** Older compilers (GCC 4.2.1) misbehave.
  */

#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include <errno.h>
#include <gcrypt.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#ifdef SPOTON_LINKED_WITH_LIBPTHREAD
#include <pthread.h>
#endif
#pragma GCC diagnostic warning "-Wdeprecated-declarations"
}

#include <QByteArray>
#include <QHostAddress>
#include <QMutex>
#include <QSslCipher>
#include <QSslConfiguration>
#include <QStringList>

class spoton_crypt
{
 public:
  static QPair<QByteArray, QByteArray> derivedKeys
    (const QString &cipherType,
     const QString &hashType,
     const unsigned long iterationCount,
     const QString &passphrase,
     const QByteArray &salt,
     QString &error);
  static QByteArray keyedHash(const QByteArray &data,
			      const QByteArray &key,
			      const QByteArray &hashType,
			      bool *ok);
  static QByteArray publicKeyEncrypt(const QByteArray &data,
				     const QByteArray &publicKey,
				     bool *ok);
  static QByteArray saltedPassphraseHash(const QString &hashType,
					 const QString &passphrase,
					 const QByteArray &salt,
					 QString &error);
  static QByteArray saltedValue(const QString &hashType,
				const QByteArray &data,
				const QByteArray &salt,
				bool *ok);
  static QByteArray sha1FileHash(const QString &fileName);
  static QByteArray sha1Hash(const QByteArray &data, bool *ok);
  static QByteArray sha512Hash(const QByteArray &data, bool *ok);
  static QByteArray shaXHash(const int algorithm,
			     const QByteArray &data, bool *ok);
  static QByteArray strongRandomBytes(const size_t size);
  static QByteArray veryStrongRandomBytes(const size_t size);
  static QByteArray weakRandomBytes(const size_t size);
  static QList<QSslCipher> defaultSslCiphers
    (const QString &sslControlString = QString(""));
  static QStringList cipherTypes(void);
  static QStringList hashTypes(void);
  static bool isValidSignature(const QByteArray &data,
			       const QByteArray &publicKey,
			       const QByteArray &signature);
  static bool memcmp(const QByteArray &bytes1, const QByteArray &bytes);
  static bool passphraseSet(void);
  static size_t cipherKeyLength(const QByteArray &cipherType);
  static void generateSslKeys(const int rsaKeySize,
			      QByteArray &certificate,
			      QByteArray &privateKey,
			      QByteArray &publicKey,
			      const QHostAddress &address,
			      const long days,
			      QString &error);
  static void init(const int secureMemorySize);
  static void purgeDatabases(void);
  static void reencodePrivatePublicKeys
    (spoton_crypt *newCrypt, spoton_crypt *oldCrypt, const QString &id,
     QString &error);
  static void setSslCiphers(const QList<QSslCipher> &ciphers,
			    QSslConfiguration &configuration);
  static void terminate(void);
  spoton_crypt(const QString &cipherType,
	       const QString &hashType,
	       const QByteArray &passphrase,
	       const QByteArray &symmetricKey,
	       const int saltLength,
	       const unsigned long iterationCount,
	       const QString &id);
  spoton_crypt(const QString &cipherType,
	       const QString &hashType,
	       const QByteArray &passphrase,
	       const QByteArray &symmetricKey,
	       const QByteArray &hashKey,
	       const int saltLength,
	       const unsigned long iterationCount,
	       const QString &id);
  ~spoton_crypt();
  QByteArray decrypted(const QByteArray &data, bool *ok);
  QByteArray decryptedAfterAuthenticated(const QByteArray &data, bool *ok);
  QByteArray digitalSignature(const QByteArray &data, bool *ok);
  QByteArray encrypted(const QByteArray &data, bool *ok);
  QByteArray encryptedThenHashed(const QByteArray &data, bool *ok);
  QByteArray hashKey(void) const;
  QByteArray keyedHash(const QByteArray &data, bool *ok) const;
  QByteArray publicKey(bool *ok);
  QByteArray publicKeyDecrypt(const QByteArray &data, bool *ok);
  QByteArray publicKeyHash(bool *ok);
  QByteArray symmetricKey(void) const;
  QString cipherType(void) const;
  qint64 publicKeyCount(void) const;
  void generatePrivatePublicKeys(const int keySize,
				 const QString &keyType,
				 QString &error);
  void initializePrivateKeyContainer(bool *ok);

 private:
  QByteArray m_publicKey;
  QMutex m_cipherMutex;
  QString m_cipherType;
  QString m_hashType;
  QString m_id;
  char *m_hashKey; // Stored in secure memory.
  char *m_privateKey; // Stored in secure memory.
  char *m_symmetricKey; // Stored in secure memory.
  gcry_cipher_hd_t m_cipherHandle;
  int m_cipherAlgorithm;
  int m_hashAlgorithm;
  int m_saltLength;
  size_t m_hashKeyLength;
  size_t m_privateKeyLength;
  size_t m_symmetricKeyLength;
  unsigned long m_iterationCount;
  void init(const QString &cipherType,
	    const QString &hashType,
	    const QByteArray &passphrase,
	    const QByteArray &symmetricKey,
	    const QByteArray &hashKey,
	    const int saltLength,
	    const unsigned long iterationCount,
	    const QString &id);
  void setHashKey(const QByteArray &hashKey);
  static bool setInitializationVector(QByteArray &iv,
				      const int algorithm,
				      gcry_cipher_hd_t cipherHandle);
  static void generateCertificate(RSA *rsa,
				  QByteArray &certificate,
				  const QHostAddress &address,
				  const long days,
				  QString &error);
};

#endif
