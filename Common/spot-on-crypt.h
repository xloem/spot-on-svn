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
#include <pthread.h>
#pragma GCC diagnostic warning "-Wdeprecated-declarations"
}

#include <QByteArray>
#include <QHostAddress>
#include <QSslCipher>
#include <QSslConfiguration>
#include <QStringList>

class spoton_crypt
{
 public:
  static QByteArray derivedKey(const QString &cipherType,
			       const QString &hashType,
			       const unsigned long iterationCount,
			       const QString &passphrase,
			       const QByteArray &salt,
			       QString &error);
  static QByteArray keyedHash(const QByteArray &data,
			      const QByteArray &key,
			      const QString &hashType,
			      bool *ok);
  static QByteArray publicKeyEncrypt(const QByteArray &data,
				     const QByteArray &publicKey,
				     bool *ok);
  static QByteArray randomCipherType(void);
  static QByteArray saltedPassphraseHash(const QString &hashType,
					 const QString &passphrase,
					 const QByteArray &salt,
					 QString &error);
  static QByteArray saltedValue(const QString &hashType,
				const QByteArray &data,
				const QByteArray &salt,
				bool *ok);
  static QByteArray sha1Hash(const QByteArray &data, bool *ok);
  static QByteArray sha512Hash(const QByteArray &data, bool *ok);
  static QByteArray shaXHash(const int algorithm,
			     const QByteArray &data, bool *ok);
  static QByteArray strongRandomBytes(const size_t size);
  static QByteArray weakRandomBytes(const size_t size);
  static QList<QSslCipher> defaultSslCiphers
    (const QString &sslControlString = QString(""));
  static QStringList cipherTypes(void);
  static QStringList hashTypes(void);
  static bool isValidSignature(const QByteArray &data,
			       const QByteArray &publicKey,
			       const QByteArray &signature);
  static bool passphraseSet(void);
  static size_t cipherKeyLength(const QByteArray &cipherType);
  static void generateSslKeys(const int rsaKeySize,
			      QByteArray &certificate,
			      QByteArray &privateKey,
			      QByteArray &publicKey,
			      const QHostAddress &address,
			      const long days,
			      QString &error);
  static void purgeDatabases(void);
  static void reencodeKeys(const QString &newCipher,
			   const QByteArray &newPassphrase,
			   const QString &oldCipher,
			   const char *oldPassphrase,
			   const QString &id,
			   QString &error);
  static void setSslCiphers(const QList<QSslCipher> &ciphers,
			    QSslConfiguration &configuration);
  spoton_crypt(const QString &id); // Random object?
  spoton_crypt(const QString &cipherType,
		const QString &hashType,
		const QByteArray &passphrase,
		const QByteArray &symmetricKey,
		const int saltLength,
		const unsigned long iterationCount,
		const QString &id);
  spoton_crypt(spoton_crypt *other);
  ~spoton_crypt();
  QByteArray decrypted(const QByteArray &data, bool *ok);
  QByteArray digitalSignature(const QByteArray &data, bool *ok);
  QByteArray encrypted(const QByteArray &data, bool *ok);
  QByteArray keyedHash(const QByteArray &data, bool *ok);
  QByteArray privateKeyInRem(bool *ok);
  QByteArray publicKey(bool *ok);
  QByteArray publicKeyDecrypt(const QByteArray &data, bool *ok);
  QByteArray publicKeyHash(bool *ok);
  QString cipherType(void) const;
  char *symmetricKey(void) const;
  size_t symmetricKeyLength(void) const;
  void generatePrivatePublicKeys(const int keySize,
				 const QString &keyType,
				 QString &error);
  void initializePrivateKeyContainer(bool *ok);

 private:
  QByteArray m_publicKey;
  QString m_cipherType;
  QString m_hashType;
  QString m_id;
  char *m_privateKey;
  char *m_symmetricKey;
  gcry_cipher_hd_t m_cipherHandle;
  int m_cipherAlgorithm;
  int m_hashAlgorithm;
  int m_saltLength;
  size_t m_privateKeyLength;
  size_t m_symmetricKeyLength;
  unsigned long m_iterationCount;
  void init(const QString &cipherType,
	    const QString &hashType,
	    const QByteArray &symmetricKey,
	    const int saltLength,
	    const unsigned long iterationCount,
	    const QString &id);
  static bool setInitializationVector(QByteArray &iv,
				      const int algorithm,
				      gcry_cipher_hd_t cipherHandle);
  static void generateCertificate(RSA *rsa,
				  QByteArray &certificate,
				  const QHostAddress &address,
				  const long days,
				  QString &error);
  static void init(void);
};

#endif
