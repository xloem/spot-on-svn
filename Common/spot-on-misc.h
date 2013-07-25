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

#ifndef _spoton_misc_h_
#define _spoton_misc_h_

#include <QHostAddress>
#include <QSqlDatabase>
#include <QString>
#include <QVariant>

class spoton_crypt;

class spoton_misc
{
 public:
  static QByteArray findGeminiInCosmos(const QByteArray &data,
				       spoton_crypt *crypt);
  static QByteArray publicKeyFromHash(const QByteArray &publicKeyHash);
  static QByteArray publicKeyFromSignaturePublicKeyHash
    (const QByteArray &signaturePublicKeyHash);
  static QSqlDatabase database(QString &connectionName);
  static QString countryCodeFromIPAddress(const QString &ipAddress);
  static QString countryCodeFromName(const QString &country);
  static QString countryNameFromIPAddress(const QString &ipAddress);
  static QString homePath(void);
  static bool countryAllowedToConnect(const QString &country,
				      spoton_crypt *crypt);
  static bool isAcceptedParticipant(const QByteArray &publicKeyHash);
  static bool isGnome(void);
  static bool isPrivateNetwork(const QHostAddress &address);
  static bool saveFriendshipBundle(const QByteArray &keyType,
				   const QByteArray &name,
				   const QByteArray &publicKey,
				   const QByteArray &sPublicKey,
				   const int neighborOid,
				   const QSqlDatabase &db);
  static int participantCount(void);
  static void cleanupDatabases(void);
  static void correctSettingsContainer(QHash<QString, QVariant> settings);
  static void enableLog(const bool state);
  static void logError(const QString &error);
  static void moveSentMailToSentFolder(const QList<qint64> &oids,
				       spoton_crypt *crypt);
  static void populateCountryDatabase(spoton_crypt *crypt);
  static void populateUrlsDatabase(const QList<QList<QVariant> > &list,
				   spoton_crypt *crypt);
  static void prepareDatabases(void);
  static void prepareUrlDatabases(void);
  static void purgeSignatureRelationships(const QSqlDatabase &db);
  static void retrieveSymmetricData(QByteArray &gemini,
				    QByteArray &publicKey,
				    QByteArray &symmetricKey,
				    QByteArray &symmetricKeyAlgorithm,
				    QString &neighborOid,
				    const QString &oid,
				    spoton_crypt *crypt);
  static void savePublishedNeighbor(const QHostAddress &address,
				    const quint16 port,
				    const QString &statusControl,
				    spoton_crypt *crypt);

 private:
  static bool s_enableLog;
  static qint64 s_dbId;
  spoton_misc(void);
};

#endif
