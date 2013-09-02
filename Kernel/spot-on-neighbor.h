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

#ifndef _spoton_neighbor_h_
#define _spoton_neighbor_h_

#include <QDateTime>
#include <QHostAddress>
#include <QHostInfo>
#include <QNetworkProxy>
#include <QSqlDatabase>
#include <QSslSocket>
#include <QTimer>
#include <QUuid>

#include "Common/spot-on-send.h"

class QNetworkInterface;

class spoton_external_address;

class spoton_neighbor: public QSslSocket
{
  Q_OBJECT

 public:
  spoton_neighbor(const QNetworkProxy &proxy,
		  const QString &ipAddress,
		  const QString &port,
		  const QString &scopeId,
		  const qint64 id,
		  const bool userDefined,
		  const int keySize,
		  const int maximumBufferSize,
		  const int maximumContentLength,
		  const QString &echoMode,
		  QObject *parent);
  spoton_neighbor(const int socketDescriptor,
		  const QByteArray &certificate,
		  const QByteArray &privateKey,
		  const QString &echoMode,
		  QObject *parent);
  ~spoton_neighbor();
  QUuid receivedUuid(void) const;
  qint64 id(void) const;
  void setId(const qint64 id);
  void sharePublicKey(const QByteArray &keyType,
		      const QByteArray &name,
		      const QByteArray &publicKey,
		      const QByteArray &signature,
		      const QByteArray &sPublicKey,
		      const QByteArray &sSignature);

 private:
  QByteArray m_data;
  QDateTime m_lastReadTime;
  QDateTime m_startTime;
  QHostAddress m_address;
  QNetworkInterface *m_networkInterface;
  QString m_echoMode;
  QString m_ipAddress;
  QTimer m_externalAddressDiscovererTimer;
  QTimer m_keepAliveTimer;
  QTimer m_lifetime;
  QTimer m_readTimer;
  QTimer m_timer;
  QUuid m_receivedUuid;
  bool m_isUserDefined;
  bool m_useSsl;
  int m_keySize;
  int m_maximumBufferSize;
  int m_maximumContentLength;
  qint64 m_id;
  quint16 m_port;
  spoton_external_address *m_externalAddress;
  QString findMessageType(const QByteArray &data,
			  QPair<QByteArray, QByteArray> &symmetricKey);
  bool isDuplicateMessage(const QByteArray &data);
  bool readyToWrite(void);
  void prepareNetworkInterface(void);
  void process0000(int length, const QByteArray &data,
		   const QPair<QByteArray, QByteArray> &pair);
  void process0000a(int length, const QByteArray &data);
  void process0001a(int length, const QByteArray &data);
  void process0001b(int length, const QByteArray &data);
  void process0002(int length, const QByteArray &data);
  void process0011(int length, const QByteArray &data);
  void process0012(int length, const QByteArray &data);
  void process0013(int length, const QByteArray &data,
		   const QPair<QByteArray, QByteArray> &pair);
  void process0014(int length, const QByteArray &data);
  void process0015(int length, const QByteArray &data);
  void process0030(int length, const QByteArray &data);
  void process0040a(int length, const QByteArray &data,
		    const QPair<QByteArray, QByteArray> &pair);
  void process0040b(int length, const QByteArray &data,
		    const QPair<QByteArray, QByteArray> &pair);
  void recordMessageHash(const QByteArray &data);
  void resetKeepAlive(void);
  void saveEncryptedStatus(void);
  void saveExternalAddress(const QHostAddress &address,
			   const QSqlDatabase &db);
  void saveGemini(const QByteArray &publicKeyHash,
		  const QByteArray &gemini);
  void saveParticipantStatus(const QByteArray &publicKeyHash);
  void saveParticipantStatus(const QByteArray &name,
			     const QByteArray &publicKeyHash);
  void saveParticipantStatus(const QByteArray &name,
			     const QByteArray &publicKeyHash,
			     const QByteArray &status);
  void savePublicKey(const QByteArray &keyType,
		     const QByteArray &name,
		     const QByteArray &publicKey,
		     const QByteArray &signature,
		     const QByteArray &sPublicKey,
		     const QByteArray &sSignature,
		     const qint64 neighborOid);
  void saveStatistics(const QSqlDatabase &db);
  void saveStatus(const QSqlDatabase &db, const QString &status);
  void storeLetter(const QByteArray &symmetricKey,
		   const QByteArray &symmetricKeyAlgorithm,
		   const QByteArray &senderPublicKeyHash,
		   const QByteArray &name,
		   const QByteArray &subject,
		   const QByteArray &message,
		   const QByteArray &signature,
		   const bool goldbugUsed);
  void storeLetter(const QList<QByteArray> &list,
		   const QByteArray &recipientHash);

 private slots:
  void slotCallParticipant(const QByteArray &data);
  void slotConnected(void);
  void slotDisconnected(void);
  void slotDiscoverExternalAddress(void);
  void slotEncrypted(void);
  void slotError(QAbstractSocket::SocketError error);
  void slotExternalAddressDiscovered(const QHostAddress &address);
  void slotHostFound(const QHostInfo &hostInfo);
  void slotLifetimeExpired(void);
  void slotModeChanged(QSslSocket::SslMode mode);
  void slotProxyAuthenticationRequired(const QNetworkProxy &proxy,
				       QAuthenticator *authenticator);
  void slotPublicizeListenerPlaintext(const QByteArray &data,
				      const qint64 id);
  void slotPublicizeListenerPlaintext(const QHostAddress &address,
				      const quint16 port);
  void slotReadyRead(void);
  void slotReceivedMessage(const QByteArray &data, const qint64 id);
  void slotRetrieveMail(const QList<QByteArray> &list);
  void slotSendBuzz(const QByteArray &data);
  void slotSendKeepAlive(void);
  void slotSendMail(const QList<QPair<QByteArray, qint64> > &list);
  void slotSendMailFromPostOffice(const QByteArray &data);
  void slotSendMessage(const QByteArray &data);
  void slotSendStatus(const QList<QByteArray> &list);
  void slotSendUuid(void);
  void slotSslErrors(const QList<QSslError> &errors);
  void slotTimeout(void);

 signals:
  void newEMailArrived(void);
  void publicizeListenerPlaintext(const QByteArray &data, const qint64 id);
  void receivedBuzzMessage(const QList<QByteArray> &list,
			   const QPair<QByteArray, QByteArray> &pair);
  void receivedChatMessage(const QByteArray &data);
  void receivedMessage(const QByteArray &data, const qint64 id);
  void receivedPublicKey(const QByteArray &name, const QByteArray publicKey);
  void retrieveMail(const QByteArray &data,
		    const QByteArray &publicKeyHash,
		    const QByteArray &signature);
  void scrambleRequest(void);
};

#endif
