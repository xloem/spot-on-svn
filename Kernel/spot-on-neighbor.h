/*
** Copyright (c) 2013 Alexis Megas
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
#include <QTcpSocket>
#include <QTimer>
#include <QUuid>

#include "Common/spot-on-external-address.h"

class QNetworkInterface;

class spoton_neighbor: public QTcpSocket
{
  Q_OBJECT

 public:
  static qint64 s_dbId;
  spoton_neighbor(const QNetworkProxy &proxy,
		  const QString &ipAddress,
		  const QString &port,
		  const QString &scopeId,
		  const qint64 id,
		  QObject *parent);
  spoton_neighbor(const int socketDescriptor,
		  QObject *parent);
  ~spoton_neighbor();
  QUuid receivedUuid(void) const;
  qint64 id(void) const;
  void setId(const qint64 id);
  void sharePublicKey(const QByteArray &keyType,
		      const QByteArray &name,
		      const QByteArray &publicKey,
		      const QByteArray &signature);

 private:
  QByteArray m_data;
  QDateTime m_lastReadTime;
  QHostAddress m_address;
  QNetworkInterface *m_networkInterface;
  QString m_ipAddress;
  QTimer m_externalAddressDiscovererTimer;
  QTimer m_keepAliveTimer;
  QTimer m_lifetime;
  QTimer m_timer;
  QUuid m_receivedUuid;
  qint64 m_id;
  quint16 m_port;
  spoton_external_address *m_externalAddress;
  void prepareNetworkInterface(void);
  void process0000(int length, const QByteArray &data);
  void process0001a(int length, const QByteArray &data);
  void process0001b(int length, const QByteArray &data);
  void process0002(int length, const QByteArray &data);
  void process0011(int length, const QByteArray &data);
  void process0012(int length, const QByteArray &data);
  void process0013(int length, const QByteArray &data);
  void process0014(int length, const QByteArray &data);
  void process0015(int length, const QByteArray &data);
  void saveExternalAddress(const QHostAddress &address,
			   QSqlDatabase &db);
  void saveParticipantStatus(const QByteArray &name,
			     const QByteArray &publicKeyHash);
  void saveParticipantStatus(const QByteArray &name,
			     const QByteArray &publicKeyHash,
			     const QByteArray &status);
  void savePublicKey(const QByteArray &keyType,
		     const QByteArray &name,
		     const QByteArray &publicKey,
		     const QByteArray &signature,
		     const qint64 neighborOid);
  void saveStatus(QSqlDatabase &db, const QString &status);
  void storeLetter(QByteArray &symmetricKey,
		   QByteArray &symmetricKeyAlgorithm,
		   QByteArray &senderPublicKeyHash,
		   QByteArray &name,
		   QByteArray &subject,
		   QByteArray &message,
		   QByteArray &messageDigest,
		   const QString &messageType);
  void storeLetter(const QList<QByteArray> &list,
		   const QByteArray &recipientHash);

 private slots:
  void slotConnected(void);
  void slotDiscoverExternalAddress(void);
  void slotError(QAbstractSocket::SocketError error);
  void slotExternalAddressDiscovered(const QHostAddress &address);
  void slotHostFound(const QHostInfo &hostInfo);
  void slotLifetimeExpired(void);
  void slotReadyRead(void);
  void slotReceivedChatMessage(const QByteArray &data, const qint64 id);
  void slotReceivedMailMessage(const QByteArray &data, const qint64 id);
  void slotReceivedStatusMessage(const QByteArray &data, const qint64 id);
  void slotRetrieveMail(const QByteArray &data, const qint64 id);
  void slotRetrieveMail(const QList<QByteArray> &list);
  void slotSendKeepAlive(void);
  void slotSendMail(const QList<QPair<QByteArray, qint64> > &list);
  void slotSendMailFromPostOffice(const QByteArray &data);
  void slotSendMessage(const QByteArray &data);
  void slotSendStatus(const QList<QByteArray> &list);
  void slotSendUuid(void);
  void slotTimeout(void);

 signals:
  void newEMailArrived(void);
  void receivedChatMessage(const QByteArray &data);
  void receivedChatMessage(const QByteArray &data, const qint64 id);
  void receivedMailMessage(const QByteArray &data, const qint64 id);
  void receivedPublicKey(const QByteArray &name, const QByteArray publicKey);
  void receivedStatusMessage(const QByteArray &data, const qint64 id);
  void retrieveMail(const QByteArray &data,
		    const QByteArray &publicKeyHash,
		    const QByteArray &signature);
  void retrieveMail(const QByteArray &data, const qint64 id);
};

#endif
