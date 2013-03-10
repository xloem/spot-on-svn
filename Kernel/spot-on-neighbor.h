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

#include <QHostAddress>
#include <QSqlDatabase>
#include <QTcpSocket>
#include <QTimer>

class spoton_neighbor: public QTcpSocket
{
  Q_OBJECT

 public:
  static quint64 s_dbId;
  spoton_neighbor(const QString &ipAddress,
		  const QString &port,
		  const QString &scopeId,
		  const qint64 id,
		  QObject *parent);
  spoton_neighbor(const int socketDescriptor,
		  QObject *parent);
  ~spoton_neighbor();
  qint64 id(void) const;
  void setId(const qint64 id);
  void sharePublicKey(const QByteArray &name,
		      const QByteArray &publicKey,
		      const QByteArray &symmetricKey,
		      const QByteArray &symmetricKeyAlgorithm);

 private:
  QByteArray m_data;
  QHostAddress m_address;
  QTimer m_lifetime;
  QTimer m_sendKeysTimer;
  QTimer m_timer;
  qint64 m_id;
  quint16 m_port;
  quint64 m_sendKeysOffset;
  void savePublicKey(const QByteArray &name,
		     const QByteArray &publicKey,
		     const QByteArray &symmetricKey,
		     const QByteArray &symmetricKeyAlgorithm);
  void savePublicKey(const QByteArray &publicKey);
  void saveStatus(QSqlDatabase &db, const QString &status);

 private slots:
  void slotConnected(void);
  void slotLifetimeExpired(void);
  void slotSendMessage(const QByteArray &message);
  void slotReadyRead(void);
  void slotReceivedChatMessage(const QByteArray &message, const qint64 id);
  void slotReceivedPublicKey(const QByteArray &publicKey, const qint64 id);
  void slotSendKeys(void);
  void slotTimeout(void);

 signals:
  void receivedChatMessage(const QByteArray &message);
  void receivedChatMessage(const QByteArray &message, const qint64 id);
  void receivedPublicKey(const QByteArray &name, const QByteArray publicKey);
  void receivedPublicKey(const QByteArray &publicKey, const qint64 id);
};

#endif
