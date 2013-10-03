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

#ifndef _spoton_listener_h_
#define _spoton_listener_h_

#include <QPointer>
#include <QQueue>
#include <QSqlDatabase>
#include <QTcpServer>
#include <QTimer>

#include "Common/spot-on-misc.h"
#include "spot-on-neighbor.h"

class QNetworkInterface;

class spoton_external_address;

class spoton_listener_tcp_server: public QTcpServer
{
  Q_OBJECT

 public:
  spoton_listener_tcp_server(QObject *parent):QTcpServer(parent)
  {
  }

  ~spoton_listener_tcp_server()
  {
  }

#if QT_VERSION >= 0x050000
  void incomingConnection(qintptr socketDescriptor);
#else
  void incomingConnection(int socketDescriptor);
#endif

 signals:
#if QT_VERSION >= 0x050000
  void newConnection(qintptr socketDescriptor);
#else
  void newConnection(int socketDescriptor);
#endif
};

class spoton_listener: public spoton_listener_tcp_server
{
  Q_OBJECT

 public:
  spoton_listener(const QString &ipAddress,
		  const QString &port,
		  const QString &scopeId,
		  const int maximumClients,
		  const qint64 id,
		  const QString &echoMode,
		  const int keySize,
		  const QByteArray &certificate,
		  const QByteArray &privateKey,
		  const QByteArray &publicKey,
		  const bool useAccounts,
		  QObject *parent);
  ~spoton_listener();
  QHostAddress externalAddress(void) const;
  QHostAddress serverAddress(void) const;
  quint16 externalPort(void) const;
  quint16 serverPort(void) const;

 private:
  QByteArray m_certificate;
  QByteArray m_privateKey;
  QByteArray m_publicKey;
  QHostAddress m_address;
  QNetworkInterface *m_networkInterface;
  QString m_echoMode;
  QTimer m_externalAddressDiscovererTimer;
  QTimer m_timer;
  bool m_useAccounts;
  int m_keySize;
  qint64 m_id;
  quint16 m_externalPort;
  quint16 m_port;
  spoton_external_address *m_externalAddress;
  qint64 id(void) const;
  void prepareNetworkInterface(void);
  void saveExternalAddress(const QHostAddress &address,
			   const QSqlDatabase &db);
  void saveStatus(const QSqlDatabase &db);
  void updateConnectionCount(void);

 private slots:
  void slotDiscoverExternalAddress(void);
  void slotExternalAddressDiscovered(const QHostAddress &address);
  void slotNeighborDisconnected(void);
#if QT_VERSION >= 0x050000
  void slotNewConnection(const qintptr socketDescriptor);
#else
  void slotNewConnection(const int socketDescriptor);
#endif
  void slotTimeout(void);

 signals:
  void newNeighbor(QPointer<spoton_neighbor> neighbor);
};

#endif
