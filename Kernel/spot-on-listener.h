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
#include <QSqlDatabase>
#include <QQueue>
#include <QTcpServer>
#include <QTimer>

#include "spot-on-neighbor.h"

class QNetworkInterface;

class spoton_external_address;

class spoton_listener_tcp_server: public QTcpServer
{
  Q_OBJECT

 public:
  spoton_listener_tcp_server(const bool useSsl,
			     QObject *parent):QTcpServer(parent)
  {
    m_useSsl = useSsl;
  }

  QSslSocket *nextPendingConnection(void)
  {
    if(m_queue.isEmpty())
      return 0;
    else
      return m_queue.dequeue();
  }

#if QT_VERSION >= 0x050000
  void incomingConnection(qintptr socketDescriptor)
#else
  void incomingConnection(int socketDescriptor)
#endif
  {
    if(findChildren<spoton_neighbor *> ().size() >= maxPendingConnections())
      {
	QSslSocket socket;

	socket.setSocketDescriptor(socketDescriptor);
	socket.close();
      }
    else
      {
	QPointer<spoton_neighbor> neighbor = new spoton_neighbor
	  (socketDescriptor, m_useSsl, this);

	m_queue.enqueue(neighbor);
	emit encrypted();
      }
  }

 private:
  QQueue<QPointer<spoton_neighbor> > m_queue;
  bool m_useSsl;

 signals:
  void encrypted(void);
};

class spoton_listener: public spoton_listener_tcp_server
{
  Q_OBJECT

 public:
  static qint64 s_dbId;
  spoton_listener(const QString &ipAddress,
		  const QString &port,
		  const QString &scopeId,
		  const int maximumClients,
		  const qint64 id,
		  const bool useSsl,
		  QObject *parent);
  ~spoton_listener();
  QHostAddress externalAddress(void) const;
  bool useSsl(void) const;
  quint16 externalPort(void) const;

 private:
  QHostAddress m_address;
  QNetworkInterface *m_networkInterface;
  QTimer m_externalAddressDiscovererTimer;
  QTimer m_timer;
  bool m_useSsl;
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
  void slotEncrypted(void);
  void slotExternalAddressDiscovered(const QHostAddress &address);
  void slotNeighborDisconnected(void);
  void slotTimeout(void);

 signals:
  void newNeighbor(QPointer<spoton_neighbor> neighbor);
};

#endif
