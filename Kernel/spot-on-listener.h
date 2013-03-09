/*
** Copyright (c) 2012 Alexis Megas
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

class spoton_listener_tcp_server: public QTcpServer
{
  Q_OBJECT

 public:
  spoton_listener_tcp_server(QObject *parent):QTcpServer(parent)
  {
  }

  QTcpSocket *nextPendingConnection(void)
  {
    if(m_queue.isEmpty())
      return 0;
    else
      return m_queue.dequeue();
  }

  void incomingConnection(int socketDescriptor)
  {
    QPointer<spoton_neighbor> neighbor = new spoton_neighbor
      (socketDescriptor, this);

    m_queue.enqueue(neighbor);
  }

 private:
  QQueue<QPointer<spoton_neighbor> > m_queue;
};

class spoton_listener: public spoton_listener_tcp_server
{
  Q_OBJECT

 public:
  static quint64 s_dbId;
  spoton_listener(const QString &ipAddress,
		  const QString &port,
		  const QString &scopeId,
		  const int maximumClients,
		  const qint64 id,
		  QObject *parent);
  ~spoton_listener();

 private:
  QHostAddress m_address;
  QTimer m_timer;
  int m_connections;
  qint64 m_id;
  quint16 m_port;
  qint64 id(void) const;
  void saveStatus(QSqlDatabase &db);
  void updateConnectionCount(void);

 private slots:
  void slotNeighborDisconnected(void);
  void slotNewConnection(void);
  void slotTimeout(void);

 signals:
  void newNeighbor(QPointer<spoton_neighbor> neighbor);
};

#endif
