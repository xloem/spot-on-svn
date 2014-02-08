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

#ifndef _spoton_sctp_socket_h_
#define _spoton_sctp_socket_h_

#include <QHostInfo>
#include <QIODevice>
#include <QPointer>

class QSocketNotifier;

class spoton_sctp_socket: public QIODevice
{
  Q_OBJECT

 public:
  enum NetworkLayerProtocol
  {
    IPv4Protocol = 0,
    IPv6Protocol = 1
  };

  enum SocketOption
  {
    KeepAliveOption = 1,
    LowDelayOption = 0
  };

  enum SocketState
  {
    ConnectedState = 4,
    ConnectingState = 3,
    HostLookupState = 2,
    UnconnectedState = 1
  };

 public:
  spoton_sctp_socket(QObject *parent);
  ~spoton_sctp_socket();
  QHostAddress peerAddress(void) const;
  void close(void);
  void connectToHost(const QString &hostName, const quint16 port,
		     const OpenMode openMode = ReadWrite);
  void setReadBufferSize(const qint64 size);
  void setSocketOption(const SocketOption option,
		       const QVariant &value);

 private:
  QPointer<QSocketNotifier> m_socketReadNotifier;
  QPointer<QSocketNotifier> m_socketWriteNotifier;
  QString m_ipAddress;
  SocketState m_state;
  int m_hostLookupId;
  int m_socketDescriptor;
  quint16 m_port;
  void connectToHostImplementation(void);

 private slots:
  void slotHostFound(const QHostInfo &hostInfo);

 signals:
  void connected(void);
  void disconnected(void);
};

#endif
