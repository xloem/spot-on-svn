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

#include <QSocketNotifier>

#ifdef SPOTON_SCTP_ENABLED
#ifdef Q_OS_LINUX
extern "C"
{
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
#include <sys/socket.h>
#include <unistd.h>
}
#elif defined(Q_OS_MAC)
extern "C"
{
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
}
#elif defined(Q_OS_WIN32)
#endif
#endif

#include "spot-on-sctp-socket.h"

spoton_sctp_socket::spoton_sctp_socket(QObject *parent): QIODevice(parent)
{
  m_hostLookupId = -1;
  m_socketDescriptor = -1;
  m_socketReadNotifier = 0;
  m_socketWriteNotifier = 0;
  m_state = UnconnectedState;
}

spoton_sctp_socket::~spoton_sctp_socket()
{
  close();
}

QHostAddress spoton_sctp_socket::peerAddress(void) const
{
#ifdef SPOTON_SCTP_ENABLED
  return QHostAddress();
#else
  return QHostAddress();
#endif
}

void spoton_sctp_socket::close(void)
{
#ifdef SPOTON_SCTP_ENABLED
  QHostInfo::abortHostLookup(m_hostLookupId);
  QIODevice::close();

  if(m_socketReadNotifier)
    m_socketReadNotifier->deleteLater();

  if(m_socketWriteNotifier)
    m_socketWriteNotifier->deleteLater();

  ::close(m_socketDescriptor);
  m_hostLookupId = -1;
  m_ipAddress.clear();
  m_socketDescriptor = -1;
  m_state = UnconnectedState;
  emit disconnected();
#endif
}

void spoton_sctp_socket::connectToHost(const QString &hostName,
				       const quint16 port,
				       const OpenMode openMode)
{
#ifdef SPOTON_SCTP_ENABLED
  if(m_state != UnconnectedState)
    return;

  QIODevice::close();
  open(openMode);
  m_port = port;

  if(QHostAddress(hostName).isNull())
    {
      m_hostLookupId = QHostInfo::lookupHost
	(hostName, this, SLOT(slotHostFound(const QHostInfo &)));
      m_state = HostLookupState;
    }
  else
    {
      m_ipAddress = hostName;
      connectToHostImplementation();
    }
#else
  Q_UNUSED(hostName);
  Q_UNUSED(openMode);
  Q_UNUSED(port);
#endif
}

void spoton_sctp_socket::connectToHostImplementation(void)
{
#ifdef SPOTON_SCTP_ENABLED
  NetworkLayerProtocol protocol = IPv4Protocol;
  int rc = 0;

  if(QHostAddress(m_ipAddress).protocol() == QAbstractSocket::IPv6Protocol)
    protocol = IPv6Protocol;

  if(protocol == IPv4Protocol)
    m_socketDescriptor = socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP);
  else
    m_socketDescriptor = socket(AF_INET6, SOCK_SEQPACKET, IPPROTO_SCTP);

  if(m_socketDescriptor == -1)
    goto done_label;

  struct sockaddr_in servaddr;

  memset(&servaddr, 0, sizeof(servaddr));
  servaddr.sin_addr.s_addr = htonl(INADDR_ANY);

  if(protocol == IPv4Protocol)
    servaddr.sin_family = AF_INET;
  else
    servaddr.sin_family = AF_INET6;

  servaddr.sin_port = htons(m_port);

  if(protocol == IPv4Protocol)
    rc = inet_pton(AF_INET, m_ipAddress.toLatin1().constData(),
		   &servaddr.sin_addr);
  else
    rc = inet_pton(AF_INET6, m_ipAddress.toLatin1().constData(),
		   &servaddr.sin_addr);

  m_state = ConnectingState;

  if(rc != 1)
    goto done_label;

 done_label:
  if(rc != 0)
    close();
#endif
}

void spoton_sctp_socket::setReadBufferSize(const qint64 size)
{
#ifdef SPOTON_SCTP_ENABLED
  qint64 optval = size;
  socklen_t optlen = sizeof(optval);

  setsockopt(m_socketDescriptor, SOL_SOCKET, SO_RCVBUF, &optval, optlen);
#else
  Q_UNUSED(size);
#endif
}

void spoton_sctp_socket::setSocketOption(const SocketOption option,
					 const QVariant &value)
{
#ifdef SPOTON_SCTP_ENABLED
  switch(option)
    {
    case KeepAliveOption:
      {
	int optval = value.toInt();
	socklen_t optlen = sizeof(optval);

	setsockopt(m_socketDescriptor, SOL_SOCKET, SO_KEEPALIVE,
		   &optval, optlen);
	break;
      }
    case LowDelayOption:
      {
	int optval = value.toInt();
	socklen_t optlen = sizeof(optval);

	setsockopt(m_socketDescriptor, IPPROTO_SCTP, SCTP_NODELAY,
		   &optval, optlen);	
	break;
      }
    default:
      {
	break;
      }
    }
#else
  Q_UNUSED(option);
  Q_UNUSED(value);
#endif
}

void spoton_sctp_socket::slotHostFound(const QHostInfo &hostInfo)
{
#ifdef SPOTON_SCTP_ENABLED
  foreach(const QHostAddress &address, hostInfo.addresses())
    if(!address.isNull())
      {
	m_ipAddress = address.toString();
	connectToHostImplementation();
	break;
      }
#else
  Q_UNUSED(hostInfo);
#endif
}
