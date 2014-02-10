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
#ifdef Q_OS_FREEBSD
#elif defined(Q_OS_LINUX)
extern "C"
{
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
}
#elif defined(Q_OS_MAC)
extern "C"
{
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
}
#elif defined(Q_OS_WIN32)
#endif
#endif

#include "Common/spot-on-common.h"
#include "spot-on-sctp-socket.h"

spoton_sctp_socket::spoton_sctp_socket(QObject *parent):QIODevice(parent)
{
  m_hostLookupId = -1;
  m_readBufferSize = 0;
  m_socketDescriptor = -1;
  m_socketExceptionNotifier = 0;
  m_socketReadNotifier = 0;
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

qint64 spoton_sctp_socket::readData(char *data, qint64 maxSize)
{
#ifdef SPOTON_SCTP_ENABLED
  if(!data || maxSize <= 0)
    return 0;

  ssize_t rc = recv
    (m_socketDescriptor, data, static_cast<size_t> (maxSize), MSG_PEEK);

  if(rc > 0)
    rc = recv
      (m_socketDescriptor, data, static_cast<size_t> (rc), MSG_WAITALL);

  if(rc == -1)
    {
      if(errno == ECONNRESET)
	emit error(RemoteHostClosedError);
      else if(errno == ENOBUFS)
	emit error(SocketResourceError);
      else if(errno == ENOTCONN)
	emit error(NetworkError);
      else if(errno == EOPNOTSUPP)
	emit error(UnsupportedSocketOperationError);
      else
	emit error(UnknownSocketError);
    }

  return static_cast<qint64> (rc);
#else
  Q_UNUSED(data);
  Q_UNUSED(maxSize);
  return 0;
#endif
}

qint64 spoton_sctp_socket::write(const char *data, qint64 maxSize)
{
#ifdef SPOTON_SCTP_ENABLED
  return writeData(data, maxSize);
#else
  Q_UNUSED(data);
  Q_UNUSED(maxSize);
  return 0;
#endif
}

qint64 spoton_sctp_socket::writeData(const char *data, const qint64 maxSize)
{
#ifdef SPOTON_SCTP_ENABLED
  ssize_t rc = send
    (m_socketDescriptor, data, static_cast<size_t> (maxSize), MSG_DONTWAIT);

  if(rc == -1)
    {
      if(errno == EACCES)
	emit error(SocketAccessError);
      else if(errno == ECONNRESET)
	emit error(RemoteHostClosedError);
      else if(errno == EMSGSIZE ||
	      errno == ENOBUFS ||
	      errno == ENOMEM)
	emit error(SocketResourceError);
      else if(errno == EHOSTUNREACH ||
	      errno == ENETDOWN ||
	      errno == ENETUNREACH ||
	      errno == ENOTCONN)
	emit error(NetworkError);
      else if(errno == EOPNOTSUPP)
	emit error(UnsupportedSocketOperationError);
      else
	emit error(UnknownSocketError);
    }

  return static_cast<qint64> (rc);
#else
  Q_UNUSED(data);
  Q_UNUSED(maxSize);
  return 0;
#endif
}

void spoton_sctp_socket::close(void)
{
#ifdef SPOTON_SCTP_ENABLED
  QHostInfo::abortHostLookup(m_hostLookupId);
  QIODevice::close();

  if(m_socketExceptionNotifier)
    m_socketExceptionNotifier->deleteLater();

  if(m_socketReadNotifier)
    m_socketReadNotifier->deleteLater();

  ::close(m_socketDescriptor);
  m_hostLookupId = -1;
  m_ipAddress.clear();
  m_readBuffer.clear();
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

  if(!isOpen())
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
    m_socketDescriptor = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
  else
    m_socketDescriptor = socket(AF_INET6, SOCK_STREAM, IPPROTO_SCTP);

  if(m_socketDescriptor == -1)
    {
      if(errno == EACCES)
	emit error(SocketAccessError);
      else if(errno == EAFNOSUPPORT ||
	      errno == EPROTONOSUPPORT)
	emit error(UnsupportedSocketOperationError);
      else if(errno == EISCONN ||
	      errno == EMFILE ||
	      errno == ENFILE ||
	      errno == ENOBUFS ||
	      errno == ENOMEM)
	emit error(SocketResourceError);
      else
	emit error(UnknownSocketError);

      goto done_label;
    }

  if(protocol == IPv4Protocol)
    {
      struct sockaddr_in servaddr;

      memset(&servaddr, 0, sizeof(servaddr));
      servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
      servaddr.sin_family = AF_INET;
      servaddr.sin_port = htons(m_port);
      rc = inet_pton(AF_INET, m_ipAddress.toLatin1().constData(),
		     &servaddr.sin_addr);
    }
  else
    {
      struct sockaddr_in6 servaddr;

      memset(&servaddr, 0, sizeof(servaddr));
      servaddr.sin6_addr = in6addr_any;
      servaddr.sin6_family = AF_INET6;
      servaddr.sin6_port = htons(m_port);
      rc = inet_pton(AF_INET6, m_ipAddress.toLatin1().constData(),
		     &servaddr.sin6_addr);
    }

  if(rc != 1)
    {
      if(rc == -1)
	{
	  if(errno == EAFNOSUPPORT)
	    emit error(UnsupportedSocketOperationError);
	  else
	    emit error(UnknownSocketError);
	}
      else
	emit error(UnknownSocketError);

      goto done_label;
    }
  else
    rc = 0;

  m_state = ConnectingState;

 done_label:
  if(rc != 0)
    close();
#endif
}

void spoton_sctp_socket::prepareSocketNotifiers(void)
{
#ifdef SPOTON_SCTP_ENABLED
  if(m_socketDescriptor < 0)
    return;

  if(m_socketExceptionNotifier)
    m_socketExceptionNotifier->deleteLater();

  if(m_socketReadNotifier)
    m_socketReadNotifier->deleteLater();

  m_socketExceptionNotifier = new QSocketNotifier(m_socketDescriptor,
						  QSocketNotifier::Exception,
						  this);
  connect(m_socketExceptionNotifier,
	  SIGNAL(activated(int)),
	  this,
	  SLOT(slotSocketNotifierActivated(int)));
  m_socketExceptionNotifier->setEnabled(true);
  m_socketReadNotifier = new QSocketNotifier(m_socketDescriptor,
					     QSocketNotifier::Read,
					     this);
  connect(m_socketReadNotifier,
	  SIGNAL(activated(int)),
	  this,
	  SLOT(slotSocketNotifierActivated(int)));
  m_socketReadNotifier->setEnabled(true);
#endif
}

void spoton_sctp_socket::setReadBufferSize(const qint64 size)
{
#ifdef SPOTON_SCTP_ENABLED
  m_readBufferSize =
    qBound(spoton_common::MAXIMUM_NEIGHBOR_CONTENT_LENGTH,
	   size,
	   spoton_common::MAXIMUM_NEIGHBOR_BUFFER_SIZE);

  qint64 optval = m_readBufferSize;
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
  m_ipAddress.clear();

  foreach(const QHostAddress &address, hostInfo.addresses())
    if(!address.isNull())
      {
	m_ipAddress = address.toString();
	connectToHostImplementation();
	break;
      }

  if(QHostAddress(m_ipAddress).isNull())
    emit error(HostNotFoundError);
#else
  Q_UNUSED(hostInfo);
#endif
}

void spoton_sctp_socket::slotSocketNotifierActivated(int socket)
{
#ifdef SPOTON_SCTP_ENABLED
  Q_UNUSED(socket);

  QSocketNotifier *socketNotifier = qobject_cast<QSocketNotifier *>
    (sender());

  if(!socketNotifier)
    return;

  socketNotifier->setEnabled(false);

  if(m_socketReadNotifier == socketNotifier)
    {
      QByteArray data(static_cast<int> (m_readBufferSize), 0);
      qint64 rc = readData(data.data(), data.length());

      if(rc > 0)
	{
	  if(m_readBuffer.size() + static_cast<int> (rc) <= m_readBufferSize)
	    m_readBuffer.append(data.mid(0, static_cast<int> (rc)));

	  emit readyRead();
	}
    }

  socketNotifier->setEnabled(true);
#else
  Q_UNUSED(socket);
#endif
}
