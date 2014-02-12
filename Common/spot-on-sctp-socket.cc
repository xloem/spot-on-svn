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
#include <fcntl.h>
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
#include <fcntl.h>
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

/*
** Please read http://gcc.gnu.org/onlinedocs/gcc-4.4.1/gcc/Optimize-Options.html#Type_002dpunning.
*/

typedef union type_punning_sockaddr
{
    struct sockaddr sockaddr;
    struct sockaddr_in sockaddr_in;
    struct sockaddr_in6 sockaddr_in6;
    struct sockaddr_storage sockaddr_storage;
}
type_punning_sockaddr_t;

spoton_sctp_socket::spoton_sctp_socket(QObject *parent):QObject(parent)
{
  m_hostLookupId = -1;
  m_port = 0;
  m_readBufferSize = 0;
  m_socketDescriptor = -1;
  m_socketReadNotifier = 0;
  m_socketWriteNotifier = 0;
  m_state = UnconnectedState;
}

spoton_sctp_socket::~spoton_sctp_socket()
{
  close();
}

QHostAddress spoton_sctp_socket::localAddress(void) const
{
#ifdef SPOTON_SCTP_ENABLED
  return localAddressAndPort(0);
#else
  return QHostAddress();
#endif
}

QHostAddress spoton_sctp_socket::localAddressAndPort(quint16 *port) const
{
#ifdef SPOTON_SCTP_ENABLED
  if(m_socketDescriptor < 0)
    {
      if(port)
	*port = 0;

      return QHostAddress();
    }

  if(port)
    *port = 0;

  QHostAddress address;
  socklen_t length = 0;
  struct sockaddr_storage peeraddr;

  length = sizeof(peeraddr);

  if(getsockname(m_socketDescriptor, (struct sockaddr *) &peeraddr,
		 &length) == 0)
    {
      if(peeraddr.ss_family == AF_INET)
	{
	  type_punning_sockaddr_t *sockaddr =
	    (type_punning_sockaddr_t *) &peeraddr;

	  if(sockaddr)
	    {
	      address.setAddress
		(ntohl(sockaddr->sockaddr_in.sin_addr.s_addr));

	      if(port)
		*port = ntohs(sockaddr->sockaddr_in.sin_port);
	    }
	}
      else
	{
	  type_punning_sockaddr_t *sockaddr =
	    (type_punning_sockaddr_t *) &peeraddr;

	  if(sockaddr)
	    {
	      Q_IPV6ADDR tmp;

	      memcpy(&tmp, &sockaddr->sockaddr_in6.sin6_addr.s6_addr,
		     sizeof(tmp));
	      address.setAddress(tmp);
	      address.setScopeId
		(QString::number(sockaddr->sockaddr_in6.sin6_scope_id));

	      if(port)
		*port = ntohs(sockaddr->sockaddr_in6.sin6_port);
	    }
	}
    }

  return address;
#else
  return QHostAddress();
#endif
}

QHostAddress spoton_sctp_socket::peerAddress(void) const
{
#ifdef SPOTON_SCTP_ENABLED
  return peerAddressAndPort(0);
#else
  return QHostAddress();
#endif
}

QHostAddress spoton_sctp_socket::peerAddressAndPort(quint16 *port) const
{
#ifdef SPOTON_SCTP_ENABLED
  if(m_socketDescriptor < 0)
    {
      if(port)
	*port = 0;

      return QHostAddress();
    }

  if(port)
    *port = 0;

  QHostAddress address;
  socklen_t length = 0;
  struct sockaddr_storage peeraddr;

  length = sizeof(peeraddr);

  if(getpeername(m_socketDescriptor, (struct sockaddr *) &peeraddr,
		 &length) == 0)
    {
      if(peeraddr.ss_family == AF_INET)
	{
	  type_punning_sockaddr_t *sockaddr =
	    (type_punning_sockaddr_t *) &peeraddr;

	  if(sockaddr)
	    {
	      address.setAddress
		(ntohl(sockaddr->sockaddr_in.sin_addr.s_addr));

	      if(port)
		*port = ntohs(sockaddr->sockaddr_in.sin_port);
	    }
	}
      else
	{
	  type_punning_sockaddr_t *sockaddr =
	    (type_punning_sockaddr_t *) &peeraddr;

	  if(sockaddr)
	    {
	      Q_IPV6ADDR tmp;

	      memcpy(&tmp, &sockaddr->sockaddr_in6.sin6_addr.s6_addr,
		     sizeof(tmp));
	      address.setAddress(tmp);
	      address.setScopeId
		(QString::number(sockaddr->sockaddr_in6.sin6_scope_id));

	      if(port)
		*port = ntohs(sockaddr->sockaddr_in6.sin6_port);
	    }
	}
    }

  return address;
#else
  return QHostAddress();
#endif
}

QString spoton_sctp_socket::peerName(void) const
{
#ifdef SPOTON_SCTP_ENABLED
  return m_peerName;
#else
  return QString();
#endif
}

spoton_sctp_socket::SocketState spoton_sctp_socket::state(void) const
{
#ifdef SPOTON_SCTP_ENABLED
  return m_state;
#else
  return UnconnectedState;
#endif
}

bool spoton_sctp_socket::setSocketDescriptor(const int socketDescriptor)
{
#ifdef SPOTON_SCTP_ENABLED
  if(socketDescriptor >= 0)
    {
      close();
      m_socketDescriptor = socketDescriptor;
      return true;
    }
  else
    return false;
#else
  Q_UNUSED(socketDescriptor);
  return false;
#endif
}

int spoton_sctp_socket::inspectConnectResult
(const int rc, const int errorcode)
{
#ifdef SPOTON_SCTP_ENABLED
  if(rc == -1)
    {
      if(errorcode == EINPROGRESS)
	return 0;
      else if(errorcode == EACCES ||
	      errorcode == EPERM)
	emit error("inspectConnectResult()", SocketAccessError);
      else if(errorcode == EALREADY)
	emit error("inspectConnectResult()", UnfinishedSocketOperationError);
      else if(errorcode == ECONNREFUSED)
	emit error("inspectConnectResult()", ConnectionRefusedError);
      else if(errorcode == ENETUNREACH)
	emit error("inspectConnectResult()", NetworkError);
      else
	emit error("inspectConnectResult()", UnknownSocketError);

      return rc;
    }
  else
    return rc;
#else
  Q_UNUSED(errorcode);
  Q_UNUSED(rc);
  return -1;
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
      if(errno == EAGAIN ||
	 errno == EWOULDBLOCK)
	{
	  /*
	  ** We'll ignore this condition.
	  */

	  rc = 0;
	}
      else if(errno == ECONNRESET)
	emit error("readData()::recv()", RemoteHostClosedError);
      else if(errno == ENOBUFS)
	emit error("readData()::recv()", SocketResourceError);
      else if(errno == ENOTCONN)
	emit error("readData()::recv()", NetworkError);
      else if(errno == EOPNOTSUPP)
	emit error("readData()::recv()", UnsupportedSocketOperationError);
      else
	emit error("readData()::recv()", UnknownSocketError);
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
  if(!data || maxSize <= 0)
    return 0;

  ssize_t rc = send
    (m_socketDescriptor, data, static_cast<size_t> (maxSize), MSG_DONTWAIT);

  if(rc == -1)
    {
      if(errno == EACCES)
	emit error("writeData()::send()", SocketAccessError);
      else if(errno == EAGAIN ||
	      errno == EWOULDBLOCK)
	{
	  /*
	  ** We'll ignore this condition.
	  */

	  rc = 0;
	}
      else if(errno == ECONNRESET)
	emit error("writeData()::send()", RemoteHostClosedError);
      else if(errno == EMSGSIZE ||
	      errno == ENOBUFS ||
	      errno == ENOMEM)
	emit error("writeData()::send()", SocketResourceError);
      else if(errno == EHOSTUNREACH ||
	      errno == ENETDOWN ||
	      errno == ENETUNREACH ||
	      errno == ENOTCONN)
	emit error("writeData()::send()", NetworkError);
      else if(errno == EOPNOTSUPP)
	emit error("writeData()::send()", UnsupportedSocketOperationError);
      else
	emit error("writeData()::send()", UnknownSocketError);
    }

  return static_cast<qint64> (rc);
#else
  Q_UNUSED(data);
  Q_UNUSED(maxSize);
  return 0;
#endif
}

quint16 spoton_sctp_socket::localPort(void) const
{
#ifdef SPOTON_SCTP_ENABLED
  quint16 port = 0;

  localAddressAndPort(&port);
  return port;
#else
  return 0;
#endif
}

quint16 spoton_sctp_socket::peerPort(void) const
{
#ifdef SPOTON_SCTP_ENABLED
  quint16 port = 0;

  peerAddressAndPort(&port);
  return port;
#else
  return 0;
#endif
}

void spoton_sctp_socket::close(void)
{
#ifdef SPOTON_SCTP_ENABLED
  QHostInfo::abortHostLookup(m_hostLookupId);

  if(m_socketReadNotifier)
    m_socketReadNotifier->deleteLater();

  if(m_socketWriteNotifier)
    m_socketWriteNotifier->deleteLater();

  ::close(m_socketDescriptor);
  m_hostLookupId = -1;
  m_ipAddress.clear();
  m_peerName.clear();
  m_port = 0;
  m_readBuffer.clear();
  m_socketDescriptor = -1;
  m_state = UnconnectedState;
  emit disconnected();
#endif
}

void spoton_sctp_socket::connectToHost(const QString &hostName,
				       const quint16 port)
{
#ifdef SPOTON_SCTP_ENABLED
  if(m_state != UnconnectedState)
    return;

  m_peerName = hostName;
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
  Q_UNUSED(port);
#endif
}

void spoton_sctp_socket::connectToHostImplementation(void)
{
#ifdef SPOTON_SCTP_ENABLED
  NetworkLayerProtocol protocol = IPv4Protocol;
  int rc = 0;
  qint64 optval = 0;
  socklen_t optlen = sizeof(optval);

  if(QHostAddress(m_ipAddress).protocol() == QAbstractSocket::IPv6Protocol)
    protocol = IPv6Protocol;

  if(protocol == IPv4Protocol)
    m_socketDescriptor = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
  else
    m_socketDescriptor = socket(AF_INET6, SOCK_STREAM, IPPROTO_SCTP);

  if(m_socketDescriptor == -1)
    {
      rc = -1;

      if(errno == EACCES)
	emit error("connectToHostImplementation()::socket()",
		   SocketAccessError);
      else if(errno == EAFNOSUPPORT ||
	      errno == EPROTONOSUPPORT)
	emit error("connectToHostImplementation()::socket()",
		   UnsupportedSocketOperationError);
      else if(errno == EISCONN ||
	      errno == EMFILE ||
	      errno == ENFILE ||
	      errno == ENOBUFS ||
	      errno == ENOMEM)
	emit error("connectToHostImplementation()::socket()",
		   SocketResourceError);
      else
	emit error("connectToHostImplementation()::socket()",
		   UnknownSocketError);

      goto done_label;
    }

  rc = fcntl(m_socketDescriptor, F_GETFL, 0);

  if(rc == -1)
    {
      emit error("connectToHostImplementation()::fcntl()",
		 UnknownSocketError);
      goto done_label;
    }

  if(fcntl(m_socketDescriptor, F_SETFL, O_NONBLOCK | rc) == -1)
    {
      emit error("connectToHostImplementation()::fcntl()",
		 UnknownSocketError);
      goto done_label;
    }

  prepareSocketNotifiers();
  optval = 8192;
  setsockopt(m_socketDescriptor, SOL_SOCKET, SO_RCVBUF, &optval, optlen);
  setsockopt(m_socketDescriptor, SOL_SOCKET, SO_SNDBUF, &optval, optlen);

  if(protocol == IPv4Protocol)
    {
      socklen_t length = 0;
      struct sockaddr_in servaddr;

      length = sizeof(servaddr);
      memset(&servaddr, 0, sizeof(servaddr));
      servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
      servaddr.sin_family = AF_INET;
      servaddr.sin_port = htons(m_port);
      rc = inet_pton(AF_INET, m_ipAddress.toLatin1().constData(),
		     &servaddr.sin_addr);

      if(rc != 1)
	{
	  if(rc == -1)
	    {
	      if(errno == EAFNOSUPPORT)
		emit error("connectToHostImplementation()::inet_pton()",
			   UnsupportedSocketOperationError);
	      else
		emit error("connectToHostImplementation()::inet_pton()",
			   UnknownSocketError);
	    }
	  else
	    emit error("connectToHostImplementation()::inet_pton()",
		       UnknownSocketError);

	  goto done_label;
	}
      else
	rc = 0;

      m_state = ConnectingState;
      rc = ::connect
	(m_socketDescriptor, (const struct sockaddr *) &servaddr, length);
      rc = inspectConnectResult(rc, errno);
    }
  else
    {
      socklen_t length = 0;
      struct sockaddr_in6 servaddr;

      length = sizeof(servaddr);
      memset(&servaddr, 0, sizeof(servaddr));
      servaddr.sin6_addr = in6addr_any;
      servaddr.sin6_family = AF_INET6;
      servaddr.sin6_port = htons(m_port);
      rc = inet_pton(AF_INET6, m_ipAddress.toLatin1().constData(),
		     &servaddr.sin6_addr);

      if(rc != 1)
	{
	  if(rc == -1)
	    {
	      if(errno == EAFNOSUPPORT)
		emit error("connectToHostImplementation()::inet_pton()",
			   UnsupportedSocketOperationError);
	      else
		emit error("connectToHostImplementation()::inet_pton()",
			   UnknownSocketError);
	    }
	  else
	    emit error("connectToHostImplementation()::inet_pton()",
		       UnknownSocketError);

	  goto done_label;
	}
      else
	rc = 0;

      m_state = ConnectingState;
      rc = ::connect
	(m_socketDescriptor, (const struct sockaddr *) &servaddr, length);
      rc = inspectConnectResult(rc, errno);
    }

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

  if(m_socketReadNotifier)
    m_socketReadNotifier->deleteLater();

  if(m_socketWriteNotifier)
    m_socketWriteNotifier->deleteLater();

  m_socketReadNotifier = new QSocketNotifier(m_socketDescriptor,
					     QSocketNotifier::Read,
					     this);
  connect(m_socketReadNotifier,
	  SIGNAL(activated(int)),
	  this,
	  SLOT(slotSocketNotifierActivated(int)));
  m_socketReadNotifier->setEnabled(true);
  m_socketWriteNotifier = new QSocketNotifier(m_socketDescriptor,
					      QSocketNotifier::Write,
					      this);
  connect(m_socketWriteNotifier,
	  SIGNAL(activated(int)),
	  this,
	  SLOT(slotSocketNotifierActivated(int)));
  m_socketWriteNotifier->setEnabled(true);
#endif
}

void spoton_sctp_socket::setReadBufferSize(const qint64 size)
{
#ifdef SPOTON_SCTP_ENABLED
  m_readBufferSize =
    qBound(spoton_common::MAXIMUM_NEIGHBOR_CONTENT_LENGTH,
	   size,
	   spoton_common::MAXIMUM_NEIGHBOR_BUFFER_SIZE);
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

void spoton_sctp_socket::slotClose(void)
{
#ifdef SPOTON_SCTP_ENABLED
  close();
#endif
}

void spoton_sctp_socket::slotHostFound(const QHostInfo &hostInfo)
{
#ifdef SPOTON_SCTP_ENABLED
  m_ipAddress.clear();

  foreach(const QHostAddress &address, hostInfo.addresses())
    if(!address.isNull())
      {
	/*
	** In the future, we'll need attempt several connections.
	*/

	m_ipAddress = address.toString();
	connectToHostImplementation();
	break;
      }

  if(QHostAddress(m_ipAddress).isNull())
    emit error("slotHostFound()", HostNotFoundError);
#else
  Q_UNUSED(hostInfo);
#endif
}

void spoton_sctp_socket::slotSocketNotifierActivated(int socket)
{
#ifdef SPOTON_SCTP_ENABLED
  QSocketNotifier *socketNotifier = qobject_cast<QSocketNotifier *>
    (sender());

  if(!socketNotifier)
    return;

  if(m_socketReadNotifier == socketNotifier)
    {
      socketNotifier->setEnabled(false);

      QByteArray data(static_cast<int> (m_readBufferSize), 0);
      qint64 rc = readData(data.data(), data.length());

      if(rc > 0)
	{
	  if(m_readBuffer.size() + static_cast<int> (rc) <= m_readBufferSize)
	    m_readBuffer.append(data.mid(0, static_cast<int> (rc)));

	  socketNotifier->setEnabled(true);
	}

      if(rc > 0)
	emit readyRead();
      else
	{
	  m_socketWriteNotifier->setEnabled(false);
	  close();
	}
    }
  else
    {
      socketNotifier->setEnabled(false);

      int errorcode = 0;
      int rc = 0;
      socklen_t length = sizeof(errorcode);

      rc = getsockopt(socket, SOL_SOCKET, SO_ERROR, &errorcode, &length);

      if(rc == 0)
	{
	  if(errorcode == 0)
	    {
	      if(m_state == ConnectingState)
		{
		  m_state = ConnectedState;
		  emit connected();
		}
	    }
	  else
	    socketNotifier->setEnabled(true);
	}
      else
	{
	  m_socketReadNotifier->setEnabled(false);
	  close();
	}
    }
#else
  Q_UNUSED(socket);
#endif
}
