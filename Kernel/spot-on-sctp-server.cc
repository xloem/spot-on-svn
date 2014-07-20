/*
** Copyright (c) 2011 - 10^10^10, Alexis Megas.
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

#include <QAbstractSocket>

#ifdef SPOTON_SCTP_ENABLED
#ifdef Q_OS_FREEBSD
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
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <usrsctp.h>
}
#elif defined(Q_OS_WIN32)
extern "C"
{
#include <winsock2.h>
#include <ws2sctp.h>
}
#endif
#endif

#include "Common/spot-on-common.h"
#include "Common/spot-on-misc.h"
#include "spot-on-kernel.h"
#include "spot-on-sctp-server.h"

spoton_sctp_server::spoton_sctp_server(const qint64 id,
				       QObject *parent):QObject(parent)
{
  m_backlog = 30;
  m_bufferSize = 65535;
  m_id = id;
  m_isListening = false;
  m_serverPort = 0;
  m_socketDescriptor = -1;
  m_timer.setInterval(100);
  connect(&m_timer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotTimeout(void)));
}

spoton_sctp_server::~spoton_sctp_server()
{
  m_timer.stop();
  close();
}

QHostAddress spoton_sctp_server::serverAddress(void) const
{
#ifdef SPOTON_SCTP_ENABLED
  return m_serverAddress;
#else
  return QHostAddress();
#endif
}

QString spoton_sctp_server::errorString(void) const
{
#ifdef SPOTON_SCTP_ENABLED
  return m_errorString;
#else
  return QString();
#endif
}

bool spoton_sctp_server::isListening(void) const
{
#ifdef SPOTON_SCTP_ENABLED
  return m_isListening;
#else
  return false;
#endif
}

bool spoton_sctp_server::listen(const QHostAddress &address,
				const quint16 port)
{
#ifdef SPOTON_SCTP_ENABLED
  if(m_isListening)
    return true;
  else if(m_socketDescriptor > -1)
    return m_isListening;

  QAbstractSocket::NetworkLayerProtocol protocol =
    QAbstractSocket::IPv4Protocol;
  int optval = 0;
  int rc = 0;
  socklen_t optlen = sizeof(optval);
#ifdef Q_OS_WIN32
  unsigned long enabled = 1;
#endif

  if(QHostAddress(address).protocol() == QAbstractSocket::IPv6Protocol)
    protocol = QAbstractSocket::IPv6Protocol;

  if(protocol == QAbstractSocket::IPv4Protocol)
    m_socketDescriptor = rc = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
  else
    m_socketDescriptor = rc = socket(AF_INET6, SOCK_STREAM, IPPROTO_SCTP);

  if(rc == -1)
    {
#ifdef Q_OS_WIN32
      m_errorString = QString("listen()::socket()::error=%1").arg
	(WSAGetLastError());
#else
      m_errorString = QString("listen()::socket()::errno=%1").arg(errno);
#endif
      goto done_label;
    }

#ifdef Q_OS_WIN32
  rc = ioctlsocket(m_socketDescriptor, FIONBIO, &enabled);

  if(rc != 0)
    {
      m_errorString = "listen()::fcntl()::ioctlsocket()";
      goto done_label;
    }
#else
  rc = fcntl(m_socketDescriptor, F_GETFL, 0);

  if(rc == -1)
    {
      m_errorString = QString("listen()::fcntl()::errno=%1").arg(errno);
      goto done_label;
    }

  rc = fcntl(m_socketDescriptor, F_SETFL, O_NONBLOCK | rc);

  if(rc == -1)
    {
      m_errorString = QString("listen()::fcntl()::errno=%1").arg(errno);
      goto done_label;
    }
#endif
  rc = 0;

  /*
  ** Set the read and write buffer sizes.
  */

  optval = m_bufferSize;
#ifdef Q_OS_WIN32
  setsockopt
    (m_socketDescriptor, SOL_SOCKET, SO_RCVBUF, (const char *) &optval,
     optlen);
#else
  setsockopt(m_socketDescriptor, SOL_SOCKET, SO_RCVBUF, &optval, optlen);
#endif
  optval = 1;
#ifdef Q_OS_WIN32
  setsockopt
    (m_socketDescriptor, SOL_SOCKET, SO_REUSEADDR, (const char *) &optval,
     optlen);
#else
  setsockopt(m_socketDescriptor, SOL_SOCKET, SO_REUSEADDR, &optval, optlen);
#endif
  optval = m_bufferSize;
#ifdef Q_OS_WIN32
  setsockopt
    (m_socketDescriptor, SOL_SOCKET, SO_SNDBUF, (const char *) &optval,
     optlen);
#else
  setsockopt(m_socketDescriptor, SOL_SOCKET, SO_SNDBUF, &optval, optlen);
#endif

  /*
  ** Let's bind.
  */

  if(protocol == QAbstractSocket::IPv4Protocol)
    {
      socklen_t length = 0;
      struct sockaddr_in serveraddr;

      length = sizeof(serveraddr);
      memset(&serveraddr, 0, sizeof(serveraddr));
      serveraddr.sin_family = AF_INET;
      serveraddr.sin_port = htons(port);
#ifdef Q_OS_WIN32
      rc = WSAStringToAddressA((LPSTR) address.toString().toLatin1().data(),
			       AF_INET, 0, (LPSOCKADDR) &serveraddr, &length);
#else
      rc = inet_pton(AF_INET, address.toString().toLatin1().constData(),
		     &serveraddr.sin_addr.s_addr);
#endif

#ifdef Q_OS_WIN32

      if(rc != 0)
	{
	  m_errorString = QString("listen()::WSAStringToAddressA()::"
				  "error=%1").arg(WSAGetLastError());
	  goto done_label;
	}

      /*
      ** Reset sin_port.
      */

      serveraddr.sin_port = htons(port);
#else
      if(rc != 1)
	{
	  if(rc == -1)
	    m_errorString = QString
	      ("listen()::inet_pton()::errno=%1").arg(errno);
	  else
	    m_errorString = "listen()::inet_pton()";

	  goto done_label;
	}
#endif
      rc = bind
	(m_socketDescriptor, (const struct sockaddr *) &serveraddr, length);

      if(rc != 0)
	{
#ifdef Q_OS_WIN32
	  m_errorString = QString
	    ("listen()::bind()::error=%1").arg(WSAGetLastError());
#else
	  m_errorString = QString
	      ("listen()::bind()::errno=%1").arg(errno);
#endif
	  goto done_label;
	}
    }
  else
    {
      socklen_t length = 0;
      struct sockaddr_in6 serveraddr;

      length = sizeof(serveraddr);
      memset(&serveraddr, 0, sizeof(serveraddr));
      serveraddr.sin6_family = AF_INET6;
      serveraddr.sin6_port = htons(port);
#ifdef Q_OS_WIN32
      rc = WSAStringToAddressA((LPSTR) address.toString().toLatin1().data(),
			       AF_INET6, 0, (LPSOCKADDR) &serveraddr, &length);
#else
      rc = inet_pton(AF_INET6, address.toString().toLatin1().constData(),
		     &serveraddr.sin6_addr);
#endif

#ifdef Q_OS_WIN32
      if(rc != 0)
	{
	  m_errorString = QString("listen()::WSAStringToAddressA()::rc=%1").
	    arg(rc);
	  goto done_label;
	}

      /*
      ** Reset sin6_port.
      */

      serveraddr.sin6_port = htons(port);
#else
      if(rc != 1)
	{
	  if(rc == -1)
	    m_errorString = QString
	      ("listen()::inet_pton()::errno=%1").arg(errno);
	  else
	    m_errorString = "listen()::inet_pton()";

	  goto done_label;
	}
#endif
      rc = bind
	(m_socketDescriptor, (const struct sockaddr *) &serveraddr, length);

      if(rc != 0)
	{
#ifdef Q_OS_WIN32
	  m_errorString = QString
	    ("listen()::bind()::error=%1").arg(WSAGetLastError());
#else
	  m_errorString = QString
	      ("listen()::bind()::errno=%1").arg(errno);
#endif
	  goto done_label;
	}
    }

  rc = ::listen(m_socketDescriptor, m_backlog);

  if(rc == 0)
    {
      m_isListening = true;
      m_serverAddress = address;
      m_serverPort  = port;
      m_timer.start();
    }
  else
#ifdef Q_OS_WIN32
    m_errorString = QString("listen()::listen()::error=%1").
      arg(WSAGetLastError());
#else
    m_errorString = QString("listen()::listen()::errno=%1").arg(errno);
#endif

 done_label:

  if(rc != 0)
    {
      close();
      return false;
    }

  return true;
#else
  Q_UNUSED(address);
  Q_UNUSED(port);
  return false;
#endif
}

int spoton_sctp_server::maxPendingConnections(void) const
{
#ifdef SPOTON_SCTP_ENABLED
  return m_backlog;
#else
  return 0;
#endif
}

int spoton_sctp_server::socketDescriptor(void) const
{
  return m_socketDescriptor;
}

quint16 spoton_sctp_server::serverPort(void) const
{
#ifdef SPOTON_SCTP_ENABLED
  return m_serverPort;
#else
  return 0;
#endif
}

void spoton_sctp_server::close(void)
{
#ifdef SPOTON_SCTP_ENABLED
#ifdef Q_OS_WIN32
  closesocket(m_socketDescriptor);
#else
  ::close(m_socketDescriptor);
#endif
  m_isListening = false;
  m_serverAddress.clear();
  m_serverPort = 0;
  m_socketDescriptor = -1;
  m_timer.stop();
#endif
}

void spoton_sctp_server::setMaxPendingConnections(const int numConnections)
{
#ifdef SPOTON_SCTP_ENABLED
  m_backlog = qBound(1, numConnections, SOMAXCONN);
#else
  Q_UNUSED(numConnections);
#endif
}

void spoton_sctp_server::slotTimeout(void)
{
#ifdef SPOTON_SCTP_ENABLED
  QAbstractSocket::NetworkLayerProtocol protocol =
    QAbstractSocket::IPv4Protocol;

  if(QHostAddress(m_serverAddress).protocol() ==
     QAbstractSocket::IPv6Protocol)
    protocol = QAbstractSocket::IPv6Protocol;

  if(protocol == QAbstractSocket::IPv4Protocol)
    {
      QHostAddress address;
      int socketDescriptor = -1;
      quint16 port = 0;
      socklen_t length = 0;
      struct sockaddr_in clientaddr;

      length = sizeof(clientaddr);
      memset(&clientaddr, 0, sizeof(clientaddr));
      socketDescriptor = accept
	(m_socketDescriptor, (struct sockaddr *) &clientaddr,
	 &length);

      if(socketDescriptor > -1)
	{
	  if(spoton_kernel::s_connectionCounts.value(m_id, 0) >= m_backlog)
	    {
#ifdef Q_OS_WIN32
	      closesocket(socketDescriptor);
#else
	      ::close(socketDescriptor);
#endif
	      return;
	    }

	  address.setAddress
	    (ntohl(clientaddr.sin_addr.s_addr));
	  port = ntohs(clientaddr.sin_port);

	  if(!spoton_kernel::acceptRemoteConnection(address))
	    {
#ifdef Q_OS_WIN32
	      closesocket(socketDescriptor);
#else
	      ::close(socketDescriptor);
#endif
	    }
	  else if(!spoton_misc::isAcceptedIP(address, m_id,
					     spoton_kernel::s_crypts.
					     value("chat", 0)))
	    {
#ifdef Q_OS_WIN32
	      closesocket(socketDescriptor);
#else
	      ::close(socketDescriptor);
#endif
	      spoton_misc::logError
		(QString("spoton_sctp_server::slotTimeout(): "
			 "connection from %1 denied for %2:%3.").
		 arg(address.toString()).
		 arg(serverAddress().toString()).
		 arg(serverPort()));
	    }
	  else if(spoton_misc::isIpBlocked(address,
					   spoton_kernel::s_crypts.
					   value("chat", 0)))
	    {
#ifdef Q_OS_WIN32
	      closesocket(socketDescriptor);
#else
	      ::close(socketDescriptor);
#endif
	      spoton_misc::logError
		(QString("spoton_sctp_server::slotTimeout(): "
			 "connection from %1 blocked for %2:%3.").
		 arg(address.toString()).
		 arg(serverAddress().toString()).
		 arg(serverPort()));
	    }
	  else
#if QT_VERSION < 0x050000
	    emit newConnection(socketDescriptor, address, port);
#else
	    emit newConnection(static_cast<qintptr> (socketDescriptor),
			       address, port);
#endif
	}
#ifdef Q_OS_WIN32
      else if(WSAGetLastError() != WSAEWOULDBLOCK)
#else
      else if(!(errno == EAGAIN || errno == EWOULDBLOCK))
#endif
	{
#ifdef Q_OS_WIN32
	  m_errorString = QString
	    ("run()::accept()::error=%1").
	    arg(WSAGetLastError());
#else
	  m_errorString = QString
	    ("run()::accept()::errno=%1").
	    arg(errno);
#endif
	  close();
	}
    }
  else
    {
      QHostAddress address;
      int socketDescriptor = -1;
      quint16 port = 0;
      socklen_t length = 0;
      struct sockaddr_in6 clientaddr;

      length = sizeof(clientaddr);
      memset(&clientaddr, 0, sizeof(clientaddr));
      socketDescriptor = accept
	(m_socketDescriptor, (struct sockaddr *) &clientaddr,
	 &length);

      if(socketDescriptor > -1)
	{
	  if(spoton_kernel::s_connectionCounts.value(m_id, 0) >= m_backlog)
	    {
#ifdef Q_OS_WIN32
	      closesocket(socketDescriptor);
#else
	      ::close(socketDescriptor);
#endif
	      return;
	    }

	  Q_IPV6ADDR temp;

	  memcpy(&temp.c, &clientaddr.sin6_addr.s6_addr,
		 sizeof(temp.c));
	  address.setAddress(temp);
	  address.setScopeId
	    (QString::number(clientaddr.sin6_scope_id));
	  port = ntohs(clientaddr.sin6_port);

	  if(!spoton_kernel::acceptRemoteConnection(address))
	    {
#ifdef Q_OS_WIN32
	      closesocket(socketDescriptor);
#else
	      ::close(socketDescriptor);
#endif
	    }
	  else if(!spoton_misc::isAcceptedIP(address, m_id,
					     spoton_kernel::s_crypts.
					     value("chat", 0)))
	    {
#ifdef Q_OS_WIN32
	      closesocket(socketDescriptor);
#else
	      ::close(socketDescriptor);
#endif
	      spoton_misc::logError
		(QString("spoton_sctp_server::slotTimeout(): "
			 "connection from %1 denied for %2:%3.").
		 arg(address.toString()).
		 arg(serverAddress().toString()).
		 arg(serverPort()));
	    }
	  else if(spoton_misc::isIpBlocked(address,
					   spoton_kernel::s_crypts.
					   value("chat", 0)))
	    {
#ifdef Q_OS_WIN32
	      closesocket(socketDescriptor);
#else
	      ::close(socketDescriptor);
#endif
	      spoton_misc::logError
		(QString("spoton_sctp_server::slotTimeout(): "
			 "connection from %1 blocked for %2:%3.").
		 arg(address.toString()).
		 arg(serverAddress().toString()).
		 arg(serverPort()));
	    }
	  else
#if QT_VERSION < 0x050000
	    emit newConnection(socketDescriptor, address, port);
#else
	    emit newConnection(static_cast<qintptr> (socketDescriptor),
			       address, port);
#endif
	}
#ifdef Q_OS_WIN32
      else if(WSAGetLastError() != WSAEWOULDBLOCK)
#else
      else if(!(errno == EAGAIN || errno == EWOULDBLOCK))
#endif
	{
#ifdef Q_OS_WIN32
	  m_errorString = QString
	    ("run()::accept()::error=%1").
	    arg(WSAGetLastError());
#else
	  m_errorString = QString
	    ("run()::accept()::errno=%1").
	    arg(errno);
#endif
	  close();
	}
    }
#else
#endif
}
