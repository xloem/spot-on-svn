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

#include <QAbstractSocket>
#include <QSocketNotifier>

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
#include <netinet/sctp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
}
#elif defined(Q_OS_WIN32)
#endif
#endif

#include "Common/spot-on-common.h"
#include "spot-on-sctp-server.h"

spoton_sctp_server::spoton_sctp_server(const qint64 id,
				       QObject *parent):QObject(parent)
{
  m_backlog = 30;
  m_id = id;
  m_isListening = false;
  m_serverPort = 0;
  m_socketDescriptor = -1;
  m_socketReadNotifier = 0;
}

spoton_sctp_server::~spoton_sctp_server()
{
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

  if(QHostAddress(address).protocol() == QAbstractSocket::IPv6Protocol)
    protocol = QAbstractSocket::IPv6Protocol;

  if(protocol == QAbstractSocket::IPv4Protocol)
    m_socketDescriptor = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
  else
    m_socketDescriptor = socket(AF_INET6, SOCK_STREAM, IPPROTO_SCTP);

  prepareSocketNotifiers();
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

  rc = 0;

  /*
  ** Set the read and write buffer sizes.
  */

  optval = 30 * 1460;
  setsockopt(m_socketDescriptor, SOL_SOCKET, SO_RCVBUF, &optval, optlen);
  optval = 1;
  setsockopt(m_socketDescriptor, SOL_SOCKET, SO_REUSEADDR, &optval, optlen);
  optval = 30 * 1460;
  setsockopt(m_socketDescriptor, SOL_SOCKET, SO_SNDBUF, &optval, optlen);

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
      rc = inet_pton(AF_INET, address.toString().toLatin1().constData(),
		     &serveraddr.sin_addr.s_addr);

      if(rc != 1)
	{
	  if(rc == -1)
	    m_errorString = QString
	      ("listen()::inet_pton()::errno=%1").arg(errno);
	  else
	    m_errorString = "listen()::inet_pton()";

	  goto done_label;
	}
      else
	rc = 0;

      rc = bind
	(m_socketDescriptor, (const struct sockaddr *) &serveraddr, length);

      if(rc != 0)
	{
	  m_errorString = QString
	      ("listen()::bind()::errno=%1").arg(errno);
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
      rc = inet_pton(AF_INET6, address.toString().toLatin1().constData(),
		     &serveraddr.sin6_addr);

      if(rc != 1)
	{
	  if(rc == -1)
	    m_errorString = QString
	      ("listen()::inet_pton()::errno=%1").arg(errno);
	  else
	    m_errorString = "listen()::inet_pton()";

	  goto done_label;
	}
      else
	rc = 0;

      rc = bind
	(m_socketDescriptor, (const struct sockaddr *) &serveraddr, length);

      if(rc != 0)
	{
	  m_errorString = QString
	      ("listen()::bind()::errno=%1").arg(errno);
	  goto done_label;
	}
    }

  rc = ::listen(m_socketDescriptor, m_backlog);

  if(rc == 0)
    {
      m_isListening = true;
      m_serverAddress = address;
      m_serverPort  = port;
    }
  else
    m_errorString = QString("listen()::listen()::errno=%1").arg(errno);

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
  if(m_socketReadNotifier)
    {
      m_socketReadNotifier->setEnabled(false);
      m_socketReadNotifier->deleteLater();
    }

  ::close(m_socketDescriptor);
  m_errorString.clear();
  m_isListening = false;
  m_serverAddress.clear();
  m_serverPort = 0;
  m_socketDescriptor = -1;
#endif
}

void spoton_sctp_server::prepareSocketNotifiers(void)
{
#ifdef SPOTON_SCTP_ENABLED
  if(m_socketDescriptor < 0)
    return;

  if(m_socketReadNotifier)
    m_socketReadNotifier->deleteLater();

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

void spoton_sctp_server::setMaxPendingConnections(const int numConnections)
{
#ifdef SPOTON_SCTP_ENABLED
  m_backlog = qBound(1, numConnections, SOMAXCONN);
#else
  Q_UNUSED(numConnections);
#endif
}

void spoton_sctp_server::slotSocketNotifierActivated(int socket)
{
#ifdef SPOTON_SCTP_ENABLED
  Q_UNUSED(socket);

  QSocketNotifier *socketNotifier = qobject_cast<QSocketNotifier *>
    (sender());

  if(!socketNotifier)
    return;

  if(socketNotifier == m_socketReadNotifier)
    {
      socketNotifier->setEnabled(false);

      QAbstractSocket::NetworkLayerProtocol protocol =
	QAbstractSocket::IPv4Protocol;
      QHostAddress address;
      int socketDescriptor = -1;
      quint16 port = 0;
      socklen_t length = 0;

      if(QHostAddress(m_serverAddress).protocol() ==
	 QAbstractSocket::IPv6Protocol)
	protocol = QAbstractSocket::IPv6Protocol;

      if(protocol == QAbstractSocket::IPv4Protocol)
	{
	  struct sockaddr_in clientaddr;

	  length = sizeof(clientaddr);
	  socketDescriptor = accept
	    (m_socketDescriptor, (struct sockaddr *) &clientaddr,
	     &length);

	  if(socketDescriptor > -1)
	    {
	      address.setAddress
		(ntohl(clientaddr.sin_addr.s_addr));
	      port = ntohs(clientaddr.sin_port);
	    }
	}
      else
	{
	  struct sockaddr_in6 clientaddr;

	  length = sizeof(clientaddr);
	  socketDescriptor = accept
	    (m_socketDescriptor, (struct sockaddr *) &clientaddr,
	     &length);

	  if(socketDescriptor > -1)
	    {
	      Q_IPV6ADDR tmp;

	      memcpy(&tmp, &clientaddr.sin6_addr.s6_addr,
		     sizeof(tmp));
	      address.setAddress(tmp);
	      address.setScopeId
		(QString::number(clientaddr.sin6_scope_id));
	      port = ntohs(clientaddr.sin6_port);
	    }
	}

      socketNotifier->setEnabled(true);

      if(socketDescriptor > -1)
	emit newConnection(socketDescriptor, address, port);
    }
#else
  Q_UNUSED(socket);
#endif
}
