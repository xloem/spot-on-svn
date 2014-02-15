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

spoton_sctp_server::spoton_sctp_server(const qint64 id,
				       QObject *parent):QObject(parent)
{
  m_backlog = 30;
  m_id = id;
  m_isListening = false;
  m_socketDescriptor = 0;
  m_socketReadNotifier = 0;
  m_socketWriteNotifier = 0;
}

spoton_sctp_server::~spoton_sctp_server()
{
  close();
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

bool spoton_sctp_server::listen(const QHostAddress &address, quint16 port)
{
#ifdef SPOTON_SCTP_ENABLED
  Q_UNUSED(address);
  Q_UNUSED(port);

  if(m_isListening)
    return true;
  else if(m_socketDescriptor > -1)
    return m_isListening;

  QAbstractSocket::NetworkLayerProtocol protocol =
    QAbstractSocket::IPv4Protocol;
  int rc = 0;
  qint64 optval = 0;
  socklen_t optlen = sizeof(optval);

  if(QHostAddress(address).protocol() == QAbstractSocket::IPv6Protocol)
    protocol = QAbstractSocket::IPv6Protocol;

  if(protocol == QAbstractSocket::IPv4Protocol)
    m_socketDescriptor = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
  else
    m_socketDescriptor = socket(AF_INET6, SOCK_STREAM, IPPROTO_SCTP);

  rc = fcntl(m_socketDescriptor, F_GETFL, 0);

  if(rc == -1)
    {
      m_errorString = QString("listen()::fcntl()::errno=%1").arg(errno);
      goto done_label;
    }

  if(fcntl(m_socketDescriptor, F_SETFL, O_NONBLOCK | rc) == -1)
    {
      m_errorString = QString("listen()::fcntl()::errno=%1").arg(errno);
      goto done_label;
    }

  optval = 8192;
  setsockopt(m_socketDescriptor, SOL_SOCKET, SO_RCVBUF, &optval, optlen);
  optval = 1;
  setsockopt(m_socketDescriptor, SOL_SOCKET, SO_REUSEADDR, &optval, optlen);
  optlen = 8192;
  setsockopt(m_socketDescriptor, SOL_SOCKET, SO_SNDBUF, &optval, optlen);
  rc = ::listen(m_socketDescriptor, m_backlog);

  if(rc == 0)
    m_isListening = true;
  else
    {
      if(errno == EADDRINUSE)
	m_errorString = "listen()::listen()::errno=EADDRINUSE";
      else
	m_errorString = QString("listen()::listen()::errno=%1").arg(errno);
    }

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

void spoton_sctp_server::close(void)
{
#ifdef SPOTON_SCTP_ENABLED
  if(m_socketReadNotifier)
    {
      m_socketReadNotifier->setEnabled(false);
      m_socketReadNotifier->deleteLater();
    }

  if(m_socketWriteNotifier)
    {
      m_socketWriteNotifier->setEnabled(false);
      m_socketWriteNotifier->deleteLater();
    }

  ::close(m_socketDescriptor);
  m_errorString.clear();
  m_isListening = false;
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

void spoton_sctp_server::setMaxPendingConnections(const int numConnections)
{
#ifdef SPOTON_SCTP_ENABLED
  m_backlog = qAbs(qMax(static_cast<int> (SOMAXCONN), numConnections));
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
#else
  Q_UNUSED(socket);
#endif
}
