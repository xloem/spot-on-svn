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
#ifdef Q_OS_MAC
extern "C"
{
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
}
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
}

void spoton_sctp_socket::connectToHost(const QString &hostName,
				       const quint16 port,
				       const OpenMode openMode)
{
#ifdef SPOTON_SCTP_ENABLED
  QHostInfo::abortHostLookup(m_hostLookupId);
  close();
  open(openMode);
  m_hostLookupId = -1;
  m_port = port;
  m_state = UnconnectedState;

  if(m_socketReadNotifier)
    m_socketReadNotifier->deleteLater();

  if(m_socketWriteNotifier)
    m_socketWriteNotifier->deleteLater();

  if(QHostAddress(hostName).isNull())
    {
      /*
      ** Perform a host lookup.
      */

      m_hostLookupId = QHostInfo::lookupHost
	(hostName, this, SLOT(slotHostFound(const QHostInfo &)));
      m_state = HostLookupState;
    }
  else
    {
      m_state = ConnectingState;
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
  int rc = 0;

  m_socketDescriptor = socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP);

  if(m_socketDescriptor > -1)
    {
      struct sockaddr_in servaddr;

      memset(&servaddr, 0, sizeof(servaddr));
      servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
      servaddr.sin_family = AF_INET;
      servaddr.sin_port = htons(m_port);
      rc = inet_pton(AF_INET, m_ipAddress.toLatin1().constData(),
		     &servaddr.sin_addr);

      if(rc != 1)
	goto done_label;
    }

 done_label:
  if(rc != 0)
    ::close(m_socketDescriptor);
#endif
}

void spoton_sctp_socket::setReadBufferSize(const qint64 size)
{
#ifdef SPOTON_SCTP_ENABLED
  m_readBufferSize = size;
#else
  Q_UNUSED(size);
#endif
}

void spoton_sctp_socket::setSocketOption(const SocketOption option)
{
#if SPOTON_SCTP_ENABLED
  if(m_state == ConnectedState)
    {
      switch(option)
	{
	case KeepAliveOption:
	  {
	    break;
	  }
	case LowDelayOption:
	  {
	    break;
	  }
	default:
	  {
	    break;
	  }
	}
    }
#else
  Q_UNUSED(option);
#endif
}

void spoton_sctp_socket::slotHostFound(const QHostInfo &hostInfo)
{
#ifdef SPOTON_SCTP_ENABLED
  foreach(const QHostAddress &address, hostInfo.addresses())
    if(!address.isNull())
      {
	m_ipAddress = address.toString();
	m_state = ConnectingState;
	connectToHostImplementation();
	break;
      }
#else
  Q_UNUSED(hostInfo);
#endif
}
