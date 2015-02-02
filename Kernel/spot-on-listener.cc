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

#include <QDir>
#include <QNetworkInterface>
#include <QSqlDatabase>
#include <QSqlQuery>

#include <limits>

#include "Common/spot-on-common.h"
#include "Common/spot-on-crypt.h"
#include "Common/spot-on-external-address.h"
#include "spot-on-kernel.h"
#include "spot-on-listener.h"
#include "spot-on-sctp-server.h"

#if QT_VERSION >= 0x050000
void spoton_listener_tcp_server::incomingConnection(qintptr socketDescriptor)
#else
void spoton_listener_tcp_server::incomingConnection(int socketDescriptor)
#endif
{
  if(spoton_kernel::s_connectionCounts.count(m_id) >= maxPendingConnections())
    {
      QAbstractSocket socket(QAbstractSocket::TcpSocket, this);

      socket.setSocketDescriptor(socketDescriptor);
      socket.abort();
    }
  else
    {
      QHostAddress peerAddress;
      quint16 peerPort = 0;

      peerAddress = spoton_misc::peerAddressAndPort
	(static_cast<int> (socketDescriptor), &peerPort);

      if(!spoton_kernel::s_kernel->acceptRemoteConnection(serverAddress(),
							  peerAddress))
	{
	  QAbstractSocket socket(QAbstractSocket::TcpSocket, this);

	  socket.setSocketDescriptor(socketDescriptor);
	  socket.abort();
	}
      else if(!spoton_misc::
	      isAcceptedIP(peerAddress, m_id,
			   spoton_kernel::s_crypts.value("chat", 0)))
	{
	  QAbstractSocket socket(QAbstractSocket::TcpSocket, this);

	  socket.setSocketDescriptor(socketDescriptor);
	  socket.abort();
	  spoton_misc::logError
	    (QString("spoton_listener_tcp_server::incomingConnection(): "
		     "connection from %1 denied for %2:%3.").
	     arg(peerAddress.toString()).
	     arg(serverAddress().toString()).
	     arg(serverPort()));
	}
      else if(spoton_misc::isIpBlocked(peerAddress,
				       spoton_kernel::s_crypts.
				       value("chat", 0)))
	{
	  QAbstractSocket socket(QAbstractSocket::TcpSocket, this);

	  socket.setSocketDescriptor(socketDescriptor);
	  socket.abort();
	  spoton_misc::logError
	    (QString("spoton_listener_tcp_server::incomingConnection(): "
		     "connection from %1 blocked for %2:%3.").
	     arg(peerAddress.toString()).
	     arg(serverAddress().toString()).
	     arg(serverPort()));
	}
      else
	emit newConnection(socketDescriptor, peerAddress, peerPort);
    }
}

void spoton_listener_udp_server::slotReadyRead(void)
{
  /*
  ** This unfortunately violates our multi-threaded approach for UDP sockets.
  */

  QHostAddress peerAddress;
  quint16 peerPort = 0;

  readDatagram(0, 0, &peerAddress, &peerPort); // Discard the datagram.

  if(!spoton_kernel::s_kernel->acceptRemoteConnection(localAddress(),
						      peerAddress))
    {
    }
  else if(!spoton_misc::
	  isAcceptedIP(peerAddress, m_id,
		       spoton_kernel::s_crypts.value("chat", 0)))
    spoton_misc::logError
      (QString("spoton_listener_udp_server::incomingConnection(): "
	       "connection from %1 denied for %2:%3.").
       arg(peerAddress.toString()).
       arg(localAddress().toString()).
       arg(localPort()));
  else if(spoton_misc::isIpBlocked(peerAddress,
				   spoton_kernel::s_crypts.
				   value("chat", 0)))
    spoton_misc::logError
      (QString("spoton_listener_udp_server::incomingConnection(): "
	       "connection from %1 blocked for %2:%3.").
       arg(peerAddress.toString()).
       arg(localAddress().toString()).
       arg(localPort()));
  else if(!clientExists(peerAddress, peerPort))
    emit newConnection
      (socketDescriptor(), peerAddress, peerPort);
}

spoton_listener::spoton_listener(const QString &ipAddress,
				 const QString &port,
				 const QString &scopeId,
				 const int maximumClients,
				 const qint64 id,
				 const QString &echoMode,
				 const int keySize,
				 const QByteArray &certificate,
				 const QByteArray &privateKey,
				 const QByteArray &publicKey,
				 const bool useAccounts,
				 const qint64 maximumBufferSize,
				 const qint64 maximumContentLength,
				 const QString &transport,
				 const bool shareAddress,
				 const QString &orientation,
				 const QString &motd,
				 const QString &sslControlString,
				 QObject *parent):QObject(parent)
{
  m_sctpServer = 0;
  m_tcpServer = 0;
  m_udpServer = 0;

  if(transport == "sctp")
    m_sctpServer = new spoton_sctp_server(id, this);
  else if(transport == "tcp")
    m_tcpServer = new spoton_listener_tcp_server(id, this);
  else if(transport == "udp")
    m_udpServer = new spoton_listener_udp_server(id, this);

  m_address = QHostAddress(ipAddress);
  m_address.setScopeId(scopeId);
  m_certificate = certificate;
  m_echoMode = echoMode;

  try
    {
      m_externalAddress = new spoton_external_address(this);
    }
  catch(std::bad_alloc &exception)
    {
      if(m_sctpServer)
	m_sctpServer->deleteLater();

      if(m_tcpServer)
	m_tcpServer->deleteLater();

      if(m_udpServer)
	m_udpServer->deleteLater();

      throw;
    }

  m_keySize = qAbs(keySize);

  if(transport == "tcp")
    if(m_keySize != 0)
      if(!(m_keySize == 2048 || m_keySize == 3072 ||
	   m_keySize == 4096 || m_keySize == 8192))
	m_keySize = 2048;

  m_id = id;
  m_maximumBufferSize =
    qBound(spoton_common::MAXIMUM_NEIGHBOR_CONTENT_LENGTH,
	   maximumBufferSize,
	   spoton_common::MAXIMUM_NEIGHBOR_BUFFER_SIZE);
  m_maximumContentLength =
    qBound(spoton_common::MINIMUM_NEIGHBOR_CONTENT_LENGTH,
	   maximumContentLength,
	   spoton_common::MAXIMUM_NEIGHBOR_CONTENT_LENGTH);
  m_motd = motd;
  m_networkInterface = 0;
  m_orientation = orientation;
  m_port = m_externalPort = port.toUShort();
  m_privateKey = privateKey;
  m_publicKey = publicKey;
  m_shareAddress = shareAddress;
  m_sslControlString = sslControlString.trimmed();

  if(m_sslControlString.isEmpty())
    m_sslControlString = "HIGH:!aNULL:!eNULL:!3DES:!EXPORT:!SSLv3:@STRENGTH";

  m_transport = transport;
  m_useAccounts = useAccounts;

  if(m_transport != "tcp")
    m_sslControlString = "N/A";

#if QT_VERSION < 0x050000
  if(m_sctpServer)
    connect(m_sctpServer,
	    SIGNAL(newConnection(const int,
				 const QHostAddress &,
				 const quint16)),
	    this,
	    SLOT(slotNewConnection(const int,
				   const QHostAddress &,
				   const quint16)));
  else if(m_tcpServer)
    connect(m_tcpServer,
	    SIGNAL(newConnection(const int,
				 const QHostAddress &,
				 const quint16)),
	    this,
	    SLOT(slotNewConnection(const int,
				   const QHostAddress &,
				   const quint16)));
  else if(m_udpServer)
    connect(m_udpServer,
	    SIGNAL(newConnection(const int,
				 const QHostAddress &,
				 const quint16)),
	    this,
	    SLOT(slotNewConnection(const int,
				   const QHostAddress &,
				   const quint16)));
#else
  if(m_sctpServer)
    connect(m_sctpServer,
	    SIGNAL(newConnection(const qintptr,
				 const QHostAddress &,
				 const quint16)),
	    this,
	    SLOT(slotNewConnection(const qintptr,
				   const QHostAddress &,
				   const quint16)));
  else if(m_tcpServer)
    connect(m_tcpServer,
	    SIGNAL(newConnection(const qintptr,
				 const QHostAddress &,
				 const quint16)),
	    this,
	    SLOT(slotNewConnection(const qintptr,
				   const QHostAddress &,
				   const quint16)));
  else if(m_udpServer)
    connect(m_udpServer,
	    SIGNAL(newConnection(const qintptr,
				 const QHostAddress &,
				 const quint16)),
	    this,
	    SLOT(slotNewConnection(const qintptr,
				   const QHostAddress &,
				   const quint16)));
#endif
  connect(m_externalAddress,
	  SIGNAL(ipAddressDiscovered(const QHostAddress &)),
	  this,
	  SLOT(slotExternalAddressDiscovered(const QHostAddress &)));
  m_maximumClients = maximumClients;

  if(m_maximumClients <= 0)
    m_maximumClients = std::numeric_limits<int>::max();

  if(m_sctpServer)
    m_sctpServer->setMaxPendingConnections(m_maximumClients);
  else if(m_tcpServer)
    m_tcpServer->setMaxPendingConnections(m_maximumClients);
  else if(m_udpServer)
    m_udpServer->setMaxPendingConnections(m_maximumClients);

  connect(&m_timer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotTimeout(void)));
  m_timer.start(2500);
  connect(&m_externalAddressDiscovererTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotDiscoverExternalAddress(void)));
}

spoton_listener::~spoton_listener()
{
  spoton_misc::logError(QString("Listener %1:%2 deallocated.").
			arg(m_address.toString()).
			arg(m_port));
  m_externalAddressDiscovererTimer.stop();
  m_timer.stop();

  if(m_sctpServer)
    m_sctpServer->close();
  else if(m_tcpServer)
    m_tcpServer->close();
  else if(m_udpServer)
    m_udpServer->close();

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "listeners.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("PRAGMA secure_delete = ON");
	query.prepare("DELETE FROM listeners WHERE OID = ? AND "
		      "status_control = 'deleted'");
	query.bindValue(0, m_id);
	query.exec();
	query.prepare
	  ("DELETE FROM listeners_accounts_consumed_authentications "
	   "WHERE OID = ?");
	query.bindValue(0, m_id);
	query.exec();
	query.exec("DELETE FROM listeners_accounts WHERE "
		   "listener_oid NOT IN "
		   "(SELECT OID FROM listeners)");
	query.exec("DELETE FROM listeners_allowed_ips WHERE "
		   "listener_oid NOT IN "
		   "(SELECT OID FROM listeners)");
	query.prepare("UPDATE listeners SET connections = 0, "
		      "external_ip_address = NULL, "
		      "status = 'offline' WHERE OID = ?");
	query.bindValue(0, m_id);
	query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(m_networkInterface)
    delete m_networkInterface;

  spoton_kernel::s_connectionCounts.remove(m_id);
}

void spoton_listener::slotTimeout(void)
{
  /*
  ** We'll change states here.
  */

  /*
  ** Retrieve the interface that this listener is listening on.
  ** If the interface disappears, destroy the listener.
  */

  QString connectionName("");
  bool shouldDelete = false;

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "listeners.db");

    if(db.open())
      {
	QSqlQuery query(db);

	/*
	** Remove expired entries from
	** listeners_accounts_consumed_authentications.
	*/

	query.setForwardOnly(true);
	query.exec("PRAGMA secure_delete = ON");
	query.prepare
	  ("DELETE FROM listeners_accounts_consumed_authentications "
	   "WHERE "
	   "strftime('%s', ?) - "
	   "strftime('%s', insert_date) > ? AND listener_oid = ?");
	query.bindValue
	  (0, QDateTime::currentDateTime().toString(Qt::ISODate));
	query.bindValue(1, 120);
	query.bindValue(2, m_id);
	query.exec();
	query.prepare("SELECT status_control, maximum_clients, "
		      "echo_mode, use_accounts, maximum_buffer_size, "
		      "maximum_content_length, motd, ssl_control_string "
		      "FROM listeners WHERE OID = ?");
	query.bindValue(0, m_id);

	if(query.exec())
	  {
	    if(query.next())
	      {
		QString echoMode("");
		QString status(query.value(0).toString());
		bool ok = true;
		spoton_crypt *s_crypt =
		  spoton_kernel::s_crypts.value("chat", 0);

		m_useAccounts = static_cast<int>
		  (query.value(3).toLongLong());
		m_maximumBufferSize =
		  qBound(spoton_common::MAXIMUM_NEIGHBOR_CONTENT_LENGTH,
			 query.value(4).toLongLong(),
			 spoton_common::MAXIMUM_NEIGHBOR_BUFFER_SIZE);
		m_maximumContentLength =
		  qBound(spoton_common::MINIMUM_NEIGHBOR_CONTENT_LENGTH,
			 query.value(5).toLongLong(),
			 spoton_common::MAXIMUM_NEIGHBOR_CONTENT_LENGTH);
		m_motd = query.value(6).toString();
		m_sslControlString = query.value(7).toString().trimmed();

		if(m_sslControlString.isEmpty())
		  m_sslControlString =
		    "HIGH:!aNULL:!eNULL:!3DES:!EXPORT:!SSLv3:@STRENGTH";

		if(s_crypt)
		  {
		    echoMode = s_crypt->decryptedAfterAuthenticated
		      (QByteArray::
		       fromBase64(query.
				  value(2).
				  toByteArray()),
		       &ok).
		      constData();

		    if(ok)
		      if(echoMode == "full" || echoMode == "half")
			m_echoMode = echoMode;
		  }

		if(status == "offline")
		  close();
		else if(status == "online")
		  {
		    if(!isListening())
		      {
			if(!listen(m_address, m_port))
			  spoton_misc::logError
			    (QString("spoton_listener::slotTimeout(): "
				     "listen() failure (%1) for %2:%3.").
			     arg(errorString()).
			     arg(m_address.toString()).
			     arg(m_port));
			else
			  {
			    int v = spoton_kernel::setting
			      ("gui/kernelExternalIpInterval", -1).toInt();

			    if(v != -1)
			      /*
			      ** Initial discovery of the external
			      ** IP address.
			      */

			      m_externalAddress->discover();
			  }
		      }

		    if(isListening())
		      if(static_cast<int> (query.value(1).
					   toLongLong()) !=
			 maxPendingConnections())
			{
			  int maximumPendingConnections =
			    qAbs(static_cast<int> (query.value(1).
						   toLongLong()));

			  if(maximumPendingConnections > 0)
			    {
			      if(maximumPendingConnections % 5 != 0)
				maximumPendingConnections = 5;
			    }
			  else
			    maximumPendingConnections =
			      std::numeric_limits<int>::max();

			  if(m_sctpServer)
			    m_sctpServer->setMaxPendingConnections
			      (maximumPendingConnections);
			  else if(m_tcpServer)
			    m_tcpServer->setMaxPendingConnections
			      (maximumPendingConnections);
			  else if(m_udpServer)
			    m_udpServer->setMaxPendingConnections
			      (maximumPendingConnections);
			}
		  }

		if(isListening())
		  {
		    int v = 1000 * spoton_kernel::setting
		      ("gui/kernelExternalIpInterval", -1).toInt();

		    if(v == 30000 || v == 60000)
		      {
			if(v == 30000)
			  {
			    if(m_externalAddressDiscovererTimer.
			       interval() != v)
			      m_externalAddressDiscovererTimer.start
				(30000);
			    else if(!m_externalAddressDiscovererTimer.
				    isActive())
			      m_externalAddressDiscovererTimer.start
				(30000);
			  }
			else
			  {
			    if(m_externalAddressDiscovererTimer.
			       interval() != v)
			      m_externalAddressDiscovererTimer.start
				(60000);
			    else if(!m_externalAddressDiscovererTimer.
				    isActive())
			      m_externalAddressDiscovererTimer.start
				(60000);
			  }
		      }
		    else
		      m_externalAddressDiscovererTimer.stop();
		  }
		else
		  {
		    m_externalAddressDiscovererTimer.stop();
		    saveExternalAddress(QHostAddress(), db);
		  }

		if(status == "offline" || status == "online")
		  saveStatus(db);
	      }
	    else
	      {
		foreach(spoton_neighbor *socket,
			findChildren<spoton_neighbor *> ())
		  socket->deleteLater();

		shouldDelete = true;
	      }
	  }
	else
	  {
	    foreach(spoton_neighbor *socket,
		    findChildren<spoton_neighbor *> ())
	      socket->deleteLater();

	    shouldDelete = true;
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(shouldDelete)
    {
      spoton_misc::logError
	(QString("spoton_listener:slotTimeout(): instructed "
		 "to delete listener %1:%2.").
	 arg(m_address.toString()).
	 arg(m_port));
      deleteLater();
      return;
    }

  /*
  ** Retrieve the interface that this listener is using.
  ** If the interface disappears, destroy the listener.
  */

  prepareNetworkInterface();

  if(isListening())
    if(!m_networkInterface || !(m_networkInterface->flags() &
				QNetworkInterface::IsUp))
      {
	if(m_networkInterface)
	  spoton_misc::logError
	    (QString("spoton_listener::slotTimeout(): "
		     "network interface %1 for %2:%3 is not active. "
		     "Aborting.").
	     arg(m_networkInterface->name()).
	     arg(m_address.toString()).
	     arg(m_port));
	else
	  spoton_misc::logError
	    (QString("spoton_listener::slotTimeout(): "
		     "undefined network interface for %1:%2. "
		     "Aborting.").
	     arg(m_address.toString()).
	     arg(m_port));

	deleteLater();
      }
}

void spoton_listener::saveStatus(const QSqlDatabase &db)
{
  if(!db.isOpen())
    return;

  QSqlQuery query(db);
  QString status("");

  query.prepare("UPDATE listeners SET connections = ?, status = ? "
		"WHERE OID = ? AND status <> ?");
  query.bindValue
    (0, QString::number(spoton_kernel::s_connectionCounts.count(m_id)));

  if(isListening())
    status = "online";
  else
    status = "offline";

  query.bindValue(1, status);
  query.bindValue(2, m_id);
  query.bindValue(3, status);
  query.exec();
}

#if QT_VERSION < 0x050000
void spoton_listener::slotNewConnection(const int socketDescriptor,
					const QHostAddress &address,
					const quint16 port)
#else
void spoton_listener::slotNewConnection(const qintptr socketDescriptor,
					const QHostAddress &address,
					const quint16 port)
#endif
{
  /*
  ** Record the IP address of the client as soon as possible.
  */

  QByteArray certificate(m_certificate);
  QByteArray privateKey(m_privateKey);
  QPointer<spoton_neighbor> neighbor = 0;
  QString error("");

  if(m_keySize != 0)
    {
      QByteArray publicKey;

      if(certificate.isEmpty() || privateKey.isEmpty())
	spoton_crypt::generateSslKeys
	  (m_keySize,
	   certificate,
	   privateKey,
	   publicKey,
	   m_externalAddress->address(),
	   60 * 60 * 24 * 7, // Seven days.
	   error);
    }

  if(error.isEmpty())
    {
      try
	{
	  neighbor = new spoton_neighbor
	    (socketDescriptor, certificate, privateKey,
	     m_echoMode, m_useAccounts, m_id, m_maximumBufferSize,
	     m_maximumContentLength, m_transport, address.toString(),
	     QString::number(port),
	     m_address.toString(),
	     QString::number(m_port),
	     m_orientation,
	     m_motd,
	     m_sslControlString,
	     QThread::HighPriority,
	     this);
	}
      catch(std::bad_alloc &exception)
	{
	  error = "memory allocation failure";
	  neighbor = 0;
	  spoton_misc::logError("spoton_listener::slotNewConnection(): "
				"memory failure.");
	}
      catch(...)
	{
	  if(neighbor)
	    neighbor->deleteLater();

	  error = "irregular exception";
	  spoton_misc::logError("spoton_listener::slotNewConnection(): "
				"critical failure.");
	}
    }

  if(!error.isEmpty() || !neighbor)
    {
      if(m_transport == "sctp")
	{
	  spoton_sctp_socket socket(this);

	  socket.setSocketDescriptor(socketDescriptor);
	  socket.abort();

	  if(!error.isEmpty())
	    spoton_misc::logError
	      (QString("spoton_listener::"
		       "slotNewConnection(): "
		       "generateSslKeys() failure (%1) for %2:%3.").
	       arg(error).
	       arg(m_address.toString()).
	       arg(m_port));
	}
      else if(m_transport == "tcp")
	{
	  QAbstractSocket socket(QAbstractSocket::TcpSocket, this);

	  socket.setSocketDescriptor(socketDescriptor);
	  socket.abort();

	  if(!error.isEmpty())
	    spoton_misc::logError
	      (QString("spoton_listener::"
		       "slotNewConnection(): "
		       "generateSslKeys() failure (%1) for %2:%3.").
	       arg(error).
	       arg(m_address.toString()).
	       arg(m_port));
	}
      else if(m_transport == "udp")
	{
	  QAbstractSocket socket(QAbstractSocket::UdpSocket, this);

	  socket.setSocketDescriptor(socketDescriptor);
	  socket.abort();

	  if(!error.isEmpty())
	    spoton_misc::logError
	      (QString("spoton_listener::"
		       "slotNewConnection(): "
		       "generateSslKeys() failure (%1) for %2:%3.").
	       arg(error).
	       arg(m_address.toString()).
	       arg(m_port));
	}
    }

  if(!neighbor)
    return;

  connect(neighbor,
	  SIGNAL(disconnected(void)),
	  neighbor,
	  SLOT(deleteLater(void)));

  if(m_udpServer)
    {
      QString address(QString("%1:%2:%3").
		      arg(neighbor->peerAddress().toString()).
		      arg(neighbor->peerAddress().scopeId()).
		      arg(neighbor->peerPort()));

      neighbor->setProperty("address", address);
      m_udpServer->addClientAddress(address);
      connect(neighbor,
	      SIGNAL(destroyed(QObject *)),
	      m_udpServer,
	      SLOT(slotClientDestroyed(QObject *)));
    }

  connect(neighbor,
	  SIGNAL(destroyed(void)),
	  this,
	  SLOT(slotNeighborDisconnected(void)));

  spoton_crypt *s_crypt = spoton_kernel::s_crypts.value("chat", 0);

  if(!s_crypt)
    {
      spoton_misc::logError
	(QString("spoton_listener::slotNewConnection(): "
		 "chat key is missing for %1:%2.").
	 arg(m_address.toString()).arg(m_port));
      neighbor->deleteLater();
      return;
    }

  QString connectionName("");
  QString country
    (spoton_misc::
     countryNameFromIPAddress(neighbor->peerAddress().toString()));
  qint64 id = -1;

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "neighbors.db");

    if(db.open())
      {
	if(db.transaction() && neighbor)
	  {
	    QSqlQuery query(db);
	    bool ok = true;

	    query.exec("INSERT INTO neighbors "
		       "(local_ip_address, "
		       "local_port, "
		       "protocol, "
		       "remote_ip_address, "
		       "remote_port, "
		       "scope_id, "
		       "status, "
		       "hash, "
		       "sticky, "
		       "country, "
		       "remote_ip_address_hash, "
		       "qt_country_hash, "
		       "external_ip_address, "
		       "uuid, "
		       "user_defined, "
		       "proxy_hostname, "
		       "proxy_password, "
		       "proxy_port, "
		       "proxy_type, "
		       "proxy_username, "
		       "echo_mode, "
		       "ssl_key_size, "
		       "certificate, "
		       "account_name, "
		       "account_password, "
		       "maximum_buffer_size, "
		       "maximum_content_length, "
		       "transport, "
		       "orientation, "
		       "motd, "
		       "ssl_control_string) "
		       "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
		       "?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
	    query.bindValue(0, m_address.toString());
	    query.bindValue(1, m_port);

	    if(m_address.protocol() == QAbstractSocket::IPv4Protocol)
	      query.bindValue
		(2, s_crypt->
		 encryptedThenHashed("IPv4", &ok).toBase64());
	    else
	      query.bindValue
		(2, s_crypt->
		 encryptedThenHashed("IPv6", &ok).toBase64());

	    if(ok)
	      query.bindValue
		(3,
		 s_crypt->encryptedThenHashed(neighbor->peerAddress().
					      toString().toLatin1(),
					      &ok).toBase64());

	    if(ok)
	      query.bindValue
		(4,
		 s_crypt->
		 encryptedThenHashed(QByteArray::number(neighbor->peerPort()),
				     &ok).toBase64());

	    if(ok)
	      query.bindValue
		(5,
		 s_crypt->encryptedThenHashed(neighbor->peerAddress().
					      scopeId().toLatin1(),
					      &ok).toBase64());

	    query.bindValue(6, "connected");

	    if(ok)
	      /*
	      ** We do not have proxy information.
	      */

	      query.bindValue
		(7,
		 s_crypt->keyedHash((neighbor->peerAddress().toString() +
				     QString::number(neighbor->peerPort()) +
				     neighbor->peerAddress().scopeId() +
				     m_transport).
				    toLatin1(), &ok).toBase64());

	    query.bindValue(8, 1); // Sticky

	    if(ok)
	      query.bindValue
		(9, s_crypt->encryptedThenHashed(country.toLatin1(),
						 &ok).toBase64());

	    if(ok)
	      query.bindValue
		(10, s_crypt->
		 keyedHash(neighbor->peerAddress().
			   toString().toLatin1(), &ok).toBase64());

	    if(ok)
	      query.bindValue
		(11, s_crypt->
		 keyedHash(country.remove(" ").toLatin1(), &ok).toBase64());

	    if(ok)
	      query.bindValue
		(12,
		 s_crypt->encryptedThenHashed(m_externalAddress->
					      address().
					      toString().toLatin1(),
					      &ok).toBase64());

	    if(ok)
	      query.bindValue
		(13,
		 s_crypt->encryptedThenHashed
		 (neighbor->receivedUuid().toString().
		  toLatin1(), &ok).toBase64());

	    query.bindValue(14, 0);

	    QString proxyHostname("");
	    QString proxyPassword("");
	    QString proxyPort("1");
	    QString proxyType(QString::number(QNetworkProxy::NoProxy));
	    QString proxyUsername("");

	    if(ok)
	      query.bindValue
		(15, s_crypt->encryptedThenHashed
		 (proxyHostname.toLatin1(), &ok).
		 toBase64());

	    if(ok)
	      query.bindValue
		(16, s_crypt->encryptedThenHashed(proxyPassword.toUtf8(), &ok).
		 toBase64());

	    if(ok)
	      query.bindValue
		(17, s_crypt->encryptedThenHashed(proxyPort.toLatin1(),
						  &ok).toBase64());

	    if(ok)
	      query.bindValue
		(18, s_crypt->encryptedThenHashed(proxyType.toLatin1(), &ok).
		 toBase64());

	    if(ok)
	      query.bindValue
		(19, s_crypt->encryptedThenHashed
		 (proxyUsername.toUtf8(), &ok).
		 toBase64());

	    if(ok)
	      query.bindValue
		(20, s_crypt->encryptedThenHashed(m_echoMode.toLatin1(),
						  &ok).toBase64());

	    query.bindValue(21, m_keySize);

	    if(ok)
	      query.bindValue
		(22, s_crypt->encryptedThenHashed
		 (QByteArray(), &ok).toBase64());

	    if(ok)
	      query.bindValue
		(23, s_crypt->encryptedThenHashed
		 (QByteArray(), &ok).toBase64());

	    if(ok)
	      query.bindValue
		(24, s_crypt->encryptedThenHashed
		 (QByteArray(), &ok).toBase64());

	    query.bindValue(25, m_maximumBufferSize);
	    query.bindValue(26, m_maximumContentLength);

	    if(ok)
	      query.bindValue
		(27, s_crypt->encryptedThenHashed
		 (m_transport.toLatin1(), &ok).
		 toBase64());

	    if(ok)
	      query.bindValue
		(28, s_crypt->encryptedThenHashed
		 (m_orientation.toLatin1(), &ok).
		 toBase64());

	    query.bindValue(29, m_motd);

	    if(m_transport == "tcp")
	      query.bindValue
		(30, "HIGH:!aNULL:!eNULL:!3DES:!EXPORT:!SSLv3:@STRENGTH");
	    else
	      query.bindValue(30, "N/A");

	    if(ok)
	      {
		if(query.exec())
		  {
		    QVariant variant(query.lastInsertId());

		    if(variant.isValid())
		      id = query.lastInsertId().toLongLong();
		  }
	      }

	    query.clear();
	  }

	if(id == -1)
	  db.rollback();
	else
	  db.commit();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(id != -1)
    {
      neighbor->setId(id);
      emit newNeighbor(neighbor);
      spoton_kernel::s_connectionCounts.insert(m_id, neighbor);
      updateConnectionCount();
    }
  else
    {
      neighbor->deleteLater();
      spoton_misc::logError
	(QString("spoton_listener::slotNewConnection(): "
		 "severe error(s). Purging neighbor "
		 "object for %1:%2.").
	 arg(m_address.toString()).
	 arg(m_port));
    }
}

void spoton_listener::updateConnectionCount(void)
{
  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "listeners.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.prepare("UPDATE listeners SET connections = ? "
		      "WHERE OID = ?");
	query.bindValue
	  (0, QString::number(spoton_kernel::
			      s_connectionCounts.count(m_id)));
	query.bindValue(1, m_id);
	query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_listener::slotNeighborDisconnected(void)
{
  QPointer<spoton_neighbor> neighbor =
    qobject_cast<spoton_neighbor *> (sender());

  spoton_kernel::s_connectionCounts.remove(m_id, neighbor);
  updateConnectionCount();
}

qint64 spoton_listener::id(void) const
{
  return m_id;
}

void spoton_listener::prepareNetworkInterface(void)
{
  if(m_networkInterface)
    {
      delete m_networkInterface;
      m_networkInterface = 0;
    }

  QList<QNetworkInterface> list(QNetworkInterface::allInterfaces());

  for(int i = 0; i < list.size(); i++)
    {
      QList<QNetworkAddressEntry> addresses(list.at(i).addressEntries());

      for(int j = 0; j < addresses.size(); j++)
	if(m_sctpServer)
	  {
	    if(addresses.at(j).ip() == m_sctpServer->serverAddress())
	      {
		m_networkInterface = new (std::nothrow)
		  QNetworkInterface(list.at(i));

		if(m_networkInterface)
		  break;
		else
		  spoton_misc::logError
		    ("spoton_listener::prepareNetworkInterface(): "
		     "memory failure.");
	      }
	  }
	else if(m_tcpServer)
	  {
	    if(addresses.at(j).ip() == m_tcpServer->serverAddress())
	      {
		m_networkInterface = new (std::nothrow)
		  QNetworkInterface(list.at(i));

		if(m_networkInterface)
		  break;
		else
		  spoton_misc::logError
		    ("spoton_listener::prepareNetworkInterface(): "
		     "memory failure.");
	      }
	  }
	else if(m_udpServer)
	  {
	    if(addresses.at(j).ip() == m_udpServer->localAddress())
	      {
		m_networkInterface = new (std::nothrow)
		  QNetworkInterface(list.at(i));

		if(m_networkInterface)
		  break;
		else
		  spoton_misc::logError
		    ("spoton_listener::prepareNetworkInterface(): "
		     "memory failure.");
	      }
	  }
	else
	  break;

      if(m_networkInterface)
	break;
    }
}

void spoton_listener::saveExternalAddress(const QHostAddress &address,
					  const QSqlDatabase &db)
{
  if(!db.isOpen())
    return;

  QSqlQuery query(db);
  bool ok = true;

  if(isListening())
    {
      if(address.isNull())
	{
	  query.prepare("UPDATE listeners SET "
			"external_ip_address = NULL "
			"WHERE OID = ? AND external_ip_address IS "
			"NOT NULL");
	  query.bindValue(0, m_id);
	}
      else
	{
	  spoton_crypt *s_crypt = spoton_kernel::s_crypts.value("chat", 0);

	  if(s_crypt)
	    {
	      query.prepare("UPDATE listeners SET external_ip_address = ? "
			    "WHERE OID = ?");
	      query.bindValue
		(0, s_crypt->encryptedThenHashed(address.toString().
						 toLatin1(), &ok).
		 toBase64());
	      query.bindValue(1, m_id);
	    }
	  else
	    ok = false;
	}
    }
  else
    {
      query.prepare("UPDATE listeners SET external_ip_address = NULL "
		    "WHERE OID = ? AND external_ip_address IS NOT NULL");
      query.bindValue(0, m_id);
    }

  if(ok)
    query.exec();
}

void spoton_listener::slotExternalAddressDiscovered
(const QHostAddress &address)
{
  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "listeners.db");

    if(db.open())
      saveExternalAddress(address, db);

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_listener::slotDiscoverExternalAddress(void)
{
  if(isListening())
    m_externalAddress->discover();
}

QHostAddress spoton_listener::externalAddress(void) const
{
  if(m_externalAddress)
    return m_externalAddress->address();
  else
    return QHostAddress();
}

quint16 spoton_listener::externalPort(void) const
{
  /*
  ** The external port is currently the local port.
  */

  return m_externalPort;
}

QHostAddress spoton_listener::serverAddress(void) const
{
  return m_address;
}

quint16 spoton_listener::serverPort(void) const
{
  return m_port;
}

void spoton_listener::close(void)
{
  if(m_sctpServer)
    m_sctpServer->close();
  else if(m_tcpServer)
    m_tcpServer->close();
  else if(m_udpServer)
    m_udpServer->close();
}

bool spoton_listener::isListening(void) const
{
  if(m_sctpServer)
    return m_sctpServer->isListening();
  else if(m_tcpServer)
    return m_tcpServer->isListening();
  else if(m_udpServer)
    return m_udpServer->state() == QAbstractSocket::BoundState;
  else
    return false;
}

bool spoton_listener::listen(const QHostAddress &address, const quint16 port)
{
  if(m_sctpServer)
    return m_sctpServer->listen(address, port);
  else if(m_tcpServer)
    return m_tcpServer->listen(address, port);
  else if(m_udpServer)
    {
      if(m_shareAddress)
	return m_udpServer->bind(address, port,
				 QUdpSocket::ReuseAddressHint |
				 QUdpSocket::ShareAddress);
      else
	return m_udpServer->bind(address, port,
				 QUdpSocket::DontShareAddress |
				 QUdpSocket::ReuseAddressHint);
    }
  else
    return false;
}

QString spoton_listener::errorString(void) const
{
  if(m_sctpServer)
    return m_sctpServer->errorString();
  else if(m_tcpServer)
    return m_tcpServer->errorString();
  else if(m_udpServer)
    return m_udpServer->errorString();
  else
    return QString();
}

int spoton_listener::maxPendingConnections(void) const
{
  if(m_sctpServer)
    return m_sctpServer->maxPendingConnections();
  else if(m_tcpServer)
    return m_tcpServer->maxPendingConnections();
  else if(m_udpServer)
    return m_udpServer->maxPendingConnections();
  else
    return 0;
}

QString spoton_listener::transport(void) const
{
  return m_transport;
}

QString spoton_listener::orientation(void) const
{
  return m_orientation;
}
