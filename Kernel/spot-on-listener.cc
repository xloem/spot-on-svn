/*
** Copyright (c) 2011, 2012, 2013 Alexis Megas
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

#if QT_VERSION >= 0x050000
void spoton_listener_tcp_server::incomingConnection(qintptr socketDescriptor)
#else
void spoton_listener_tcp_server::incomingConnection(int socketDescriptor)
#endif
{
  if(findChildren<spoton_neighbor *> ().size() >= maxPendingConnections())
    {
      QTcpSocket socket;

      socket.setSocketDescriptor(socketDescriptor);
      socket.abort();
    }
  else
    {
      QHostAddress peerAddress;
      sockaddr nativeAddress;
#ifdef Q_OS_OS2
      int length = sizeof(nativeAddress);
#else
      socklen_t length = sizeof(nativeAddress);
#endif

      if(getpeername(socketDescriptor, &nativeAddress, &length) != 0)
	spoton_misc::logError
	  (QString("spoton_listener_tcp_server::incomingConnection: "
		   "getpeername() failure for %1:%2.").
	   arg(serverAddress().toString()).
	   arg(serverPort()));

      peerAddress = QHostAddress(&nativeAddress);

      if(!spoton_misc::isAcceptedIP(peerAddress, m_id,
				    spoton_kernel::s_crypts.value("chat", 0)))
	{
	  QTcpSocket socket;

	  socket.setSocketDescriptor(socketDescriptor);
	  socket.abort();
	  spoton_misc::logError
	    (QString("spoton_listener_tcp_server::incomingConnection(): "
		     "connection from %1 denied for %2:%3").
	     arg(peerAddress.toString()).
	     arg(serverAddress().toString()).
	     arg(serverPort()));
	}
      else
	emit newConnection(socketDescriptor, QHostAddress(), 0);
    }
}

void spoton_listener_udp_server::slotReadyRead(void)
{
  /*
  ** This unfortunately violates our multi-threaded approach.
  */

  QHostAddress peerAddress;
  quint16 peerPort = 0;

  readDatagram(0, 0, &peerAddress, &peerPort); // Discard the datagram.

  if(!spoton_misc::isAcceptedIP(peerAddress, m_id,
				spoton_kernel::s_crypts.value("chat", 0)))
    spoton_misc::logError
      (QString("spoton_listener_udp_server::incomingConnection(): "
	       "connection from %1 denied for %2:%3").
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
				 const int maximumBufferSize,
				 const int maximumContentLength,
				 const QString &transport,
				 const bool shareAddress,
				 QObject *parent):QObject(parent)
{
  m_tcpServer = 0;
  m_udpServer = 0;

  if(transport == "tcp")
    m_tcpServer = new spoton_listener_tcp_server(id, parent);
  else if(transport == "udp")
    m_udpServer = new spoton_listener_udp_server(id, parent);

  m_address = QHostAddress(ipAddress);
  m_address.setScopeId(scopeId);
  m_certificate = certificate;
  m_echoMode = echoMode;
  m_externalAddress = new spoton_external_address(this);
  m_keySize = qAbs(keySize);

  if(m_keySize != 0)
    if(!(m_keySize == 2048 || m_keySize == 3072 || m_keySize == 4096))
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
  m_networkInterface = 0;
  m_port = m_externalPort = quint16(port.toInt());
  m_privateKey = privateKey;
  m_publicKey = publicKey;
  m_shareAddress = shareAddress;
  m_transport = transport;
  m_useAccounts = useAccounts;
#if QT_VERSION >= 0x050000
  if(m_tcpServer)
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
#else
  if(m_tcpServer)
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
#endif
  connect(m_externalAddress,
	  SIGNAL(ipAddressDiscovered(const QHostAddress &)),
	  this,
	  SLOT(slotExternalAddressDiscovered(const QHostAddress &)));

  if(m_tcpServer)
    m_tcpServer->setMaxPendingConnections(maximumClients);

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
  char *a = new char[32];

  snprintf(a, 32, "%p", this);
  spoton_misc::logError
    (QString("Listener (%1) %2:%3 deallocated.").
     arg(a).
     arg(m_address.toString()).
     arg(m_port));
  delete []a;
  m_timer.stop();

  if(m_tcpServer)
    m_tcpServer->close();
  else if(m_udpServer)
    m_udpServer->abort();

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "listeners.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.prepare("DELETE FROM listeners WHERE OID = ? AND "
		      "status_control = 'deleted'");
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

	query.setForwardOnly(true);
	query.prepare("SELECT status_control, maximum_clients, "
		      "echo_mode, use_accounts, maximum_buffer_size, "
		      "maximum_content_length "
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

		m_useAccounts = query.value(3).toInt();
		m_maximumBufferSize =
		  qBound(spoton_common::MAXIMUM_NEIGHBOR_CONTENT_LENGTH,
			 qAbs(query.value(4).toInt()),
			 spoton_common::MAXIMUM_NEIGHBOR_BUFFER_SIZE);
		m_maximumContentLength =
		  qBound(spoton_common::MINIMUM_NEIGHBOR_CONTENT_LENGTH,
			 qAbs(query.value(5).toInt()),
			 spoton_common::MAXIMUM_NEIGHBOR_CONTENT_LENGTH);

		if(s_crypt)
		  {
		    echoMode = s_crypt->decrypted
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
			    int v =
			      spoton_kernel::setting
			      ("gui/kernelExternalIpInterval", 30).toInt();

			    if(v != -1)
			      /*
			      ** Initial discovery of the external
			      ** IP address.
			      */

			      m_externalAddress->discover();
			  }
		      }

		    if(isListening())
		      {
			if(m_tcpServer)
			  if(query.value(1).toInt() != maxPendingConnections())
			    {
			      int maximumPendingConnections = query.value(1).
				toInt();

			      if(!maximumPendingConnections)
				maximumPendingConnections = 1;
			      else if(maximumPendingConnections % 5 != 0)
				maximumPendingConnections = 1;

			      m_tcpServer->setMaxPendingConnections
				(maximumPendingConnections);
			    }
		      }
		  }

		if(isListening())
		  {
		    int v = 1000 *
		      spoton_kernel::setting("gui/kernelExternalIpInterval",
					     30).toInt();

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
		  {
		    socket->flush();
		    socket->abort();
		    socket->deleteLater();
		  }

		shouldDelete = true;
	      }
	  }
	else
	  {
	    foreach(spoton_neighbor *socket,
		    findChildren<spoton_neighbor *> ())
	      {
		socket->flush();
		socket->abort();
		socket->deleteLater();
	      }

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

  /*
  ** Please note that findChildren() will not locate neighbors that have
  ** been detached.
  */

  query.bindValue
    (0, QString::number(findChildren<spoton_neighbor *> ().size()));

  if(isListening())
    status = "online";
  else
    status = "offline";

  query.bindValue(1, status);
  query.bindValue(2, m_id);
  query.bindValue(3, status);
  query.exec();
}

#if QT_VERSION >= 0x050000
void spoton_listener::slotNewConnection(const qintptr socketDescriptor,
					const QHostAddress &address,
					const quint16 port)
#else
void spoton_listener::slotNewConnection(const int socketDescriptor,
					const QHostAddress &address,
					const quint16 port)
#endif
{
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
      if(m_tcpServer)
	neighbor = new spoton_neighbor
	  (socketDescriptor, certificate, privateKey,
	   m_echoMode, m_useAccounts, m_id, m_maximumBufferSize,
	   m_maximumContentLength, m_transport, address.toString(),
	   QString::number(port),
	   m_tcpServer->serverAddress().toString(),
	   QString::number(m_tcpServer->serverPort()),
	   this);
      else if(m_udpServer)
	neighbor = new spoton_neighbor
	  (socketDescriptor, certificate, privateKey,
	   m_echoMode, m_useAccounts, m_id, m_maximumBufferSize,
	   m_maximumContentLength, m_transport, address.toString(),
	   QString::number(port),
	   m_udpServer->localAddress().toString(),
	   QString::number(m_udpServer->localPort()),
	   this);
    }
  else
    {
      if(m_transport == "tcp")
	{
	  QTcpSocket socket;

	  socket.setSocketDescriptor(socketDescriptor);
	  socket.abort();
	  spoton_misc::logError
	    (QString("spoton_listener::"
		     "slotNewConnection(): "
		     "generateSslKeys() failure (%1) for %2:%3.").
	     arg(error.remove(".")).
	     arg(m_address.toString()).
	     arg(m_port));
	}
      else if(m_transport == "udp")
	{
	  QUdpSocket socket;

	  socket.setSocketDescriptor(socketDescriptor);
	  socket.abort();
	  spoton_misc::logError
	    (QString("spoton_listener::"
		     "slotNewConnection(): "
		     "generateSslKeys() failure (%1) for %2:%3.").
	     arg(error.remove(".")).
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

  updateConnectionCount();

  QString connectionName("");
  QString country
    (spoton_misc::
     countryNameFromIPAddress(neighbor->peerAddress().toString()));
  int count = -1;

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "neighbors.db");

    if(db.open())
      {
	bool ok = true;
	QSqlQuery query(db);

	query.setForwardOnly(true);
	query.prepare("SELECT COUNT(*) FROM neighbors WHERE "
		      "remote_ip_address_hash = ? AND "
		      "status_control = 'blocked'");
	query.bindValue
	  (0, s_crypt->
	   keyedHash(neighbor->peerAddress().
		     toString().toLatin1(), &ok).toBase64());

	if(query.exec())
	  if(query.next())
	    count = query.value(0).toInt();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(count == -1)
    spoton_misc::logError(QString("spoton_listener::slotNewConnection(): "
				  "unable to determine if IP address %1 "
				  "is blocked. Accepting "
				  "connection from %1:%2.").
			  arg(neighbor->peerAddress().toString()).
			  arg(neighbor->peerPort()));
  else if(count > 0)
    {
      spoton_misc::logError(QString("spoton_listener::slotNewConnection(): "
				    "IP address %1 is blocked. Terminating "
				    "connection from %1:%2.").
			    arg(neighbor->peerAddress().toString()).
			    arg(neighbor->peerPort()));
      neighbor->deleteLater();
      return;
    }

  bool created = false;
  qint64 id = -1;

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "neighbors.db");

    if(db.open())
      {
	if(neighbor)
	  {
	    QSqlQuery query(db);

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
		       "transport) "
		       "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
		       "?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
	    query.bindValue(0, m_address.toString());
	    query.bindValue(1, m_port);

	    if(m_address.protocol() == QAbstractSocket::IPv4Protocol)
	      query.bindValue(2, "IPv4");
	    else
	      query.bindValue(2, "IPv6");

	    bool ok = true;

	    query.bindValue
	      (3,
	       s_crypt->encrypted(neighbor->peerAddress().
				  toString().toLatin1(),
				  &ok).toBase64());

	    if(ok)
	      query.bindValue
		(4,
		 s_crypt->
		 encrypted(QString::number(neighbor->peerPort()).
			   toLatin1(), &ok).toBase64());

	    if(ok)
	      query.bindValue
		(5,
		 s_crypt->encrypted(neighbor->peerAddress().
				    scopeId().toLatin1(),
				    &ok).toBase64());

	    query.bindValue(6, "connected");

	    if(ok)
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
		(9, s_crypt->encrypted(country.toLatin1(), &ok).toBase64());

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
		 s_crypt->encrypted(m_externalAddress->
				    address().
				    toString().toLatin1(),
				    &ok).toBase64());

	    if(ok)
	      query.bindValue
		(13,
		 s_crypt->encrypted(neighbor->receivedUuid().toString().
				    toLatin1(), &ok).toBase64());

	    query.bindValue(14, 0);

	    QString proxyHostname("");
	    QString proxyPassword("");
	    QString proxyPort("1");
	    QString proxyType(QString::number(QNetworkProxy::NoProxy));
	    QString proxyUsername("");

	    if(ok)
	      query.bindValue
		(15, s_crypt->encrypted(proxyHostname.toLatin1(), &ok).
		 toBase64());

	    if(ok)
	      query.bindValue
		(16, s_crypt->encrypted(proxyPassword.toUtf8(), &ok).
		 toBase64());

	    if(ok)
	      query.bindValue
		(17, s_crypt->encrypted(proxyPort.toLatin1(),
					&ok).toBase64());

	    if(ok)
	      query.bindValue
		(18, s_crypt->encrypted(proxyType.toLatin1(), &ok).
		 toBase64());

	    if(ok)
	      query.bindValue
		(19, s_crypt->encrypted(proxyUsername.toUtf8(), &ok).
		 toBase64());

	    if(ok)
	      query.bindValue
		(20, s_crypt->encrypted(m_echoMode.toLatin1(),
					&ok).toBase64());

	    query.bindValue(21, m_keySize);

	    if(ok)
	      query.bindValue
		(22, s_crypt->encrypted(QByteArray(), &ok).toBase64());

	    if(ok)
	      query.bindValue
		(23, s_crypt->encrypted(QByteArray(), &ok).toBase64());

	    if(ok)
	      query.bindValue
		(24, s_crypt->encrypted(QByteArray(), &ok).toBase64());

	    query.bindValue(25, m_maximumBufferSize);
	    query.bindValue(26, m_maximumContentLength);
	    query.bindValue(27, m_transport);

	    if(ok)
	      created = query.exec();

	    if(ok)
	      {
		QSqlQuery query(db);

		query.setForwardOnly(true);

		if(query.exec("SELECT OID, remote_ip_address, "
			      "remote_port, scope_id, transport "
			      "FROM neighbors"))
		  while(query.next())
		    {
		      QByteArray b1;
		      QByteArray b2;
		      QByteArray b3;
		      QString b4("");

		      b1 = s_crypt->decrypted
			(QByteArray::fromBase64(query.value(1).
						toByteArray()),
			 &ok);

		      if(ok)
			b2 = s_crypt->decrypted
			  (QByteArray::fromBase64(query.value(2).
						  toByteArray()),
			   &ok);

		      if(ok)
			b3 = s_crypt->decrypted
			  (QByteArray::fromBase64(query.value(3).
						  toByteArray()),
			   &ok);

		      b4 = query.value(4).toString();

		      if(b1 == neighbor->peerAddress().toString() &&
			 b2.toUShort() == neighbor->peerPort() &&
			 b3 == neighbor->peerAddress().scopeId() &&
			 b4 == neighbor->transport()) /*
						      ** toUShort()
						      ** returns
						      ** zero on
						      ** failure.
						      */
			{
			  id = query.value(0).toLongLong();
			  break;
			}
		    }
	      }
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(created && id != -1)
    {
      neighbor->setId(id);
      emit newNeighbor(neighbor);
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
	  (0, QString::number(findChildren<spoton_neighbor *> ().size()));
	query.bindValue(1, m_id);
	query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_listener::slotNeighborDisconnected(void)
{
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
	if(m_tcpServer)
	  {
	    if(addresses.at(j).ip() == m_tcpServer->serverAddress())
	      {
		m_networkInterface = new QNetworkInterface(list.at(i));
		break;
	      }
	  }
	else if(m_udpServer)
	  {
	    if(addresses.at(j).ip() == m_udpServer->localAddress())
	      {
		m_networkInterface = new QNetworkInterface(list.at(i));
		break;
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
		(0, s_crypt->encrypted(address.toString().
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
  if(m_tcpServer)
    m_tcpServer->close();
  else if(m_udpServer)
    m_udpServer->close();
}

bool spoton_listener::isListening(void) const
{
  if(m_tcpServer)
    return m_tcpServer->isListening();
  else if(m_udpServer)
    return m_udpServer->state() == QAbstractSocket::BoundState;
  else
    return false;
}

bool spoton_listener::listen(const QHostAddress &address, const quint16 port)
{
  if(m_tcpServer)
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
  if(m_tcpServer)
    return m_tcpServer->errorString();
  else if(m_udpServer)
    return m_udpServer->errorString();
  else
    return QString();
}

int spoton_listener::maxPendingConnections(void) const
{
  if(m_tcpServer)
    return m_tcpServer->maxPendingConnections();
  else
    return std::numeric_limits<int>::max();
}

QString spoton_listener::transport(void) const
{
  return m_transport;
}
