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

#include "Common/spot-on-external-address.h"
#include "Common/spot-on-crypt.h"
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
      socket.close();
    }
  else
    emit newConnection(socketDescriptor);
}

spoton_listener::spoton_listener(const QString &ipAddress,
				 const QString &port,
				 const QString &scopeId,
				 const int maximumClients,
				 const qint64 id,
				 const QString &echoMode,
				 const int keySize,
				 QObject *parent):
  spoton_listener_tcp_server(parent)
{
  m_address = QHostAddress(ipAddress);
  m_address.setScopeId(scopeId);
  m_echoMode = echoMode;
  m_externalAddress = new spoton_external_address(this);
  m_keySize = qAbs(keySize);

  if(m_keySize != 0)
    if(!(m_keySize == 2048 || m_keySize == 3072 || m_keySize == 4096))
      m_keySize = 2048;

  m_id = id;
  m_networkInterface = 0;
  m_port = m_externalPort = quint16(port.toInt());
#if QT_VERSION >= 0x050000
  connect(this,
	  SIGNAL(newConnection(const qintptr)),
	  this,
	  SLOT(slotNewConnection(const qintptr)));
#else
  connect(this,
	  SIGNAL(newConnection(const int)),
	  this,
	  SLOT(slotNewConnection(const int)));
#endif
  connect(m_externalAddress,
	  SIGNAL(ipAddressDiscovered(const QHostAddress &)),
	  this,
	  SLOT(slotExternalAddressDiscovered(const QHostAddress &)));
  setMaxPendingConnections(maximumClients);
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

  prepareNetworkInterface();

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "listeners.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);
	query.prepare("SELECT status_control, maximum_clients "
		      "FROM listeners WHERE OID = ?");
	query.bindValue(0, m_id);

	if(query.exec())
	  {
	    if(query.next())
	      {
		QString status(query.value(0).toString());

		if(status == "offline")
		  close();
		else if(status == "online")
		  {
		    if(!isListening())
		      {
			if(!listen(m_address, m_port))
			  spoton_misc::logError
			    (QString("spoton_listener::slotTimeout(): "
				     "%1.").arg(errorString()));
			else
			  {
			    prepareNetworkInterface();

			    /*
			    ** Initial discovery of the external
			    ** IP address.
			    */

			    m_externalAddress->discover();
			  }
		      }

		    if(isListening())
		      {
			if(query.value(1).toInt() != maxPendingConnections())
			  {
			    int maximumPendingConnections = query.value(1).
			      toInt();

			    if(!maximumPendingConnections)
			      maximumPendingConnections = 1;
			    else if(maximumPendingConnections % 5 != 0)
			      maximumPendingConnections = 1;

			    setMaxPendingConnections
			      (maximumPendingConnections);
			  }
		      }
		  }

		if(isListening())
		  {
		    if(!m_externalAddressDiscovererTimer.isActive())
		      m_externalAddressDiscovererTimer.start(30000);
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
      spoton_misc::logError("spoton_listener_::slotTimeout(): instructed "
			    "to delete listener.");
      deleteLater();
    }

  if(isListening())
    if(!m_networkInterface || !(m_networkInterface->flags() &
				QNetworkInterface::IsUp))
      {
	if(m_networkInterface)
	  spoton_misc::logError
	    (QString("spoton_listener::slotTimeout(): "
		     "network interface %1 is not active. "
		     "Aborting.").
	     arg(m_networkInterface->name()));
	else
	  spoton_misc::logError("spoton_listener::slotTimeout(): "
				"undefined network interface. "
				"Aborting.");

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
void spoton_listener::slotNewConnection(const qintptr socketDescriptor)
#else
void spoton_listener::slotNewConnection(const int socketDescriptor)
#endif
{
  QByteArray certificate;
  QByteArray privateKey;
  QPointer<spoton_neighbor> neighbor = 0;
  QString error("");

  if(m_keySize != 0)
    {
      QByteArray publicKey;

      spoton_crypt::generateSslKeys
	(m_keySize,
	 certificate,
	 privateKey,
	 publicKey,
	 m_externalAddress->address(),
	 error);
    }

  if(error.isEmpty())
    neighbor = new spoton_neighbor
      (socketDescriptor, certificate, privateKey, m_echoMode, this);
  else
    {
      QTcpSocket socket;

      socket.setSocketDescriptor(socketDescriptor);
      socket.close();
      spoton_misc::logError
	(QString("spoton_listener::"
		 "slotNewConnection(): "
		 "generateSslKeys() failure (%1).").
	 arg(error.remove(".")));
    }

  if(!neighbor)
    return;

  connect(neighbor,
	  SIGNAL(disconnected(void)),
	  neighbor,
	  SLOT(deleteLater(void)));
  connect(neighbor,
	  SIGNAL(destroyed(void)),
	  this,
	  SLOT(slotNeighborDisconnected(void)));
  updateConnectionCount();

  spoton_crypt *s_crypt = 0;

  if(spoton_kernel::s_crypts.contains("messaging"))
    s_crypt = spoton_kernel::s_crypts["messaging"];

  if(!s_crypt)
    {
      spoton_misc::logError
	("spoton_listener::slotNewConnection(): "
	 "messaging key is missing.");
      neighbor->deleteLater();
      return;
    }

  QString country
    (spoton_misc::
     countryNameFromIPAddress(neighbor->peerAddress().toString()));

#ifdef SPOTON_LINKED_WITH_LIBGEOIP
  if(!spoton_misc::isPrivateNetwork(neighbor->peerAddress()))
    if(country == "Unknown" ||
       !spoton_misc::countryAllowedToConnect(country.remove(" "),
					     s_crypt))
      {
	if(country == "Unknown")
	  spoton_misc::logError
	    (QString("spoton_listener::slotNewConnection(): "
		     "unknown country. Terminating connection from "
		     "%1:%2.").
	     arg(neighbor->peerAddress().toString()).
	     arg(neighbor->peerPort()));
	else
	  spoton_misc::logError
	    (QString("spoton_listener::slotNewConnection(): "
		     "country %1 is blocked. Terminating "
		     "connection from %2:%3.").
	     arg(country).
	     arg(neighbor->peerAddress().toString()).
	     arg(neighbor->peerPort()));

	neighbor->deleteLater();
	return;
      }
#endif

  QString connectionName("");
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
		       "ssl_key_size) "
		       "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
		       "?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
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
				     neighbor->peerAddress().scopeId()).
				    toLatin1(), &ok).toBase64());

	    query.bindValue(8, 0);

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
	      created = query.exec();

	    if(ok)
	      {
		QSqlQuery query(db);

		query.setForwardOnly(true);

		if(query.exec("SELECT OID, remote_ip_address, "
			      "remote_port, scope_id FROM neighbors"))
		  while(query.next())
		    {
		      QByteArray b1;
		      QByteArray b2;
		      QByteArray b3;

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

		      if(b1 == neighbor->peerAddress().toString() &&
			 b2.toUShort() == neighbor->peerPort() &&
			 b3 == neighbor->peerAddress().scopeId()) /*
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
      spoton_misc::logError("spoton_listener::slotEncrypted(): "
			    "severe error(s). Purging neighbor "
			    "object.");
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
	if(addresses.at(j).ip() == serverAddress())
	  {
	    m_networkInterface = new QNetworkInterface(list.at(i));
	    break;
	  }

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
	  spoton_crypt *s_crypt = 0;

	  if(spoton_kernel::s_crypts.contains("messaging"))
	    s_crypt = spoton_kernel::s_crypts["messaging"];

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
