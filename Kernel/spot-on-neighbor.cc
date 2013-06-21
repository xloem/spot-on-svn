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

#include <QDateTime>
#include <QDir>
#include <QNetworkInterface>
#include <QSqlError>
#include <QSqlQuery>
#include <QtCore/qmath.h>

#include <limits>

#include "Common/spot-on-external-address.h"
#include "Common/spot-on-gcrypt.h"
#include "Common/spot-on-misc.h"
#include "Common/spot-on-send.h"
#include "spot-on-kernel.h"
#include "spot-on-neighbor.h"

qint64 spoton_neighbor::s_dbId = 0;

spoton_neighbor::spoton_neighbor(const int socketDescriptor,
				 QObject *parent):QTcpSocket(parent)
{
  s_dbId += 1;
  setSocketDescriptor(socketDescriptor);
  m_address = peerAddress();
  m_ipAddress = m_address.toString();
  m_externalAddress = new spoton_external_address(this);
  m_id = s_dbId; // This neighbor was created by a listener.
  m_lastReadTime = QDateTime::currentDateTime();
  m_networkInterface = 0;
  m_port = peerPort();
  setReadBufferSize(8192);
  setSocketOption(QAbstractSocket::KeepAliveOption, 1);
  connect(this,
	  SIGNAL(disconnected(void)),
	  this,
	  SLOT(deleteLater(void)));
  connect(this,
	  SIGNAL(error(QAbstractSocket::SocketError)),
	  this,
	  SLOT(slotError(QAbstractSocket::SocketError)));
  connect(this,
	  SIGNAL(readyRead(void)),
	  this,
	  SLOT(slotReadyRead(void)));
  connect(m_externalAddress,
	  SIGNAL(ipAddressDiscovered(const QHostAddress &)),
	  this,
	  SLOT(slotExternalAddressDiscovered(const QHostAddress &)));
  connect(&m_keepAliveTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotSendKeepAlive(void)));
  connect(&m_timer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotTimeout(void)));
  connect(&m_lifetime,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotLifetimeExpired(void)));
  connect(&m_externalAddressDiscovererTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotDiscoverExternalAddress(void)));
  m_externalAddressDiscovererTimer.start(30000);
  m_keepAliveTimer.start(30000);
  m_lifetime.start(10 * 60 * 1000);
  m_timer.start(2500);
  QTimer::singleShot(15000, this, SLOT(slotSendUuid(void)));
}

spoton_neighbor::spoton_neighbor(const QNetworkProxy &proxy,
				 const QString &ipAddress,
				 const QString &port,
				 const QString &scopeId,
				 const qint64 id,
				 QObject *parent):QTcpSocket(parent)
{
  s_dbId += 1;
  setProxy(proxy);
  m_address = QHostAddress(ipAddress);
  m_ipAddress = ipAddress;

  if(m_address.isNull())
    if(!m_ipAddress.isEmpty())
      QHostInfo::lookupHost(m_ipAddress,
			    this, SLOT(slotHostFound(const QHostInfo &)));

  m_address.setScopeId(scopeId);
  m_externalAddress = new spoton_external_address(this);
  m_id = id;
  m_lastReadTime = QDateTime::currentDateTime();
  m_networkInterface = 0;
  m_port = quint16(port.toInt());
  setReadBufferSize(8192);
  setSocketOption(QAbstractSocket::KeepAliveOption, 1);
  connect(this,
	  SIGNAL(connected(void)),
	  this,
	  SLOT(slotConnected(void)));
  connect(this,
	  SIGNAL(disconnected(void)),
	  this,
	  SLOT(deleteLater(void)));
  connect(this,
	  SIGNAL(error(QAbstractSocket::SocketError)),
	  this,
	  SLOT(slotError(QAbstractSocket::SocketError)));
  connect(this,
	  SIGNAL(readyRead(void)),
	  this,
	  SLOT(slotReadyRead(void)));
  connect(m_externalAddress,
	  SIGNAL(ipAddressDiscovered(const QHostAddress &)),
	  this,
	  SLOT(slotExternalAddressDiscovered(const QHostAddress &)));
  connect(&m_keepAliveTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotSendKeepAlive(void)));
  connect(&m_timer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotTimeout(void)));
  connect(&m_lifetime,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotLifetimeExpired(void)));
  connect(&m_externalAddressDiscovererTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotDiscoverExternalAddress(void)));
  m_externalAddressDiscovererTimer.setInterval(30000);
  m_keepAliveTimer.setInterval(30000);
  m_lifetime.start(10 * 60 * 1000);
  m_timer.start(2500);
}

spoton_neighbor::~spoton_neighbor()
{
  spoton_misc::logError
    (QString("Neighbor %1:%2 deallocated.").arg(m_address.toString()).
     arg(m_port));
  m_timer.stop();

  {
    QSqlDatabase db = QSqlDatabase::addDatabase
      ("QSQLITE", "spoton_neighbor_" + QString::number(s_dbId));

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() +
       "friends_public_keys.db");

    if(db.open())
      {
	/*
	** Remove symmetric keys that were not completely shared.
	*/

	QSqlQuery query(db);

	query.prepare("DELETE FROM friends_public_keys WHERE "
		      "neighbor_oid = ?");
	query.bindValue(0, m_id);
	query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton_neighbor_" + QString::number(s_dbId));

  {
    QSqlDatabase db = QSqlDatabase::addDatabase
      ("QSQLITE", "spoton_neighbor_" + QString::number(s_dbId));

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "neighbors.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.prepare("DELETE FROM neighbors WHERE "
		      "OID = ? AND status_control = 'deleted'");
	query.bindValue(0, m_id);
	query.exec();

	if(spoton_kernel::s_settings.
	   value("gui/keepOnlyUserDefinedNeighbors", false).toBool())
	  {
	    query.prepare("DELETE FROM neighbors WHERE "
			  "OID = ? AND status_control <> 'blocked' AND "
			  "user_defined = 0");
	    query.bindValue(0, m_id);
	    query.exec();
	  }

	query.prepare("UPDATE neighbors SET external_ip_address = NULL, "
		      "local_ip_address = NULL, "
		      "local_port = NULL, status = 'disconnected' "
		      "WHERE OID = ?");
	query.bindValue(0, m_id);
	query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton_neighbor_" + QString::number(s_dbId));

  if(m_networkInterface)
    delete m_networkInterface;
}

void spoton_neighbor::slotTimeout(void)
{
  if(state() == QAbstractSocket::ConnectedState)
    if(m_lastReadTime.secsTo(QDateTime::currentDateTime()) >= 90)
      {
	spoton_misc::logError("spoton_neighbor::slotTimeout(): "
			      "aborting because of silent connection.");
	abort();
      }

  /*
  ** We'll change states here.
  */

  /*
  ** Retrieve the interface that this neighbor is using.
  ** If the interface disappears, destroy the neighbor.
  */

  prepareNetworkInterface();

  {
    QSqlDatabase db = QSqlDatabase::addDatabase
      ("QSQLITE", "spoton_neighbor_" + QString::number(s_dbId));

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "neighbors.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);
	query.prepare("SELECT status_control, sticky "
		      "FROM neighbors WHERE OID = ?");
	query.bindValue(0, m_id);

	if(query.exec())
	  {
	    if(query.next())
	      {
		QString status(query.value(0).toString());

		if(status == "connected")
		  {
		    if(state() == QAbstractSocket::UnconnectedState)
		      connectToHost(m_address, m_port);
		  }

		if(status == "blocked" || status == "disconnected")
		  {
		    saveStatus(db, status);
		    abort();
		  }

		if(query.value(1).toInt() == 1)
		  m_lifetime.stop();
		else if(!m_lifetime.isActive())
		  m_lifetime.start();
	      }
	    else if(m_id != -1)
	      abort();
	  }
	else if(m_id != -1)
	  abort();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton_neighbor_" + QString::number(s_dbId));

  if(state() == QAbstractSocket::ConnectedState)
    if(!m_networkInterface || !(m_networkInterface->flags() &
				QNetworkInterface::IsUp))
      {
	if(m_networkInterface)
	  spoton_misc::logError
	    (QString("spoton_neighbor::slotTimeout(): "
		     "network interface %1 is not active. "
		     "Aborting socket.").
	     arg(m_networkInterface->name()));
	else
	  spoton_misc::logError("spoton_neighbor::slotTimeout(): "
				"undefined network interface. "
				"Aborting socket.");

	abort();
      }
}

void spoton_neighbor::saveStatus(QSqlDatabase &db, const QString &status)
{
  QSqlQuery query(db);

  query.prepare("UPDATE neighbors SET status = ? "
		"WHERE OID = ? AND status <> 'deleted'");
  query.bindValue(0, status);
  query.bindValue(1, m_id);
  query.exec();
}

void spoton_neighbor::slotReadyRead(void)
{
  m_data.append(readAll());

  if(m_data.isEmpty())
    spoton_misc::logError
      ("spoton_neighbor::slotReadyRead(): m_data.isEmpty().");

  if(m_data.contains(spoton_send::EOM))
    {
      QList<QByteArray> list;

      while(m_data.contains(spoton_send::EOM))
	{
	  QByteArray data
	    (m_data.mid(0,
			m_data.indexOf(spoton_send::EOM) +
			spoton_send::EOM.length()));

	  m_data.remove(0, data.length());

	  if(!data.isEmpty())
	    list.append(data);
	}

      if(list.isEmpty())
	spoton_misc::logError("spoton_neighbor::slotReadyRead(): "
			      "list is empty.");

      while(!list.isEmpty())
	{
	  QByteArray data(list.takeFirst());
	  int length = 0;

	  if(data.contains("Content-Length: "))
	    {
	      QByteArray contentLength(data);

	      contentLength.remove
		(0,
		 contentLength.indexOf("Content-Length: ") +
		 strlen("Content-Length: "));
	      length = contentLength.mid(0, contentLength.indexOf("\r\n")).
		toInt();
	    }
	  else
	    spoton_misc::logError
	      ("spoton_neighbor::slotReadyRead() "
	       "data does not contain Content-Length.");

	  if(length > 0 && data.contains("type=0000&content="))
	    {
	      if(!spoton_kernel::s_crypt1)
		spoton_misc::logError
		  ("spoton_neighbor::slotReadyRead(): "
		   "spoton_kernel::s_crypt1 is 0.");
	      else
		process0000(length, data);
	    }
	  else if(length > 0 && data.contains("type=0001a&content="))
	    {
	      if(!spoton_kernel::s_crypt1)
		spoton_misc::logError
		  ("spoton_neighbor::slotReadyRead(): "
		   "spoton_kernel::s_crypt1 is 0.");
	      else
		process0001a(length, data);
	    }
	  
	  else if(length > 0 && data.contains("type=0001b&content="))
	    {
	      if(!spoton_kernel::s_crypt1)
		spoton_misc::logError
		  ("spoton_neighbor::slotReadyRead(): "
		   "spoton_kernel::s_crypt1 is 0.");
	      else
		process0001b(length, data);
	    }
	  else if(length > 0 && data.contains("type=0002&content="))
	    {
	      if(!spoton_kernel::s_crypt1)
		spoton_misc::logError
		  ("spoton_neighbor::slotReadyRead(): "
		   "spoton_kernel::s_crypt1 is 0.");
	      else
		process0002(length, data);
	    }
	  else if(length > 0 && data.contains("type=0011&content="))
	    {
	      if(!spoton_kernel::s_crypt1)
		spoton_misc::logError
		  ("spoton_neighbor::slotReadyRead(): "
		   "spoton_kernel::s_crypt1 is 0.");
	      else
		process0011(length, data);
	    }
	  else if(length > 0 && data.contains("type=0012&content="))
	    {
	      if(!spoton_kernel::s_crypt1)
		spoton_misc::logError
		  ("spoton_neighbor::slotReadyRead(): "
		   "spoton_kernel::s_crypt1 is 0.");
	      else
		process0012(length, data);
	    }
	  else if(length > 0 && data.contains("type=0013&content="))
	    {
	      if(!spoton_kernel::s_crypt1)
		spoton_misc::logError
		  ("spoton_neighbor::slotReadyRead(): "
		   "spoton_kernel::s_crypt1 is 0.");
	      else
		process0013(length, data);
	    }
	  else if(length > 0 && data.contains("type=0014&content="))
	    process0014(length, data);
	  else if(length > 0 && data.contains("type=0015&content="))
	    process0015(length, data);
	  else if(length > 0 && data.contains("type=0030&content="))
	    {
	      if(!spoton_kernel::s_crypt1)
		spoton_misc::logError
		  ("spoton_neighbor::slotReadyRead(): "
		   "spoton_kernel::s_crypt1 is 0.");
	      else
		process0030(length, data);
	    }
	  else
	    {
	      if(readBufferSize() != 1000)
		{
		  spoton_misc::logError
		    (QString("spoton_neighbor::slotReadyRead(): "
			     "received irregular data from %1:%2. Setting "
			     "the read buffer size to 1000 bytes.").
		     arg(peerAddress().toString()).arg(peerPort()));
		  setReadBufferSize(1000);
		}
	      else
		spoton_misc::logError
		  (QString("spoton_neighbor::slotReadyRead(): "
			   "received irregular data from %1:%2. The "
			   "read buffer size remains at 1000 bytes.").
		   arg(peerAddress().toString()).arg(peerPort()));
	    }
	}
    }
}

void spoton_neighbor::slotConnected(void)
{
  if(proxy().type() != QNetworkProxy::NoProxy)
    {
      /*
      ** The local address is the address of the proxy. Unfortunately,
      ** we do not have network interfaces that have such an address. Hence,
      ** m_networkInterface will always be zero.
      */

      QHostAddress address(m_ipAddress);

      if(address.protocol() == QAbstractSocket::IPv4Protocol)
	setLocalAddress(QHostAddress("127.0.0.1"));
      else
	setLocalAddress(QHostAddress("::1"));
    }

  if(!m_keepAliveTimer.isActive())
    m_keepAliveTimer.start();

  m_lastReadTime = QDateTime::currentDateTime();

  if(spoton_kernel::s_crypt1)
    {
      {
	QSqlDatabase db = QSqlDatabase::addDatabase
	  ("QSQLITE", "spoton_neighbor_" + QString::number(s_dbId));

	db.setDatabaseName
	  (spoton_misc::homePath() + QDir::separator() + "neighbors.db");

	if(db.open())
	  {
	    QSqlQuery query(db);
	    QString country
	      (spoton_misc::countryNameFromIPAddress(peerAddress().
						     toString()));
	    bool ok = true;

	    query.prepare("UPDATE neighbors SET country = ?, "
			  "local_ip_address = ?, "
			  "local_port = ?, qt_country_hash = ?, "
			  "status = 'connected' "
			  "WHERE OID = ?");
	    query.bindValue(0, spoton_kernel::s_crypt1->
			    encrypted(country.toLatin1(), &ok).toBase64());
	    query.bindValue(1, localAddress().toString());
	    query.bindValue(2, localPort());
	    query.bindValue
	      (3, spoton_kernel::s_crypt1->keyedHash(country.remove(" ").
						     toLatin1(), &ok).
	       toBase64());
	    query.bindValue(4, m_id);
	    query.exec();
	  }

	db.close();
      }

      QSqlDatabase::removeDatabase
	("spoton_neighbor_" + QString::number(s_dbId));
    }

  QTimer::singleShot(15000, this, SLOT(slotSendUuid(void)));

  /*
  ** Initial discovery of the external IP address.
  */

  m_externalAddress->discover();
  m_externalAddressDiscovererTimer.start();
}

void spoton_neighbor::savePublicKey(const QByteArray &keyType,
				    const QByteArray &name,
				    const QByteArray &publicKey,
				    const QByteArray &signature,
				    const qint64 neighborOid)
{
  /*
  ** Save a friendly key.
  */

  if(!spoton_gcrypt::isValidSignature(publicKey, publicKey, signature))
    return;

  /*
  ** If neighborOid is -1, we have bonded two neighbors.
  */

  bool share = false;

  {
    QSqlDatabase db = QSqlDatabase::addDatabase
      ("QSQLITE", "spoton_neighbor_" + QString::number(s_dbId));

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() +
       "friends_public_keys.db");

    if(db.open())
      {
	if(neighborOid != -1)
	  {
	    /*
	    ** We have received a request for friendship.
	    ** Do we already have the neighbor's public key?
	    ** If we've already accepted the public key, we should
	    ** respond with our public key.
	    */

	    QSqlQuery query(db);

	    query.setForwardOnly(true);
	    query.prepare("SELECT neighbor_oid "
			  "FROM friends_public_keys "
			  "WHERE public_key = ?");
	    query.bindValue(0, publicKey);

	    if(query.exec())
	      if(query.next())
		if(query.value(0).toInt() == -1)
		  share = true;

	    if(!share)
	      /*
	      ** An error occurred or we do not have the public key.
	      */

	      spoton_misc::saveFriendshipBundle
		(keyType, name, publicKey, neighborOid, db);
	  }
	else
	  spoton_misc::saveFriendshipBundle
	    (keyType, name, publicKey, -1, db);
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton_neighbor_" + QString::number(s_dbId));

  if(share)
    if(spoton_kernel::s_crypt1)
      {
	QByteArray myName
	  (spoton_kernel::s_settings.value("gui/nodeName",
					   "unknown").
	   toByteArray().trimmed());
	QByteArray myPublicKey;
	QByteArray mySignature;
	bool ok = true;

	myPublicKey = spoton_kernel::s_crypt1->publicKey(&ok);

	if(ok)
	  mySignature = spoton_kernel::s_crypt1->digitalSignature
	    (myPublicKey, &ok);

	if(ok)
	  sharePublicKey(keyType, myName, myPublicKey, mySignature);
      }
}

qint64 spoton_neighbor::id(void) const
{
  return m_id;
}

void spoton_neighbor::setId(const qint64 id)
{
  m_id = id;
}

void spoton_neighbor::slotSendMessage(const QByteArray &message)
{
  if(state() == QAbstractSocket::ConnectedState)
    {
      if(write(message.constData(), message.length()) != message.length())
	spoton_misc::logError
	  ("spoton_neighbor::slotSendMessage(): write() error.");
      else
	flush();
    }
}

void spoton_neighbor::slotReceivedChatMessage(const QByteArray &data,
					      const qint64 id)
{
  /*
  ** A neighbor (id) received a message. This neighbor now needs
  ** to send the message to its peer. Please note that data also contains
  ** the TTL.
  */

  if(id != m_id)
    if(state() == QAbstractSocket::ConnectedState)
      {
	QByteArray message(spoton_send::message0000(data));

	if(write(message.constData(), message.length()) != message.length())
	  spoton_misc::logError
	    ("spoton_neighbor::slotReceivedChatMessage(): write() "
	     "error.");
	else
	  flush();
      }
}

void spoton_neighbor::slotReceivedMailMessage(const QByteArray &data,
					      const qint64 id)
{
  /*
  ** A neighbor (id) received a letter. This neighbor now needs
  ** to send the letter to its peer. Please note that data also contains
  ** the TTL.
  */

  if(id != m_id)
    if(state() == QAbstractSocket::ConnectedState)
      {
	QByteArray message(spoton_send::message0001a(data));

	if(write(message.constData(), message.length()) != message.length())
	  spoton_misc::logError
	    ("spoton_neighbor::slotReceivedMailMessage(): write() "
	     "error.");
	else
	  flush();
      }
}

void spoton_neighbor::slotReceivedStatusMessage(const QByteArray &data,
						const qint64 id)
{
  /*
  ** A neighbor (id) received a status message. This neighbor now needs
  ** to send the message to its peer. Please note that data also contains
  ** the TTL.
  */

  if(id != m_id)
    if(state() == QAbstractSocket::ConnectedState)
      {
	QByteArray message(spoton_send::message0013(data));

	if(write(message.constData(), message.length()) != message.length())
	  spoton_misc::logError
	    ("spoton_neighbor::slotReceivedStatusMessage(): write() "
	     "error.");
	else
	  flush();
      }
}

void spoton_neighbor::slotRetrieveMail(const QByteArray &data,
				       const qint64 id)
{
  /*
  ** A neighbor (id) received a request to retrieve mail. This neighbor
  ** now needs to send the message to its peer. Please note that data
  ** also contains the TTL.
  */

  if(id != m_id)
    if(state() == QAbstractSocket::ConnectedState)
      {
	QByteArray message(spoton_send::message0002(data));

	if(write(message.constData(), message.length()) != message.length())
	  spoton_misc::logError
	    ("spoton_neighbor::slotRetrieveMail(): write() "
	     "error.");
	else
	  flush();
      }
}

void spoton_neighbor::slotLifetimeExpired(void)
{
  spoton_misc::logError("spoton_neighbor::slotLifetimeExpired(): "
			"expiration time reached. Aborting socket.");
  abort();
}

void spoton_neighbor::sharePublicKey(const QByteArray &keyType,
				     const QByteArray &name,
				     const QByteArray &publicKey,
				     const QByteArray &signature)
{
  if(state() != QAbstractSocket::ConnectedState)
    return;

  QByteArray message;

  message.append(keyType.toBase64());
  message.append("\n");
  message.append(name.toBase64());
  message.append("\n");
  message.append(publicKey.toBase64());
  message.append("\n");
  message.append(signature.toBase64());
  message = spoton_send::message0012(message);

  if(write(message.constData(), message.length()) != message.length())
    spoton_misc::logError
      ("spoton_neighbor::sharePublicKey(): "
       "write() failure.");
  else
    {
      flush();

      {
	QSqlDatabase db = QSqlDatabase::addDatabase
	  ("QSQLITE", "spoton_neighbor_" + QString::number(s_dbId));

	db.setDatabaseName
	  (spoton_misc::homePath() + QDir::separator() +
	   "friends_public_keys.db");

	if(db.open())
	  {
	    QSqlQuery query(db);

	    query.prepare("UPDATE friends_public_keys SET "
			  "neighbor_oid = -1 WHERE neighbor_oid = "
			  "?");
	    query.bindValue(0, m_id);
	    query.exec();
	  }

	db.close();
      }

      QSqlDatabase::removeDatabase
	("spoton_neighbor_" + QString::number(s_dbId));
    }
}

void spoton_neighbor::process0000(int length, const QByteArray &dataIn)
{
  if(!spoton_kernel::s_crypt1)
    return;

  length -= strlen("type=0000&content=");

  /*
  ** We may have received a chat message. Let's see if the message
  ** is intended for us.
  */

  QByteArray data(dataIn.mid(0, dataIn.lastIndexOf("\r\n") + 2));

  data.remove
    (0,
     data.indexOf("type=0000&content=") + strlen("type=0000&content="));

  if(length == data.length())
    {
      data = QByteArray::fromBase64(data);

      bool ok = true;
      short ttl = 0;

      if(!data.isEmpty())
	memcpy(static_cast<void *> (&ttl),
	       static_cast<const void *> (data.constData()), 1);

      if(ttl > 0)
	ttl -= 1;

      data.remove(0, 1); // Remove TTL.

      QByteArray originalData(data); /*
				     ** We may need to echo the
				     ** message. Don't forget to
				     ** decrease the TTL!
				     */
      QList<QByteArray> list(data.split('\n'));

      if(list.size() == 2)
	{
	  /*
	  ** Gemini?
	  */

	  for(int i = 0; i < list.size(); i++)
	    list.replace(i, QByteArray::fromBase64(list.at(i)));

	  QByteArray gemini
	    (spoton_misc::findGeminiInCosmos(list.at(0),
					     spoton_kernel::s_crypt1));

	  if(!gemini.isEmpty())
	    {
	      QByteArray computedMessageDigest;
	      QByteArray message(list.at(0));
	      QByteArray messageDigest(list.at(1));
	      spoton_gcrypt crypt("aes256",
				  QString("sha512"),
				  QByteArray(),
				  gemini,
				  0,
				  0,
				  QString(""));

	      message = crypt.decrypted(message, &ok);

	      if(ok)
		messageDigest = crypt.decrypted(messageDigest, &ok);

	      if(ok)
		computedMessageDigest = crypt.keyedHash(message, &ok);

	      if(ok)
		{
		  if(computedMessageDigest == messageDigest)
		    {
		      list = message.split('\n');

		      if(list.size() != 6)
			{
			  spoton_misc::logError
			    (QString("spoton_neighbor::process0000(): "
				     "received irregular data. Expecting 6 "
				     "entries, "
				     "received %1.").arg(list.size()));
			  return;
			}
		    }
		  else
		    spoton_misc::logError("spoton_neighbor::process0000(): "
					  "computed message digest does "
					  "not match provided digest.");
		}
	    }
	}
      else if(list.size() != 6)
	{
	  spoton_misc::logError
	    (QString("spoton_neighbor::process0000(): "
		     "received irregular data. Expecting 6 "
		     "entries, "
		     "received %1.").arg(list.size()));
	  return;
	}

      for(int i = 0; i < list.size(); i++)
	list.replace(i, QByteArray::fromBase64(list.at(i)));

      QByteArray message(list.value(4));
      QByteArray messageDigest(list.value(5));
      QByteArray name(list.value(3));
      QByteArray publicKeyHash(list.value(2));
      QByteArray symmetricKey(list.value(0));
      QByteArray symmetricKeyAlgorithm(list.value(1));

      if(ok)
	symmetricKey = spoton_kernel::s_crypt1->
	  publicKeyDecrypt(symmetricKey, &ok);

      if(ok)
	symmetricKeyAlgorithm = spoton_kernel::s_crypt1->
	  publicKeyDecrypt(symmetricKeyAlgorithm, &ok);

      if(ok)
	{
	  spoton_gcrypt crypt(symmetricKeyAlgorithm,
			      QString("sha512"),
			      QByteArray(),
			      symmetricKey,
			      0,
			      0,
			      QString(""));

	  message = crypt.decrypted(message, &ok);

	  if(ok)
	    name = crypt.decrypted(name, &ok);

	  if(ok)
	    publicKeyHash = crypt.decrypted(publicKeyHash, &ok);

	  if(ok)
	    messageDigest = crypt.decrypted(messageDigest, &ok);
	}

      if(ok)
	{
	  if(spoton_misc::isAcceptedParticipant(publicKeyHash))
	    {
	      QByteArray computedMessageDigest
		(spoton_gcrypt::keyedHash(symmetricKey +
					  symmetricKeyAlgorithm +
					  publicKeyHash +
					  name +
					  message,
					  symmetricKey,
					  "sha512",
					  &ok));

	      /*
	      ** Let's not echo messages whose message digests
	      ** are incompatible.
	      */

	      if(ok)
		{
		  if(computedMessageDigest == messageDigest)
		    {
		      QByteArray hash
			(spoton_kernel::s_crypt1->
			 keyedHash(originalData, &ok));

		      saveParticipantStatus(name, publicKeyHash);

                      if(!hash.isEmpty() &&
			 !message.isEmpty() &&
			 !name.isEmpty())
			emit receivedChatMessage
			  ("message_" +
			   hash.toBase64() + "_" +
			   name.toBase64() + "_" +
			   message.toBase64().append('\n'));
		    }
		  else
		    spoton_misc::logError("spoton_neighbor::process0000(): "
					  "computed message digest does "
					  "not match provided digest.");
		}
	    }
	}
      else if(ttl > 0)
	{
	  if(isDuplicateMessage(originalData))
	    return;

	  recordMessageHash(originalData);

	  /*
	  ** Replace TTL.
	  */

	  char c = 0;

	  memcpy(&c, static_cast<void *> (&ttl), 1);
	  originalData.prepend(c);
	  emit receivedChatMessage(originalData, m_id);
	}
    }
  else
    spoton_misc::logError
      (QString("spoton_neighbor::process0000(): 0000 "
	       "content-length mismatch (advertised: %1, received: %2).").
       arg(length).arg(data.length()));
}

void spoton_neighbor::process0001a(int length, const QByteArray &dataIn)
{
  if(!spoton_kernel::s_crypt1)
    return;

  length -= strlen("type=0001a&content=");

  QByteArray data(dataIn.mid(0, dataIn.lastIndexOf("\r\n") + 2));

  data.remove
    (0,
     data.indexOf("type=0001a&content=") + strlen("type=0001a&content="));

  if(length == data.length())
    {
      data = QByteArray::fromBase64(data);

      bool ok = true;
      short ttl = 0;

      if(!data.isEmpty())
	memcpy(static_cast<void *> (&ttl),
	       static_cast<const void *> (data.constData()), 1);

      if(ttl > 0)
	ttl -= 1;

      data.remove(0, 1); // Remove TTL.

      QByteArray originalData(data); /*
				     ** We may need to echo the
				     ** message. Don't forget to
				     ** decrease the TTL!
				     */
      QList<QByteArray> list(data.split('\n'));

      if(list.size() != 11)
	{
	  spoton_misc::logError
	    (QString("spoton_neighbor::process0001a(): "
		     "received irregular data. Expecting 11 "
		     "entries, "
		     "received %1.").arg(list.size()));
	  return;
	}

      for(int i = 0; i < list.size(); i++)
	list.replace(i, QByteArray::fromBase64(list.at(i)));

      QByteArray message(list.value(9));
      QByteArray messageDigest(list.value(10));
      QByteArray name(list.value(7));
      QByteArray recipientHash(list.value(3));
      QByteArray senderPublicKeyHash1(list.value(2));
      QByteArray senderPublicKeyHash2(list.value(6));
      QByteArray subject(list.value(8));
      QByteArray symmetricKey1(list.value(0));
      QByteArray symmetricKey2(list.value(4));
      QByteArray symmetricKeyAlgorithm1(list.value(1));
      QByteArray symmetricKeyAlgorithm2(list.value(5));

      if(ok)
	symmetricKey1 = spoton_kernel::s_crypt1->
	  publicKeyDecrypt(symmetricKey1, &ok);

      if(ok)
	symmetricKeyAlgorithm1 = spoton_kernel::s_crypt1->
	  publicKeyDecrypt(symmetricKeyAlgorithm1, &ok);

      QByteArray publicKey;
      QByteArray publicKeyHash;

      if(ok)
	{
	  spoton_gcrypt crypt(symmetricKeyAlgorithm1,
			      QString("sha512"),
			      QByteArray(),
			      symmetricKey1,
			      0,
			      0,
			      QString(""));

	  recipientHash = crypt.decrypted(recipientHash, &ok);

	  if(ok)
	    publicKey = spoton_kernel::s_crypt1->publicKey(&ok);

	  if(ok)
	    publicKeyHash = spoton_gcrypt::sha512Hash(publicKey, &ok);

	  if(ok)
	    senderPublicKeyHash1 = crypt.decrypted
	      (senderPublicKeyHash1, &ok);
	}

      if(ok)
	if(publicKeyHash == recipientHash)
	  {
	    /*
	    ** This is our letter! Please remember that the message
	    ** may have been encrypted via a goldbug.
	    */

	    storeLetter(symmetricKey2,
			symmetricKeyAlgorithm2,
			senderPublicKeyHash2,
			name,
			subject,
			message,
			messageDigest,
			"0001a");
	    return;
	  }

      if(ok)
	{
	  if(spoton_kernel::s_settings.value("gui/postoffice_enabled",
					     false).toBool())
	    if(spoton_misc::isAcceptedParticipant(recipientHash))
	      if(spoton_misc::isAcceptedParticipant(senderPublicKeyHash1))
		storeLetter(list, recipientHash);
	}
      else if(ttl > 0)
	{
	  if(isDuplicateMessage(originalData))
	    return;

	  recordMessageHash(originalData);

	  /*
	  ** Replace TTL.
	  */

	  char c = 0;

	  memcpy(&c, static_cast<void *> (&ttl), 1);
	  originalData.prepend(c);
	  emit receivedMailMessage(originalData, m_id);
	}
    }
  else
    spoton_misc::logError
      (QString("spoton_neighbor::process0001a(): 0001a "
	       "content-length mismatch (advertised: %1, received: %2).").
       arg(length).arg(data.length()));
}

void spoton_neighbor::process0001b(int length, const QByteArray &dataIn)
{
  if(!spoton_kernel::s_crypt1)
    return;

  length -= strlen("type=0001b&content=");

  QByteArray data(dataIn.mid(0, dataIn.lastIndexOf("\r\n") + 2));

  data.remove
    (0,
     data.indexOf("type=0001b&content=") + strlen("type=0001b&content="));

  if(length == data.length())
    {
      data = QByteArray::fromBase64(data);

      bool ok = true;
      short ttl = 0;

      if(!data.isEmpty())
	memcpy(static_cast<void *> (&ttl),
	       static_cast<const void *> (data.constData()), 1);

      if(ttl > 0)
	ttl -= 1;

      data.remove(0, 1); // Remove TTL.

      QByteArray originalData(data); /*
				     ** We may need to echo the
				     ** message. Don't forget to
				     ** decrease the TTL!
				     */
      QList<QByteArray> list(data.split('\n'));

      if(list.size() != 7)
	{
	  spoton_misc::logError
	    (QString("spoton_neighbor::process0001b(): "
		     "received irregular data. Expecting 7 "
		     "entries, "
		     "received %1.").arg(list.size()));
	  return;
	}

      for(int i = 0; i < list.size(); i++)
	list.replace(i, QByteArray::fromBase64(list.at(i)));

      QByteArray message(list.value(5));
      QByteArray messageDigest(list.value(6));
      QByteArray name(list.value(3));
      QByteArray publicKeyHash(list.value(2));
      QByteArray subject(list.value(4));
      QByteArray symmetricKey(list.value(0));
      QByteArray symmetricKeyAlgorithm(list.value(1));

      if(ok)
	symmetricKey = spoton_kernel::s_crypt1->
	  publicKeyDecrypt(symmetricKey, &ok);

      if(ok)
	symmetricKeyAlgorithm = spoton_kernel::s_crypt1->
	  publicKeyDecrypt(symmetricKeyAlgorithm, &ok);

      if(ok)
	publicKeyHash = spoton_kernel::s_crypt1->
	  publicKeyDecrypt(publicKeyHash, &ok);

      if(ok)
	/*
	** This may be our letter! Please remember that the message
	** may have been encrypted via a goldbug.
	*/

	storeLetter(symmetricKey,
		    symmetricKeyAlgorithm,
		    publicKeyHash,
		    name,
		    subject,
		    message,
		    messageDigest,
		    "0001b");
      else if(ttl > 0)
	{
	  if(isDuplicateMessage(originalData))
	    return;

	  recordMessageHash(originalData);

	  /*
	  ** Replace TTL.
	  */

	  char c = 0;

	  memcpy(&c, static_cast<void *> (&ttl), 1);
	  originalData.prepend(c);
	  emit receivedMailMessage(originalData, m_id);
	}
    }
  else
    spoton_misc::logError
      (QString("spoton_neighbor::process0001b(): 0001b "
	       "content-length mismatch (advertised: %1, received: %2).").
       arg(length).arg(data.length()));
}

void spoton_neighbor::process0002(int length, const QByteArray &dataIn)
{
  if(!spoton_kernel::s_crypt1)
    return;

  length -= strlen("type=0002&content=");

  QByteArray data(dataIn.mid(0, dataIn.lastIndexOf("\r\n") + 2));

  data.remove
    (0,
     data.indexOf("type=0002&content=") + strlen("type=0002&content="));

  if(length == data.length())
    {
      data = QByteArray::fromBase64(data);

      bool ok = true;
      short ttl = 0;

      if(!data.isEmpty())
	memcpy(static_cast<void *> (&ttl),
	       static_cast<const void *> (data.constData()), 1);

      if(ttl > 0)
	ttl -= 1;

      data.remove(0, 1); // Remove TTL.

      QByteArray originalData(data); /*
				     ** We may need to echo the
				     ** message. Don't forget to
				     ** decrease the TTL!
				     */
      QList<QByteArray> list(data.split('\n'));

      if(list.size() != 5)
	{
	  spoton_misc::logError
	    (QString("spoton_neighbor::process0002(): "
		     "received irregular data. Expecting 5 entries, "
		     "received %1.").arg(list.size()));
	  return;
	}

      for(int i = 0; i < list.size(); i++)
	list.replace(i, QByteArray::fromBase64(list.at(i)));

      /*
      ** We must do some sort of thinking.
      ** Remember, we may receive multiple mail requests. And we may
      ** have many letters for the requesting parties. How should
      ** we retrieve the letters in a timely, yet functional, manner?
      */

      QByteArray messageDigest(list.at(4));
      QByteArray publicKeyHash(list.at(2));
      QByteArray signature(list.at(3));
      QByteArray symmetricKey(list.at(0));
      QByteArray symmetricKeyAlgorithm(list.at(1));

      if(ok)
	symmetricKey = spoton_kernel::s_crypt1->
	  publicKeyDecrypt(symmetricKey, &ok);

      if(ok)
	symmetricKeyAlgorithm = spoton_kernel::s_crypt1->
	  publicKeyDecrypt(symmetricKeyAlgorithm, &ok);

      if(ok)
	publicKeyHash = spoton_kernel::s_crypt1->
	  publicKeyDecrypt(publicKeyHash, &ok);

      if(ok)
	{
	  spoton_gcrypt crypt(symmetricKeyAlgorithm,
			      QString("sha512"),
			      QByteArray(),
			      symmetricKey,
			      0,
			      0,
			      QString(""));

	  signature = crypt.decrypted(signature, &ok);

	  if(ok)
	    messageDigest = crypt.decrypted(messageDigest, &ok);
	}

      if(ok)
	{
	  QByteArray computedMessageDigest
	    (spoton_gcrypt::keyedHash(symmetricKey +
				      symmetricKeyAlgorithm +
				      publicKeyHash +
				      signature,
				      symmetricKey,
				      "sha512",
				      &ok));

	  /*
	  ** Let's not echo messages whose message digests are
	  ** incompatible.
	  */

	  if(ok)
	    {
	      if(computedMessageDigest == messageDigest)
		{
		  QByteArray messageDigest
		    (spoton_gcrypt::keyedHash(symmetricKey +
					      symmetricKeyAlgorithm +
					      publicKeyHash,
					      symmetricKey,
					      "sha512",
					      &ok));

		  if(ok)
		    emit retrieveMail
		      (messageDigest,
		       publicKeyHash, signature);
		}
	      else
		spoton_misc::logError("spoton_neighbor::process0002(): "
				      "computed message digest does "
				      "not match provided digest.");
	    }
	}
      else if(ttl > 0)
	{
	  if(isDuplicateMessage(originalData))
	    return;

	  recordMessageHash(originalData);

	  /*
	  ** Replace TTL.
	  */

	  char c = 0;

	  memcpy(&c, static_cast<void *> (&ttl), 1);
	  originalData.prepend(c);
	  emit retrieveMail(originalData, m_id);
	}
    }
  else
    spoton_misc::logError
      (QString("spoton_neighbor::process0002(): 0002 "
	       "content-length mismatch (advertised: %1, received: %2).").
       arg(length).arg(data.length()));
}

void spoton_neighbor::process0011(int length, const QByteArray &dataIn)
{
  length -= strlen("type=0011&content=");

  /*
  ** We may have received a name and a public key.
  */

  QByteArray data(dataIn.mid(0, dataIn.lastIndexOf("\r\n") + 2));

  data.remove
    (0,
     data.indexOf("type=0011&content=") + strlen("type=0011&content="));

  if(length == data.length())
    {
      data = QByteArray::fromBase64(data);

      QList<QByteArray> list(data.split('\n'));

      if(list.size() != 4)
	{
	  spoton_misc::logError
	    (QString("spoton_neighbor::process0011(): "
		     "received irregular data. Expecting 4 entries, "
		     "received %1.").arg(list.size()));
	  return;
	}

      for(int i = 0; i < list.size(); i++)
	list.replace(i, QByteArray::fromBase64(list.at(i)));

      savePublicKey(list.at(0), list.at(1), list.at(2), list.at(3), m_id);
    }
  else
    spoton_misc::logError
      (QString("spoton_neighbor::process0011(): 0011 "
	       "content-length mismatch (advertised: %1, received: %2).").
       arg(length).arg(data.length()));
}

void spoton_neighbor::process0012(int length, const QByteArray &dataIn)
{
  length -= strlen("type=0012&content=");

  /*
  ** We may have received a name and a public key.
  */

  QByteArray data(dataIn.mid(0, dataIn.lastIndexOf("\r\n") + 2));

  data.remove
    (0,
     data.indexOf("type=0012&content=") + strlen("type=0012&content="));

  if(length == data.length())
    {
      data = QByteArray::fromBase64(data);

      QList<QByteArray> list(data.split('\n'));

      if(list.size() != 4)
	{
	  spoton_misc::logError
	    (QString("spoton_neighbor::process0012(): "
		     "received irregular data. Expecting 4 entries, "
		     "received %1.").arg(list.size()));
	  return;
	}

      for(int i = 0; i < list.size(); i++)
	list.replace(i, QByteArray::fromBase64(list.at(i)));

      savePublicKey(list.at(0), list.at(1), list.at(2), list.at(3), -1);
    }
  else
    spoton_misc::logError
      (QString("spoton_neighbor::process0012(): 0012 "
	       "content-length mismatch (advertised: %1, received: %2).").
       arg(length).arg(data.length()));
}

void spoton_neighbor::process0013(int length, const QByteArray &dataIn)
{
  if(!spoton_kernel::s_crypt1)
    return;

  length -= strlen("type=0013&content=");

  /*
  ** We may have received a status message.
  */

  QByteArray data(dataIn.mid(0, dataIn.lastIndexOf("\r\n") + 2));

  data.remove
    (0,
     data.indexOf("type=0013&content=") + strlen("type=0013&content="));

  if(length == data.length())
    {
      data = QByteArray::fromBase64(data);

      bool ok = true;
      short ttl = 0;

      if(!data.isEmpty())
	memcpy(static_cast<void *> (&ttl),
	       static_cast<const void *> (data.constData()), 1);

      if(ttl > 0)
	ttl -= 1;

      data.remove(0, 1); // Remove TTL.

      QByteArray originalData(data); /*
				     ** We may need to echo the
				     ** message. Don't forget to
				     ** decrease the TTL!
				     */
      QList<QByteArray> list(data.split('\n'));

      if(list.size() == 2)
	{
	  /*
	  ** Gemini?
	  */

	  for(int i = 0; i < list.size(); i++)
	    list.replace(i, QByteArray::fromBase64(list.at(i)));

	  QByteArray gemini
	    (spoton_misc::findGeminiInCosmos(list.at(0),
					     spoton_kernel::s_crypt1));

	  if(!gemini.isEmpty())
	    {
	      QByteArray computedMessageDigest;
	      QByteArray message(list.at(0));
	      QByteArray messageDigest(list.at(1));
	      spoton_gcrypt crypt("aes256",
				  QString("sha512"),
				  QByteArray(),
				  gemini,
				  0,
				  0,
				  QString(""));

	      message = crypt.decrypted(message, &ok);

	      if(ok)
		messageDigest = crypt.decrypted(messageDigest, &ok);

	      if(ok)
		computedMessageDigest = crypt.keyedHash(message, &ok);

	      if(ok)
		{
		  if(computedMessageDigest == messageDigest)
		    {
		      list = message.split('\n');

		      if(list.size() != 6)
			{
			  spoton_misc::logError
			    (QString("spoton_neighbor::process0013(): "
				     "received irregular data. Expecting 6 "
				     "entries, "
				     "received %1.").arg(list.size()));
			  return;
			}
		    }
		  else
		    spoton_misc::logError("spoton_neighbor::process0013(): "
					  "computed message digest does "
					  "not match provided digest.");
		}
	    }
	}
      else if(list.size() != 6)
	{
	  spoton_misc::logError
	    (QString("spoton_neighbor::process0013(): "
		     "received irregular data. Expecting 6 "
		     "entries, "
		     "received %1.").arg(list.size()));
	  return;
	}

      for(int i = 0; i < list.size(); i++)
	list.replace(i, QByteArray::fromBase64(list.at(i)));

      QByteArray messageDigest(list.value(5));
      QByteArray name(list.value(3));
      QByteArray publicKeyHash(list.value(2));
      QByteArray status(list.value(4));
      QByteArray symmetricKey(list.value(0));
      QByteArray symmetricKeyAlgorithm(list.value(1));

      if(ok)
	symmetricKey = spoton_kernel::s_crypt1->
	  publicKeyDecrypt(symmetricKey, &ok);

      if(ok)
	symmetricKeyAlgorithm = spoton_kernel::s_crypt1->
	  publicKeyDecrypt(symmetricKeyAlgorithm, &ok);

      if(ok)
	{
	  spoton_gcrypt crypt(symmetricKeyAlgorithm,
			      QString("sha512"),
			      QByteArray(),
			      symmetricKey,
			      0,
			      0,
			      QString(""));

	  name = crypt.decrypted(name, &ok);

	  if(ok)
	    publicKeyHash = crypt.decrypted(publicKeyHash, &ok);

	  if(ok)
	    status = crypt.decrypted(status, &ok);

	  if(ok)
	    messageDigest = crypt.decrypted(messageDigest, &ok);
	}

      if(ok)
	{
	  QByteArray computedMessageDigest
	    (spoton_gcrypt::keyedHash(symmetricKey +
				      symmetricKeyAlgorithm +
				      publicKeyHash +
				      name +
				      status,
				      symmetricKey,
				      "sha512",
				      &ok));

	  /*
	  ** Let's not echo messages whose message digests are
	  ** incompatible.
	  */

	  if(ok)
	    {
	      if(computedMessageDigest == messageDigest)
		{
		  if(spoton_misc::isAcceptedParticipant(publicKeyHash))
		    saveParticipantStatus(name, publicKeyHash, status);
		}
	      else
		spoton_misc::logError("spoton_neighbor::process0013(): "
				      "computed message digest does "
				      "not match provided digest.");
	    }
	}
      else if(ttl > 0)
	{
	  if(isDuplicateMessage(originalData))
	    return;

	  recordMessageHash(originalData);

	  /*
	  ** Replace TTL.
	  */

	  char c = 0;

	  memcpy(&c, static_cast<void *> (&ttl), 1);
	  originalData.prepend(c);
	  emit receivedStatusMessage(originalData, m_id);
	}
    }
  else
    spoton_misc::logError
      (QString("spoton_neighbor::process0013(): 0013 "
	       "content-length mismatch (advertised: %1, received: %2).").
       arg(length).arg(data.length()));
}

void spoton_neighbor::process0014(int length, const QByteArray &dataIn)
{
  length -= strlen("type=0014&content=");

  /*
  ** We may have received a status message.
  */

  QByteArray data(dataIn.mid(0, dataIn.lastIndexOf("\r\n") + 2));

  data.remove
    (0,
     data.indexOf("type=0014&content=") + strlen("type=0014&content="));

  if(length == data.length())
    {
      data = QByteArray::fromBase64(data);

      QUuid uuid(data.constData());

      if(uuid.isNull())
	spoton_misc::logError
	  ("spoton_neighbor::process0014(): empty UUID.");
      else
	{
	  m_receivedUuid = uuid;

	  {
	    QSqlDatabase db = QSqlDatabase::addDatabase
	      ("QSQLITE", "spoton_neighbor_" + QString::number(s_dbId));

	    db.setDatabaseName
	      (spoton_misc::homePath() + QDir::separator() + "neighbors.db");

	    if(db.open())
	      {
		QSqlQuery query(db);

		query.prepare("UPDATE neighbors SET uuid = ? "
			      "WHERE OID = ?");
		query.bindValue(0, uuid.toString());
		query.bindValue(1, m_id);
		query.exec();
	      }

	    db.close();
	  }

	  QSqlDatabase::removeDatabase
	    ("spoton_neighbor_" + QString::number(s_dbId));
	}
    }
  else
    spoton_misc::logError
      (QString("spoton_neighbor::process0014(): 0014 "
	       "content-length mismatch (advertised: %1, received: %2).").
       arg(length).arg(data.length()));
}

void spoton_neighbor::process0015(int length, const QByteArray &dataIn)
{
  length -= strlen("type=0015&content=");

  QByteArray data(dataIn.mid(0, dataIn.lastIndexOf("\r\n") + 2));

  data.remove
    (0,
     data.indexOf("type=0015&content=") + strlen("type=0015&content="));

  if(length == data.length())
    {
      data = QByteArray::fromBase64(data);

      if(data == "0")
	{
	  m_lastReadTime = QDateTime::currentDateTime();
	  spoton_misc::logError
	    (QString("spoton_neighbor::process0015(): received "
		     "keep-alive from %1:%2. Resetting time object.").
	     arg(peerAddress().toString()).arg(peerPort()));
	}
      else
	spoton_misc::logError
	  ("spoton_neighbor::process0015(): received unknown keep-alive "
	   "instruction.");
    }
  else
    spoton_misc::logError
      (QString("spoton_neighbor::process0015(): 0015 "
	       "content-length mismatch (advertised: %1, received: %2).").
       arg(length).arg(data.length()));
}

void spoton_neighbor::process0030(int length, const QByteArray &dataIn)
{
  if(!spoton_kernel::s_crypt1)
    return;

  length -= strlen("type=0030&content=");

  /*
  ** We may have received a status message.
  */

  QByteArray data(dataIn.mid(0, dataIn.lastIndexOf("\r\n") + 2));

  data.remove
    (0,
     data.indexOf("type=0030&content=") + strlen("type=0030&content="));

  if(length == data.length())
    {
      data = QByteArray::fromBase64(data);

      short ttl = 0;

      if(!data.isEmpty())
	memcpy(static_cast<void *> (&ttl),
	       static_cast<const void *> (data.constData()), 1);

      if(ttl > 0)
	ttl -= 1;

      data.remove(0, 1); // Remove TTL.

      QByteArray originalData(data); /*
				     ** We may need to echo the
				     ** message. Don't forget to
				     ** decrease the TTL!
				     */
      QList<QByteArray> list(data.split('\n'));

      for(int i = 0; i < list.size(); i++)
	list.replace(i, QByteArray::fromBase64(list.at(i)));

      if(list.size() != 3)
	{
	  spoton_misc::logError
	    (QString("spoton_neighbor::process0030(): "
		     "received irregular data. Expecting 3 "
		     "entries, "
		     "received %1.").arg(list.size()));
	  return;
	}
      else if(spoton_kernel::s_settings.
	      value("gui/acceptPublicizedListeners", false).toBool())
	{
	  QHostAddress address;

	  address.setAddress(list.at(0).constData());
	  address.setScopeId(list.at(2).constData());

	  if(!spoton_misc::isPrivateNetwork(address))
	    {
	      quint16 port = list.at(1).toUShort();

	      spoton_misc::saveNeighbor
		(address, port, spoton_kernel::s_crypt1);
	    }
	}

      if(ttl > 0)
	{
	  if(isDuplicateMessage(originalData))
	    return;

	  recordMessageHash(originalData);

	  /*
	  ** Replace TTL.
	  */

	  char c = 0;

	  memcpy(&c, static_cast<void *> (&ttl), 1);
	  originalData.prepend(c);
	  emit publicizeListenerPlaintext(originalData, m_id);
	}
    }
  else
    spoton_misc::logError
      (QString("spoton_neighbor::process0030(): 0030 "
	       "content-length mismatch (advertised: %1, received: %2).").
       arg(length).arg(data.length()));
}

void spoton_neighbor::slotSendStatus(const QList<QByteArray> &list)
{
  if(state() == QAbstractSocket::ConnectedState)
    for(int i = 0; i < list.size(); i++)
      {
	QByteArray message(spoton_send::message0013(list.at(i)));

	if(write(message.constData(), message.length()) != message.length())
	  spoton_misc::logError
	    ("spoton_neighbor::slotSendStatus(): write() "
	     "error.");
	else
	  flush();
      }
}

void spoton_neighbor::saveParticipantStatus(const QByteArray &name,
					    const QByteArray &publicKeyHash)
{
  saveParticipantStatus(name, publicKeyHash, QByteArray());
}

void spoton_neighbor::saveParticipantStatus(const QByteArray &name,
					    const QByteArray &publicKeyHash,
					    const QByteArray &status)
{
  {
    QSqlDatabase db = QSqlDatabase::addDatabase
      ("QSQLITE", "spoton_neighbor_" + QString::number(s_dbId));

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() +
       "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("PRAGMA synchronous = OFF");

	if(status.isEmpty())
	  {
	    query.prepare("UPDATE friends_public_keys SET "
			  "name = ?, "
			  "last_status_update = ? "
			  "WHERE neighbor_oid = -1 AND "
			  "public_key_hash = ?");
	    query.bindValue(0, name);
	    query.bindValue
	      (1, QDateTime::currentDateTime().toString(Qt::ISODate));
	    query.bindValue(2, publicKeyHash.toBase64());
	  }
	else
	  {
	    query.prepare("UPDATE friends_public_keys SET "
			  "name = ?, "
			  "status = ?, "
			  "last_status_update = ? "
			  "WHERE neighbor_oid = -1 AND "
			  "public_key_hash = ?");
	    query.bindValue(0, name);
	    query.bindValue(1, status);
	    query.bindValue
	      (2, QDateTime::currentDateTime().toString(Qt::ISODate));
	    query.bindValue(3, publicKeyHash.toBase64());
	  }

	query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton_neighbor_" + QString::number(s_dbId));
}

void spoton_neighbor::slotError(QAbstractSocket::SocketError error)
{
  if(error != QAbstractSocket::ConnectionRefusedError)
    spoton_misc::logError
      (QString("spoton_neighbor::slotError(): socket error %1. "
	       "Aborting socket.").arg(error));

  abort();
}

void spoton_neighbor::prepareNetworkInterface(void)
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
	if(addresses.at(j).ip() == localAddress())
	  {
	    m_networkInterface = new QNetworkInterface(list.at(i));
	    break;
	  }

      if(m_networkInterface)
	break;
    }
}

void spoton_neighbor::slotSendUuid(void)
{
  if(state() != QAbstractSocket::ConnectedState)
    return;

  QByteArray message;
  QUuid uuid(spoton_kernel::s_settings.value("gui/uuid").toString());

  if(!uuid.isNull())
    {
      message = spoton_send::message0014(uuid.toString().toLatin1());

      if(write(message.constData(), message.length()) !=
	 message.length())
	spoton_misc::logError
	  ("spoton_neighbor::slotSendUuid(): write() error.");
      else
	flush();
    }
  else
    spoton_misc::logError("spoton_neighbor::slotSendUuid(): "
			  "empty UUID.");
}

void spoton_neighbor::saveExternalAddress(const QHostAddress &address,
					  QSqlDatabase &db)
{
  if(!db.isOpen())
    return;

  QAbstractSocket::SocketState state = this->state();
  QSqlQuery query(db);
  bool ok = true;

  if(state == QAbstractSocket::ConnectedState)
    {
      if(address.isNull())
	{
	  query.prepare("UPDATE neighbors SET "
			"external_ip_address = NULL "
			"WHERE OID = ? AND external_ip_address IS "
			"NOT NULL");
	  query.bindValue(0, m_id);
	}
      else if(spoton_kernel::s_crypt1)
	{
	  query.prepare("UPDATE neighbors SET external_ip_address = ? "
			"WHERE OID = ?");
	  query.bindValue
	    (0, spoton_kernel::s_crypt1->encrypted(address.toString().
						   toLatin1(), &ok).
	     toBase64());
	  query.bindValue(1, m_id);
	}
    }
  else if(state == QAbstractSocket::UnconnectedState)
    {
      query.prepare("UPDATE neighbors SET external_ip_address = NULL "
		    "WHERE OID = ? AND external_ip_address IS NOT NULL");
      query.bindValue(0, m_id);
    }

  if(ok)
    query.exec();
}

void spoton_neighbor::slotExternalAddressDiscovered
(const QHostAddress &address)
{
  {
    QSqlDatabase db = QSqlDatabase::addDatabase
      ("QSQLITE", "spoton_neighbor_" + QString::number(s_dbId));

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "neighbors.db");

    if(db.open())
      saveExternalAddress(address, db);

    db.close();
  }

  QSqlDatabase::removeDatabase
    ("spoton_neighbor_" + QString::number(s_dbId));
}

void spoton_neighbor::slotDiscoverExternalAddress(void)
{
  if(state() == QAbstractSocket::ConnectedState)
    m_externalAddress->discover();
}

void spoton_neighbor::slotSendKeepAlive(void)
{
  if(state() == QAbstractSocket::ConnectedState)
    {
      QByteArray message(spoton_send::message0015());

      /*
      ** Sending 0015 should be a priority. Does Qt
      ** support out-of-band data?
      */

      if(write(message.constData(),
	       message.length()) != message.length())
	spoton_misc::logError
	  ("spoton_neighbor::slotSendKeepAlive(): write() "
	   "error.");
      else
	flush();
    }
}

QUuid spoton_neighbor::receivedUuid(void) const
{
  return m_receivedUuid;
}

void spoton_neighbor::slotSendMail
(const QList<QPair<QByteArray, qint64> > &list)
{
  QList<qint64> oids;

  if(state() == QAbstractSocket::ConnectedState)
    for(int i = 0; i < list.size(); i++)
      {
	QByteArray message;
	QPair<QByteArray, qint64> pair(list.at(i));

	message = spoton_send::message0001a(pair.first);

	if(write(message.constData(), message.length()) != message.length())
	  spoton_misc::logError
	    ("spoton_neighbor::slotSendMail(): write() "
	     "error.");
	else
	  {
	    flush();
	    oids.append(pair.second);
	  }
      }

  if(!oids.isEmpty())
    spoton_misc::moveSentMailToSentFolder
      (oids, spoton_kernel::s_crypt1);
}

void spoton_neighbor::slotSendMailFromPostOffice(const QByteArray &data)
{
  if(state() == QAbstractSocket::ConnectedState)
    {
      QByteArray message(spoton_send::message0001b(data));

      if(write(message.constData(), message.length()) != message.length())
	spoton_misc::logError
	  ("spoton_neighbor::slotSendMailFromPostOffice(): write() "
	   "error.");
      else
	flush();
    }
}

void spoton_neighbor::storeLetter(QByteArray &symmetricKey,
				  QByteArray &symmetricKeyAlgorithm,
				  QByteArray &senderPublicKeyHash,
				  QByteArray &name,
				  QByteArray &subject,
				  QByteArray &message,
				  QByteArray &messageDigest,
				  const QString &messageType)
{
  if(!spoton_kernel::s_crypt1)
    return;

  bool ok = true;

  /*
  ** We need to remember that the information here may have been
  ** encoded with a goldbug. The interface will prompt the user
  ** for the symmetric key.
  */

  if(messageType == "0001a")
    {
      symmetricKey = spoton_kernel::s_crypt1->publicKeyDecrypt
	(symmetricKey, &ok);

      if(!ok)
	return;

      symmetricKeyAlgorithm = spoton_kernel::s_crypt1->publicKeyDecrypt
	(symmetricKeyAlgorithm, &ok);

      if(!ok)
	return;

      senderPublicKeyHash = spoton_kernel::s_crypt1->publicKeyDecrypt
	(senderPublicKeyHash, &ok);

      if(!ok)
	return;
    }

  if(!spoton_misc::isAcceptedParticipant(senderPublicKeyHash))
    return;

  QByteArray bytes;
  bool goldbugSet = false;
  spoton_gcrypt crypt(symmetricKeyAlgorithm,
		      QString("sha512"),
		      QByteArray(),
		      symmetricKey,
		      0,
		      0,
		      QString(""));

  bytes = crypt.decrypted(name, &ok);

  if(ok)
    {
      /*
      ** OK, we were able to decipher the name.
      ** We'll assume that a goldbug was not applied.
      */

      name = bytes;
      subject = crypt.decrypted(subject, &ok);

      if(!ok)
	return;

      message = crypt.decrypted(message, &ok);

      if(!ok)
	return;

      messageDigest = crypt.decrypted(messageDigest, &ok);

      if(!ok)
	return;

      QByteArray computedMessageDigest;

      computedMessageDigest = crypt.keyedHash(symmetricKey +
					      symmetricKeyAlgorithm +
					      senderPublicKeyHash +
					      name +
					      subject +
					      message, &ok);

      if(!ok)
	return;

      if(computedMessageDigest != messageDigest)
	{
	  spoton_misc::logError("spoton_neighbor::storeLetter(): "
				"computed message digest does "
				"not match provided digest.");
	  return;
	}
    }
  else
    {
      /*
      ** Is there a goldbug loose?
      */

      goldbugSet = true;
      ok = true;
    }

  {
    QSqlDatabase db = QSqlDatabase::addDatabase
      ("QSQLITE", "spoton_neighbor_" + QString::number(s_dbId));

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "email.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.prepare("INSERT INTO folders "
		      "(date, folder_index, goldbug, hash, "
		      "message, message_digest, "
		      "receiver_sender, receiver_sender_hash, "
		      "status, subject, participant_oid) "
		      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
	query.bindValue
	  (0, spoton_kernel::s_crypt1->
	   encrypted(QDateTime::currentDateTime().
		     toString(Qt::ISODate).
		     toLatin1(), &ok).toBase64());
	query.bindValue(1, 0); // Inbox Folder

	if(ok)
	  query.bindValue
	    (2, spoton_kernel::s_crypt1->
	     encrypted(QString::number(goldbugSet).toLatin1(), &ok).
	     toBase64());

	if(ok)
	  query.bindValue
	    (3, spoton_kernel::s_crypt1->keyedHash(message + subject, &ok).
	     toBase64());

	if(!message.isEmpty())
	  if(ok)
	    query.bindValue
	      (4, spoton_kernel::s_crypt1->encrypted(message, &ok).toBase64());

	if(!messageDigest.isEmpty())
	  if(ok)
	    query.bindValue
	      (5, spoton_kernel::s_crypt1->encrypted(messageDigest, &ok).
	       toBase64());

	if(!name.isEmpty())
	  if(ok)
	    query.bindValue
	      (6, spoton_kernel::s_crypt1->encrypted(name, &ok).toBase64());

	if(ok)
	  query.bindValue
	    (7, senderPublicKeyHash.toBase64());

	if(ok)
	  query.bindValue
	    (8, spoton_kernel::s_crypt1->
	     encrypted(tr("Unread").toUtf8(), &ok).toBase64());
 
	if(!subject.isEmpty())
	  if(ok)
	    query.bindValue
	      (9, spoton_kernel::s_crypt1->encrypted(subject, &ok).toBase64());

	if(ok)
	  query.bindValue
	    (10, spoton_kernel::s_crypt1->
	     encrypted(QString::number(-1).toLatin1(), &ok).
	     toBase64());

	if(ok)
	  if(query.exec())
	    emit newEMailArrived();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton_neighbor_" + QString::number(s_dbId));
}

void spoton_neighbor::storeLetter(const QList<QByteArray> &list,
				  const QByteArray &recipientHash)
{
  if(!spoton_kernel::s_crypt1)
    return;

  {
    QSqlDatabase db = QSqlDatabase::addDatabase
      ("QSQLITE", "spoton_neighbor_" + QString::number(s_dbId));

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "email.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	query.prepare("INSERT INTO post_office "
		      "(date_received, message_bundle, "
		      "message_bundle_hash, recipient_hash) "
		      "VALUES (?, ?, ?, ?)");
	query.bindValue
	  (0, spoton_kernel::s_crypt1->
	   encrypted(QDateTime::currentDateTime().
		     toString(Qt::ISODate).
		     toLatin1(), &ok).toBase64());

	if(ok)
	  {
	    QByteArray data;

	    data.append(list.value(4).toBase64());
	    data.append("\n");
	    data.append(list.value(5).toBase64());
	    data.append("\n");
	    data.append(list.value(6).toBase64());
	    data.append("\n");
	    data.append(list.value(7).toBase64());
	    data.append("\n");
	    data.append(list.value(8).toBase64());
	    data.append("\n");
	    data.append(list.value(9).toBase64());
	    data.append("\n");
	    data.append(list.value(10).toBase64());
	    query.bindValue
	      (1, spoton_kernel::s_crypt1->encrypted(data, &ok).toBase64());

	    if(ok)
	      query.bindValue
		(2, spoton_kernel::s_crypt1->keyedHash(data, &ok).
		 toBase64());
	  }

	query.bindValue(3, recipientHash.toBase64());

	if(ok)
	  query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton_neighbor_" + QString::number(s_dbId));
}

void spoton_neighbor::slotRetrieveMail(const QList<QByteArray> &list)
{
  if(state() == QAbstractSocket::ConnectedState)
    for(int i = 0; i < list.size(); i++)
      {
	QByteArray message(spoton_send::message0002(list.at(i)));

	if(write(message.constData(), message.length()) != message.length())
	  spoton_misc::logError
	    ("spoton_neighbor::slotRetrieveMail(): write() "
	     "error.");
	else
	  flush();
      }
}

void spoton_neighbor::slotHostFound(const QHostInfo &hostInfo)
{
  foreach(const QHostAddress &address, hostInfo.addresses())
    if(!address.isNull())
      {
	m_address = address;
	m_ipAddress = m_address.toString();
	break;
      }
}

void spoton_neighbor::slotPublicizeListenerPlaintext
(const QHostAddress &address, const quint16 port)
{
  if(state() == QAbstractSocket::ConnectedState)
    {
      char c = 0;
      short ttl = spoton_kernel::s_settings.value
	("kernel/ttl_0030", 64).toInt();

      memcpy(&c, static_cast<void *> (&ttl), 1);

      QByteArray message(spoton_send::message0030(address, port, c));

      if(write(message.constData(), message.length()) != message.length())
	spoton_misc::logError
	  ("spoton_neighbor::slotPublicizeListenerPlaintext(): write() "
	   "error.");
      else
	flush();
    }
}

void spoton_neighbor::slotPublicizeListenerPlaintext(const QByteArray &data,
						     const qint64 id)
{
  /*
  ** A neighbor (id) received a request to publish listener information.
  ** This neighbor now needs to send the message to its peer. Please
  ** note that data also contains the TTL.
  */

  if(id != m_id)
    if(state() == QAbstractSocket::ConnectedState)
      {
	QByteArray message(spoton_send::message0030(data));

	if(write(message.constData(), message.length()) != message.length())
	  spoton_misc::logError
	    ("spoton_neighbor::slotPublicizeListenerPlaintext(): write() "
	     "error.");
	else
	  flush();
      }
}

void spoton_neighbor::recordMessageHash(const QByteArray &data)
{
  if(!spoton_kernel::s_crypt1)
    return;
  else if(!spoton_kernel::s_settings.value("gui/enableCongestionControl",
					   false).toBool())
    return;

  QByteArray hash;
  bool ok = true;

  hash = spoton_kernel::s_crypt1->keyedHash(data, &ok);

  if(!ok)
    return;

  if(spoton_kernel::s_messagingCache.contains(hash))
    {
      int *count = spoton_kernel::s_messagingCache.object(hash);
      int *value = new int;

      if(count)
	*value = *count + 1;
      else
	*value = 1;

      spoton_kernel::s_messagingCache.remove(hash);
      spoton_kernel::s_messagingCache.insert(hash, value);
    }
  else
    {
      int *count = new int;

      *count = 1;
      spoton_kernel::s_messagingCache.insert(hash, count);
    }
}

bool spoton_neighbor::isDuplicateMessage(const QByteArray &data)
{
  if(!spoton_kernel::s_crypt1)
    return false;

  QByteArray hash;
  bool ok = true;

  hash = spoton_kernel::s_crypt1->keyedHash(data, &ok);

  if(!ok)
    return false;

  if(spoton_kernel::s_messagingCache.contains(hash))
    {
      int *count = spoton_kernel::s_messagingCache.object(hash);

      if(count)
	if(*count > 3)
	  return true;

      return false;
    }
  else
    return false;
}
