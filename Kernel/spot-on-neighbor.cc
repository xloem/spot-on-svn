/*
** Copyright (c) 2013 Alexis Megas
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
#include <QUuid>
#include <QtCore/qmath.h>

#include <limits>

#include "Common/spot-on-gcrypt.h"
#include "Common/spot-on-misc.h"
#include "Common/spot-on-send.h"
#include "spot-on-kernel.h"
#include "spot-on-neighbor.h"

quint64 spoton_neighbor::s_dbId = 0;

spoton_neighbor::spoton_neighbor(const int socketDescriptor,
				 QObject *parent):QTcpSocket(parent)
{
  s_dbId += 1;
  setSocketDescriptor(socketDescriptor);
  m_address = peerAddress();
  m_id = std::numeric_limits<qint64>::min();
  m_networkInterface = 0;
  m_port = peerPort();
  m_sendKeysOffset = 0;
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
  connect(&m_sendKeysTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotSendKeys(void)));
  connect(&m_timer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotTimeout(void)));
  connect(&m_lifetime,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotLifetimeExpired(void)));
  m_sendKeysTimer.start(2500);
  m_timer.start(2500);
  m_lifetime.setInterval(10 * 60 * 1000);
  m_lifetime.start();
  sendUuid();
}

spoton_neighbor::spoton_neighbor(const QString &ipAddress,
				 const QString &port,
				 const QString &scopeId,
				 const qint64 id,
				 QObject *parent):QTcpSocket(parent)
{
  s_dbId += 1;
  m_address = QHostAddress(ipAddress);
  m_address.setScopeId(scopeId);
  m_id = id;
  m_networkInterface = 0;
  m_port = quint16(port.toInt());
  m_sendKeysOffset = 0;
  m_sendKeysTimer.setInterval(2500);
  setSocketOption(QAbstractSocket::KeepAliveOption, 1);
  connect(this,
	  SIGNAL(connected(void)),
	  &m_sendKeysTimer,
	  SLOT(start(void)));
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
  connect(&m_sendKeysTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotSendKeys(void)));
  connect(&m_timer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotTimeout(void)));
  connect(&m_lifetime,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotLifetimeExpired(void)));
  m_timer.start(2500);
  m_lifetime.setInterval(10 * 60 * 1000);
  m_lifetime.start();
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
	query.prepare("UPDATE neighbors SET local_ip_address = '127.0.0.1', "
		      "local_port = 0, status = 'disconnected' "
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
  prepareNetworkInterface();

  /*
  ** We'll change states here.
  */

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
		QString status(query.value(0).toString().trimmed());

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
	  spoton_misc::logError(QString("spoton_neighbor::slotTimeout(): "
					"network interface (%1) is not active. "
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

void spoton_neighbor::slotSendKeys(void)
{
  if(state() != QAbstractSocket::ConnectedState)
    return;

  {
    QSqlDatabase db = QSqlDatabase::addDatabase
      ("QSQLITE", "spoton_neighbor_" + QString::number(s_dbId));

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "public_keys.db");

    if(db.open())
      {
	/*
	** We'll terminate the m_sendKeysTimer once all of the keys
	** have been read. As new keys arrive, we'll be responsible
	** for sending them to other neighbors.
	*/

	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec(QString("SELECT key FROM public_keys LIMIT 1 "
			      "OFFSET %1").
		      arg(m_sendKeysOffset)))
	  {
	    if(query.next())
	      {
		QByteArray message(query.value(0).toByteArray().toBase64());
		char c = 0;
		short ttl = spoton_kernel::s_settings.value
		  ("kernel/ttl_0010", 16).toInt();

		memcpy(&c, static_cast<void *> (&ttl), 1);
		message.prepend(c);
		message = spoton_send::message0010(message);

		if(write(message.constData(), message.length()) !=
		   message.length())
		  spoton_misc::logError
		    ("spoton_neighbor::slotSendKeys(): write() "
		     "error.");
		else
		  flush();

		m_sendKeysOffset += 1;
	      }
	    else if(!query.lastError().isValid())
	      m_sendKeysTimer.stop();
	  }
	else if(!query.lastError().isValid())
	  m_sendKeysTimer.stop();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase
    ("spoton_neighbor_" + QString::number(s_dbId));
}

void spoton_neighbor::slotReadyRead(void)
{
  m_data.append(readAll());

  if(m_data.isEmpty() ||
     m_data.length() > spoton_kernel::s_settings.
     value("kernel/maximum_number_of_bytes_buffered_by_neighbor",
	   100000).toInt())
    {
      spoton_misc::logError
	("spoton_neighbor::slotReadyRead(): m_data.isEmpty() or "
	 "m_data.length() > "
	 "maximum_number_of_bytes_buffered_by_neighbor. Abort!");
      abort();
    }

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
	  else if(length > 0 && data.contains("type=0010&content="))
	    process0010(length, data);
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
	  else
	    spoton_misc::logError(QString("spoton_neighbor::slotReadyRead(): "
					  "received unknown message (%1).").
				  arg(data.constData()));
	}
    }
}

void spoton_neighbor::slotConnected(void)
{
  {
    QSqlDatabase db = QSqlDatabase::addDatabase
      ("QSQLITE", "spoton_neighbor_" + QString::number(s_dbId));

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "neighbors.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.prepare("UPDATE neighbors SET local_ip_address = ?, "
		      "local_port = ?, status = 'connected' "
		      "WHERE OID = ?");
	query.bindValue(0, localAddress().toString());
	query.bindValue(1, localPort());
	query.bindValue(2, m_id);
	query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton_neighbor_" + QString::number(s_dbId));
  sendUuid();
}

void spoton_neighbor::savePublicKey(const QByteArray &name,
				    const QByteArray &publicKey,
				    const qint64 neighborOid)
{
  /*
  ** Save a friendly key.
  */

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
	QSqlQuery query(db);
	int value = -10;

	if(neighborOid != -1)
	  {
	    /*
	    ** We have received a request for friendship.
	    ** Do we already have the neighbor's public key?
	    ** If we've already accepted the public key, we should
	    ** respond with our public key.
	    */

	    query.setForwardOnly(true);
	    query.prepare("SELECT neighbor_oid "
			  "FROM friends_public_keys "
			  "WHERE public_key = ?");
	    query.bindValue(0, publicKey);

	    if(query.exec())
	      if(query.next())
		value = query.value(0).toInt();
	  }

	if(value != -1)
	  spoton_misc::saveFriendshipBundle
	    (name, publicKey, neighborOid, db);
	else
	  share = true;
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton_neighbor_" + QString::number(s_dbId));

  if(share)
    if(spoton_kernel::s_crypt1)
      {
	QByteArray myName
	  (spoton_kernel::s_settings.
	   value("gui/nodeName",
		 "unknown").toByteArray().trimmed());
	QByteArray myPublicKey;
	bool ok = true;

	myPublicKey = spoton_kernel::s_crypt1->publicKey(&ok);

	if(ok)
	  sharePublicKey(myName, myPublicKey);
      }
}

void spoton_neighbor::savePublicKey(const QByteArray &publicKey)
{
  /*
  ** Save a public key.
  */

  {
    QSqlDatabase db = QSqlDatabase::addDatabase
      ("QSQLITE", "spoton_neighbor_" + QString::number(s_dbId));

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() +
       "public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.prepare("INSERT INTO public_keys (key) VALUES (?)");
	query.bindValue(0, publicKey);
	query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton_neighbor_" + QString::number(s_dbId));
}

qint64 spoton_neighbor::id(void) const
{
  return m_id;
}

void spoton_neighbor::setId(const qint64 id)
{
  m_id = id;
}

void spoton_neighbor::slotReceivedPublicKey(const QByteArray &data,
					    const qint64 id)
{
  /*
  ** A neighbor (id) received a public key. This neighbor now needs
  ** to send the key to its peer. Please note that data also contains
  ** the TTL.
  */

  if(id != m_id)
    if(state() == QAbstractSocket::ConnectedState)
      {
	QByteArray message(spoton_send::message0010(data));

	if(write(message.constData(), message.length()) != message.length())
	  spoton_misc::logError
	    ("spoton_neighbor::slotReceivedPublicKey(): write() "
	     "error.");
	else
	  flush();
      }
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

void spoton_neighbor::slotLifetimeExpired(void)
{
  abort();
}

void spoton_neighbor::sharePublicKey(const QByteArray &name,
				     const QByteArray &publicKey)
{
  if(state() != QAbstractSocket::ConnectedState)
    return;

  QByteArray message;

  message.append(name.toBase64());
  message.append("\n");
  message.append(publicKey.toBase64());
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
      /*
      ** We are essentially performing an inverse function.
      ** Please see Documentation/PROTOCOLS.
      */

      data = QByteArray::fromBase64(data);

      bool ok = true;
      short ttl = 0;

      if(!data.isEmpty())
	memcpy(static_cast<void *> (&ttl),
	       static_cast<const void *> (data.constData()), 1);

      if(ttl > 0)
	ttl -= 1;

      data.remove(0, 1); // Remove TTL.

      QByteArray hash(spoton_gcrypt::sha512Hash(data, &ok));
      QByteArray originalData(data); /*
				     ** We may need to echo the
				     ** message. Don't forget to
				     ** decrease the TTL!
				     */
      bool duplicate = false;

      if(ok)
	{
	  if(spoton_kernel::s_messagingCache.contains(hash))
	    duplicate = true;
	  else
	    spoton_kernel::s_messagingCache.insert(hash, 0);
	}

      QList<QByteArray> list(data.split('\n'));

      if(list.size() != 6)
	{
	  spoton_misc::logError
	    (QString("spoton_neighbor::process0000(): "
		     "received irregular data. Expecting 6 entries, "
		     "received %1.").arg(list.size()));
	  return;
	}

      for(int i = 0; i < list.size(); i++)
	list.replace(i, QByteArray::fromBase64(list.at(i)));

      QByteArray symmetricKey(list.at(0));
      QByteArray symmetricKeyAlgorithm(list.at(1));

      symmetricKey = spoton_kernel::s_crypt1->
	publicKeyDecrypt(symmetricKey, &ok);

      if(ok)
	symmetricKeyAlgorithm = spoton_kernel::s_crypt1->
	  publicKeyDecrypt(symmetricKeyAlgorithm, &ok);

      if(ok)
	{
	  QByteArray computedHash;
	  QByteArray message(list.at(5));
	  QByteArray messageDigest(list.at(2));
	  QByteArray name(list.at(4));
	  QByteArray publicKeyHash(list.at(3));

	  spoton_gcrypt crypt(symmetricKeyAlgorithm,
			      QString("sha512"),
			      QByteArray(),
			      symmetricKey,
			      0,
			      0,
			      QString(""));

	  messageDigest = crypt.decrypted(messageDigest, &ok);

	  if(ok)
	    publicKeyHash = crypt.decrypted(publicKeyHash, &ok);

	  if(ok)
	    name = crypt.decrypted(name, &ok);

	  if(ok)
	    message = crypt.decrypted(message, &ok);

	  if(ok)
	    computedHash = crypt.keyedHash
	      (symmetricKey + symmetricKeyAlgorithm +
	       publicKeyHash + name + message, &ok);

	  if(ok && computedHash == messageDigest)
	    {
	      if(!duplicate)
		if(spoton_misc::isAcceptedParticipant(publicKeyHash))
		  {
		    saveParticipantStatus(name, publicKeyHash);
		    emit receivedChatMessage
		      ("message_" +
		       name.toBase64() + "_" +
		       message.toBase64().append('\n'));
		  }
	    }
	  else if(ttl > 0)
	    {
	      /*
	      ** Replace TTL.
	      */

	      char c = 0;

	      memcpy(&c, static_cast<void *> (&ttl), 1);
	      originalData.prepend(c);
	      emit receivedChatMessage(originalData, m_id);
	    }
	}
      else if(ttl > 0)
	{
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

void spoton_neighbor::process0010(int length, const QByteArray &dataIn)
{
  length -= strlen("type=0010&content=");

  /*
  ** We may have received a public key.
  */

  QByteArray data(dataIn.mid(0, dataIn.lastIndexOf("\r\n") + 2));

  data.remove
    (0,
     data.indexOf("type=0010&content=") + strlen("type=0010&content="));

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
      data = QByteArray::fromBase64(data);
      savePublicKey(data);

      if(ttl > 0)
	{
	  data = data.toBase64(); // The public key as Base-64.

	  /*
	  ** We received a key. We need to send this key to the
	  ** other neighbors. Prepend the TTL.
	  */

	  char c = 0;

	  memcpy(&c, static_cast<void *> (&ttl), 1);
	  data.prepend(c);
	  emit receivedPublicKey(data, m_id);
	}
    }
  else
    spoton_misc::logError
      (QString("spoton_neighbor::process0010(): 0010 "
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

      if(list.size() != 2)
	{
	  spoton_misc::logError
	    (QString("spoton_neighbor::process0011(): "
		     "received irregular data. Expecting 2 entries, "
		     "received %1.").arg(list.size()));
	  return;
	}

      for(int i = 0; i < list.size(); i++)
	list.replace(i, QByteArray::fromBase64(list.at(i)));

      savePublicKey(list.at(0), list.at(1), m_id);
    }
  else
    spoton_misc::logError
      (QString("spoton_neighbor::process0011(): 0011 "
	       "content-length mismatch (advertised: %1, received: %2).").
       arg(length).arg(data.length()));
}

void spoton_neighbor::process0012(int length, const QByteArray &dataIn)
{
  if(!spoton_kernel::s_crypt1)
    return;

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

      if(list.size() != 2)
	{
	  spoton_misc::logError
	    (QString("spoton_neighbor::process0012(): "
		     "received irregular data. Expecting 2 entries, "
		     "received %1.").arg(list.size()));
	  return;
	}

      for(int i = 0; i < list.size(); i++)
	list.replace(i, QByteArray::fromBase64(list.at(i)));

      savePublicKey(list.at(0), list.at(1), -1);
    }
  else
    spoton_misc::logError
      (QString("spoton_neighbor::process0012(): 0012 "
	       "content-length mismatch (advertised: %1, received: %2).").
       arg(length).arg(data.length()));
}

void spoton_neighbor::process0013(int length, const QByteArray &dataIn)
{
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

      if(list.size() != 6)
	{
	  spoton_misc::logError
	    (QString("spoton_neighbor::process0013(): "
		     "received irregular data. Expecting 6 entries, "
		     "received %1.").arg(list.size()));
	  return;
	}

      for(int i = 0; i < list.size(); i++)
	list.replace(i, QByteArray::fromBase64(list.at(i)));

      QByteArray symmetricKey(list.at(0));
      QByteArray symmetricKeyAlgorithm(list.at(1));

      symmetricKey = spoton_kernel::s_crypt1->
	publicKeyDecrypt(symmetricKey, &ok);

      if(ok)
	symmetricKeyAlgorithm = spoton_kernel::s_crypt1->
	  publicKeyDecrypt(symmetricKeyAlgorithm, &ok);

      if(ok)
	{
	  QByteArray computedHash;
	  QByteArray messageDigest(list.at(2));
	  QByteArray name(list.at(3));
	  QByteArray publicKeyHash(list.at(4));
	  QByteArray status(list.at(5));

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
	    messageDigest = crypt.decrypted(messageDigest, &ok);

	  if(ok)
	    status = crypt.decrypted(status, &ok);

	  if(ok)
	    computedHash = crypt.keyedHash
	      (symmetricKey + symmetricKeyAlgorithm +
	       name + publicKeyHash + status, &ok);

	  if(ok && computedHash == messageDigest)
	    {
	      if(spoton_misc::isAcceptedParticipant(publicKeyHash))
		saveParticipantStatus(name, publicKeyHash, status);
	    }
	  else if(ttl > 0)
	    {
	      /*
	      ** Replace TTL.
	      */

	      char c = 0;

	      memcpy(&c, static_cast<void *> (&ttl), 1);
	      originalData.prepend(c);
	      emit receivedStatusMessage(originalData, m_id);
	    }
	}
      else if(ttl > 0)
	{
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

      QUuid uuid(QUuid::fromRfc4122(data));

      if(uuid.isNull())
	spoton_misc::logError
	  ("spoton_neighbor::process0014(): QUuid::fromRfc4122() failure.");
      else
	{
	  {
	    QSqlDatabase db = QSqlDatabase::addDatabase
	      ("QSQLITE", "spoton_neighbor_" + QString::number(s_dbId));

	    db.setDatabaseName
	      (spoton_misc::homePath() + QDir::separator() + "neighbors.db");

	    if(db.open())
	      {
		QSqlQuery query(db);

		query.prepare("UPDATE neighbors SET uuid = ? "
			      "WHERE OID = ? AND uuid IS NULL");
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
			  "neighbor_oid = -1, "
			  "last_status_update = ? "
			  "WHERE public_key_hash = ?");
	    query.bindValue(0, name);
	    query.bindValue
	      (1, QDateTime::currentDateTime().toString(Qt::ISODate));
	    query.bindValue(2, publicKeyHash.toBase64());
	  }
	else
	  {
	    query.prepare("UPDATE friends_public_keys SET "
			  "name = ?, "
			  "neighbor_oid = -1, "
			  "status = ?, "
			  "last_status_update = ? "
			  "WHERE public_key_hash = ?");
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

void spoton_neighbor::sendUuid(void)
{
  QByteArray message;
  QUuid uuid(QUuid::fromRfc4122(spoton_kernel::
				s_settings.value("gui/uuid").toByteArray()));

  if(!uuid.isNull())
    {
      message = spoton_send::message0014(uuid.toRfc4122());

      if(write(message.constData(), message.length()) !=
	 message.length())
	spoton_misc::logError
	  ("spoton_neighbor::sendUuid(): write() error.");
      else
	flush();
    }
  else
    spoton_misc::logError("spoton_neighbor::sendUuid(): "
			  "QUuid::fromRfc4122() failure.");
}
