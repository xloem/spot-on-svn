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
#include <QSqlError>
#include <QSqlQuery>
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
  m_port = peerPort();
  m_sendKeysOffset = 0;
  connect(this,
	  SIGNAL(disconnected(void)),
	  this,
	  SLOT(deleteLater(void)));
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
  m_port = quint16(port.toInt());
  m_sendKeysOffset = 0;
  m_sendKeysTimer.setInterval(2500);
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
    (QString("Neighbor %1:%2 destroyed.").arg(m_address.toString()).
     arg(m_port));
  m_timer.stop();

  {
    QSqlDatabase db = QSqlDatabase::addDatabase
      ("QSQLITE", "neighbor_" + QString::number(s_dbId));

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() +
       "friends_symmetric_keys.db");

    if(db.open())
      {
	/*
	** Remove symmetric keys that were not completely shared.
	*/

	QSqlQuery query(db);

	query.prepare("DELETE FROM symmetric_keys WHERE "
		      "neighbor_oid = ?");
	query.bindValue(0, m_id);

	if(query.exec())
	  db.commit();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("neighbor_" + QString::number(s_dbId));

  {
    QSqlDatabase db = QSqlDatabase::addDatabase
      ("QSQLITE", "neighbor_" + QString::number(s_dbId));

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "neighbors.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok1 = true;
	bool ok2 = true;

	query.prepare("DELETE FROM neighbors WHERE "
		      "OID = ? AND status_control = 'deleted'");
	query.bindValue(0, m_id);
	ok1 = query.exec();
	query.prepare("UPDATE neighbors SET local_ip_address = '127.0.0.1', "
		      "local_port = 0, "
		      "status = 'disconnected' "
		      "WHERE OID = ?");
	query.bindValue(0, m_id);
	ok2 = query.exec();

	if(ok1 && ok2)
	  db.commit();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("neighbor_" + QString::number(s_dbId));
}

void spoton_neighbor::slotTimeout(void)
{
  /*
  ** We'll change states here.
  */

  {
    QSqlDatabase db = QSqlDatabase::addDatabase
      ("QSQLITE", "neighbor_" + QString::number(s_dbId));

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

  QSqlDatabase::removeDatabase("neighbor_" + QString::number(s_dbId));
}

void spoton_neighbor::saveStatus(QSqlDatabase &db, const QString &status)
{
  QSqlQuery query(db);

  query.exec("PRAGMA synchronous = OFF");
  query.prepare("UPDATE neighbors SET status = ? "
		"WHERE OID = ? AND status <> 'deleted'");
  query.bindValue(0, status);
  query.bindValue(1, m_id);

  if(query.exec())
    db.commit();
}

void spoton_neighbor::slotSendKeys(void)
{
  if(state() != QAbstractSocket::ConnectedState)
    return;

  {
    QSqlDatabase db = QSqlDatabase::addDatabase
      ("QSQLITE", "neighbor_" + QString::number(s_dbId));

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
		QByteArray message(query.value(0).toByteArray());
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
    ("neighbor_" + QString::number(s_dbId));
}

void spoton_neighbor::slotReadyRead(void)
{
  m_data.append(readAll());

  if(m_data.isEmpty() ||
     m_data.length() > spoton_kernel::s_settings.
     value("kernel/maximum_number_of_bytes_buffered_by_neighbor",
	   25000).toInt())
    {
      spoton_misc::logError
	("spoton_neighbor::slotReadyRead(): m_data.isEmpty() or "
	 "m_data.length() > "
	 "maximum_number_of_bytes_buffered_by_neighbor. Abort!");
      abort();
    }

  if(m_data.endsWith("\r\n"))
    {
      int length = 0;

      if(m_data.contains("Content-Length: "))
	{
	  QByteArray contentLength(m_data);

	  contentLength.remove
	    (0,
	     contentLength.indexOf("Content-Length: ") +
	     strlen("Content-Length: "));
	  length = contentLength.mid(0, contentLength.indexOf("\r\n")).
	    toInt();
	}

      if(length > 0 && m_data.contains("type=0000&content="))
	{
	  if(!spoton_kernel::s_crypt1)
	    {
	      m_data.remove(0, m_data.lastIndexOf("\r\n") + 2);
	      spoton_misc::logError
		("spoton_neighbor::slotReadyRead(): "
		 "spoton_kernel::s_crypt1 is 0.");
	    }
	  else
	    process0000(length);
	}
      else if(length > 0 && m_data.contains("type=0010&content="))
	process0010(length);
      else if(length > 0 && m_data.contains("type=0011&content="))
	{
	  if(!spoton_kernel::s_crypt1)
	    {
	      m_data.remove(0, m_data.lastIndexOf("\r\n") + 2);
	      spoton_misc::logError
		("spoton_neighbor::slotReadyRead(): "
		 "spoton_kernel::s_crypt1 is 0.");
	    }
	  else
	    process0011(length);
	}
      else if(length > 0 && m_data.contains("type=0012&content="))
	{
	  if(!spoton_kernel::s_crypt1)
	    {
	      m_data.remove(0, m_data.lastIndexOf("\r\n") + 2);
	      spoton_misc::logError
		("spoton_neighbor::slotReadyRead(): "
		 "spoton_kernel::s_crypt1 is 0.");
	    }
	  else
	    process0012(length);
	}
      else
	m_data.clear();
    }
}

void spoton_neighbor::slotConnected(void)
{
  {
    QSqlDatabase db = QSqlDatabase::addDatabase
      ("QSQLITE", "neighbor_" + QString::number(s_dbId));

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "neighbors.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("PRAGMA synchronous = OFF");
	query.prepare("UPDATE neighbors SET local_ip_address = ?, "
		      "local_port = ?, status = 'connected' "
		      "WHERE OID = ?");
	query.bindValue(0, localAddress().toString());
	query.bindValue(1, localPort());
	query.bindValue(2, m_id);

	if(query.exec())
	  db.commit();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("neighbor_" + QString::number(s_dbId));
}

void spoton_neighbor::savePublicKey(const QByteArray &name,
				    const QByteArray &publicKey,
				    const QByteArray &symmetricKey,
				    const QByteArray &symmetricKeyAlgorithm,
				    const qint64 neighborOid)
{
  if(!spoton_kernel::s_crypt1)
    return;

  /*
  ** Save a friendly key.
  */

  /*
  ** If neighborOid is -1, we have bonded two neighbors.
  */

  QList<QByteArray> list;

  {
    QSqlDatabase db = QSqlDatabase::addDatabase
      ("QSQLITE", "neighbor_" + QString::number(s_dbId));

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() +
       "friends_symmetric_keys.db");

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
	    ** respond with our public key and the symmetric bundle.
	    */

	    query.prepare("SELECT neighbor_oid, "
			  "symmetric_key, symmetric_key_algorithm "
			  "FROM symmetric_keys "
			  "WHERE public_key = ?");
	    query.bindValue(0, publicKey);

	    if(query.exec())
	      if(query.next())
		value = query.value(0).toInt();
	  }

	if(value != -1)
	  {
	    query.exec("PRAGMA synchronous = OFF");
	    query.prepare("INSERT OR REPLACE INTO symmetric_keys "
			  "(name, symmetric_key, symmetric_key_algorithm, "
			  "public_key, public_key_hash, neighbor_oid) "
			  "VALUES (?, ?, ?, ?, ?, ?)");
	    query.bindValue(0, name);

	    bool ok = true;

	    if(spoton_kernel::s_crypt1)
	      {
		query.bindValue
		  (1, spoton_kernel::s_crypt1->encrypted(symmetricKey,
							 &ok).toBase64());

		if(ok)
		  query.bindValue
		    (2,
		     spoton_kernel::s_crypt1->encrypted(symmetricKeyAlgorithm,
							&ok).toBase64());
	      }
	    else
	      {
		query.bindValue(1, symmetricKey);
		query.bindValue(2, symmetricKeyAlgorithm);
	      }

	    query.bindValue(3, publicKey);

	    if(ok)
	      query.bindValue
		(4, spoton_gcrypt::sha512Hash(publicKey, &ok).toHex());

	    query.bindValue(5, neighborOid);

	    if(ok)
	      if(query.exec())
		db.commit();
	  }
	else
	  {
	    /*
	    ** We received a public key from a neighbor. We already have
	    ** this approved public key. We need to resend the
	    ** symmetric bundle.
	    */

	    QByteArray bytes1;
	    QByteArray bytes2;
	    bool ok = true;

	    if(ok)
	      bytes1 = spoton_kernel::s_crypt1->decrypted
		(QByteArray::fromBase64(query.value(1).toByteArray()),
		 &ok).trimmed();

	    if(ok)
	      bytes2 = spoton_kernel::s_crypt1->decrypted
		(QByteArray::fromBase64(query.value(2).toByteArray()),
		 &ok).trimmed();

	    if(ok)
	      {
		list.append(bytes1);
		list.append(bytes2);
	      }
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("neighbor_" + QString::number(s_dbId));

  if(!list.isEmpty())
    sharePublicKey(publicKey, list.value(0), list.value(1));
}

void spoton_neighbor::savePublicKey(const QByteArray &publicKey)
{
  /*
  ** Save a public key.
  */

  {
    QSqlDatabase db = QSqlDatabase::addDatabase
      ("QSQLITE", "neighbor_" + QString::number(s_dbId));

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() +
       "public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("PRAGMA synchronous = OFF");
	query.prepare("INSERT INTO public_keys (key) VALUES (?)");
	query.bindValue(0, publicKey);

	if(query.exec())
	  db.commit();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("neighbor_" + QString::number(s_dbId));
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

void spoton_neighbor::slotLifetimeExpired(void)
{
  abort();
}

void spoton_neighbor::sharePublicKey(const QByteArray &publicKey,
				     const QByteArray &symmetricKey,
				     const QByteArray &symmetricKeyAlgorithm)
{
  if(state() != QAbstractSocket::ConnectedState)
    return;
  else if(!spoton_kernel::s_crypt1)
    return;

  QByteArray message;

  message.append(symmetricKey);
  message.append(symmetricKeyAlgorithm.
		 leftJustified(spoton_send::
			       SYMMETRIC_KEY_ALGORITHM_MAXIMUM_LENGTH,
			       '\n'));

  bool ok = true;

  message = spoton_gcrypt::publicKeyEncrypt
    (message, publicKey, &ok).toBase64();

  if(ok)
    {
      QByteArray name // My name.
	(spoton_kernel::s_settings.value("gui/nodeName", "unknown").
	 toByteArray().trimmed());

      if(name.isEmpty())
	name = "unknown";

      QByteArray publicKey // My public key.
	(spoton_kernel::s_crypt1->publicKey(&ok));

      if(ok)
	{
	  message.append('\n');
	  message.append
	    (name.leftJustified(spoton_send::NAME_MAXIMUM_LENGTH, '\n'));
	  message.append(publicKey);
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
		  ("QSQLITE", "neighbor_" + QString::number(s_dbId));

		db.setDatabaseName
		  (spoton_misc::homePath() + QDir::separator() +
		   "friends_symmetric_keys.db");

		if(db.open())
		  {
		    QSqlQuery query(db);

		    query.prepare("UPDATE symmetric_keys SET "
				  "neighbor_oid = -1 WHERE neighbor_oid = "
				  "?");
		    query.bindValue(0, m_id);

		    if(query.exec())
		      db.commit();
		  }

		db.close();
	      }

	      QSqlDatabase::removeDatabase
		("neighbor_" + QString::number(s_dbId));
	    }
	}
      else
	spoton_misc::logError
	  ("spoton_neighbor::sharePublicKey(): "
	   "publicKey() failure.");
    }
  else
    spoton_misc::logError
      ("spoton_neighbor::sharePublicKey(): "
       "publicKeyEncrypt() failure.");
}

void spoton_neighbor::process0000(int length)
{
  if(!spoton_kernel::s_crypt1)
    return;

  length -= strlen("type=0000&content=");

  /*
  ** We may have received a chat message. Let's see if the message
  ** is intended for us.
  */

  QByteArray data(m_data.mid(0, m_data.lastIndexOf("\r\n") + 2));

  m_data.remove(0, data.length());
  data.remove
    (0,
     data.indexOf("type=0000&content=") +
     strlen("type=0000&content="));

  if(length == data.length())
    {
      /*
      ** OK, here's what we're going to do.
      ** First, we need to convert data from Base64.
      ** Second, decrypt the data with the symmetric key.
      ** Third, retrieve the checksum from the decrypted data.
      ** Fourth, compare the checksum with the computed checksum
      ** of the remaining data.
      ** Fifth, if the checksums are identical, forward the
      ** message to the UI. Otherwise, decrement TTL and
      ** forward the original message to the other neighbors if
      ** TTL is greater than zero.
      */

      data = QByteArray::fromBase64(data).trimmed();

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

      /*
      ** Find the symmetric key.
      */

      QByteArray hash
	(data.mid(0,
		  spoton_send::SHA512_HEX_OUTPUT_MAXIMUM_LENGTH));

      data.remove(0, hash.length());

      {
	QSqlDatabase db = QSqlDatabase::addDatabase
	  ("QSQLITE", "neighbor_" + QString::number(s_dbId));

	db.setDatabaseName
	  (spoton_misc::homePath() + QDir::separator() +
	   "friends_symmetric_keys.db");

	if(db.open())
	  {
	    QSqlQuery query(db);

	    query.setForwardOnly(true);
	    query.prepare("SELECT symmetric_key, "
			  "symmetric_key_algorithm "
			  "FROM symmetric_keys WHERE "
			  "HEX(public_key_hash) = HEX(?)");
	    query.bindValue(0, hash);

	    if((ok = query.exec()))
	      if((ok = query.next()))
		{
		  QByteArray symmetricKey
		    (QByteArray::fromBase64(query.value(0).
					    toByteArray()));
		  QByteArray symmetricKeyAlgorithm
		    (QByteArray::fromBase64(query.value(1).
					    toByteArray()));

		  symmetricKey = spoton_kernel::s_crypt1->
		    decrypted(symmetricKey, &ok);

		  if(ok)
		    symmetricKeyAlgorithm =
		      spoton_kernel::s_crypt1->decrypted
		      (symmetricKeyAlgorithm, &ok);

		  if(ok)
		    {
		      spoton_gcrypt crypt(symmetricKeyAlgorithm,
					  QString(""),
					  symmetricKey,
					  0,
					  0,
					  QString(""));

		      data = crypt.decrypted(data, &ok);
		    }
		}
	  }

	db.close();
      }

      QSqlDatabase::removeDatabase
	("neighbor_" + QString::number(s_dbId));

      if(ok)
	{
	  QByteArray hash1
	    (data.mid(0, spoton_send::
		      SHA512_HEX_OUTPUT_MAXIMUM_LENGTH));
	  QByteArray hash2;

	  data.remove(0, hash1.length());
	  hash2 = spoton_gcrypt::sha512Hash(data, &ok).toHex();

	  if(ok && hash1 == hash2)
	    emit receivedChatMessage
	      ("message_" + data.toBase64().append('\n'));
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
      (QString("spoton_kernel::process0000(): 0000 "
	       "content-length mismatch (advertised: %1, received: %2).").
       arg(length).arg(data.length()));
}

void spoton_neighbor::process0010(int length)
{
  length -= strlen("type=0010&content=");

  /*
  ** We may have received a public key.
  */

  QByteArray data(m_data.mid(0, m_data.lastIndexOf("\r\n") + 2));

  m_data.remove(0, data.length());
  data.remove
    (0,
     data.indexOf("type=0010&content=") +
     strlen("type=0010&content="));

  if(length == data.length())
    {
      data = QByteArray::fromBase64(data).trimmed();

      short ttl = 0;

      if(!data.isEmpty())
	memcpy(static_cast<void *> (&ttl),
	       static_cast<const void *> (data.constData()), 1);
	  
      if(ttl > 0)
	ttl -= 1;

      data.remove(0, 1); // Remove TTL.
      savePublicKey(data);
      m_data.clear();

      if(ttl > 0)
	{
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
      (QString("spoton_kernel::process0010(): 0010 "
	       "content-length mismatch (advertised: %1, received: %2).").
       arg(length).arg(data.length()));
}

void spoton_neighbor::process0011(int length)
{
  length -= strlen("type=0011&content=");

  /*
  ** We may have received a name and a public key.
  */

  QByteArray data(m_data.mid(0, m_data.lastIndexOf("\r\n") + 2));

  m_data.remove(0, data.length());
  data.remove
    (0,
     data.indexOf("type=0011&content=") +
     strlen("type=0011&content="));

  if(length == data.length())
    {
      QByteArray name;
      QByteArray publicKey;

      name = data.mid
	(0, 4 * qCeil(spoton_send::NAME_MAXIMUM_LENGTH / 3.0));
      data.remove(0, name.length());
      name = QByteArray::fromBase64(name).trimmed();
      publicKey = QByteArray::fromBase64(data).trimmed();

      QByteArray symmetricKey
	(spoton_send::SYMMETRIC_KEY_MAXIMUM_LENGTH, 0);
      QByteArray symmetricKeyAlgorithm
	(spoton_kernel::s_settings.value("gui/cipherType").
	 toByteArray());

      gcry_randomize
	(static_cast<void *> (symmetricKey.data()),
	 static_cast<size_t> (symmetricKey.length()),
	 GCRY_STRONG_RANDOM);
      savePublicKey
	(name, publicKey, symmetricKey, symmetricKeyAlgorithm, m_id);
    }
  else
    spoton_misc::logError
      (QString("spoton_kernel::process0011(): 0011 "
	       "content-length mismatch (advertised: %1, received: %2).").
       arg(length).arg(data.length()));
}

void spoton_neighbor::process0012(int length)
{
  if(!spoton_kernel::s_crypt1)
    return;

  length -= strlen("type=0012&content=");

  /*
  ** We may have received a name and a public key.
  */

  QByteArray data(m_data.mid(0, m_data.lastIndexOf("\r\n") + 2));

  m_data.remove(0, data.length());
  data.remove
    (0,
     data.indexOf("type=0012&content=") +
     strlen("type=0012&content="));

  if(length == data.length())
    {
      data = QByteArray::fromBase64(data);

      QByteArray encrypted(data.mid(0, data.indexOf('\n')));

      data.remove(0, encrypted.length());
      data = data.trimmed();

      QByteArray name(data.mid(0, spoton_send::NAME_MAXIMUM_LENGTH).
		      trimmed());

      data.remove(0, name.length());
      data = data.trimmed();

      QByteArray publicKey(data);
      bool ok = true;

      data = spoton_kernel::s_crypt1->publicKeyDecrypt
	(QByteArray::fromBase64(encrypted), &ok);

      if(ok)
	{
	  QByteArray symmetricKey;
	  QByteArray symmetricKeyAlgorithm;

	  symmetricKey = data.mid
	    (0, spoton_send::SYMMETRIC_KEY_MAXIMUM_LENGTH);
	  data.remove(0, symmetricKey.length());
	  symmetricKeyAlgorithm = data.mid
	    (0, spoton_send::SYMMETRIC_KEY_ALGORITHM_MAXIMUM_LENGTH).
	    trimmed();
	  data.remove(0, symmetricKeyAlgorithm.length());
	  savePublicKey
	    (name, publicKey, symmetricKey, symmetricKeyAlgorithm, -1);
	}
      else
	spoton_misc::logError
	  ("spoton_neighbor::process0012(): "
	   "publicKeyDecrypt() error.");
    }
  else
    spoton_misc::logError
      (QString("spoton_kernel::process0012(): 0012 "
	       "content-length mismatch (advertised: %1, received: %2).").
       arg(length).arg(data.length()));
}

void spoton_neighbor::slotSendStatus(const QList<QByteArray> &data)
{
  if(state() == QAbstractSocket::ConnectedState)
    for(int i = 0; i < data.size(); i++)
      {
	QByteArray message(spoton_send::message0013(data.at(i)));

	if(write(message.constData(), message.length()) != message.length())
	  spoton_misc::logError
	    ("spoton_neighbor::slotSendStatus(): write() "
	     "error.");
	else
	  flush();
      }
}
