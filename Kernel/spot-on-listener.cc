/*
** Copyright (c) 2012 Alexis Megas
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
#include <QSqlQuery>
#include <QSqlDatabase>

#include "Common/spot-on-gcrypt.h"
#include "Common/spot-on-misc.h"
#include "spot-on-kernel.h"
#include "spot-on-listener.h"

quint64 spoton_listener::s_dbId = 0;

spoton_listener::spoton_listener(const QString &ipAddress,
				 const QString &port,
				 const QString &scopeId,
				 const int maximumClients,
				 const qint64 id,
				 QObject *parent):
  spoton_listener_tcp_server(parent)
{
  s_dbId += 1;
  m_address = QHostAddress(ipAddress);
  m_address.setScopeId(scopeId);
  m_connections = 0;
  m_id = id;
  m_port = quint16(port.toInt());
  connect(this,
	  SIGNAL(newConnection(void)),
	  this,
	  SLOT(slotNewConnection(void)));
  setMaxPendingConnections(maximumClients);
  QTcpServer::listen(m_address, m_port);
  connect(&m_timer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotTimeout(void)));
  m_timer.start(2500);
}

spoton_listener::~spoton_listener()
{
  m_timer.stop();

  {
    QSqlDatabase db = QSqlDatabase::addDatabase
      ("QSQLITE", "listener_" + QString::number(s_dbId));

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
		      "status = 'off' WHERE OID = ?");
	query.bindValue(0, m_id);

	if(query.exec())
	  db.commit();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("listener_" + QString::number(s_dbId));
}

void spoton_listener::slotTimeout(void)
{
  /*
  ** We'll change states here.
  */

  {
    QSqlDatabase db = QSqlDatabase::addDatabase
      ("QSQLITE", "listener_" + QString::number(s_dbId));

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
		QString status(query.value(0).toString().trimmed());

		if(status == "online")
		  {
		    if(!isListening())
		      {
			if(!listen(m_address, m_port))
			  spoton_misc::logError
			    (QString("spoton_listener::slotTimeout(): "
				     "%1.").arg(errorString()));
		      }

		    if(isListening())
		      if(query.value(1).toInt() != maxPendingConnections())
			setMaxPendingConnections(query.value(1).toInt());
		  }
		else if(status == "off")
		  {
		    close();
		    m_connections = 0;

		    foreach(spoton_neighbor *socket,
			    findChildren<spoton_neighbor *> ())
		      {
			socket->abort();
			socket->deleteLater();
		      }
		  }

		if(status == "off" || status == "online")
		  saveStatus(db);
	      }
	    else
	      {
		foreach(spoton_neighbor *socket,
			findChildren<spoton_neighbor *> ())
		  {
		    socket->abort();
		    socket->deleteLater();
		  }

		deleteLater();
	      }
	  }
	else
	  {
	    foreach(spoton_neighbor *socket,
		    findChildren<spoton_neighbor *> ())
	      {
		socket->abort();
		socket->deleteLater();
	      }

	    deleteLater();
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("listener_" + QString::number(s_dbId));
}

void spoton_listener::saveStatus(QSqlDatabase &db)
{
  QSqlQuery query(db);
  QString status("");

  query.exec("PRAGMA synchronous = OFF");
  query.prepare("UPDATE listeners SET connections = ?, status = ? "
		"WHERE OID = ? AND status <> ?");
  query.bindValue(0, QString::number(m_connections));

  if(isListening())
    status = "online";
  else
    status = "off";

  query.bindValue(1, status);
  query.bindValue(2, m_id);
  query.bindValue(3, status);

  if(query.exec())
    db.commit();
}

void spoton_listener::slotNewConnection(void)
{
  spoton_neighbor *neighbor = qobject_cast<spoton_neighbor *>
    (nextPendingConnection());

  if(!neighbor)
    return;

  bool created = false;
  qint64 id = -1;

  {
    QSqlDatabase db = QSqlDatabase::addDatabase
      ("QSQLITE", "listener_" + QString::number(s_dbId));

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "neighbors.db");

    if(db.open())
      {
	if(neighbor)
	  {
	    QSqlQuery query(db);

	    query.exec("PRAGMA synchronous = OFF");
	    query.exec("INSERT OR REPLACE INTO neighbors "
		       "(local_ip_address, "
		       "local_port, "
		       "protocol, "
		       "remote_ip_address, "
		       "remote_port, "
		       "scope_id, "
		       "status, "
		       "hash, "
		       "sticky) "
		       "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
	    query.bindValue(0, m_address.toString());
	    query.bindValue(1, m_port);

	    if(m_address.protocol() == QAbstractSocket::IPv4Protocol)
	      query.bindValue(2, "IPv4");
	    else
	      query.bindValue(2, "IPv6");

	    bool ok = true;

	    if(spoton_kernel::s_crypt1)
	      {
		query.bindValue
		  (3,
		   spoton_kernel::s_crypt1->encrypted(neighbor->peerAddress().
						      toString().toLatin1(),
						      &ok).toBase64());

		if(ok)
		  query.bindValue
		    (4,
		     spoton_kernel::s_crypt1->
		     encrypted(QString::number(neighbor->peerPort()).
			       toLatin1(), &ok).toBase64());

		if(ok)
		  query.bindValue
		    (5,
		     spoton_kernel::s_crypt1->encrypted(neighbor->peerAddress().
							scopeId().toLatin1(),
							&ok).toBase64());

		if(ok)
		  query.bindValue
		    (7,
		     spoton_kernel::s_crypt1->
		     keyedHash((neighbor->peerAddress().toString() +
				QString::number(neighbor->peerPort())).
			       toLatin1(), &ok).toBase64());
	      }
	    else
	      {
		query.bindValue(3, neighbor->peerAddress().toString());
		query.bindValue(4, neighbor->peerPort());
		query.bindValue(5, neighbor->peerAddress().scopeId());
		query.bindValue(7,
				neighbor->peerAddress().toString() +
				QString::number(neighbor->peerPort()));
	      }

	    query.bindValue(6, "connected");
	    query.bindValue(8, 0);

	    if(ok)
	      {
		created = query.exec();

		if(created)
		  db.commit();
	      }

	    if(spoton_kernel::s_crypt1)
	      {
		if(ok)
		  {
		    if(query.exec("SELECT OID, remote_ip_address, "
				  "remote_port FROM neighbors"))
		      while(query.next())
			{
			  QByteArray b1;
			  QByteArray b2;

			  b1 = spoton_kernel::s_crypt1->decrypted
			    (QByteArray::fromBase64(query.value(1).
						    toByteArray()),
			     &ok);

			  if(ok)
			    b2 = spoton_kernel::s_crypt1->decrypted
			      (QByteArray::fromBase64(query.value(2).
						      toByteArray()),
			       &ok);

			  if(b1 == neighbor->peerAddress().toString() &&
			     b2.toUShort() == neighbor->peerPort())
			    {
			      id = query.value(0).toLongLong();
			      break;
			    }
			}
		  }
	      }
	    else
	      {
		query.prepare("SELECT OID FROM neighbors WHERE "
			      "remote_ip_address = ? AND remote_port = ?");
		query.bindValue(0, neighbor->peerAddress().toString());
		query.bindValue(1, neighbor->peerPort());
		query.exec();
		query.next();
		id = query.value(0).toLongLong();
	      }
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("listener_" + QString::number(s_dbId));

  if(created && id > -1)
    {
      m_connections += 1;
      updateConnectionCount();
      connect(neighbor,
	      SIGNAL(disconnected(void)),
	      this,
	      SLOT(slotNeighborDisconnected(void)));
      neighbor->setId(id);
      emit newNeighbor(neighbor);
    }
  else
    neighbor->deleteLater();
}

void spoton_listener::updateConnectionCount(void)
{
  {
    QSqlDatabase db = QSqlDatabase::addDatabase
      ("QSQLITE", "listener_" + QString::number(s_dbId));

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "listeners.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("PRAGMA synchronous = OFF");
	query.prepare("UPDATE listeners SET connections = ? "
		      "WHERE OID = ?");
	query.bindValue(0, QString::number(m_connections));
	query.bindValue(1, m_id);

	if(query.exec())
	  db.commit();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("listener_" + QString::number(s_dbId));
}

void spoton_listener::slotNeighborDisconnected(void)
{
  spoton_neighbor *socket = qobject_cast<spoton_neighbor *> (sender());

  if(socket)
    {
      if(m_connections > 0)
	m_connections -= 1;

      socket->deleteLater();
    }

  updateConnectionCount();
}

qint64 spoton_listener::id(void) const
{
  return m_id;
}
