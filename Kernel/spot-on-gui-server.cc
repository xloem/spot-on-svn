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

#include <QDir>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QTcpSocket>

#include "Common/spot-on-gcrypt.h"
#include "Common/spot-on-misc.h"
#include "spot-on-gui-server.h"
#include "spot-on-kernel.h"

spoton_gui_server::spoton_gui_server(QObject *parent):QTcpServer(parent)
{
  listen();
  connect(this,
	  SIGNAL(newConnection(void)),
	  this,
	  SLOT(slotClientConnected(void)));
  connect(&m_generalTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotTimeout(void)));
  m_generalTimer.start(2500);
}

spoton_gui_server::~spoton_gui_server()
{  
  {
    QSqlDatabase db = QSqlDatabase::addDatabase
      ("QSQLITE", "spoton_gui_server");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "kernel.db");

    if(db.open())
      {
	QSqlQuery query(db);

	if(query.exec("DELETE FROM kernel_gui_server"))
	  db.commit();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton_gui_server");
}

void spoton_gui_server::slotClientConnected(void)
{
  QTcpSocket *socket = nextPendingConnection();

  if(socket)
    {
      connect(socket,
	      SIGNAL(disconnected(void)),
	      this,
	      SLOT(slotClientDisconnected(void)));
      connect(socket,
	      SIGNAL(readyRead(void)),
	      this,
	      SLOT(slotReadyRead(void)));
    }
}

void spoton_gui_server::slotClientDisconnected(void)
{
  QTcpSocket *socket = qobject_cast<QTcpSocket *> (sender());

  if(socket)
    {
      m_guiSocketData.remove(socket->socketDescriptor());
      socket->deleteLater();
    }
}

void spoton_gui_server::slotReadyRead(void)
{
  QTcpSocket *socket = qobject_cast<QTcpSocket *> (sender());

  if(socket)
    {
      m_guiSocketData[socket->socketDescriptor()].append
	(socket->readAll());

      if(m_guiSocketData[socket->socketDescriptor()].endsWith('\n'))
	{
	  QByteArray data(m_guiSocketData[socket->socketDescriptor()]);

	  m_guiSocketData.remove(socket->socketDescriptor());

	  QList<QByteArray> list(data.split('\n'));

	  while(!list.isEmpty())
	    {
	      QByteArray message(list.takeFirst());

	      if(message.startsWith("befriendparticipant_"))
		{
		  message.remove(0, strlen("befriendparticipant_"));

		  QList<QByteArray> list(message.split('_'));

		  emit publicKeyReceivedFromUI
		    (list.value(0).toLongLong(),
		     QByteArray::fromBase64(list.value(1)),
		     QByteArray::fromBase64(list.value(2)),
		     QByteArray::fromBase64(list.value(3)));
		}
	      else if(message.startsWith("keys_"))
		{
		  message.remove(0, strlen("keys_"));
		  message = message.trimmed();

		  QList<QByteArray> list(message.split('_'));

		  if(!spoton_kernel::s_crypt1)
		    {
		      spoton_kernel::s_crypt1 = new spoton_gcrypt
			(spoton_kernel::s_settings.value("gui/cipherType",
							 "aes256").
			 toString().trimmed(),
			 spoton_kernel::s_settings.value("gui/hashType",
							 "sha512").
			 toString().trimmed(),
			 QByteArray::fromBase64(list.value(0)),
			 QByteArray::fromBase64(list.value(1)),
			 spoton_kernel::s_settings.value("gui/saltLength",
							 256).toInt(),
			 spoton_kernel::s_settings.value("gui/iterationCount",
							 1000).toInt(),
			 "private");
		      spoton_misc::populateCountryDatabase
			(spoton_kernel::s_crypt1);
		    }

		  if(!spoton_kernel::s_crypt2)
		    spoton_kernel::s_crypt2 = new spoton_gcrypt
		      (spoton_kernel::s_settings.value("gui/cipherType",
						       "aes256").
		       toString().trimmed(),
		       spoton_kernel::s_settings.value("gui/hashType",
						       "sha512").
		       toString().trimmed(),
		       QByteArray::fromBase64(list.value(0)),
		       QByteArray::fromBase64(list.value(1)),
		       spoton_kernel::s_settings.value("gui/saltLength",
						       256).toInt(),
		       spoton_kernel::s_settings.value("gui/iterationCount",
						       1000).toInt(),
		       "shared");
		}
	      else if(message.startsWith("message_"))
		{
		  message.remove(0, strlen("message_"));

		  QList<QByteArray> list(message.split('_'));

		  emit messageReceivedFromUI
		    (list.value(0).toLongLong(),
		     QByteArray::fromBase64(list.value(1)),
		     QByteArray::fromBase64(list.value(2)));
		}
	      else if(message.startsWith("sharepublickey_"))
		{
		  message.remove(0, strlen("sharepublickey_"));

		  QList<QByteArray> list(message.split('_'));

		  emit publicKeyReceivedFromUI
		    (list.value(0).toLongLong(),
		     QByteArray::fromBase64(list.value(1)),
		     QByteArray::fromBase64(list.value(2)));
		}
	    }
	}
    }
}

void spoton_gui_server::slotTimeout(void)
{
  {
    QSqlDatabase db = QSqlDatabase::addDatabase
      ("QSQLITE", "spoton_gui_server");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "kernel.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("PRAGMA synchronous = OFF");
	query.prepare("INSERT INTO kernel_gui_server (port) "
		      "VALUES (?)");
	query.bindValue(0, serverPort());

	if(query.exec())
	  db.commit();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton_gui_server");
}

void spoton_gui_server::slotReceivedChatMessage(const QByteArray &message)
{
  foreach(QTcpSocket *socket, findChildren<QTcpSocket *> ())
    if(socket->write(message.constData(),
		     message.length()) != message.length())
      spoton_misc::logError("spoton_gui_server::slotReceivedChatMessage(): "
			    "write() failure.");
    else
      socket->flush();
}
