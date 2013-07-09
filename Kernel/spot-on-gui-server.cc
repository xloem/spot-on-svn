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
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QTcpSocket>

#include "Common/spot-on-crypt.h"
#include "Common/spot-on-misc.h"
#include "spot-on-gui-server.h"
#include "spot-on-kernel.h"

spoton_gui_server::spoton_gui_server(QObject *parent):QTcpServer(parent)
{
  listen(QHostAddress("127.0.0.1"));
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

	query.exec("DELETE FROM kernel_gui_server");
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
	  QList<QByteArray> list(data.mid(0, data.lastIndexOf('\n')).
				 split('\n'));

	  data.remove(0, data.lastIndexOf('\n'));

	  if(data.isEmpty())
	    m_guiSocketData.remove(socket->socketDescriptor());
	  else
	    m_guiSocketData[socket->socketDescriptor()] = data;

	  while(!list.isEmpty())
	    {
	      QByteArray message(list.takeFirst());

	      if(message.startsWith("befriendparticipant_"))
		{
		  message.remove(0, strlen("befriendparticipant_"));

		  QList<QByteArray> list(message.split('_'));

		  if(list.size() == 7)
		    emit publicKeyReceivedFromUI
		      (list.at(0).toLongLong(),
		       QByteArray::fromBase64(list.at(1)),
		       QByteArray::fromBase64(list.at(2)),
		       QByteArray::fromBase64(list.at(3)),
		       QByteArray::fromBase64(list.at(4)),
		       QByteArray::fromBase64(list.at(5)),
		       QByteArray::fromBase64(list.at(6)),
		       "0012");
		}
	      else if(message.startsWith("keys_"))
		{
		  message.remove(0, strlen("keys_"));

		  QList<QByteArray> list(message.split('_'));

		  if(list.size() != 2)
		    continue;

		  if(!spoton_kernel::s_crypts.contains("messaging"))
		    {
		      spoton_crypt *crypt = new spoton_crypt
			(spoton_kernel::s_settings.value("gui/cipherType",
							 "aes256").
			 toString().trimmed(),
			 spoton_kernel::s_settings.value("gui/hashType",
							 "sha512").
			 toString().trimmed(),
			 QByteArray::fromBase64(list.at(0)),
			 QByteArray::fromBase64(list.at(1)),
			 spoton_kernel::s_settings.value("gui/saltLength",
							 256).toInt(),
			 spoton_kernel::s_settings.value("gui/iterationCount",
							 10000).toInt(),
			 "messaging");
		      spoton_misc::populateCountryDatabase
			(crypt);
		      spoton_kernel::s_crypts.insert("messaging", crypt);
		    }

		  if(!spoton_kernel::s_crypts.contains("signature"))
		    {
		      spoton_crypt *crypt = new spoton_crypt
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
							 10000).toInt(),
			 "signature");
		      spoton_kernel::s_crypts.insert("signature", crypt);
		    }

		  if(!spoton_kernel::s_crypts.contains("url"))
		    {
		      spoton_crypt *crypt = new spoton_crypt
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
							 10000).toInt(),
			 "url");
		      spoton_kernel::s_crypts.insert("url", crypt);
		    }
		}
	      else if(message.startsWith("message_"))
		{
		  message.remove(0, strlen("message_"));

		  QList<QByteArray> list(message.split('_'));

		  if(list.size() == 3)
		    emit messageReceivedFromUI
		      (list.at(0).toLongLong(),
		       QByteArray::fromBase64(list.at(1)),
		       QByteArray::fromBase64(list.at(2)));
		}
	      else if(message.startsWith("publicizealllistenersplaintext"))
		emit publicizeAllListenersPlaintext();
	      else if(message.startsWith("publicizelistenerplaintext"))
		{
		  message.remove(0, strlen("publicizelistenerplaintext_"));

		  QList<QByteArray> list(message.split('_'));

		  if(list.size() == 1)
		    emit publicizeListenerPlaintext
		      (list.at(0).toLongLong());
		}
	      else if(message.startsWith("retrievemail"))
		emit retrieveMail();
	      else if(message.startsWith("sharepublickey_"))
		{
		  message.remove(0, strlen("sharepublickey_"));

		  QList<QByteArray> list(message.split('_'));

		  if(list.size() == 7)
		    emit publicKeyReceivedFromUI
		      (list.at(0).toLongLong(),
		       QByteArray::fromBase64(list.at(1)),
		       QByteArray::fromBase64(list.at(2)),
		       QByteArray::fromBase64(list.at(3)),
		       QByteArray::fromBase64(list.at(4)),
		       QByteArray::fromBase64(list.at(5)),
		       QByteArray::fromBase64(list.at(6)),
		       "0011");
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
	query.exec();
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

void spoton_gui_server::slotNewEMailArrived(void)
{
  QByteArray message("newmail\n");

  foreach(QTcpSocket *socket, findChildren<QTcpSocket *> ())
    if(socket->write(message.constData(),
		     message.length()) != message.length())
      spoton_misc::logError("spoton_gui_server::slotNewEMailArrived() "
			    "write() failure.");
    else
      socket->flush();
}
