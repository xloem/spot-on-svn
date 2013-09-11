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
#include <QSslKey>
#include <QSslSocket>

#include "Common/spot-on-common.h"
#include "Common/spot-on-crypt.h"
#include "Common/spot-on-misc.h"
#include "spot-on-gui-server.h"
#include "spot-on-kernel.h"

#if QT_VERSION >= 0x050000
void spoton_gui_server_tcp_server::incomingConnection(qintptr socketDescriptor)
#else
void spoton_gui_server_tcp_server::incomingConnection(int socketDescriptor)
#endif
{
  QByteArray certificate;
  QByteArray privateKey;
  QByteArray publicKey;
  QString error("");

  spoton_crypt::generateSslKeys
    (spoton_kernel::s_settings.value("gui/kernelKeySize", 2048).toInt(),
     certificate,
     privateKey,
     publicKey,
     serverAddress(),
     60 * 60 * 24 * 7,
     error);

  if(error.isEmpty())
    {
      QSslSocket *socket = new QSslSocket(this);

      socket->setSocketDescriptor(socketDescriptor);
      connect(socket,
	      SIGNAL(encrypted(void)),
	      this,
	      SLOT(slotEncrypted(void)));
      connect(socket,
	      SIGNAL(modeChanged(QSslSocket::SslMode)),
	      this,
	      SIGNAL(modeChanged(QSslSocket::SslMode)));

      QSslConfiguration configuration;

      configuration.setLocalCertificate(QSslCertificate(certificate));
      configuration.setPrivateKey(QSslKey(privateKey, QSsl::Rsa));
#if QT_VERSION >= 0x040800
      configuration.setSslOption
	(QSsl::SslOptionDisableCompression, true);
      configuration.setSslOption
	(QSsl::SslOptionDisableEmptyFragments, true);
      configuration.setSslOption
	(QSsl::SslOptionDisableLegacyRenegotiation, true);
#endif
      socket->setSslConfiguration(configuration);
      socket->startServerEncryption();
      m_queue.enqueue(socket);
      emit newConnection();
    }
  else
    spoton_misc::logError
      (QString("spoton_gui_server_tcp_server::"
	       "spoton_gui_server_tcp_server(): "
	       "generateSslKeys() failure (%1).").arg(error.remove(".")));
}

spoton_gui_server::spoton_gui_server(QObject *parent):
  spoton_gui_server_tcp_server(parent)
{
  if(!listen(QHostAddress("127.0.0.1")))
    spoton_misc::logError("spoton_gui_server::spoton_gui_server(): "
			  "listen() failure. This is a serious problem!");

  connect(this,
	  SIGNAL(modeChanged(QSslSocket::SslMode)),
	  this,
	  SLOT(slotModeChanged(QSslSocket::SslMode)));
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
  m_guiSocketData.clear();

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "kernel.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("DELETE FROM kernel_gui_server");
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_gui_server::slotClientConnected(void)
{
  QSslSocket *socket = qobject_cast<QSslSocket *> (nextPendingConnection());

  if(socket)
    {
      connect(socket,
	      SIGNAL(disconnected(void)),
	      this,
	      SLOT(slotClientDisconnected(void)));
      connect(socket,
	      SIGNAL(modeChanged(QSslSocket::SslMode)),
	      this,
	      SLOT(slotModeChanged(QSslSocket::SslMode)));
      connect(socket,
	      SIGNAL(readyRead(void)),
	      this,
	      SLOT(slotReadyRead(void)));
    }
}

void spoton_gui_server::slotClientDisconnected(void)
{
  QSslSocket *socket = qobject_cast<QSslSocket *> (sender());

  if(socket)
    {
      m_guiSocketData.remove(socket->socketDescriptor());
      socket->deleteLater();
    }

  if(m_guiSocketData.isEmpty())
    spoton_kernel::clearBuzzKeysContainer();
}

void spoton_gui_server::slotReadyRead(void)
{
  QSslSocket *socket = qobject_cast<QSslSocket *> (sender());

  if(!socket)
    return;

  if(!socket->isEncrypted())
    {
      socket->readAll();
      spoton_misc::logError
	(QString("spoton_gui_server::slotReadyRead(): "
		 "socket %1:%2 is not encrypted. Discarding data.").
	 arg(socket->localAddress().toString()).
	 arg(socket->localPort()));
      return;
    }

  /*
  ** What if socketDescriptor() equals negative one?
  */

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

	  if(message.startsWith("addbuzz_"))
	    {
	      message.remove(0, strlen("addbuzz_"));

	      QList<QByteArray> list(message.split('_'));

	      if(list.size() == 2)
		spoton_kernel::addBuzzKey
		  (QByteArray::fromBase64(list.value(0)),
		   QByteArray::fromBase64(list.value(1)));
	    }
	  else if(message.startsWith("befriendparticipant_"))
	    {
	      message.remove(0, strlen("befriendparticipant_"));

	      QList<QByteArray> list(message.split('_'));

	      if(list.size() == 7)
		emit publicKeyReceivedFromUI
		  (list.value(0).toLongLong(),
		   QByteArray::fromBase64(list.value(1)),
		   QByteArray::fromBase64(list.value(2)),
		   QByteArray::fromBase64(list.value(3)),
		   QByteArray::fromBase64(list.value(4)),
		   QByteArray::fromBase64(list.value(5)),
		   QByteArray::fromBase64(list.value(6)),
		   "0012");
	    }
	  else if(message.startsWith("buzz_"))
	    {
	      message.remove(0, strlen("buzz_"));

	      QList<QByteArray> list(message.split('_'));

	      if(list.size() == 4)
		emit buzzReceivedFromUI
		  (QByteArray::fromBase64(list.value(0)),
		   QByteArray::fromBase64(list.value(1)),
		   QByteArray::fromBase64(list.value(2)),
		   QByteArray::fromBase64(list.value(3)),
		   QByteArray(),
		   QByteArray(),
		   "0040a");
	      else if(list.size() == 6)
		emit buzzReceivedFromUI
		  (QByteArray::fromBase64(list.value(0)),
		   QByteArray::fromBase64(list.value(1)),
		   QByteArray::fromBase64(list.value(2)),
		   QByteArray::fromBase64(list.value(3)),
		   QByteArray::fromBase64(list.value(4)),
		   QByteArray::fromBase64(list.value(5)),
		   "0040b");
	    }
	  else if(message.startsWith("call_participant_"))
	    {
	      message.remove(0, strlen("call_participant_"));

	      if(!message.isEmpty())
		emit callParticipant(message.toLongLong());
	    }
	  else if(message.startsWith("detach_listener_neighbors_"))
	    {
	      message.remove(0, strlen("detach_listener_neighbors_"));

	      if(!message.isEmpty())
		emit detachNeighbors(message.toLongLong());
	    }
	  else if(message.startsWith("disconnect_listener_neighbors_"))
	    {
	      message.remove(0, strlen("disconnect_listener_neighbors_"));

	      if(!message.isEmpty())
		emit disconnectNeighbors(message.toLongLong());
	    }
	  else if(message.startsWith("keys_"))
	    {
	      message.remove(0, strlen("keys_"));

	      QList<QByteArray> list(message.split('_'));

	      if(list.size() != 2)
		continue;

	      QStringList names;

	      names << "chat"
		    << "chat-signature"
		    << "email"
		    << "email-signature"
		    << "url"
		    << "url-signature";

	      for(int i = 0; i < names.size(); i++)
		if(!spoton_kernel::s_crypts.contains(names.at(i)))
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
		       names.at(i));
		    spoton_misc::populateCountryDatabase
		      (crypt);
		    spoton_kernel::s_crypts.insert(names.at(i), crypt);
		  }
	    }
	  else if(message.startsWith("message_"))
	    {
	      message.remove(0, strlen("message_"));

	      QList<QByteArray> list(message.split('_'));

	      if(list.size() == 3)
		emit messageReceivedFromUI
		  (list.value(0).toLongLong(),
		   QByteArray::fromBase64(list.value(1)),
		   QByteArray::fromBase64(list.value(2)));
	    }
	  else if(message.startsWith("publicizealllistenersplaintext"))
	    emit publicizeAllListenersPlaintext();
	  else if(message.startsWith("publicizelistenerplaintext"))
	    {
	      message.remove(0, strlen("publicizelistenerplaintext_"));

	      QList<QByteArray> list(message.split('_'));

	      if(list.size() == 1)
		emit publicizeListenerPlaintext
		  (list.value(0).toLongLong());
	    }
	  else if(message.startsWith("removebuzz_"))
	    {
	      message.remove(0, strlen("removebuzz_"));
	      spoton_kernel::removeBuzzKey(QByteArray::fromBase64(message));
	    }
	  else if(message.startsWith("retrievemail"))
	    emit retrieveMail();
	  else if(message.startsWith("sharepublickey_"))
	    {
	      message.remove(0, strlen("sharepublickey_"));

	      QList<QByteArray> list(message.split('_'));

	      if(list.size() == 7)
		emit publicKeyReceivedFromUI
		  (list.value(0).toLongLong(),
		   QByteArray::fromBase64(list.value(1)),
		   QByteArray::fromBase64(list.value(2)),
		   QByteArray::fromBase64(list.value(3)),
		   QByteArray::fromBase64(list.value(4)),
		   QByteArray::fromBase64(list.value(5)),
		   QByteArray::fromBase64(list.value(6)),
		   "0011");
	    }
	}
    }
}

void spoton_gui_server::slotTimeout(void)
{
  if(!isListening())
    if(!listen(QHostAddress("127.0.0.1")))
      spoton_misc::logError("spoton_gui_server::slotTimeout(): "
			    "listen() failure. This is a serious problem!");

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "kernel.db");

    if(db.open())
      {
	QSqlQuery query(db);
	quint16 port = 0;

	query.setForwardOnly(true);

	if(query.exec("SELECT port FROM kernel_gui_server"))
	  if(query.next())
	    port = query.value(0).toInt();

	if(port == 0 || port != serverPort())
	  {
	    QSqlQuery updateQuery(db);

	    updateQuery.prepare("INSERT INTO kernel_gui_server (port) "
				"VALUES (?)");
	    updateQuery.bindValue(0, serverPort());
	    updateQuery.exec();
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_gui_server::slotReceivedBuzzMessage
(const QList<QByteArray> &list, const QPair<QByteArray, QByteArray> &pair)
{
  QPair<QByteArray, QByteArray> p(pair);

  if(p.first.isEmpty() || p.second.isEmpty())
    p = spoton_kernel::findBuzzKey(list.value(0));

  QByteArray computedMessageCode;
  QByteArray data;
  QByteArray message;
  bool ok = true;
  spoton_crypt crypt(p.second,
		     QString("sha512"),
		     QByteArray(),
		     p.first,
		     0,
		     0,
		     QString(""));

  computedMessageCode = crypt.keyedHash(list.value(0), &ok);

  if(!ok)
    return;

  if(computedMessageCode != list.value(1))
    {
      spoton_misc::logError("spoton_gui_server::slotReceivedBuzzMessage(): "
			    "computed message code does not match "
			    "provided code.");
      return;
    }

  data = crypt.decrypted(list.value(0), &ok);

  if(!ok)
    return;

  message.append("buzz_");
  message.append(data.toBase64()); // Message
  message.append("_");
  message.append(pair.first.toBase64()); // Key
  message.append("_");

  QByteArray hash;
  spoton_crypt *s_crypt = spoton_kernel::s_crypts.value("chat", 0);

  if(s_crypt)
    hash = spoton_crypt::keyedHash
      (list.value(0),
       QByteArray(s_crypt->symmetricKey(),
		  s_crypt->symmetricKeyLength()), "sha512", &ok);
  else
    hash = spoton_crypt::sha512Hash(hash, &ok);

  if(!ok)
    return;

  message.append(hash.toBase64());
  message.append("\n");

  foreach(QSslSocket *socket, findChildren<QSslSocket *> ())
    if(socket->isEncrypted())
      {
	if(socket->write(message.constData(),
			 message.length()) != message.length())
	  spoton_misc::logError
	    (QString("spoton_gui_server::slotReceivedBuzzMessage(): "
		     "write() failure for %1:%2.").
	     arg(socket->peerAddress().toString()).
	     arg(socket->peerPort()));
	else
	  socket->flush();
      }
    else
      spoton_misc::logError
	(QString("spoton_gui_server::slotReceivedBuzzMessage(): "
		 "socket %1:%2 is not encrypted. Ignoring write() request.").
	 arg(socket->peerAddress().toString()).
	 arg(socket->peerPort()));
}

void spoton_gui_server::slotReceivedChatMessage(const QByteArray &message)
{
  foreach(QSslSocket *socket, findChildren<QSslSocket *> ())
    if(socket->isEncrypted())
      {
	if(socket->write(message.constData(),
			 message.length()) != message.length())
	  spoton_misc::logError
	    (QString("spoton_gui_server::slotReceivedChatMessage(): "
		     "write() failure for %1:%2.").
	     arg(socket->peerAddress().toString()).
	     arg(socket->peerPort()));
	else
	  socket->flush();
      }
    else
      spoton_misc::logError
	(QString("spoton_gui_server::slotReceivedChatMessage(): "
		 "socket %1:%2 is not encrypted. Ignoring write() request.").
	 arg(socket->peerAddress().toString()).
	 arg(socket->peerPort()));
}

void spoton_gui_server::slotNewEMailArrived(void)
{
  QByteArray message("newmail\n");

  foreach(QSslSocket *socket, findChildren<QSslSocket *> ())
    if(socket->isEncrypted())
      {
	if(socket->write(message.constData(),
			 message.length()) != message.length())
	  spoton_misc::logError
	    (QString("spoton_gui_server::slotNewEMailArrived(): "
		     "write() failure for %1:%2.").
	     arg(socket->peerAddress().toString()).
	     arg(socket->peerPort()));
	else
	  socket->flush();
      }
    else
      spoton_misc::logError
	(QString("spoton_gui_server::slotNewEMailArrived(): "
		 "socket %1:%2 is not encrypted. Ignoring write() request.").
	 arg(socket->peerAddress().toString()).
	 arg(socket->peerPort()));
}

void spoton_gui_server::slotModeChanged(QSslSocket::SslMode mode)
{
  QSslSocket *socket = qobject_cast<QSslSocket *> (sender());

  if(!socket)
    {
      spoton_misc::logError("spoton_gui_server::slotModeChanged(): "
			    "empty socket object.");
      return;
    }

  spoton_misc::logError(QString("spoton_gui_server::slotModeChanged(): "
				"the connection mode has changed to %1 "
				"for %2:%3.").
			arg(mode).
			arg(socket->peerAddress().toString()).
			arg(socket->peerPort()));

  if(mode == QSslSocket::UnencryptedMode)
    {
      spoton_misc::logError
	(QString("spoton_gui_server::slotModeChanged(): "
		 "plaintext mode. Disconnecting kernel socket %1:%2.").
	 arg(socket->peerAddress().toString()).
	 arg(socket->peerPort()));
      socket->abort();
    }
}

void spoton_gui_server::slotEncrypted(void)
{
  QSslSocket *socket = qobject_cast<QSslSocket *> (sender());

  if(!socket)
    return;

  QSslCipher cipher(socket->sessionCipher());

  spoton_misc::logError
    (QString("spoton_gui_server::slotEncrypted(): "
	     "using session cipher %1-%2-%3-%4-%5-%6-%7 for %8:%9.").
     arg(cipher.authenticationMethod()).
     arg(cipher.encryptionMethod()).
     arg(cipher.keyExchangeMethod()).
     arg(cipher.name()).
     arg(cipher.protocolString()).
     arg(cipher.supportedBits()).
     arg(cipher.usedBits()).
     arg(socket->peerAddress().toString()).
     arg(socket->peerPort()));
}
