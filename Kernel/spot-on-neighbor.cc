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

#include <QAuthenticator>
#include <QDateTime>
#include <QDir>
#include <QNetworkInterface>
#include <QSqlError>
#include <QSqlQuery>
#include <QSslCipher>
#include <QSslConfiguration>
#include <QSslKey>
#include <QtCore/qmath.h>

#include <limits>

#include "Common/spot-on-common.h"
#include "Common/spot-on-external-address.h"
#include "Common/spot-on-crypt.h"
#include "Common/spot-on-misc.h"
#include "spot-on-kernel.h"
#include "spot-on-neighbor.h"

spoton_neighbor::spoton_neighbor(const int socketDescriptor,
				 const QByteArray &certificate,
				 const QByteArray &privateKey,
				 QObject *parent):QSslSocket(parent)
{
  m_isDedicatedLine = false;
  m_isUserDefined = false;
  m_maximumBufferSize = 131072; // 2 ^ 17
  m_maximumContentLength = 65536; // 2 ^ 16
  m_receivedUuid = "{00000000-0000-0000-0000-000000000000}";

  if(certificate.isEmpty() || privateKey.isEmpty())
    m_useSsl = false;
  else
    m_useSsl = true;

  setReadBufferSize(8192);
  setSocketDescriptor(socketDescriptor);
  setSocketOption(QAbstractSocket::KeepAliveOption, 1);

  if(m_useSsl)
    {
      QSslConfiguration configuration;

      configuration.setLocalCertificate(QSslCertificate(certificate));

      if(configuration.localCertificate().isValid())
	{
	  configuration.setPeerVerifyMode(QSslSocket::VerifyNone);
	  configuration.setPrivateKey(QSslKey(privateKey, QSsl::Rsa));

	  if(!configuration.privateKey().isNull())
	    {
#if QT_VERSION >= 0x050000
	      configuration.setProtocol(QSsl::TlsV1_2);
#else
	      configuration.setProtocol(QSsl::SecureProtocols);
#endif
	      configuration.setSslOption
		(QSsl::SslOptionDisableCompression, true);
	      configuration.setSslOption
		(QSsl::SslOptionDisableEmptyFragments, true);
	      configuration.setSslOption
		(QSsl::SslOptionDisableLegacyRenegotiation, true);
	      spoton_crypt::setSslCiphers(supportedCiphers(), configuration);
	      setSslConfiguration(configuration);
	    }
	  else
	    {
	      m_useSsl = false;
	       spoton_misc::logError
		 ("spoton_neighbor::spoton_neighbor(): "
		  "empty private key. SSL disabled.");
	    }
	}
      else
	{
	  m_useSsl = false;
	  spoton_misc::logError
	    ("spoton_neighbor::spoton_neighbor(): "
	     "invalid local certificate. SSL disabled.");
	}
    }

  m_address = peerAddress();
  m_ipAddress = m_address.toString();
  m_externalAddress = new spoton_external_address(this);
  m_id = -1; /*
	     ** This neighbor was created by a listener. We must
	     ** have a valid id at some point (setId()). If not,
	     ** we're deep in the hole.
	     */
  m_lastReadTime = QDateTime::currentDateTime();
  m_networkInterface = 0;
  m_port = peerPort();
  connect(this,
	  SIGNAL(disconnected(void)),
	  this,
	  SLOT(slotDisconnected(void)));
  connect(this,
	  SIGNAL(encrypted(void)),
	  this,
	  SLOT(slotEncrypted(void)));
  connect(this,
	  SIGNAL(error(QAbstractSocket::SocketError)),
	  this,
	  SLOT(slotError(QAbstractSocket::SocketError)));
  connect(this,
	  SIGNAL(modeChanged(QSslSocket::SslMode)),
	  this,
	  SLOT(slotModeChanged(QSslSocket::SslMode)));
  connect(this,
	  SIGNAL(readyRead(void)),
	  this,
	  SLOT(slotReadyRead(void)));
  connect(this,
	  SIGNAL(sslErrors(const QList<QSslError> &)),
	  this,
	  SLOT(slotSslErrors(const QList<QSslError> &)));
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

  if(m_useSsl)
    startServerEncryption();

  m_externalAddress->discover();
  m_externalAddressDiscovererTimer.start(30000);
  m_keepAliveTimer.start(45000);
  m_lifetime.start(10 * 60 * 1000);
  m_timer.start(2500);
  QTimer::singleShot(5000, this, SLOT(slotSendUuid(void)));
}

spoton_neighbor::spoton_neighbor(const QNetworkProxy &proxy,
				 const QString &ipAddress,
				 const QString &port,
				 const QString &scopeId,
				 const qint64 id,
				 const bool userDefined,
				 const QByteArray &privateKey,
				 const int maximumBufferSize,
				 const int maximumContentLength,
				 const bool isDedicatedLine,
				 QObject *parent):QSslSocket(parent)
{
  m_isDedicatedLine = isDedicatedLine;
  m_isUserDefined = userDefined;
  m_maximumBufferSize = maximumBufferSize;
  m_maximumContentLength = maximumContentLength;
  m_receivedUuid = "{00000000-0000-0000-0000-000000000000}";
  m_useSsl = true;
  setProxy(proxy);
  setReadBufferSize(8192);
  setSocketOption(QAbstractSocket::KeepAliveOption, 1);

  if(!privateKey.isEmpty())
    {
      QSslConfiguration configuration;

      configuration.setPeerVerifyMode(QSslSocket::VerifyNone);
      configuration.setPrivateKey(QSslKey(privateKey, QSsl::Rsa));

      if(!configuration.privateKey().isNull())
	{
#if QT_VERSION >= 0x050000
	  configuration.setProtocol(QSsl::TlsV1_2);
#else
	  configuration.setProtocol(QSsl::SecureProtocols);
#endif
	  configuration.setSslOption
	    (QSsl::SslOptionDisableCompression, true);
	  configuration.setSslOption
	    (QSsl::SslOptionDisableEmptyFragments, true);
	  configuration.setSslOption
	    (QSsl::SslOptionDisableLegacyRenegotiation, true);
	  spoton_crypt::setSslCiphers(supportedCiphers(), configuration);
	  setSslConfiguration(configuration);
	}
      else
	{
	  m_useSsl = false;
	  spoton_misc::logError
	    ("spoton_neighbor::spoton_neighbor(): "
	     "empty private key. SSL disabled.");
	}
    }

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
  connect(this,
	  SIGNAL(connected(void)),
	  this,
	  SLOT(slotConnected(void)));
  connect(this,
	  SIGNAL(disconnected(void)),
	  this,
	  SLOT(slotDisconnected(void)));
  connect(this,
	  SIGNAL(encrypted(void)),
	  this,
	  SLOT(slotEncrypted(void)));
  connect(this,
	  SIGNAL(error(QAbstractSocket::SocketError)),
	  this,
	  SLOT(slotError(QAbstractSocket::SocketError)));
  connect(this,
	  SIGNAL(modeChanged(QSslSocket::SslMode)),
	  this,
	  SLOT(slotModeChanged(QSslSocket::SslMode)));
  connect(this,
	  SIGNAL(proxyAuthenticationRequired(const QNetworkProxy &,
					     QAuthenticator *)),
	  this,
	  SLOT(slotProxyAuthenticationRequired(const QNetworkProxy &,
					       QAuthenticator *)));
  connect(this,
	  SIGNAL(readyRead(void)),
	  this,
	  SLOT(slotReadyRead(void)));
  connect(this,
	  SIGNAL(sslErrors(const QList<QSslError> &)),
	  this,
	  SLOT(slotSslErrors(const QList<QSslError> &)));
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
  m_keepAliveTimer.setInterval(45000);
  m_lifetime.start(10 * 60 * 1000);
  m_timer.start(2500);
}

spoton_neighbor::~spoton_neighbor()
{
  char a[32];

  snprintf(a, sizeof(a), "%p", this);
  spoton_misc::logError
    (QString("Neighbor (%1) %2:%3 deallocated.").
     arg(a).
     arg(m_address.toString()).
     arg(m_port));
  m_timer.stop();

  if(m_id != -1)
    {
      /*
      ** We must not delete accepted participants (neighbor_oid = -1).
      */

      QString connectionName("");

      {
	QSqlDatabase db = spoton_misc::database(connectionName);

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
	    spoton_misc::purgeSignatureRelationships(db);
	  }

	db.close();
      }

      QSqlDatabase::removeDatabase(connectionName);

      {
	QSqlDatabase db = spoton_misc::database(connectionName);

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
			  "is_encrypted = 0, "
			  "local_ip_address = NULL, "
			  "local_port = NULL, status = 'disconnected' "
			  "WHERE OID = ?");
	    query.bindValue(0, m_id);
	    query.exec();
	  }

	db.close();
      }

      QSqlDatabase::removeDatabase(connectionName);
    }

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
	deleteLater();
      }

  /*
  ** We'll change states here.
  */

  QString connectionName("");
  QString status("");
  bool shouldDelete = false;

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "neighbors.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);
	query.prepare("SELECT status_control, sticky, dedicated_line "
		      "FROM neighbors WHERE OID = ?");
	query.bindValue(0, m_id);

	if(query.exec())
	  {
	    if(query.next())
	      {
		status = query.value(0).toString();

		if(status == "blocked" || status == "disconnected")
		  {
		    saveStatus(db, status);
		    shouldDelete = true;
		  }
		else
		  {
		    spoton_crypt *s_crypt = 0;

		    if(spoton_kernel::s_crypts.contains("messaging"))
		      s_crypt = spoton_kernel::s_crypts["messaging"];

		    if(s_crypt)
		      {
			bool ok = true;

			m_isDedicatedLine = s_crypt->decrypted
			  (QByteArray::fromBase64(query.value(2).
						  toByteArray()),
			   &ok).toInt();
		      }
		  }

		if(query.value(1).toInt() == 1)
		  m_lifetime.stop();
		else if(!m_lifetime.isActive())
		  m_lifetime.start();
	      }
	    else if(m_id != -1)
	      shouldDelete = true;
	  }
	else if(m_id != -1)
	  shouldDelete = true;
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(shouldDelete)
    {
      spoton_misc::logError("spoton_neighbor::slotTimeout(): instructed "
			    "to delete neighbor.");
      deleteLater();
    }

  if(m_isUserDefined)
    if(status == "connected")
      {
	if(state() == QAbstractSocket::UnconnectedState)
	  {
	    if(m_useSsl)
	      connectToHostEncrypted(m_address.toString(), m_port);
	    else
	      connectToHost(m_address, m_port);
	  }
      }

  /*
  ** Retrieve the interface that this neighbor is using.
  ** If the interface disappears, destroy the neighbor.
  */

  prepareNetworkInterface();

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

	deleteLater();
      }

  saveEncryptedStatus();
}

void spoton_neighbor::saveEncryptedStatus(void)
{
  if(m_id == -1)
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "neighbors.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.prepare("UPDATE neighbors SET is_encrypted = ? "
		      "WHERE OID = ? AND is_encrypted <> ?");
	query.bindValue(0, isEncrypted() ? 1 : 0);
	query.bindValue(1, m_id);
	query.bindValue(2, isEncrypted() ? 1 : 0);
	query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_neighbor::saveStatus(const QSqlDatabase &db,
				 const QString &status)
{
  if(m_id == -1)
    return;

  QSqlQuery query(db);

  query.prepare("UPDATE neighbors SET is_encrypted = ?, status = ? "
		"WHERE OID = ? AND status <> 'deleted'");
  query.bindValue(0, isEncrypted() ? 1 : 0);
  query.bindValue(1, status);
  query.bindValue(2, m_id);
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
	{
	  spoton_misc::logError
	    ("spoton_neighbor::slotReadyRead(): "
	     "list is empty. Purging contents of m_data.");
	  m_data.clear();
	}

      while(!list.isEmpty())
	{
	  QByteArray data(list.takeFirst());
	  int length = 0;
	  spoton_send::spoton_send_method sendMethod =
	    spoton_send::ARTIFICIAL_GET;

	  if(data.startsWith("POST"))
	    sendMethod = spoton_send::NORMAL_POST;

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

	  if(length >= m_maximumContentLength)
	    spoton_misc::logError
	      (QString("spoton_neighbor::slotReadyRead(): "
		       "the Content-Length header from node %1:%2 "
		       "contains a lot of data (%3). Ignoring. ").
	       arg(peerAddress().isNull() ? peerName() :
		   peerAddress().toString()).
	       arg(peerPort()).
	       arg(length));
	  else if(length > 0 && data.contains("type=0000&content="))
	    process0000(length, data, sendMethod);
	  else if(length > 0 && data.contains("type=0001a&content="))
	    process0001a(length, data);
	  else if(length > 0 && data.contains("type=0001b&content="))
	    process0001b(length, data);
	  else if(length > 0 && data.contains("type=0002&content="))
	    process0002(length, data);
	  else if(length > 0 && data.contains("type=0011&content="))
	    process0011(length, data);
	  else if(length > 0 && data.contains("type=0012&content="))
	    process0012(length, data);
	  else if(length > 0 && data.contains("type=0013&content="))
	    process0013(length, data);
	  else if(length > 0 && data.contains("type=0014&content="))
	    process0014(length, data);
	  else if(length > 0 && data.contains("type=0015&content="))
	    process0015(length, data);
	  else if(length > 0 && data.contains("type=0030&content="))
	    process0030(length, data);
	  else if(length > 0 && data.contains("type=0040a&content="))
	    process0040a(length, data, sendMethod);
	  else if(length > 0 && data.contains("type=0040b&content="))
	    process0040b(length, data, sendMethod);
	  else
	    {
	      if(readBufferSize() != 1000)
		{
		  spoton_misc::logError
		    (QString("spoton_neighbor::slotReadyRead(): "
			     "received irregular data from %1:%2. Setting "
			     "the read buffer size to 1000 bytes.").
		     arg(peerAddress().isNull() ? peerName() :
			 peerAddress().toString()).arg(peerPort()));
		  setReadBufferSize(1000);
		}
	      else
		spoton_misc::logError
		  (QString("spoton_neighbor::slotReadyRead(): "
			   "received irregular data from %1:%2. The "
			   "read buffer size remains at 1000 bytes.").
		   arg(peerAddress().isNull() ? peerName() :
		       peerAddress().toString()).arg(peerPort()));
	    }
	}
    }
  else if(m_data.length() > m_maximumBufferSize)
    {
      spoton_misc::logError
	(QString("spoton_neighbor::slotReadyRead(): "
		 "the m_data container contains too much "
		 "data (%1) that hasn't been processed. Purging.").
	 arg(m_data.length()));
      m_data.clear();
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

  if(m_id != -1)
    {
      spoton_crypt *s_crypt = 0;

      if(spoton_kernel::s_crypts.contains("messaging"))
	s_crypt = spoton_kernel::s_crypts["messaging"];

      if(s_crypt)
	{
	  QString connectionName("");

	  {
	    QSqlDatabase db = spoton_misc::database(connectionName);

	    db.setDatabaseName
	      (spoton_misc::homePath() + QDir::separator() + "neighbors.db");

	    if(db.open())
	      {
		QSqlQuery query(db);
		QString country
		  (spoton_misc::
		   countryNameFromIPAddress(peerAddress().isNull() ?
					    peerName() :
					    peerAddress().toString()));
		bool ok = true;

		query.prepare("UPDATE neighbors SET country = ?, "
			      "is_encrypted = ?, "
			      "local_ip_address = ?, "
			      "local_port = ?, qt_country_hash = ?, "
			      "status = 'connected' "
			      "WHERE OID = ?");
		query.bindValue
		  (0, s_crypt->
		   encrypted(country.toLatin1(), &ok).toBase64());
		query.bindValue(1, isEncrypted() ? 1 : 0);
		query.bindValue(2, localAddress().toString());
		query.bindValue(3, localPort());
		query.bindValue
		  (4, s_crypt->keyedHash(country.remove(" ").
					 toLatin1(), &ok).
		   toBase64());
		query.bindValue(5, m_id);
		query.exec();
	      }

	    db.close();
	  }

	  QSqlDatabase::removeDatabase(connectionName);
	}
    }

  /*
  ** Initial discovery of the external IP address.
  */

  m_externalAddress->discover();
  m_externalAddressDiscovererTimer.start();
  m_lastReadTime = QDateTime::currentDateTime();

  if(!m_keepAliveTimer.isActive())
    m_keepAliveTimer.start();
}

void spoton_neighbor::savePublicKey(const QByteArray &keyType,
				    const QByteArray &name,
				    const QByteArray &publicKey,
				    const QByteArray &signature,
				    const QByteArray &sPublicKey,
				    const QByteArray &sSignature,
				    const qint64 neighborOid)
{
  /*
  ** Save a friendly key.
  */

  if(!spoton_crypt::isValidSignature(publicKey, publicKey, signature))
    return;

  if(!spoton_crypt::isValidSignature(sPublicKey, sPublicKey, sSignature))
    return;

  /*
  ** If neighborOid is -1, we have bonded two neighbors.
  */

  QString connectionName("");
  bool share = false;

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

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
	      {
		/*
		** An error occurred or we do not have the public key.
		*/

		spoton_misc::saveFriendshipBundle
		  (keyType, name, publicKey, sPublicKey,
		   neighborOid, db);
		spoton_misc::saveFriendshipBundle
		  ("signature", name, sPublicKey, QByteArray(),
		   neighborOid, db);
	      }
	  }
	else
	  {
	    spoton_misc::saveFriendshipBundle
	      (keyType, name, publicKey, sPublicKey, -1, db);
	    spoton_misc::saveFriendshipBundle
	      ("signature", name, sPublicKey, QByteArray(), -1, db);
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(share)
    {
      spoton_crypt *s_crypt1 = 0;
      spoton_crypt *s_crypt2 = 0;

      if(spoton_kernel::s_crypts.contains("messaging"))
	s_crypt1 = spoton_kernel::s_crypts["messaging"];

      if(spoton_kernel::s_crypts.contains("signature"))
	s_crypt2 = spoton_kernel::s_crypts["signature"];

      if(s_crypt1 && s_crypt2)
	{
	  QByteArray myName
	    (spoton_kernel::s_settings.value("gui/nodeName",
					     "unknown").
	     toByteArray().trimmed());
	  QByteArray myPublicKey;
	  QByteArray mySignature;
	  QByteArray mySPublicKey;
	  QByteArray mySSignature;
	  bool ok = true;

	  myPublicKey = s_crypt1->publicKey(&ok);

	  if(ok)
	    mySignature = s_crypt1->digitalSignature
	      (myPublicKey, &ok);

	  if(ok)
	    mySPublicKey = s_crypt2->publicKey(&ok);

	  if(ok)
	    mySSignature = s_crypt2->digitalSignature
	      (mySPublicKey, &ok);

	  if(ok)
	    sharePublicKey(keyType, myName,
			   myPublicKey, mySignature,
			   mySPublicKey, mySSignature);
	}
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

void spoton_neighbor::slotSendMessage(const QByteArray &data)
{
  if(readyToWrite())
    {
      if(write(data.constData(), data.length()) != data.length())
	spoton_misc::logError
	  ("spoton_neighbor::slotSendMessage(): write() error.");
      else
	flush();
    }
}

void spoton_neighbor::slotReceivedBuzzMessage
(const QByteArray &data,
 const QString &messageType,
 const qint64 id,
 const spoton_send::spoton_send_method sendMethod)
{
  /*
  ** A neighbor (id) received a buzz message. This neighbor now needs
  ** to send the message to its peer. Please note that data also contains
  ** the TTL. We do not echo messages on lines that are dedicated.
  */

  if(!m_isDedicatedLine)
    if(id != m_id)
      if(readyToWrite())
	{
	  QByteArray message;

	  if(messageType == "0040a")
	    message = spoton_send::message0040a(data, sendMethod);
	  else
	    message = spoton_send::message0040b(data, sendMethod);

	  if(write(message.constData(), message.length()) != message.length())
	    spoton_misc::logError
	      ("spoton_neighbor::slotReceivedBuzzMessage(): write() "
	       "error.");
	  else
	    flush();
	}
}

void spoton_neighbor::slotReceivedChatMessage
(const QByteArray &data,
 const qint64 id,
 const spoton_send::spoton_send_method sendMethod)
{
  /*
  ** A neighbor (id) received a message. This neighbor now needs
  ** to send the message to its peer. Please note that data also contains
  ** the TTL. We do not echo messages on lines that are dedicated.
  */

  if(!m_isDedicatedLine)
    if(id != m_id)
      if(readyToWrite())
	{
	  QByteArray message(spoton_send::message0000(data, sendMethod));

	  if(write(message.constData(), message.length()) != message.length())
	    spoton_misc::logError
	      ("spoton_neighbor::slotReceivedChatMessage(): write() "
	       "error.");
	  else
	    flush();
	}
}

void spoton_neighbor::slotReceivedMailMessage(const QByteArray &data,
					      const QString &messageType,
					      const qint64 id)
{
  /*
  ** A neighbor (id) received a letter. This neighbor now needs
  ** to send the letter to its peer. Please note that data also contains
  ** the TTL. We do not echo messages on lines that are dedicated.
  */

  if(!m_isDedicatedLine)
    if(id != m_id)
      if(readyToWrite())
	{
	  QByteArray message;

	  if(messageType == "0001a")
	    message = spoton_send::message0001a(data);
	  else
	    message = spoton_send::message0001b(data);

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
  ** the TTL. We do not echo messages on lines that are dedicated.
  */

  if(!m_isDedicatedLine)
    if(id != m_id)
      if(readyToWrite())
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
  ** also contains the TTL. We do not echo messages on lines that are
  ** dedicated.
  */

  if(!m_isDedicatedLine)
    if(id != m_id)
      if(readyToWrite())
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
  deleteLater();
}

void spoton_neighbor::sharePublicKey(const QByteArray &keyType,
				     const QByteArray &name,
				     const QByteArray &publicKey,
				     const QByteArray &signature,
				     const QByteArray &sPublicKey,
				     const QByteArray &sSignature)
{
  if(m_id == -1)
    return;
  else if(!readyToWrite())
    return;

  QByteArray message;

  message.append(keyType.toBase64());
  message.append("\n");
  message.append(name.toBase64());
  message.append("\n");
  message.append(publicKey.toBase64());
  message.append("\n");
  message.append(signature.toBase64());
  message.append("\n");
  message.append(sPublicKey.toBase64());
  message.append("\n");
  message.append(sSignature.toBase64());
  message = spoton_send::message0012(message);

  if(write(message.constData(), message.length()) != message.length())
    spoton_misc::logError
      ("spoton_neighbor::sharePublicKey(): "
       "write() failure.");
  else
    {
      flush();

      QString connectionName("");

      {
	QSqlDatabase db = spoton_misc::database(connectionName);

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

      QSqlDatabase::removeDatabase(connectionName);
    }
}

void spoton_neighbor::process0000
(int length, const QByteArray &dataIn,
 const spoton_send::spoton_send_method sendMethod)
{
  spoton_crypt *s_crypt = 0;

  if(spoton_kernel::s_crypts.contains("messaging"))
    s_crypt = spoton_kernel::s_crypts["messaging"];

  if(!s_crypt)
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
	    (spoton_misc::findGeminiInCosmos(list.value(0), s_crypt));

	  if(!gemini.isEmpty())
	    {
	      QByteArray computedMessageCode;
	      QByteArray message(list.value(0));
	      QByteArray messageCode(list.value(1));
	      spoton_crypt crypt("aes256",
				 QString("sha512"),
				 QByteArray(),
				 gemini,
				 0,
				 0,
				 QString(""));

	      computedMessageCode = crypt.keyedHash(message, &ok);

	      if(ok)
		{
		  if(computedMessageCode == messageCode)
		    {
		      message = crypt.decrypted(message, &ok);

		      if(ok)
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
					  "computed message code does "
					  "not match provided code.");
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
      QByteArray messageCode(list.value(5));
      QByteArray name(list.value(3));
      QByteArray publicKeyHash(list.value(2));
      QByteArray symmetricKey(list.value(0));
      QByteArray symmetricKeyAlgorithm(list.value(1));

      if(ok)
	symmetricKey = s_crypt->
	  publicKeyDecrypt(symmetricKey, &ok);

      if(ok)
	symmetricKeyAlgorithm = s_crypt->
	  publicKeyDecrypt(symmetricKeyAlgorithm, &ok);

      if(ok)
	{
	  spoton_crypt crypt(symmetricKeyAlgorithm,
			     QString("sha512"),
			     QByteArray(),
			     symmetricKey,
			     0,
			     0,
			     QString(""));

	  publicKeyHash = crypt.decrypted(publicKeyHash, &ok);
	}

      if(ok)
	{
	  if(spoton_misc::isAcceptedParticipant(publicKeyHash))
	    {
	      QByteArray computedMessageCode
		(spoton_crypt::
		 keyedHash(list.value(2) + // Sender's Sha-512 Hash
			   list.value(3) + // Name
			   list.value(4),  // Message
			   symmetricKey,
			   "sha512",
			   &ok));

	      /*
	      ** Let's not echo messages whose message codes
	      ** are incompatible.
	      */

	      if(ok)
		{
		  if(computedMessageCode == messageCode)
		    {
		      spoton_crypt crypt(symmetricKeyAlgorithm,
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
			{
			  QByteArray hash
			    (s_crypt->
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
		    }
		  else
		    spoton_misc::logError("spoton_neighbor::process0000(): "
					  "computed message code does "
					  "not match provided code.");
		}
	    }
	}

      if(ttl > 0)
	if(!ok ||
	   spoton_kernel::s_settings.value("gui/superEcho", false).toBool())
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
	    emit receivedChatMessage(originalData, m_id, sendMethod);
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
  spoton_crypt *s_crypt1 = 0;
  spoton_crypt *s_crypt2 = 0;

  if(spoton_kernel::s_crypts.contains("messaging"))
    s_crypt1 = spoton_kernel::s_crypts["messaging"];

  if(spoton_kernel::s_crypts.contains("signature"))
    s_crypt2 = spoton_kernel::s_crypts["signature"];

  if(!s_crypt1)
    return;
  else if(!s_crypt2)
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
      QByteArray messageCode(list.value(10));
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
	symmetricKey1 = s_crypt1->
	  publicKeyDecrypt(symmetricKey1, &ok);

      if(ok)
	symmetricKeyAlgorithm1 = s_crypt1->
	  publicKeyDecrypt(symmetricKeyAlgorithm1, &ok);

      QByteArray publicKey;
      QByteArray publicKeyHash;

      if(ok)
	{
	  spoton_crypt crypt(symmetricKeyAlgorithm1,
			     QString("sha512"),
			     QByteArray(),
			     symmetricKey1,
			     0,
			     0,
			     QString(""));

	  recipientHash = crypt.decrypted(recipientHash, &ok);

	  if(ok)
	    publicKey = s_crypt1->publicKey(&ok);

	  if(ok)
	    publicKeyHash = spoton_crypt::sha512Hash(publicKey, &ok);

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
			messageCode,
			"0001a");
	    return;
	  }

      if(ok)
	{
	  if(spoton_kernel::s_settings.value("gui/postoffice_enabled",
					     false).toBool())
	    if(spoton_misc::isAcceptedParticipant(recipientHash))
	      if(spoton_misc::isAcceptedParticipant(senderPublicKeyHash1))
		/*
		** Store the letter in the post office!
		*/

		storeLetter(list, recipientHash);
	}

      if(ttl > 0)
	if(!ok ||
	   spoton_kernel::s_settings.value("gui/superEcho", false).toBool())
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
	    emit receivedMailMessage(originalData, "0001a", m_id);
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
  spoton_crypt *s_crypt = 0;

  if(spoton_kernel::s_crypts.contains("messaging"))
    s_crypt = spoton_kernel::s_crypts["messaging"];

  if(!s_crypt)
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
      QByteArray messageCode(list.value(6));
      QByteArray name(list.value(3));
      QByteArray publicKeyHash(list.value(2));
      QByteArray subject(list.value(4));
      QByteArray symmetricKey(list.value(0));
      QByteArray symmetricKeyAlgorithm(list.value(1));

      if(ok)
	symmetricKey = s_crypt->
	  publicKeyDecrypt(symmetricKey, &ok);

      if(ok)
	symmetricKeyAlgorithm = s_crypt->
	  publicKeyDecrypt(symmetricKeyAlgorithm, &ok);

      if(ok)
	publicKeyHash = s_crypt->
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
		    messageCode,
		    "0001b");

      if(ttl > 0)
	if(!ok ||
	   spoton_kernel::s_settings.value("gui/superEcho", false).toBool())
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
	    emit receivedMailMessage(originalData, "0001b", m_id);
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
  spoton_crypt *s_crypt = 0;

  if(spoton_kernel::s_crypts.contains("messaging"))
    s_crypt = spoton_kernel::s_crypts["messaging"];

  if(!s_crypt)
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

      QByteArray messageCode(list.value(4));
      QByteArray publicKeyHash(list.value(2));
      QByteArray signature(list.value(3));
      QByteArray symmetricKey(list.value(0));
      QByteArray symmetricKeyAlgorithm(list.value(1));

      if(ok)
	symmetricKey = s_crypt->
	  publicKeyDecrypt(symmetricKey, &ok);

      if(ok)
	symmetricKeyAlgorithm = s_crypt->
	  publicKeyDecrypt(symmetricKeyAlgorithm, &ok);

      if(ok)
	publicKeyHash = s_crypt->
	  publicKeyDecrypt(publicKeyHash, &ok);

      if(ok)
	{
	  spoton_crypt crypt(symmetricKeyAlgorithm,
			     QString("sha512"),
			     QByteArray(),
			     symmetricKey,
			     0,
			     0,
			     QString(""));

	  signature = crypt.decrypted(signature, &ok);
	}

      if(ok)
	{
	  QByteArray computedMessageCode
	    (spoton_crypt::keyedHash(publicKeyHash +
				     list.value(3),
				     symmetricKey,
				     "sha512",
				     &ok));

	  /*
	  ** Let's not echo messages whose message codes are
	  ** incompatible.
	  */

	  if(ok)
	    {
	      if(computedMessageCode == messageCode)
		{
		  QByteArray messageCode
		    (spoton_crypt::keyedHash(symmetricKey +
					     symmetricKeyAlgorithm +
					     publicKeyHash,
					     symmetricKey,
					     "sha512",
					     &ok));

		  if(ok)
		    emit retrieveMail
		      (messageCode,
		       publicKeyHash, signature);
		}
	      else
		spoton_misc::logError("spoton_neighbor::process0002(): "
				      "computed message code does "
				      "not match provided code.");
	    }
	}

      if(ttl > 0)
	if(!ok ||
	   spoton_kernel::s_settings.value("gui/superEcho", false).toBool())
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

      if(list.size() != 6)
	{
	  spoton_misc::logError
	    (QString("spoton_neighbor::process0011(): "
		     "received irregular data. Expecting 6 entries, "
		     "received %1.").arg(list.size()));
	  return;
	}

      for(int i = 0; i < list.size(); i++)
	list.replace(i, QByteArray::fromBase64(list.at(i)));

      if(m_id != -1)
	savePublicKey
	  (list.value(0), list.value(1), list.value(2), list.value(3),
	   list.value(4), list.value(5), m_id);
      else
	spoton_misc::logError("spoton_neighbor::process0011(): "
			      "m_id equals negative one. "
			      "Calling savePublicKey() would be "
			      "problematic. Ignoring request.");
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

      if(list.size() != 6)
	{
	  spoton_misc::logError
	    (QString("spoton_neighbor::process0012(): "
		     "received irregular data. Expecting 6 entries, "
		     "received %1.").arg(list.size()));
	  return;
	}

      for(int i = 0; i < list.size(); i++)
	list.replace(i, QByteArray::fromBase64(list.at(i)));

      savePublicKey
	(list.value(0), list.value(1), list.value(2), list.value(3),
	 list.value(4), list.value(5), -1);
    }
  else
    spoton_misc::logError
      (QString("spoton_neighbor::process0012(): 0012 "
	       "content-length mismatch (advertised: %1, received: %2).").
       arg(length).arg(data.length()));
}

void spoton_neighbor::process0013(int length, const QByteArray &dataIn)
{
  spoton_crypt *s_crypt = 0;

  if(spoton_kernel::s_crypts.contains("messaging"))
    s_crypt = spoton_kernel::s_crypts["messaging"];

  if(!s_crypt)
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
	    (spoton_misc::findGeminiInCosmos(list.value(0), s_crypt));

	  if(!gemini.isEmpty())
	    {
	      QByteArray computedMessageCode;
	      QByteArray message(list.value(0));
	      QByteArray messageCode(list.value(1));
	      spoton_crypt crypt("aes256",
				 QString("sha512"),
				 QByteArray(),
				 gemini,
				 0,
				 0,
				 QString(""));

	      computedMessageCode = crypt.keyedHash(message, &ok);

	      if(ok)
		{
		  if(computedMessageCode == messageCode)
		    {
		      message = crypt.decrypted(message, &ok);

		      if(ok)
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
					  "computed message code does "
					  "not match provided code.");
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

      QByteArray messageCode(list.value(5));
      QByteArray name(list.value(3));
      QByteArray publicKeyHash(list.value(2));
      QByteArray status(list.value(4));
      QByteArray symmetricKey(list.value(0));
      QByteArray symmetricKeyAlgorithm(list.value(1));

      if(ok)
	symmetricKey = s_crypt->
	  publicKeyDecrypt(symmetricKey, &ok);

      if(ok)
	symmetricKeyAlgorithm = s_crypt->
	  publicKeyDecrypt(symmetricKeyAlgorithm, &ok);

      if(ok)
	{
	  spoton_crypt crypt(symmetricKeyAlgorithm,
			     QString("sha512"),
			     QByteArray(),
			     symmetricKey,
			     0,
			     0,
			     QString(""));

	  publicKeyHash = crypt.decrypted(publicKeyHash, &ok);
	}

      if(ok)
	{
	  QByteArray computedMessageCode
	    (spoton_crypt::keyedHash(list.value(2) +
				     list.value(3) +
				     list.value(4),
				     symmetricKey,
				     "sha512",
				     &ok));

	  /*
	  ** Let's not echo messages whose message codes are
	  ** incompatible.
	  */

	  if(ok)
	    {
	      if(computedMessageCode == messageCode)
		{
		  if(spoton_misc::isAcceptedParticipant(publicKeyHash))
		    {
		      spoton_crypt crypt(symmetricKeyAlgorithm,
					 QString("sha512"),
					 QByteArray(),
					 symmetricKey,
					 0,
					 0,
					 QString(""));

		      name = crypt.decrypted(name, &ok);

		      if(ok)
			status = crypt.decrypted(status, &ok);

		      if(ok)
			saveParticipantStatus(name, publicKeyHash, status);
		    }
		}
	      else
		spoton_misc::logError("spoton_neighbor::process0013(): "
				      "computed message code does "
				      "not match provided code.");
	    }
	}

      if(ttl > 0)
	if(!ok ||
	   spoton_kernel::s_settings.value("gui/superEcho", false).toBool())
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
  if(m_id == -1)
    return;

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

	  if(m_receivedUuid.isNull())
	    m_receivedUuid = "{00000000-0000-0000-0000-000000000000}";

	  spoton_crypt *s_crypt = 0;

	  if(spoton_kernel::s_crypts.contains("messaging"))
	    s_crypt = spoton_kernel::s_crypts["messaging"];

	  if(s_crypt)
	    {
	      QString connectionName("");

	      {
		QSqlDatabase db = spoton_misc::database(connectionName);

		db.setDatabaseName
		  (spoton_misc::homePath() + QDir::separator() +
		   "neighbors.db");

		if(db.open())
		  {
		    QSqlQuery query(db);
		    bool ok = true;

		    query.prepare("UPDATE neighbors SET uuid = ? "
				  "WHERE OID = ?");
		    query.bindValue
		      (0, s_crypt->encrypted(uuid.toString().toLatin1(),
					     &ok).toBase64());
		    query.bindValue(1, m_id);

		    if(ok)
		      query.exec();
		  }

		db.close();
	      }

	      QSqlDatabase::removeDatabase(connectionName);
	    }
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
	     arg(peerAddress().isNull() ? peerName() :
		 peerAddress().toString()).arg(peerPort()));
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
  spoton_crypt *s_crypt = 0;

  if(spoton_kernel::s_crypts.contains("messaging"))
    s_crypt = spoton_kernel::s_crypts["messaging"];

  if(!s_crypt)
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
      else
	{
	  QString statusControl
	    (spoton_kernel::s_settings.
	     value("gui/acceptPublicizedListeners", "ignored").toString().
	     toLower().trimmed());

	  if(statusControl == "connected" || statusControl == "disconnected")
	    {
	      QHostAddress address;

	      address.setAddress(list.value(0).constData());
	      address.setScopeId(list.value(2).constData());

	      if(!spoton_misc::isPrivateNetwork(address))
		{
		  quint16 port = list.value(1).toUShort();

		  spoton_misc::savePublishedNeighbor
		    (address, port, statusControl,s_crypt);
		}
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

void spoton_neighbor::process0040a
(int length, const QByteArray &dataIn,
 const spoton_send::spoton_send_method sendMethod)
{
  spoton_crypt *s_crypt = 0;

  if(spoton_kernel::s_crypts.contains("messaging"))
    s_crypt = spoton_kernel::s_crypts["messaging"];

  if(!s_crypt)
    return;

  length -= strlen("type=0040a&content=");

  /*
  ** We may have received a buzz.
  */

  QByteArray data(dataIn.mid(0, dataIn.lastIndexOf("\r\n") + 2));

  data.remove
    (0,
     data.indexOf("type=0040a&content=") + strlen("type=0040a&content="));

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

      if(list.size() != 2)
	{
	  spoton_misc::logError
	    (QString("spoton_neighbor::process0040a(): "
		     "received irregular data. Expecting 2 "
		     "entries, "
		     "received %1.").arg(list.size()));
	  return;
	}
      else
	emit receivedBuzzMessage(list, "0040a");

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
	  emit receivedBuzzMessage(originalData, "0040a", m_id, sendMethod);
	}
    }
  else
    spoton_misc::logError
      (QString("spoton_neighbor::process0030(): 0040a "
	       "content-length mismatch (advertised: %1, received: %2).").
       arg(length).arg(data.length()));
}

void spoton_neighbor::process0040b
(int length, const QByteArray &dataIn,
 const spoton_send::spoton_send_method sendMethod)
{
  spoton_crypt *s_crypt = 0;

  if(spoton_kernel::s_crypts.contains("messaging"))
    s_crypt = spoton_kernel::s_crypts["messaging"];

  if(!s_crypt)
    return;

  length -= strlen("type=0040b&content=");

  /*
  ** We may have received a buzz.
  */

  QByteArray data(dataIn.mid(0, dataIn.lastIndexOf("\r\n") + 2));

  data.remove
    (0,
     data.indexOf("type=0040b&content=") + strlen("type=0040b&content="));

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
	    (QString("spoton_neighbor::process0040b(): "
		     "received irregular data. Expecting 3 "
		     "entries, "
		     "received %1.").arg(list.size()));
	  return;
	}
      else
	emit receivedBuzzMessage(list, "0040b");

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
	  emit receivedBuzzMessage(originalData, "0040b", m_id, sendMethod);
	}
    }
  else
    spoton_misc::logError
      (QString("spoton_neighbor::process0030(): 0040b "
	       "content-length mismatch (advertised: %1, received: %2).").
       arg(length).arg(data.length()));
}

void spoton_neighbor::slotSendStatus(const QList<QByteArray> &list)
{
  if(readyToWrite())
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
  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

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
	    query.bindValue
	      (0,
	       name.mid(0, spoton_common::NAME_MAXIMUM_LENGTH).trimmed());
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
	    query.bindValue
	      (0,
	       name.mid(0, spoton_common::NAME_MAXIMUM_LENGTH).trimmed());
	    query.bindValue(1, status);
	    query.bindValue
	      (2, QDateTime::currentDateTime().toString(Qt::ISODate));
	    query.bindValue(3, publicKeyHash.toBase64());
	  }

	query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_neighbor::slotError(QAbstractSocket::SocketError error)
{
  if(error == QAbstractSocket::SslHandshakeFailedError)
    {
      /*
      ** Do not use SSL.
      */

      if(state() == QAbstractSocket::ConnectedState)
	QTimer::singleShot(5000, this, SLOT(slotSendUuid(void)));

      m_useSsl = false;
      spoton_misc::logError
	(QString("spoton_neighbor::slotError(): socket error (%1). "
		 "Disabling SSL.").arg(errorString()));
      return;
    }

  spoton_misc::logError
    (QString("spoton_neighbor::slotError(): socket error (%1). "
	     "Aborting socket.").arg(errorString()));
  deleteLater();
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
  if(!readyToWrite())
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
					  const QSqlDatabase &db)
{
  if(!db.isOpen())
    return;
  else if(m_id == -1)
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
      else
	{
	  spoton_crypt *s_crypt = 0;

	  if(spoton_kernel::s_crypts.contains("messaging"))
	    s_crypt = spoton_kernel::s_crypts["messaging"];

	  if(s_crypt)
	    {
	      query.prepare("UPDATE neighbors SET external_ip_address = ? "
			    "WHERE OID = ?");
	      query.bindValue
		(0, s_crypt->encrypted(address.toString().
				       toLatin1(), &ok).
		 toBase64());
	      query.bindValue(1, m_id);
	    }
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
  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "neighbors.db");

    if(db.open())
      saveExternalAddress(address, db);

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_neighbor::slotDiscoverExternalAddress(void)
{
  if(state() == QAbstractSocket::ConnectedState)
    m_externalAddress->discover();
}

void spoton_neighbor::slotSendKeepAlive(void)
{
  if(readyToWrite())
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

  if(readyToWrite())
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
    {
      spoton_crypt *s_crypt = 0;

      if(spoton_kernel::s_crypts.contains("messaging"))
	s_crypt = spoton_kernel::s_crypts["messaging"];

      spoton_misc::moveSentMailToSentFolder(oids, s_crypt);
    }
}

void spoton_neighbor::slotSendMailFromPostOffice(const QByteArray &data)
{
  if(readyToWrite())
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
				  QByteArray &messageCode,
				  const QString &messageType)
{
  spoton_crypt *s_crypt = 0;

  if(spoton_kernel::s_crypts.contains("messaging"))
    s_crypt = spoton_kernel::s_crypts["messaging"];

  if(!s_crypt)
    return;

  bool ok = true;

  /*
  ** We need to remember that the information here may have been
  ** encoded with a goldbug. The interface will prompt the user
  ** for the symmetric key.
  */

  if(messageType == "0001a")
    {
      symmetricKey = s_crypt->publicKeyDecrypt
	(symmetricKey, &ok);

      if(!ok)
	return;

      symmetricKeyAlgorithm = s_crypt->publicKeyDecrypt
	(symmetricKeyAlgorithm, &ok);

      if(!ok)
	return;

      senderPublicKeyHash = s_crypt->publicKeyDecrypt
	(senderPublicKeyHash, &ok);

      if(!ok)
	return;
    }

  if(!spoton_misc::isAcceptedParticipant(senderPublicKeyHash))
    return;

  QByteArray bytes;
  bool goldbugSet = false;
  spoton_crypt crypt(symmetricKeyAlgorithm,
		     QString("sha512"),
		     QByteArray(),
		     symmetricKey,
		     0,
		     0,
		     QString(""));

  bytes = crypt.decrypted(name, &ok);

  if(ok)
    {
      QList<QByteArray> list;

      /*
      ** Encrypted entries.
      */

      list.append(name);
      list.append(subject);
      list.append(message);

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

      QByteArray computedMessageCode;

      computedMessageCode = crypt.keyedHash(list.value(0) +
					    list.value(1) +
					    list.value(2), &ok);

      if(!ok)
	return;

      if(computedMessageCode != messageCode)
	{
	  spoton_misc::logError("spoton_neighbor::storeLetter(): "
				"computed message code does "
				"not match provided code.");
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

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "email.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.prepare("INSERT INTO folders "
		      "(date, folder_index, goldbug, hash, "
		      "message, message_code, "
		      "receiver_sender, receiver_sender_hash, "
		      "status, subject, participant_oid) "
		      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
	query.bindValue
	  (0, s_crypt->
	   encrypted(QDateTime::currentDateTime().
		     toString(Qt::ISODate).
		     toLatin1(), &ok).toBase64());
	query.bindValue(1, 0); // Inbox Folder

	if(ok)
	  query.bindValue
	    (2, s_crypt->
	     encrypted(QString::number(goldbugSet).toLatin1(), &ok).
	     toBase64());

	if(ok)
	  query.bindValue
	    (3, s_crypt->keyedHash(message + subject, &ok).
	     toBase64());

	if(!message.isEmpty())
	  if(ok)
	    query.bindValue
	      (4, s_crypt->encrypted(message, &ok).toBase64());

	if(!messageCode.isEmpty())
	  if(ok)
	    query.bindValue
	      (5, s_crypt->encrypted(messageCode, &ok).
	       toBase64());

	if(!name.isEmpty())
	  if(ok)
	    query.bindValue
	      (6, s_crypt->encrypted(name, &ok).toBase64());

	if(ok)
	  query.bindValue
	    (7, senderPublicKeyHash.toBase64());

	if(ok)
	  query.bindValue
	    (8, s_crypt->
	     encrypted(tr("Unread").toUtf8(), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (9, s_crypt->encrypted(subject, &ok).toBase64());

	if(ok)
	  query.bindValue
	    (10, s_crypt->
	     encrypted(QString::number(-1).toLatin1(), &ok).
	     toBase64());

	if(ok)
	  if(query.exec())
	    emit newEMailArrived();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_neighbor::storeLetter(const QList<QByteArray> &list,
				  const QByteArray &recipientHash)
{
  spoton_crypt *s_crypt = 0;

  if(spoton_kernel::s_crypts.contains("messaging"))
    s_crypt = spoton_kernel::s_crypts["messaging"];

  if(!s_crypt)
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

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
	  (0, s_crypt->
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
	      (1, s_crypt->encrypted(data, &ok).toBase64());

	    if(ok)
	      query.bindValue
		(2, s_crypt->keyedHash(data, &ok).
		 toBase64());
	  }

	query.bindValue(3, recipientHash.toBase64());

	if(ok)
	  query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_neighbor::slotRetrieveMail(const QList<QByteArray> &list)
{
  if(readyToWrite())
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
  if(!address.isNull())
    if(readyToWrite())
      {
	char c = 0;
	short ttl = spoton_kernel::s_settings.value
	  ("kernel/ttl_0030", 64).toInt();

	memcpy(&c, static_cast<void *> (&ttl), 1);

	QByteArray message
	  (spoton_send::message0030(address, port, c));

	if(write(message.constData(), message.length()) !=
	   message.length())
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
  ** note that data also contains the TTL. We do not echo messages
  ** on lines that are dedicated.
  */

  if(!m_isDedicatedLine)
    if(id != m_id)
      if(readyToWrite())
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
  spoton_crypt *s_crypt = 0;

  if(spoton_kernel::s_crypts.contains("messaging"))
    s_crypt = spoton_kernel::s_crypts["messaging"];

  if(!s_crypt)
    return;
  else if(!spoton_kernel::s_settings.value("gui/enableCongestionControl",
					   false).toBool())
    return;

  QByteArray hash;
  bool ok = true;

  hash = s_crypt->keyedHash(data, &ok);

  if(!ok)
    return;

  if(!spoton_kernel::s_messagingCache.contains(hash))
    spoton_kernel::s_messagingCache.insert(hash, 0);
}

bool spoton_neighbor::isDuplicateMessage(const QByteArray &data)
{
  if(!spoton_kernel::s_settings.value("gui/enableCongestionControl",
				      false).toBool())
    return false;

  spoton_crypt *s_crypt = 0;

  if(spoton_kernel::s_crypts.contains("messaging"))
    s_crypt = spoton_kernel::s_crypts["messaging"];

  if(!s_crypt)
    return false;

  QByteArray hash;
  bool ok = true;

  hash = s_crypt->keyedHash(data, &ok);

  if(!ok)
    return false;

  return spoton_kernel::s_messagingCache.contains(hash);
}

void spoton_neighbor::slotSslErrors(const QList<QSslError> &errors)
{
  for(int i = 0; i < errors.size(); i++)
    spoton_misc::logError(QString("spoton_neighbor::slotSslErrors(): "
				  "error (%1) occurred from %2:%3.").
			  arg(errors.at(i).errorString()).
			  arg(peerAddress().isNull() ? peerName() :
			      peerAddress().toString()).
			  arg(peerPort()));
}

void spoton_neighbor::slotModeChanged(QSslSocket::SslMode mode)
{
  spoton_misc::logError(QString("spoton_neighbor::slotModeChanged(): "
				"the connection mode has changed to %1.").
			arg(mode));

  if(m_useSsl)
    if(mode == QSslSocket::UnencryptedMode)
      {
	spoton_misc::logError("spoton_neighbor::slotModeChanged(): "
			      "unencrypted connection mode. Aborting.");
	deleteLater();
      }
}

void spoton_neighbor::slotDisconnected(void)
{
  int attempts = property("connection-attempts").toInt();

  if(attempts < 5)
    {
      attempts += 1;
      setProperty("connection-attempts", attempts);
      spoton_misc::logError
	(QString("spoton_neighbor::slotDisconnected(): "
		 "retrying %1 of %2.").arg(attempts).arg(5));
      return;
    }

  spoton_misc::logError("spoton_neighbor::slotDisconnected(): "
			"aborting socket!");
  deleteLater();
}

void spoton_neighbor::slotEncrypted(void)
{
  QTimer::singleShot(5000, this, SLOT(slotSendUuid(void)));

  QSslCipher cipher(sessionCipher());

  spoton_misc::logError
    (QString("spoton_neighbor::slotEncrypted(): "
	     "using session cipher %1-%2-%3-%4-%5-%6.").
     arg(cipher.authenticationMethod()).
     arg(cipher.encryptionMethod()).
     arg(cipher.keyExchangeMethod()).
     arg(cipher.protocolString()).
     arg(cipher.supportedBits()).
     arg(cipher.usedBits()));
}

void spoton_neighbor::slotProxyAuthenticationRequired
(const QNetworkProxy &proxy,
 QAuthenticator *authenticator)
{
  Q_UNUSED(proxy);

  if(authenticator)
    {
      authenticator->setPassword(this->proxy().password());
      authenticator->setUser(this->proxy().user());
    }
}

bool spoton_neighbor::readyToWrite(void)
{
  if(state() != QAbstractSocket::ConnectedState)
    return false;
  else if(isEncrypted() && m_useSsl)
    return true;
  else if(!isEncrypted() && !m_useSsl)
    return true;
  else
    return false;
}

void spoton_neighbor::slotSendBuzz(const QByteArray &data)
{
  if(readyToWrite())
    {
      if(write(data.constData(), data.length()) != data.length())
	spoton_misc::logError
	  ("spoton_neighbor::slotSendBuzz(): write() error.");
      else
	flush();
    }
}
