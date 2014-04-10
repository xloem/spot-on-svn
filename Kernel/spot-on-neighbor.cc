/*
** Copyright (c) 2011 - 10^10^10 Alexis Megas
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

extern "C"
{
#ifdef Q_OS_UNIX
#include <unistd.h>
#elif defined(Q_OS_WIN32)
#include <io.h>
#endif
}

spoton_neighbor::spoton_neighbor(const int socketDescriptor,
				 const QByteArray &certificate,
				 const QByteArray &privateKey,
				 const QString &echoMode,
				 const bool useAccounts,
				 const qint64 listenerOid,
				 const qint64 maximumBufferSize,
				 const qint64 maximumContentLength,
				 const QString &transport,
				 const QString &ipAddress,
				 const QString &port,
				 const QString &localIpAddress,
				 const QString &localPort,
				 const QString &orientation,
				 QObject *parent):QThread(parent)
{
  m_sctpSocket = 0;
  m_tcpSocket = 0;
  m_udpSocket = 0;
  m_maximumBufferSize =
    qBound(spoton_common::MAXIMUM_NEIGHBOR_CONTENT_LENGTH,
	   maximumBufferSize,
	   spoton_common::MAXIMUM_NEIGHBOR_BUFFER_SIZE);

  if(transport == "sctp")
    m_sctpSocket = new spoton_sctp_socket(this);
  else if(transport == "tcp")
    m_tcpSocket = new spoton_neighbor_tcp_socket(this);
  else if(transport == "udp")
    m_udpSocket = new spoton_neighbor_udp_socket(this);

  if(m_sctpSocket)
    {
      m_sctpSocket->setReadBufferSize(m_maximumBufferSize);
      m_sctpSocket->setSocketDescriptor(socketDescriptor);
      m_sctpSocket->setSocketOption
	(spoton_sctp_socket::KeepAliveOption, 0); /*
						  ** We have our
						  ** own mechanism.
						  */
      m_sctpSocket->setSocketOption
	(spoton_sctp_socket::LowDelayOption,
	 spoton_kernel::setting("kernel/sctp_nodelay", 1).
	 toInt()); /*
		   ** Disable Nagle?
		   */
    }
  else if(m_tcpSocket)
    {
      m_tcpSocket->setReadBufferSize(m_maximumBufferSize);
      m_tcpSocket->setSocketDescriptor(socketDescriptor);
      m_tcpSocket->setSocketOption
	(QAbstractSocket::KeepAliveOption, 0); /*
					       ** We have our
					       ** own mechanism.
					       */
      m_tcpSocket->setSocketOption
	(QAbstractSocket::LowDelayOption,
	 spoton_kernel::setting("kernel/tcp_nodelay", 1).
	 toInt()); /*
		   ** Disable Nagle?
		   */
    }
  else if(m_udpSocket)
    {
#ifdef Q_OS_UNIX
      m_udpSocket->setSocketDescriptor(dup(socketDescriptor));
#elif defined(Q_OS_WIN32)
      m_udpSocket->setSocketDescriptor(_dup(socketDescriptor));
#endif
      m_udpSocket->setLocalAddress(QHostAddress(localIpAddress));
      m_udpSocket->setLocalPort(localPort.toUShort());
      m_udpSocket->setPeerAddress(QHostAddress(ipAddress));
      m_udpSocket->setPeerPort(port.toUShort());
    }

  if(m_sctpSocket)
    m_address = m_sctpSocket->peerAddress();
  else if(m_tcpSocket)
    m_address = m_tcpSocket->peerAddress();
  else if(m_udpSocket)
    m_address = ipAddress;

  m_accountAuthenticated = false;
  m_allowExceptions = false;
  m_bytesRead = 0;
  m_bytesWritten = 0;
  m_echoMode = echoMode;

  try
    {
      m_externalAddress = new spoton_external_address(this);
    }
  catch(std::bad_alloc &exception)
    {
      if(m_sctpSocket)
	m_sctpSocket->deleteLater();

      if(m_tcpSocket)
	m_tcpSocket->deleteLater();

      if(m_udpSocket)
	m_udpSocket->deleteLater();

      throw;
    }

  m_id = -1; /*
	     ** This neighbor was created by a listener. We must
	     ** obtain a valid id at some point (setId())!
	     */
  m_ipAddress = m_address.toString();
  m_isUserDefined = false;
  m_lastReadTime = QDateTime::currentDateTime();
  m_listenerOid = listenerOid;
  m_maximumContentLength =
    qBound(spoton_common::MINIMUM_NEIGHBOR_CONTENT_LENGTH,
	   maximumContentLength,
	   spoton_common::MAXIMUM_NEIGHBOR_CONTENT_LENGTH);
  m_orientation = orientation;

  if(m_sctpSocket)
    m_port = m_sctpSocket->peerPort();
  else if(m_tcpSocket)
    m_port = m_tcpSocket->peerPort();
  else if(m_udpSocket)
    m_port = port.toUShort();

  m_receivedUuid = "{00000000-0000-0000-0000-000000000000}";

  if(m_transport == "tcp")
    m_requireSsl = true;
  else
    m_requireSsl = false;

  m_startTime = QDateTime::currentDateTime();
  m_transport = transport;
  m_useAccounts = useAccounts;

  if(certificate.isEmpty() || privateKey.isEmpty())
    m_useSsl = false;
  else
    m_useSsl = true;

  if(m_useSsl)
    {
      if(m_tcpSocket)
	{
	  QSslConfiguration configuration;

	  configuration.setLocalCertificate(QSslCertificate(certificate));

	  if(
#if QT_VERSION < 0x050000
	     configuration.localCertificate().isValid()
#else
	     !configuration.localCertificate().isNull()
#endif
	     )
	    {
	      configuration.setPrivateKey(QSslKey(privateKey, QSsl::Rsa));

	      if(!configuration.privateKey().isNull())
		{
#if QT_VERSION >= 0x040800
		  configuration.setSslOption
		    (QSsl::SslOptionDisableCompression, true);
		  configuration.setSslOption
		    (QSsl::SslOptionDisableEmptyFragments, true);
		  configuration.setSslOption
		    (QSsl::SslOptionDisableLegacyRenegotiation, true);
#endif
		  spoton_crypt::setSslCiphers
		    (m_tcpSocket->supportedCiphers(), configuration);
		  m_tcpSocket->setSslConfiguration(configuration);
		}
	      else
		{
		  m_useSsl = false;
		  spoton_misc::logError
		    (QString("spoton_neighbor::spoton_neighbor(): "
			     "empty private key for %1:%2. SSL disabled.").
		     arg(m_address.toString()).
		     arg(m_port));
		}
	    }
	  else
	    {
	      m_useSsl = false;
	      spoton_misc::logError
		(QString("spoton_neighbor::spoton_neighbor(): "
			 "invalid local certificate for %1:%2. "
			 "SSL disabled.").
		 arg(m_address.toString()).
		 arg(m_port));
	    }
	}
    }

  connect(this,
	  SIGNAL(accountAuthenticated(const QByteArray &,
				      const QByteArray &)),
	  this,
	  SLOT(slotAccountAuthenticated(const QByteArray &,
					const QByteArray &)));
  connect(this,
	  SIGNAL(resetKeepAlive(void)),
	  this,
	  SLOT(slotResetKeepAlive(void)));
  connect(this,
	  SIGNAL(sharePublicKey(const QByteArray &,
				const QByteArray &,
				const QByteArray &,
				const QByteArray &,
				const QByteArray &,
				const QByteArray &)),
	  this,
	  SLOT(slotSharePublicKey(const QByteArray &,
				  const QByteArray &,
				  const QByteArray &,
				  const QByteArray &,
				  const QByteArray &,
				  const QByteArray &)));

  if(m_sctpSocket)
    {
      connect(m_sctpSocket,
	      SIGNAL(disconnected(void)),
	      this,
	      SIGNAL(disconnected(void)));
      connect(m_sctpSocket,
	      SIGNAL(disconnected(void)),
	      this,
	      SLOT(slotDisconnected(void)));
      connect(m_sctpSocket,
	      SIGNAL(error(const QString &,
			   const spoton_sctp_socket::SocketError)),
	      this,
	      SLOT(slotError(const QString &,
			     const spoton_sctp_socket::SocketError)));
      connect(m_sctpSocket,
	      SIGNAL(readyRead(void)),
	      this,
	      SLOT(slotReadyRead(void)));
    }
  else if(m_tcpSocket)
    {
      connect(m_tcpSocket,
	      SIGNAL(disconnected(void)),
	      this,
	      SIGNAL(disconnected(void)));
      connect(m_tcpSocket,
	      SIGNAL(disconnected(void)),
	      this,
	      SLOT(slotDisconnected(void)));
      connect(m_tcpSocket,
	      SIGNAL(encrypted(void)),
	      this,
	      SLOT(slotEncrypted(void)));
      connect(m_tcpSocket,
	      SIGNAL(error(QAbstractSocket::SocketError)),
	      this,
	      SLOT(slotError(QAbstractSocket::SocketError)));
      connect(m_tcpSocket,
	      SIGNAL(modeChanged(QSslSocket::SslMode)),
	      this,
	      SLOT(slotModeChanged(QSslSocket::SslMode)));
      connect(m_tcpSocket,
	      SIGNAL(readyRead(void)),
	      this,
	      SLOT(slotReadyRead(void)));
      connect(m_tcpSocket,
	      SIGNAL(sslErrors(const QList<QSslError> &)),
	      this,
	      SLOT(slotSslErrors(const QList<QSslError> &)));
    }
  else if(m_udpSocket)
    {
      /*
      ** UDP sockets are connection-less. However, most of the communications
      ** logic requires connected sockets.
      */

      m_udpSocket->setSocketState(QAbstractSocket::ConnectedState);
      connect(m_udpSocket,
	      SIGNAL(disconnected(void)),
	      this,
	      SIGNAL(disconnected(void)));
      connect(m_udpSocket,
	      SIGNAL(disconnected(void)),
	      this,
	      SLOT(slotDisconnected(void)));
      connect(m_udpSocket,
	      SIGNAL(error(QAbstractSocket::SocketError)),
	      this,
	      SLOT(slotError(QAbstractSocket::SocketError)));
      connect(m_udpSocket,
	      SIGNAL(readyRead(void)),
	      this,
	      SLOT(slotReadyRead(void)));
    }

  connect(m_externalAddress,
	  SIGNAL(ipAddressDiscovered(const QHostAddress &)),
	  this,
	  SLOT(slotExternalAddressDiscovered(const QHostAddress &)));
  connect(&m_accountTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotSendAuthenticationRequest(void)));
  connect(&m_externalAddressDiscovererTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotDiscoverExternalAddress(void)));
  connect(&m_authenticationTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotAuthenticationTimerTimeout(void)));
  connect(&m_keepAliveTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotSendUuid(void)));
  connect(&m_lifetime,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotLifetimeExpired(void)));
  connect(&m_timer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotTimeout(void)));

  if(m_useSsl)
    {
      if(m_tcpSocket)
	m_tcpSocket->startServerEncryption();
    }

  m_accountTimer.setInterval(2500);
  m_authenticationTimer.setInterval
    (spoton_kernel::
     setting("kernel/server_account_verification_window_msecs",
	     15000).toInt());

  if(spoton_kernel::setting("gui/kernelExternalIpInterval", -1).
     toInt() == 30)
    {
      m_externalAddress->discover();
      m_externalAddressDiscovererTimer.start(30000);
    }
  else if(spoton_kernel::setting("gui/kernelExternalIpInterval", -1).
	  toInt() == 60)
    {
      m_externalAddress->discover();
      m_externalAddressDiscovererTimer.start(60000);
    }
  else
    m_externalAddressDiscovererTimer.setInterval(30000);

  if(m_useAccounts)
    if(!m_useSsl)
      {
	m_accountTimer.start();
	m_authenticationTimer.start();
      }

  m_keepAliveTimer.start(30000);
  m_lifetime.start(10 * 60 * 1000);
  m_timer.start(2500);
  start();
}

spoton_neighbor::spoton_neighbor(const QNetworkProxy &proxy,
				 const QString &ipAddress,
				 const QString &port,
				 const QString &scopeId,
				 const qint64 id,
				 const bool userDefined,
				 const int keySize,
				 const qint64 maximumBufferSize,
				 const qint64 maximumContentLength,
				 const QString &echoMode,
				 const QByteArray &peerCertificate,
				 const bool allowExceptions,
				 const QString &protocol,
				 const bool requireSsl,
				 const QByteArray &accountName,
				 const QByteArray &accountPassword,
				 const QString &transport,
				 const QString &orientation,
				 QObject *parent):QThread(parent)
{
  m_accountAuthenticated = false;
  m_accountName = accountName;
  m_accountPassword = accountPassword;
  m_allowExceptions = allowExceptions;
  m_address = QHostAddress(ipAddress);
  m_bytesRead = 0;
  m_bytesWritten = 0;
  m_echoMode = echoMode;
  m_externalAddress = new spoton_external_address(this);
  m_id = id;
  m_ipAddress = ipAddress;
  m_isUserDefined = userDefined;
  m_keySize = qAbs(keySize);

  if(!(m_keySize == 2048 || m_keySize == 3072 ||
       m_keySize == 4096 || m_keySize == 8192))
    m_keySize = 2048;

  m_lastReadTime = QDateTime::currentDateTime();
  m_listenerOid = -1;
  m_maximumBufferSize =
    qBound(spoton_common::MAXIMUM_NEIGHBOR_CONTENT_LENGTH,
	   maximumBufferSize,
	   spoton_common::MAXIMUM_NEIGHBOR_BUFFER_SIZE);
  m_maximumContentLength =
    qBound(spoton_common::MINIMUM_NEIGHBOR_CONTENT_LENGTH,
	   maximumContentLength,
	   spoton_common::MAXIMUM_NEIGHBOR_CONTENT_LENGTH);
  m_orientation = orientation;
  m_peerCertificate = QSslCertificate(peerCertificate);
  m_port = port.toUShort();
  m_protocol = protocol;
  m_receivedUuid = "{00000000-0000-0000-0000-000000000000}";
  m_requireSsl = requireSsl;
  m_sctpSocket = 0;
  m_startTime = QDateTime::currentDateTime();
  m_tcpSocket = 0;
  m_transport = transport;
  m_udpSocket = 0;

  spoton_crypt *s_crypt = spoton_kernel::s_crypts.value("chat", 0);

  if(s_crypt)
    {
      QByteArray name(m_accountName);
      QByteArray password(m_accountPassword);
      bool ok = true;

      name = s_crypt->decryptedAfterAuthenticated(name, &ok);

      if(ok)
	password = s_crypt->decryptedAfterAuthenticated(password, &ok);

      m_useAccounts = !name.isEmpty() || !password.isEmpty();
    }

  if(m_transport == "tcp")
    m_useSsl = true;
  else
    m_useSsl = false;

  try
    {
      if(m_transport == "sctp")
	m_sctpSocket = new spoton_sctp_socket(this);
      else if(m_transport == "tcp")
	m_tcpSocket = new spoton_neighbor_tcp_socket(this);
      else if(m_transport == "udp")
	m_udpSocket = new spoton_neighbor_udp_socket(this);
    }
  catch(std::bad_alloc &exception)
    {
      m_externalAddress->deleteLater();
      throw;
    }

  if(m_sctpSocket)
    m_sctpSocket->setReadBufferSize(m_maximumBufferSize);
  else if(m_tcpSocket)
    {
      m_tcpSocket->setProxy(proxy);
      m_tcpSocket->setReadBufferSize(m_maximumBufferSize);
    }
  else if(m_udpSocket)
    m_udpSocket->setProxy(proxy);

  QByteArray certificate;
  QByteArray privateKey;
  QByteArray publicKey;
  QString error("");

  spoton_crypt::generateSslKeys
    (m_keySize,
     certificate,
     privateKey,
     publicKey,
     QHostAddress(),
     0, // Days are not used.
     error);

  if(!error.isEmpty())
    spoton_misc::logError
      (QString("spoton_neighbor:: "
	       "spoton_neighbor(): "
	       "generateSslKeys() failure (%1) for %2:%3.").
       arg(error.remove(".")).
       arg(ipAddress).
       arg(port));

  if(!privateKey.isEmpty())
    {
      if(m_tcpSocket)
	{
	  QSslConfiguration configuration;

	  configuration.setPrivateKey(QSslKey(privateKey, QSsl::Rsa));

	  if(!configuration.privateKey().isNull())
	    {
#if QT_VERSION >= 0x040800
	      configuration.setSslOption
		(QSsl::SslOptionDisableCompression, true);
	      configuration.setSslOption
		(QSsl::SslOptionDisableEmptyFragments, true);
	      configuration.setSslOption
		(QSsl::SslOptionDisableLegacyRenegotiation, true);
#endif
	      configuration.setPeerVerifyMode(QSslSocket::QueryPeer);
	      spoton_crypt::setSslCiphers
		(m_tcpSocket->supportedCiphers(), configuration);
	      m_tcpSocket->setSslConfiguration(configuration);
	    }
	  else
	    {
	      m_useSsl = m_requireSsl;
	      spoton_misc::logError
		(QString("spoton_neighbor::spoton_neighbor(): "
			 "empty private key for %1:%2.").
		 arg(ipAddress).
		 arg(port));
	    }
	}
    }

  if(m_address.isNull())
    if(!m_ipAddress.isEmpty())
      QHostInfo::lookupHost(m_ipAddress,
			    this, SLOT(slotHostFound(const QHostInfo &)));

  m_address.setScopeId(scopeId);
  connect(this,
	  SIGNAL(resetKeepAlive(void)),
	  this,
	  SLOT(slotResetKeepAlive(void)));
  connect(this,
	  SIGNAL(sharePublicKey(const QByteArray &,
				const QByteArray &,
				const QByteArray &,
				const QByteArray &,
				const QByteArray &,
				const QByteArray &)),
	  this,
	  SLOT(slotSharePublicKey(const QByteArray &,
				  const QByteArray &,
				  const QByteArray &,
				  const QByteArray &,
				  const QByteArray &,
				  const QByteArray &)));

  if(m_sctpSocket)
    {
      connect(m_sctpSocket,
	      SIGNAL(connected(void)),
	      this,
	      SLOT(slotConnected(void)));
      connect(m_sctpSocket,
	      SIGNAL(disconnected(void)),
	      this,
	      SIGNAL(disconnected(void)));
      connect(m_sctpSocket,
	      SIGNAL(disconnected(void)),
	      this,
	      SLOT(slotDisconnected(void)));
      connect(m_sctpSocket,
	      SIGNAL(error(const QString &,
			   const spoton_sctp_socket::SocketError)),
	      this,
	      SLOT(slotError(const QString &,
			     const spoton_sctp_socket::SocketError)));
      connect(m_sctpSocket,
	      SIGNAL(readyRead(void)),
	      this,
	      SLOT(slotReadyRead(void)));
    }
  else if(m_tcpSocket)
    {
      connect(m_tcpSocket,
	      SIGNAL(connected(void)),
	      this,
	      SLOT(slotConnected(void)));
      connect(m_tcpSocket,
	      SIGNAL(disconnected(void)),
	      this,
	      SIGNAL(disconnected(void)));
      connect(m_tcpSocket,
	      SIGNAL(disconnected(void)),
	      this,
	      SLOT(slotDisconnected(void)));
      connect(m_tcpSocket,
	      SIGNAL(encrypted(void)),
	      this,
	      SLOT(slotEncrypted(void)));
      connect(m_tcpSocket,
	      SIGNAL(error(QAbstractSocket::SocketError)),
	      this,
	      SLOT(slotError(QAbstractSocket::SocketError)));
      connect(m_tcpSocket,
	      SIGNAL(modeChanged(QSslSocket::SslMode)),
	      this,
	      SLOT(slotModeChanged(QSslSocket::SslMode)));
      connect(m_tcpSocket,
	      SIGNAL(peerVerifyError(const QSslError &)),
	      this,
	      SLOT(slotPeerVerifyError(const QSslError &)));
      connect(m_tcpSocket,
	      SIGNAL(proxyAuthenticationRequired(const QNetworkProxy &,
						 QAuthenticator *)),
	      this,
	      SLOT(slotProxyAuthenticationRequired(const QNetworkProxy &,
						   QAuthenticator *)));
      connect(m_tcpSocket,
	      SIGNAL(readyRead(void)),
	      this,
	      SLOT(slotReadyRead(void)));
      connect(m_tcpSocket,
	      SIGNAL(sslErrors(const QList<QSslError> &)),
	      this,
	      SLOT(slotSslErrors(const QList<QSslError> &)));
    }
  else if(m_udpSocket)
    {
      connect(m_udpSocket,
	      SIGNAL(connected(void)),
	      this,
	      SLOT(slotConnected(void)));
      connect(m_udpSocket,
	      SIGNAL(disconnected(void)),
	      this,
	      SIGNAL(disconnected(void)));
      connect(m_udpSocket,
	      SIGNAL(disconnected(void)),
	      this,
	      SLOT(slotDisconnected(void)));
      connect(m_udpSocket,
	      SIGNAL(error(QAbstractSocket::SocketError)),
	      this,
	      SLOT(slotError(QAbstractSocket::SocketError)));
      connect(m_udpSocket,
	      SIGNAL(proxyAuthenticationRequired(const QNetworkProxy &,
						 QAuthenticator *)),
	      this,
	      SLOT(slotProxyAuthenticationRequired(const QNetworkProxy &,
						   QAuthenticator *)));
      connect(m_udpSocket,
	      SIGNAL(readyRead(void)),
	      this,
	      SLOT(slotReadyRead(void)));
    }

  connect(m_externalAddress,
	  SIGNAL(ipAddressDiscovered(const QHostAddress &)),
	  this,
	  SLOT(slotExternalAddressDiscovered(const QHostAddress &)));
  connect(&m_accountTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotSendAccountInformation(void)));
  connect(&m_authenticationTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotAuthenticationTimerTimeout(void)));
  connect(&m_externalAddressDiscovererTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotDiscoverExternalAddress(void)));
  connect(&m_keepAliveTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotSendUuid(void)));
  connect(&m_lifetime,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotLifetimeExpired(void)));
  connect(&m_timer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotTimeout(void)));
  m_accountTimer.setInterval(2500);
  m_authenticationTimer.setInterval
    (spoton_kernel::
     setting("kernel/server_account_verification_window_msecs",
	     15000).toInt());

  if(spoton_kernel::setting("gui/kernelExternalIpInterval", -1).
     toInt() == 30)
    m_externalAddressDiscovererTimer.setInterval(30000);
  else if(spoton_kernel::setting("gui/kernelExternalIpInterval", -1).
	  toInt() == 60)
    m_externalAddressDiscovererTimer.setInterval(60000);
  else
    m_externalAddressDiscovererTimer.setInterval(30000);

  m_keepAliveTimer.setInterval(30000);
  m_lifetime.start(10 * 60 * 1000);
  m_timer.start(2500);
  start();
}

spoton_neighbor::~spoton_neighbor()
{
  spoton_misc::logError(QString("Neighbor %1:%2 deallocated.").
			arg(m_address.toString()).
			arg(m_port));
  m_accountTimer.stop();
  m_authenticationTimer.stop();
  m_externalAddressDiscovererTimer.stop();
  m_keepAliveTimer.stop();
  m_lifetime.stop();
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
	    ** Remove asymmetric keys that were not completely shared.
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

	    if(spoton_kernel::setting("gui/keepOnlyUserDefinedNeighbors",
				      true).toBool())
	      {
		query.prepare("DELETE FROM neighbors WHERE "
			      "OID = ? AND status_control <> 'blocked' AND "
			      "user_defined = 0");
		query.bindValue(0, m_id);
		query.exec();
	      }

	    query.prepare("UPDATE neighbors SET "
			  "account_authenticated = NULL, "
			  "bytes_read = 0, "
			  "bytes_written = 0, "
			  "external_ip_address = NULL, "
			  "is_encrypted = 0, "
			  "local_ip_address = NULL, "
			  "local_port = NULL, "
			  "ssl_session_cipher = NULL, "
			  "status = 'disconnected', "
			  "uptime = 0 "
			  "WHERE OID = ?");
	    query.bindValue(0, m_id);
	    query.exec();
	  }

	db.close();
      }

      QSqlDatabase::removeDatabase(connectionName);
    }

  quit();
  wait(30000);
}

void spoton_neighbor::slotTimeout(void)
{
  if(m_sctpSocket)
    {
      if(m_sctpSocket->state() == spoton_sctp_socket::ConnectedState)
	if(m_lastReadTime.secsTo(QDateTime::currentDateTime()) >= 90)
	  {
	    spoton_misc::logError
	      (QString("spoton_neighbor::slotTimeout(): "
		       "aborting because of silent connection for %1:%2.").
	       arg(m_address.toString()).
	       arg(m_port));
	    deleteLater();
	    return;
	  }
    }
  else if(m_tcpSocket)
    {
      if(m_tcpSocket->state() == QAbstractSocket::ConnectedState)
	if(m_lastReadTime.secsTo(QDateTime::currentDateTime()) >= 90)
	  {
	    spoton_misc::logError
	      (QString("spoton_neighbor::slotTimeout(): "
		       "aborting because of silent connection for %1:%2.").
	       arg(m_address.toString()).
	       arg(m_port));
	    deleteLater();
	    return;
	  }
    }
  else if(m_udpSocket)
    {
      if(m_lastReadTime.secsTo(QDateTime::currentDateTime()) >= 90)
	{
	  spoton_misc::logError
	    (QString("spoton_neighbor::slotTimeout(): "
		     "aborting because of silent connection for %1:%2.").
	     arg(m_address.toString()).
	     arg(m_port));
	  deleteLater();
	  return;
	}
    }

  /*
  ** We'll change socket states here.
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
	saveStatistics(db);

	QSqlQuery query(db);

	query.setForwardOnly(true);
	query.prepare("SELECT status_control, sticky, echo_mode, "
		      "maximum_buffer_size, maximum_content_length, "
		      "account_name, account_password "
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
		    spoton_crypt *s_crypt =
		      spoton_kernel::s_crypts.value("chat", 0);

		    if(s_crypt)
		      {
			bool ok = true;

			m_echoMode = s_crypt->decryptedAfterAuthenticated
			  (QByteArray::fromBase64(query.value(2).
						  toByteArray()),
			   &ok).constData();

			if(m_isUserDefined && !m_accountAuthenticated)
			  {
			    QByteArray name
			      (QByteArray::fromBase64(query.value(5).
						      toByteArray()));
			    QByteArray password
			      (QByteArray::fromBase64(query.value(6).
						      toByteArray()));

			    if(!spoton_crypt::
			       memcmp(name, m_accountName) ||
			       !spoton_crypt::
			       memcmp(password, m_accountPassword))
			      {
				m_accountName = name;
				m_accountPassword = password;

				/*
				** What if m_accountName or m_accountPassword
				** is empty?
				*/

				m_accountTimer.start();
			      }
			  }
		      }

		    m_maximumBufferSize =
		      qBound(spoton_common::MAXIMUM_NEIGHBOR_CONTENT_LENGTH,
			     query.value(3).toLongLong(),
			     spoton_common::MAXIMUM_NEIGHBOR_BUFFER_SIZE);
		    m_maximumContentLength =
		      qBound(spoton_common::MINIMUM_NEIGHBOR_CONTENT_LENGTH,
			     query.value(4).toLongLong(),
			     spoton_common::MAXIMUM_NEIGHBOR_CONTENT_LENGTH);
		  }

		if(query.value(1).toLongLong())
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
      spoton_misc::logError
	(QString("spoton_neighbor::slotTimeout(): instructed "
		 "to delete neighbor for %1:%2.").
	 arg(m_address.toString()).
	 arg(m_port));
      deleteLater();
      return;
    }

  if(m_isUserDefined)
    if(status == "connected")
      {
	if(m_sctpSocket)
	  {
	    if(m_sctpSocket->state() == spoton_sctp_socket::UnconnectedState)
	      {
		saveStatus("connecting");
		m_sctpSocket->connectToHost(m_address.toString(), m_port);
	      }
	  }
	else if(m_tcpSocket)
	  {
	    if(m_tcpSocket->state() == QAbstractSocket::UnconnectedState)
	      {
		saveStatus("connecting");

		if(m_useSsl)
		  m_tcpSocket->connectToHostEncrypted
		    (m_address.toString(), m_port);
		else
		  m_tcpSocket->connectToHost(m_address, m_port);

		int timeout = 2500;

		if(m_tcpSocket->proxy().type() != QNetworkProxy::NoProxy)
		  timeout = 5000;

		if(!m_tcpSocket->waitForConnected(timeout))
		  {
		    deleteLater();
		    return;
		  }
	      }
	  }
	else if(m_udpSocket)
	  {
	    if(m_udpSocket->state() == QAbstractSocket::UnconnectedState)
	      {
		saveStatus("connecting");
		m_udpSocket->connectToHost(m_address, m_port);

		int timeout = 2500;

		if(m_udpSocket->proxy().type() != QNetworkProxy::NoProxy)
		  timeout = 5000;

		if(!m_udpSocket->waitForConnected(timeout))
		  {
		    deleteLater();
		    return;
		  }
	      }
	  }
      }

  int v = spoton_kernel::setting
    ("gui/kernelExternalIpInterval", -1).toInt();

  if(v != -1)
    {
      v *= 1000;

      if(v == 30000)
	{
	  if(m_externalAddressDiscovererTimer.interval() != v)
	    m_externalAddressDiscovererTimer.start(30000);
	  else if(!m_externalAddressDiscovererTimer.isActive())
	    m_externalAddressDiscovererTimer.start(30000);
	}
      else
	{
	  if(m_externalAddressDiscovererTimer.interval() != v)
	    m_externalAddressDiscovererTimer.start(60000);
	  else if(!m_externalAddressDiscovererTimer.isActive())
	    m_externalAddressDiscovererTimer.start(60000);
	}
    }
  else
    m_externalAddressDiscovererTimer.stop();
}

void spoton_neighbor::saveStatistics(const QSqlDatabase &db)
{
  if(!db.isOpen())
    return;
  else if(m_id == -1)
    return;

  QSqlQuery query(db);
  QSslCipher cipher;
  bool ok = true;

  if(m_tcpSocket)
    cipher = m_tcpSocket->sessionCipher();

  int seconds = m_startTime.secsTo(QDateTime::currentDateTime());

  query.exec("PRAGMA synchronous = OFF");
  query.prepare("UPDATE neighbors SET "
		"bytes_read = ?, "
		"bytes_written = ?, "
		"is_encrypted = ?, "
		"ssl_session_cipher = ?, "
		"uptime = ? "
		"WHERE OID = ? AND "
		"status = 'connected' "
		"AND ? - uptime >= 10");
  query.bindValue(0, m_bytesRead);
  query.bindValue(1, m_bytesWritten);
  query.bindValue(2, isEncrypted() ? 1 : 0);

  if(cipher.isNull() || !spoton_kernel::s_crypts.value("chat", 0))
    query.bindValue(3, QVariant::String);
  else
    {
      query.bindValue
	(3, spoton_kernel::s_crypts.value("chat")->
	 encryptedThenHashed(QString("%1-%2-%3-%4-%5-%6-%7").
			     arg(cipher.name()).
			     arg(cipher.authenticationMethod()).
			     arg(cipher.encryptionMethod()).
			     arg(cipher.keyExchangeMethod()).
			     arg(cipher.protocolString()).
			     arg(cipher.supportedBits()).
			     arg(cipher.usedBits()).toUtf8(), &ok).
	 toBase64());

      if(!ok)
	query.bindValue(3, QVariant::String);
    }

  query.bindValue(4, seconds);
  query.bindValue(5, m_id);
  query.bindValue(6, seconds);

  if(ok)
    query.exec();
}

void spoton_neighbor::saveStatus(const QString &status)
{
  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "neighbors.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("PRAGMA synchronous = OFF");
	query.prepare("UPDATE neighbors SET is_encrypted = ?, status = ? "
		      "WHERE OID = ? AND status_control <> 'deleted'");
	query.bindValue(0, isEncrypted() ? 1 : 0);
	query.bindValue(1, status);
	query.bindValue(2, m_id);
	query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_neighbor::saveStatus(const QSqlDatabase &db,
				 const QString &status)
{
  if(!db.isOpen())
    return;
  else if(m_id == -1)
    return;
  else if(status.isEmpty())
    return;

  QSqlQuery query(db);

  query.exec("PRAGMA synchronous = OFF");
  query.prepare("UPDATE neighbors SET is_encrypted = ?, status = ? "
		"WHERE OID = ? AND status_control <> 'deleted'");
  query.bindValue(0, isEncrypted());
  query.bindValue(1, status);
  query.bindValue(2, m_id);
  query.exec();
}

void spoton_neighbor::run(void)
{
  spoton_neighbor_worker worker(this);

  exec();
  worker.stop();
}

void spoton_neighbor::slotReadyRead(void)
{
  QByteArray data;

  if(m_sctpSocket)
    data = m_sctpSocket->readAll();
  else if(m_tcpSocket)
    data = m_tcpSocket->readAll();
  else if(m_udpSocket)
    data = m_udpSocket->readAll();

  m_bytesRead += data.length();

  if(!data.isEmpty() && !isEncrypted() && m_useSsl)
    {
      data.clear();
      spoton_misc::logError
	(QString("spoton_neighbor::slotReadyRead(): "
		 "m_useSsl is true, however, isEncrypted() "
		 "is false "
		 "for %1:%2. "
		 "Purging read data.").
	 arg(m_address.toString()).
	 arg(m_port));
    }

  if(!data.isEmpty())
    {
      m_dataMutex.lockForWrite();

      if(data.length() <= m_maximumBufferSize - m_data.length())
	m_data.append(data);
      else
	{
	  m_data.clear();

	  if(data.length() <= m_maximumBufferSize)
	    m_data.append(data);

	  spoton_misc::logError
	    (QString("spoton_neighbor::slotReadyRead(): "
		     "too much data for %1:%2."
		     "Purging.").
	     arg(m_address.toString()).
	     arg(m_port));
	}

      m_dataMutex.unlock();
    }
}

void spoton_neighbor::processData(void)
{
  m_dataMutex.lockForRead();

  QByteArray data(m_data);

  m_dataMutex.unlock();

  QList<QByteArray> list;

  if(data.contains(spoton_send::EOM))
    {
      bool reset_keep_alive = false;
      int totalBytes = 0;

      while(data.contains(spoton_send::EOM))
	{
	  QByteArray bytes
	    (data.mid(0,
		      data.indexOf(spoton_send::EOM) +
		      spoton_send::EOM.length()));

	  data.remove(0, bytes.length());
	  totalBytes += bytes.length();

	  if(!bytes.isEmpty())
	    {
	      if(!spoton_kernel::messagingCacheContains(bytes))
		list.append(bytes);
	      else
		reset_keep_alive = true;
	    }
	}

      if(reset_keep_alive)
	emit resetKeepAlive();

      if(totalBytes > 0)
	{
	  m_dataMutex.lockForWrite();
	  m_data.remove(0, totalBytes);
	  m_dataMutex.unlock();
	}
    }

  while(!list.isEmpty())
    {
      QByteArray data(list.takeFirst());
      QByteArray originalData(data);
      int length = 0;

      if(data.contains("Content-Length: "))
	{
	  QByteArray contentLength(data);
	  int indexOf = -1;

	  contentLength.remove
	    (0,
	     contentLength.indexOf("Content-Length: ") +
	     qstrlen("Content-Length: "));
	  indexOf = contentLength.indexOf("\r\n");

	  if(indexOf > -1)
	    /*
	    ** toInt() returns zero on failure.
	    */

	    length = contentLength.mid(0, indexOf).toInt();
	}
      else
	{
	  spoton_misc::logError
	    (QString("spoton_neighbor::processData() "
		     "data does not contain Content-Length "
		     "for %1:%2.").
	     arg(m_address.toString()).
	     arg(m_port));
	  continue;
	}

      if(length <= 0)
	continue;

      if(length > m_maximumContentLength)
	{
	  spoton_misc::logError
	    (QString("spoton_neighbor::processData(): "
		     "the Content-Length header from node %1:%2 "
		     "contains a lot of data (%3). Ignoring. ").
	     arg(m_address.toString()).
	     arg(m_port).
	     arg(length));
	  continue;
	}

      if(!m_isUserDefined)
	{
	  /*
	  ** We're a server!
	  */

	  if(m_useAccounts)
	    {
	      if(length > 0 && data.contains("type=0050&content="))
		/*
		** This will certainly emit multiple authentication
		** approvals to the client.
		*/

		process0050(length, data);

	      if(!m_accountAuthenticated)
		continue;
	    }
	  else if(length > 0 && (data.contains("type=0050&content=") ||
				 data.contains("type=0051&content=") ||
				 data.contains("type=0052&content=")))
	    continue;
	}
      else if(length > 0 && data.contains("type=0051&content="))
	{
	  /*
	  ** The server responded. Let's verify that the server's
	  ** response is valid.
	  */

	  if(!m_accountClientSentSalt.isEmpty())
	    process0051(length, data);
	  else
	    m_accountAuthenticated = false;
	}
      else if(length > 0 && data.contains("type=0052&content="))
	{
	  if(!m_accountAuthenticated)
	    {
	      if(m_sctpSocket)
		{
		  if(m_sctpSocket->peerAddress().scopeId().trimmed().isEmpty())
		    emit authenticationRequested
		      (QString("%1:%2").
		       arg(m_sctpSocket->peerAddress().toString()).
		       arg(m_sctpSocket->peerPort()));
		  else
		    emit authenticationRequested
		      (QString("%1:%2:%3").
		       arg(m_sctpSocket->peerAddress().toString()).
		       arg(m_sctpSocket->peerPort()).
		       arg(m_sctpSocket->peerAddress().scopeId()));
		}
	      else if(m_tcpSocket)
		{
		  if(m_tcpSocket->peerAddress().scopeId().trimmed().isEmpty())
		    emit authenticationRequested
		      (QString("%1:%2").
		       arg(m_tcpSocket->peerAddress().toString()).
		       arg(m_tcpSocket->peerPort()));
		  else
		    emit authenticationRequested
		      (QString("%1:%2:%3").
		       arg(m_tcpSocket->peerAddress().toString()).
		       arg(m_tcpSocket->peerPort()).
		       arg(m_tcpSocket->peerAddress().scopeId()));
		}
	      else if(m_udpSocket)
		{
		  if(m_udpSocket->peerAddress().scopeId().trimmed().isEmpty())
		    emit authenticationRequested
		      (QString("%1:%2").
		       arg(m_udpSocket->peerAddress().toString()).
		       arg(m_udpSocket->peerPort()));
		  else
		    emit authenticationRequested
		      (QString("%1:%2:%3").
		       arg(m_udpSocket->peerAddress().toString()).
		       arg(m_udpSocket->peerPort()).
		   arg(m_udpSocket->peerAddress().scopeId()));
		}
	    }
	}

      if(m_isUserDefined)
	if(m_useAccounts)
	  {
	    if(!m_accountAuthenticated)
	      continue;
	  }

      if(length > 0 && data.contains("type=0011&content="))
	process0011(length, data);
      else if(length > 0 && data.contains("type=0012&content="))
	process0012(length, data);
      else if(length > 0 && data.contains("type=0014&content="))
	process0014(length, data);
      else if(length > 0 && data.contains("type=0030&content="))
	process0030(length, data);
      else if(length > 0 && (data.contains("type=0050&content=") ||
			     data.contains("type=0051&content=") ||
			     data.contains("type=0052&content=")))
	/*
	** We shouldn't be here!
	*/

	return;
      else if(length > 0 && data.contains("type=0065&content="))
	process0065(length, data);
      else if(length > 0 && data.contains("content="))
	{
	  emit resetKeepAlive();
	  spoton_kernel::messagingCacheAdd(originalData);

	  /*
	  ** Remove some header data.
	  */

	  length -= qstrlen("content=");

	  int indexOf = data.lastIndexOf("\r\n");

	  if(indexOf > -1)
	    data = data.mid(0, indexOf + 2);

	  indexOf = data.indexOf("content=");

	  if(indexOf > -1)
	    data.remove(0, indexOf + qstrlen("content="));

	  /*
	  ** Please note that findMessageType() calls
	  ** participantCount(). Therefore, the process() methods
	  ** that would do not.
	  */

	  QList<QByteArray> symmetricKeys;
	  QString messageType(findMessageType(data, symmetricKeys));

	  if(messageType == "0000")
	    process0000(length, data, symmetricKeys);
	  else if(messageType == "0000a")
	    process0000a(length, data);
	  else if(messageType == "0001a")
	    process0001a(length, data);
	  else if(messageType == "0001b")
	    process0001b(length, data, symmetricKeys);
	  else if(messageType == "0002a")
	    process0002a(length, data);
	  else if(messageType == "0002b")
	    process0002b(length, data, symmetricKeys);
	  else if(messageType == "0013")
	    process0013(length, data, symmetricKeys);
	  else if(messageType == "0040a")
	    process0040a(length, data, symmetricKeys);
	  else if(messageType == "0040b")
	    process0040b(length, data, symmetricKeys);
	  else
	    messageType.clear();

	  if(messageType.isEmpty())
	    if(data.length() == length)
	      spoton_kernel::s_kernel->processPotentialStarBeamData(data);

	  if(spoton_kernel::setting("gui/scramblerEnabled", false).toBool())
	    emit scrambleRequest();

	  if(spoton_kernel::setting("gui/superEcho", false).toBool())
	    emit receivedMessage(originalData, m_id);
	  else if(m_echoMode == "full")
	    {
	      if(messageType == "0001b" && data.split('\n').size() == 5)
		emit receivedMessage(originalData, m_id);
	      else if(messageType.isEmpty() ||
		      messageType == "0002b" ||
		      messageType == "0040a" || messageType == "0040b")
		emit receivedMessage(originalData, m_id);
	    }
	}
    }
}

void spoton_neighbor::slotConnected(void)
{
  if(m_sctpSocket)
    {
      m_sctpSocket->setSocketOption
	(spoton_sctp_socket::KeepAliveOption, 0); /*
						  ** We have our
						  ** own mechanism.
						  */
      m_sctpSocket->setSocketOption
	(spoton_sctp_socket::LowDelayOption,
	 spoton_kernel::setting("kernel/sctp_nodelay", 1).
	 toInt()); /*
		   ** Disable Nagle?
		   */
    }
  else if(m_tcpSocket)
    {
      m_tcpSocket->setSocketOption
	(QAbstractSocket::KeepAliveOption, 0); /*
					       ** We have our
					       ** own mechanism.
					       */
      m_tcpSocket->setSocketOption
	(QAbstractSocket::LowDelayOption,
	 spoton_kernel::setting("kernel/tcp_nodelay", 1).
	 toInt()); /*
		   ** Disable Nagle?
		   */
    }

  /*
  ** The local address is the address of the proxy. Unfortunately,
  ** we do not have network interfaces that have such an address.
  ** Hence, m_networkInterface will always be zero. The object
  ** m_networkInterface was removed on 11/08/2013. The following
  ** logic remains.
  */

  if(m_tcpSocket)
    {
      if(m_tcpSocket->proxy().type() != QNetworkProxy::NoProxy)
	{
	  QHostAddress address(m_ipAddress);

	  if(address.protocol() == QAbstractSocket::IPv4Protocol)
	    m_tcpSocket->setLocalAddress(QHostAddress("127.0.0.1"));
	  else
	    m_tcpSocket->setLocalAddress(QHostAddress("::1"));
	}
    }
  else if(m_udpSocket)
    {
      if(m_udpSocket->proxy().type() != QNetworkProxy::NoProxy)
	{
	  QHostAddress address(m_ipAddress);

	  if(address.protocol() == QAbstractSocket::IPv4Protocol)
	    m_udpSocket->setLocalAddress(QHostAddress("127.0.0.1"));
	  else
	    m_udpSocket->setLocalAddress(QHostAddress("::1"));
	}
    }

  if(m_id != -1)
    {
      spoton_crypt *s_crypt = spoton_kernel::s_crypts.value("chat", 0);

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
		QString country;

		if(m_sctpSocket)
		  country = spoton_misc::countryNameFromIPAddress
		    (m_sctpSocket->peerAddress().isNull() ?
		     m_sctpSocket->peerName() :
		     m_sctpSocket->peerAddress().
		     toString());
		else if(m_tcpSocket)
		  country = spoton_misc::countryNameFromIPAddress
		    (m_tcpSocket->peerAddress().isNull() ?
		     m_tcpSocket->peerName() :
		     m_tcpSocket->peerAddress().
		     toString());
		else if(m_udpSocket)
		  country = spoton_misc::countryNameFromIPAddress
		    (m_udpSocket->peerAddress().isNull() ?
		     m_udpSocket->peerName() :
		     m_udpSocket->peerAddress().
		     toString());

		bool ok = true;

		query.prepare("UPDATE neighbors SET country = ?, "
			      "is_encrypted = ?, "
			      "local_ip_address = ?, "
			      "local_port = ?, qt_country_hash = ?, "
			      "status = 'connected' "
			      "WHERE OID = ?");
		query.bindValue
		  (0, s_crypt->
		   encryptedThenHashed(country.toLatin1(), &ok).toBase64());
		query.bindValue(1, isEncrypted() ? 1 : 0);

		if(m_sctpSocket)
		  {
		    query.bindValue
		      (2, m_sctpSocket->localAddress().toString());
		    query.bindValue(3, m_sctpSocket->localPort());
		  }
		else if(m_tcpSocket)
		  {
		    query.bindValue
		      (2, m_tcpSocket->localAddress().toString());
		    query.bindValue(3, m_tcpSocket->localPort());
		  }
		else if(m_udpSocket)
		  {
		    query.bindValue
		      (2, m_udpSocket->localAddress().toString());
		    query.bindValue(3, m_udpSocket->localPort());
		  }

		if(ok)
		  query.bindValue
		    (4, s_crypt->keyedHash(country.remove(" ").
					   toLatin1(), &ok).
		     toBase64());

		query.bindValue(5, m_id);

		if(ok)
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

  if(spoton_kernel::setting("gui/kernelExternalIpInterval", -1).
     toInt() != -1)
    {
      if(m_externalAddress)
	{
	  m_externalAddress->discover();
	  m_externalAddressDiscovererTimer.start();
	}
      else
	m_externalAddressDiscovererTimer.stop();
    }
  else
    m_externalAddressDiscovererTimer.stop();

  m_lastReadTime = QDateTime::currentDateTime();

  if(!m_keepAliveTimer.isActive())
    m_keepAliveTimer.start();

  if(m_useAccounts)
    if(!m_useSsl)
      {
	m_accountTimer.start();
	m_authenticationTimer.start();
      }
}

void spoton_neighbor::savePublicKey(const QByteArray &keyType,
				    const QByteArray &name,
				    const QByteArray &publicKey,
				    const QByteArray &signature,
				    const QByteArray &sPublicKey,
				    const QByteArray &sSignature,
				    const qint64 neighborOid)
{
  if(keyType == "chat")
    {
      if(!spoton_kernel::setting("gui/acceptChatKeys", false).toBool())
	return;
    }
  else if(keyType == "email")
    {
      if(!spoton_kernel::setting("gui/acceptEmailKeys", false).toBool())
	return;
    }
  else if(keyType == "url")
    {
      if(!spoton_kernel::setting("gui/acceptUrlKeys", false).toBool())
	return;
    }
  else
    {
      spoton_misc::logError
	(QString("spoton_neighbor::savePublicKey(): unexpected key type "
		 "for %1:%2.").
	 arg(m_address.toString()).
	 arg(m_port));
      return;
    }

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
  spoton_crypt *s_crypt1 = spoton_kernel::s_crypts.value(keyType, 0);

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
	    bool ok = true;

	    query.setForwardOnly(true);
	    query.prepare("SELECT neighbor_oid "
			  "FROM friends_public_keys "
			  "WHERE public_key_hash = ?");
	    query.bindValue(0, spoton_crypt::sha512Hash(publicKey,
							&ok).toBase64());

	    if(ok)
	      if(query.exec())
		if(query.next())
		  if(query.value(0).toLongLong() == -1)
		    share = true;

	    if(!share)
	      {
		/*
		** An error occurred or we do not have the public key.
		*/

		spoton_misc::saveFriendshipBundle
		  (keyType, name, publicKey, sPublicKey,
		   neighborOid, db, s_crypt1);
		spoton_misc::saveFriendshipBundle
		  (keyType + "-signature", name, sPublicKey, QByteArray(),
		   neighborOid, db, s_crypt1);
	      }
	  }
	else
	  {
	    spoton_misc::saveFriendshipBundle
	      (keyType, name, publicKey, sPublicKey, -1, db, s_crypt1);
	    spoton_misc::saveFriendshipBundle
	      (keyType + "-signature", name, sPublicKey, QByteArray(), -1,
	       db, s_crypt1);
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(share)
    {
      spoton_crypt *s_crypt2 = spoton_kernel::s_crypts.value
	(keyType + "-signature", 0);

      if(s_crypt1 && s_crypt2)
	{
	  QByteArray myName;

	  if(keyType == "chat")
	    myName = spoton_kernel::setting("gui/nodeName",
					    "unknown").
	      toByteArray().trimmed();
	  else if(keyType == "email")
	    myName = spoton_kernel::setting("gui/emailName",
					    "unknown").
	      toByteArray().trimmed();
	  else
	    myName = spoton_kernel::setting("gui/urlName",
					    "unknown").
	      toByteArray().trimmed();

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
	    emit sharePublicKey(keyType, myName,
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
	  (QString("spoton_neighbor::slotSendMessage(): write() error "
		   "for %1:%2.").
	   arg(m_address.toString()).
	   arg(m_port));
      else
	{
	  addToBytesWritten(data.length());
	  spoton_kernel::messagingCacheAdd(data);
	}
    }
}

void spoton_neighbor::slotReceivedMessage(const QByteArray &data,
					  const qint64 id)
{
  /*
  ** A neighbor (id) received a message. This neighbor now needs
  ** to send the message to its peer.
  */

  if(id != m_id)
    if(m_echoMode == "full" ||
       spoton_kernel::setting("gui/superEcho", false).toBool())
      if(readyToWrite())
	{
	  if(write(data.constData(), data.length()) != data.length())
	    spoton_misc::logError
	      (QString("spoton_neighbor::slotReceivedMessage(): write() "
		       "error for %1:%2.").
	       arg(m_address.toString()).
	       arg(m_port));
	  else
	    {
	      addToBytesWritten(data.length());
	      spoton_kernel::messagingCacheAdd(data);
	    }
	}
}

void spoton_neighbor::slotLifetimeExpired(void)
{
  spoton_misc::logError
    (QString("spoton_neighbor::slotLifetimeExpired(): "
	     "expiration time reached for %1:%2. Aborting socket.").
     arg(m_address.toString()).
     arg(m_port));
  deleteLater();
}

void spoton_neighbor::slotSharePublicKey(const QByteArray &keyType,
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
      (QString("spoton_neighbor::slotSharePublicKey(): "
	       "write() failure for %1:%2.").
       arg(m_address.toString()).
       arg(m_port));
  else
    {
      addToBytesWritten(message.length());

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
			  "neighbor_oid = -1 WHERE "
			  "key_type = ? AND "
			  "neighbor_oid = ?");
	    query.bindValue(0, keyType.constData());
	    query.bindValue(1, m_id);
	    query.exec();
	    query.prepare("UPDATE friends_public_keys SET "
			  "neighbor_oid = -1 WHERE "
			  "key_type = ? AND "
			  "neighbor_oid = ?");
	    query.bindValue(0, (keyType + "-signature").constData());
	    query.bindValue(1, m_id);
	    query.exec();
	  }

	db.close();
      }

      QSqlDatabase::removeDatabase(connectionName);
    }
}

void spoton_neighbor::process0000(int length, const QByteArray &dataIn,
				  const QList<QByteArray> &symmetricKeys)
{
  spoton_crypt *s_crypt = spoton_kernel::s_crypts.value("chat", 0);

  if(!s_crypt)
    return;

  QByteArray data(dataIn);

  if(length == data.length())
    {
      data = QByteArray::fromBase64(data);

      QByteArray originalData(data);
      QList<QByteArray> list(data.split('\n'));
      bool ok = true;

      if(list.size() == 2)
	{
	  /*
	  ** Gemini?
	  */

	  for(int i = 0; i < list.size(); i++)
	    list.replace(i, QByteArray::fromBase64(list.at(i)));

	  QPair<QByteArray, QByteArray> gemini;

	  if(symmetricKeys.value(0).isEmpty() ||
	     symmetricKeys.value(2).isEmpty())
	    gemini = spoton_misc::findGeminiInCosmos(list.value(0),
						     list.value(1),
						     s_crypt);
	  else
	    {
	      gemini.first = symmetricKeys.value(0);
	      gemini.second = symmetricKeys.value(2);
	    }

	  if(!gemini.first.isEmpty() && !gemini.second.isEmpty())
	    {
	      QByteArray computedHash;
	      QByteArray message(list.value(0));
	      spoton_crypt crypt("aes256",
				 "sha512",
				 QByteArray(),
				 gemini.first,
				 0,
				 0,
				 QString(""));

	      computedHash = spoton_crypt::keyedHash
		(message, gemini.second, "sha512", &ok);

	      if(ok)
		{
		  QByteArray messageCode(list.value(1));

		  if(!computedHash.isEmpty() && !messageCode.isEmpty() &&
		     spoton_crypt::memcmp(computedHash, messageCode))
		    {
		      message = crypt.decrypted(message, &ok);

		      if(ok)
			list = message.split('\n');

		      list.removeAt(0); // Message Type

		      if(list.size() != 3)
			{
			  spoton_misc::logError
			    (QString("spoton_neighbor::process0000(): "
				     "received irregular data. "
				     "Expecting 3 "
				     "entries, "
				     "received %1.").arg(list.size()));
			  return;
			}
		    }
		  else
		    {
		      spoton_misc::logError("spoton_neighbor::"
					    "process0000(): "
					    "computed message code does "
					    "not match provided code.");
		      return;
		    }
		}
	    }
	  else
	    ok = false; // A gemini was not discovered. We need to echo.
	}
      else if(list.size() != 3)
	{
	  spoton_misc::logError
	    (QString("spoton_neighbor::process0000(): "
		     "received irregular data. Expecting 3 "
		     "entries, "
		     "received %1.").arg(list.size()));
	  return;
	}

      if(list.size() == 3)
	{
	  for(int i = 0; i < list.size(); i++)
	    list.replace(i, QByteArray::fromBase64(list.at(i)));

	  QByteArray hashKey;
	  QByteArray keyInformation(list.value(0));
	  QByteArray symmetricKey;
	  QByteArray symmetricKeyAlgorithm;

	  keyInformation = s_crypt->
	    publicKeyDecrypt(keyInformation, &ok);

	  if(ok)
	    {
	      QList<QByteArray> list(keyInformation.split('\n'));

	      list.removeAt(0); // Message Type

	      if(list.size() == 3)
		{
		  hashKey = QByteArray::fromBase64(list.value(1));
		  symmetricKey = QByteArray::fromBase64(list.value(0));
		  symmetricKeyAlgorithm = QByteArray::fromBase64
		    (list.value(2));
		}
	      else
		{
		  spoton_misc::logError
		    (QString("spoton_neighbor::process0000(): "
			     "received irregular data. "
			     "Expecting 3 "
			     "entries, "
			     "received %1.").arg(list.size()));
		  return;
		}
	    }

	  if(ok)
	    {
	      QByteArray computedHash;
	      QByteArray data(list.value(1));

	      computedHash = spoton_crypt::keyedHash(data,
						     hashKey,
						     "sha512",
						     &ok);

	      if(ok)
		{
		  QByteArray messageCode(list.value(2));

		  if(!computedHash.isEmpty() && !messageCode.isEmpty() &&
		     spoton_crypt::memcmp(computedHash, messageCode))
		    {
		      spoton_crypt crypt(symmetricKeyAlgorithm,
					 "sha512",
					 QByteArray(),
					 symmetricKey,
					 0,
					 0,
					 QString(""));

		      data = crypt.decrypted(data, &ok);

		      if(ok)
			{
			  QList<QByteArray> list(data.split('\n'));

			  if(list.size() == 6)
			    {
			      for(int i = 0; i < list.size(); i++)
				list.replace
				  (i, QByteArray::fromBase64(list.at(i)));

			      if(spoton_misc::
				 isAcceptedParticipant(list.value(0), "chat"))
				{
				  if(spoton_kernel::setting("gui/chatAccept"
							    "SignedMessages"
							    "Only",
							    true).toBool())
				    if(!spoton_misc::
				       isValidSignature(list.value(0) +
							list.value(1) +
							list.value(2) +
							list.value(3) +
							list.value(4),
							list.value(0),
							list.value(5),
							s_crypt))
				      {
					spoton_misc::logError
					  ("spoton_neighbor::"
					   "process0000(): invalid "
					   "signature.");
					return;
				      }

				  saveParticipantStatus
				    (list.value(1),  // Name
				     list.value(0)); // Public Key Hash

				  if(!list.value(0).isEmpty() &&
				     !list.value(1).isEmpty() &&
				     !list.value(2).isEmpty() &&
				     !list.value(3).isEmpty() &&
				     !list.value(4).isEmpty())
				    emit receivedChatMessage
				      ("message_" +
				       list.value(0).toBase64() + "_" +
				       list.value(1).toBase64() + "_" +
				       list.value(2).toBase64() + "_" +
				       list.value(3).toBase64() + "_" +
				       list.value(4).toBase64() + "_" +
				       messageCode.toBase64().
				       append('\n'));
				}
			    }
			  else
			    spoton_misc::logError
			      (QString("spoton_neighbor::process0000(): "
				       "received irregular data. "
				       "Expecting 6 "
				       "entries, "
				       "received %1.").arg(list.size()));
			}
		    }
		  else
		    spoton_misc::logError("spoton_neighbor::"
					  "process0000(): "
					  "computed message code does "
					  "not match provided code.");
		}
	    }
	}
    }
  else
    spoton_misc::logError
      (QString("spoton_neighbor::process0000(): 0000 "
	       "content-length mismatch (advertised: %1, received: %2) "
	       "for %3:%4.").
       arg(length).arg(data.length()).
       arg(m_address.toString()).
       arg(m_port));
}

void spoton_neighbor::process0000a(int length, const QByteArray &dataIn)
{
  spoton_crypt *s_crypt = spoton_kernel::s_crypts.value("chat", 0);

  if(!s_crypt)
    return;

  QByteArray data(dataIn);

  if(length == data.length())
    {
      data = QByteArray::fromBase64(data);

      QByteArray originalData(data);
      QList<QByteArray> list(data.split('\n'));

      if(list.size() != 3)
	{
	  spoton_misc::logError
	    (QString("spoton_neighbor::process0000a(): "
		     "received irregular data. Expecting 3 "
		     "entries, "
		     "received %1.").arg(list.size()));
	  return;
	}

      bool ok = true;

      for(int i = 0; i < list.size(); i++)
	list.replace(i, QByteArray::fromBase64(list.at(i)));

      QByteArray hashKey;
      QByteArray keyInformation(list.value(0));
      QByteArray symmetricKey;
      QByteArray symmetricKeyAlgorithm;

      keyInformation = s_crypt->
	publicKeyDecrypt(keyInformation, &ok);

      if(ok)
	{
	  QList<QByteArray> list(keyInformation.split('\n'));

	  list.removeAt(0); // Message Type

	  if(list.size() == 3)
	    {
	      hashKey = QByteArray::fromBase64(list.value(1));
	      symmetricKey = QByteArray::fromBase64(list.value(0));
	      symmetricKeyAlgorithm = QByteArray::fromBase64
		(list.value(2));
	    }
	  else
	    {
	      spoton_misc::logError
		(QString("spoton_neighbor::process0000a(): "
			 "received irregular data. "
			 "Expecting 3 "
			 "entries, "
			 "received %1.").arg(list.size()));
	      return;
	    }
	}

      if(ok)
	{
	  QByteArray computedHash;
	  QByteArray data(list.value(1));

	  computedHash = spoton_crypt::keyedHash(data, hashKey,
						 "sha512", &ok);

	  if(ok)
	    {
	      QByteArray messageCode(list.value(2));

	      if(!computedHash.isEmpty() && !messageCode.isEmpty() &&
		 spoton_crypt::memcmp(computedHash, messageCode))
		{
		  spoton_crypt crypt(symmetricKeyAlgorithm,
				     "sha512",
				     QByteArray(),
				     symmetricKey,
				     0,
				     0,
				     QString(""));

		  data = crypt.decrypted(data, &ok);

		  if(ok)
		    {
		      QList<QByteArray> list(data.split('\n'));

		      if(list.size() == 4)
			{
			  for(int i = 0; i < list.size(); i++)
			    list.replace
			      (i, QByteArray::fromBase64(list.at(i)));

			  if(spoton_misc::
			     isAcceptedParticipant(list.value(0), "chat"))
			    {
			      if(spoton_kernel::setting("gui/chatAccept"
							"SignedMessagesOnly",
							true).toBool())
				if(!spoton_misc::
				   /*
				   ** 0 - Sender's SHA-512 Hash
				   ** 1 - Gemini Encryption Key
				   ** 2 - Gemini Hash Key
				   ** 3 - Signature
				   */
				   isValidSignature(list.value(0) +
						    list.value(1) +
						    list.value(2),
						    list.value(0),
						    list.value(3),
						    s_crypt))
				  {
				    spoton_misc::logError
				      ("spoton_neighbor::"
				       "process0000a(): invalid "
				       "signature.");
				    return;
				  }

			      saveGemini(list.value(0), list.value(1),
					 list.value(2));
			    }
			}
		      else
			spoton_misc::logError
			  (QString("spoton_neighbor::process0000a(): "
				   "received irregular data. "
				   "Expecting 4 "
				   "entries, "
				   "received %1.").arg(list.size()));
		    }
		}
	      else
		spoton_misc::logError("spoton_neighbor::process0000a(): "
				      "computed message code does "
				      "not match provided code.");
	    }
	}
    }
  else
    spoton_misc::logError
      (QString("spoton_neighbor::process0000a(): 0000a "
	       "content-length mismatch (advertised: %1, received: %2) "
	       "for %3:%4.").
       arg(length).arg(data.length()).
       arg(m_address.toString()).
       arg(m_port));
}

void spoton_neighbor::process0001a(int length, const QByteArray &dataIn)
{
  spoton_crypt *s_crypt = spoton_kernel::s_crypts.value("email", 0);

  if(!s_crypt)
    return;

  QByteArray data(dataIn);

  if(length == data.length())
    {
      data = QByteArray::fromBase64(data);

      QList<QByteArray> list(data.split('\n'));

      if(list.size() != 6)
	{
	  spoton_misc::logError
	    (QString("spoton_neighbor::process0001a(): "
		     "received irregular data. Expecting 6 "
		     "entries, "
		     "received %1.").arg(list.size()));
	  return;
	}

      bool ok = true;

      for(int i = 0; i < list.size(); i++)
	list.replace(i, QByteArray::fromBase64(list.at(i)));

      QByteArray computedHash;
      QByteArray data1(list.value(1));
      QByteArray data2(list.value(3));
      QByteArray hashKey;
      QByteArray keyInformation1(list.value(0));
      QByteArray keyInformation2(list.value(2));
      QByteArray messageCode1(list.value(5));
      QByteArray messageCode2(list.value(4));
      QByteArray recipientHash;
      QByteArray senderPublicKeyHash1;
      QByteArray signature;
      QByteArray symmetricKey;
      QByteArray symmetricKeyAlgorithm;

      keyInformation1 = s_crypt->
	publicKeyDecrypt(keyInformation1, &ok);

      if(ok)
	{
	  QList<QByteArray> list(keyInformation1.split('\n'));

	  list.removeAt(0); // Message Type

	  if(list.size() == 3)
	    {
	      hashKey = QByteArray::fromBase64(list.value(1));
	      symmetricKey = QByteArray::fromBase64(list.value(0));
	      symmetricKeyAlgorithm = QByteArray::fromBase64
		(list.value(2));
	    }
	  else
	    {
	      spoton_misc::logError
		(QString("spoton_neighbor::process0001a(): "
			 "received irregular data. "
			 "Expecting 3 "
			 "entries, "
			 "received %1.").arg(list.size()));
	      return;
	    }

	  computedHash = spoton_crypt::keyedHash
	    (data1 + keyInformation2 + data2, hashKey, "sha512", &ok);

	  if(ok)
	    if(computedHash.isEmpty() || messageCode1.isEmpty() ||
	       !spoton_crypt::memcmp(computedHash, messageCode1))
	      {
		spoton_misc::logError
		  ("spoton_neighbor::"
		   "process0001a(): "
		   "computed message code 1 does "
		   "not match provided code.");
		return;
	      }

	  QByteArray data;
	  QByteArray senderPublicKeyHash2;
	  spoton_crypt crypt(symmetricKeyAlgorithm,
			     "sha512",
			     QByteArray(),
			     symmetricKey,
			     0,
			     0,
			     QString(""));

	  data = crypt.decrypted(data1, &ok);

	  if(ok)
	    {
	      QList<QByteArray> list(data.split('\n'));

	      if(list.size() == 3)
		{
		  senderPublicKeyHash1 = QByteArray::fromBase64
		    (list.value(0));
		  recipientHash = QByteArray::fromBase64(list.value(1));
		  signature = QByteArray::fromBase64(list.value(2));

		  if(spoton_kernel::setting("gui/emailAcceptSigned"
					    "MessagesOnly",
					    true).toBool())
		    if(!spoton_misc::
		       isValidSignature(senderPublicKeyHash1 +
					recipientHash,
					senderPublicKeyHash1,
					signature,
					s_crypt))
		      {
			spoton_misc::logError
			  ("spoton_neighbor::"
			   "process0001a(): invalid "
			   "signature.");
			return;
		      }
		}
	      else
		{
		  spoton_misc::logError
		    (QString("spoton_neighbor::process0001a(): "
			     "received irregular data. "
			     "Expecting 3 "
			     "entries, "
			     "received %1.").arg(list.size()));
		  return;
		}
	    }

	  if(ok)
	    {
	      QByteArray publicKey = s_crypt->publicKey(&ok);
	      QByteArray publicKeyHash;

	      if(ok)
		publicKeyHash = spoton_crypt::sha512Hash(publicKey, &ok);

	      if(publicKeyHash == recipientHash)
		{
		  keyInformation2 = s_crypt->
		    publicKeyDecrypt(keyInformation2, &ok);

		  if(ok)
		    {
		      QList<QByteArray> list(keyInformation2.split('\n'));

		      list.removeAt(0); // Message Type

		      if(list.size() == 3)
			{
			  hashKey = QByteArray::fromBase64(list.value(1));
			  symmetricKey = QByteArray::fromBase64
			    (list.value(0));
			  symmetricKeyAlgorithm = QByteArray::fromBase64
			    (list.value(2));
			}
		      else
			{
			  spoton_misc::logError
			    (QString("spoton_neighbor::process0001a(): "
				     "received irregular data. "
				     "Expecting 3 "
				     "entries, "
				     "received %1.").arg(list.size()));
			  return;
			}

		      computedHash = spoton_crypt::keyedHash
			(data2, hashKey, "sha512", &ok);

		      if(ok)
			if(computedHash.isEmpty() || messageCode2.isEmpty() ||
			   !spoton_crypt::memcmp(computedHash, messageCode2))
			  {
			    spoton_misc::logError
			      ("spoton_neighbor::"
			       "process0001a(): "
			       "computed message code 2 does "
			       "not match provided code.");
			    return;
			  }

		      QByteArray message;
		      QByteArray name;
		      QByteArray signature;
		      QByteArray subject;
		      bool goldbugUsed = false;
		      spoton_crypt crypt(symmetricKeyAlgorithm,
					 "sha512",
					 QByteArray(),
					 symmetricKey,
					 0,
					 0,
					 QString(""));

		      if(ok)
			data = crypt.decrypted(data2, &ok);

		      if(ok)
			{
			  QList<QByteArray> list(data.split('\n'));

			  if(list.size() == 6)
			    {
			      senderPublicKeyHash2 =
				QByteArray::fromBase64(list.value(0));
			      name =
				QByteArray::fromBase64(list.value(1));
			      subject =
				QByteArray::fromBase64(list.value(2));
			      message =
				QByteArray::fromBase64(list.value(3));
			      signature =
				QByteArray::fromBase64(list.value(4));
			      goldbugUsed =
				QVariant
				(QByteArray::fromBase64(list.value(5))).
				toBool();
			    }
			  else
			    {
			      spoton_misc::logError
				(QString("spoton_neighbor::process0001a(): "
					 "received irregular data. "
					 "Expecting 6 "
					 "entries, "
					 "received %1.").arg(list.size()));
			      return;
			    }
			}

		      if(ok)
			{
			  /*
			  ** This is our letter! Please remember that the
			  ** message may have been encrypted via a goldbug.
			  */

			  storeLetter(symmetricKey,
				      symmetricKeyAlgorithm,
				      senderPublicKeyHash2,
				      name,
				      subject,
				      message,
				      signature,
				      goldbugUsed);
			  return;
			}
		    }
		}
	    }
	}

      if(ok)
	if(spoton_kernel::setting("gui/postoffice_enabled",
				  false).toBool())
	  if(spoton_misc::
	     isAcceptedParticipant(recipientHash, "email"))
	    if(spoton_misc::
	       isAcceptedParticipant(senderPublicKeyHash1, "email"))
	      {
		if(spoton_kernel::setting("gui/coAcceptSignedMessagesOnly",
					  true).toBool())
		  if(!spoton_misc::
		     isValidSignature(senderPublicKeyHash1 +
				      recipientHash,
				      senderPublicKeyHash1,
				      signature,
				      s_crypt))
		    {
		      spoton_misc::logError
			("spoton_neighbor::"
			 "process0001a(): invalid "
			 "signature.");
		      return;
		    }

		/*
		** Store the letter in the post office!
		*/

		saveParticipantStatus(senderPublicKeyHash1);
		storeLetter(list.mid(2, 3), recipientHash);
	      }
    }
  else
    spoton_misc::logError
      (QString("spoton_neighbor::process0001a(): 0001a "
	       "content-length mismatch (advertised: %1, received: %2) "
	       "for %3:%4.").
       arg(length).arg(data.length()).
       arg(m_address.toString()).
       arg(m_port));
}

void spoton_neighbor::process0001b(int length, const QByteArray &dataIn,
				   const QList<QByteArray> &symmetricKeys)
{
  spoton_crypt *s_crypt = spoton_kernel::s_crypts.value("email", 0);

  if(!s_crypt)
    return;

  QByteArray data(dataIn);

  if(length == data.length())
    {
      data = QByteArray::fromBase64(data);

      QByteArray originalData(data);
      QList<QByteArray> list(data.split('\n'));

      if(!(list.size() == 3 || list.size() == 5))
	{
	  spoton_misc::logError
	    (QString("spoton_neighbor::process0001b(): "
		     "received irregular data. Expecting 3 or 5 "
		     "entries, "
		     "received %1.").arg(list.size()));
	  return;
	}

      for(int i = 0; i < list.size(); i++)
	list.replace(i, QByteArray::fromBase64(list.at(i)));

      if(list.size() == 3)
	{
	  QByteArray hashKey;
	  QByteArray keyInformation(list.value(0));
	  QByteArray symmetricKey;
	  QByteArray symmetricKeyAlgorithm;
	  bool ok = true;

	  keyInformation = s_crypt->
	    publicKeyDecrypt(keyInformation, &ok);

	  if(ok)
	    {
	      QList<QByteArray> list(keyInformation.split('\n'));

	      list.removeAt(0); // Message Type

	      if(list.size() == 3)
		{
		  hashKey = QByteArray::fromBase64(list.value(1));
		  symmetricKey = QByteArray::fromBase64(list.value(0));
		  symmetricKeyAlgorithm = QByteArray::fromBase64
		    (list.value(2));
		}
	      else
		{
		  spoton_misc::logError
		    (QString("spoton_neighbor::0001b(): "
			     "received irregular data. "
			     "Expecting 3 "
			     "entries, "
			     "received %1.").arg(list.size()));
		  return;
		}
	    }

	  if(ok)
	    {
	      QByteArray computedHash;
	      QByteArray data(list.value(1));

	      computedHash = spoton_crypt::keyedHash
		(data, hashKey, "sha512", &ok);

	      if(ok)
		{
		  QByteArray messageCode(list.value(2));

		  if(!computedHash.isEmpty() && !messageCode.isEmpty() &&
		     spoton_crypt::memcmp(computedHash, messageCode))
		    {
		      spoton_crypt crypt(symmetricKeyAlgorithm,
					 "sha512",
					 QByteArray(),
					 symmetricKey,
					 0,
					 0,
					 QString(""));

		      data = crypt.decrypted(data, &ok);

		      if(ok)
			{
			  QList<QByteArray> list(data.split('\n'));

			  if(list.size() == 6)
			    {
			      for(int i = 0; i < list.size(); i++)
				list.replace
				  (i, QByteArray::fromBase64(list.at(i)));

			      storeLetter
				(symmetricKey,
				 symmetricKeyAlgorithm,
				 list.value(0),  // Public Key Hash
				 list.value(1),  // Name
				 list.value(2),  // Subject
				 list.value(3),  // Message
				 list.value(4),  // Signature
				 QVariant(list.value(5)).
				 toBool());      // Gold Bug Used?
			      return;
			    }
			  else
			    {
			      spoton_misc::logError
				(QString("spoton_neighbor::process0001b(): "
					 "received irregular data. "
					 "Expecting 6 "
					 "entries, "
					 "received %1.").arg(list.size()));
			      return;
			    }
			}
		    }
		  else
		    spoton_misc::logError("spoton_neighbor::process0001b(): "
					  "computed message code does "
					  "not match provided code.");
		}
	    }
	}

      if(list.size() == 5)
	/*
	** This letter is destined for someone else.
	*/

	if(spoton_kernel::setting("gui/postoffice_enabled",
				  false).toBool())
	  {
	    QByteArray recipientHash;
	    bool ok = true;
	    spoton_crypt crypt("aes256",
			       "sha512",
			       QByteArray(),
			       symmetricKeys.value(0),
			       0,
			       0,
			       QString(""));

	    recipientHash = crypt.decrypted(list.value(3), &ok);

	    if(ok)
	      if(spoton_misc::isAcceptedParticipant(recipientHash, "email"))
		storeLetter(list.mid(0, 3), recipientHash);
	  }
    }
  else
    spoton_misc::logError
      (QString("spoton_neighbor::process0001b(): 0001b "
	       "content-length mismatch (advertised: %1, received: %2) "
	       "for %3:%4.").
       arg(length).arg(data.length()).
       arg(m_address.toString()).
       arg(m_port));
}

void spoton_neighbor::process0002a(int length, const QByteArray &dataIn)
{
  spoton_crypt *s_crypt = spoton_kernel::s_crypts.value("email", 0);

  if(!s_crypt)
    return;

  QByteArray data(dataIn);

  if(length == data.length())
    {
      data = QByteArray::fromBase64(data);

      QByteArray originalData(data);
      QList<QByteArray> list(data.split('\n'));

      if(list.size() != 3)
	{
	  spoton_misc::logError
	    (QString("spoton_neighbor::process0002a(): "
		     "received irregular data. Expecting 3 entries, "
		     "received %1.").arg(list.size()));
	  return;
	}

      bool ok = true;

      for(int i = 0; i < list.size(); i++)
	list.replace(i, QByteArray::fromBase64(list.at(i)));

      /*
      ** We must do some sort of thinking.
      ** Remember, we may receive multiple mail requests. And we may
      ** have many letters for the requesting parties. How should
      ** we retrieve the letters in a timely, yet functional, manner?
      */

      QByteArray hashKey;
      QByteArray keyInformation(list.value(0));
      QByteArray symmetricKey;
      QByteArray symmetricKeyAlgorithm;

      keyInformation = s_crypt->
	publicKeyDecrypt(keyInformation, &ok);

      if(ok)
	{
	  QList<QByteArray> list(keyInformation.split('\n'));

	  list.removeAt(0); // Message Type

	  if(list.size() == 3)
	    {
	      hashKey = QByteArray::fromBase64(list.value(1));
	      symmetricKey = QByteArray::fromBase64(list.value(0));
	      symmetricKeyAlgorithm = QByteArray::fromBase64
		(list.value(2));
	    }
	  else
	    {
	      spoton_misc::logError
		(QString("spoton_neighbor::process0002a(): "
			 "received irregular data. "
			 "Expecting 3 "
			 "entries, "
			 "received %1.").arg(list.size()));
	      return;
	    }
	}

      if(ok)
	{
	  QByteArray computedHash;
	  QByteArray data(list.value(1));

	  computedHash = spoton_crypt::keyedHash
	    (data, hashKey, "sha512", &ok);

	  if(ok)
	    {
	      QByteArray messageCode(list.value(2));

	      if(!computedHash.isEmpty() && !messageCode.isEmpty() &&
		 spoton_crypt::memcmp(computedHash, messageCode))
		{
		  spoton_crypt crypt(symmetricKeyAlgorithm,
				     "sha512",
				     QByteArray(),
				     symmetricKey,
				     0,
				     0,
				     QString(""));

		  data = crypt.decrypted(data, &ok);

		  if(ok)
		    {
		      QList<QByteArray> list(data.split('\n'));

		      if(list.size() == 3)
			{
			  for(int i = 0; i < list.size(); i++)
			    list.replace
			      (i, QByteArray::fromBase64(list.at(i)));

			  saveParticipantStatus
			    (list.value(0)); // Public Key Hash
			  emit retrieveMail
			    (list.value(1),  // Data
			     list.value(0),  // Public Key Hash
			     list.value(2)); // Signature
			}
		      else
			spoton_misc::logError
			  (QString("spoton_neighbor::process0002a(): "
				   "received irregular data. "
				   "Expecting 3 "
				   "entries, "
				   "received %1.").arg(list.size()));
		    }
		}
	      else
		spoton_misc::logError("spoton_neighbor::process0002a(): "
				      "computed message code does "
				      "not match provided code.");
	    }
	}
    }
  else
    spoton_misc::logError
      (QString("spoton_neighbor::process0002a(): 0002a "
	       "content-length mismatch (advertised: %1, received: %2) "
	       "for %3:%4.").
       arg(length).arg(data.length()).
       arg(m_address.toString()).
       arg(m_port));
}

void spoton_neighbor::process0002b(int length, const QByteArray &dataIn,
				   const QList<QByteArray> &symmetricKeys)
{
  Q_UNUSED(symmetricKeys);
  spoton_crypt *s_crypt = spoton_kernel::s_crypts.value("email", 0);

  if(!s_crypt)
    return;

  QByteArray data(dataIn);

  if(length == data.length())
    {
      data = QByteArray::fromBase64(data);

      QByteArray originalData(data);
      QList<QByteArray> list(data.split('\n'));

      if(list.size() != 2)
	{
	  spoton_misc::logError
	    (QString("spoton_neighbor::process0002b(): "
		     "received irregular data. Expecting 2 entries, "
		     "received %1.").arg(list.size()));
	  return;
	}

      bool ok = true;

      for(int i = 0; i < list.size(); i++)
	list.replace(i, QByteArray::fromBase64(list.at(i)));

      /*
      ** We must do some sort of thinking.
      ** Remember, we may receive multiple mail requests. And we may
      ** have many letters for the requesting parties. How should
      ** we retrieve the letters in a timely, yet functional, manner?
      */

      /*
      ** symmetricKeys[0]: Encryption Key
      ** symmetricKeys[1]: Encryption Type
      ** symmetricKeys[2]: Hash Key
      ** symmetricKeys[3]: Hash Type
      */

      QByteArray computedHash;
      QByteArray data(list.value(0));

      computedHash = spoton_crypt::keyedHash
	(data, symmetricKeys.value(2), symmetricKeys.value(3), &ok);

      if(ok)
	{
	  QByteArray messageCode(list.value(1));

	  if(!computedHash.isEmpty() && !messageCode.isEmpty() &&
	     spoton_crypt::memcmp(computedHash, messageCode))
	    {
	      spoton_crypt crypt(symmetricKeys.value(1),
				 "sha512",
				 QByteArray(),
				 symmetricKeys.value(0),
				 0,
				 0,
				 QString(""));

	      data = crypt.decrypted(data, &ok);

	      if(ok)
		{
		  QList<QByteArray> list(data.split('\n'));

		  if(list.size() == 4)
		    {
		      for(int i = 0; i < list.size(); i++)
			list.replace
			  (i, QByteArray::fromBase64(list.at(i)));

		      if(list.value(0) == "0002b")
			{
			  saveParticipantStatus
			    (list.value(1)); // Public Key Hash
			  emit retrieveMail
			    (list.value(2),  // Data
			     list.value(1),  // Public Key Hash
			     list.value(3)); // Signature
			}
		      else
			spoton_misc::logError
			  ("spoton_neighbor::process0002b(): "
			   "message type does not match 0002b.");
		    }
		  else
		    spoton_misc::logError
		      (QString("spoton_neighbor::process0002b(): "
			       "received irregular data. "
			       "Expecting 4 "
			       "entries, "
			       "received %1.").arg(list.size()));
		}
	    }
	  else
	    spoton_misc::logError("spoton_neighbor::process0002b(): "
				  "computed message code does "
				  "not match provided code.");
	}
    }
  else
    spoton_misc::logError
      (QString("spoton_neighbor::process0002b(): 0002b "
	       "content-length mismatch (advertised: %1, received: %2) "
	       "for %3:%4.").
       arg(length).arg(data.length()).
       arg(m_address.toString()).
       arg(m_port));
}

void spoton_neighbor::process0011(int length, const QByteArray &dataIn)
{
  int indexOf = dataIn.lastIndexOf("\r\n");

  if(indexOf < 0)
    return;

  length -= qstrlen("type=0011&content=");

  /*
  ** We may have received a name and a public key.
  */

  QByteArray data(dataIn.mid(0, indexOf + 2));

  indexOf = data.indexOf("type=0011&content=");

  if(indexOf < 0)
    return;

  data.remove(0, indexOf + qstrlen("type=0011&content="));

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

      emit resetKeepAlive();
    }
  else
    spoton_misc::logError
      (QString("spoton_neighbor::process0011(): 0011 "
	       "content-length mismatch (advertised: %1, received: %2) "
	       "for %3:%4.").
       arg(length).arg(data.length()).
       arg(m_address.toString()).
       arg(m_port));
}

void spoton_neighbor::process0012(int length, const QByteArray &dataIn)
{
  int indexOf = dataIn.lastIndexOf("\r\n");

  if(indexOf < 0)
    return;

  length -= qstrlen("type=0012&content=");

  /*
  ** We may have received a name and a public key.
  */

  QByteArray data(dataIn.mid(0, indexOf + 2));

  indexOf = data.indexOf("type=0012&content=");

  if(indexOf < 0)
    return;

  data.remove(0, indexOf + qstrlen("type=0012&content="));

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
      emit resetKeepAlive();
    }
  else
    spoton_misc::logError
      (QString("spoton_neighbor::process0012(): 0012 "
	       "content-length mismatch (advertised: %1, received: %2) "
	       "for %3:%4.").
       arg(length).arg(data.length()).
       arg(m_address.toString()).
       arg(m_port));
}

void spoton_neighbor::process0013(int length, const QByteArray &dataIn,
				  const QList<QByteArray> &symmetricKeys)
{
  spoton_crypt *s_crypt = spoton_kernel::s_crypts.value("chat", 0);

  if(!s_crypt)
    return;

  QByteArray data(dataIn);

  if(length == data.length())
    {
      data = QByteArray::fromBase64(data);

      QByteArray originalData(data);
      QList<QByteArray> list(data.split('\n'));
      bool ok = true;

      if(list.size() == 2)
	{
	  /*
	  ** Gemini?
	  */

	  for(int i = 0; i < list.size(); i++)
	    list.replace(i, QByteArray::fromBase64(list.at(i)));

	  QPair<QByteArray, QByteArray> gemini;

	  if(symmetricKeys.value(0).isEmpty() ||
	     symmetricKeys.value(2).isEmpty())
	    gemini = spoton_misc::findGeminiInCosmos
	      (list.value(0), list.value(1), s_crypt);
	  else
	    {
	      gemini.first = symmetricKeys.value(0);
	      gemini.second = symmetricKeys.value(2);
	    }

	  if(!gemini.first.isEmpty() && !gemini.second.isEmpty())
	    {
	      QByteArray computedHash;
	      QByteArray message(list.value(0));
	      spoton_crypt crypt("aes256",
				 "sha512",
				 QByteArray(),
				 gemini.first,
				 0,
				 0,
				 QString(""));

	      computedHash = spoton_crypt::keyedHash
		(message, gemini.second, "sha512", &ok);

	      if(ok)
		{
		  QByteArray messageCode(list.value(1));

		  if(!computedHash.isEmpty() && !messageCode.isEmpty() &&
		     spoton_crypt::memcmp(computedHash, messageCode))
		    {
		      message = crypt.decrypted(message, &ok);

		      if(ok)
			list = message.split('\n');

		      list.removeAt(0); // Message Type

		      if(list.size() != 3)
			{
			  spoton_misc::logError
			    (QString("spoton_neighbor::process0013(): "
				     "received irregular data. "
				     "Expecting 3 "
				     "entries, "
				     "received %1.").arg(list.size()));
			  return;
			}
		    }
		  else
		    {
		      spoton_misc::logError("spoton_neighbor::"
					    "process0013(): "
					    "computed message code does "
					    "not match provided code.");
		      return;
		    }
		}
	    }
	  else
	    ok = false; // A gemini was not discovered. We need to echo.
	}
      else if(list.size() != 3)
	{
	  spoton_misc::logError
	    (QString("spoton_neighbor::process0013(): "
		     "received irregular data. Expecting 3 "
		     "entries, "
		     "received %1.").arg(list.size()));
	  return;
	}

      if(list.size() == 3)
	{
	  for(int i = 0; i < list.size(); i++)
	    list.replace(i, QByteArray::fromBase64(list.at(i)));

	  QByteArray hashKey;
	  QByteArray keyInformation(list.value(0));
	  QByteArray symmetricKey;
	  QByteArray symmetricKeyAlgorithm;

	  keyInformation = s_crypt->
	    publicKeyDecrypt(keyInformation, &ok);

	  if(ok)
	    {
	      QList<QByteArray> list(keyInformation.split('\n'));

	      list.removeAt(0); // Message Type

	      if(list.size() == 3)
		{
		  hashKey = QByteArray::fromBase64(list.value(1));
		  symmetricKey = QByteArray::fromBase64(list.value(0));
		  symmetricKeyAlgorithm = QByteArray::fromBase64
		    (list.value(2));
		}
	      else
		{
		  spoton_misc::logError
		    (QString("spoton_neighbor::process0013(): "
			     "received irregular data. "
			     "Expecting 3 "
			     "entries, "
			     "received %1.").arg(list.size()));
		  return;
		}
	    }

	  if(ok)
	    {
	      QByteArray computedHash;
	      QByteArray data(list.value(1));

	      computedHash = spoton_crypt::keyedHash
		(data, hashKey, "sha512", &ok);

	      if(ok)
		{
		  QByteArray messageCode(list.value(2));

		  if(!computedHash.isEmpty() && !messageCode.isEmpty() &&
		     spoton_crypt::memcmp(computedHash, messageCode))
		    {
		      spoton_crypt crypt(symmetricKeyAlgorithm,
					 "sha512",
					 QByteArray(),
					 symmetricKey,
					 0,
					 0,
					 QString(""));

		      data = crypt.decrypted(data, &ok);

		      if(ok)
			{
			  QList<QByteArray> list(data.split('\n'));

			  if(list.size() == 4)
			    {
			      for(int i = 0; i < list.size(); i++)
				list.replace
				  (i, QByteArray::fromBase64(list.at(i)));

			      if(spoton_misc::
				 isAcceptedParticipant(list.value(0), "chat"))
				{
				  if(spoton_kernel::setting("gui/chatAccept"
							    "SignedMessages"
							    "Only",
							    true).toBool())
				    if(!spoton_misc::
				       isValidSignature(list.value(0) +
							list.value(1) +
							list.value(2),
							list.value(0),
							list.value(3),
							s_crypt))
				      {
					spoton_misc::logError
					  ("spoton_neighbor::"
					   "process0013(): invalid "
					   "signature.");
					return;
				      }

				  saveParticipantStatus
				    (list.value(1),  // Name
				     list.value(0),  // Public Key Hash
				     list.value(2)); // Status
				}
			    }
			  else
			    spoton_misc::logError
			      (QString("spoton_neighbor::process0013(): "
				       "received irregular data. "
				       "Expecting 4 "
				       "entries, "
				       "received %1.").arg(list.size()));
			}
		    }
		  else
		    spoton_misc::logError("spoton_neighbor::process0013(): "
					  "computed message code does "
					  "not match provided code.");
		}
	    }
	}
    }
  else
    spoton_misc::logError
      (QString("spoton_neighbor::process0013(): 0013 "
	       "content-length mismatch (advertised: %1, received: %2) "
	       "for %3:%4.").
       arg(length).arg(data.length()).
       arg(m_address.toString()).
       arg(m_port));
}

void spoton_neighbor::process0014(int length, const QByteArray &dataIn)
{
  if(m_id == -1)
    return;

  int indexOf = dataIn.lastIndexOf("\r\n");

  if(indexOf < 0)
    return;

  length -= qstrlen("type=0014&content=");

  /*
  ** We may have received a status message.
  */

  QByteArray data(dataIn.mid(0, indexOf + 2));

  indexOf = data.indexOf("type=0014&content=");

  if(indexOf < 0)
    return;

  data.remove(0, indexOf + qstrlen("type=0014&content="));

  if(length == data.length())
    {
      data = QByteArray::fromBase64(data);

      QUuid uuid(data.constData());

      m_receivedUuid = uuid;

      if(m_receivedUuid.isNull())
	m_receivedUuid = "{00000000-0000-0000-0000-000000000000}";

      spoton_crypt *s_crypt = spoton_kernel::s_crypts.value("chat", 0);

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
		  (0, s_crypt->encryptedThenHashed(uuid.toString().toLatin1(),
						   &ok).toBase64());
		query.bindValue(1, m_id);

		if(ok)
		  query.exec();
	      }

	    db.close();
	  }

	  QSqlDatabase::removeDatabase(connectionName);
	}

      emit resetKeepAlive();
    }
  else
    spoton_misc::logError
      (QString("spoton_neighbor::process0014(): 0014 "
	       "content-length mismatch (advertised: %1, received: %2) "
	       "for %3:%4.").
       arg(length).arg(data.length()).
       arg(m_address.toString()).
       arg(m_port));
}

void spoton_neighbor::process0030(int length, const QByteArray &dataIn)
{
  spoton_crypt *s_crypt = spoton_kernel::s_crypts.value("chat", 0);

  if(!s_crypt)
    return;

  int indexOf = dataIn.lastIndexOf("\r\n");

  if(indexOf < 0)
    return;

  length -= qstrlen("type=0030&content=");

  /*
  ** We may have received a listener's information.
  */

  QByteArray data(dataIn.mid(0, indexOf + 2));

  indexOf = data.indexOf("type=0030&content=");

  if(indexOf < 0)
    return;

  data.remove(0, indexOf + qstrlen("type=0030&content="));

  if(length == data.length())
    {
      data = QByteArray::fromBase64(data);

      QByteArray originalData(data);
      QList<QByteArray> list(data.split('\n'));

      for(int i = 0; i < list.size(); i++)
	list.replace(i, QByteArray::fromBase64(list.at(i)));

      if(list.size() != 5)
	{
	  spoton_misc::logError
	    (QString("spoton_neighbor::process0030(): "
		     "received irregular data. Expecting 5 "
		     "entries, "
		     "received %1.").arg(list.size()));
	  return;
	}
      else
	{
	  QString statusControl
	    (spoton_kernel::setting("gui/acceptPublicizedListeners",
				    "ignored").toString().
	     toLower().trimmed());

	  if(statusControl == "connected" || statusControl == "disconnected")
	    {
	      QHostAddress address;

	      address.setAddress(list.value(0).constData());
	      address.setScopeId(list.value(2).constData());

	      if(!spoton_misc::isPrivateNetwork(address))
		{
		  QString orientation(list.value(4).constData());
		  QString transport(list.value(3).constData());
		  quint16 port = list.value(1).toUShort(); /*
							   ** toUShort()
							   ** returns zero
							   ** on failure.
							   */

		  spoton_misc::savePublishedNeighbor
		    (address, port, transport, statusControl, orientation,
		     s_crypt);
		}
	    }
	}

      emit resetKeepAlive();
      spoton_kernel::messagingCacheAdd(dataIn);
      emit publicizeListenerPlaintext(originalData, m_id);
    }
  else
    spoton_misc::logError
      (QString("spoton_neighbor::process0030(): 0030 "
	       "content-length mismatch (advertised: %1, received: %2) "
	       "for %3:%4.").
       arg(length).arg(data.length()).
       arg(m_address.toString()).
       arg(m_port));
}

void spoton_neighbor::process0040a(int length, const QByteArray &dataIn,
				   const QList<QByteArray> &symmetricKeys)
{
  spoton_crypt *s_crypt = spoton_kernel::s_crypts.value("chat", 0);

  if(!s_crypt)
    return;

  QByteArray data(dataIn);

  if(length == data.length())
    {
      data = QByteArray::fromBase64(data);

      QByteArray originalData(data);
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

      /*
      ** symmetricKeys[0]: Encryption Key
      ** symmetricKeys[1]: Encryption Type
      ** symmetricKeys[2]: Hash Key
      ** symmetricKeys[3]: Hash Type
      */

      QByteArray computedHash;
      bool ok = true;

      computedHash = spoton_crypt::keyedHash
	(list.value(0), symmetricKeys.value(2), symmetricKeys.value(3), &ok);

      if(ok)
	{
	  QByteArray messageCode(list.value(1));

	  if(!computedHash.isEmpty() && !messageCode.isEmpty() &&
	     spoton_crypt::memcmp(computedHash, messageCode))
	    {
	      QByteArray data(list.value(0));
	      bool ok = true;
	      spoton_crypt crypt(symmetricKeys.value(1),
				 "sha512",
				 QByteArray(),
				 symmetricKeys.value(0),
				 0,
				 0,
				 QString(""));

	      data = crypt.decrypted(data, &ok);

	      if(ok)
		{
		  list.replace(0, data);
		  emit receivedBuzzMessage(list, symmetricKeys);
		}
	    }
	  else
	    spoton_misc::logError("spoton_neighbor::"
				  "process0040a(): "
				  "computed message code does "
				  "not match provided code.");
	}
    }
  else
    spoton_misc::logError
      (QString("spoton_neighbor::process0040a(): 0040a "
	       "content-length mismatch (advertised: %1, received: %2) "
	       "for %3:%4.").
       arg(length).arg(data.length()).
       arg(m_address.toString()).
       arg(m_port));
}

void spoton_neighbor::process0040b(int length, const QByteArray &dataIn,
				   const QList<QByteArray> &symmetricKeys)
{
  spoton_crypt *s_crypt = spoton_kernel::s_crypts.value("chat", 0);

  if(!s_crypt)
    return;

  QByteArray data(dataIn);

  if(length == data.length())
    {
      data = QByteArray::fromBase64(data);

      QByteArray originalData(data);
      QList<QByteArray> list(data.split('\n'));

      for(int i = 0; i < list.size(); i++)
	list.replace(i, QByteArray::fromBase64(list.at(i)));

      if(list.size() != 2)
	{
	  spoton_misc::logError
	    (QString("spoton_neighbor::process0040b(): "
		     "received irregular data. Expecting 2 "
		     "entries, "
		     "received %1.").arg(list.size()));
	  return;
	}

      /*
      ** symmetricKeys[0]: Encryption Key
      ** symmetricKeys[1]: Encryption Type
      ** symmetricKeys[2]: Hash Key
      ** symmetricKeys[3]: Hash Type
      */

      QByteArray computedHash;
      bool ok = true;

      computedHash = spoton_crypt::keyedHash
	(list.value(0), symmetricKeys.value(2), symmetricKeys.value(3), &ok);

      if(ok)
	{
	  QByteArray messageCode(list.value(1));

	  if(!computedHash.isEmpty() && !messageCode.isEmpty() &&
	     spoton_crypt::memcmp(computedHash, messageCode))
	    {
	      QByteArray data(list.value(0));
	      bool ok = true;
	      spoton_crypt crypt(symmetricKeys.value(1),
				 "sha512",
				 QByteArray(),
				 symmetricKeys.value(0),
				 0,
				 0,
				 QString(""));

	      data = crypt.decrypted(data, &ok);

	      if(ok)
		{
		  list.replace(0, data);
		  emit receivedBuzzMessage(list, symmetricKeys);
		}
	    }
	  else
	    spoton_misc::logError("spoton_neighbor::"
				  "process0040b(): "
				  "computed message code does "
				  "not match provided code.");
	}
    }
  else
    spoton_misc::logError
      (QString("spoton_neighbor::process0040b(): 0040b "
	       "content-length mismatch (advertised: %1, received: %2) "
	       "for %3:%4.").
       arg(length).arg(data.length()).
       arg(m_address.toString()).
       arg(m_port));
}

void spoton_neighbor::process0050(int length, const QByteArray &dataIn)
{
  int indexOf = dataIn.lastIndexOf("\r\n");

  if(indexOf < 0)
    return;

  length -= qstrlen("type=0050&content=");

  /*
  ** We may have received a name and a password from the client.
  */

  QByteArray data(dataIn.mid(0, indexOf + 2));

  indexOf = data.indexOf("type=0050&content=");

  if(indexOf < 0)
    return;

  data.remove(0, indexOf + qstrlen("type=0050&content="));

  if(length == data.length())
    {
      data = QByteArray::fromBase64(data);

      QList<QByteArray> list(data.split('\n'));

      if(list.size() != 2)
	{
	  spoton_misc::logError
	    (QString("spoton_neighbor::process0050(): "
		     "received irregular data. Expecting 2 entries, "
		     "received %1.").arg(list.size()));
	  return;
	}

      for(int i = 0; i < list.size(); i++)
	list.replace(i, QByteArray::fromBase64(list.at(i)));

      QByteArray name;
      QByteArray password;

      if(spoton_misc::authenticateAccount(name,
					  password,
					  m_listenerOid,
					  list.at(0),
					  list.at(1),
					  spoton_kernel::
					  s_crypts.value("chat", 0)))
	{
	  m_accountAuthenticated = true;
	  m_accountTimer.stop();
	  m_authenticationTimer.stop();
	  emit accountAuthenticated(name, password);
	}
      else
	{
	  m_accountAuthenticated = false;
	  emit accountAuthenticated(spoton_crypt::weakRandomBytes(64),
				    spoton_crypt::weakRandomBytes(64));
	}

      if(m_accountAuthenticated)
	emit resetKeepAlive();

      spoton_crypt *s_crypt = spoton_kernel::s_crypts.value("chat", 0);

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

		query.prepare("UPDATE neighbors SET "
			      "account_authenticated = ?, "
			      "account_name = ? "
			      "WHERE OID = ? AND "
			      "user_defined = 0");
		query.bindValue
		  (0,
		   m_accountAuthenticated ?
		   s_crypt->encryptedThenHashed(QByteArray::number(1),
						&ok).toBase64() :
		   s_crypt->encryptedThenHashed(QByteArray::number(0),
						&ok).toBase64());

		if(ok)
		  query.bindValue
		    (1, s_crypt->encryptedThenHashed(name, &ok).toBase64());

		query.bindValue(2, m_id);

		if(ok)
		  query.exec();
	      }

	    db.close();
	  }

	  QSqlDatabase::removeDatabase(connectionName);
	}
    }
  else
    spoton_misc::logError
      (QString("spoton_neighbor::process0050(): 0050 "
	       "content-length mismatch (advertised: %1, received: %2) "
	       "for %3:%4.").
       arg(length).arg(data.length()).
       arg(m_address.toString()).
       arg(m_port));
}

void spoton_neighbor::process0051(int length, const QByteArray &dataIn)
{
  int indexOf = dataIn.lastIndexOf("\r\n");

  if(indexOf < 0)
    return;

  length -= qstrlen("type=0051&content=");

  /*
  ** We may have received a name and a password from the server.
  */

  QByteArray data(dataIn.mid(0, indexOf + 2));

  indexOf = data.indexOf("type=0051&content=");

  if(indexOf < 0)
    return;

  data.remove(0, indexOf + qstrlen("type=0051&content="));

  if(length == data.length())
    {
      data = QByteArray::fromBase64(data);

      QList<QByteArray> list(data.split('\n'));

      if(list.size() != 2)
	{
	  spoton_misc::logError
	    (QString("spoton_neighbor::process0051(): "
		     "received irregular data. Expecting 2 entries, "
		     "received %1.").arg(list.size()));
	  return;
	}

      for(int i = 0; i < list.size(); i++)
	list.replace(i, QByteArray::fromBase64(list.at(i)));

      spoton_crypt *s_crypt = spoton_kernel::s_crypts.value("chat", 0);

      if(!list.at(1).isEmpty() && !m_accountClientSentSalt.isEmpty() &&
	 !spoton_crypt::memcmp(list.at(1), m_accountClientSentSalt))
	{
	  if(s_crypt)
	    {
	      QByteArray name(m_accountName);
	      QByteArray password(m_accountPassword);
	      QByteArray newSaltedCredentials;
	      QByteArray salt(list.at(1));
	      QByteArray saltedCredentials(list.at(0));
	      bool ok = true;

	      name = s_crypt->decryptedAfterAuthenticated(name, &ok);

	      if(ok)
		password = s_crypt->decryptedAfterAuthenticated
		  (password, &ok);

	      if(ok)
		newSaltedCredentials = spoton_crypt::saltedValue
		  ("sha512", name + password +
		   QDateTime::currentDateTime().toUTC().
		   toString("MMddyyyyhhmm").toLatin1(), salt, &ok);

	      if(ok)
		{
		  if(!newSaltedCredentials.isEmpty() &&
		     !saltedCredentials.isEmpty() &&
		     spoton_crypt::memcmp(newSaltedCredentials,
					  saltedCredentials))
		    {
		      m_accountAuthenticated = true;
		      m_accountTimer.stop();
		      m_authenticationTimer.stop();
		    }
		  else
		    {
		      newSaltedCredentials = spoton_crypt::saltedValue
			("sha512",
			 name + password +
			 QDateTime::currentDateTime().toUTC().addSecs(60).
			 toString("MMddyyyyhhmm").toLatin1(), salt, &ok);

		      if(ok)
			{
			  if(!newSaltedCredentials.isEmpty() &&
			     !saltedCredentials.isEmpty() &&
			     spoton_crypt::memcmp(newSaltedCredentials,
						  saltedCredentials))
			    {
			      m_accountAuthenticated = true;
			      m_accountTimer.stop();
			      m_authenticationTimer.stop();
			    }
			}
		      else
			m_accountAuthenticated = false;
		    }
		}
	      else
		m_accountAuthenticated = false;
	    }
	  else
	    m_accountAuthenticated = false;
	}
      else
	{
	  m_accountAuthenticated = false;

	  if(m_accountClientSentSalt.isEmpty())
	    spoton_misc::logError
	      ("spoton_neighbor::process0051(): "
	       "the server replied to an authentication message, however, "
	       "my provided salt is empty.");
	  else if(spoton_crypt::memcmp(list.at(1), m_accountClientSentSalt))
	    spoton_misc::logError
	      ("spoton_neighbor::process0051(): "
	       "the provided salt is identical to the generated salt. "
	       "The server may be devious.");
	}

      m_accountClientSentSalt.clear();

      if(m_accountAuthenticated)
	emit resetKeepAlive();

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

		query.prepare("UPDATE neighbors SET "
			      "account_authenticated = ? "
			      "WHERE OID = ? AND "
			      "user_defined = 1");
		query.bindValue
		  (0,
		   m_accountAuthenticated ?
		   s_crypt->encryptedThenHashed(QByteArray::number(1),
						&ok).toBase64() :
		   s_crypt->encryptedThenHashed(QByteArray::number(0),
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
  else
    spoton_misc::logError
      (QString("spoton_neighbor::process0051(): 0051 "
	       "content-length mismatch (advertised: %1, received: %2) "
	       "for %3:%4.").
       arg(length).arg(data.length()).
       arg(m_address.toString()).
       arg(m_port));
}

void spoton_neighbor::process0065(int length, const QByteArray &dataIn)
{
  spoton_crypt *s_crypt = spoton_kernel::s_crypts.value("chat", 0);

  if(!s_crypt)
    return;

  /*
  ** Shared Buzz Magnet?
  */

  int indexOf = dataIn.lastIndexOf("\r\n");

  if(indexOf < 0)
    return;

  length -= qstrlen("type=0065&content=");

  QByteArray data(dataIn.mid(0, indexOf + 2));

  indexOf = data.indexOf("type=0065&content=");

  if(indexOf < 0)
    return;

  data.remove(0, indexOf + qstrlen("type=0065&content="));

  if(length == data.length())
    {
      data = QByteArray::fromBase64(data);

      if(spoton_kernel::setting("gui/acceptBuzzMagnets", false).toBool())
	if(spoton_misc::isValidBuzzMagnetData(data))
	  {
	    QString connectionName("");

	    {
	      QSqlDatabase db = spoton_misc::database(connectionName);

	      db.setDatabaseName
		(spoton_misc::homePath() + QDir::separator() +
		 "buzz_channels.db");

	      if(db.open())
		{
		  QSqlQuery query(db);
		  bool ok = true;

		  query.prepare("INSERT OR REPLACE INTO buzz_channels "
				"(data, data_hash) "
				"VALUES (?, ?)");
		  query.bindValue
		    (0, s_crypt->encryptedThenHashed(data, &ok).toBase64());

		  if(ok)
		    query.bindValue
		      (1, s_crypt->keyedHash(data, &ok).toBase64());

		  if(ok)
		    query.exec();
		}

	      db.close();
	    }

	    QSqlDatabase::removeDatabase(connectionName);
	  }

      emit resetKeepAlive();
    }
  else
    spoton_misc::logError
      (QString("spoton_neighbor::process0065(): 0065 "
	       "content-length mismatch (advertised: %1, received: %2) "
	       "for %3:%4.").
       arg(length).arg(data.length()).
       arg(m_address.toString()).
       arg(m_port));
}

void spoton_neighbor::slotSendStatus(const QByteArrayList &list)
{
  if(readyToWrite())
    for(int i = 0; i < list.size(); i++)
      {
	QByteArray message(spoton_send::message0013(list.at(i)));

	if(write(message.constData(), message.length()) != message.length())
	  spoton_misc::logError
	    (QString("spoton_neighbor::slotSendStatus(): write() "
		     "error for %1:%2.").
	     arg(m_address.toString()).
	     arg(m_port));
	else
	  {
	    addToBytesWritten(message.length());
	    spoton_kernel::messagingCacheAdd(message);
	  }
      }
}

void spoton_neighbor::saveParticipantStatus(const QByteArray &publicKeyHash)
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
	query.prepare("UPDATE friends_public_keys SET "
		      "last_status_update = ? "
		      "WHERE neighbor_oid = -1 AND "
		      "public_key_hash = ?");
	query.bindValue
	  (0, QDateTime::currentDateTime().toString(Qt::ISODate));
	query.bindValue(1, publicKeyHash.toBase64());
     	query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
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
	    if(name.isEmpty())
	      {
		query.prepare("UPDATE friends_public_keys SET "
			      "last_status_update = ? "
			      "WHERE neighbor_oid = -1 AND "
			      "public_key_hash = ?");
		query.bindValue
		  (0, QDateTime::currentDateTime().toString(Qt::ISODate));
		query.bindValue(1, publicKeyHash.toBase64());
	      }
	    else
	      {
		query.prepare("UPDATE friends_public_keys SET "
			      "last_status_update = ? "
			      "WHERE neighbor_oid = -1 AND "
			      "public_key_hash = ?");
		query.bindValue
		  (0, QDateTime::currentDateTime().toString(Qt::ISODate));
		query.bindValue(1, publicKeyHash.toBase64());
		query.exec();
		query.prepare("UPDATE friends_public_keys SET "
			      "name = ? "
			      "WHERE name_changed_by_user = 0 AND "
			      "neighbor_oid = -1 AND "
			      "public_key_hash = ?");
		query.bindValue
		  (0,
		   name.mid(0, spoton_common::NAME_MAXIMUM_LENGTH).trimmed());
		query.bindValue(1, publicKeyHash.toBase64());
		query.exec();
	      }
	  }
	else
	  {
	    if(name.isEmpty())
	      {
		query.prepare("UPDATE friends_public_keys SET "
			      "status = ?, "
			      "last_status_update = ? "
			      "WHERE neighbor_oid = -1 AND "
			      "public_key_hash = ?");

		if(status == "away" || status == "busy" ||
		   status == "offline" || status == "online")
		  query.bindValue(0, status);
		else
		  query.bindValue(0, "offline");

		query.bindValue
		  (1, QDateTime::currentDateTime().toString(Qt::ISODate));
		query.bindValue(2, publicKeyHash.toBase64());
	      }
	    else
	      {
		QDateTime now(QDateTime::currentDateTime());

		query.prepare("UPDATE friends_public_keys SET "
			      "name = ?, "
			      "status = ?, "
			      "last_status_update = ? "
			      "WHERE name_changed_by_user = 0 AND "
			      "neighbor_oid = -1 AND "
			      "public_key_hash = ?");
		query.bindValue
		  (0,
		   name.mid(0, spoton_common::NAME_MAXIMUM_LENGTH).trimmed());

		if(status == "away" || status == "busy" ||
		   status == "offline" || status == "online")
		  query.bindValue(1, status);
		else
		  query.bindValue(1, "offline");

		query.bindValue
		  (2, now.toString(Qt::ISODate));
		query.bindValue(3, publicKeyHash.toBase64());
		query.exec();
		query.prepare("UPDATE friends_public_keys SET "
			      "status = ?, "
			      "last_status_update = ? "
			      "WHERE neighbor_oid = -1 AND "
			      "public_key_hash = ?");

		if(status == "away" || status == "busy" ||
		   status == "offline" || status == "online")
		  query.bindValue(0, status);
		else
		  query.bindValue(0, "offline");

		query.bindValue
		  (1, now.toString(Qt::ISODate));
		query.bindValue(2, publicKeyHash.toBase64());
		query.exec();
	      }
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

      if(!m_requireSsl)
	{
	  m_useSsl = false;

	  if(m_tcpSocket)
	    spoton_misc::logError
	      (QString("spoton_neighbor::slotError(): socket error "
		       "(%1) for "
		       "%2:%3. "
		       "Disabling SSL.").arg(m_tcpSocket->errorString()).
	       arg(m_address.toString()).arg(m_port));

	  return;
	}
    }

  if(m_tcpSocket)
    spoton_misc::logError
      (QString("spoton_neighbor::slotError(): "
	       "socket error (%1) for %2:%3. "
	       "Aborting socket.").arg(m_tcpSocket->errorString()).
       arg(m_address.toString()).
       arg(m_port));
  else if(m_udpSocket)
    spoton_misc::logError
      (QString("spoton_neighbor::slotError(): "
	       "socket error (%1) for %2:%3. "
	       "Aborting socket.").arg(m_udpSocket->errorString()).
       arg(m_address.toString()).
       arg(m_port));

  deleteLater();
}

void spoton_neighbor::slotError(const QString &method,
				const spoton_sctp_socket::SocketError error)
{
  spoton_misc::logError
    (QString("spoton_neighbor::slotError(): "
	     "socket error (%1:%2) for %3:%4. "
	     "Aborting socket.").
     arg(method).
     arg(error).
     arg(m_address.toString()).
     arg(m_port));
  deleteLater();
}

void spoton_neighbor::slotSendUuid(void)
{
  if(!readyToWrite())
    return;

  QByteArray message;
  QUuid uuid(spoton_kernel::
	     setting("gui/uuid",
		     "{00000000-0000-0000-0000-000000000000}").toString());

  message = spoton_send::message0014(uuid.toString().toLatin1());

  if(write(message.constData(), message.length()) != message.length())
    spoton_misc::logError
      (QString("spoton_neighbor::slotSendUuid(): write() error for %1:%2.").
       arg(m_address.toString()).
       arg(m_port));
  else
    addToBytesWritten(message.length());
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
	  spoton_crypt *s_crypt =
	    spoton_kernel::s_crypts.value("chat", 0);

	  if(s_crypt)
	    {
	      query.prepare("UPDATE neighbors SET external_ip_address = ? "
			    "WHERE OID = ?");
	      query.bindValue
		(0, s_crypt->encryptedThenHashed(address.toString().
						 toLatin1(), &ok).
		 toBase64());
	      query.bindValue(1, m_id);
	    }
	  else
	    ok = false;
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
  if(m_externalAddress)
    if(state() == QAbstractSocket::ConnectedState)
      m_externalAddress->discover();
}

QUuid spoton_neighbor::receivedUuid(void) const
{
  return m_receivedUuid;
}

void spoton_neighbor::slotSendMail
(const QPairListByteArrayQInt64 &list, const QString &messageType)
{
  QList<qint64> oids;

  if(readyToWrite())
    for(int i = 0; i < list.size(); i++)
      {
	QByteArray message;
	QPair<QByteArray, qint64> pair(list.at(i));

	if(messageType == "0001a")
	  message = spoton_send::message0001a(pair.first);
	else
	  message = spoton_send::message0001b(pair.first);

	if(write(message.constData(), message.length()) != message.length())
	  spoton_misc::logError
	    (QString("spoton_neighbor::slotSendMail(): write() "
		     "error for %1:%2.").
	     arg(m_address.toString()).
	     arg(m_port));
	else
	  {
	    addToBytesWritten(message.length());
	    oids.append(pair.second);
	    spoton_kernel::messagingCacheAdd(message);
	  }
      }

  if(!oids.isEmpty())
    {
      spoton_crypt *s_crypt = spoton_kernel::s_crypts.value("email", 0);

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
	  (QString("spoton_neighbor::slotSendMailFromPostOffice(): write() "
		   "error for %1:%2.").
	   arg(m_address.toString()).
	   arg(m_port));
      else
	{
	  addToBytesWritten(message.length());
	  spoton_kernel::messagingCacheAdd(data);
	}
    }
}

void spoton_neighbor::storeLetter(const QByteArray &symmetricKey,
				  const QByteArray &symmetricKeyAlgorithm,
				  const QByteArray &senderPublicKeyHash,
				  const QByteArray &name,
				  const QByteArray &subject,
				  const QByteArray &message,
				  const QByteArray &signature,
				  const bool goldbugUsed)
{
  QFileInfo fileInfo(spoton_misc::homePath() + QDir::separator() +
		     "email.db");
  qint64 maximumSize = 1048576 * spoton_kernel::setting
    ("gui/maximumEmailFileSize", 100).toLongLong();

  if(fileInfo.size() >= maximumSize)
    {
      spoton_misc::logError("spoton_neighbor::storeLetter(): "
			    "email.db has exceeded the specified limit.");
      return;
    }

  Q_UNUSED(symmetricKey);
  Q_UNUSED(symmetricKeyAlgorithm);

  spoton_crypt *s_crypt = spoton_kernel::s_crypts.value("email", 0);

  if(!s_crypt)
    return;

  if(spoton_kernel::setting("gui/emailAcceptSignedMessagesOnly",
			    true).toBool())
    if(!spoton_misc::
       isValidSignature(senderPublicKeyHash +
			name +
			subject +
			message,
			senderPublicKeyHash,
			signature, s_crypt))
      {
	spoton_misc::logError
	  ("spoton_neighbor::storeLetter: invalid signature.");
	return;
      }

  /*
  ** We need to remember that the information here may have been
  ** encoded with a goldbug. The interface will prompt the user
  ** for the symmetric key.
  */

  if(!spoton_misc::isAcceptedParticipant(senderPublicKeyHash, "email"))
    return;

  if(goldbugUsed)
    saveParticipantStatus(senderPublicKeyHash);
  else
    saveParticipantStatus(name, senderPublicKeyHash);

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "email.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	query.prepare("INSERT INTO folders "
		      "(date, folder_index, goldbug, hash, "
		      "message, message_code, "
		      "receiver_sender, receiver_sender_hash, "
		      "status, subject, participant_oid) "
		      "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
	query.bindValue
	  (0, s_crypt->
	   encryptedThenHashed(QDateTime::currentDateTime().
			       toString(Qt::ISODate).
			       toLatin1(), &ok).toBase64());
	query.bindValue(1, 0); // Inbox Folder

	if(ok)
	  query.bindValue
	    (2, s_crypt->
	     encryptedThenHashed(QByteArray::number(goldbugUsed), &ok).
	     toBase64());

	if(ok)
	  query.bindValue
	    (3, s_crypt->keyedHash(message.trimmed() + subject.trimmed(),
				   &ok).toBase64());

	if(!message.trimmed().isEmpty())
	  if(ok)
	    query.bindValue
	      (4, s_crypt->encryptedThenHashed(message.trimmed(),
					       &ok).toBase64());

	if(ok)
	  query.bindValue
	    (5, s_crypt->encryptedThenHashed(QByteArray(), &ok).toBase64());

	if(!name.trimmed().isEmpty())
	  if(ok)
	    query.bindValue
	      (6, s_crypt->encryptedThenHashed(name.trimmed(),
					       &ok).toBase64());

	if(ok)
	  query.bindValue
	    (7, senderPublicKeyHash.toBase64());

	if(ok)
	  query.bindValue
	    (8, s_crypt->
	     encryptedThenHashed(tr("Unread").toUtf8(), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (9, s_crypt->encryptedThenHashed(subject, &ok).toBase64());

	if(ok)
	  query.bindValue
	    (10, s_crypt->
	     encryptedThenHashed(QByteArray::number(-1), &ok).
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
  QFileInfo fileInfo(spoton_misc::homePath() + QDir::separator() +
		     "email.db");
  qint64 maximumSize = 1048576 * spoton_kernel::setting
    ("gui/maximumEmailFileSize", 100).toLongLong();

  if(fileInfo.size() >= maximumSize)
    {
      spoton_misc::logError("spoton_neighbor::storeLetter(): "
			    "email.db has exceeded the specified limit.");
      return;
    }

  spoton_crypt *s_crypt = spoton_kernel::s_crypts.value("email", 0);

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
	   encryptedThenHashed(QDateTime::currentDateTime().
			       toString(Qt::ISODate).
			       toLatin1(), &ok).toBase64());

	if(ok)
	  {
	    QByteArray data;

	    data =
	      list.value(0).toBase64() + "\n" + // Symmetric Key Bundle
	      list.value(1).toBase64() + "\n" + // Data
	      list.value(2).toBase64();         // Message Code
	    query.bindValue
	      (1, s_crypt->encryptedThenHashed(data, &ok).toBase64());

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

void spoton_neighbor::slotRetrieveMail(const QByteArrayList &list,
				       const QString &messageType)
{
  if(readyToWrite())
    for(int i = 0; i < list.size(); i++)
      {
	QByteArray message;

	if(messageType == "0002a")
	  message = spoton_send::message0002a(list.at(i));
	else
	  message = spoton_send::message0002b(list.at(i));

	if(write(message.constData(), message.length()) != message.length())
	  spoton_misc::logError
	    (QString("spoton_neighbor::slotRetrieveMail(): write() "
		     "error for %1:%2.").
	     arg(m_address.toString()).
	     arg(m_port));
	else
	  {
	    addToBytesWritten(message.length());
	    spoton_kernel::messagingCacheAdd(message);
	  }
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
(const QHostAddress &address, const quint16 port, const QString &transport,
 const QString &orientation)
{
  if(!address.isNull())
    if(readyToWrite())
      {
	QByteArray message
	  (spoton_send::message0030(address, port, transport, orientation));

	if(write(message.constData(), message.length()) !=
	   message.length())
	  spoton_misc::logError
	    (QString("spoton_neighbor::slotPublicizeListenerPlaintext(): "
		     "write() "
		     "error for %1:%2.").
	     arg(m_address.toString()).
	     arg(m_port));
	else
	  {
	    addToBytesWritten(message.length());
	    spoton_kernel::messagingCacheAdd(message);
	  }
      }
}

void spoton_neighbor::slotPublicizeListenerPlaintext(const QByteArray &data,
						     const qint64 id)
{
  /*
  ** A neighbor (id) received a request to publish listener information.
  ** This neighbor now needs to send the message to its peer.
  */

  if(id != m_id)
    if(m_echoMode == "full" ||
       spoton_kernel::setting("gui/superEcho", false).toBool())
      if(readyToWrite())
	{
	  QByteArray message(spoton_send::message0030(data));

	  if(write(message.constData(), message.length()) != message.length())
	    spoton_misc::logError
	      (QString("spoton_neighbor::slotPublicizeListenerPlaintext(): "
		       "write() "
		       "error for %1:%2.").
	       arg(m_address.toString()).
	       arg(m_port));
	  else
	    {
	      addToBytesWritten(message.length());
	      spoton_kernel::messagingCacheAdd(message);
	    }
	}
}

void spoton_neighbor::slotSslErrors(const QList<QSslError> &errors)
{
  for(int i = 0; i < errors.size(); i++)
    spoton_misc::logError(QString("spoton_neighbor::slotSslErrors(): "
				  "error (%1) occurred from %2:%3.").
			  arg(errors.at(i).errorString()).
			  arg(m_address.toString()).
			  arg(m_port));
}

void spoton_neighbor::slotPeerVerifyError(const QSslError &error)
{
  /*
  ** This method may be called several times!
  */

  bool shouldDelete = true;

  if(error.error() == QSslError::CertificateUntrusted ||
     error.error() == QSslError::HostNameMismatch ||
     error.error() == QSslError::SelfSignedCertificate)
    shouldDelete = false;

  if(shouldDelete)
    {
      spoton_misc::logError
	(QString("spoton_neighbor::slotPeerVerifyError(): instructed "
		 "to delete neighbor for %1:%2.").
	 arg(m_address.toString()).
	 arg(m_port));
      deleteLater();
      return;
    }

  if(m_tcpSocket)
    if(m_isUserDefined)
      if(!m_peerCertificate.isNull() &&
	 !m_tcpSocket->peerCertificate().isNull())
	if(!m_allowExceptions)
	  if(!spoton_crypt::memcmp(m_peerCertificate.toPem(),
				   m_tcpSocket->peerCertificate().toPem()))
	    /*
	    ** Do we really need to verify that m_peerCertificate.toPem()
	    ** is empty? What if m_tcpSocket->peerCertificate().toPem() is
	    ** empty? We do verify that both m_peerCertificate and
	    ** m_tcpSocket->peerCertificate() are not void.
	    */
	    {
	      spoton_misc::logError
		(QString("spoton_neighbor::slotPeerVerifyError(): "
			 "the stored certificate does not match "
			 "the peer's certificate for %1:%2. This is a "
			 "serious problem! Aborting.").
		 arg(m_address.toString()).
		 arg(m_port));
	      deleteLater();
	    }
}

void spoton_neighbor::slotModeChanged(QSslSocket::SslMode mode)
{
  spoton_misc::logError
    (QString("spoton_neighbor::slotModeChanged(): "
	     "the connection mode has changed to %1 for %2:%3.").
     arg(mode).
     arg(m_address.toString()).
     arg(m_port));

  if(m_useSsl)
    {
      if(mode == QSslSocket::UnencryptedMode)
	{
	  spoton_misc::logError
	    (QString("spoton_neighbor::slotModeChanged(): "
		     "unencrypted connection mode for %1:%2. Aborting.").
	     arg(m_address.toString()).
	     arg(m_port));
	  deleteLater();
	  return;
	}

      if(m_useAccounts)
	{
	  m_accountTimer.start();
	  m_authenticationTimer.start();
	}
    }
}

void spoton_neighbor::slotDisconnected(void)
{
  if(m_tcpSocket)
    if(m_isUserDefined)
      if(!m_useSsl)
	{
	  int attempts = property("connection-attempts").toInt();

	  if(attempts < 5)
	    {
	      attempts += 1;
	      setProperty("connection-attempts", attempts);
	      spoton_misc::logError
		(QString("spoton_neighbor::slotDisconnected(): "
			 "retrying %1 of %2 for %3:%4.").arg(attempts).arg(5).
		 arg(m_address.toString()).
		 arg(m_port));
	      return;
	    }
	}

  spoton_misc::logError
    (QString("spoton_neighbor::slotDisconnected(): "
	     "aborting socket for %1:%2!").
     arg(m_address.toString()).
     arg(m_port));
  deleteLater();
}

void spoton_neighbor::slotEncrypted(void)
{
  recordCertificateOrAbort();
}

void spoton_neighbor::recordCertificateOrAbort(void)
{
  QSslCertificate certificate;
  bool save = false;

  if(m_isUserDefined)
    {
      if(m_tcpSocket)
	{
	  if(m_peerCertificate.isNull() &&
	     !m_tcpSocket->peerCertificate().isNull())
	    {
	      certificate = m_peerCertificate = m_tcpSocket->peerCertificate();
	      save = true;
	    }
	  else if(!m_allowExceptions)
	    {
	      if(m_tcpSocket->peerCertificate().isNull())
		{
		  spoton_misc::logError
		    (QString("spoton_neighbor::recordCertificateOrAbort(): "
			     "null peer certificate for %1:%2. Aborting.").
		     arg(m_address.toString()).
		     arg(m_port));
		  deleteLater();
		  return;
		}
	      else if(!spoton_crypt::
		      memcmp(m_peerCertificate.toPem(),
			     m_tcpSocket->peerCertificate().toPem()))
		{
		  spoton_misc::logError
		    (QString("spoton_neighbor::recordCertificateOrAbort(): "
			     "the stored certificate does not match "
			     "the peer's certificate for %1:%2. This is a "
			     "serious problem! Aborting.").
		     arg(m_address.toString()).
		     arg(m_port));
		  deleteLater();
		  return;
		}
	    }
	}
    }
  else
    {
      if(m_tcpSocket)
	certificate = m_tcpSocket->sslConfiguration().localCertificate();

      save = true;
    }

  if(!save)
    return;

  spoton_crypt *s_crypt = spoton_kernel::s_crypts.value("chat", 0);

  if(!s_crypt)
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "neighbors.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	query.prepare
	  ("UPDATE neighbors SET certificate = ? WHERE OID = ?");
	query.bindValue
	  (0, s_crypt->encryptedThenHashed(certificate.toPem(),
					   &ok).toBase64());
	query.bindValue(1, m_id);

	if(ok)
	  query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_neighbor::slotProxyAuthenticationRequired
(const QNetworkProxy &proxy,
 QAuthenticator *authenticator)
{
  Q_UNUSED(proxy);

  if(authenticator)
    {
      if(m_tcpSocket)
	{
	  authenticator->setPassword(m_tcpSocket->proxy().password());
	  authenticator->setUser(m_tcpSocket->proxy().user());
	}
      else if(m_udpSocket)
	{
	  authenticator->setPassword(m_udpSocket->proxy().password());
	  authenticator->setUser(m_udpSocket->proxy().user());
	}
    }
}

bool spoton_neighbor::readyToWrite(void) const
{
  if(state() != QAbstractSocket::ConnectedState)
    return false;
  else if(isEncrypted() && m_useSsl)
    {
      if(m_useAccounts)
	return m_accountAuthenticated;
      else
	return true;
    }
  else if(!isEncrypted() && !m_useSsl)
    {
      if(m_useAccounts)
	return m_accountAuthenticated;
      else
	return true;
    }
  else
    return false;
}

void spoton_neighbor::slotSendBuzz(const QByteArray &data)
{
  if(readyToWrite())
    {
      if(write(data.constData(), data.length()) != data.length())
	spoton_misc::logError
	  (QString("spoton_neighbor::slotSendBuzz(): write() error for "
		   "%1:%2.").
	   arg(m_address.toString()).
	   arg(m_port));
      else
	{
	  addToBytesWritten(data.length());
	  spoton_kernel::messagingCacheAdd(data);
	}
    }
}

void spoton_neighbor::slotResetKeepAlive(void)
{
  m_lastReadTime = QDateTime::currentDateTime();
}

QString spoton_neighbor::findMessageType
(const QByteArray &data, QList<QByteArray> &symmetricKeys)
{
  QList<QByteArray> list(QByteArray::fromBase64(data).split('\n'));
  QString type("");
  int interfaces = spoton_kernel::interfaces();
  spoton_crypt *s_crypt = spoton_kernel::s_crypts.value("chat", 0);

  /*
  ** list[0]: Data
  ** ...
  ** list[list.size - 1]: Hash
  ** symmetricKeys[0]: Encryption Key
  ** symmetricKeys[1]: Encryption Type
  ** symmetricKeys[2]: Hash Key
  ** symmetricKeys[3]: Hash Type
  */

  /*
  ** Do not attempt to locate a Buzz key if an interface is not
  ** attached to the kernel.
  */

  if(interfaces > 0 && list.size() == 2)
    {
      symmetricKeys = spoton_kernel::findBuzzKey
	(QByteArray::fromBase64(list.value(0)),
	 QByteArray::fromBase64(list.value(1)));

      if(!symmetricKeys.isEmpty())
	{
	  QByteArray data;
	  bool ok = true;
	  spoton_crypt crypt(symmetricKeys.value(1),
			     "sha512",
			     QByteArray(),
			     symmetricKeys.value(0),
			     0,
			     0,
			     QString(""));

	  data = crypt.decrypted(QByteArray::fromBase64(list.value(0)), &ok);

	  if(ok)
	    type = QByteArray::fromBase64(data.split('\n').value(0));

	  if(!type.isEmpty())
	    goto done_label;
	  else
	    symmetricKeys.clear();
	}
      else
	symmetricKeys.clear();
    }

  /*
  ** Do not attempt to locate a gemini if an interface is not
  ** attached to the kernel.
  */

  if(s_crypt)
    if(interfaces > 0 && list.size() == 2 &&
       spoton_misc::participantCount("chat") > 0)
      {
	QPair<QByteArray, QByteArray> gemini;

	gemini = spoton_misc::findGeminiInCosmos
	  (QByteArray::fromBase64(list.value(0)),
	   QByteArray::fromBase64(list.value(1)),
	   s_crypt);

	if(!gemini.first.isEmpty())
	  {
	    QByteArray data;
	    bool ok = true;
	    spoton_crypt crypt("aes256",
			       "sha512",
			       QByteArray(),
			       gemini.first,
			       0,
			       0,
			       QString(""));

	    data = crypt.decrypted
	      (QByteArray::fromBase64(list.value(0)), &ok);

	    if(ok)
	      type = QByteArray::fromBase64(data.split('\n').value(0));

	    if(!type.isEmpty())
	      {
		symmetricKeys.append(gemini.first);
		symmetricKeys.append("aes256");
		symmetricKeys.append(gemini.second);
		symmetricKeys.append("sha512");
		goto done_label;
	      }
	    else
	      symmetricKeys.clear();
	  }
	else
	  symmetricKeys.clear();
      }

  /*
  ** Finally, attempt to decipher the message via our private key.
  ** We would like to determine the message type only if we have at least
  ** one interface attached to the kernel or if we're processing
  ** a letter.
  */

  if(s_crypt)
    if(interfaces > 0 && list.size() == 3)
      if(!spoton_misc::allParticipantsHaveGeminis())
	if(spoton_misc::participantCount("chat") > 0)
	  {
	    QByteArray data;
	    bool ok = true;

	    data = s_crypt->publicKeyDecrypt
	      (QByteArray::fromBase64(list.value(0)), &ok);

	    if(ok)
	      type = QByteArray::fromBase64(data.split('\n').value(0));

	    if(!type.isEmpty())
	      goto done_label;
	  }

  if(list.size() == 2 || list.size() == 5)
    /*
    ** 0001b
    ** 0002b
    */

    if(spoton_misc::participantCount("email") > 0)
      {
	if(list.size() == 2)
	  symmetricKeys = spoton_kernel::findInstitutionKey
	    (QByteArray::fromBase64(list.value(0)),
	     QByteArray::fromBase64(list.value(1)));
	else
	  symmetricKeys = spoton_kernel::findInstitutionKey
	    (QByteArray::fromBase64(list.value(0)) +
	     QByteArray::fromBase64(list.value(1)) +
	     QByteArray::fromBase64(list.value(2)) +
	     QByteArray::fromBase64(list.value(3)),
	     QByteArray::fromBase64(list.value(4)));

	if(!symmetricKeys.isEmpty())
	  {
	    if(list.size() == 2)
	      type = "0002b";
	    else
	      type = "0001b";

	    goto done_label;
	  }
	else
	  symmetricKeys.clear();
      }

  if(list.size() == 3 || list.size() == 6)
    if((s_crypt = spoton_kernel::s_crypts.value("email", 0)))
      if(spoton_misc::participantCount("email") > 0)
	{
	  QByteArray data;
	  bool ok = true;

	  data = s_crypt->publicKeyDecrypt
	    (QByteArray::fromBase64(list.value(0)), &ok);

	  if(ok)
	    type = QByteArray::fromBase64(data.split('\n').value(0));

	  if(!type.isEmpty())
	    goto done_label;
	}

 done_label:
  return type;
}

void spoton_neighbor::slotCallParticipant(const QByteArray &data)
{
  if(readyToWrite())
    {
      QByteArray message;

      if(spoton_kernel::setting("gui/chatSendMethod",
				"Artificial_GET").toString().
	 trimmed() == "Artificial_GET")
	message = spoton_send::message0000a(data,
					    spoton_send::
					    ARTIFICIAL_GET);
      else
	message = spoton_send::message0000a(data,
					    spoton_send::
					    NORMAL_POST);

      if(write(message.constData(),
	       message.length()) != message.length())
	spoton_misc::logError
	  (QString("spoton_neighbor::slotCallParticipant(): write() "
		   "error for %1:%2.").
	   arg(m_address.toString()).
	   arg(m_port));
      else
	{
	  addToBytesWritten(message.length());
	  spoton_kernel::messagingCacheAdd(message);
	}
    }
}

void spoton_neighbor::saveGemini(const QByteArray &publicKeyHash,
				 const QByteArray &gemini,
				 const QByteArray &geminiHashKey)
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
	bool ok = true;

	query.prepare("UPDATE friends_public_keys SET "
		      "gemini = ?, gemini_hash_key = ?, "
		      "last_status_update = ? "
		      "WHERE neighbor_oid = -1 AND "
		      "public_key_hash = ?");

	if(gemini.isEmpty() || geminiHashKey.isEmpty())
	  {
	    query.bindValue(0, QVariant(QVariant::String));
	    query.bindValue(1, QVariant(QVariant::String));
	  }
	else
	  {
	    spoton_crypt *s_crypt =
	      spoton_kernel::s_crypts.value("chat", 0);

	    if(s_crypt)
	      {
		query.bindValue
		  (0, s_crypt->encryptedThenHashed(gemini, &ok).toBase64());

		if(ok)
		  query.bindValue
		    (1, s_crypt->encryptedThenHashed(geminiHashKey,
						     &ok).toBase64());
	      }
	    else
	      {
		query.bindValue(0, QVariant(QVariant::String));
		query.bindValue(1, QVariant(QVariant::String));
	      }
	  }

	query.bindValue
	  (2, QDateTime::currentDateTime().toString(Qt::ISODate));
	query.bindValue(3, publicKeyHash.toBase64());

	if(ok)
	  query.exec();

      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_neighbor::addToBytesWritten(const int bytesWritten)
{
  m_bytesWritten += qAbs(bytesWritten);
}

void spoton_neighbor::slotSendAccountInformation(void)
{
  if(state() != QAbstractSocket::ConnectedState)
    return;

  spoton_crypt *s_crypt = spoton_kernel::s_crypts.value("chat", 0);

  if(!s_crypt)
    return;

  QByteArray name(m_accountName);
  QByteArray password(m_accountPassword);
  bool ok = true;

  name = s_crypt->decryptedAfterAuthenticated(name, &ok);

  if(ok)
    password = s_crypt->decryptedAfterAuthenticated(password, &ok);

  if(ok)
    if(!name.isEmpty() && password.length() >= 16)
      {
	QByteArray message;
	QByteArray salt(spoton_crypt::strongRandomBytes(512));
	QByteArray saltedCredentials
	  (spoton_crypt::saltedValue("sha512", name + password +
				     QDateTime::currentDateTime().toUTC().
				     toString("MMddyyyyhhmm").toLatin1(),
				     salt, &ok));

	if(ok)
	  message = spoton_send::message0050(saltedCredentials, salt);

	if(ok)
	  {
	    if(write(message.constData(), message.length()) !=
	       message.length())
	      spoton_misc::logError
		(QString("spoton_neighbor::slotSendAccountInformation(): "
			 "write() error for %1:%2.").
		 arg(m_address.toString()).
		 arg(m_port));
	    else
	      {
		m_accountClientSentSalt = salt;
		addToBytesWritten(message.length());
	      }
	  }
      }
}

void spoton_neighbor::slotAccountAuthenticated(const QByteArray &name,
					       const QByteArray &password)
{
  if(state() != QAbstractSocket::ConnectedState)
    return;

  QByteArray message;
  QByteArray salt(spoton_crypt::strongRandomBytes(512));
  QByteArray saltedCredentials;
  bool ok = true;

  /*
  ** The server authenticated the client's credentials. We'll
  ** now create a similar response so that the client can
  ** verify the server.
  */

  saltedCredentials = spoton_crypt::saltedValue
    ("sha512", name + password +
     QDateTime::currentDateTime().toUTC().
     toString("MMddyyyyhhmm").toLatin1(), salt, &ok);

  if(ok)
    message = spoton_send::message0051(saltedCredentials, salt);

  if(ok)
    {
      if(write(message.constData(), message.length()) != message.length())
	spoton_misc::logError
	  (QString("spoton_neighbor::slotAccountAuthenticated(): "
		   "write() error for %1:%2.").
	   arg(m_address.toString()).
	   arg(m_port));
      else
	addToBytesWritten(message.length());
    }
}

void spoton_neighbor::slotSendAuthenticationRequest(void)
{
  if(state() != QAbstractSocket::ConnectedState)
    return;

  QByteArray message(spoton_send::message0052());

  if(write(message.constData(), message.length()) != message.length())
    spoton_misc::logError
      (QString("spoton_neighbor::slotSendAuthenticationRequest(): "
	       "write() error for %1:%2.").
       arg(m_address.toString()).
       arg(m_port));
  else
    addToBytesWritten(message.length());
}

qint64 spoton_neighbor::write(const char *data, const qint64 size)
{
  qint64 remaining = size;
  qint64 sent = 0;

  while(remaining > 0)
    {
      if(m_sctpSocket)
	sent = m_sctpSocket->write(data, remaining);
      else if(m_tcpSocket)
	sent = m_tcpSocket->write(data, remaining);
      else if(m_udpSocket)
	{
	  if(m_isUserDefined)
	    sent = m_udpSocket->write(data, remaining);
	  else
	    sent = m_udpSocket->writeDatagram
	      (data, remaining, m_address, m_port);

	  if(sent == -1)
	    if(m_udpSocket->error() == QAbstractSocket::UnknownSocketError)
	      {
		/*
		** If the end-point is absent, QIODevice::write() may
		** return -1.
		*/

		deleteLater();
		break;
	      }
	}
      else
	sent = 0;

      if(sent <= 0)
	break;

      data += sent; // What should we do if sent is monstrously large?
      remaining -= sent;
    }

  return size - remaining;
}

QAbstractSocket::SocketState spoton_neighbor::state(void) const
{
  if(m_sctpSocket)
    return QAbstractSocket::SocketState(m_sctpSocket->state());
  else if(m_tcpSocket)
    return m_tcpSocket->state();
  else if(m_udpSocket)
    return m_udpSocket->state();
  else
    return QAbstractSocket::UnconnectedState;
}

QHostAddress spoton_neighbor::peerAddress(void) const
{
  if(m_sctpSocket)
    return m_sctpSocket->peerAddress();
  else if(m_tcpSocket)
    return m_tcpSocket->peerAddress();
  else if(m_udpSocket)
    return m_udpSocket->peerAddress();
  else
    return QHostAddress();
}

quint16 spoton_neighbor::peerPort(void) const
{
  if(m_sctpSocket)
    return m_sctpSocket->peerPort();
  else if(m_tcpSocket)
    return m_tcpSocket->peerPort();
  else if(m_udpSocket)
    return m_udpSocket->peerPort();
  else
    return -1;
}

bool spoton_neighbor::isEncrypted(void) const
{
  if(m_tcpSocket)
    return m_tcpSocket->isEncrypted();
  else
    return false;
}

QString spoton_neighbor::transport(void) const
{
  return m_transport;
}

void spoton_neighbor::slotAuthenticationTimerTimeout(void)
{
  spoton_misc::logError
    (QString("spoton_neighbor::slotAuthenticationTimerTimeout(): "
	     "authentication timer expired for %1:%2. Aborting!").
     arg(m_address.toString()).
     arg(m_port));
  deleteLater();
}
