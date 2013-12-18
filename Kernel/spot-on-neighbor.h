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

#ifndef _spoton_neighbor_h_
#define _spoton_neighbor_h_

#include <QDateTime>
#include <QHostAddress>
#include <QHostInfo>
#include <QNetworkProxy>
#include <QSqlDatabase>
#include <QSslSocket>
#include <QThread>
#include <QTimer>
#include <QUdpSocket>
#include <QUuid>

#include "Common/spot-on-send.h"

class spoton_external_address;

class spoton_neighbor_tcp_socket: public QSslSocket
{
  Q_OBJECT

 public:
  spoton_neighbor_tcp_socket(QObject *parent = 0):QSslSocket(parent)
  {
  }

  void setLocalAddress(const QHostAddress &address)
  {
    QSslSocket::setLocalAddress(address);
  }
};

class spoton_neighbor_udp_socket: public QUdpSocket
{
  Q_OBJECT

 public:
  spoton_neighbor_udp_socket(QObject *parent = 0):QUdpSocket(parent)
  {
  }

  void setLocalAddress(const QHostAddress &address)
  {
    QUdpSocket::setLocalAddress(address);
  }

  void setLocalPort(quint16 port)
  {
    QUdpSocket::setLocalPort(port);
  }

  void setPeerAddress(const QHostAddress &address)
  {
    QUdpSocket::setPeerAddress(address);
  }

  void setPeerPort(quint16 port)
  {
    QUdpSocket::setPeerPort(port);
  }

  void setSocketState(QAbstractSocket::SocketState state)
  {
    QUdpSocket::setSocketState(state);
  }
};

class spoton_neighbor: public QThread
{
  Q_OBJECT

 public:
  spoton_neighbor(const QNetworkProxy &proxy,
		  const QString &ipAddress,
		  const QString &port,
		  const QString &scopeId,
		  const qint64 id,
		  const bool userDefined,
		  const int keySize,
		  const int maximumBufferSize,
		  const int maximumContentLength,
		  const QString &echoMode,
		  const QByteArray &peerCertificate,
		  const bool allowExceptions,
		  const QString &protocol,
		  const bool requireSsl,
		  const QByteArray &accountName,
		  const QByteArray &accountPassword,
		  const QString &transport,
		  QObject *parent);
  spoton_neighbor(const int socketDescriptor,
		  const QByteArray &certificate,
		  const QByteArray &privateKey,
		  const QString &echoMode,
		  const bool useAccounts,
		  const qint64 listenerOid,
		  const int maximumBufferSize,
		  const int maximumContentLength,
		  const QString &transport,
		  const QString &ipAddress,
		  const QString &port,
		  const QString &localIpAddress,
		  const QString &localPort,
		  QObject *parent);
  ~spoton_neighbor();
  QAbstractSocket::SocketState state(void) const;
  QHostAddress peerAddress(void) const;
  QString transport(void) const;
  QUuid receivedUuid(void) const;
  bool isEncrypted(void) const;
  bool readyToWrite(void) const;
  qint64 id(void) const;
  qint64 write(const char *data, qint64 size);
  quint16 peerPort(void) const;
  void abort(void);
  void addToBytesWritten(const int bytesWritten);
  void deleteLater(void);
  void flush(void);
  void setId(const qint64 id);
  void sharePublicKey(const QByteArray &keyType,
		      const QByteArray &name,
		      const QByteArray &publicKey,
		      const QByteArray &signature,
		      const QByteArray &sPublicKey,
		      const QByteArray &sSignature);

 private:
  QByteArray m_accountName;
  QByteArray m_accountPassword;
  QByteArray m_accountClientSentSalt;
  QByteArray m_data;
  QDateTime m_authenticationSentTime;
  QDateTime m_lastReadTime;
  QDateTime m_startTime;
  QHostAddress m_address;
  QSslCertificate m_peerCertificate;
  QString m_echoMode;
  QString m_ipAddress;
  QString m_protocol;
  QString m_transport;
  QTimer m_accountTimer;
  QTimer m_externalAddressDiscovererTimer;
  QTimer m_keepAliveTimer;
  QTimer m_lifetime;
  QTimer m_timer;
  QUuid m_receivedUuid;
  bool m_accountAuthenticated;
  bool m_allowExceptions;
  bool m_isUserDefined;
  bool m_requireSsl;
  bool m_useAccounts;
  bool m_useSsl;
  int m_keySize;
  int m_maximumBufferSize;
  int m_maximumContentLength;
  qint64 m_id;
  qint64 m_listenerOid;
  quint16 m_port;
  quint64 m_bytesRead;
  quint64 m_bytesWritten;
  spoton_external_address *m_externalAddress;
  spoton_neighbor_tcp_socket *m_tcpSocket;
  spoton_neighbor_udp_socket *m_udpSocket;
  QString findMessageType(const QByteArray &data,
			  QList<QByteArray> &symmetricKeys);
  qint64 readBufferSize(void) const;
  void process0000(int length, const QByteArray &data,
		   const QList<QByteArray> &symmetricKeys);
  void process0000a(int length, const QByteArray &data);
  void process0001a(int length, const QByteArray &data);
  void process0001b(int length, const QByteArray &data);
  void process0002(int length, const QByteArray &data);
  void process0011(int length, const QByteArray &data);
  void process0012(int length, const QByteArray &data);
  void process0013(int length, const QByteArray &data,
		   const QList<QByteArray> &symmetricKeys);
  void process0014(int length, const QByteArray &data);
  void process0030(int length, const QByteArray &data);
  void process0040a(int length, const QByteArray &data,
		    const QList<QByteArray> &symmetricKeys);
  void process0040b(int length, const QByteArray &data,
		    const QList<QByteArray> &symmetricKeys);
  void process0050(int length, const QByteArray &data);
  void process0051(int length, const QByteArray &data);
  void process0065(int length, const QByteArray &data);
  void recordCertificateOrAbort(void);
  void resetKeepAlive(void);
  void run(void);
  void saveExternalAddress(const QHostAddress &address,
			   const QSqlDatabase &db);
  void saveGemini(const QByteArray &publicKeyHash,
		  const QByteArray &gemini,
		  const QByteArray &geminiMac);
  void saveParticipantStatus(const QByteArray &publicKeyHash);
  void saveParticipantStatus(const QByteArray &name,
			     const QByteArray &publicKeyHash);
  void saveParticipantStatus(const QByteArray &name,
			     const QByteArray &publicKeyHash,
			     const QByteArray &status);
  void savePublicKey(const QByteArray &keyType,
		     const QByteArray &name,
		     const QByteArray &publicKey,
		     const QByteArray &signature,
		     const QByteArray &sPublicKey,
		     const QByteArray &sSignature,
		     const qint64 neighborOid);
  void saveStatistics(const QSqlDatabase &db);
  void saveStatus(const QSqlDatabase &db, const QString &status);
  void saveStatus(const QString &status);
  void sendAuthenticationRequest(void);
  void setReadBufferSize(const qint64 size);
  void storeLetter(const QByteArray &symmetricKey,
		   const QByteArray &symmetricKeyAlgorithm,
		   const QByteArray &senderPublicKeyHash,
		   const QByteArray &name,
		   const QByteArray &subject,
		   const QByteArray &message,
		   const QByteArray &signature,
		   const bool goldbugUsed);
  void storeLetter(const QList<QByteArray> &list,
		   const QByteArray &recipientHash);

 private slots:
  void slotAccountAuthenticated(const QByteArray &name,
				const QByteArray &password);
  void slotCallParticipant(const QByteArray &data);
  void slotConnected(void);
  void slotDisconnected(void);
  void slotDiscoverExternalAddress(void);
  void slotEncrypted(void);
  void slotError(QAbstractSocket::SocketError error);
  void slotExternalAddressDiscovered(const QHostAddress &address);
  void slotHostFound(const QHostInfo &hostInfo);
  void slotLifetimeExpired(void);
  void slotModeChanged(QSslSocket::SslMode mode);
  void slotPeerVerifyError(const QSslError &error);
  void slotProxyAuthenticationRequired(const QNetworkProxy &proxy,
				       QAuthenticator *authenticator);
  void slotPublicizeListenerPlaintext(const QByteArray &data,
				      const qint64 id);
  void slotPublicizeListenerPlaintext(const QHostAddress &address,
				      const quint16 port,
				      const QString &transport);
  void slotReadyRead(void);
  void slotReceivedMessage(const QByteArray &data, const qint64 id);
  void slotRetrieveMail(const QList<QByteArray> &list);
  void slotSendAccountInformation(void);
  void slotSendBuzz(const QByteArray &data);
  void slotSendMail(const QList<QPair<QByteArray, qint64> > &list);
  void slotSendMailFromPostOffice(const QByteArray &data);
  void slotSendMessage(const QByteArray &data);
  void slotSendStatus(const QList<QByteArray> &list);
  void slotSendUuid(void);
  void slotSslErrors(const QList<QSslError> &errors);
  void slotTimeout(void);

 signals:
  void accountAuthenticated(const QByteArray &name,
			    const QByteArray &password);
  void authenticationRequested(const QString &peerInformation);
  void disconnected(void);
  void newEMailArrived(void);
  void publicizeListenerPlaintext(const QByteArray &data, const qint64 id);
  void receivedBuzzMessage(const QList<QByteArray> &list,
			   const QList<QByteArray> &symmetricKeys);
  void receivedChatMessage(const QByteArray &data);
  void receivedMessage(const QByteArray &data, const qint64 id);
  void receivedPublicKey(const QByteArray &name, const QByteArray publicKey);
  void retrieveMail(const QByteArray &data,
		    const QByteArray &publicKeyHash,
		    const QByteArray &signature);
  void scrambleRequest(void);
};

#endif
