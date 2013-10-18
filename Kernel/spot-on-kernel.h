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

#ifndef _spoton_kernel_h_
#define _spoton_kernel_h_

#include <QFileSystemWatcher>
#include <QFuture>
#include <QHash>
#include <QHostAddress>
#include <QMutex>
#include <QPointer>
#include <QSqlDatabase>
#include <QTimer>

#include "Common/spot-on-send.h"

class spoton_crypt;
class spoton_gui_server;
class spoton_listener;
class spoton_mailer;
class spoton_neighbor;
class spoton_shared_reader;

class spoton_kernel: public QObject
{
  Q_OBJECT

 public:
  spoton_kernel(void);
  ~spoton_kernel();
  static QHash<QString, spoton_crypt *> s_crypts; /*
						  ** private
						  ** server
						  ** signature
						  ** url
						  */
  
  static QPair<QByteArray, QByteArray> findBuzzKey
    (const QByteArray &data);
  static QVariant setting(const QString &name,
			  const QVariant &defaultValue);
  static bool messagingCacheContains(const QByteArray &data);
  static int interfaces(void);
  static void addBuzzKey(const QByteArray &key,
			 const QByteArray &channelType);
  static void clearBuzzKeysContainer(void);
  static void messagingCacheAdd(const QByteArray &data);
  static void removeBuzzKey(const QByteArray &data);

 private:
  static QHash<QString, QVariant> s_settings;
  static QMutex s_buzzKeysMutex;
  static QMutex s_settingsMutex;
  QFileSystemWatcher m_settingsWatcher;
  QFuture<void> m_future;
  QHash<qint64, QPointer<spoton_listener> > m_listeners;
  QHash<qint64, QPointer<spoton_neighbor> > m_neighbors;
  QTimer m_controlDatabaseTimer;
  QTimer m_messagingCachePurgeTimer;
  QTimer m_publishAllListenersPlaintextTimer;
  QTimer m_scramblerTimer;
  QTimer m_statusTimer;
  spoton_gui_server *m_guiServer;
  spoton_mailer *m_mailer;
  spoton_shared_reader *m_sharedReader;
  static QHash<QByteArray, QByteArray> s_buzzKeys;
  static QHash<QByteArray, QDateTime> s_messagingCache;
  static QMutex s_messagingCacheMutex;
  bool initializeSecurityContainers(const QString &passphrase);
  void checkForTermination(void);
  void cleanup(void);
  void cleanupDatabases(void);
  void cleanupListenersDatabase(const QSqlDatabase &db);
  void cleanupNeighborsDatabase(const QSqlDatabase &db);
  void connectSignalsToNeighbor(QPointer<spoton_neighbor> neighbor);
  void prepareListeners(void);
  void prepareNeighbors(void);
  void purgeMessagingCache(void);

 private slots:
  void slotBuzzReceivedFromUI(const QByteArray &key,
			      const QByteArray &channelType,
			      const QByteArray &name,
			      const QByteArray &id,
			      const QByteArray &message,
			      const QByteArray &sendMethod,
			      const QString &messageType);
  void slotCallParticipant(const qint64 oid);
  void slotDetachNeighbors(const qint64 listenerOid);
  void slotDisconnectNeighbors(const qint64 listenerOid);
  void slotMessagingCachePurge(void);
  void slotMessageReceivedFromUI(const qint64 oid,
				 const QByteArray &name,
				 const QByteArray &message);
  void slotNewNeighbor(QPointer<spoton_neighbor> neighbor);
  void slotPollDatabase(void);
  void slotPublicKeyReceivedFromUI(const qint64 oid,
				   const QByteArray &keyType,
				   const QByteArray &name,
				   const QByteArray &publicKey,
				   const QByteArray &signature,
				   const QByteArray &sPublicKey,
				   const QByteArray &sSignature,
				   const QString &messageType);
  void slotPublicizeAllListenersPlaintext(void);
  void slotPublicizeListenerPlaintext(const qint64 oid);
  void slotRequestScramble(void);
  void slotRetrieveMail(void);
  void slotScramble(void);
  void slotSendMail(const QByteArray &goldbug,
		    const QByteArray &message,
		    const QByteArray &name,
		    const QByteArray &publicKey,
		    const QByteArray &subject,
		    const qint64 mailOid);
  void slotSettingsChanged(const QString &path);
  void slotStatusTimerExpired(void);

 signals:
  void callParticipant(const QByteArray &data);
  void publicizeListenerPlaintext(const QByteArray &data,
				  const qint64 id);
  void publicizeListenerPlaintext(const QHostAddress &address,
				  const quint16 port);
  void receivedMessage(const QByteArray &data, const qint64 id);
  void retrieveMail(const QList<QByteArray> &list);
  void sendBuzz(const QByteArray &buzz);
  void sendMessage(const QByteArray &message);
  void sendMail(const QList<QPair<QByteArray, qint64> > &mail);
  void sendStatus(const QList<QByteArray> &status);
};

#endif
