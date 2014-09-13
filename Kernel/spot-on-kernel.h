/*
** Copyright (c) 2011 - 10^10^10, Alexis Megas.
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

#include <QDateTime>
#include <QFileSystemWatcher>
#include <QFuture>
#include <QHash>
#include <QHostAddress>
#include <QPointer>
#include <QReadWriteLock>
#include <QSqlDatabase>
#include <QTimer>

#include "Common/spot-on-common.h"
#include "Common/spot-on-send.h"

class spoton_crypt;
class spoton_gui_server;
class spoton_listener;
class spoton_mailer;
class spoton_neighbor;
class spoton_shared_reader;
class spoton_starbeam_reader;
class spoton_starbeam_writer;

class spoton_kernel: public QObject
{
  Q_OBJECT

 public:
  spoton_kernel(void);
  ~spoton_kernel();
  static QHash<QString, spoton_crypt *> s_crypts;
  static QHash<qint64, int> s_connectionCounts;
  static QList<QPair<QByteArray, QByteArray> > s_adaptiveEchoPairs;
  static QPointer<spoton_kernel> s_kernel;
  static QList<QByteArray> findBuzzKey(const QByteArray &data,
				       const QByteArray &hash);
  static QList<QByteArray> findInstitutionKey(const QByteArray &data,
					      const QByteArray &hash);
  static QVariant setting(const QString &name,
			  const QVariant &defaultValue);
  static bool messagingCacheContains(const QByteArray &data,
				     const bool do_not_hash = false);
  static int buzzKeyCount(void);
  static int interfaces(void);
  static void addBuzzKey(const QByteArray &key,
			 const QByteArray &channelType,
			 const QByteArray &hashKey,
			 const QByteArray &hashType);
  static void clearBuzzKeysContainer(void);
  static void discoverAdaptiveEchoPair
    (const QByteArray &data,
     QPair<QByteArray, QByteArray> &discoveredAdaptiveEchoPair);
  static void messagingCacheAdd(const QByteArray &data,
				const bool do_not_hash = false,
				const int add_msecs = 0);
  static void receivedMessage
    (const QByteArray &data, const qint64 id,
     const QPair<QByteArray, QByteArray> &adaptiveEchoPair);
  static void removeBuzzKey(const QByteArray &data);
  bool acceptRemoteConnection(const QHostAddress &localAddress,
			      const QHostAddress &peerAddress);
  bool processPotentialStarBeamData(const QByteArray &data);
  void writeMessage0060(const QByteArray &data, bool *ok);

 private:
  QDateTime m_uptime;
  QFileSystemWatcher m_settingsWatcher;
  QFuture<void> m_future;
  QFuture<void> m_statisticsFuture;
  QHash<qint64, QPointer<spoton_listener> > m_listeners;
  QHash<qint64, QPointer<spoton_neighbor> > m_neighbors;
  QHash<qint64, QPointer<spoton_starbeam_reader> > m_starbeamReaders;
  QTimer m_controlDatabaseTimer;
  QTimer m_impersonateTimer;
  QTimer m_messagingCachePurgeTimer;
  QTimer m_processReceivedMessagesTimer;
  QTimer m_publishAllListenersPlaintextTimer;
  QTimer m_scramblerTimer;
  QTimer m_settingsTimer;
  QTimer m_statusTimer;
  spoton_gui_server *m_guiServer;
  spoton_mailer *m_mailer;
  spoton_shared_reader *m_sharedReader;
  spoton_starbeam_writer *m_starbeamWriter;
  static QDateTime s_institutionLastModificationTime;
  static QHash<QByteArray, QList<QByteArray> > s_buzzKeys;
  static QHash<QString, QVariant> s_settings;
  static QList<QList<QByteArray> > s_institutionKeys;
  static QList<QList<QVariant> > s_messagesToProcess;
  static QHash<QByteArray, uint> s_messagingCache;
  static QReadWriteLock s_adaptiveEchoPairsMutex;
  static QReadWriteLock s_buzzKeysMutex;
  static QReadWriteLock s_institutionKeysMutex;
  static QReadWriteLock s_messagesToProcessMutex;
  static QReadWriteLock s_messagingCacheMutex;
  static QReadWriteLock s_settingsMutex;
  bool initializeSecurityContainers(const QString &passphrase);
  void checkForTermination(void);
  void cleanup(void);
  void cleanupDatabases(void);
  void cleanupListenersDatabase(const QSqlDatabase &db);
  void cleanupNeighborsDatabase(const QSqlDatabase &db);
  void cleanupStarbeamsDatabase(const QSqlDatabase &db);
  void connectSignalsToNeighbor(QPointer<spoton_neighbor> neighbor);
  void prepareListeners(void);
  void prepareNeighbors(void);
  void prepareStarbeamReaders(void);
  void purgeMessagingCache(void);
  void updateStatistics(void);

 private slots:
  void slotBuzzMagnetReceivedFromUI(const qint64 oid,
				    const QByteArray &magnet);
  void slotBuzzReceivedFromUI(const QByteArray &key,
			      const QByteArray &channelType,
			      const QByteArray &name,
			      const QByteArray &id,
			      const QByteArray &message,
			      const QByteArray &sendMethod,
			      const QString &messageType,
			      const QByteArray &hashKey,
			      const QByteArray &hashType);
  void slotCallParticipant(const qint64 oid);
  void slotCallParticipantUsingGemini(const qint64 oid);
  void slotDetachNeighbors(const qint64 listenerOid);
  void slotDisconnectNeighbors(const qint64 listenerOid);
  void slotImpersonateTimeout(void);
  void slotMessagingCachePurge(void);
  void slotMessageReceivedFromUI(const qint64 oid,
				 const QByteArray &name,
				 const QByteArray &message,
				 const QByteArray &sequenceNumber,
				 const QByteArray &utcDate);
  void slotNewNeighbor(QPointer<spoton_neighbor> neighbor);
  void slotPollDatabase(void);
  void slotProcessReceivedMessages(void);
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
		    const QByteArray &attachment,
		    const qint64 mailOid);
  void slotSettingsChanged(const QString &path);
  void slotStatusTimerExpired(void);
  void slotUpdateSettings(void);

 signals:
  void callParticipant(const QByteArray &data,
		       const QString &messageType);
  void publicizeListenerPlaintext(const QByteArray &data,
				  const qint64 id);
  void publicizeListenerPlaintext(const QHostAddress &address,
				  const quint16 port,
				  const QString &transport,
				  const QString &orientation);
  void retrieveMail(const QByteArrayList &list, const QString &messageType);
  void sendBuzz(const QByteArray &buzz);
  void sendMessage(const QByteArray &message,
		   const spoton_send::spoton_send_method sendMethod);
  void sendMail(const QPairByteArrayInt64List &mail,
		const QString &messageType);
  void sendStatus(const QByteArrayList &status);
};

#endif
