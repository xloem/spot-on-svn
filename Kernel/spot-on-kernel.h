/*
** Copyright (c) 2012, 2013 Alexis Megas
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
#include <QHash>
#include <QPointer>
#include <QTimer>

class spoton_gcrypt;
class spoton_gui_server;
class spoton_listener;
class spoton_neighbor;

class spoton_kernel: public QObject
{
  Q_OBJECT

 public:
  spoton_kernel(void);
  ~spoton_kernel();
  static QHash<QString, QVariant> s_settings;
  static spoton_gcrypt *s_crypt1; // private_public_keys.db
  static spoton_gcrypt *s_crypt2; // shared.db
  static const short TTL_0000 = 16;
  static const short TTL_0010 = 16;

 private:
  QFileSystemWatcher m_settingsWatcher;
  QHash<qint64, QPointer<spoton_listener> > m_listeners;
  QHash<qint64, QPointer<spoton_neighbor> > m_neighbors;
  QTimer m_controlDatabaseTimer;
  spoton_gui_server *m_guiServer;
  void checkForTermination(void);
  void cleanup(void);
  void cleanupDatabases(void);
  void connectSignalsToNeighbor(spoton_neighbor *neighbor);
  void copyPublicKey(void);
  void prepareListeners(void);
  void prepareNeighbors(void);

 private slots:
  void slotMessageReceivedFromUI(const qint64 oid,
				 const QByteArray &name,
				 const QByteArray &message);
  void slotNewNeighbor(QPointer<spoton_neighbor> neighbor);
  void slotPollDatabase(void);
  void slotPublicKeyReceivedFromUI(const qint64 oid,
				   const QByteArray &name,
				   const QByteArray &publicKey);
  void slotPublicKeyReceivedFromUI(const qint64 oid,
				   const QByteArray &publicKey,
				   const QByteArray &symmetricKey,
				   const QByteArray &symmetricKeyAlgorithm);
  void slotSettingsChanged(const QString &path);

 signals:
  void sendMessage(const QByteArray &message);
  void receivedChatMessage(const QByteArray &name, const qint64 id);
  void receivedPublicKey(const QByteArray &publicKey,
			 const qint64 id);
};

#endif
