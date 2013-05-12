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

#ifndef _spoton_h_
#define _spoton_h_

#include <QDateTime>
#include <QMainWindow>
#include <QSqlDatabase>
#include <QTcpSocket>
#include <QTimer>
 
#include "Common/spot-on-gcrypt.h"
#include "spot-on-docviewer.h"
#include "spot-on-logviewer.h"
#include "ui_controlcenter.h"

class spoton: public QMainWindow
{
  Q_OBJECT

 public:
  spoton(void);
  Ui_spoton_mainwindow ui(void) const;

 private:
  static const int NAME_MAXIMUM_LENGTH = 64;
  QByteArray m_kernelSocketData;
  QDateTime m_countriesLastModificationTime;
  QDateTime m_listenersLastModificationTime;
  QDateTime m_neighborsLastModificationTime;
  QDateTime m_participantsLastModificationTime;
  QHash<QString, QVariant> m_settings;
  QTcpSocket m_kernelSocket;
  QTimer m_generalTimer;
  QTimer m_tableTimer;
  Ui_spoton_mainwindow m_ui;
  spoton_gcrypt *m_crypt;
  spoton_docviewer m_docViewer;
  spoton_logviewer m_logViewer;
  QIcon iconForCountry(const QString &country);
  bool isKernelActive(void) const;
  void closeEvent(QCloseEvent *event);
  void highlightKernelPath(void);
  void prepareListenerIPCombo(void);
  void saveKernelPath(const QString &path);
  void saveSettings(void);
  void sendKeyToKernel(void);
  void updateListenersTable(QSqlDatabase &db);
  void updateNeighborsTable(QSqlDatabase &db);
  void updateParticipantsTable(QSqlDatabase &db);

 private slots:
  void slotActivateKernel(void);
  void slotAddBootstrapper(void);
  void slotAddListener(void);
  void slotAddFriendsKey(void);
  void slotAddNeighbor(void);
  void slotBlockNeighbor(void);
  void slotChatSendMethodChanged(int index);
  void slotClearOutgoingMessage(void);
  void slotConnectNeighbor(void);
  void slotCopyFriendshipBundle(void);
  void slotCopyMyPublicKey(void);
  void slotCopyMyURLPublicKey(void);
  void slotCountryChanged(QListWidgetItem *item);
  void slotDeactivateKernel(void);
  void slotDeleteAllBlockedNeighbors(void);
  void slotDeleteAllListeners(void);
  void slotDeleteAllNeighbors(void);
  void slotDeleteAllUuids(void);
  void slotDeleteListener(void);
  void slotDeleteMail(void);
  void slotDeleteNeighbor(void);
  void slotDisconnectNeighbor(void);
  void slotDisplayLocalSearchResults(void);
  void slotDoSearch(void);
  void slotFetchMoreAlgo(void);
  void slotFetchMoreButton(void);
  void slotGeneralTimerTimeout(void);
  void slotGenerateGeminiInChat(void);
  void slotKernelSocketState(void);
  void slotListenerCheckChange(int state);
  void slotListenerIPComboChanged(int index);
  void slotMailSelected(void);
  void slotMaximumClientsChanged(int index);
  void slotNeighborCheckChange(int state);
  void slotOnlyConnectedNeighborsToggled(bool state);
  void slotOnlyOnlineListenersToggled(bool state);
  void slotPopulateCountries(void);
  void slotPopulateListeners(void);
  void slotPopulateNeighbors(void);
  void slotPopulateParticipants(void);
  void slotProtocolRadioToggled(bool state);
  void slotQuit(void);
  void slotReceivedKernelMessage(void);
  void slotRefreshMail(void);
  void slotRemoveParticipants(void);
  void slotResetAll(void);
  void slotSaveKernelPath(void);
  void slotSaveNodeName(void);
  void slotScramble(bool state);
  void slotSelectKernelPath(void);
  void slotSendMail(void);
  void slotSendMessage(void);
  void slotSetPassphrase(void);
  void slotSharePublicKey(void);
  void slotSharePublicKeyWithParticipant(void);
  void slotShareURLPublicKey(void);
  void slotShowContextMenu(const QPoint &point);
  void slotStatusChanged(int index);
  void slotTabChanged(int index);
  void slotUnblockNeighbor(void);
  void slotValidatePassphrase(void);
  void slotViewDocumentation(void);
  void slotViewLog(void);
};

#endif
