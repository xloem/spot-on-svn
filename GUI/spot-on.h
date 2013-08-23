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

#ifndef _spoton_h_
#define _spoton_h_

#include <QApplication>
#include <QCheckBox>
#include <QClipboard>
#include <QDateTime>
#include <QDesktopServices>
#include <QDir>
#include <QFileDialog>
#include <QFuture>
#include <QHash>
#include <QInputDialog>
#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
#include <QMacStyle>
#endif
#endif
#include <QMainWindow>
#include <QMessageBox>
#include <QMutex>
#ifdef Q_OS_WIN32
#include <qt_windows.h>
#include <QtNetwork>
#else
#include <QNetworkInterface>
#endif
#include <QProcess>
#include <QScrollBar>
#include <QSettings>
#include <QSqlDatabase>
#include <QSqlError>
#include <QSqlQuery>
#include <QSqlRecord>
#include <QSslSocket>
#include <QStyle>
#include <QTimer>
#include <QTranslator>
#include <QUuid>
#include <QtDebug>
#ifdef SPOTON_LINKED_WITH_LIBPHONON
#if 0
#include <phonon/AudioOutput>
#include <phonon/MediaObject>
#endif
#endif

#include <limits>

extern "C"
{
#include "libSpotOn/libspoton.h"
}

#ifdef Q_OS_MAC
#if QT_VERSION >= 0x050000
#include "CocoaInitializer.h"
#endif
#endif

#include "Common/spot-on-common.h"
#include "Common/spot-on-crypt.h"
#include "Common/spot-on-misc.h"
#include "Common/spot-on-send.h"
#include "spot-on-docviewer.h"
#include "spot-on-logviewer.h"
#include "spot-on-reencode.h"
#include "ui_controlcenter.h"
#include "ui_statusbar.h"

class spoton: public QMainWindow
{
  Q_OBJECT

 public:
  spoton(void);
  ~spoton();
  Ui_spoton_mainwindow ui(void) const;

 private:
  static const int APPLY_GOLDBUG_TO_INBOX_ERROR_GENERAL = 1;
  static const int APPLY_GOLDBUG_TO_INBOX_ERROR_MEMORY = 2;
  QByteArray m_kernelSocketData;
  QDateTime m_countriesLastModificationTime;
  QDateTime m_listenersLastModificationTime;
  QDateTime m_neighborsLastModificationTime;
  QDateTime m_participantsLastModificationTime;
  QFuture<void> m_future;
  QHash<QByteArray, QDateTime> m_messagingCache; /*
						 ** Prevent duplicate
						 ** echoed messages.
						 */
  QHash<QString, QByteArray> m_buzzIds;
  QHash<QString, QVariant> m_settings;
  QHash<QString, bool> m_booleans;
  QMutex m_messagingCacheMutex;
  QMutex m_purgeMutex;
#ifdef SPOTON_LINKED_WITH_LIBPHONON
#if 0
  Phonon::MediaObject *m_mediaObject;
#endif
#endif
  QSslSocket m_kernelSocket;
  QTimer m_buzzStatusTimer;
  QTimer m_generalTimer;
  QTimer m_messagingCachePurgeTimer;
  QTimer m_tableTimer;
  QWidget *m_sbWidget;
  Ui_statusbar m_sb;
  Ui_spoton_mainwindow m_ui;
  bool m_purge;
  spoton_crypt *m_crypt;
  spoton_crypt *m_signatureCrypt;
  spoton_docviewer m_docViewer;
  spoton_logviewer m_logViewer;
  QPixmap pixmapForCountry(const QString &country);
#ifdef Q_OS_MAC
#if QT_VERSION >= 0x050000
  bool event(QEvent *event);
#endif
#endif
  bool isKernelActive(void) const;
  bool saveGemini(const QByteArray &gemini, const QString &oid);
  bool updateMailStatus(const QString &oid, const QString &status);
  int applyGoldbugToInboxLetter(const QByteArray &goldbug,
				const int row);
  void changeEchoMode(const QString &mode, QTableWidget *tableWidget);
  void closeEvent(QCloseEvent *event);
  void countriesToggle(const bool state);
  void highlightPaths(void);
  void initializeKernelSocket(void);
  void prepareListenerIPCombo(void);
  void purgeMessagingCache(void);
  void saveGeoIPPath(const QString &path);
  void saveKernelPath(const QString &path);
  void saveSettings(void);
  void sendBuzzKeysToKernel(void);
  void sendKeysToKernel(void);
  void updateListenersTable(const QSqlDatabase &db);
  void updateNeighborsTable(const QSqlDatabase &db);
  void updateParticipantsTable(const QSqlDatabase &db);

 private slots:
  void slotAcceptPublicizedListeners(void);
  void slotActivateKernel(void);
  void slotAddBootstrapper(void);
  void slotAddListener(void);
  void slotAddFriendsKey(void);
  void slotAddNeighbor(void);
  void slotBlockNeighbor(void);
  void slotBuzzChanged(void);
  void slotCallParticipant(void);
  void slotChatSendMethodChanged(int index);
  void slotClearOutgoingMessage(void);
  void slotCloseBuzzTab(int index);
  void slotCongestionControl(bool state);
  void slotConnectNeighbor(void);
  void slotCopyFriendshipBundle(void);
  void slotCopyMyPublicKey(void);
  void slotCopyMyURLPublicKey(void);
  void slotCostChanged(int value);
  void slotCountriesToggleOff(void);
  void slotCountriesToggleOn(void);
  void slotCountryChanged(QListWidgetItem *item);
  void slotDaysChanged(int value);
  void slotDeactivateKernel(void);
  void slotDeleteAllBlockedNeighbors(void);
  void slotDeleteAllListeners(void);
  void slotDeleteAllNeighbors(void);
  void slotDeleteAllUuids(void);
  void slotDeleteListener(void);
  void slotDeleteMail(void);
  void slotDeleteNeighbor(void);
  void slotDetachListenerNeighbors(void);
  void slotDisconnectListenerNeighbors(void);
  void slotDisconnectNeighbor(void);
  void slotDisplayLocalSearchResults(void);
  void slotDoSearch(void);
  void slotEmptyTrash(void);
  void slotEnableRetrieveMail(void);
  void slotEnabledPostOffice(bool state);
  void slotFetchMoreAlgo(void);
  void slotFetchMoreButton(void);
  void slotGeminiChanged(QTableWidgetItem *item);
  void slotGeneralTimerTimeout(void);
  void slotGenerateGoldBug(void);
  void slotGenerateGeminiInChat(void);
  void slotKeepCopy(bool state);
  void slotKeepOnlyUserDefinedNeighbors(bool state);
  void slotKernelKeySizeChanged(const QString &text);
  void slotKernelLogEvents(bool state);
  void slotKernelSocketError(QAbstractSocket::SocketError error);
  void slotKernelSocketSslErrors(const QList<QSslError> &errors);
  void slotKernelSocketState(void);
  void slotKernelStatus(void);
  void slotHideOfflineParticipants(bool state);
  void slotJoinBuzzChannel(void);
  void slotListenerCheckChange(int state);
  void slotListenerFullEcho(void);
  void slotListenerHalfEcho(void);
  void slotListenerIPComboChanged(int index);
  void slotMailSelected(QTableWidgetItem *item);
  void slotMailTabChanged(int index);
  void slotMaximumClientsChanged(int index);
  void slotMessagingCachePurge(void);
  void slotModeChanged(QSslSocket::SslMode mode);
  void slotNeighborCheckChange(int state);
  void slotNeighborFullEcho(void);
  void slotNeighborHalfEcho(void);
  void slotNeighborMaximumChanged(int value);
  void slotPopulateCountries(void);
  void slotPopulateListeners(void);
  void slotPopulateNeighbors(void);
  void slotPopulateParticipants(void);
  void slotProtocolRadioToggled(bool state);
  void slotProxyChecked(bool state);
  void slotProxyTypeChanged(int index);
  void slotPublicizeAllListenersPlaintext(void);
  void slotPublicizeListenerPlaintext(void);
  void slotPublishPeriodicallyToggled(bool sate);
  void slotPublishedKeySizeChanged(const QString &text);
  void slotQuit(void);
  void slotReceivedKernelMessage(void);
  void slotRefreshMail(void);
  void slotRefreshPostOffice(void);
  void slotRemoveParticipants(void);
  void slotReply(void);
  void slotResetAll(void);
  void slotRetrieveMail(void);
  void slotSaveBuzzName(void);
  void slotSaveGeoIPPath(void);
  void slotSaveKernelPath(void);
  void slotSaveNodeName(void);
  void slotScramble(bool state);
  void slotSelectGeoIPPath(void);
  void slotSelectKernelPath(void);
  void slotSendMail(void);
  void slotSendMessage(void);
  void slotSetIcons(void);
  void slotSetPassphrase(void);
  void slotSharePublicKey(void);
  void slotSharePublicKeyWithParticipant(void);
  void slotShareURLPublicKey(void);
  void slotShowContextMenu(const QPoint &point);
  void slotSignatureCheckBoxToggled(bool state);
  void slotStatusButtonClicked(void);
  void slotStatusChanged(int index);
  void slotSuperEcho(bool state);
  void slotTabChanged(int index);
  void slotUnblockNeighbor(void);
  void slotValidatePassphrase(void);
  void slotViewDocumentation(void);
  void slotViewLog(void);

 signals:
  void iconsChanged(void);
};

#endif
