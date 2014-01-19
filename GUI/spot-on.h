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
#include <QHash>
#include <QInputDialog>
#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
#include <QMacStyle>
#endif
#endif
#include <QMainWindow>
#include <QMessageBox>
#ifdef Q_OS_WIN32
#include <qt_windows.h>
#include <QtNetwork>
#else
#include <QNetworkInterface>
#endif
#include <QPointer>
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
#include "Common/spot-on-external-address.h"
#include "Common/spot-on-misc.h"
#include "Common/spot-on-send.h"
#include "spot-on-chatwindow.h"
#include "spot-on-logviewer.h"
#include "spot-on-reencode.h"
#include "spot-on-rosetta.h"
#include "ui_controlcenter.h"
#include "ui_statusbar.h"

class spoton: public QMainWindow
{
  Q_OBJECT

 public:
  spoton(void);
  ~spoton();
  QHash<QString, QVariant> m_settings;
  QHash<int, quint64> m_chatSequenceNumbers;
  Ui_spoton_mainwindow ui(void) const;
  static QPointer<spoton> s_gui;

 private:
  static const int APPLY_GOLDBUG_TO_INBOX_ERROR_GENERAL = 1;
  static const int APPLY_GOLDBUG_TO_INBOX_ERROR_MEMORY = 2;
  QByteArray m_kernelSocketData;
  QDateTime m_buzzFavoritesLastModificationTime;
  QDateTime m_magnetsLastModificationTime;
  QDateTime m_kernelStatisticsLastModificationTime;
  QDateTime m_listenersLastModificationTime;
  QDateTime m_neighborsLastModificationTime;
  QDateTime m_participantsLastModificationTime;
  QDateTime m_starsLastModificationTime;
  QHash<QByteArray, QString> m_neighborToOidMap;
  QHash<QByteArray, quint64> m_receivedChatSequenceNumbers;
  QHash<QString, QByteArray> m_buzzIds;
  QHash<QString, QPointer<spoton_chatwindow> > m_chatWindows;
  QHash<QString, bool> m_booleans;
  QHash<QString, spoton_crypt *> m_crypts;
#ifdef SPOTON_LINKED_WITH_LIBPHONON
#if 0
  Phonon::MediaObject *m_mediaObject;
#endif
#endif
  QSslSocket m_kernelSocket;
  QTimer m_buzzStatusTimer;
  QTimer m_chatInactivityTimer;
  QTimer m_emailRetrievalTimer;
  QTimer m_externalAddressDiscovererTimer;
  QTimer m_generalTimer;
  QTimer m_tableTimer;
  QWidget *m_sbWidget;
  Ui_statusbar m_sb;
  Ui_spoton_mainwindow m_ui;
  spoton_external_address *m_externalAddress;
  spoton_logviewer m_logViewer;
  spoton_rosetta m_rosetta;
  QByteArray copyMyChatPublicKey(void) const;
  QByteArray copyMyEmailPublicKey(void) const;
  QByteArray copyMyRosettaPublicKey(void) const;
  QByteArray copyMyUrlPublicKey(void) const;
  QPixmap pixmapForCountry(const QString &country) const;
#ifdef Q_OS_MAC
#if QT_VERSION >= 0x050000
  bool event(QEvent *event);
#endif
#endif
  bool isKernelActive(void) const;
  bool saveGemini(const QPair<QByteArray, QByteArray> &gemini,
		  const QString &oid);
  bool updateMailStatus(const QString &oid, const QString &status);
  int applyGoldbugToInboxLetter(const QByteArray &goldbug,
				const int row);
  void addFriendsKey(const QByteArray &key);
  void authenticate(spoton_crypt *crypt, const QString &oid,
		    const QString &message = QString(""));
  void askKernelToReadStarBeamKeys(void);
  void authenticationRequested(const QByteArray &data);
  void changeEchoMode(const QString &mode, QTableWidget *tableWidget);
  void closeEvent(QCloseEvent *event);
  void demagnetize(void);
  void highlightPaths(void);
  void initializeKernelSocket(void);
  void magnetize(void);
  void prepareContextMenuMirrors(void);
  void prepareListenerIPCombo(void);
  void populateAccounts(const QString &listenerOid);
  void populateListenerIps(const QString &listenerOid);
  void populateNovas(void);
  void removeFavorite(const bool removeAll);
  void saveDestination(const QString &path);
  void saveGeoIPPath(const QString &path);
  void saveKernelPath(const QString &path);
  void saveSettings(void);
  void sendBuzzKeysToKernel(void);
  void sendKeysToKernel(void);
  void sharePublicKeyWithParticipant(const QString &keyType);
  void updateListenersTable(const QSqlDatabase &db);
  void updateNeighborsTable(const QSqlDatabase &db);
  void updateParticipantsTable(const QSqlDatabase &db);
  void updatePublicKeysLabel(void);

 private slots:
  void slotAcceptBuzzMagnets(bool state);
  void slotAcceptChatKeys(bool state);
  void slotAcceptEmailKeys(bool state);
  void slotAcceptPublicizedListeners(void);
  void slotAcceptUrlKeys(bool state);
  void slotActivateKernel(void);
  void slotAddAcceptedIP(void);
  void slotAddAccount(void);
  void slotAddBootstrapper(void);
  void slotAddEtpMagnet(void);
  void slotAddListener(void);
  void slotAddFriendsKey(void);
  void slotAddNeighbor(void);
  void slotAddReceiveNova(void);
  void slotAuthenticate(void);
  void slotAuthenticationRequestButtonClicked(void);
  void slotAutoRetrieveEmail(bool state);
  void slotBlockNeighbor(void);
  void slotBuzzActionsActivated(int index);
  void slotBuzzChanged(void);
  void slotBuzzTools(int index);
  void slotCallParticipant(void);
  void slotChangeTabPosition(void);
  void slotChatInactivityTimeout(void);
  void slotChatSendMethodChanged(int index);
  void slotChatWindowDestroyed(void);
  void slotChatWindowMessageSent(void);
  void slotClearOutgoingMessage(void);
  void slotCloseBuzzTab(int index);
  void slotComputeFileHash(void);
  void slotConnectNeighbor(void);
  void slotCopyAllMyPublicKeys(void);
  void slotCopyEmailFriendshipBundle(void);
  void slotCopyEmailKeys(void);
  void slotCopyEtpMagnet(void);
  void slotCopyFileHash(void);
  void slotCopyFriendshipBundle(void);
  void slotCopyMyChatPublicKey(void);
  void slotCopyMyEmailPublicKey(void);
  void slotCopyMyRosettaPublicKey(void);
  void slotCopyMyURLPublicKey(void);
  void slotCopyOrPaste(void);
  void slotCopyTransmittedMagnet(void);
  void slotCopyUrlFriendshipBundle(void);
  void slotCostChanged(int value);
  void slotDaysChanged(int value);
  void slotDeactivateKernel(void);
  void slotDeleteAccepedIP(void);
  void slotDeleteAccount(void);
  void slotDeleteAllBlockedNeighbors(void);
  void slotDeleteAllListeners(void);
  void slotDeleteAllNeighbors(void);
  void slotDeleteAllReceived(void);
  void slotDeleteAllTransmitted(void);
  void slotDeleteAllUuids(void);
  void slotDeleteEtpAllMagnets(void);
  void slotDeleteEtpMagnet(void);
  void slotDeleteListener(void);
  void slotDeleteMail(void);
  void slotDeleteNeighbor(void);
  void slotDeleteNova(void);
  void slotDeleteReceived(void);
  void slotDeleteTransmitted(void);
  void slotDetachListenerNeighbors(void);
  void slotDisconnectListenerNeighbors(void);
  void slotDisconnectNeighbor(void);
  void slotDiscoverExternalAddress(void);
  void slotDisplayLocalSearchResults(void);
  void slotDoSearch(void);
  void slotEmptyTrash(void);
  void slotEnableRetrieveMail(void);
  void slotEnabledPostOffice(bool state);
  void slotExportListeners(void);
  void slotExportPublicKeys(void);
  void slotExternalIp(int index);
  void slotFavoritesActivated(int index);
  void slotFetchMoreAlgo(void);
  void slotFetchMoreButton(void);
  void slotForceKernelRegistration(bool state);
  void slotGeminiChanged(QTableWidgetItem *item);
  void slotGenerateEtpKeys(int index);
  void slotGeneralTimerTimeout(void);
  void slotGenerateGoldBug(void);
  void slotGenerateGeminiInChat(void);
  void slotGenerateNova(void);
  void slotKeepCopy(bool state);
  void slotKeepOnlyUserDefinedNeighbors(bool state);
  void slotKernelCipherTypeChanged(int index);
  void slotKernelKeySizeChanged(const QString &text);
  void slotKernelLogEvents(bool state);
  void slotKernelSocketError(QAbstractSocket::SocketError error);
  void slotKernelSocketSslErrors(const QList<QSslError> &errors);
  void slotKernelSocketState(void);
  void slotKernelStatus(void);
  void slotHideOfflineParticipants(bool state);
  void slotImpersonate(bool state);
  void slotImportNeighbors(void);
  void slotImportPublicKeys(void);
  void slotJoinBuzzChannel(void);
  void slotListenerCheckChange(bool state);
  void slotListenerFullEcho(void);
  void slotListenerHalfEcho(void);
  void slotListenerIPComboChanged(int index);
  void slotListenerMaximumChanged(int value);
  void slotListenerSelected(void);
  void slotListenerUseAccounts(bool state);
  void slotMailRetrievalIntervalChanged(int value);
  void slotMailSelected(QTableWidgetItem *item);
  void slotMailTabChanged(int index);
  void slotMaxMosaicSize(int value);
  void slotMaximumClientsChanged(int index);
  void slotModeChanged(QSslSocket::SslMode mode);
  void slotNeighborCheckChange(bool state);
  void slotNeighborFullEcho(void);
  void slotNeighborHalfEcho(void);
  void slotNeighborMaximumChanged(int value);
  void slotNeighborSelected(void);
  void slotParticipantDoubleClicked(QTableWidgetItem *item);
  void slotPopulateBuzzFavorites(void);
  void slotPopulateEtpMagnets(void);
  void slotPopulateKernelStatistics(void);
  void slotPopulateListeners(void);
  void slotPopulateNeighbors(void);
  void slotPopulateParticipants(void);
  void slotPopulateStars(void);
  void slotProtocolRadioToggled(bool state);
  void slotProxyChecked(bool state);
  void slotProxyTypeChanged(int index);
  void slotPublicizeAllListenersPlaintext(void);
  void slotPublicizeListenerPlaintext(void);
  void slotPublishPeriodicallyToggled(bool sate);
  void slotPublishedKeySizeChanged(const QString &text);
  void slotQuit(void);
  void slotReceivedKernelMessage(void);
  void slotReceiversClicked(bool state);
  void slotRefreshMail(void);
  void slotRefreshPostOffice(void);
  void slotRegenerateKey(void);
  void slotRemoveEmailParticipants(void);
  void slotRemoveParticipants(void);
  void slotRemoveUrlParticipants(void);
  void slotReply(void);
  void slotResetAccountInformation(void);
  void slotResetAll(void);
  void slotResetCertificate(void);
  void slotRetrieveMail(void);
  void slotRewindFile(void);
  void slotSaveBuzzName(void);
  void slotSaveDestination(void);
  void slotSaveEmailName(void);
  void slotSaveGeoIPPath(void);
  void slotSaveKernelPath(void);
  void slotSaveNodeName(void);
  void slotSaveSslControlString(void);
  void slotSaveUrlName(void);
  void slotScramble(bool state);
  void slotSecureMemoryPoolChanged(int value);
  void slotSelectDestination(void);
  void slotSelectGeoIPPath(void);
  void slotSelectKernelPath(void);
  void slotSelectTransmitFile(void);
  void slotSendMail(void);
  void slotSendMessage(void);
  void slotSetIcons(void);
  void slotSetPassphrase(void);
  void slotShareBuzzMagnet(void);
  void slotShareChatPublicKey(void);
  void slotShareChatPublicKeyWithParticipant(void);
  void slotShareEmailPublicKey(void);
  void slotShareEmailPublicKeyWithParticipant(void);
  void slotShareUrlPublicKeyWithParticipant(void);
  void slotShareURLPublicKey(void);
  void slotShowContextMenu(const QPoint &point);
  void slotShowEtpMagnetsMenu(const QPoint &point);
  void slotShowStatistics(void);
  void slotSignatureCheckBoxToggled(bool state);
  void slotStarOTMCheckChange(bool state);
  void slotStatusButtonClicked(void);
  void slotStatusChanged(int index);
  void slotSuperEcho(bool state);
  void slotTabChanged(int index);
  void slotTestSslControlString(void);
  void slotTransmit(void);
  void slotTransmittedPaused(bool state);
  void slotTransmittedSelected(void);
  void slotTransportChanged(int index);
  void slotUnblockNeighbor(void);
  void slotValidatePassphrase(void);
  void slotViewLog(void);
  void slotViewRosetta(void);

 signals:
  void buzzNameChanged(const QByteArray &name);
  void iconsChanged(void);
  void statusChanged(const QIcon &icon,
		     const QString &name,
		     const QString &id);
};

#endif
