/*
** Copyright (c) 2011, 2012, 2013 Alexis Megas
** All rights reserved.
**
** Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions
** are met
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

#include "spot-on.h"
#include "spot-on-buzzpage.h"
#include "ui_passwordprompt.h"

int main(int argc, char *argv[])
{
#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
  QApplication::setStyle(new QMacStyle());
#else
  QApplication::setStyle("fusion");
#endif
#endif

  QApplication qapplication(argc, argv);

#ifdef Q_OS_MAC
#if QT_VERSION >= 0x050000
  /*
  ** Eliminate pool errors on OS X.
  */

  CocoaInitializer ci;
#endif
#endif

  /*
  ** Configure translations.
  */

  QTranslator qtTranslator;

  qtTranslator.load("qt_" + QLocale::system().name(), "Translations");
  qapplication.installTranslator(&qtTranslator);

  QTranslator myappTranslator;

  myappTranslator.load("spot-on_" + QLocale::system().name(),
		       "Translations");
  qapplication.installTranslator(&myappTranslator);
  QCoreApplication::setApplicationName("Spot-On");
  QCoreApplication::setOrganizationName("Spot-On");
  QCoreApplication::setOrganizationDomain("spot-on.sf.net");
  QCoreApplication::setApplicationVersion(SPOTON_VERSION_STR);
  QSettings::setPath(QSettings::IniFormat, QSettings::UserScope,
                     spoton_misc::homePath());
  QSettings::setDefaultFormat(QSettings::IniFormat);

  QSettings settings;

  if(!settings.contains("gui/gcryctl_init_secmem"))
    settings.setValue("gui/gcryctl_init_secmem", 65536);

  Q_UNUSED(new spoton());
  return qapplication.exec();
}

spoton::spoton(void):QMainWindow()
{
  qsrand(QTime(0, 0, 0).secsTo(QTime::currentTime()));
  QDir().mkdir(spoton_misc::homePath());
  m_booleans["buzz_channels_sent_to_kernel"] = false;
  m_booleans["keys_sent_to_kernel"] = false;
  m_buzzStatusTimer.setInterval(15000);
  m_externalAddress = new spoton_external_address(this);
  m_acceptedIPsLastModificationTime = QDateTime();
  m_countriesLastModificationTime = QDateTime();
  m_listenersLastModificationTime = QDateTime();
  m_neighborsLastModificationTime = QDateTime();
  m_participantsLastModificationTime = QDateTime();
  m_ui.setupUi(this);

  bool sslSupported = QSslSocket::supportsSsl();

  m_ui.buildInformation->setText
    (QString("%1.\n"
	     "Qt %2, %3-bit.\n"
	     "gcrypt %4.").
     arg(sslSupported ?
	 SSLeay_version(SSLEAY_VERSION) : "OpenSSL is not supported").
     arg(QT_VERSION_STR).arg(sizeof(void *) * 8).
     arg(GCRYPT_VERSION));
#ifndef SPOTON_LINKED_WITH_LIBGEOIP
  m_ui.countries->setEnabled(false);
  m_ui.countries->setToolTip(tr("Spot-On was configured without "
				"libGeoIP."));
  m_ui.countriesRadio->setToolTip(tr("Spot-On was configured without "
				     "libGeoIP."));
  m_ui.countriesToggle->setEnabled(false);
  m_ui.countriesToggle->setToolTip(tr("Spot-On was configured without "
				      "libGeoIP."));
  m_ui.geoipPath->setEnabled(false);
  m_ui.geoipPath->setToolTip(tr("Spot-On was configured without "
				"libGeoIP."));
  m_ui.selectGeoIP->setEnabled(false);
  m_ui.selectGeoIP->setToolTip(tr("Spot-On was configured without "
				  "libGeoIP."));
#endif
#ifndef SPOTON_LINKED_WITH_LIBPHONON
#if 0
  m_ui.buzzSound->setEnabled(false);
  m_ui.buzzSound->setToolTip(tr("Spot-On was configured without "
				"libphoton."));
  m_ui.chatSound->setEnabled(false);
  m_ui.chatSound->setToolTip(tr("Spot-On was configured without "
				"libphoton."));
#endif
#else
#if 0
  m_mediaObject = new Phonon::MediaObject(this);
#endif
#endif
#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
  setAttribute(Qt::WA_MacMetalStyle, true);
#endif
#endif
  m_sbWidget = new QWidget(this);
  m_sb.setupUi(m_sbWidget);
  m_sb.buzz->setVisible(false);
  m_sb.chat->setVisible(false);
  m_sb.email->setVisible(false);
#ifdef Q_OS_MAC
  foreach(QToolButton *toolButton, m_sbWidget->findChildren<QToolButton *> ())
    toolButton->setStyleSheet
    ("QToolButton {border: none;}"
     "QToolButton::menu-button {border: none;}");
#endif
  connect(this,
	  SIGNAL(iconsChanged(void)),
	  &m_logViewer,
	  SLOT(slotSetIcons(void)));
  connect(m_sb.buzz,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotStatusButtonClicked(void)));
  connect(m_sb.chat,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotStatusButtonClicked(void)));
  connect(m_sb.email,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotStatusButtonClicked(void)));
  connect(m_sb.listeners,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotStatusButtonClicked(void)));
  connect(m_sb.neighbors,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotStatusButtonClicked(void)));
  connect(m_sb.errorlog,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotViewLog(void)));
  connect(m_sb.kernelstatus,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotKernelStatus(void)));
  statusBar()->addPermanentWidget(m_sbWidget, 100);
  statusBar()->setStyleSheet("QStatusBar::item {"
			     "border: none; "
			     "}");
  statusBar()->setMaximumHeight(m_sbWidget->height());
  connect(m_ui.action_Quit,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotQuit(void)));
  connect(m_ui.action_Log_Viewer,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotViewLog(void)));
  connect(m_ui.addListener,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotAddListener(void)));
  connect(m_ui.addNeighbor,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotAddNeighbor(void)));
  connect(m_ui.dynamicdns,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotProtocolRadioToggled(bool)));
  connect(m_ui.ipv4Listener,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotProtocolRadioToggled(bool)));
  connect(m_ui.ipv4Neighbor,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotProtocolRadioToggled(bool)));
  connect(m_ui.ipv6Listener,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotProtocolRadioToggled(bool)));
  connect(m_ui.ipv6Neighbor,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotProtocolRadioToggled(bool)));
  connect(m_ui.activateKernel,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotActivateKernel(void)));
  connect(m_ui.deactivateKernel,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotDeactivateKernel(void)));
  connect(m_ui.selectGeoIP,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSelectGeoIPPath(void)));
  connect(m_ui.selectKernelPath,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSelectKernelPath(void)));
  connect(m_ui.setPassphrase,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSetPassphrase(void)));
  connect(m_ui.geoipPath,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotSaveGeoIPPath(void)));
  connect(m_ui.kernelPath,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotSaveKernelPath(void)));
  connect(m_ui.passphrase,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotValidatePassphrase(void)));
  connect(m_ui.passphraseButton,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotValidatePassphrase(void)));
  connect(m_ui.tab,
	  SIGNAL(currentChanged(int)),
	  this,
	  SLOT(slotTabChanged(int)));
  connect(m_ui.sendMessage,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSendMessage(void)));
  connect(m_ui.message,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotSendMessage(void)));
  connect(m_ui.clearMessages,
	  SIGNAL(clicked(void)),
	  m_ui.messages,
	  SLOT(clear(void)));
  connect(m_ui.saveBuzzName,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSaveBuzzName(void)));
  connect(m_ui.saveNodeName,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSaveNodeName(void)));
  connect(m_ui.saveEmailName,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSaveEmailName(void)));
  connect(m_ui.buzzName,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotSaveBuzzName(void)));
  connect(m_ui.nodeName,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotSaveNodeName(void)));
  connect(m_ui.emailName,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotSaveEmailName(void)));
  connect(m_ui.scrambler,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotScramble(bool)));
  connect(m_ui.action_Documentation,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotViewDocumentation(void)));
  connect(m_ui.listenerIP,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotAddListener(void)));
  connect(m_ui.neighborIP,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotAddNeighbor(void)));
  connect(m_ui.listenerIPCombo,
	  SIGNAL(currentIndexChanged(int)),
	  this,
	  SLOT(slotListenerIPComboChanged(int)));
  connect(m_ui.folder,
	  SIGNAL(currentIndexChanged(int)),
	  this,
	  SLOT(slotRefreshMail(void)));
  connect(m_ui.chatSendMethod,
	  SIGNAL(currentIndexChanged(int)),
	  this,
	  SLOT(slotChatSendMethodChanged(int)));
  connect(m_ui.status,
	  SIGNAL(currentIndexChanged(int)),
	  this,
	  SLOT(slotStatusChanged(int)));
  connect(m_ui.kernelCipherType,
	  SIGNAL(currentIndexChanged(int)),
	  this,
	  SLOT(slotKernelCipherTypeChanged(int)));
  connect(m_ui.addFriend,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotAddFriendsKey(void)));
  connect(m_ui.clearFriend,
	  SIGNAL(clicked(void)),
	  m_ui.friendInformation,
	  SLOT(clear(void)));
  connect(m_ui.action_ResetSpotOn,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotResetAll(void)));
  connect(m_ui.resetSpotOn,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotResetAll(void)));
  connect(m_ui.sendMail,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSendMail(void)));
  connect(m_ui.participants,
	  SIGNAL(itemChanged(QTableWidgetItem *)),
	  this,
	  SLOT(slotGeminiChanged(QTableWidgetItem *)));
  connect(m_ui.generateGoldBug,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotGenerateGoldBug(void)));
  connect(m_ui.acceptPublishedConnected,
	  SIGNAL(pressed(void)),
	  this,
	  SLOT(slotAcceptPublicizedListeners(void)));
  connect(m_ui.acceptPublishedDisconnected,
	  SIGNAL(pressed(void)),
	  this,
	  SLOT(slotAcceptPublicizedListeners(void)));
  connect(m_ui.ignorePublished,
	  SIGNAL(pressed(void)),
	  this,
	  SLOT(slotAcceptPublicizedListeners(void)));
  connect(m_ui.keepOnlyUserDefinedNeighbors,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotKeepOnlyUserDefinedNeighbors(bool)));
  connect(m_ui.pushButtonClearMail,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotClearOutgoingMessage(void)));
  connect(m_ui.pushButtonClearMail,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotDeleteMail(void)));
  connect(m_ui.refreshMail,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotRefreshMail(void)));
  connect(m_ui.refreshMail,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotRefreshPostOffice(void)));
  connect(m_ui.mail,
	  SIGNAL(itemClicked(QTableWidgetItem *)),
	  this,
	  SLOT(slotMailSelected(QTableWidgetItem *)));
  connect(m_ui.neighbors,
	  SIGNAL(itemSelectionChanged(void)),
	  this,
	  SLOT(slotNeighborSelected(void)));
  connect(m_ui.listeners,
	  SIGNAL(itemSelectionChanged(void)),
	  this,
	  SLOT(slotListenerSelected(void)));
  connect(m_ui.emptyTrash,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotEmptyTrash(void)));
  connect(m_ui.retrieveMail,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotRetrieveMail(void)));
  connect(m_ui.mailTab,
	  SIGNAL(currentChanged(int)),
	  this,
	  SLOT(slotMailTabChanged(int)));
  connect(m_ui.postofficeCheckBox,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotEnabledPostOffice(bool)));
  connect(m_ui.saveCopy,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotKeepCopy(bool)));
  connect(m_ui.actionNouve,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotSetIcons(void)));
  connect(m_ui.actionNuvola,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotSetIcons(void)));
  connect(m_ui.action_East,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotChangeTabPosition(void)));
  connect(m_ui.action_North,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotChangeTabPosition(void)));
  connect(m_ui.action_West,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotChangeTabPosition(void)));
  connect(m_ui.newKeys,
	  SIGNAL(toggled(bool)),
	  m_ui.keySize,
	  SLOT(setEnabled(bool)));
  connect(m_ui.newKeys,
	  SIGNAL(toggled(bool)),
	  m_ui.encryptionKeyType,
	  SLOT(setEnabled(bool)));
  connect(m_ui.newKeys,
	  SIGNAL(toggled(bool)),
	  m_ui.signatureKeyType,
	  SLOT(setEnabled(bool)));
  connect(m_ui.countriesRadio,
	  SIGNAL(toggled(bool)),
	  m_ui.approvedCountries,
	  SLOT(setEnabled(bool)));
  connect(m_ui.acceptedIPsRadio,
	  SIGNAL(toggled(bool)),
	  m_ui.approvedIPs,
	  SLOT(setEnabled(bool)));
  connect(m_ui.cost,
	  SIGNAL(valueChanged(int)),
	  this,
	  SLOT(slotCostChanged(int)));
  connect(m_ui.days,
	  SIGNAL(valueChanged(int)),
	  this,
	  SLOT(slotDaysChanged(int)));
  connect(m_ui.reply,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotReply(void)));
  connect(m_ui.congestionControl,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotCongestionControl(bool)));
  connect(m_ui.congestionControl,
	  SIGNAL(toggled(bool)),
	  m_ui.cost,
	  SLOT(setEnabled(bool)));
  connect(m_ui.sslListener,
	  SIGNAL(toggled(bool)),
	  m_ui.listenerKeySize,
	  SLOT(setEnabled(bool)));
  connect(m_ui.sslListener,
	  SIGNAL(toggled(bool)),
	  m_ui.permanentCertificate,
	  SLOT(setEnabled(bool)));
  connect(m_ui.sslListener,
	  SIGNAL(toggled(bool)),
	  m_ui.recordIPAddress,
	  SLOT(setEnabled(bool)));
  connect(m_ui.publishPeriodically,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotPublishPeriodicallyToggled(bool)));
  connect(m_ui.hideOfflineParticipants,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotHideOfflineParticipants(bool)));
  connect(m_ui.proxyType,
	  SIGNAL(currentIndexChanged(int)),
	  this,
	  SLOT(slotProxyTypeChanged(int)));
  connect(m_ui.publishedKeySize,
	  SIGNAL(currentIndexChanged(const QString &)),
	  this,
	  SLOT(slotPublishedKeySizeChanged(const QString &)));
  connect(m_ui.kernelKeySize,
	  SIGNAL(currentIndexChanged(const QString &)),
	  this,
	  SLOT(slotKernelKeySizeChanged(const QString &)));
  connect(m_ui.superEcho,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotSuperEcho(bool)));
  connect(m_ui.kernelLogEvents,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotKernelLogEvents(bool)));
  connect(m_ui.proxy,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotProxyChecked(bool)));
  connect(m_ui.channel,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotJoinBuzzChannel(void)));
  connect(m_ui.acceptedIP,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotAddAcceptedIP(void)));
  connect(m_ui.sslControlString,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotSaveSslControlString(void)));
  connect(m_ui.saveSslControlString,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSaveSslControlString(void)));
  connect(m_ui.join,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotJoinBuzzChannel(void)));
  connect(m_ui.buzzTab,
	  SIGNAL(tabCloseRequested(int)),
	  this,
	  SLOT(slotCloseBuzzTab(int)));
  connect(m_ui.chatAcceptSigned,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotSignatureCheckBoxToggled(bool)));
  connect(m_ui.chatSignMessages,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotSignatureCheckBoxToggled(bool)));
  connect(m_ui.emailAcceptSigned,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotSignatureCheckBoxToggled(bool)));
  connect(m_ui.emailSignMessages,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotSignatureCheckBoxToggled(bool)));
  connect(m_ui.coAcceptSigned,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotSignatureCheckBoxToggled(bool)));
  connect(m_ui.acceptedIPsRadio,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotAcceptedIPs(bool)));
  connect(m_ui.addAcceptedIP,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotAddAcceptedIP(void)));
  connect(m_ui.testSslControlString,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotTestSslControlString(void)));
  connect(m_ui.addAccount,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotAddAccount(void)));
  connect(m_ui.deleteAccount,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotDeleteAccount(void)));
  connect(&m_chatInactivityTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotChatInactivityTimeout(void)));
  connect(&m_generalTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotGeneralTimerTimeout(void)));
  connect(&m_messagingCachePurgeTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotMessagingCachePurge(void)));
  connect(&m_tableTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotPopulateAcceptedIPs(void)));
  connect(&m_tableTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotPopulateCountries(void)));
  connect(&m_tableTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotPopulateListeners(void)));
  connect(&m_tableTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotPopulateNeighbors(void)));
  connect(&m_tableTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotPopulateParticipants(void)));
  connect(&m_kernelSocket,
	  SIGNAL(connected(void)),
	  this,
	  SLOT(slotKernelSocketState(void)));
  connect(&m_kernelSocket,
	  SIGNAL(disconnected(void)),
	  this,
	  SLOT(slotKernelSocketState(void)));
  connect(&m_kernelSocket,
	  SIGNAL(error(QAbstractSocket::SocketError)),
	  this,
	  SLOT(slotKernelSocketError(QAbstractSocket::SocketError)));
  connect(&m_kernelSocket,
	  SIGNAL(modeChanged(QSslSocket::SslMode)),
	  this,
	  SLOT(slotModeChanged(QSslSocket::SslMode)));
  connect(&m_kernelSocket,
	  SIGNAL(readyRead(void)),
	  this,
	  SLOT(slotReceivedKernelMessage(void)));
  connect(&m_kernelSocket,
	  SIGNAL(sslErrors(const QList<QSslError> &)),
	  this,
	  SLOT(slotKernelSocketSslErrors(const QList<QSslError> &)));
  m_sb.kernelstatus->setToolTip
    (tr("Not connected to the kernel. Is the kernel "
	"active?"));
  m_sb.listeners->setToolTip(tr("Listeners are offline."));
  m_sb.neighbors->setToolTip(tr("Neighbors are offline."));

  QMenu *menu = new QMenu(this);

  connect
    (menu->addAction(tr("Copy &Chat Public Key")),
     SIGNAL(triggered(void)), this, SLOT(slotCopyMyChatPublicKey(void)));
  connect
    (menu->addAction(tr("Copy &E-Mail Public Key")),
     SIGNAL(triggered(void)), this, SLOT(slotCopyMyEmailPublicKey(void)));
#if 0
  connect
    (menu->addAction(tr("Copy &URL Public Key")),
     SIGNAL(triggered(void)), this, SLOT(slotCopyMyURLPublicKey(void)));
#endif
  menu->addSeparator();
  connect
    (menu->addAction(tr("Copy &All Public Keys")),
     SIGNAL(triggered(void)), this, SLOT(slotCopyAllMyPublicKeys(void)));
  m_ui.toolButtonCopytoClipboard->setMenu(menu);
  menu = new QMenu(this);
  connect(menu->addAction(tr("Share &Chat Public Key")),
	  SIGNAL(triggered(void)), this, SLOT(slotShareChatPublicKey(void)));
  connect(menu->addAction(tr("Share &E-Mail Public Key")),
	  SIGNAL(triggered(void)), this, SLOT(slotShareEmailPublicKey(void)));
#if 0
  connect(menu->addAction(tr("Share &URL Public Key")),
	  SIGNAL(triggered(void)), this, SLOT(slotShareURLPublicKey(void)));
#endif
  m_ui.toolButtonMakeFriends->setMenu(menu);
  menu = new QMenu(this);
  connect(menu->addAction(tr("&Off")),
	  SIGNAL(triggered(void)), this, SLOT(slotCountriesToggleOff(void)));
  connect(menu->addAction(tr("&On")),
	  SIGNAL(triggered(void)), this, SLOT(slotCountriesToggleOn(void)));
  m_ui.countriesToggle->setMenu(menu);
  m_generalTimer.start(2500);
  m_messagingCachePurgeTimer.start(120000);
  m_chatInactivityTimer.start(120000);
  m_tableTimer.setInterval(2500);
  m_ui.ipv4Listener->setChecked(true);
  m_ui.listenerIP->setInputMask("000.000.000.000; ");
  m_ui.listenerScopeId->setEnabled(false);
  m_ui.listenerScopeIdLabel->setEnabled(false);
  m_ui.neighborIP->setInputMask("000.000.000.000; ");
  m_ui.neighborScopeId->setEnabled(false);
  m_ui.neighborScopeIdLabel->setEnabled(false);
  m_ui.emailParticipants->setStyleSheet
    ("QTableWidget {selection-background-color: lightgreen}");
  m_ui.participants->setStyleSheet
    ("QTableWidget {selection-background-color: lightgreen}");

  QSettings settings;

  if(settings.contains("gui/rsaKeySize"))
    {
      settings.setValue("gui/keySize",
			settings.value("gui/rsaKeySize"));
      settings.remove("gui/rsaKeySize");
    }

  if(!settings.contains("gui/saveCopy"))
    settings.setValue("gui/saveCopy", true);

  if(!settings.contains("gui/uuid"))
    {
      QUuid uuid(QUuid::createUuid());

      settings.setValue("gui/uuid", uuid.toString());
    }

  for(int i = 0; i < settings.allKeys().size(); i++)
    m_settings[settings.allKeys().at(i)] = settings.value
      (settings.allKeys().at(i));

  spoton_misc::correctSettingsContainer(m_settings);

  if(m_ui.menu_Icons->actions().size() == 2)
    {
      if(m_settings.value("gui/iconSet", "nouve").toString() == "nouve")
	{
	  m_ui.menu_Icons->actions().at(0)->setChecked(true);
	  m_ui.menu_Icons->actions().at(0)->trigger();
	}
      else
	{
	  m_ui.menu_Icons->actions().at(1)->setChecked(true);
	  m_ui.menu_Icons->actions().at(1)->trigger();
	}
    }

  QString str(m_settings.value("gui/tabPosition", "north").toString());

  if(str == "east")
    {
      m_ui.action_East->setChecked(true);
      m_ui.action_East->trigger();
    }
  else if(str == "west")
    {
      m_ui.action_West->setChecked(true);
      m_ui.action_West->trigger();
    }
  else
    {
      m_ui.action_North->setChecked(true);
      m_ui.action_North->trigger();
    }

  m_sb.kernelstatus->setIcon
    (QIcon(QString(":/%1/deactivate.png").
	   arg(m_settings.value("gui/iconSet", "nouve").toString())));
  m_sb.listeners->setIcon
    (QIcon(QString(":/%1/status-offline.png").
	   arg(m_settings.value("gui/iconSet", "nouve").toString())));
  m_sb.neighbors->setIcon
    (QIcon(QString(":/%1/status-offline.png").
	   arg(m_settings.value("gui/iconSet", "nouve").toString())));

  if(spoton_misc::isGnome())
    setGeometry(m_settings.value("gui/geometry").toRect());
  else
    restoreGeometry(m_settings.value("gui/geometry").toByteArray());

#ifdef SPOTON_LINKED_WITH_LIBGEOIP
  m_ui.acceptedIPsRadio->setChecked
    (m_settings.value("gui/acceptedIPs", false).toBool());
  m_ui.geoipPath->setText
    (m_settings.value("gui/geoipPath", "GeoIP.dat").toString().trimmed());
#else
  m_ui.countriesRadio->setEnabled(false);
  m_ui.acceptedIPsRadio->setChecked(true);
#endif
  m_ui.approvedCountries->setEnabled(m_ui.countriesRadio->isChecked());
  m_ui.approvedIPs->setEnabled(m_ui.acceptedIPsRadio->isChecked());

  if(m_settings.contains("gui/kernelPath") &&
     QFileInfo(m_settings.value("gui/kernelPath").toString().trimmed()).
     isExecutable())
    m_ui.kernelPath->setText(m_settings.value("gui/kernelPath").toString().
			     trimmed());
  else
    {
#ifndef Q_OS_MAC
      QString path(QCoreApplication::applicationDirPath() +
		   QDir::separator() +
#if defined(Q_OS_WIN32)
		   "Spot-On-Kernel.exe"
#else
		   "Spot-On-Kernel"
#endif
		   );

      m_ui.kernelPath->setText(path);
#endif
    }

  if(m_settings.value("gui/chatSendMethod", "Artificial_GET").
     toString() == "Artificial_GET")
    m_ui.chatSendMethod->setCurrentIndex(1);
  else
    m_ui.chatSendMethod->setCurrentIndex(0);

  if(m_settings.value("gui/encryptionKey", "rsa").toString() == "elg")
    m_ui.encryptionKeyType->setCurrentIndex(0);
  else
    m_ui.encryptionKeyType->setCurrentIndex(1);

  if(m_settings.value("gui/signatureKey", "rsa").toString() == "dsa")
    m_ui.signatureKeyType->setCurrentIndex(0);
  else
    m_ui.signatureKeyType->setCurrentIndex(1);

  QString keySize
    (m_settings.value("gui/kernelKeySize", "2048").toString());

  if(m_ui.kernelKeySize->findText(keySize) > -1)
    m_ui.kernelKeySize->setCurrentIndex
      (m_ui.kernelKeySize->findText(keySize));
  else
    m_ui.kernelKeySize->setCurrentIndex(0);

  keySize = m_settings.value("gui/publishedKeySize", "2048").toString();

  if(m_ui.publishedKeySize->findText(keySize) > -1)
    m_ui.publishedKeySize->setCurrentIndex
      (m_ui.publishedKeySize->findText(keySize));
  else
    m_ui.publishedKeySize->setCurrentIndex(0);

  QByteArray status
    (m_settings.value("gui/my_status", "Online").toByteArray());

  if(status == "Away")
    m_ui.status->setCurrentIndex(0);
  else if(status == "Busy")
    m_ui.status->setCurrentIndex(1);
  else if(status == "Offline")
    m_ui.status->setCurrentIndex(2);
  else
    m_ui.status->setCurrentIndex(3);

#ifdef SPOTON_LINKED_WITH_LIBGEOIP
  if(!m_ui.geoipPath->text().isEmpty())
    m_ui.geoipPath->setToolTip(m_ui.geoipPath->text());
#endif

  m_ui.kernelPath->setToolTip(m_ui.kernelPath->text());
  m_ui.buzzName->setMaxLength(spoton_common::NAME_MAXIMUM_LENGTH);
  m_ui.buzzName->setText
    (QString::fromUtf8(m_settings.value("gui/buzzName", "unknown").
		       toByteArray()).trimmed());
  m_ui.channel->setMaxLength
    (spoton_crypt::cipherKeyLength("aes256"));
  m_ui.emailName->setMaxLength(spoton_common::NAME_MAXIMUM_LENGTH);
  m_ui.emailName->setText
    (QString::fromUtf8(m_settings.value("gui/emailName", "unknown").
		       toByteArray()).trimmed());
  m_ui.nodeName->setMaxLength(spoton_common::NAME_MAXIMUM_LENGTH);
  m_ui.nodeName->setText
    (QString::fromUtf8(m_settings.value("gui/nodeName", "unknown").
		       toByteArray()).trimmed());
  m_ui.sslControlString->setText
    (m_settings.value("gui/sslControlString",
		      "HIGH:!aNULL:!eNULL:!3DES:!EXPORT:@STRENGTH").
     toString());
  m_ui.goldbug->setMaxLength
    (spoton_crypt::cipherKeyLength("aes256"));
  m_ui.channelType->clear();
  m_ui.channelType->addItems(spoton_crypt::cipherTypes());
  m_ui.cipherType->clear();
  m_ui.cipherType->addItems(spoton_crypt::cipherTypes());
  m_ui.kernelCipherType->insertSeparator(1);
  m_ui.kernelCipherType->addItems(spoton_crypt::cipherTypes());
  m_ui.cost->setValue(m_settings.value("gui/congestionCost", 10000).toInt());
  m_ui.days->setValue(m_settings.value("gui/postofficeDays", 1).toInt());

  QString statusControl
    (m_settings.
     value("gui/acceptPublicizedListeners",
	   "ignored").toString().toLower().trimmed());

  if(statusControl == "connected")
    {
      m_ui.acceptPublishedConnected->setChecked(true);
      m_ui.publishedKeySize->setEnabled(true);
    }
  else if(statusControl == "disconnected")
    {
      m_ui.acceptPublishedDisconnected->setChecked(true);
      m_ui.publishedKeySize->setEnabled(true);
    }
  else
    {
      m_ui.ignorePublished->setChecked(true);
      m_ui.publishedKeySize->setEnabled(false);
    }

  m_ui.congestionControl->setChecked
    (m_settings.value("gui/enableCongestionControl", true).toBool());
  m_ui.cost->setEnabled(m_ui.congestionControl->isChecked());
  m_ui.hideOfflineParticipants->setChecked
    (m_settings.value("gui/hideOfflineParticipants", false).toBool());
  m_ui.keepOnlyUserDefinedNeighbors->setChecked
    (m_settings.value("gui/keepOnlyUserDefinedNeighbors", false).toBool());
  m_ui.kernelLogEvents->setChecked
    (m_settings.value("gui/kernelLogEvents", false).toBool());
  m_ui.postofficeCheckBox->setChecked
    (m_settings.value("gui/postoffice_enabled", false).toBool());
  m_ui.publishPeriodically->setChecked
    (m_settings.value("gui/publishPeriodically", false).toBool());
  m_ui.saveCopy->setChecked
    (m_settings.value("gui/saveCopy", true).toBool());
  m_ui.scrambler->setChecked
    (m_settings.value("gui/scramblerEnabled", false).toBool());
  m_ui.superEcho->setChecked
    (m_settings.value("gui/superEcho", false).toBool());
  m_ui.chatAcceptSigned->setChecked
    (m_settings.value("gui/chatAcceptSignedMessagesOnly", true).toBool());
  m_ui.chatSignMessages->setChecked
    (m_settings.value("gui/chatSignMessages", true).toBool());
  m_ui.emailAcceptSigned->setChecked
    (m_settings.value("gui/emailAcceptSignedMessagesOnly", true).toBool());
  m_ui.emailSignMessages->setChecked
    (m_settings.value("gui/emailSignMessages", true).toBool());
  m_ui.coAcceptSigned->setChecked
    (m_settings.value("gui/coAcceptSignedMessagesOnly", true).toBool());

  /*
  ** Please don't translate n/a.
  */

  if(m_ui.channelType->count() == 0)
    m_ui.channelType->addItem("n/a");

  if(m_ui.cipherType->count() == 0)
    m_ui.cipherType->addItem("n/a");

  if(m_ui.kernelCipherType->count() <= 2)
    m_ui.kernelCipherType->addItem("n/a");

  m_ui.hashType->clear();
  m_ui.hashType->addItems(spoton_crypt::hashTypes());

  if(m_ui.hashType->count() == 0)
    m_ui.hashType->addItem("n/a");

  str = m_settings.value("gui/cipherType", "aes256").
    toString().toLower().trimmed();

  if(m_ui.cipherType->findText(str) > -1)
    m_ui.cipherType->setCurrentIndex(m_ui.cipherType->findText(str));

  str = m_settings.value("gui/kernelCipherType", "randomized").
    toString().toLower().trimmed();

  if(m_ui.kernelCipherType->findText(str) > -1)
    m_ui.kernelCipherType->setCurrentIndex
      (m_ui.kernelCipherType->findText(str));

  str = m_settings.value("gui/hashType", "sha512").
    toString().toLower().trimmed();

  if(m_ui.hashType->findText(str) > -1)
    m_ui.hashType->setCurrentIndex(m_ui.hashType->findText(str));

  m_ui.iterationCount->setValue(m_settings.value("gui/iterationCount",
						 10000).toInt());
  str = m_settings.value("gui/keySize", "3072").
    toString().toLower().trimmed();

  if(m_ui.keySize->findText(str) > -1)
    m_ui.keySize->setCurrentIndex(m_ui.keySize->findText(str));

  m_ui.saltLength->setValue(m_settings.value("gui/saltLength", 256).toInt());
  m_ui.tab->removeTab(5); // Search
  m_ui.tab->removeTab(6); // URLs

  if(spoton_crypt::passphraseSet())
    {
      m_sb.kernelstatus->setEnabled(false);
      m_sb.listeners->setEnabled(false);
      m_sb.neighbors->setEnabled(false);
      m_ui.encryptionKeyType->setEnabled(false);
      m_ui.passphrase1->setText("0000000000");
      m_ui.passphrase2->setText("0000000000");
      m_ui.keySize->setEnabled(false);
      m_ui.signatureKeyType->setEnabled(false);

      for(int i = 0; i < m_ui.tab->count(); i++)
	if(i == m_ui.tab->count() - 1)
	  {
	    m_ui.tab->blockSignals(true);
	    m_ui.tab->setCurrentIndex(i);
	    m_ui.tab->blockSignals(false);
	    m_ui.tab->setTabEnabled(i, true);
	  }
	else
	  m_ui.tab->setTabEnabled(i, false);

      m_ui.passphrase->setFocus();
    }
  else
    {
      m_sb.kernelstatus->setEnabled(false);
      m_sb.listeners->setEnabled(false);
      m_sb.neighbors->setEnabled(false);
      m_ui.encryptionKeyType->setEnabled(false);
      m_ui.newKeys->setEnabled(false);
      m_ui.passphrase->setEnabled(false);
      m_ui.passphraseButton->setEnabled(false);
      m_ui.passphraseLabel->setEnabled(false);
      m_ui.signatureKeyType->setEnabled(false);
      m_ui.newKeys->setChecked(true);
      m_ui.kernelBox->setEnabled(false);

      for(int i = 0; i < m_ui.tab->count(); i++)
	if(i == 5) // Settings
	  {
	    m_ui.tab->blockSignals(true);
	    m_ui.tab->setCurrentIndex(i);
	    m_ui.tab->blockSignals(false);
	    m_ui.tab->setTabEnabled(i, true);
	  }
	else
	  m_ui.tab->setTabEnabled(i, false);

      m_ui.passphrase1->setFocus();
    }

  if(m_settings.contains("gui/chatHorizontalSplitter"))
    m_ui.chatHorizontalSplitter->restoreState
      (m_settings.value("gui/chatHorizontalSplitter").toByteArray());

  if(m_settings.contains("gui/listenersHorizontalSplitter"))
    m_ui.listenersHorizontalSplitter->restoreState
      (m_settings.value("gui/listenersHorizontalSplitter").toByteArray());

  if(m_settings.contains("gui/neighborsVerticalSplitter"))
    m_ui.neighborsVerticalSplitter->restoreState
      (m_settings.value("gui/neighborsVerticalSplitter").toByteArray());

  if(m_settings.contains("gui/readVerticalSplitter"))
    m_ui.readVerticalSplitter->restoreState
      (m_settings.value("gui/readVerticalSplitter").toByteArray());

  if(m_settings.contains("gui/urlsVerticalSplitter"))
    m_ui.urlsVerticalSplitter->restoreState
      (m_settings.value("gui/urlsVerticalSplitter").toByteArray());

  m_ui.acceptedIPList->setContextMenuPolicy(Qt::CustomContextMenu);
  m_ui.emailParticipants->setContextMenuPolicy(Qt::CustomContextMenu);
  m_ui.listeners->setContextMenuPolicy(Qt::CustomContextMenu);
  m_ui.neighbors->setContextMenuPolicy(Qt::CustomContextMenu);
  m_ui.participants->setContextMenuPolicy(Qt::CustomContextMenu);
  connect(m_ui.acceptedIPList,
	  SIGNAL(customContextMenuRequested(const QPoint &)),
	  this,
	  SLOT(slotShowContextMenu(const QPoint &)));
  connect(m_ui.emailParticipants,
	  SIGNAL(customContextMenuRequested(const QPoint &)),
	  this,
	  SLOT(slotShowContextMenu(const QPoint &)));
  connect(m_ui.listeners,
	  SIGNAL(customContextMenuRequested(const QPoint &)),
	  this,
	  SLOT(slotShowContextMenu(const QPoint &)));
  connect(m_ui.neighbors,
	  SIGNAL(customContextMenuRequested(const QPoint &)),
	  this,
	  SLOT(slotShowContextMenu(const QPoint &)));
  connect(m_ui.participants,
	  SIGNAL(customContextMenuRequested(const QPoint &)),
	  this,
	  SLOT(slotShowContextMenu(const QPoint &)));
  m_ui.emailParticipants->setColumnHidden(1, true); // OID
  m_ui.emailParticipants->setColumnHidden(2, true); // neighbor_oid
  m_ui.emailParticipants->setColumnHidden(3, true); // public_key_hash
  m_ui.mail->setColumnHidden(4, true); // goldbug
  m_ui.mail->setColumnHidden(5, true); // message
  m_ui.mail->setColumnHidden(6, true); // message_code
  m_ui.mail->setColumnHidden(7, true); // receiver_sender_hash
  m_ui.mail->setColumnHidden(8, true); // OID
  m_ui.listeners->setColumnHidden(m_ui.listeners->columnCount() - 1,
				  true); // OID
  m_ui.neighbors->setColumnHidden
    (m_ui.neighbors->columnCount() - 1, true); // OID
  m_ui.neighbors->setColumnHidden
    (m_ui.neighbors->columnCount() - 2, true); // is_encrypted
  m_ui.participants->setColumnHidden(1, true); // OID
  m_ui.participants->setColumnHidden(2, true); // neighbor_oid
  m_ui.participants->setColumnHidden(3, true); // public_key_hash
  m_ui.participants->resizeColumnsToContents();
  m_ui.postoffice->setColumnHidden(2, true); // Recipient Hash
  m_ui.urlParticipants->setColumnHidden(1, true); // OID
  m_ui.urlParticipants->setColumnHidden(2, true); // neighbor_oid
  m_ui.urlParticipants->setColumnHidden(3, true); // public_key_hash
  m_ui.urlParticipants->setColumnHidden(4, true); // ignored
  m_ui.urlParticipants->setColumnHidden(5, true); // ignored
  m_ui.emailParticipants->horizontalHeader()->setSortIndicator
    (0, Qt::AscendingOrder);
  m_ui.mail->horizontalHeader()->setSortIndicator
    (0, Qt::AscendingOrder);
  m_ui.listeners->horizontalHeader()->setSortIndicator
    (3, Qt::AscendingOrder);
  m_ui.neighbors->horizontalHeader()->setSortIndicator
    (1, Qt::AscendingOrder);
  m_ui.participants->horizontalHeader()->setSortIndicator
    (0, Qt::AscendingOrder);
  m_ui.postoffice->horizontalHeader()->setSortIndicator
    (0, Qt::AscendingOrder);
  m_ui.urlParticipants->horizontalHeader()->setSortIndicator
    (0, Qt::AscendingOrder);
  m_ui.listenersHorizontalSplitter->setStretchFactor(0, 1);
  m_ui.listenersHorizontalSplitter->setStretchFactor(1, 0);
  m_ui.neighborsVerticalSplitter->setStretchFactor(0, 1);
  m_ui.neighborsVerticalSplitter->setStretchFactor(1, 0);
  m_ui.readVerticalSplitter->setStretchFactor(0, 1);
  m_ui.readVerticalSplitter->setStretchFactor(1, 0);
  m_ui.urlsVerticalSplitter->setStretchFactor(0, 0);
  m_ui.urlsVerticalSplitter->setStretchFactor(1, 1);
  prepareListenerIPCombo();

  /*
  ** Not wise! We may find things we're not prepared for.
  */

  foreach(QAbstractButton *button,
	  m_ui.emailParticipants->findChildren<QAbstractButton *> ())
    button->setToolTip(tr("Broadcast"));

  foreach(QAbstractButton *button,
	  m_ui.participants->findChildren<QAbstractButton *> ())
    button->setToolTip(tr("Broadcast"));

  connect(&m_externalAddressDiscovererTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotDiscoverExternalAddress(void)));
  m_externalAddress->discover();
  m_externalAddressDiscovererTimer.start(30000);
  show();
  update();
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  m_sb.status->setText(tr("Preparing databases. Please be patient."));
  m_sb.status->repaint();
  spoton_misc::prepareDatabases();
  m_sb.status->clear();
  QApplication::restoreOverrideCursor();
}

spoton::~spoton()
{
  m_messagingCacheMutex.lock();
  m_messagingCache.clear();
  m_messagingCacheMutex.unlock();
  m_future.waitForFinished();
}

void spoton::slotQuit(void)
{
  close();
}

void spoton::slotAddListener(void)
{
  if(!m_crypts.value("chat", 0))
    {
      QMessageBox::critical(this, tr("Spot-On: Error"),
			    tr("Invalid spoton_crypt object."));
      return;
    }

  spoton_misc::prepareDatabases();

  QByteArray certificate;
  QByteArray privateKey;
  QByteArray publicKey;
  QString error("");

  if(m_ui.sslListener->isChecked() &&
     m_ui.permanentCertificate->isChecked())
    {
      QHostAddress address;

      if(m_ui.recordIPAddress->isChecked())
	address = m_externalAddress->address();

      QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
      m_sb.status->setText
	(tr("Generating SSL data for listener. Please be patient."));
      QApplication::processEvents();
      spoton_crypt::generateSslKeys
	(m_ui.kernelKeySize->currentText().toInt(),
	 certificate,
	 privateKey,
	 publicKey,
	 address,
	 60 * 60 * 24 * 365 * 50, // Fifty years.
	 error);
      QApplication::restoreOverrideCursor();
      m_sb.status->clear();
    }

  QString connectionName("");
  bool ok = true;

  if(!error.isEmpty())
    {
      ok = false;
      spoton_misc::logError
	(QString("spoton::"
		 "slotAddListener(): "
		 "generateSslKeys() failure (%1).").arg(error.remove(".")));
      goto done_label;
    }

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "listeners.db");

    if(db.open())
      {
	QString ip("");

	if(m_ui.listenerIPCombo->currentIndex() == 0)
	  ip = m_ui.listenerIP->text().trimmed();
	else
	  ip = m_ui.listenerIPCombo->currentText();

	QString port(QString::number(m_ui.listenerPort->value()));
	QString protocol("");
	QString scopeId(m_ui.listenerScopeId->text().trimmed());
	QString status("online");
	QSqlQuery query(db);

	if(m_ui.ipv4Listener->isChecked())
	  protocol = "IPv4";
	else
	  protocol = "IPv6";

	query.prepare("INSERT INTO listeners "
		      "(ip_address, "
		      "port, "
		      "protocol, "
		      "scope_id, "
		      "status_control, "
		      "hash, "
		      "echo_mode, "
		      "ssl_key_size, "
		      "certificate, "
		      "private_key, "
		      "public_key) "
		      "VALUES "
		      "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");

	if(ip.isEmpty())
	  query.bindValue
	    (0, m_crypts.value("chat")->
	     encrypted(QByteArray(), &ok).toBase64());
	else
	  {
	    QStringList digits;
	    QStringList list;

	    if(protocol == "IPv4")
	      list = ip.split(".", QString::KeepEmptyParts);
	    else
	      list = ip.split(":", QString::KeepEmptyParts);

	    for(int i = 0; i < list.size(); i++)
	      digits.append(list.at(i));

	    if(protocol == "IPv4")
	      {
		ip = QString::number(digits.value(0).toInt()) + "." +
		  QString::number(digits.value(1).toInt()) + "." +
		  QString::number(digits.value(2).toInt()) + "." +
		  QString::number(digits.value(3).toInt());
		ip.remove("...");
	      }
	    else
	      {
		if(m_ui.listenerIPCombo->currentIndex() == 0)
		  {
		    ip = digits.value(0) + ":" +
		      digits.value(1) + ":" +
		      digits.value(2) + ":" +
		      digits.value(3) + ":" +
		      digits.value(4) + ":" +
		      digits.value(5) + ":" +
		      digits.value(6) + ":" +
		      digits.value(7);
		    ip.remove(":::::::");

		    /*
		    ** Special exception.
		    */

		    if(ip == "0:0:0:0:0:0:0:0")
		      ip = "::";
		  }
	      }

	    if(ok)
	      query.bindValue
		(0, m_crypts.value("chat")->
		 encrypted(ip.toLatin1(), &ok).toBase64());
	  }

	if(ok)
	  query.bindValue
	    (1, m_crypts.value("chat")->
	     encrypted(port.toLatin1(), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (2, m_crypts.value("chat")->
	     encrypted(protocol.toLatin1(), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (3, m_crypts.value("chat")->
	     encrypted(scopeId.toLatin1(), &ok).toBase64());

	query.bindValue(4, status);

	if(ok)
	  query.bindValue
	    (5, m_crypts.value("chat")->
	     keyedHash((ip + port + scopeId).toLatin1(), &ok).
	     toBase64());

	if(ok)
	  {
	    if(m_ui.listenersEchoMode->currentIndex() == 0)
	      query.bindValue
		(6, m_crypts.value("chat")->encrypted(QByteArray("full"),
						      &ok).toBase64());
	    else
	      query.bindValue
		(6, m_crypts.value("chat")->encrypted(QByteArray("half"),
						      &ok).toBase64());
	  }

	if(m_ui.sslListener->isChecked())
	  query.bindValue(7, m_ui.listenerKeySize->currentText().toInt());
	else
	  query.bindValue(7, 0);

	if(ok)
	  query.bindValue
	    (8, m_crypts.value("chat")->encrypted(certificate, &ok).
	     toBase64());

	if(ok)
	  query.bindValue
	    (9, m_crypts.value("chat")->encrypted(privateKey, &ok).
	     toBase64());

	if(ok)
	  query.bindValue
	    (10, m_crypts.value("chat")->encrypted(publicKey, &ok).
	     toBase64());

	if(ok)
	  ok = query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

 done_label:

  if(ok)
    m_ui.listenerIP->selectAll();
  else
    QMessageBox::critical(this, tr("Spot-On: Error"),
			  tr("Unable to add the specified listener. "
			     "Please enable logging via the Log Viewer "
			     "and try again."));
}

void spoton::slotAddNeighbor(void)
{
  if(!m_crypts.value("chat", 0))
    {
      QMessageBox::critical(this, tr("Spot-On: Error"),
			    tr("Invalid spoton_crypt object."));
      return;
    }

  spoton_misc::prepareDatabases();

  QString connectionName("");
  bool ok = true;

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "neighbors.db");

    if(db.open())
      {
	QString ip(m_ui.neighborIP->text().trimmed());
	QString port(QString::number(m_ui.neighborPort->value()));
	QString protocol("");
	QString proxyHostname("");
	QString proxyPassword("");
	QString proxyPort("1");
	QString proxyType("");
	QString proxyUsername("");
	QString scopeId(m_ui.neighborScopeId->text().trimmed());
	QString status("connected");
	QSqlQuery query(db);

	if(m_ui.ipv4Neighbor->isChecked())
	  protocol = "IPv4";
	else if(m_ui.ipv6Neighbor->isChecked())
	  protocol = "IPv6";
	else
	  protocol = "Dynamic DNS";

	query.prepare("INSERT INTO neighbors "
		      "(local_ip_address, "
		      "local_port, "
		      "protocol, "
		      "remote_ip_address, "
		      "remote_port, "
		      "sticky, "
		      "scope_id, "
		      "hash, "
		      "status_control, "
		      "country, "
		      "remote_ip_address_hash, "
		      "qt_country_hash, "
		      "proxy_hostname, "
		      "proxy_password, "
		      "proxy_port, "
		      "proxy_type, "
		      "proxy_username, "
		      "uuid, "
		      "echo_mode, "
		      "ssl_key_size, "
		      "allow_exceptions, "
		      "peer_certificate, "
		      "ssl_required, "
		      "account_name, "
		      "account_password) "
		      "VALUES "
		      "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
		      "?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");

	query.bindValue(0, QVariant(QVariant::String));
	query.bindValue(1, QVariant(QVariant::String));
	query.bindValue
	  (2, m_crypts.value("chat")->
	   encrypted(protocol.toLatin1(), &ok).toBase64());

	if(ip.isEmpty())
	  query.bindValue
	    (3, m_crypts.value("chat")->
	     encrypted(QByteArray(), &ok).toBase64());
	else
	  {
	    if(protocol == "IPv4" || protocol == "IPv6")
	      {
		QStringList digits;
		QStringList list;

		if(protocol == "IPv4")
		  list = ip.split(".", QString::KeepEmptyParts);
		else
		  list = ip.split(":", QString::KeepEmptyParts);

		for(int i = 0; i < list.size(); i++)
		  digits.append(list.at(i));

		ip.clear();

		if(protocol == "IPv4")
		  {
		    ip = QString::number(digits.value(0).toInt()) + "." +
		      QString::number(digits.value(1).toInt()) + "." +
		      QString::number(digits.value(2).toInt()) + "." +
		      QString::number(digits.value(3).toInt());
		    ip.remove("...");
		  }
		else
		  {
		    ip = digits.value(0) + ":" +
		      digits.value(1) + ":" +
		      digits.value(2) + ":" +
		      digits.value(3) + ":" +
		      digits.value(4) + ":" +
		      digits.value(5) + ":" +
		      digits.value(6) + ":" +
		      digits.value(7);
		    ip.remove(":::::::");

		    /*
		    ** Special exception.
		    */

		    if(ip == "0:0:0:0:0:0:0:0")
		      ip = "::";
		  }
	      }

	    if(ok)
	      query.bindValue
		(3, m_crypts.value("chat")->
		 encrypted(ip.toLatin1(), &ok).toBase64());
	  }

	if(ok)
	  query.bindValue
	    (4, m_crypts.value("chat")->
	     encrypted(port.toLatin1(), &ok).toBase64());

	query.bindValue(5, 1); // Sticky.

	if(ok)
	  query.bindValue
	    (6, m_crypts.value("chat")->
	     encrypted(scopeId.toLatin1(), &ok).toBase64());

	if(m_ui.proxy->isChecked())
	  {
	    proxyHostname = m_ui.proxyHostname->text().trimmed();
	    proxyPort = QString::number(m_ui.proxyPort->value());
	  }

	if(ok)
	  query.bindValue
	    (7, m_crypts.value("chat")->
	     keyedHash((proxyHostname + proxyPort + ip + port + scopeId).
		       toLatin1(), &ok).
	     toBase64());

	query.bindValue(8, status);

	QString country(spoton_misc::countryNameFromIPAddress(ip));

	if(ok)
	  query.bindValue
	    (9, m_crypts.value("chat")->
	     encrypted(country.toLatin1(), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (10, m_crypts.value("chat")->keyedHash(ip.toLatin1(), &ok).
	     toBase64());

	if(ok)
	  query.bindValue
	    (11, m_crypts.value("chat")->
	     keyedHash(country.remove(" ").toLatin1(), &ok).
	     toBase64());

	if(m_ui.proxy->isChecked())
	  proxyPassword = m_ui.proxyPassword->text();

	if(m_ui.proxy->isChecked())
	  {
	    /*
	    ** Avoid translation mishaps.
	    */

	    if(m_ui.proxyType->currentIndex() == 0)
	      proxyType = "HTTP";
	    else if(m_ui.proxyType->currentIndex() == 1)
	      proxyType = "Socks5";
	    else
	      proxyType = "System";
	  }
	else
	  proxyType = "NoProxy";

	if(m_ui.proxy->isChecked())
	  proxyUsername = m_ui.proxyUsername->text();

	if(ok)
	  query.bindValue
	    (12, m_crypts.value("chat")->
	     encrypted(proxyHostname.toLatin1(), &ok).
	     toBase64());

	if(ok)
	  query.bindValue
	    (13, m_crypts.value("chat")->
	     encrypted(proxyPassword.toUtf8(), &ok).
	     toBase64());

	if(ok)
	  query.bindValue
	    (14, m_crypts.value("chat")->encrypted(proxyPort.toLatin1(),
						   &ok).toBase64());

	if(ok)
	  query.bindValue
	    (15, m_crypts.value("chat")->encrypted(proxyType.toLatin1(), &ok).
	     toBase64());

	if(ok)
	  query.bindValue
	    (16, m_crypts.value("chat")->encrypted(proxyUsername.toUtf8(), &ok).
	     toBase64());

	if(ok)
	  query.bindValue
	    (17, m_crypts.value("chat")->
	     encrypted(QByteArray("{00000000-0000-0000-0000-"
				  "000000000000}"), &ok).toBase64());

	if(ok)
	  {
	    if(m_ui.neighborsEchoMode->currentIndex() == 0)
	      query.bindValue
		(18, m_crypts.value("chat")->
		 encrypted(QByteArray("full"), &ok).toBase64());
	    else
	      query.bindValue
		(18, m_crypts.value("chat")->
		 encrypted(QByteArray("half"), &ok).toBase64());
	  }

	query.bindValue(19, m_ui.neighborKeySize->currentText().toInt());

	if(m_ui.addException->isChecked())
	  query.bindValue(20, 1);
	else
	  query.bindValue(20, 0);

	if(ok)
	  query.bindValue
	    (21, m_crypts.value("chat")->encrypted(QByteArray(),
						   &ok).toBase64());

	query.bindValue(22, m_ui.requireSsl->isChecked() ? 1 : 0);

	if(ok)
	  query.bindValue
	    (23, m_crypts.value("chat")->encrypted(QByteArray(),
						   &ok).toBase64());

	if(ok)
	  query.bindValue
	    (24, m_crypts.value("chat")->encrypted(QByteArray(),
						   &ok).toBase64());

	if(ok)
	  ok = query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(ok)
    m_ui.neighborIP->selectAll();
  else
    QMessageBox::critical(this, tr("Spot-On: Error"),
			  tr("Unable to add the specified neighbor. "
			     "Please enable logging via the Log Viewer "
			     "and try again."));
}

void spoton::slotHideOfflineParticipants(bool state)
{
  m_settings["gui/hideOfflineParticipants"] = state;

  QSettings settings;

  settings.setValue("gui/hideOfflineParticipants", state);
  m_participantsLastModificationTime = QDateTime();
}

void spoton::slotProtocolRadioToggled(bool state)
{
  Q_UNUSED(state);

  QRadioButton *radio = qobject_cast<QRadioButton *> (sender());

  if(!radio)
    return;

  if(radio == m_ui.dynamicdns)
    {
      m_ui.neighborIP->clear();
      m_ui.neighborIP->setInputMask("");
      m_ui.neighborScopeId->setEnabled(true);
      m_ui.neighborScopeIdLabel->setEnabled(true);
    }
  else if(radio == m_ui.ipv4Listener || radio == m_ui.ipv4Neighbor)
    {
      if(radio == m_ui.ipv4Listener)
	{
	  m_ui.listenerIP->setInputMask("000.000.000.000; ");
	  m_ui.listenerScopeId->setEnabled(false);
	  m_ui.listenerScopeIdLabel->setEnabled(false);
	}
      else
	{
	  m_ui.neighborIP->clear();
	  m_ui.neighborIP->setInputMask("000.000.000.000; ");
	  m_ui.neighborScopeId->setEnabled(false);
	  m_ui.neighborScopeIdLabel->setEnabled(false);
	}
    }
  else 
    {
      if(radio == m_ui.ipv6Listener)
	{
	  m_ui.listenerIP->setInputMask
	    ("hhhh:hhhh:hhhh:hhhh:hhhh:hhhh:hhhh:hhhh; ");
	  m_ui.listenerScopeId->setEnabled(true);
	  m_ui.listenerScopeIdLabel->setEnabled(true);
	}
      else
	{
	  m_ui.neighborIP->clear();
	  m_ui.neighborIP->setInputMask
	    ("hhhh:hhhh:hhhh:hhhh:hhhh:hhhh:hhhh:hhhh; ");
	  m_ui.neighborScopeId->setEnabled(true);
	  m_ui.neighborScopeIdLabel->setEnabled(true);
	}
    }

  prepareListenerIPCombo();
}

void spoton::slotScramble(bool state)
{
  m_settings["gui/scramblerEnabled"] = state;

  QSettings settings;

  settings.setValue("gui/scramblerEnabled", state);
}

void spoton::slotPopulateListeners(void)
{
  if(!m_crypts.value("chat", 0))
    return;

  QFileInfo fileInfo(spoton_misc::homePath() + QDir::separator() +
		     "listeners.db");

  if(fileInfo.exists())
    {
      if(fileInfo.lastModified() <= m_listenersLastModificationTime)
	return;
      else
	m_listenersLastModificationTime = fileInfo.lastModified();
    }
  else
    m_listenersLastModificationTime = QDateTime();

  QString connectionName("");
  int active = 0;

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(fileInfo.absoluteFilePath());

    if(db.open())
      {
	updateListenersTable(db);

	QModelIndexList list;
	QString ip("");
	QString port("");
	QString scopeId("");
	int columnIP = 3;
	int columnPORT = 4;
	int columnSCOPE_ID = 5;
	int hval = m_ui.listeners->horizontalScrollBar()->value();
	int row = -1;
	int vval = m_ui.listeners->verticalScrollBar()->value();

	list = m_ui.listeners->selectionModel()->selectedRows
	  (columnIP);

	if(!list.isEmpty())
	  ip = list.at(0).data().toString();

	list = m_ui.listeners->selectionModel()->selectedRows
	  (columnPORT);

	if(!list.isEmpty())
	  port = list.at(0).data().toString();

	list = m_ui.listeners->selectionModel()->selectedRows
	  (columnSCOPE_ID);

	if(!list.isEmpty())
	  scopeId = list.at(0).data().toString();

	m_ui.listeners->setSortingEnabled(false);
	m_ui.listeners->clearContents();
	m_ui.listeners->setRowCount(0);

	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec("SELECT "
		      "status_control, "
		      "status, "
		      "ssl_key_size, "
		      "ip_address, "
		      "port, "
		      "scope_id, "
		      "protocol, "
		      "external_ip_address, "
		      "external_port, "
		      "connections, "
		      "maximum_clients, "
		      "echo_mode, "
		      "use_accounts, "
		      "OID "
		      "FROM listeners WHERE status_control <> 'deleted'"))
	  {
	    row = 0;

	    while(query.next())
	      {
		m_ui.listeners->setRowCount(row + 1);

		QString tooltip("");
		bool ok = true;

		tooltip = QString
		  (tr("Status: %1\n"
		      "SSL Key Size: %2\n"
		      "Local IP: %3 Local Port: %4 Scope ID: %5\n"
		      "External IP: %6\n"
		      "Connections: %7\n"
		      "Echo Mode: %8\n"
		      "Use Accounts?: %9")).
		  arg(query.value(1).toString()).
		  arg(query.value(2).toInt()).
		  arg(m_crypts.value("chat")->
		      decrypted(QByteArray::
				fromBase64(query.
					   value(3).
					   toByteArray()),
				&ok).
		      constData()).
		  arg(m_crypts.value("chat")->
		      decrypted(QByteArray::
				fromBase64(query.
					   value(4).
					   toByteArray()),
				&ok).
		      constData()).
		  arg(m_crypts.value("chat")->
		      decrypted(QByteArray::
				fromBase64(query.
					   value(5).
					   toByteArray()),
				&ok).
		      constData()).
		  arg(m_crypts.value("chat")->
		      decrypted(QByteArray::
				fromBase64(query.
					   value(7).
					   toByteArray()),
				&ok).
		      constData()).
		  arg(query.value(9).toString()).
		  arg(m_crypts.value("chat")->
		      decrypted(QByteArray::
				fromBase64(query.
					   value(11).
					   toByteArray()),
				&ok).
		      constData()).
		  arg(query.value(12).toInt());

		for(int i = 0; i < query.record().count(); i++)
		  {
		    QCheckBox *check = 0;
		    QComboBox *box = 0;
		    QTableWidgetItem *item = 0;

		    if(i == 0 || i == 12)
		      {
			check = new QCheckBox();

			if(i == 0)
			  {
			    if(query.value(0).toString() == "online")
			      check->setChecked(true);

			    if(query.value(1).toString() == "online")
			      active += 1;
			  }
			else
			  {
			    if(query.value(2).toInt() > 0)
			      {
				if(query.value(i).toInt() == 1)
				  check->setChecked(true);
			      }
			    else
			      check->setEnabled(false);
			  }

			check->setProperty("oid", query.value(13));
			check->setProperty("table_row", row);
			check->setToolTip(tooltip);

			if(i == 0)
			  connect(check,
				  SIGNAL(stateChanged(int)),
				  this,
				  SLOT(slotListenerCheckChange(int)));
			else
			  connect(check,
				  SIGNAL(stateChanged(int)),
				  this,
				  SLOT(slotListenerUseAccounts(int)));

			m_ui.listeners->setCellWidget(row, i, check);
		      }
		    else if(i == 2)
		      {
			if(query.value(i).toInt() == 0)
			  {
			    item = new QTableWidgetItem("0");
			    item->setBackground
			      (QBrush(QColor("red")));
			  }
			else
			  {
			    item = new QTableWidgetItem
			      (query.value(i).toString());
			    item->setBackground(QBrush());
			  }
		      }
		    else if(i == 10)
		      {
			box = new QComboBox();
			box->setProperty("oid", query.value(13));
			box->setProperty("table_row", row);
			box->addItem("1");

			for(int j = 1; j <= 10; j++)
			  box->addItem(QString::number(5 * j));

			box->addItem(tr("Unlimited"));
			box->setMaximumWidth
			  (box->fontMetrics().width(tr("Unlimited")) + 50);
			box->setToolTip(tooltip);
			m_ui.listeners->setCellWidget(row, i, box);

			if(std::numeric_limits<int>::max() ==
			   query.value(i).toInt())
			  box->setCurrentIndex(box->count() - 1);
			else if(box->findText(QString::number(query.
							      value(i).
							      toInt())) >= 0)
			  box->setCurrentIndex
			    (box->findText(QString::number(query.
							   value(i).
							   toInt())));
			else
			  box->setCurrentIndex(1); // Default of five.

			connect(box,
				SIGNAL(currentIndexChanged(int)),
				this,
				SLOT(slotMaximumClientsChanged(int)));
		      }
		    else
		      {
			if((i >= 3 && i <= 7) || i == 11)
			  {
			    bool ok = true;

			    if(query.isNull(i))
			      item = new QTableWidgetItem();
			    else
			      item = new QTableWidgetItem
				(m_crypts.value("chat")->
				 decrypted(QByteArray::
					   fromBase64(query.
						      value(i).
						      toByteArray()),
					   &ok).
				 constData());
			  }
			else
			  item = new QTableWidgetItem
			    (query.value(i).toString());
		      }

		    if(item)
		      {
			item->setFlags
			  (Qt::ItemIsSelectable | Qt::ItemIsEnabled);
			item->setToolTip(tooltip);
			m_ui.listeners->setItem(row, i, item);

			if(i == 1)
			  {
			    if(query.value(i).toString() == "online")
			      item->setBackground
				(QBrush(QColor("lightgreen")));
			    else
			      item->setBackground(QBrush());
			  }
		      }
		  }

		QByteArray bytes1;
		QByteArray bytes2;
		QByteArray bytes3;
		QWidget *focusWidget = QApplication::focusWidget();

		ok = true;
		bytes1 = m_crypts.value("chat")->decrypted
		  (QByteArray::fromBase64(query.value(3).toByteArray()),
		   &ok);
		bytes2 = m_crypts.value("chat")->decrypted
		  (QByteArray::fromBase64(query.value(4).toByteArray()),
		   &ok);
		bytes3 = m_crypts.value("chat")->decrypted
		  (QByteArray::fromBase64(query.value(5).toByteArray()),
		   &ok);

		if(ip == bytes1 && port == bytes2 && scopeId == bytes3)
		  m_ui.listeners->selectRow(row);

		if(focusWidget)
		  focusWidget->setFocus();

		row += 1;
	      }
	  }

	m_ui.listeners->setSortingEnabled(true);

	for(int i = 0; i < m_ui.listeners->columnCount() - 1; i++)
	  /*
	  ** Ignore the OID column.
	  */

	  m_ui.listeners->resizeColumnToContents(i);

	m_ui.listeners->horizontalHeader()->setStretchLastSection(true);
	m_ui.listeners->horizontalScrollBar()->setValue(hval);
	m_ui.listeners->verticalScrollBar()->setValue(vval);
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(active > 0)
    {
      m_sb.listeners->setIcon
	(QIcon(QString(":/%1/status-online.png").
	       arg(m_settings.value("gui/iconSet", "nouve").toString())));
      m_sb.listeners->setToolTip
	(tr("There is (are) %1 active listener(s).").arg(active));
    }
  else
    {
      m_sb.listeners->setIcon
	(QIcon(QString(":/%1/status-offline.png").
	       arg(m_settings.value("gui/iconSet", "nouve").toString())));
      m_sb.listeners->setToolTip(tr("Listeners are offline."));
    }
}

void spoton::slotPopulateNeighbors(void)
{
  if(!m_crypts.value("chat", 0))
    return;

  QFileInfo fileInfo(spoton_misc::homePath() + QDir::separator() +
		     "neighbors.db");

  if(fileInfo.exists())
    {
      if(fileInfo.lastModified() <= m_neighborsLastModificationTime)
	return;
      else
	m_neighborsLastModificationTime = fileInfo.lastModified();
    }
  else
    m_neighborsLastModificationTime = QDateTime();

  QString connectionName("");
  int active = 0;

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(fileInfo.absoluteFilePath());

    if(db.open())
      {
	updateNeighborsTable(db);

	QModelIndexList list;
	QString proxyIp("");
	QString proxyPort("1");
	QString remoteIp("");
	QString remotePort("");
	QString scopeId("");
	int columnCOUNTRY = 9;
	int columnPROXY_IP = 14;
	int columnPROXY_PORT = 15;
	int columnREMOTE_IP = 10;
	int columnREMOTE_PORT = 11;
	int columnSCOPE_ID = 12;
	int hval = m_ui.neighbors->horizontalScrollBar()->value();
	int row = -1;
	int vval = m_ui.neighbors->verticalScrollBar()->value();

	list = m_ui.neighbors->selectionModel()->selectedRows
	  (columnPROXY_IP);

	if(!list.isEmpty())
	  proxyIp = list.at(0).data().toString();

	list = m_ui.neighbors->selectionModel()->selectedRows
	  (columnPROXY_PORT);

	if(!list.isEmpty())
	  proxyPort = list.at(0).data().toString();

	list = m_ui.neighbors->selectionModel()->selectedRows
	  (columnREMOTE_IP);

	if(!list.isEmpty())
	  remoteIp = list.at(0).data().toString();

	list = m_ui.neighbors->selectionModel()->selectedRows
	  (columnREMOTE_PORT);

	if(!list.isEmpty())
	  remotePort = list.at(0).data().toString();

	list = m_ui.neighbors->selectionModel()->selectedRows
	  (columnSCOPE_ID);

	if(!list.isEmpty())
	  scopeId = list.at(0).data().toString();

	m_ui.neighbors->setSortingEnabled(false);
	m_ui.neighbors->clearContents();
	m_ui.neighbors->setRowCount(0);

	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec("SELECT sticky, "
		      "uuid, "
		      "status, "
		      "ssl_key_size, "
		      "status_control, "
		      "local_ip_address, "
		      "local_port, "
		      "external_ip_address, "
		      "external_port, "
		      "country, "
		      "remote_ip_address, "
		      "remote_port, "
		      "scope_id, "
		      "protocol, "
		      "proxy_hostname, "
		      "proxy_port, "
		      "maximum_buffer_size, "
		      "maximum_content_length, "
		      "echo_mode, "
		      "uptime, "
		      "allow_exceptions, "
		      "peer_certificate, "
		      "bytes_read, "
		      "bytes_written, "
		      "ssl_session_cipher, "
		      "account_name, "
		      "is_encrypted, "
		      "OID "
		      "FROM neighbors WHERE status_control <> 'deleted'"))
	  {
	    QString localIp("");
	    QString localPort("");

	    row = 0;

	    while(query.next())
	      {
		m_ui.neighbors->setRowCount(row + 1);

		QByteArray certificateDigest;
		QByteArray sslSessionCipher;
		QString tooltip("");
		bool ok = true;

		certificateDigest = m_crypts.value("chat")->
		  decrypted(QByteArray::
			    fromBase64(query.
				       value(21).
				       toByteArray()),
			    &ok);

		if(ok)
		  certificateDigest = spoton_crypt::
		    sha512Hash(certificateDigest, &ok).toHex();

		if(!ok)
		  certificateDigest = "XYZ";

		sslSessionCipher = m_crypts.value("chat")->
		  decrypted(QByteArray::
			    fromBase64(query.
				       value(24).
				       toByteArray()),
			    &ok);

		tooltip =
		  (tr("UUID: %1\n"
		      "Status: %2\n"
		      "SSL Key Size: %3\n"
		      "Local IP: %4 Local Port: %5\n"
		      "External IP: %6\n"
		      "Country: %7 Remote IP: %8 Remote Port: %9 "
		      "Scope ID: %10\n"
		      "Proxy Hostname: %11 Proxy Port: %12\n"
		      "Echo Mode: %13\n"
		      "Communications Mode: %14\n"
		      "Uptime: %15 Minutes\n"
		      "Allow Certificate Exceptions: %16\n"
		      "Bytes Read: %17\n"
		      "Bytes Written: %18\n"
		      "SSL Session Cipher: %19\n"
		      "Account Name: %20")).
		  arg(m_crypts.value("chat")->
		      decrypted(QByteArray::
				fromBase64(query.
					   value(1).
					   toByteArray()),
				&ok).
		      constData()).
		  arg(query.value(2).toString()).
		  arg(query.value(3).toInt()).
		  arg(query.value(5).toString()).
		  arg(query.value(6).toString()).
		  arg(m_crypts.value("chat")->
		      decrypted(QByteArray::
				fromBase64(query.
					   value(7).
					   toByteArray()),
				&ok).
		      constData()).
		  arg(m_crypts.value("chat")->
		      decrypted(QByteArray::
				fromBase64(query.
					   value(9).
					   toByteArray()),
				&ok).
		      constData()).
		  arg(m_crypts.value("chat")->
		      decrypted(QByteArray::
				fromBase64(query.
					   value(10).
					   toByteArray()),
				&ok).
		      constData()).
		  arg(m_crypts.value("chat")->
		      decrypted(QByteArray::
				fromBase64(query.
					   value(11).
					   toByteArray()),
				&ok).
		      constData()).
		  arg(m_crypts.value("chat")->
		      decrypted(QByteArray::
				fromBase64(query.
					   value(12).
					   toByteArray()),
				&ok).
		      constData()).
		  arg(m_crypts.value("chat")->
		      decrypted(QByteArray::
				fromBase64(query.
					   value(14).
					   toByteArray()),
				&ok).
		      constData()).
		  arg(m_crypts.value("chat")->
		      decrypted(QByteArray::
				fromBase64(query.
					   value(15).
					   toByteArray()),
				&ok).
		      constData()).
		  arg(m_crypts.value("chat")->
		      decrypted(QByteArray::
				fromBase64(query.
					   value(18).
					   toByteArray()),
				&ok).
		      constData()).
		  arg(query.value(25).toInt() == 1 ?
		      "Secure" : "Insecure").
		  arg(QString::number(query.value(19).toInt() / 60.0,
				      'f', 1)).
		  arg(query.value(21).toInt() == 1 ?
		      "Yes" : "No").
		  arg(query.value(22).toULongLong()).
		  arg(query.value(23).toULongLong()).
		  arg(sslSessionCipher.constData()).
		  arg(m_crypts.value("chat")->
		      decrypted(QByteArray::
				fromBase64(query.
					   value(25).
					   toByteArray()),
				&ok).
		      constData());

		QCheckBox *check = 0;

		check = new QCheckBox();
		check->setToolTip(tr("The sticky feature enables an "
				     "indefinite lifetime for a neighbor.\n"
				     "If "
				     "not checked, the neighbor will be "
				     "terminated after some internal "
				     "timer expires."));

		if(query.value(0).toInt() == 1)
		  check->setChecked(true);
		else
		  check->setChecked(false);

		check->setProperty
		  ("oid", query.value(query.record().count() - 1));
		check->setProperty("table_row", row);
		connect(check,
			SIGNAL(stateChanged(int)),
			this,
			SLOT(slotNeighborCheckChange(int)));
		m_ui.neighbors->setCellWidget(row, 0, check);

		bool isEncrypted = query.value
		  (query.record().indexOf("is_encrypted")).toBool();

		for(int i = 1; i < query.record().count(); i++)
		  {
		    QTableWidgetItem *item = 0;

		    if(i == 2)
		      {
			if(query.value(i).toString() == "connected")
			  active += 1;
		      }

		    if(i == 1 || i == 3 ||
		       i == 7 || (i >= 9 && i <= 13) || (i >= 14 &&
							 i <= 15) ||
		       i == 18 || i == 25)
		      {
			if(query.isNull(i))
			  item = new QTableWidgetItem();
			else
			  {
			    QByteArray bytes;
			    bool ok = true;

			    if(i != 3) // SSL Key Size
			      bytes = m_crypts.value("chat")->decrypted
				(QByteArray::
				 fromBase64(query.
					    value(i).
					    toByteArray()),
				 &ok);

			    if(i == 1) // uuid
			      {
				if(bytes.isEmpty())
				  bytes =
				    "{00000000-0000-0000-0000-000000000000}";
			      }
			    else if(i == 3) // SSL Key Size
			      {
				if(query.value(i).toInt() == 0)
				  {
				    item = new QTableWidgetItem("0");
				    item->setBackground
				      (QBrush(QColor("red")));
				  }
				else
				  {
				    item = new QTableWidgetItem
				      (query.value(i).toString());
				    item->setBackground(QBrush());
				  }
			      }

			    if(i != 3) // SSL Key Size
			      item = new QTableWidgetItem(bytes.constData());
			  }
		      }
		    else if(i >= 16 && i <= 17)
		      {
			// maximum_buffer_size
			// maximum_content_length

			QSpinBox *box = new QSpinBox();

			if(i == 16)
			  {
			    box->setMaximum
			      (spoton_common::MAXIMUM_NEIGHBOR_BUFFER_SIZE);
			    box->setMinimum
			      (spoton_common::MAXIMUM_NEIGHBOR_CONTENT_LENGTH);
			  }
			else
			  box->setMaximum
			    (spoton_common::MAXIMUM_NEIGHBOR_CONTENT_LENGTH);

			box->setMaximumWidth
			  (box->fontMetrics().
			   width(QString::
				 number(spoton_common::
					MAXIMUM_NEIGHBOR_BUFFER_SIZE)) + 50);
			box->setProperty
			  ("field_name", query.record().fieldName(i));
			box->setProperty
			  ("oid", query.value(query.record().count() - 1));
			box->setProperty("table_row", row);
			box->setToolTip(tooltip);
			box->setValue(query.value(i).toInt());
			connect(box,
				SIGNAL(valueChanged(int)),
				this,
				SLOT(slotNeighborMaximumChanged(int)));
			m_ui.neighbors->setCellWidget(row, i, box);
		      }
		    else if(i == 21) // Certificate Digest
		      item = new QTableWidgetItem
			(certificateDigest.constData());
		    else if(i == 24) // SSL Session Cipher
		      item = new QTableWidgetItem
			(sslSessionCipher.constData());
		    else
		      item = new QTableWidgetItem
			(query.value(i).toString());

		    if(item)
		      {
			item->setFlags
			  (Qt::ItemIsSelectable | Qt::ItemIsEnabled);

			if(i == 2)
			  {
			    if(query.value(i).toString() == "connected")
			      item->setBackground
				(QBrush(QColor("lightgreen")));
			    else
			      item->setBackground(QBrush());

			    if(isEncrypted)
			      item->setIcon
				(QIcon(QString(":/%1/lock.png").
				       arg(m_settings.
					   value("gui/iconSet",
						 "nouve").toString())));
			  }

			item->setToolTip(tooltip);
			m_ui.neighbors->setItem(row, i, item);
		      }
		  }

		QTableWidgetItem *item1 = m_ui.neighbors->item
		  (row, columnCOUNTRY);

		if(item1)
		  {
		    QIcon icon;
		    QPixmap pixmap;
		    QString str("");
		    QTableWidgetItem *item2 = m_ui.neighbors->item
		      (row, columnREMOTE_IP);

		    if(item2)
		      str = QString(":/Flags/%1.png").
			arg(spoton_misc::
			    countryCodeFromIPAddress(item2->text()).
			    toLower());
		    else
		      str = ":/Flags/unknown.png";

		    pixmap = QPixmap(str);

		    if(!pixmap.isNull())
		      pixmap = pixmap.scaled(QSize(16, 16),
					     Qt::KeepAspectRatio,
					     Qt::SmoothTransformation);

		    if(!pixmap.isNull())
		      icon = QIcon(pixmap);

		    if(!icon.isNull())
		      item1->setIcon(icon);
		  }

		QByteArray bytes1;
		QByteArray bytes2;
		QByteArray bytes3;
		QByteArray bytes4;
		QByteArray bytes5;
		QWidget *focusWidget = QApplication::focusWidget();

		ok = true;
		bytes1 = m_crypts.value("chat")->decrypted
		  (QByteArray::fromBase64(query.value(columnREMOTE_IP).
					  toByteArray()), &ok);
		bytes2 = m_crypts.value("chat")->decrypted
		  (QByteArray::fromBase64(query.value(columnREMOTE_PORT).
					  toByteArray()), &ok);
		bytes3 = m_crypts.value("chat")->decrypted
		  (QByteArray::fromBase64(query.value(columnSCOPE_ID).
					  toByteArray()), &ok);
		bytes4 = m_crypts.value("chat")->decrypted
		  (QByteArray::fromBase64(query.value(columnPROXY_IP).
					  toByteArray()), &ok);
		bytes5 = m_crypts.value("chat")->decrypted
		  (QByteArray::fromBase64(query.value(columnPROXY_PORT).
					  toByteArray()), &ok);

		if(remoteIp == bytes1 && remotePort == bytes2 &&
		   scopeId == bytes3 && proxyIp == bytes4 &&
		   proxyPort == bytes5)
		  m_ui.neighbors->selectRow(row);

		if(focusWidget)
		  focusWidget->setFocus();

		row += 1;
	      }

	    if(row == 0)
	      m_ui.neighborSummary->clear();
	  }
	else
	  m_ui.neighborSummary->clear();

	m_ui.neighbors->setSortingEnabled(true);
	m_ui.neighbors->horizontalHeader()->setStretchLastSection(true);
	m_ui.neighbors->horizontalScrollBar()->setValue(hval);
	m_ui.neighbors->verticalScrollBar()->setValue(vval);
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(active > 0)
    {
      m_sb.neighbors->setIcon
	(QIcon(QString(":/%1/status-online.png").
	       arg(m_settings.value("gui/iconSet", "nouve").toString())));
      m_sb.neighbors->setToolTip
	(tr("There is (are) %1 connected neighbor(s).").
	 arg(active));
    }
  else
    {
      m_messagingCacheMutex.lock();
      m_messagingCache.clear();
      m_messagingCacheMutex.unlock();
      m_sb.neighbors->setIcon
	(QIcon(QString(":/%1/status-offline.png").
	       arg(m_settings.value("gui/iconSet", "nouve").toString())));
      m_sb.neighbors->setToolTip(tr("Neighbors are offline."));
    }
}

void spoton::slotActivateKernel(void)
{
  QProcess process;
  QString program(m_ui.kernelPath->text());

#ifdef Q_OS_MAC
  if(QFileInfo(program).isBundle())
    {
      QStringList list;

      list << "-a"
	   << program
	   << "-g";
      process.startDetached("open", list);
    }
  else
    process.startDetached(program);
#elif defined(Q_OS_WIN32)
  process.startDetached(QString("\"%1\"").arg(program));
#else
  process.startDetached(program);
#endif
}

void spoton::slotDeactivateKernel(void)
{
  QString sharedPath(spoton_misc::homePath() + QDir::separator() +
		     "shared.db");
  libspoton_handle_t libspotonHandle;

  if(libspoton_init_b(sharedPath.toStdString().c_str(),
		      0,
		      0,
		      0,
		      0,
		      0,
		      0,
		      0,
		      &libspotonHandle,
		      m_settings.value("gui/gcryctl_init_secmem",
				       65536).toInt()) == LIBSPOTON_ERROR_NONE)
    libspoton_deregister_kernel
      (libspoton_registered_kernel_pid(&libspotonHandle, 0),
       &libspotonHandle);

  libspoton_close(&libspotonHandle);
  m_kernelSocket.close();
  m_messagingCacheMutex.lock();
  m_messagingCache.clear();
  m_messagingCacheMutex.unlock();
}

void spoton::slotGeneralTimerTimeout(void)
{
  QColor color(240, 128, 128); // Light coral!
  QPalette pidPalette(m_ui.pid->palette());
  QString sharedPath(spoton_misc::homePath() + QDir::separator() +
		     "shared.db");
  QString text(m_ui.pid->text());
  libspoton_handle_t libspotonHandle;

  pidPalette.setColor(m_ui.pid->backgroundRole(), color);

  if(libspoton_init_b(sharedPath.toStdString().c_str(),
		      0,
		      0,
		      0,
		      0,
		      0,
		      0,
		      0,
		      &libspotonHandle,
		      m_settings.value("gui/gcryctl_init_secmem",
				       65536).
		      toInt()) == LIBSPOTON_ERROR_NONE)
    {
      libspoton_error_t err = LIBSPOTON_ERROR_NONE;
      pid_t pid = 0;

      pid = libspoton_registered_kernel_pid(&libspotonHandle, &err);

      if(err == LIBSPOTON_ERROR_SQLITE_DATABASE_LOCKED || pid == 0)
	{
	  /*
	  ** Try next time.
	  */

	  m_ui.pid->setPalette(pidPalette);

	  if(pid == 0)
	    m_ui.pid->setText("0");
	  else
	    m_ui.pid->setText("-1");
	}
      else
	{
	  QColor color(144, 238, 144); // Light green!
	  QPalette palette(m_ui.pid->palette());

	  palette.setColor(m_ui.pid->backgroundRole(), color);
	  m_ui.pid->setPalette(palette);
	  m_ui.pid->setText(QString::number(pid));
	}
    }
  else
    {
      m_ui.pid->setPalette(pidPalette);
      m_ui.pid->setText("-1");
    }

  libspoton_close(&libspotonHandle);
  highlightPaths();

  if(text != m_ui.pid->text())
    {
      m_acceptedIPsLastModificationTime = QDateTime();
      m_countriesLastModificationTime = QDateTime();
      m_listenersLastModificationTime = QDateTime();
      m_neighborsLastModificationTime = QDateTime();
      m_participantsLastModificationTime = QDateTime();
    }

  if(isKernelActive())
    if(m_kernelSocket.state() == QAbstractSocket::UnconnectedState)
      {
	QString connectionName("");
	quint16 port = 0;

	{
	  QSqlDatabase db = spoton_misc::database(connectionName);

	  db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
			     "kernel.db");

	  if(db.open())
	    {
	      QSqlQuery query(db);

	      query.setForwardOnly(true);
	      
	      if(query.exec("SELECT port FROM kernel_gui_server"))
		if(query.next())
		  port = query.value(0).toInt();
	    }

	  db.close();
	}

	QSqlDatabase::removeDatabase(connectionName);

	if(port > 0)
	  {
	    initializeKernelSocket();
	    m_kernelSocket.connectToHostEncrypted
	      ("127.0.0.1", port);
	  }
      }

  slotKernelSocketState();

  if(isKernelActive())
    {
      if(m_ui.buzzTab->count() > 0)
	{
	  if(!m_buzzStatusTimer.isActive())
	    m_buzzStatusTimer.start();
	}
      else
	m_buzzStatusTimer.stop();
    }
  else
    m_buzzStatusTimer.stop();

  m_sb.status->setText
    (tr("External IP: %1.").
     arg(m_externalAddress->address().isNull() ?
	 "unknown" : m_externalAddress->address().toString()));
}

void spoton::slotSelectGeoIPPath(void)
{
  QFileDialog dialog(this);

  dialog.setFilter(QDir::AllDirs | QDir::Files
#if defined Q_OS_LINUX || defined Q_OS_MAC || defined Q_OS_UNIX
		   | QDir::Readable);
#else
                  );
#endif
  dialog.setWindowTitle
    (tr("Spot-On: Select GeoIP Data Path"));
  dialog.setFileMode(QFileDialog::ExistingFile);
  dialog.setDirectory(QDir::homePath());
  dialog.setLabelText(QFileDialog::Accept, tr("&Select"));
  dialog.setAcceptMode(QFileDialog::AcceptOpen);
#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
  dialog.setAttribute(Qt::WA_MacMetalStyle, false);
#endif
#endif

  if(dialog.exec() == QDialog::Accepted)
    saveGeoIPPath(dialog.selectedFiles().value(0).trimmed());
}

void spoton::slotSelectKernelPath(void)
{
  QFileDialog dialog(this);

  dialog.setFilter(QDir::AllDirs | QDir::Files
#if defined Q_OS_LINUX || defined Q_OS_MAC || defined Q_OS_UNIX
		   | QDir::Readable | QDir::Executable);
#else
                  );
#endif
  dialog.setWindowTitle
    (tr("Spot-On: Select Kernel Path"));
  dialog.setFileMode(QFileDialog::ExistingFile);
  dialog.setDirectory(QDir::homePath());
  dialog.setLabelText(QFileDialog::Accept, tr("&Select"));
  dialog.setAcceptMode(QFileDialog::AcceptOpen);
#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
  dialog.setAttribute(Qt::WA_MacMetalStyle, false);
#endif
#endif

  if(dialog.exec() == QDialog::Accepted)
    saveKernelPath(dialog.selectedFiles().value(0).trimmed());
}

void spoton::slotSaveGeoIPPath(void)
{
  saveGeoIPPath(m_ui.geoipPath->text().trimmed());
}

void spoton::slotSaveKernelPath(void)
{
  saveKernelPath(m_ui.kernelPath->text().trimmed());
}

void spoton::saveGeoIPPath(const QString &path)
{
  if(!path.isEmpty())
    {
      m_settings["gui/geoipPath"] = path;

      QSettings settings;
      
      settings.setValue("gui/geoipPath", path);
      m_ui.geoipPath->setText(path);
      m_ui.geoipPath->setToolTip(path);
      m_ui.geoipPath->selectAll();
    }
}

void spoton::saveKernelPath(const QString &path)
{
  if(!path.isEmpty())
    {
      m_settings["gui/kernelPath"] = path;

      QSettings settings;
      
      settings.setValue("gui/kernelPath", path);
      m_ui.kernelPath->setText(path);
      m_ui.kernelPath->setToolTip(path);
      m_ui.kernelPath->selectAll();
    }
}

void spoton::saveSettings(void)
{
  QSettings settings;

  if(spoton_misc::isGnome())
    settings.setValue("gui/geometry", geometry());
  else
    settings.setValue("gui/geometry", saveGeometry());

  settings.setValue("gui/chatHorizontalSplitter",
		    m_ui.chatHorizontalSplitter->saveState());
  settings.setValue("gui/currentTabIndex", m_ui.tab->currentIndex());
  settings.setValue("gui/listenersHorizontalSplitter",
		    m_ui.listenersHorizontalSplitter->saveState());
  settings.setValue("gui/neighborsVerticalSplitter",
		    m_ui.neighborsVerticalSplitter->saveState());
  settings.setValue("gui/readVerticalSplitter",
		    m_ui.readVerticalSplitter->saveState());
  settings.setValue("gui/urlsVerticalSplitter",
		    m_ui.urlsVerticalSplitter->saveState());
}

void spoton::closeEvent(QCloseEvent *event)
{
  saveSettings();
  QMainWindow::closeEvent(event);
  QApplication::instance()->quit();
}

void spoton::slotDeleteListener(void)
{
  QString oid("");
  int row = -1;

  if((row = m_ui.listeners->currentRow()) >= 0)
    {
      QTableWidgetItem *item = m_ui.listeners->item
	(row, m_ui.listeners->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "listeners.db");

    if(db.open())
      {
	QSqlQuery query(db);

	if(!isKernelActive())
	  query.prepare("DELETE FROM listeners WHERE "
			"OID = ?");
	else
	  query.prepare("UPDATE listeners SET status_control = 'deleted' "
			"WHERE "
			"OID = ? AND status_control <> 'deleted'");

	query.bindValue(0, oid);
	query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(row > -1)
    m_ui.listeners->removeRow(row);

  m_ui.accounts->clear();
}

void spoton::slotDeleteNeighbor(void)
{
  QString oid("");
  int row = -1;

  if((row = m_ui.neighbors->currentRow()) >= 0)
    {
      QTableWidgetItem *item = m_ui.neighbors->item
	(row, m_ui.neighbors->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "neighbors.db");

    if(db.open())
      {
	QSqlQuery query(db);

	if(!isKernelActive())
	  query.prepare("DELETE FROM neighbors WHERE "
			"OID = ?");
	else
	  query.prepare("UPDATE neighbors SET status_control = 'deleted' "
			"WHERE OID = ? AND status_control <> 'deleted'");

	query.bindValue(0, oid);
	query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(row > -1)
    m_ui.neighbors->removeRow(row);

  if(m_ui.neighbors->rowCount() == 0)
    m_ui.neighborSummary->clear();
}

void spoton::slotListenerCheckChange(int state)
{
  QCheckBox *checkBox = qobject_cast<QCheckBox *> (sender());

  if(checkBox)
    {
      QString connectionName("");

      {
	QSqlDatabase db = spoton_misc::database(connectionName);

	db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
			   "listeners.db");

	if(db.open())
	  {
	    QSqlQuery query(db);

	    query.prepare("UPDATE listeners SET "
			  "status_control = ? "
			  "WHERE OID = ? AND status_control <> 'deleted'");

	    if(state)
	      query.bindValue(0, "online");
	    else
	      query.bindValue(0, "offline");

	    query.bindValue(1, checkBox->property("oid"));
	    query.exec();
	  }

	db.close();
      }

      QSqlDatabase::removeDatabase(connectionName);
    }
}

void spoton::slotListenerUseAccounts(int state)
{
  QCheckBox *checkBox = qobject_cast<QCheckBox *> (sender());

  if(checkBox)
    {
      QString connectionName("");

      {
	QSqlDatabase db = spoton_misc::database(connectionName);

	db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
			   "listeners.db");

	if(db.open())
	  {
	    QSqlQuery query(db);

	    query.prepare("UPDATE listeners SET "
			  "use_accounts = ? "
			  "WHERE OID = ? AND ssl_key_size > 0");

	    if(state)
	      query.bindValue(0, 1);
	    else
	      query.bindValue(0, 0);

	    query.bindValue(1, checkBox->property("oid"));
	    query.exec();
	  }

	db.close();
      }

      QSqlDatabase::removeDatabase(connectionName);
    }
}

void spoton::updateListenersTable(const QSqlDatabase &db)
{
  if(!isKernelActive())
    if(db.isOpen())
      {
	QSqlQuery query(db);

	/*
	** OK, so the kernel is inactive. Discover the
	** listeners that have not been deleted and update some of their
	** information.
	*/

	query.exec("DELETE FROM listeners WHERE "
		   "status_control = 'deleted'");
	query.exec("UPDATE listeners SET connections = 0, "
		   "external_ip_address = NULL, "
		   "status = 'offline' WHERE "
		   "status = 'online' OR connections > 0");
      }
}

void spoton::updateNeighborsTable(const QSqlDatabase &db)
{
  if(m_ui.keepOnlyUserDefinedNeighbors->isChecked())
    if(db.isOpen())
      {
	/*
	** Delete random, disconnected peers.
	*/

	QSqlQuery query(db);

	query.exec("DELETE FROM neighbors WHERE "
		   "status <> 'connected' AND "
		   "status_control <> 'blocked' AND "
		   "user_defined = 0");
      }

  if(!isKernelActive())
    if(db.isOpen())
      {
	QSqlQuery query(db);

	/*
	** OK, so the kernel is inactive. Discover the
	** neighbors that have not been deleted and not disconnected
	** and update some of their information.
	*/

	query.exec("DELETE FROM neighbors WHERE "
		   "status_control = 'deleted'");
	query.exec("UPDATE neighbors SET "
		   "bytes_read = 0, "
		   "bytes_written = 0, "
		   "external_ip_address = NULL, "
		   "is_encrypted = 0, "
		   "local_ip_address = NULL, "
		   "local_port = NULL, "
		   "ssl_session_cipher = NULL, "
		   "status = 'disconnected', "
		   "uptime = 0 WHERE "
		   "local_ip_address IS NOT NULL OR local_port IS NOT NULL "
		   "OR status <> 'disconnected'");
      }
}

void spoton::updateParticipantsTable(const QSqlDatabase &db)
{
  if(!isKernelActive())
    if(db.isOpen())
      {
	QSqlQuery query(db);

	/*
	** OK, so the kernel is inactive. All participants are offline.
	*/

	query.exec("UPDATE friends_public_keys SET status = 'offline' WHERE "
		   "status <> 'offline'");
      }
}

void spoton::slotSetPassphrase(void)
{
  bool reencode = false;
  QString str1(m_ui.passphrase1->text());
  QString str2(m_ui.passphrase2->text());

  if(str1.length() < 16 || str2.length() < 16)
    {
      QMessageBox::critical(this, tr("Spot-On: Error"),
			    tr("The passphrases must contain at least "
			       "sixteen characters each."));
      m_ui.passphrase1->selectAll();
      m_ui.passphrase1->setFocus();
      return;
    }
  else if(str1 != str2)
    {
      QMessageBox::critical(this, tr("Spot-On: Error"),
			    tr("The passphrases are not identical."));
      m_ui.passphrase1->selectAll();
      m_ui.passphrase1->setFocus();
      return;
    }

  if(spoton_crypt::passphraseSet())
    {
      QMessageBox mb(this);

#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
      mb.setAttribute(Qt::WA_MacMetalStyle, true);
#endif
#endif
      mb.setIcon(QMessageBox::Question);
      mb.setWindowTitle(tr("Spot-On: Confirmation"));
      mb.setWindowModality(Qt::WindowModal);
      mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
      mb.setText(tr("Are you sure that you wish to replace the "
		    "existing passphrase?"));
#if 0
      mb.setText(tr("Are you sure that you wish to replace the "
		    "existing passphrase? Please note that URL data must "
		    "be re-encoded via a separate tool. Please see "
		    "the Tools folder."));
#endif

      if(mb.exec() != QMessageBox::Yes)
	{
	  m_ui.passphrase1->setText("0000000000");
	  m_ui.passphrase2->setText("0000000000");
	  return;
	}
      else
	reencode = true;
    }

  /*
  ** Create the RSA public and private keys.
  */

  m_sb.status->setText
    (tr("Generating a derived key. Please be patient."));
  m_sb.status->repaint();
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QByteArray salt;
  QByteArray saltedPassphraseHash;
  QString error1("");
  QString error2("");
  QString error3("");

  salt.resize(m_ui.saltLength->value());
  salt = spoton_crypt::strongRandomBytes(salt.length());

  QByteArray derivedKey
    (spoton_crypt::derivedKey(m_ui.cipherType->currentText(),
			      m_ui.hashType->currentText(),
			      m_ui.iterationCount->value(),
			      str1,
			      salt,
			      error1));

  m_sb.status->clear();

  if(error1.isEmpty())
    {
      slotDeactivateKernel();

      if(!m_ui.newKeys->isChecked() && reencode)
	{
	  if(m_crypts.value("chat", 0))
	    {
	      QStringList list;

	      list << "chat"
		   << "chat-signature"
		   << "email"
		   << "email-signature";
#if 0
	           << "url"
		   << "url-signature";
#endif

	      for(int i = 0; i < list.size(); i++)
		{
		  m_sb.status->setText
		    (tr("Re-encoding public key pair 1 of %1. "
			"Please be patient.").arg(list.size()));
		  m_sb.status->repaint();
		  spoton_crypt::reencodeKeys
		    (m_ui.cipherType->currentText(),
		     derivedKey,
		     m_settings.value("gui/cipherType", "aes256").
		     toString().trimmed(),
		     m_crypts.value("chat")->
		     symmetricKey(), /*
				     ** All such containers
				     ** have identical symmetric keys.
				     */
		     list.at(i),
		     error2);
		  m_sb.status->clear();

		  if(!error2.isEmpty())
		    break;
		}
	    }
	}
      else
	{
	  QString encryptionKeyType("");
	  QString signatureKeyType("");
	  QStringList list;

	  if(m_ui.encryptionKeyType->currentIndex() == 0)
	    encryptionKeyType = "elg";
	  else
	    encryptionKeyType = "rsa";

	  if(m_ui.signatureKeyType->currentIndex() == 0)
	    signatureKeyType = "dsa";
	  else
	    signatureKeyType = "rsa";

	  list << "chat"
	       << "chat-signature"
	       << "email"
	       << "email-signature";
#if 0
	       << "url"
	       << "url-signature";
#endif
	  m_sb.status->setText(tr("Generating public key pairs."));
	  m_sb.status->repaint();

	  for(int i = 0; i < list.size(); i++)
	    {
	      m_sb.status->setText
		(tr("Generating public key pair %1 of %2. "
		    "Please be patient.").
		 arg(i + 1).arg(list.size()));
	      m_sb.status->repaint();

	      spoton_crypt crypt
		(m_ui.cipherType->currentText(),
		 m_ui.hashType->currentText(),
		 str1.toUtf8(),
		 derivedKey,
		 m_ui.saltLength->value(),
		 m_ui.iterationCount->value(),
		 list.at(i));

	      if(!list.at(i).contains("signature"))
		crypt.generatePrivatePublicKeys
		  (m_ui.keySize->currentText().toInt(),
		   encryptionKeyType,
		   error2);
	      else
		crypt.generatePrivatePublicKeys
		  (m_ui.keySize->currentText().toInt(),
		   signatureKeyType,
		   error2);

	      m_sb.status->clear();

	      if(!error2.isEmpty())
		break;
	    }
	}
    }

  if(error1.isEmpty() && error2.isEmpty())
    saltedPassphraseHash = spoton_crypt::saltedPassphraseHash
      (m_ui.hashType->currentText(), str1, salt, error3);

  QApplication::restoreOverrideCursor();

  if(!error1.remove(".").trimmed().isEmpty())
    {
      spoton_crypt::purgeDatabases();
      QMessageBox::critical
	(this, tr("Spot-On: Error"),
	 tr("An error (%1) occurred with spoton_crypt::"
	    "derivedKey().").arg(error1.remove(".").trimmed()));
    }
  else if(!error2.remove(".").trimmed().isEmpty())
    {
      spoton_crypt::purgeDatabases();
      QMessageBox::critical(this, tr("Spot-On: Error"),
			    tr("An error (%1) occurred with "
			       "spoton_crypt::"
			       "generatePrivatePublicKeys() or "
			       "spoton_crypt::"
			       "reencodeKeys().").
			    arg(error2.remove(".").trimmed()));
    }
  else if(!error3.remove(".").trimmed().isEmpty())
    {
      spoton_crypt::purgeDatabases();
      QMessageBox::critical(this, tr("Spot-On: Error"),
			    tr("An error (%1) occurred with spoton_crypt::"
			       "saltedPassphraseHash().").
			    arg(error3.remove(".").trimmed()));
    }
  else
    {
      if(!m_crypts.value("chat", 0) || reencode)
	{
	  if(reencode)
	    {
	      spoton_crypt *crypt = new spoton_crypt
		(m_ui.cipherType->currentText(),
		 m_ui.hashType->currentText(),
		 QByteArray(),
		 derivedKey,
		 m_ui.saltLength->value(),
		 m_ui.iterationCount->value(),
		 "chat");

	      spoton_reencode reencode;

	      m_tableTimer.stop();
	      reencode.reencode(m_sb, crypt, m_crypts.value("chat"));
	      delete crypt;
	      m_tableTimer.start();
	    }

	  delete m_crypts.value("chat", 0);
	  delete m_crypts.value("chat-signature", 0);
	  delete m_crypts.value("email", 0);
	  delete m_crypts.value("email-signature", 0);
	  m_crypts.clear();

	  QStringList list;

	  list << "chat"
	       << "chat-signature"
	       << "email"
	       << "email-signature";

	  for(int i = 0; i < list.size(); i++)
	    m_crypts.insert
	      (list.at(i),
	       new spoton_crypt(m_ui.cipherType->currentText(),
				m_ui.hashType->currentText(),
				QByteArray(),
				derivedKey,
				m_ui.saltLength->value(),
				m_ui.iterationCount->value(),
				list.at(i)));

	  if(!reencode)
	    {
	      m_sb.status->setText
		(tr("Initializing country_inclusion.db."));
	      m_sb.status->repaint();
	      spoton_misc::populateCountryDatabase
		(m_crypts.value("chat", 0));
	      m_sb.status->clear();
	    }

	  if(!m_tableTimer.isActive())
	    m_tableTimer.start();

	  sendBuzzKeysToKernel();
	  sendKeysToKernel();
	}

      m_sb.kernelstatus->setEnabled(true);
      m_sb.listeners->setEnabled(true);
      m_sb.neighbors->setEnabled(true);
      m_ui.encryptionKeyType->setEnabled(false);
      m_ui.kernelBox->setEnabled(true);
      m_ui.keySize->setEnabled(false);
      m_ui.newKeys->setEnabled(true);
      m_ui.passphrase1->setText("0000000000");
      m_ui.passphrase2->setText("0000000000");
      m_ui.signatureKeyType->setEnabled(false);
      m_ui.newKeys->setChecked(false);

      for(int i = 0; i < m_ui.tab->count(); i++)
	m_ui.tab->setTabEnabled(i, true);

      /*
      ** Save the various entities.
      */

      m_settings["gui/cipherType"] = m_ui.cipherType->currentText();

      if(m_ui.encryptionKeyType->currentIndex() == 0)
	m_settings["gui/encryptionKey"] = "elg";
      else
	m_settings["gui/encryptionKey"] = "rsa";

      m_settings["gui/hashType"] = m_ui.hashType->currentText();
      m_settings["gui/iterationCount"] = m_ui.iterationCount->value();

      if(m_ui.kernelCipherType->currentIndex() == 0)
	m_settings["gui/kernelCipherType"] = "randomized";
      else
	m_settings["gui/kernelCipherType"] =
	  m_ui.kernelCipherType->currentText();

      m_settings["gui/keySize"] = m_ui.keySize->currentText().toInt();
      m_settings["gui/salt"] = salt;
      m_settings["gui/saltLength"] = m_ui.saltLength->value();
      m_settings["gui/saltedPassphraseHash"] = saltedPassphraseHash;

      if(m_ui.signatureKeyType->currentIndex() == 0)
	m_settings["gui/signatureKey"] = "dsa";
      else
	m_settings["gui/signatureKey"] = "rsa";

      QSettings settings;

      settings.setValue("gui/cipherType", m_settings["gui/cipherType"]);
      settings.setValue("gui/encryptionKey", m_settings["gui/encryptionKey"]);
      settings.setValue("gui/hashType", m_settings["gui/hashType"]);
      settings.setValue("gui/iterationCount",
			m_settings["gui/iterationCount"]);
      settings.setValue("gui/kernelCipherType",
			m_settings["gui/kernelCipherType"]);
      settings.setValue("gui/keySize", m_settings["gui/keySize"]);
      settings.setValue("gui/salt", m_settings["gui/salt"]);
      settings.setValue("gui/saltLength", m_settings["gui/saltLength"]);
      settings.setValue
	("gui/saltedPassphraseHash", m_settings["gui/saltedPassphraseHash"]);
      settings.setValue
	("gui/signatureKey", m_settings["gui/signatureKey"]);

      QMessageBox::information
	(this, tr("Spot-On: Information"),
	 tr("Your confidential information has been recorded. "
	    "You are now ready to use the full power of Spot-On. Enjoy!"));

      if(QFileInfo(m_ui.kernelPath->text().trimmed()).isExecutable())
	{
	  QMessageBox mb(this);

#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
	  mb.setAttribute(Qt::WA_MacMetalStyle, true);
#endif
#endif
	  mb.setIcon(QMessageBox::Question);
	  mb.setWindowTitle(tr("Spot-On: Question"));
	  mb.setWindowModality(Qt::WindowModal);
	  mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
	  mb.setText(tr("Would you like the kernel to be activated?"));

	  if(mb.exec() == QMessageBox::Yes)
	    slotActivateKernel();
	}
    }
}

void spoton::slotValidatePassphrase(void)
{
  QByteArray salt;
  QByteArray saltedPassphraseHash;
  QString error("");

  salt = m_settings.value("gui/salt", "").toByteArray();
  saltedPassphraseHash = m_settings.value("gui/saltedPassphraseHash", "").
    toByteArray();

  if(saltedPassphraseHash ==
     spoton_crypt::saltedPassphraseHash(m_ui.hashType->currentText(),
					m_ui.passphrase->text(),
					salt, error))
    if(error.isEmpty())
      {
	QByteArray key
	  (spoton_crypt::derivedKey(m_ui.cipherType->currentText(),
				    m_ui.hashType->currentText(),
				    m_ui.iterationCount->value(),
				    m_ui.passphrase->text(),
				    salt,
				    error));

	if(error.isEmpty())
	  {
	    delete m_crypts.value("chat", 0);
	    delete m_crypts.value("chat-signature", 0);
	    delete m_crypts.value("email", 0);
	    delete m_crypts.value("email-signature", 0);
	    m_crypts.clear();

	    QStringList list;

	    list << "chat"
		 << "chat-signature"
		 << "email"
		 << "email-signature";

	    for(int i = 0; i < list.size(); i++)
	      m_crypts.insert
		(list.at(i),
		 new spoton_crypt(m_ui.cipherType->currentText(),
				  m_ui.hashType->currentText(),
				  QByteArray(),
				  key,
				  m_ui.saltLength->value(),
				  m_ui.iterationCount->value(),
				  list.at(i)));

	    if(!m_tableTimer.isActive())
	      m_tableTimer.start();

	    sendBuzzKeysToKernel();
	    sendKeysToKernel();
	    m_sb.kernelstatus->setEnabled(true);
	    m_sb.listeners->setEnabled(true);
	    m_sb.neighbors->setEnabled(true);
	    m_ui.encryptionKeyType->setEnabled(false);
	    m_ui.kernelBox->setEnabled(true);
	    m_ui.keySize->setEnabled(false);
	    m_ui.newKeys->setEnabled(true);
	    m_ui.passphrase->clear();
	    m_ui.passphrase->setEnabled(false);
	    m_ui.passphraseButton->setEnabled(false);
	    m_ui.passphraseLabel->setEnabled(false);
	    m_ui.signatureKeyType->setEnabled(false);

	    for(int i = 0; i < m_ui.tab->count(); i++)
	      m_ui.tab->setTabEnabled(i, true);

	    m_ui.tab->setCurrentIndex
	      (m_settings.value("gui/currentTabIndex", m_ui.tab->count() - 1).
	       toInt());
	  }
      }

  m_ui.passphrase->clear();
  m_ui.passphrase->setFocus();
}

void spoton::slotTabChanged(int index)
{
  if(index == 0)
    m_sb.buzz->setVisible(false);
  else if(index == 1)
    m_sb.chat->setVisible(false);
}

void spoton::slotNeighborCheckChange(int state)
{
  QCheckBox *checkBox = qobject_cast<QCheckBox *> (sender());

  if(checkBox)
    {
      QString connectionName("");

      {
	QSqlDatabase db = spoton_misc::database(connectionName);

	db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
			   "neighbors.db");

	if(db.open())
	  {
	    QSqlQuery query(db);

	    query.prepare("UPDATE neighbors SET "
			  "sticky = ? "
			  "WHERE OID = ?");
	    query.bindValue(0, state > 0 ? 1 : 0);
	    query.bindValue(1, checkBox->property("oid"));
	    query.exec();
	  }

	db.close();
      }

      QSqlDatabase::removeDatabase(connectionName);
    }
}

void spoton::slotMaximumClientsChanged(int index)
{
  QComboBox *comboBox = qobject_cast<QComboBox *> (sender());

  if(comboBox)
    {
      QString connectionName("");

      {
	QSqlDatabase db = spoton_misc::database(connectionName);

	db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
			   "listeners.db");

	if(db.open())
	  {
	    QSqlQuery query(db);

	    query.prepare("UPDATE listeners SET "
			  "maximum_clients = ? "
			  "WHERE OID = ?");

	    if(index != comboBox->count() - 1)
	      query.bindValue(0, comboBox->itemText(index).toInt());
	    else
	      query.bindValue(0, std::numeric_limits<int>::max());

	    query.bindValue(1, comboBox->property("oid"));
	    query.exec();
	  }

	db.close();
      }

      QSqlDatabase::removeDatabase(connectionName);
    }
}

void spoton::slotShowContextMenu(const QPoint &point)
{
  QMenu menu(this);

  if(m_ui.acceptedIPList == sender())
    {
      menu.addAction(QIcon(QString(":/%1/clear.png").
			   arg(m_settings.value("gui/iconSet", "nouve").
			       toString())),
		     tr("&Delete IP Address"),
		     this, SLOT(slotDeleteAccepedIP(void)));
      menu.exec(m_ui.acceptedIPList->mapToGlobal(point));
    }
  else if(m_ui.emailParticipants == sender())
    {
      QAction *action = menu.addAction
	(QIcon(QString(":/%1/add.png").
	       arg(m_settings.value("gui/iconSet", "nouve").toString())),
	 tr("&Add participant as friend."),
	 this, SLOT(slotShareEmailPublicKeyWithParticipant(void)));
      QTableWidgetItem *item = m_ui.emailParticipants->itemAt(point);

      if(item && item->data(Qt::UserRole).toBool()) // Temporary friend?
	action->setEnabled(true);
      else
	action->setEnabled(false);

      menu.addSeparator();
      menu.addAction(QIcon(QString(":/%1/copy.png").
			   arg(m_settings.value("gui/iconSet", "nouve").
			       toString())),
		     tr("&Copy Repleo to the clipboard buffer."),
		     this, SLOT(slotCopyEmailFriendshipBundle(void)));
      menu.addSeparator();
      menu.addAction(QIcon(QString(":/%1/clear.png").
			   arg(m_settings.value("gui/iconSet", "nouve").
			       toString())),
		     tr("&Remove participant(s)."),
		     this, SLOT(slotRemoveEmailParticipants(void)));
      menu.exec(m_ui.emailParticipants->mapToGlobal(point));
    }
  else if(m_ui.listeners == sender())
    {
      menu.addAction(QIcon(QString(":/%1/clear.png").
			   arg(m_settings.value("gui/iconSet", "nouve").
			       toString())),
		     tr("&Delete"),
		     this, SLOT(slotDeleteListener(void)));
      menu.addAction(tr("Delete &All"),
		     this, SLOT(slotDeleteAllListeners(void)));
      menu.addSeparator();
      menu.addAction(tr("Detach &Neighbors"),
		     this, SLOT(slotDetachListenerNeighbors(void)));
      menu.addAction(tr("Disconnect &Neighbors"),
		     this, SLOT(slotDisconnectListenerNeighbors(void)));
      menu.addSeparator();
      menu.addAction(tr("&Publish Information (Plaintext)"),
		     this, SLOT(slotPublicizeListenerPlaintext(void)));
      menu.addAction(tr("Publish &All (Plaintext)"),
		     this, SLOT(slotPublicizeAllListenersPlaintext(void)));
      menu.addSeparator();
      menu.addAction(tr("&Full Echo"),
		     this, SLOT(slotListenerFullEcho(void)));
      menu.addAction(tr("&Half Echo"),
		     this, SLOT(slotListenerHalfEcho(void)));
      menu.exec(m_ui.listeners->mapToGlobal(point));
    }
  else if(m_ui.neighbors == sender())
    {
      menu.addAction(QIcon(QString(":/%1/share.png").
			   arg(m_settings.value("gui/iconSet", "nouve").
			       toString())),
		     tr("Share &Chat Public Key"),
		     this, SLOT(slotShareChatPublicKey(void)));
      menu.addAction(QIcon(QString(":/%1/share.png").
			   arg(m_settings.value("gui/iconSet", "nouve").
			       toString())),
		     tr("Share &E-Mail Public Key"),
		     this, SLOT(slotShareEmailPublicKey(void)));
#if 0
      menu.addAction(QIcon(QString(":%1//share.png").
			   arg(m_settings.value("gui/iconSet", "nouve").
			       toString())),
		     tr("Share &URL Public Key"),
		     this, SLOT(slotShareURLPublicKey(void)));
#endif
      menu.addSeparator();
      menu.addAction(tr("&Connect"),
		     this, SLOT(slotConnectNeighbor(void)));
      menu.addAction(tr("&Disconnect"),
		     this, SLOT(slotDisconnectNeighbor(void)));
      menu.addSeparator();
      menu.addAction
	(tr("&Authenticate"),
	 this,
	 SLOT(slotAuthenticate(void)));
      menu.addSeparator();
      menu.addAction(QIcon(QString(":/%1/clear.png").
			   arg(m_settings.value("gui/iconSet", "nouve").
			       toString())),
		     tr("&Delete"),
		     this, SLOT(slotDeleteNeighbor(void)));
      menu.addAction(tr("Delete &All"),
		     this, SLOT(slotDeleteAllNeighbors(void)));
      menu.addAction(tr("Delete All Non-Unique &Blocked Neighbors"),
		     this, SLOT(slotDeleteAllBlockedNeighbors(void)));
      menu.addAction(tr("Delete All Non-Unique &UUIDs"),
		     this, SLOT(slotDeleteAllUuids(void)));
      menu.addSeparator();
      menu.addAction(tr("B&lock"),
		     this, SLOT(slotBlockNeighbor(void)));
      menu.addAction(tr("U&nblock"),
		     this, SLOT(slotUnblockNeighbor(void)));
      menu.addSeparator();
      menu.addAction(tr("&Full Echo"),
		     this, SLOT(slotNeighborFullEcho(void)));
      menu.addAction(tr("&Half Echo"),
		     this, SLOT(slotNeighborHalfEcho(void)));
      menu.exec(m_ui.neighbors->mapToGlobal(point));
    }
  else
    {
      QAction *action = menu.addAction
	(QIcon(QString(":/%1/add.png").
	       arg(m_settings.value("gui/iconSet", "nouve").toString())),
	 tr("&Add participant as friend."),
	 this, SLOT(slotShareChatPublicKeyWithParticipant(void)));
      QTableWidgetItem *item = m_ui.participants->itemAt(point);

      if(item && item->data(Qt::UserRole).toBool()) // Temporary friend?
	action->setEnabled(true);
      else
	action->setEnabled(false);

      menu.addAction(QIcon(QString(":/%1/copy.png").
			   arg(m_settings.value("gui/iconSet", "nouve").
			       toString())),
		     tr("&Copy Repleo to the clipboard buffer."),
		     this, SLOT(slotCopyFriendshipBundle(void)));
      menu.addSeparator();
      action = menu.addAction(tr("&Call participant."),
			      this, SLOT(slotCallParticipant(void)));
      action->setProperty("type", "calling");

      if(item && item->data(Qt::UserRole).toBool()) // Temporary friend?
	action->setEnabled(false);
      else
	action->setEnabled(true);

      action = menu.addAction(tr("&Terminate call."),
			      this, SLOT(slotCallParticipant(void)));
      action->setProperty("type", "terminating");

      if(item && item->data(Qt::UserRole).toBool()) // Temporary friend?
	action->setEnabled(false);
      else
	action->setEnabled(true);

      menu.addSeparator();
      action = menu.addAction(tr("&Generate random Gemini (AES-256)."),
			      this, SLOT(slotGenerateGeminiInChat(void)));

      if(item && item->data(Qt::UserRole).toBool()) // Temporary friend?
	action->setEnabled(false);
      else
	action->setEnabled(true);

      menu.addSeparator();
      menu.addAction(QIcon(QString(":/%1/clear.png").
			   arg(m_settings.value("gui/iconSet", "nouve").
			       toString())),
		     tr("&Remove participant(s)."),
		     this, SLOT(slotRemoveParticipants(void)));
      menu.exec(m_ui.participants->mapToGlobal(point));
    }
}

void spoton::slotKernelSocketState(void)
{
  QAbstractSocket::SocketState state = m_kernelSocket.state();

  if(state == QAbstractSocket::ConnectedState)
    {
      if(m_kernelSocket.isEncrypted())
	{
	  sendBuzzKeysToKernel();
	  sendKeysToKernel();
	  m_sb.kernelstatus->setToolTip
	    (tr("Connected securely to the kernel on port %1 "
		"from local port %2.").
	     arg(m_kernelSocket.peerPort()).
	     arg(m_kernelSocket.localPort()));
	}
      else
	m_sb.kernelstatus->setToolTip
	  (tr("Connected insecurely to the kernel on port %1 "
	      "from local port %2. Communications between the interface and "
	      "the kernel have been disabled.").
	   arg(m_kernelSocket.peerPort()).
	   arg(m_kernelSocket.localPort()));

      m_sb.kernelstatus->setIcon
	(QIcon(QString(":/%1/activate.png").
	       arg(m_settings.value("gui/iconSet", "nouve").toString())));
    }
  else if(state == QAbstractSocket::UnconnectedState)
    {
      m_booleans["buzz_channels_sent_to_kernel"] = false;
      m_booleans["keys_sent_to_kernel"] = false;
      m_messagingCacheMutex.lock();
      m_messagingCache.clear();
      m_messagingCacheMutex.unlock();
      m_sb.kernelstatus->setIcon
	(QIcon(QString(":/%1/deactivate.png").
	       arg(m_settings.value("gui/iconSet", "nouve").toString())));
      m_sb.kernelstatus->setToolTip
	(tr("Not connected to the kernel. Is the kernel "
	    "active?"));
    }
}

void spoton::sendBuzzKeysToKernel(void)
{
  if(m_booleans.value("buzz_channels_sent_to_kernel", false))
    return;

  bool sent = true;

  if((sent = (m_kernelSocket.state() == QAbstractSocket::ConnectedState)))
    if((sent = m_kernelSocket.isEncrypted()))
      foreach(spoton_buzzpage *page,
	      m_ui.tab->findChildren<spoton_buzzpage *> ())
	{
	  QByteArray message;

	  message.append("addbuzz_");
	  message.append(page->key().toBase64());
	  message.append("_");
	  message.append(page->channelType().toBase64());
	  message.append("\n");

	  if(m_kernelSocket.write(message.constData(), message.length()) !=
	     message.length())
	    {
	      sent = false;
	      spoton_misc::logError
		(QString("spoton::sendBuzzKeysToKernel(): write() failure "
			 "for %1:%2.").
		 arg(m_kernelSocket.peerAddress().toString()).
		 arg(m_kernelSocket.peerPort()));
	    }
	  else
	    m_kernelSocket.flush();
	}

  m_booleans["buzz_channels_sent_to_kernel"] = sent;
}

void spoton::sendKeysToKernel(void)
{
  if(m_booleans.value("keys_sent_to_kernel", false))
    return;

  if(m_crypts.value("chat", 0))
    if(m_kernelSocket.state() == QAbstractSocket::ConnectedState)
      if(m_kernelSocket.isEncrypted())
	{
	  QByteArray keys("keys_");
	  QByteArray symmetricKey
	    (m_crypts.value("chat")->
	     symmetricKey(), m_crypts.value("chat")->symmetricKeyLength());

	  symmetricKey = symmetricKey.toBase64();
	  keys.append(symmetricKey);
	  keys.append('\n');

	  if(m_kernelSocket.write(keys.constData(), keys.length()) !=
	     keys.length())
	    spoton_misc::logError
	      (QString("spoton::sendKeysToKernel(): write() failure "
		       "for %1:%2.").
	       arg(m_kernelSocket.peerAddress().toString()).
	       arg(m_kernelSocket.peerPort()));
	  else
	    {
	      m_booleans["keys_sent_to_kernel"] = true;
	      m_kernelSocket.flush();
	    }
	}
}

void spoton::slotConnectNeighbor(void)
{
  QString oid("");
  int row = -1;

  if((row = m_ui.neighbors->currentRow()) >= 0)
    {
      QTableWidgetItem *item = m_ui.neighbors->item
	(row, m_ui.neighbors->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "neighbors.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.prepare("UPDATE neighbors SET "
		      "status_control = ? "
		      "WHERE OID = ? AND status_control <> 'deleted'");
	query.bindValue(0, "connected");
	query.bindValue(1, oid);
	query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotDisconnectNeighbor(void)
{
  QString oid("");
  int row = -1;

  if((row = m_ui.neighbors->currentRow()) >= 0)
    {
      QTableWidgetItem *item = m_ui.neighbors->item
	(row, m_ui.neighbors->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "neighbors.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.prepare("UPDATE neighbors SET "
		      "status_control = ? "
		      "WHERE OID = ?");
	query.bindValue(0, "disconnected");
	query.bindValue(1, oid);
	query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotBlockNeighbor(void)
{
  if(!m_crypts.value("chat", 0))
    return;

  QString remoteIp("");
  int row = -1;

  if((row = m_ui.neighbors->currentRow()) >= 0)
    {
      QTableWidgetItem *item = m_ui.neighbors->item
	(row, 10); // Remote IP Address

      if(item)
	remoteIp = item->text();
    }

  if(remoteIp.isEmpty())
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "neighbors.db");

    if(db.open())
      {
	/*
	** We must block all neighbors having the given remote IP
	** address. The neighbors must be in unblocked control states.
	** Neighbors that are marked as deleted must be left as is since
	** they will be purged by either the interface or the kernel.
	*/

	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec("SELECT remote_ip_address, OID "
		      "FROM neighbors WHERE status_control <> 'blocked' "
		      "AND status_control <> 'deleted'"))
	  while(query.next())
	    {
	      QString ip("");
	      bool ok = true;

	      ip =
		m_crypts.value("chat")->decrypted(QByteArray::
						  fromBase64(query.
							     value(0).
							     toByteArray()),
						  &ok).
		constData();

	      if(ok)
		if(ip == remoteIp)
		  {
		    QSqlQuery updateQuery(db);

		    updateQuery.prepare("UPDATE neighbors SET "
					"status_control = 'blocked' WHERE "
					"OID = ?");
		    updateQuery.bindValue(0, query.value(1));
		    updateQuery.exec();
		  }
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  QApplication::restoreOverrideCursor();
}

void spoton::slotUnblockNeighbor(void)
{
  if(!m_crypts.value("chat", 0))
    return;

  QString remoteIp("");
  int row = -1;

  if((row = m_ui.neighbors->currentRow()) >= 0)
    {
      QTableWidgetItem *item = m_ui.neighbors->item
	(row, 10); // Remote IP Address

      if(item)
	remoteIp = item->text();
    }

  if(remoteIp.isEmpty())
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "neighbors.db");

    if(db.open())
      {
	/*
	** We must unblock all neighbors having the given remote IP
	** address. The neighbors must be in blocked control states. We shall
	** place the unblocked neighbors in disconnected control states.
	*/

	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec("SELECT remote_ip_address, OID "
		      "FROM neighbors WHERE status_control = 'blocked'"))
	  while(query.next())
	    {
	      bool ok = true;

	      QString ip
		(m_crypts.value("chat")->decrypted(QByteArray::
						   fromBase64(query.
							      value(0).
							      toByteArray()),
						   &ok).
		 constData());

	      if(ok)
		if(ip == remoteIp)
		  {
		    QSqlQuery updateQuery(db);

		    updateQuery.prepare("UPDATE neighbors SET "
					"status_control = 'disconnected' "
					"WHERE "
					"OID = ?");
		    updateQuery.bindValue(0, query.value(1));
		    updateQuery.exec();
		  }
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  QApplication::restoreOverrideCursor();
}

void spoton::slotDeleteAllListeners(void)
{
  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "listeners.db");

    if(db.open())
      {
	QSqlQuery query(db);

	if(!isKernelActive())
	  query.exec("DELETE FROM listeners");
	else
	  query.exec("UPDATE listeners SET "
		     "status_control = 'deleted' WHERE "
		     "status_control <> 'deleted'");
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  while(m_ui.listeners->rowCount() > 0)
    m_ui.listeners->removeRow(0);

  m_ui.accounts->clear();
  m_ui.accountName->clear();
  m_ui.accountPassword->clear();
}

void spoton::slotDeleteAllNeighbors(void)
{
  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "neighbors.db");

    if(db.open())
      {
	QSqlQuery query(db);

	if(!isKernelActive())
	  query.exec("DELETE FROM neighbors");
	else
	  query.exec("UPDATE neighbors SET "
		     "status_control = 'deleted' WHERE "
		     "status_control <> 'deleted'");
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  while(m_ui.neighbors->rowCount() > 0)
    m_ui.neighbors->removeRow(0);

  m_ui.neighborSummary->clear();
}

void spoton::slotPopulateParticipants(void)
{
  if(!m_crypts.value("chat", 0))
    return;

  QFileInfo fileInfo(spoton_misc::homePath() + QDir::separator() +
		     "friends_public_keys.db");

  if(fileInfo.exists())
    {
      if(fileInfo.lastModified() <= m_participantsLastModificationTime)
	return;
      else
	m_participantsLastModificationTime = fileInfo.lastModified();
    }
  else
    m_participantsLastModificationTime = QDateTime();

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(fileInfo.absoluteFilePath());

    if(db.open())
      {
	updateParticipantsTable(db);

	QList<int> rows;
	QList<int> rowsE;
	QModelIndexList list
	  (m_ui.participants->selectionModel()->
	   selectedRows(3)); // public_key_hash
	QModelIndexList listE
	  (m_ui.emailParticipants->selectionModel()->
	   selectedRows(3)); // public_key_hash
	QStringList hashes;
	QStringList hashesE;
	int hval = m_ui.participants->horizontalScrollBar()->value();
	int hvalE = m_ui.emailParticipants->horizontalScrollBar()->value();
	int row = 0;
	int rowE = 0;
	int vval = m_ui.participants->verticalScrollBar()->value();
	int vvalE = m_ui.emailParticipants->verticalScrollBar()->value();

	while(!list.isEmpty())
	  {
	    QModelIndex index(list.takeFirst());
	    QVariant data(index.data());

	    /*
	    ** Do not select participants that are offline if
	    ** the user does not wish to list them.
	    */

	    if(!data.isNull() && data.isValid())
	      {
		if(m_ui.hideOfflineParticipants->isChecked())
		  {
		    QTableWidgetItem *item = m_ui.participants->
		      item(index.row(), 4); // Status

		    if(item && item->text() != tr("Offline"))
		      hashes.append(data.toString());
		  }
		else
		  hashes.append(data.toString());
	      }
	  }

	while(!listE.isEmpty())
	  {
	    QVariant data(listE.takeFirst().data());

	    if(!data.isNull() && data.isValid())
	      hashesE.append(data.toString());
	  }

	m_ui.emailParticipants->setSortingEnabled(false);
	m_ui.emailParticipants->clearContents();
	m_ui.emailParticipants->setRowCount(0);
	m_ui.participants->setSortingEnabled(false);
	m_ui.participants->clearContents();
	m_ui.participants->setRowCount(0);
	disconnect(m_ui.participants,
		   SIGNAL(itemChanged(QTableWidgetItem *)),
		   this,
		   SLOT(slotGeminiChanged(QTableWidgetItem *)));

	QSqlQuery query(db);
	QWidget *focusWidget = QApplication::focusWidget();

	query.setForwardOnly(true);

	/*
	** We only wish to display other public keys.
	*/

	if(query.exec("SELECT "
		      "name, "
		      "OID, "
		      "neighbor_oid, "
		      "public_key_hash, "
		      "status, "
		      "last_status_update, "
		      "gemini, "
		      "key_type "
		      "FROM friends_public_keys "
		      "WHERE key_type = 'chat' OR key_type = 'email'"))
	  while(query.next())
	    {
	      QString keyType(query.value(7).toString());
	      QString status(query.value(4).toString());
	      bool temporary =
		query.value(2).toInt() == -1 ? false : true;

	      if(!isKernelActive())
		status = "offline";

	      for(int i = 0; i < query.record().count(); i++)
		{
		  QTableWidgetItem *item = 0;

		  if(keyType == "chat")
		    {
		      if(i == 0)
			{
			  /*
			  ** Do not increase the table's row count
			  ** if the participant is offline and the
			  ** user wishes to hide offline participants.
			  */

			  if(!(m_ui.hideOfflineParticipants->isChecked() &&
			       status == "offline"))
			    {
			      row += 1;
			      m_ui.participants->setRowCount(row);
			    }
			}

		      if(i == 0) // Name
			item = new QTableWidgetItem
			  (QString::fromUtf8(query.value(i).toByteArray()));
		      else if(i == 4) // Status
			{
			  QString status(query.value(i).toString());

			  if(!status.isEmpty())
			    {
			      if(status.at(0).isLetter())
				status[0] = status.toUpper()[0];
			    }
			  else
			    status = "Offline";

			  if(status == "Away")
			    item = new QTableWidgetItem(tr("Away"));
			  else if(status == "Busy")
			    item = new QTableWidgetItem(tr("Busy"));
			  else if(status == "Offline")
			    item = new QTableWidgetItem(tr("Offline"));
			  else if(status == "Online")
			    item = new QTableWidgetItem(tr("Online"));
			  else
			    item = new QTableWidgetItem(tr("Friend"));
			}
		      else if(i == 6) // Gemini
			{
			  bool ok = true;

			  if(query.isNull(i))
			    item = new QTableWidgetItem();
			  else
			    item = new QTableWidgetItem
			      (m_crypts.value("chat")->
			       decrypted(QByteArray::
					 fromBase64(query.
						    value(i).
						    toByteArray()),
					 &ok).constData());
			}
		      else
			item = new QTableWidgetItem
			  (query.value(i).toString());

		      item->setFlags
			(Qt::ItemIsSelectable | Qt::ItemIsEnabled);

		      if(i == 0) // Name
			{
			  if(!temporary)
			    {
			      if(status == "away")
				item->setIcon
				  (QIcon(QString(":/%1/away.png").
					 arg(m_settings.value("gui/iconSet",
							      "nouve").
					     toString())));
			      else if(status == "busy")
				item->setIcon
				  (QIcon(QString(":/%1/busy.png").
					 arg(m_settings.value("gui/iconSet",
							      "nouve").
					     toString())));
			      else if(status == "offline")
				item->setIcon
				  (QIcon(QString(":/%1/offline.png").
					 arg(m_settings.value("gui/iconSet",
							      "nouve").
					     toString())));
			      else if(status == "online")
				item->setIcon
				  (QIcon(QString(":/%1/online.png").
					 arg(m_settings.value("gui/iconSet",
							      "nouve").
					     toString())));

			      item->setToolTip
				(query.value(3).toString().mid(0, 16) +
				 "..." +
				 query.value(3).toString().right(16));
			    }
			  else
			    {
			      item->setIcon
				(QIcon(QString(":/%1/add.png").
				       arg(m_settings.value("gui/iconSet",
							    "nouve").
					   toString())));
			      item->setToolTip
				(tr("User %1 requests your friendship.").
				 arg(item->text()));
			    }
			}
		      else if(i == 6) // Gemini
			{
			  if(!temporary)
			    item->setFlags
			      (item->flags() | Qt::ItemIsEditable);
			}

		      item->setData(Qt::UserRole, temporary);

		      /*
		      ** Delete the item if the participant is offline
		      ** and the user wishes to hide offline participants.
		      ** Please note that the e-mail participants are cloned
		      ** and are not subjected to this restriction.
		      */

		      if(m_ui.hideOfflineParticipants->isChecked() &&
			 status == "offline")
			delete item;
		      else
			m_ui.participants->setItem(row - 1, i, item);
		    }
		  else // E-Mail!
		    {
		      if(i == 0)
			{
			  rowE += 1;
			  m_ui.emailParticipants->setRowCount(rowE);
			}

		      if(i == 0)
			item = new QTableWidgetItem
			  (QString::fromUtf8(query.value(i).toByteArray()));
		      else if(i == 1 || i == 2 || i == 3)
			item = new QTableWidgetItem(query.value(i).toString());

		      if(i == 0)
			{
			  if(temporary)
			    {
			      item->setIcon
				(QIcon(QString(":/%1/add.png").
				       arg(m_settings.value("gui/iconSet",
							    "nouve").
					   toString())));
			      item->setToolTip
				(tr("User %1 requests your friendship.").
				 arg(item->text()));
			    }
			  else
			    item->setToolTip
			      (query.value(3).toString().mid(0, 16) +
			       "..." +
			       query.value(3).toString().right(16));
			}

		      if(item)
			{
			  item->setData(Qt::UserRole, temporary);
			  item->setFlags
			    (Qt::ItemIsSelectable | Qt::ItemIsEnabled);
			}

		      m_ui.emailParticipants->setItem
			(rowE - 1, i, item);
		    }
		}

	      if(hashes.contains(query.value(3).toString()))
		rows.append(row - 1);

	      if(hashesE.contains(query.value(3).toString()))
		rowsE.append(rowE - 1);
	    }

	if(focusWidget)
	  focusWidget->setFocus();

	connect(m_ui.participants,
		SIGNAL(itemChanged(QTableWidgetItem *)),
		this,
		SLOT(slotGeminiChanged(QTableWidgetItem *)));
	m_ui.emailParticipants->setSelectionMode
	  (QAbstractItemView::MultiSelection);
	m_ui.participants->setSelectionMode(QAbstractItemView::MultiSelection);

	while(!rows.isEmpty())
	  m_ui.participants->selectRow(rows.takeFirst());

	while(!rowsE.isEmpty())
	  m_ui.emailParticipants->selectRow(rowsE.takeFirst());

	m_ui.emailParticipants->setSelectionMode
	  (QAbstractItemView::ExtendedSelection);
	m_ui.emailParticipants->setSortingEnabled(true);
	m_ui.emailParticipants->resizeColumnsToContents();
	m_ui.emailParticipants->horizontalHeader()->
	  setStretchLastSection(true);
	m_ui.emailParticipants->horizontalScrollBar()->setValue(hvalE);
	m_ui.emailParticipants->verticalScrollBar()->setValue(vvalE);
	m_ui.participants->setSelectionMode
	  (QAbstractItemView::ExtendedSelection);
	m_ui.participants->setSortingEnabled(true);
	m_ui.participants->resizeColumnsToContents();
	m_ui.participants->horizontalHeader()->setStretchLastSection(true);
	m_ui.participants->horizontalScrollBar()->setValue(hval);
	m_ui.participants->verticalScrollBar()->setValue(vval);
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotProxyTypeChanged(int index)
{
  m_ui.proxyHostname->clear();
  m_ui.proxyHostname->setEnabled(index != 2);
  m_ui.proxyPassword->clear();
  m_ui.proxyPort->setEnabled(index != 2);
  m_ui.proxyPort->setValue(m_ui.proxyPort->minimum());
  m_ui.proxyUsername->clear();
}

void spoton::slotProxyChecked(bool state)
{
  Q_UNUSED(state);
  m_ui.proxyHostname->clear();
  m_ui.proxyPassword->clear();
  m_ui.proxyPort->setValue(m_ui.proxyPort->minimum());
  m_ui.proxyType->setCurrentIndex(0);
  m_ui.proxyUsername->clear();
}

void spoton::slotKernelSocketError(QAbstractSocket::SocketError error)
{
  Q_UNUSED(error);
  spoton_misc::logError
    (QString("spoton::slotKernelSocketError(): socket error (%1).").
     arg(m_kernelSocket.errorString()));
}

void spoton::slotKernelSocketSslErrors(const QList<QSslError> &errors)
{
  m_kernelSocket.ignoreSslErrors();

  for(int i = 0; i < errors.size(); i++)
    spoton_misc::logError
      (QString("spoton::slotKernelSocketSslErrors(): "
	       "error (%1) occurred for %2:%3.").
       arg(errors.at(i).errorString()).
       arg(m_kernelSocket.peerAddress().isNull() ? m_kernelSocket.peerName() :
	   m_kernelSocket.peerAddress().toString()).
       arg(m_kernelSocket.peerPort()));
}

void spoton::changeEchoMode(const QString &mode, QTableWidget *tableWidget)
{
  if(!m_crypts.value("chat", 0))
    return;
  else if(!tableWidget)
    return;

  QString table("");

  if(m_ui.listeners == tableWidget)
    table = "listeners";
  else
    table = "neighbors";

  QString oid("");
  int row = -1;

  if((row = tableWidget->currentRow()) >= 0)
    {
      QTableWidgetItem *item = tableWidget->item
	(row, tableWidget->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       QString("%1.db").arg(table));

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	query.prepare(QString("UPDATE %1 SET "
			      "echo_mode = ? "
			      "WHERE OID = ?").arg(table));
	query.bindValue
	  (0, m_crypts.value("chat")->encrypted(mode.toLatin1(), &ok).
	   toBase64());
	query.bindValue(1, oid);

	if(ok)
	  query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(m_ui.listeners == tableWidget)
    m_listenersLastModificationTime = QDateTime();
  else
    m_neighborsLastModificationTime = QDateTime();
}

void spoton::slotListenerFullEcho(void)
{
  changeEchoMode("full", m_ui.listeners);
}

void spoton::slotListenerHalfEcho(void)
{
  changeEchoMode("half", m_ui.listeners);
}

void spoton::slotNeighborFullEcho(void)
{
  changeEchoMode("full", m_ui.neighbors);
}

void spoton::slotNeighborHalfEcho(void)
{
  changeEchoMode("half", m_ui.neighbors);
}

void spoton::slotCountriesToggleOff(void)
{
  countriesToggle(false);
}

void spoton::slotCountriesToggleOn(void)
{
  countriesToggle(true);
}

void spoton::countriesToggle(const bool state)
{
  if(!m_crypts.value("chat", 0))
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  update();

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "country_inclusion.db");

    if(db.open())
      {
	disconnect(m_ui.countries,
		   SIGNAL(itemChanged(QListWidgetItem *)),
		   this,
		   SLOT(slotCountryChanged(QListWidgetItem *)));

	QSqlQuery query(db);

	for(int i = 0; i < m_ui.countries->count(); i++)
	  {
	    QListWidgetItem *item = m_ui.countries->item(i);

	    if(!item)
	      continue;

	    bool ok = true;

	    query.prepare("UPDATE country_inclusion SET accepted = ? "
			  "WHERE country_hash = ?");
	    query.bindValue
	      (0, m_crypts.value("chat")->
	       encrypted(QString::number(state).
			 toLatin1(), &ok).toBase64());

	    if(ok)
	      query.bindValue
		(1, m_crypts.value("chat")->
		 keyedHash(item->text().toLatin1(), &ok).
		 toBase64());

	    if(ok)
	      ok = query.exec();

	    if(ok)
	      {
		if(state)
		  item->setCheckState(Qt::Checked);
		else
		  item->setCheckState(Qt::Unchecked);
	      }
	  }

	connect(m_ui.countries,
		SIGNAL(itemChanged(QListWidgetItem *)),
		this,
		SLOT(slotCountryChanged(QListWidgetItem *)));
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(!state)
    {
      QString connectionName("");

      {
	QSqlDatabase db = spoton_misc::database(connectionName);

	db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
			   "neighbors.db");

	if(db.open())
	  {
	    QSqlQuery query(db);

	    for(int i = 0; i < m_ui.countries->count(); i++)
	      {
		QListWidgetItem *item = m_ui.countries->item(i);

		if(!item)
		  continue;

		bool ok = true;

		query.prepare("UPDATE neighbors SET "
			      "status_control = 'disconnected' "
			      "WHERE qt_country_hash = ?");
		query.bindValue
		  (0,
		   m_crypts.value("chat")->
		   keyedHash(item->text().toLatin1(), &ok).
		   toBase64());

		if(ok)
		  query.exec();
	      }
	  }

	db.close();
      }

      QSqlDatabase::removeDatabase(connectionName);
    }

  QApplication::restoreOverrideCursor();
}

void spoton::slotKernelLogEvents(bool state)
{
  m_settings["gui/kernelLogEvents"] = state;

  QSettings settings;

  settings.setValue("gui/kernelLogEvents", state);
}

void spoton::slotModeChanged(QSslSocket::SslMode mode)
{
  spoton_misc::logError(QString("spoton::slotModeChanged(): "
				"the connection mode has changed to %1 "
				"for %2:%3.").
			arg(mode).
			arg(m_kernelSocket.peerAddress().toString()).
			arg(m_kernelSocket.peerPort()));

  if(mode == QSslSocket::UnencryptedMode)
    {
      spoton_misc::logError
	(QString("spoton::slotModeChanged(): "
		 "plaintext mode. Disconnecting kernel socket for "
		 "%1:%2.").
	 arg(m_kernelSocket.peerAddress().toString()).
	 arg(m_kernelSocket.peerPort()));
      m_kernelSocket.abort();
    }
}

void spoton::slotNeighborMaximumChanged(int value)
{
  QSpinBox *spinBox = qobject_cast<QSpinBox *> (sender());

  if(!spinBox)
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "neighbors.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.prepare(QString("UPDATE neighbors SET "
			      "%1 = ? "
			      "WHERE OID = ?").
		      arg(spinBox->property("field_name").toString()));
	query.bindValue(0, value);
	query.bindValue(1, spinBox->property("oid"));
	query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotDetachListenerNeighbors(void)
{
  QString oid("");
  int row = -1;

  if((row = m_ui.listeners->currentRow()) >= 0)
    {
      QTableWidgetItem *item = m_ui.listeners->item
	(row, m_ui.listeners->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    return;

  if(m_kernelSocket.state() == QAbstractSocket::ConnectedState)
    if(m_kernelSocket.isEncrypted())
      {
	QByteArray message;

	message.append("detach_listener_neighbors_");
	message.append(oid);
	message.append("\n");

	if(m_kernelSocket.write(message.constData(), message.length()) !=
	   message.length())
	  spoton_misc::logError
	    (QString("spoton::slotDetachListenerNeighbors(): write() "
		     "failure for %1:%2.").
	     arg(m_kernelSocket.peerAddress().toString()).
	     arg(m_kernelSocket.peerPort()));
	else
	  m_kernelSocket.flush();
      }
}

void spoton::slotDisconnectListenerNeighbors(void)
{
  QString oid("");
  int row = -1;

  if((row = m_ui.listeners->currentRow()) >= 0)
    {
      QTableWidgetItem *item = m_ui.listeners->item
	(row, m_ui.listeners->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    return;

  if(m_kernelSocket.state() == QAbstractSocket::ConnectedState)
    if(m_kernelSocket.isEncrypted())
      {
	QByteArray message;

	message.append("disconnect_listener_neighbors_");
	message.append(oid);
	message.append("\n");

	if(m_kernelSocket.write(message.constData(), message.length()) !=
	   message.length())
	  spoton_misc::logError
	    (QString("spoton::slotDisconnectListenerNeighbors(): "
		     "write() failure for %1:%2.").
	     arg(m_kernelSocket.peerAddress().toString()).
	     arg(m_kernelSocket.peerPort()));
	else
	  m_kernelSocket.flush();
      }
}

void spoton::slotCallParticipant(void)
{
  if(!m_crypts.value("chat", 0))
    return;
  else if(m_kernelSocket.state() != QAbstractSocket::ConnectedState)
    return;
  else if(!m_kernelSocket.isEncrypted())
    return;

  QAction *action = qobject_cast<QAction *> (sender());

  if(!action)
    return;

  QString oid("");
  QString type(action->property("type").toString());
  int row = -1;

  if((row = m_ui.participants->currentRow()) >= 0)
    {
      QTableWidgetItem *item = m_ui.participants->item
	(row, 1); // OID

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    return;

  if(type == "calling")
    slotGenerateGeminiInChat();
  else
    saveGemini(QByteArray(), oid);

  QByteArray message;

  message.append("call_participant_");
  message.append(oid);
  message.append("\n");

  if(m_kernelSocket.write(message.constData(), message.length()) !=
     message.length())
    spoton_misc::logError
      (QString("spoton::slotCallParticipant(): write() failure for %1:%2.").
       arg(m_kernelSocket.peerAddress().toString()).
       arg(m_kernelSocket.peerPort()));
  else
    m_kernelSocket.flush();
}

void spoton::slotSignatureCheckBoxToggled(bool state)
{
  QCheckBox *checkBox = qobject_cast<QCheckBox *> (sender());
  QString str("");

  if(checkBox == m_ui.chatAcceptSigned)
    str = "chatAcceptSignedMessagesOnly";
  else if(checkBox == m_ui.chatSignMessages)
    str = "chatSignMessages";
  else if(checkBox == m_ui.emailAcceptSigned)
    str = "emailAcceptSignedMessagesOnly";
  else if(checkBox == m_ui.emailSignMessages)
    str = "emailSignMessages";
  else if(checkBox == m_ui.coAcceptSigned)
    str = "coAcceptSignedMessagesOnly";

  if(!str.isEmpty())
    {
      m_settings[QString("gui/%1").arg(str)] = state;

      QSettings settings;

      settings.setValue(QString("gui/%1").arg(str), state);
    }
}

void spoton::slotCopyEmailFriendshipBundle(void)
{
  QClipboard *clipboard = QApplication::clipboard();

  if(!clipboard)
    return;

  if(!m_crypts.value("email", 0) ||
     !m_crypts.value("email-signature", 0))
    {
      clipboard->clear();
      return;
    }

  QString oid("");
  int row = -1;

  if((row = m_ui.emailParticipants->currentRow()) >= 0)
    {
      QTableWidgetItem *item = m_ui.emailParticipants->item
	(row, 1); // OID

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    {
      clipboard->clear();
      return;
    }

  /*
  ** 1. Generate some symmetric information, S.
  ** 2. Encrypt S with the participant's public key.
  ** 3. Encrypt our information (name, public keys, signatures) with the
  **    symmetric key. Call our information T.
  ** 4. Compute a keyed hash of T using the symmetric key.
  */

  QString neighborOid("");
  QByteArray cipherType(m_settings.value("gui/kernelCipherType",
					 "randomized").toString().
			toLatin1());
  QByteArray gemini;
  QByteArray keyInformation;
  QByteArray publicKey;
  QByteArray symmetricKey;

  if(cipherType == "randomized")
    cipherType = spoton_crypt::randomCipherType();

  if(cipherType.isEmpty())
    {
      clipboard->clear();
      return;
    }

  spoton_misc::retrieveSymmetricData(gemini,
				     publicKey,
				     symmetricKey,
				     neighborOid,
				     cipherType,
				     oid,
				     m_crypts.value("email"));

  if(publicKey.isEmpty() || symmetricKey.isEmpty())
    {
      clipboard->clear();
      return;
    }

  bool ok = true;

  keyInformation = spoton_crypt::publicKeyEncrypt
    (symmetricKey.toBase64() + "@" + cipherType.toBase64(),
     publicKey, &ok);

  if(!ok)
    {
      clipboard->clear();
      return;
    }

  QByteArray mySPublicKey(m_crypts.value("email-signature")->publicKey(&ok));

  if(!ok)
    {
      clipboard->clear();
      return;
    }

  QByteArray mySSignature
    (m_crypts.value("email-signature")->digitalSignature(mySPublicKey, &ok));

  if(!ok)
    {
      clipboard->clear();
      return;
    }

  QByteArray myPublicKey(m_crypts.value("email")->publicKey(&ok));

  if(!ok)
    {
      clipboard->clear();
      return;
    }

  QByteArray mySignature(m_crypts.value("email")->
			 digitalSignature(myPublicKey, &ok));

  if(!ok)
    {
      clipboard->clear();
      return;
    }

  QByteArray myName
    (m_settings.value("gui/emailName", "unknown").toByteArray().
     trimmed());

  if(myName.isEmpty())
    myName = "unknown";

  QByteArray data;
  spoton_crypt crypt(cipherType,
		     QString("sha512"),
		     QByteArray(),
		     symmetricKey,
		     0,
		     0,
		     QString(""));

  data = crypt.encrypted(QByteArray("email").toBase64() + "@" +
			 myName.toBase64() + "@" +
			 myPublicKey.toBase64() + "@" +
			 mySignature.toBase64() + "@" +
			 mySPublicKey.toBase64() + "@" +
			 mySSignature.toBase64(), &ok);

  if(!ok)
    {
      clipboard->clear();
      return;
    }

  QByteArray hash(crypt.keyedHash(data, &ok));

  if(!ok)
    {
      clipboard->clear();
      return;
    }

  clipboard->setText("R" +
		     keyInformation.toBase64() + "@" +
		     data.toBase64() + "@" +
		     hash.toBase64());
}

void spoton::slotCopyAllMyPublicKeys(void)
{
  QClipboard *clipboard = QApplication::clipboard();

  if(clipboard)
    clipboard->setText(copyMyChatPublicKey() + "@" +
		       copyMyEmailPublicKey());
}

void spoton::slotAcceptedIPs(bool state)
{
  m_settings["gui/acceptedIPs"] = state;

  QSettings settings;

  settings.setValue("gui/acceptedIPs", state);
}

void spoton::slotPopulateAcceptedIPs(void)
{
  if(!m_crypts.value("chat", 0))
    return;

  QFileInfo fileInfo(spoton_misc::homePath() + QDir::separator() +
		     "accepted_ips.db");

  if(fileInfo.exists())
    {
      if(fileInfo.lastModified() <= m_acceptedIPsLastModificationTime)
	return;
      else
	m_acceptedIPsLastModificationTime = fileInfo.lastModified();
    }
  else
    m_acceptedIPsLastModificationTime = QDateTime();

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(fileInfo.absoluteFilePath());

    if(db.open())
      {
	QSqlQuery query(db);
	QWidget *focusWidget = QApplication::focusWidget();

	query.setForwardOnly(true);

	if(query.exec("SELECT ip_address FROM accepted_ips"))
	  {
	    QList<QListWidgetItem *> list
	      (m_ui.acceptedIPList->selectedItems());
	    QString selectedIP("");
	    QStringList acceptedIPList;
	    int hval = m_ui.acceptedIPList->horizontalScrollBar()->value();
	    int vval = m_ui.acceptedIPList->verticalScrollBar()->value();

	    if(!list.isEmpty())
	      selectedIP = list.at(0)->text();

	    m_ui.acceptedIPList->clear();

	    while(query.next())
	      {
		QString ip("");
		bool ok = true;

		ip = m_crypts.value("chat")->
		  decrypted(QByteArray::
			    fromBase64(query.
				       value(0).
				       toByteArray()),
			    &ok).constData();

		if(!ip.isEmpty())
		  acceptedIPList.append(ip);
	      }

	    qSort(acceptedIPList);

	    QListWidgetItem *selected = 0;

	    while(!acceptedIPList.isEmpty())
	      {
		QListWidgetItem *item = 0;

		item = new QListWidgetItem(acceptedIPList.takeFirst());
		item->setFlags
		  (Qt::ItemIsEnabled | Qt::ItemIsSelectable);

		m_ui.acceptedIPList->addItem(item);

		if(!selectedIP.isEmpty())
		  if(item->text() == selectedIP)
		    selected = item;
	      }

	    if(selected)
	      selected->setSelected(true);

	    m_ui.acceptedIPList->horizontalScrollBar()->setValue(hval);
	    m_ui.acceptedIPList->verticalScrollBar()->setValue(vval);

	    if(focusWidget)
	      focusWidget->setFocus();
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotSaveSslControlString(void)
{
  QString str(m_ui.sslControlString->text().trimmed());

  if(str.isEmpty())
    str = "HIGH:!aNULL:!eNULL:!3DES:!EXPORT:@STRENGTH";

  m_ui.sslControlString->setText(str);
  m_ui.sslControlString->selectAll();
  m_settings["gui/sslControlString"] = str;

  QSettings settings;

  settings.setValue("gui/sslControlString", str);
}

void spoton::slotDiscoverExternalAddress(void)
{
  m_externalAddress->discover();
}

void spoton::slotNeighborSelected(void)
{
  QTableWidgetItem *item = m_ui.neighbors->selectedItems().value(0);

  if(item)
    {
      QString label("");
      QStringList list;
      int row = item->row();

      for(int i = 0; i < m_ui.neighbors->columnCount() - 2; i++)
	{
	  QTableWidgetItem *item = m_ui.neighbors->item(row, i);

	  if(item)
	    {
	      label += m_ui.neighbors->horizontalHeaderItem(i)->text() +
		": %" + QString::number(i) + "\n";
	      list << item->text();
	    }
	}

      QString str
	(label.
	 arg(list.value(0)).
	 arg(list.value(1)).
	 arg(list.value(2)).
	 arg(list.value(3)).
	 arg(list.value(4)).
	 arg(list.value(5)).
	 arg(list.value(6)).
	 arg(list.value(7)).
	 arg(list.value(8)).
	 arg(list.value(9)).
	 arg(list.value(10)).
	 arg(list.value(11)).
	 arg(list.value(12)).
	 arg(list.value(13)).
	 arg(list.value(14)).
	 arg(list.value(15)).
	 arg(list.value(16)).
	 arg(list.value(17)).
	 arg(list.value(18)).
	 arg(list.value(19)).
	 arg(list.value(20)).
	 arg(list.value(21)).
	 arg(list.value(22)));
      int h = m_ui.neighborSummary->horizontalScrollBar()->value();
      int v = m_ui.neighborSummary->verticalScrollBar()->value();

      m_ui.neighborSummary->setText(str);
      m_ui.neighborSummary->horizontalScrollBar()->setValue(h);
      m_ui.neighborSummary->verticalScrollBar()->setValue(v);
    }
}

void spoton::slotChangeTabPosition(void)
{
  QAction *action = qobject_cast<QAction *> (sender());

  if(action)
    {
      action->setChecked(true); /*
				** Do not allow the user to uncheck
				** the checked action.
				*/

      for(int i = 0; i < m_ui.menu_Tab_Position->actions().size(); i++)
	if(action != m_ui.menu_Tab_Position->actions().at(i))
	  m_ui.menu_Tab_Position->actions().at(i)->setChecked(false);
    }

  if(action == m_ui.action_East)
    {
      m_settings["gui/tabPosition"] = "east";
      m_ui.tab->setTabPosition(QTabWidget::East);
    }
  else if(action == m_ui.action_West)
    {
      m_settings["gui/tabPosition"] = "west";
      m_ui.tab->setTabPosition(QTabWidget::West);
    }
  else
    {
      m_settings["gui/tabPosition"] = "north";
      m_ui.tab->setTabPosition(QTabWidget::North);
    }

  QSettings settings;

  settings.setValue("gui/tabPosition", m_settings.value("gui/tabPosition"));
}

void spoton::slotAuthenticate(void)
{
  spoton_crypt *s_crypt = m_crypts.value("chat", 0);

  if(!s_crypt)
    {
      QMessageBox::critical(this, tr("Spot-On: Error"),
			    tr("Invalid spoton_crypt object."));
      return;
    }

  QModelIndexList list;

  list = m_ui.neighbors->selectionModel()->selectedRows
    (m_ui.neighbors->columnCount() - 1); // OID

  if(list.isEmpty())
    {
      QMessageBox::critical(this, tr("Spot-On: Error"),
			    tr("Invalid neighbors OID."));
      return;
    }

  QDialog dialog(this);
  Ui_passwordprompt ui;

  ui.setupUi(&dialog);
#ifdef Q_OS_MAC
  dialog.setAttribute(Qt::WA_MacMetalStyle, false);
#endif

  if(dialog.exec() == QDialog::Accepted)
    {
      QString name(ui.name->text().trimmed());
      QString password(ui.password->text());

      if(!name.isEmpty() && password.length() >= 16)
	{
	  QString connectionName("");

	  {
	    QSqlDatabase db = spoton_misc::database(connectionName);

	    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
			       "neighbors.db");

	    if(db.open())
	      {
		QSqlQuery query(db);
		bool ok = true;

		query.prepare("UPDATE neighbors SET "
			      "account_name = ?, "
			      "account_password = ? "
			      "WHERE OID = ? and user_defined = 1");
		query.bindValue
		  (0, s_crypt->encrypted(name.toLatin1(), &ok).toBase64());

		if(ok)
		  query.bindValue
		    (1, s_crypt->encrypted(password.toLatin1(),
					   &ok).toBase64());

		query.bindValue(2, list.at(0).data());

		if(ok)
		  query.exec();
	      }

	    db.close();
	  }

	  QSqlDatabase::removeDatabase(connectionName);
	}
      else
	QMessageBox::critical(this, tr("Spot-On: Error"),
			      tr("The account name must be non-empty "
				 "and the account password must contain "
				 "at least sixteen characters."));
    }
}
