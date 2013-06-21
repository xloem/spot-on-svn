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

#include "spot-on.h"

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
  Q_UNUSED(new spoton());
  return qapplication.exec();
}

spoton::spoton(void):QMainWindow()
{
  qsrand(QTime(0, 0, 0).secsTo(QTime::currentTime()));
  QDir().mkdir(spoton_misc::homePath());
  m_crypt = 0;
  m_countriesLastModificationTime = QDateTime();
  m_listenersLastModificationTime = QDateTime();
  m_neighborsLastModificationTime = QDateTime();
  m_participantsLastModificationTime = QDateTime();
  m_ui.setupUi(this);
#ifndef SPOTON_LINKED_WITH_LIBGEOIP
  m_ui.countries->setEnabled(false);
  m_ui.countries->setToolTip(tr("Spot-On was configured without "
				"libGeoIP."));
#endif
#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
  setAttribute(Qt::WA_MacMetalStyle, true);
#endif
#endif
  m_sbWidget = new QWidget(this);
  m_sb.setupUi(m_sbWidget);
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
  connect(m_ui.selectKernelPath,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSelectKernelPath(void)));
  connect(m_ui.setPassphrase,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSetPassphrase(void)));
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
  connect(m_ui.saveNodeName,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSaveNodeName(void)));
  connect(m_ui.nodeName,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotSaveNodeName(void)));
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
  connect(m_ui.addFriend,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotAddFriendsKey(void)));
  connect(m_ui.clearFriend,
	  SIGNAL(clicked(void)),
	  m_ui.friendInformation,
	  SLOT(clear(void)));
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
  connect(m_ui.acceptPublicizedListeners,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotAcceptPublicizedListeners(bool)));
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
  connect(m_ui.newRSAKeys,
	  SIGNAL(toggled(bool)),
	  m_ui.rsaKeySize,
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
  connect(&m_generalTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotGeneralTimerTimeout(void)));
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
	  SIGNAL(readyRead(void)),
	  this,
	  SLOT(slotReceivedKernelMessage(void)));
  m_sb.kernelstatus->setToolTip
    (tr("Not connected to the kernel. Is the kernel "
	"active?"));
  m_sb.listeners->setToolTip(tr("Listeners are offline."));
  m_sb.neighbors->setToolTip(tr("Neighbors are offline."));

  QMenu *menu = new QMenu(this);

  connect(menu->addAction(tr("Copy &Messaging Public Key")),
	  SIGNAL(triggered(void)), this, SLOT(slotCopyMyPublicKey(void)));
  connect(menu->addAction(tr("Copy &URL Public Key")),
	  SIGNAL(triggered(void)), this, SLOT(slotCopyMyURLPublicKey(void)));
  m_ui.toolButtonCopytoClipboard->setMenu(menu);
  menu = new QMenu(this);
  connect(menu->addAction(tr("Share &Messaging Public Key")),
	  SIGNAL(triggered(void)), this, SLOT(slotSharePublicKey(void)));
  connect(menu->addAction(tr("Share &URL Public Key")),
	  SIGNAL(triggered(void)), this, SLOT(slotShareURLPublicKey(void)));
  m_ui.toolButtonMakeFriends->setMenu(menu);
  m_generalTimer.start(2500);
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

  if(m_settings.contains("gui/kernelPath") &&
     QFileInfo(m_settings.value("gui/kernelPath").toString().trimmed()).
     isExecutable())
    m_ui.kernelPath->setText(m_settings.value("gui/kernelPath").toString().
			   trimmed());
  else
    {
      QString path(QCoreApplication::applicationDirPath() +
		   QDir::separator() +
#ifdef Q_OS_MAC
		   "Spot-On-Kernel.app"
#elif defined(Q_OS_WIN32)
		   "Spot-On-Kernel.exe"
#else
		   "Spot-On-Kernel"
#endif
		   );

#ifdef Q_OS_MAC
      if(!QFileInfo(path).exists())
	path = QCoreApplication::applicationDirPath() +
	  QDir::separator() + "Spot-On-Kernel";
#endif

      m_ui.kernelPath->setText(path);
    }

  if(m_settings.value("gui/chatSendMethod", "Artificial_GET").
     toString() == "Artificial_GET")
    m_ui.chatSendMethod->setCurrentIndex(0);
  else
    m_ui.chatSendMethod->setCurrentIndex(1);

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

  m_ui.kernelPath->setToolTip(m_ui.kernelPath->text());
  m_ui.nodeName->setMaxLength(NAME_MAXIMUM_LENGTH);
  m_ui.nodeName->setText
    (QString::fromUtf8(m_settings.value("gui/nodeName", "unknown").
		       toByteArray()).trimmed());
  m_ui.goldbug->setMaxLength
    (spoton_gcrypt::cipherKeyLength("aes256"));
  m_ui.cipherType->clear();
  m_ui.cipherType->addItems(spoton_gcrypt::cipherTypes());
  m_ui.cost->setValue(m_settings.value("gui/congestionCost", 10000).toInt());
  m_ui.days->setValue(m_settings.value("gui/postofficeDays", 1).toInt());
  m_ui.acceptPublicizedListeners->setChecked
    (m_settings.value("gui/acceptPublicizedListeners", false).toBool());
  m_ui.congestionControl->setChecked
    (m_settings.value("gui/enableCongestionControl", false).toBool());
  m_ui.cost->setEnabled(m_ui.congestionControl->isChecked());
  m_ui.keepOnlyUserDefinedNeighbors->setChecked
    (m_settings.value("gui/keepOnlyUserDefinedNeighbors", false).toBool());
  m_ui.postofficeCheckBox->setChecked
    (m_settings.value("gui/postoffice_enabled", false).toBool());
  m_ui.saveCopy->setChecked
    (m_settings.value("gui/saveCopy", true).toBool());
  m_ui.scrambler->setChecked
    (m_settings.value("gui/scramblerEnabled", false).toBool());

  /*
  ** Please don't translate n/a.
  */

  if(m_ui.cipherType->count() == 0)
    m_ui.cipherType->addItem("n/a");

  m_ui.hashType->clear();
  m_ui.hashType->addItems(spoton_gcrypt::hashTypes());

  if(m_ui.cipherType->count() == 0)
    m_ui.cipherType->addItem("n/a");

  QString str("");

  str = m_settings.value("gui/cipherType", "aes256").
    toString().toLower().trimmed();

  if(m_ui.cipherType->findText(str) > -1)
    m_ui.cipherType->setCurrentIndex(m_ui.cipherType->findText(str));

  str = m_settings.value("gui/hashType", "sha512").
    toString().toLower().trimmed();

  if(m_ui.hashType->findText(str) > -1)
    m_ui.hashType->setCurrentIndex(m_ui.hashType->findText(str));

  m_ui.iterationCount->setValue(m_settings.value("gui/iterationCount",
						 10000).toInt());
  str = m_settings.value("gui/rsaKeySize", "3072").
    toString().toLower().trimmed();

  if(m_ui.rsaKeySize->findText(str) > -1)
    m_ui.rsaKeySize->setCurrentIndex(m_ui.rsaKeySize->findText(str));

  m_ui.saltLength->setValue(m_settings.value("gui/saltLength", 256).toInt());

  if(spoton_gcrypt::passphraseSet())
    {
      m_sb.kernelstatus->setEnabled(false);
      m_sb.listeners->setEnabled(false);
      m_sb.neighbors->setEnabled(false);
      m_ui.passphrase1->setText("0000000000");
      m_ui.passphrase2->setText("0000000000");
      m_ui.rsaKeySize->setEnabled(false);

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
      m_ui.newRSAKeys->setChecked(true);
      m_ui.newRSAKeys->setEnabled(false);
      m_ui.passphrase->setEnabled(false);
      m_ui.passphraseButton->setEnabled(false);
      m_ui.passphraseLabel->setEnabled(false);
      m_ui.kernelBox->setEnabled(false);
      m_ui.listenersBox->setEnabled(false);

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

  m_ui.listeners->setContextMenuPolicy(Qt::CustomContextMenu);
  m_ui.neighbors->setContextMenuPolicy(Qt::CustomContextMenu);
  m_ui.participants->setContextMenuPolicy(Qt::CustomContextMenu);
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
  m_ui.emailParticipants->setColumnHidden(2, true); // public_key_hash
  m_ui.mail->setColumnHidden(4, true); // goldbug
  m_ui.mail->setColumnHidden(5, true); // message
  m_ui.mail->setColumnHidden(6, true); // message_digest
  m_ui.mail->setColumnHidden(7, true); // receiver_sender_hash
  m_ui.mail->setColumnHidden(8, true); // OID
  m_ui.listeners->setColumnHidden(m_ui.listeners->columnCount() - 1,
				  true); // OID
  m_ui.neighbors->setColumnHidden
    (m_ui.neighbors->columnCount() - 1, true); // OID
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
    (2, Qt::AscendingOrder);
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
  m_ui.urlsVerticalSplitter->setStretchFactor(0, 1);
  m_ui.urlsVerticalSplitter->setStretchFactor(1, 0);
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

  show();
  QApplication::processEvents();
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  m_sb.status->setText(tr("Preparing databases. Please be patient."));
  QApplication::processEvents();
  spoton_misc::prepareDatabases();
  m_sb.status->clear();
  QApplication::restoreOverrideCursor();
}

void spoton::slotQuit(void)
{
  close();
}

void spoton::slotAddListener(void)
{
  if(!m_crypt)
    return;

  bool ok = true;

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "listeners.db");

    if(db.open())
      {
	spoton_misc::prepareDatabases();

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
		      "hash) "
		      "VALUES "
		      "(?, ?, ?, ?, ?, ?)");

	if(ip.isEmpty())
	  query.bindValue
	    (0, m_crypt->encrypted(QByteArray(), &ok).toBase64());
	else
	  {
	    QList<int> numbers;
	    QStringList list;

	    if(protocol == "IPv4")
	      list = ip.split(".", QString::KeepEmptyParts);
	    else
	      list = ip.split(":", QString::KeepEmptyParts);

	    for(int i = 0; i < list.size(); i++)
	      numbers.append(list.at(i).toInt());

	    if(protocol == "IPv4")
	      {
		ip = QString::number(numbers.value(0)) + "." +
		  QString::number(numbers.value(1)) + "." +
		  QString::number(numbers.value(2)) + "." +
		  QString::number(numbers.value(3));
		ip.remove("...");
	      }
	    else
	      {
		if(m_ui.listenerIPCombo->currentIndex() == 0)
		  {
		    ip = QString::number(numbers.value(0)) + ":" +
		      QString::number(numbers.value(1)) + ":" +
		      QString::number(numbers.value(2)) + ":" +
		      QString::number(numbers.value(3)) + ":" +
		      QString::number(numbers.value(4)) + ":" +
		      QString::number(numbers.value(5)) + ":" +
		      QString::number(numbers.value(6)) + ":" +
		      QString::number(numbers.value(7));
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
		(0, m_crypt->encrypted(ip.toLatin1(), &ok).toBase64());
	  }

	if(ok)
	  query.bindValue
	    (1, m_crypt->encrypted(port.toLatin1(), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (2, m_crypt->encrypted(protocol.toLatin1(), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (3, m_crypt->encrypted(scopeId.toLatin1(), &ok).toBase64());

	query.bindValue(4, status);

	if(ok)
	  query.bindValue
	    (5, m_crypt->keyedHash((ip + port + scopeId).toLatin1(), &ok).
	     toBase64());

	if(ok)
	  ok = query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton");

  if(ok)
    m_ui.listenerIP->selectAll();
}

void spoton::slotAddNeighbor(void)
{
  if(!m_crypt)
    return;

  bool ok = true;

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "neighbors.db");

    if(db.open())
      {
	spoton_misc::prepareDatabases();

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
		      "proxy_username) "
		      "VALUES "
		      "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");

	query.bindValue(0, QVariant(QVariant::String));
	query.bindValue(1, QVariant(QVariant::String));
	query.bindValue(2, protocol);

	if(ip.isEmpty())
	  query.bindValue
	    (3, m_crypt->encrypted(QByteArray(), &ok).toBase64());
	else
	  {
	    if(protocol == "IPv4" || protocol == "IPv6")
	      {
		QList<int> numbers;
		QStringList list;

		if(protocol == "IPv4")
		  list = ip.split(".", QString::KeepEmptyParts);
		else
		  list = ip.split(":", QString::KeepEmptyParts);

		for(int i = 0; i < list.size(); i++)
		  numbers.append(list.at(i).toInt());

		ip.clear();

		if(protocol == "IPv4")
		  {
		    ip = QString::number(numbers.value(0)) + "." +
		      QString::number(numbers.value(1)) + "." +
		      QString::number(numbers.value(2)) + "." +
		      QString::number(numbers.value(3));
		    ip.remove("...");
		  }
		else
		  {
		    ip = QString::number(numbers.value(0)) + ":" +
		      QString::number(numbers.value(1)) + ":" +
		      QString::number(numbers.value(2)) + ":" +
		      QString::number(numbers.value(3)) + ":" +
		      QString::number(numbers.value(4)) + ":" +
		      QString::number(numbers.value(5)) + ":" +
		      QString::number(numbers.value(6)) + ":" +
		      QString::number(numbers.value(7));
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
		(3, m_crypt->encrypted(ip.toLatin1(), &ok).toBase64());
	  }

	query.bindValue(5, 1); // Sticky.

	if(ok)
	  query.bindValue
	    (4, m_crypt->encrypted(port.toLatin1(), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (6, m_crypt->encrypted(scopeId.toLatin1(), &ok).toBase64());

	proxyHostname = m_ui.proxyHostname->text().trimmed();
	proxyPort = QString::number(m_ui.proxyPort->value());

	if(ok)
	  query.bindValue
	    (7, m_crypt->
	     keyedHash((proxyHostname + proxyPort + ip + port + scopeId).
		       toLatin1(), &ok).
	     toBase64());

	query.bindValue(8, status);

	QString country(spoton_misc::countryNameFromIPAddress(ip));

	if(ok)
	  query.bindValue
	    (9, m_crypt->encrypted(country.toLatin1(), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (10, m_crypt->keyedHash(ip.toLatin1(), &ok).
	     toBase64());

	if(ok)
	  query.bindValue
	    (11, m_crypt->keyedHash(country.remove(" ").toLatin1(), &ok).
	     toBase64());

	proxyPassword = m_ui.proxyPassword->text();

	if(m_ui.proxy->isChecked())
	  proxyType = m_ui.proxyType->currentText();
	else
	  proxyType = "NoProxy";

	proxyUsername = m_ui.proxyUsername->text();

	if(ok)
	  query.bindValue
	    (12, m_crypt->encrypted(proxyHostname.toLatin1(), &ok).
	     toBase64());

	if(ok)
	  query.bindValue
	    (13, m_crypt->encrypted(proxyPassword.toUtf8(), &ok).
	     toBase64());

	if(ok)
	  query.bindValue
	    (14, m_crypt->encrypted(proxyPort.toLatin1(),
				    &ok).toBase64());

	if(ok)
	  query.bindValue
	    (15, m_crypt->encrypted(proxyType.toLatin1(), &ok).
	     toBase64());

	if(ok)
	  query.bindValue
	    (16, m_crypt->encrypted(proxyUsername.toUtf8(), &ok).
	     toBase64());

	if(ok)
	  ok = query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton");

  if(ok)
    m_ui.neighborIP->selectAll();
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
  if(!m_crypt)
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

  int active = 0;

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton");

    db.setDatabaseName(fileInfo.absoluteFilePath());

    if(db.open())
      {
	updateListenersTable(db);

	QModelIndexList list;
	QString ip("");
	QString port("");
	QString scopeId("");
	int columnIP = 2;
	int columnPORT = 3;
	int columnSCOPE_ID = 4;
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
		      "status_control, status, "
		      "ip_address, port, scope_id, protocol, "
		      "external_ip_address, external_port, "
		      "connections, maximum_clients, OID "
		      "FROM listeners"))
	  {
	    row = 0;

	    while(query.next())
	      {
		QCheckBox *check = 0;
		QComboBox *box = 0;
		QTableWidgetItem *item = 0;

		m_ui.listeners->setRowCount(row + 1);

		for(int i = 0; i < query.record().count(); i++)
		  {
		    if(i == 0)
		      {
			check = new QCheckBox();

			if(query.value(0) == "online")
			  check->setChecked(true);

			if(query.value(1) == "online")
			  active += 1;

			check->setProperty("oid", query.value(10));
			check->setProperty("table_row", row);
			connect(check,
				SIGNAL(stateChanged(int)),
				this,
				SLOT(slotListenerCheckChange(int)));
			m_ui.listeners->setCellWidget(row, i, check);
		      }
		    else if(i == 9)
		      {
			box = new QComboBox();
			box->setProperty("oid", query.value(10));
			box->setProperty("table_row", row);
			box->addItem("1");

			for(int j = 1; j <= 10; j++)
			  box->addItem(QString::number(5 * j));

			box->addItem(tr("Unlimited"));
			box->setMaximumWidth
			  (box->fontMetrics().width(tr("Unlimited")) + 50);
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
			bool ok = true;

			if(i >= 2 && i <= 6)
			  {
			    if(query.isNull(i))
			      item = new QTableWidgetItem();
			    else
			      item = new QTableWidgetItem
				(m_crypt->decrypted(QByteArray::
						    fromBase64(query.
							       value(i).
							       toByteArray()),
						    &ok).
				 constData());
			  }
			else
			  item = new QTableWidgetItem(query.
						      value(i).toString());

			item->setFlags
			  (Qt::ItemIsSelectable | Qt::ItemIsEnabled);
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
		bool ok = true;

		bytes1 = m_crypt->decrypted
		  (QByteArray::fromBase64(query.value(2).toByteArray()),
		   &ok);
		bytes2 = m_crypt->decrypted
		  (QByteArray::fromBase64(query.value(3).toByteArray()),
		   &ok);
		bytes3 = m_crypt->decrypted
		  (QByteArray::fromBase64(query.value(4).toByteArray()),
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

  QSqlDatabase::removeDatabase("spoton");

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
  if(!m_crypt)
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

  int active = 0;

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton");

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
	int columnCOUNTRY = 8;
	int columnPROXY_IP = 13;
	int columnPROXY_PORT = 14;
	int columnREMOTE_IP = 9;
	int columnREMOTE_PORT = 10;
	int columnSCOPE_ID = 11;
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

	if(query.exec("SELECT sticky, UPPER(uuid), status, "
		      "status_control, "
		      "local_ip_address, local_port, "
		      "external_ip_address, external_port, "
		      "country, "
		      "remote_ip_address, "
		      "remote_port, scope_id, protocol, "
		      "proxy_hostname, proxy_port, OID "
		      "FROM neighbors"))
	  {
	    QString localIp("");
	    QString localPort("");

	    row = 0;

	    while(query.next())
	      {
		m_ui.neighbors->setRowCount(row + 1);

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

		for(int i = 1; i < query.record().count(); i++)
		  {
		    QTableWidgetItem *item = 0;

		    if(i == 2)
		      {
			if(query.value(i).toString() == "connected")
			  active += 1;
		      }

		    if(i == 6 || (i >= 8 && i <= 11) || (i >= 13 && i <= 14))
		      {
			if(query.value(i).isNull())
			  item = new QTableWidgetItem();
			else
			  {
			    bool ok = true;

			    item = new QTableWidgetItem
			      (m_crypt->decrypted(QByteArray::
						  fromBase64(query.
							     value(i).
							     toByteArray()),
						  &ok).constData());
			  }
		      }
		    else
		      item = new QTableWidgetItem
			(query.value(i).toString());

		    item->setFlags(Qt::ItemIsSelectable | Qt::ItemIsEnabled);

		    if(i == 2)
		      {
			if(query.value(i).toString() == "connected")
			  item->setBackground(QBrush(QColor("lightgreen")));
			else
			  item->setBackground(QBrush());
		      }

		    m_ui.neighbors->setItem(row, i, item);
		  }

		QTableWidgetItem *item1 = m_ui.neighbors->item
		  (row, columnCOUNTRY);

		if(item1)
		  {
		    QIcon icon;
		    QTableWidgetItem *item2 = m_ui.neighbors->item
		      (row, columnREMOTE_IP);

		    if(item2)
		      icon =
			QIcon(QString(":/Flags/%1.png").
			      arg(spoton_misc::
				  countryCodeFromIPAddress(item2->text()).
				  toLower()));
		    else
		      icon = QIcon(":/Flags/unknown.png");

		    if(!icon.isNull())
		      item1->setIcon(icon);
		  }

		QByteArray bytes1;
		QByteArray bytes2;
		QByteArray bytes3;
		QByteArray bytes4;
		QByteArray bytes5;
		QWidget *focusWidget = QApplication::focusWidget();
		bool ok = true;

		bytes1 = m_crypt->decrypted
		  (QByteArray::fromBase64(query.value(columnREMOTE_IP).
					  toByteArray()), &ok);
		bytes2 = m_crypt->decrypted
		  (QByteArray::fromBase64(query.value(columnREMOTE_PORT).
					  toByteArray()), &ok);
		bytes3 = m_crypt->decrypted
		  (QByteArray::fromBase64(query.value(columnSCOPE_ID).
					  toByteArray()), &ok);
		bytes4 = m_crypt->decrypted
		  (QByteArray::fromBase64(query.value(columnPROXY_IP).
					  toByteArray()), &ok);
		bytes5 = m_crypt->decrypted
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
	  }

	m_ui.neighbors->setSortingEnabled(true);
	m_ui.neighbors->horizontalHeader()->setStretchLastSection(true);
	m_ui.neighbors->horizontalScrollBar()->setValue(hval);
	m_ui.neighbors->verticalScrollBar()->setValue(vval);
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton");

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
      m_messagingCache.clear();
      m_sb.neighbors->setIcon
	(QIcon(QString(":/%1/status-offline.png").
	       arg(m_settings.value("gui/iconSet", "nouve").toString())));
      m_sb.neighbors->setToolTip(tr("Neighbors are offline."));
    }
}

void spoton::slotActivateKernel(void)
{
  QString program(m_ui.kernelPath->text());

#ifdef Q_OS_MAC
  if(QFileInfo(program).isBundle())
    QProcess::startDetached
      ("open", QStringList("-a") << program);
  else
    QProcess::startDetached(program);
#elif defined(Q_OS_WIN32)
  /*
  ** Must surround the executable's name with quotations.
  */

  QProcess::startDetached(QString("\"%1\"").arg(program));
#else
  QProcess::startDetached(program);
#endif
}

void spoton::slotDeactivateKernel(void)
{
  QString sharedPath(spoton_misc::homePath() + QDir::separator() +
		     "shared.db");
  libspoton_handle_t libspotonHandle;

  if(libspoton_init(sharedPath.toStdString().c_str(),
		    &libspotonHandle) == LIBSPOTON_ERROR_NONE)
    libspoton_deregister_kernel
      (libspoton_registered_kernel_pid(&libspotonHandle), &libspotonHandle);

  libspoton_close(&libspotonHandle);
  m_kernelSocket.close();
  m_messagingCache.clear();
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

  if(libspoton_init(sharedPath.toStdString().c_str(),
		    &libspotonHandle) == LIBSPOTON_ERROR_NONE)
    {
      m_ui.pid->setText
	(QString::number(libspoton_registered_kernel_pid(&libspotonHandle)));

      if(isKernelActive())
	{
	  QColor color(144, 238, 144); // Light green!
	  QPalette palette(m_ui.pid->palette());

	  palette.setColor(m_ui.pid->backgroundRole(), color);
	  m_ui.pid->setPalette(palette);
	}
      else
	m_ui.pid->setPalette(pidPalette);
    }
  else
    m_ui.pid->setPalette(pidPalette);

  libspoton_close(&libspotonHandle);
  highlightKernelPath();

  if(text != m_ui.pid->text())
    {
      m_countriesLastModificationTime = QDateTime();
      m_listenersLastModificationTime = QDateTime();
      m_neighborsLastModificationTime = QDateTime();
      m_participantsLastModificationTime = QDateTime();
    }

  if(text != "0")
    if(m_kernelSocket.state() == QAbstractSocket::UnconnectedState)
      {
	{
	  QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton");

	  db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
			     "kernel.db");

	  if(db.open())
	    {
	      QSqlQuery query(db);

	      query.setForwardOnly(true);

	      if(query.exec("SELECT port FROM kernel_gui_server"))
		if(query.next())
		  {
		    m_kernelSocket.connectToHost("127.0.0.1",
						 query.value(0).toInt());

		    /*
		    ** If the kernel is not responsive, terminate it.
		    */

		    if(!m_kernelSocket.waitForConnected(10000))
		      slotDeactivateKernel();
		  }
	    }

	  db.close();
	}

	QSqlDatabase::removeDatabase("spoton");
      }

  slotKernelSocketState();
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

void spoton::slotSaveKernelPath(void)
{
  saveKernelPath(m_ui.kernelPath->text().trimmed());
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

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton");

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
			"OID = ?");

	query.bindValue(0, oid);
	query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton");

  if(row > -1)
    m_ui.listeners->removeRow(row);
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

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton");

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
			"WHERE OID = ?");

	query.bindValue(0, oid);
	query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton");

  if(row > -1)
    m_ui.neighbors->removeRow(row);
}

void spoton::slotListenerCheckChange(int state)
{
  QCheckBox *checkBox = qobject_cast<QCheckBox *> (sender());

  if(checkBox)
    {
      {
	QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton");

	db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
			   "listeners.db");

	if(db.open())
	  {
	    QSqlQuery query(db);

	    query.prepare("UPDATE listeners SET "
			  "status_control = ? "
			  "WHERE OID = ?");

	    if(state)
	      query.bindValue(0, "online");
	    else
	      query.bindValue(0, "offline");

	    query.bindValue(1, checkBox->property("oid"));
	    query.exec();
	  }

	db.close();
      }

      QSqlDatabase::removeDatabase("spoton");
    }
}

void spoton::updateListenersTable(QSqlDatabase &db)
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

	query.exec("PRAGMA synchronous = OFF");
	query.exec("DELETE FROM listeners WHERE "
		   "status_control = 'deleted'");
	query.exec("UPDATE listeners SET connections = 0, "
		   "external_ip_address = NULL, "
		   "status = 'offline' WHERE "
		   "(status = 'online' OR connections > 0) AND "
		   "status_control <> 'deleted'");
      }
}

void spoton::updateNeighborsTable(QSqlDatabase &db)
{
  if(m_ui.keepOnlyUserDefinedNeighbors->isChecked())
    if(db.isOpen())
      {
	/*
	** Delete random, disconnected peers.
	*/

	QSqlQuery query(db);

	query.exec("PRAGMA synchronous = OFF");
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

	query.exec("PRAGMA synchronous = OFF");
	query.exec("DELETE FROM neighbors WHERE "
		   "status_control = 'deleted'");
	query.exec("UPDATE neighbors SET external_ip_address = NULL, "
		   "local_ip_address = NULL, "
		   "local_port = NULL, status = 'disconnected' WHERE "
		   "(local_ip_address IS NOT NULL OR local_port IS NOT NULL "
		   "OR status <> 'disconnected') AND "
		   "status_control <> 'deleted'");
      }
}

void spoton::updateParticipantsTable(QSqlDatabase &db)
{
  if(!isKernelActive())
    if(db.isOpen())
      {
	QSqlQuery query(db);

	/*
	** OK, so the kernel is inactive. All participants are offline.
	*/

	query.exec("PRAGMA synchronous = OFF");
	query.exec("UPDATE symmetric_keys SET status = 'offline' WHERE "
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
			    tr("The passphrases are not equal."));
      m_ui.passphrase1->selectAll();
      m_ui.passphrase1->setFocus();
      return;
    }

  if(spoton_gcrypt::passphraseSet())
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
		    "existing passphrase? Please note that URL data must "
		    "be re-encoded via a separate tool. Please see "
		    "the Tools folder."));

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
  QApplication::processEvents();
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  /*
  ** Generate a key and use the key to encrypt the private RSA key.
  */

  QByteArray salt;
  QByteArray saltedPassphraseHash;
  QString error1("");
  QString error2("");
  QString error3("");

  salt.resize(m_ui.saltLength->value());
  salt = spoton_gcrypt::strongRandomBytes(salt.length());

  QByteArray derivedKey
    (spoton_gcrypt::derivedKey(m_ui.cipherType->currentText(),
			       m_ui.hashType->currentText(),
			       static_cast<unsigned long> (m_ui.
							   iterationCount->
							   value()),
			       str1,
			       salt,
			       error1));

  m_sb.status->clear();

  if(error1.isEmpty())
    {
      slotDeactivateKernel();

      if(!m_ui.newRSAKeys->isChecked() && reencode)
	{
	  m_sb.status->setText
	    (tr("Re-encoding RSA key pair 1 of 2. Please be patient."));
	  m_sb.status->repaint();
	  spoton_gcrypt::reencodeRSAKeys
	    (m_ui.cipherType->currentText(),
	     derivedKey,
	     m_settings.value("gui/cipherType", "aes256").
	     toString().trimmed(),
	     m_crypt->symmetricKey(),
	     "messaging",
	     error2);
	  m_sb.status->clear();

	  if(error2.isEmpty())
	    {
	      m_sb.status->setText
		(tr("Re-encoding RSA key pair 2 of 2. Please be patient."));
	      m_sb.status->repaint();
	      spoton_gcrypt::reencodeRSAKeys
		(m_ui.cipherType->currentText(),
		 derivedKey,
		 m_settings.value("gui/cipherType", "aes256").
		 toString().trimmed(),
		 m_crypt->symmetricKey(),
		 "url",
		 error2);
	      m_sb.status->clear();
	    }
	}
      else
	{
	  QStringList list;

	  list << "messaging"
	       << "url";

	  for(int i = 0; i < list.size(); i++)
	    {
	      m_sb.status->setText
		(tr("Generating RSA key pair %1 of %2. Please be patient.").
		 arg(i + 1).arg(list.size()));
	      m_sb.status->repaint();

	      spoton_gcrypt crypt
		(m_ui.cipherType->currentText(),
		 m_ui.hashType->currentText(),
		 str1.toUtf8(),
		 derivedKey,
		 m_ui.saltLength->value(),
		 m_ui.iterationCount->value(),
		 list.at(i));

	      crypt.generatePrivatePublicKeys
		(m_ui.rsaKeySize->currentText().toInt(), error2);
	      m_sb.status->clear();

	      if(!error2.isEmpty())
		break;
	    }
	}
    }

  if(error1.isEmpty() && error2.isEmpty())
    saltedPassphraseHash = spoton_gcrypt::saltedPassphraseHash
      (m_ui.hashType->currentText(), str1, salt, error3);

  QApplication::restoreOverrideCursor();

  if(!error1.isEmpty())
    QMessageBox::critical(this, tr("Spot-On: Error"),
			  tr("An error (%1) occurred with spoton_gcrypt::"
			     "derivedKey().").arg(error1.remove(".")));
  else if(!error2.isEmpty())
    QMessageBox::critical(this, tr("Spot-On: Error"),
			  tr("An error (%1) occurred with "
			     "spoton_gcrypt::"
			     "generatePrivatePublicKeys() or "
			     "spoton_gcrypt::"
			     "reencodeRSAKeys().").
			  arg(error2.remove(".")));
  else if(!error3.isEmpty())
    QMessageBox::critical(this, tr("Spot-On: Error"),
			  tr("An error (%1) occurred with spoton_gcrypt::"
			     "saltedPassphraseHash().").
			  arg(error3.remove(".")));
  else
    {
      if(!m_crypt || reencode)
	{
	  if(reencode)
	    {
	      spoton_gcrypt *crypt = new spoton_gcrypt
		(m_ui.cipherType->currentText(),
		 m_ui.hashType->currentText(),
		 str1.toUtf8(),
		 derivedKey,
		 m_ui.saltLength->value(),
		 m_ui.iterationCount->value(),
		 "messaging");

	      spoton_reencode reencode;

	      m_tableTimer.stop();
	      reencode.reencode(m_sb, crypt, m_crypt);
	      delete crypt;
	      m_tableTimer.start();
	    }

	  delete m_crypt;
	  m_crypt = new spoton_gcrypt
	    (m_ui.cipherType->currentText(),
	     m_ui.hashType->currentText(),
	     str1.toUtf8(),
	     derivedKey,
	     m_ui.saltLength->value(),
	     m_ui.iterationCount->value(),
	     "messaging");

	  if(!reencode)
	    {
	      m_sb.status->setText
		(tr("Initializing country_inclusion.db."));
	      m_sb.status->repaint();
	      QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
	      spoton_misc::populateCountryDatabase(m_crypt);
	      QApplication::restoreOverrideCursor();
	      m_sb.status->clear();
	    }

	  if(!m_tableTimer.isActive())
	    m_tableTimer.start();

	  sendKeysToKernel();
	}

      m_sb.kernelstatus->setEnabled(true);
      m_sb.listeners->setEnabled(true);
      m_sb.neighbors->setEnabled(true);
      m_ui.kernelBox->setEnabled(true);
      m_ui.listenersBox->setEnabled(true);
      m_ui.newRSAKeys->setChecked(false);
      m_ui.newRSAKeys->setEnabled(true);
      m_ui.passphrase1->setText("0000000000");
      m_ui.passphrase2->setText("0000000000");
      m_ui.rsaKeySize->setEnabled(false);

      for(int i = 0; i < m_ui.tab->count(); i++)
	m_ui.tab->setTabEnabled(i, true);

      /*
      ** Save the various entities.
      */

      m_settings["gui/cipherType"] = m_ui.cipherType->currentText();
      m_settings["gui/hashType"] = m_ui.hashType->currentText();
      m_settings["gui/iterationCount"] = m_ui.iterationCount->value();
      m_settings["gui/rsaKeySize"] = m_ui.rsaKeySize->currentText().toInt();
      m_settings["gui/salt"] = salt.toHex();
      m_settings["gui/saltLength"] = m_ui.saltLength->value();
      m_settings["gui/saltedPassphraseHash"] = saltedPassphraseHash.toHex();

      QSettings settings;

      settings.setValue("gui/cipherType", m_settings["gui/cipherType"]);
      settings.setValue("gui/hashType", m_settings["gui/hashType"]);
      settings.setValue("gui/iterationCount",
			m_settings["gui/iterationCount"]);
      settings.setValue("gui/rsaKeySize", m_settings["gui/rsaKeySize"]);
      settings.setValue("gui/salt", m_settings["gui/salt"]);
      settings.setValue("gui/saltLength", m_settings["gui/saltLength"]);
      settings.setValue
	("gui/saltedPassphraseHash", m_settings["gui/saltedPassphraseHash"]);

      QMessageBox::information
	(this, tr("Spot-On: Information"),
	 tr("Your RSA keys and the passphrase have been recorded. "
	    "You are now ready to use the full power of Spot-On. Enjoy!"));

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

void spoton::slotValidatePassphrase(void)
{
  QByteArray salt;
  QByteArray saltedPassphraseHash;
  QString error("");

  salt = QByteArray::fromHex(m_settings.value("gui/salt", "").toByteArray());
  saltedPassphraseHash = m_settings.value("gui/saltedPassphraseHash", "").
    toByteArray();

  if(saltedPassphraseHash ==
     spoton_gcrypt::saltedPassphraseHash(m_ui.hashType->currentText(),
					 m_ui.passphrase->text(),
					 salt, error).toHex())
    if(error.isEmpty())
      {
	QByteArray key
	  (spoton_gcrypt::derivedKey(m_ui.cipherType->currentText(),
				     m_ui.hashType->currentText(),
				     static_cast
				     <unsigned long> (m_ui.
						      iterationCount->value()),
				     m_ui.passphrase->text(),
				     salt,
				     error));

	if(error.isEmpty())
	  {
	    delete m_crypt;
	    m_crypt = new spoton_gcrypt
	      (m_ui.cipherType->currentText(),
	       m_ui.hashType->currentText(),
	       m_ui.passphrase->text().toUtf8(),
	       key,
	       m_ui.saltLength->value(),
	       m_ui.iterationCount->value(),
	       "messaging");
	    m_sb.status->setText
	      (tr("Initializing country_inclusion.db."));
	    m_sb.status->repaint();
	    QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
	    spoton_misc::populateCountryDatabase(m_crypt);
	    QApplication::restoreOverrideCursor();
	    spoton_misc::populateCountryDatabase(m_crypt);
	    m_sb.status->clear();

	    if(!m_tableTimer.isActive())
	      m_tableTimer.start();

	    sendKeysToKernel();
	    m_sb.kernelstatus->setEnabled(true);
	    m_sb.listeners->setEnabled(true);
	    m_sb.neighbors->setEnabled(true);
	    m_ui.kernelBox->setEnabled(true);
	    m_ui.listenersBox->setEnabled(true);
	    m_ui.newRSAKeys->setEnabled(true);
	    m_ui.passphrase->clear();
	    m_ui.passphrase->setEnabled(false);
	    m_ui.passphraseButton->setEnabled(false);
	    m_ui.passphraseLabel->setEnabled(false);
	    m_ui.rsaKeySize->setEnabled(false);

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
    m_sb.chat->setVisible(false);
}

void spoton::slotNeighborCheckChange(int state)
{
  QCheckBox *checkBox = qobject_cast<QCheckBox *> (sender());

  if(checkBox)
    {
      {
	QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton");

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

      QSqlDatabase::removeDatabase("spoton");
    }
}

void spoton::slotMaximumClientsChanged(int index)
{
  QComboBox *comboBox = qobject_cast<QComboBox *> (sender());

  if(comboBox)
    {
      {
	QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton");

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

      QSqlDatabase::removeDatabase("spoton");
    }
}

void spoton::slotShowContextMenu(const QPoint &point)
{
  QMenu menu(this);

  if(m_ui.listeners == sender())
    {
      menu.addAction(QIcon(QString(":/%1/clear.png").
			   arg(m_settings.value("gui/iconSet", "nouve").
			       toString())),
		     tr("&Delete"),
		     this, SLOT(slotDeleteListener(void)));
      menu.addAction(tr("Delete &All"),
		     this, SLOT(slotDeleteAllListeners(void)));
      menu.addSeparator();
      menu.addAction(tr("&Publish Information (Plaintext)"),
		     this, SLOT(slotPublicizeListenerPlaintext(void)));
      menu.addAction(tr("Publish &All (Plaintext)"),
		     this, SLOT(slotPublicizeAllListenersPlaintext(void)));
      menu.exec(m_ui.neighbors->mapToGlobal(point));
    }
  else if(m_ui.neighbors == sender())
    {
      menu.addAction(QIcon(QString(":/%1/share.png").
			   arg(m_settings.value("gui/iconSet", "nouve").
			       toString())),
		     tr("Share &Messaging Public Key"),
		     this, SLOT(slotSharePublicKey(void)));
      menu.addAction(QIcon(QString(":%1//share.png").
			   arg(m_settings.value("gui/iconSet", "nouve").
			       toString())),
		     tr("Share &URL Public Key"),
		     this, SLOT(slotShareURLPublicKey(void)));
      menu.addSeparator();
      menu.addAction(tr("&Connect"),
		     this, SLOT(slotConnectNeighbor(void)));
      menu.addAction(tr("&Disconnect"),
		     this, SLOT(slotDisconnectNeighbor(void)));
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
      menu.exec(m_ui.neighbors->mapToGlobal(point));
    }
  else
    {
      QAction *action = menu.addAction
	(QIcon(QString(":/%1/add.png").
	       arg(m_settings.value("gui/iconSet", "nouve").toString())),
	 tr("&Add participant as friend."),
	 this, SLOT(slotSharePublicKeyWithParticipant(void)));
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
      menu.addAction(tr("&Generate random Gemini (AES-256)."),
		     this, SLOT(slotGenerateGeminiInChat(void)));
      menu.addAction(QIcon(QString(":/%1/clear.png").
			   arg(m_settings.value("gui/iconSet", "nouve").
			       toString())),
		     tr("&Remove"),
		     this, SLOT(slotRemoveParticipants(void)));
      menu.exec(m_ui.participants->mapToGlobal(point));
    }
}

void spoton::slotKernelSocketState(void)
{
  QAbstractSocket::SocketState state = m_kernelSocket.state();

  if(state == QAbstractSocket::ConnectedState)
    {
      sendKeysToKernel();
      m_sb.kernelstatus->setIcon
	(QIcon(QString(":/%1/activate.png").
	       arg(m_settings.value("gui/iconSet", "nouve").toString())));
      m_sb.kernelstatus->setToolTip
	(tr("Connected to the kernel on port %1 "
	    "from local port %2.").
	 arg(m_kernelSocket.peerPort()).
	 arg(m_kernelSocket.localPort()));
    }
  else if(state == QAbstractSocket::UnconnectedState)
    {
      m_messagingCache.clear();
      m_sb.kernelstatus->setIcon
	(QIcon(QString(":/%1/deactivate.png").
	       arg(m_settings.value("gui/iconSet", "nouve").toString())));
      m_sb.kernelstatus->setToolTip
	(tr("Not connected to the kernel. Is the kernel "
	    "active?"));
    }
}

void spoton::sendKeysToKernel(void)
{
  if(m_crypt)
    if(m_kernelSocket.state() == QAbstractSocket::ConnectedState)
      {
	QByteArray keys("keys_");
	QByteArray passphrase
	  (m_crypt->passphrase(), m_crypt->passphraseLength());
	QByteArray symmetricKey
	  (m_crypt->symmetricKey(), m_crypt->symmetricKeyLength());

	passphrase = passphrase.toBase64();
	symmetricKey = symmetricKey.toBase64();
	keys.append(passphrase);
	keys.append("_");
	keys.append(symmetricKey);
	keys.append('\n');

	if(m_kernelSocket.write(keys.constData(), keys.length()) !=
	   keys.length())
	  spoton_misc::logError
	    ("spoton::sendKeysToKernel(): write() failure.");
	else
	  m_kernelSocket.flush();
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

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "neighbors.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.prepare("UPDATE neighbors SET "
		      "status_control = ? "
		      "WHERE OID = ?");
	query.bindValue(0, "connected");
	query.bindValue(1, oid);
	query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton");
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

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton");

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

  QSqlDatabase::removeDatabase("spoton");
}

void spoton::slotBlockNeighbor(void)
{
  if(!m_crypt)
    return;

  QString remoteIp("");
  int row = -1;

  if((row = m_ui.neighbors->currentRow()) >= 0)
    {
      QTableWidgetItem *item = m_ui.neighbors->item
	(row, 9); // Remote IP Address

      if(item)
	remoteIp = item->text();
    }

  if(remoteIp.isEmpty())
    return;

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton");

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
	QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

	if(query.exec("SELECT remote_ip_address, OID "
		      "FROM neighbors WHERE status_control <> 'blocked' "
		      "AND status_control <> 'deleted'"))
	  while(query.next())
	    {
	      QString ip("");
	      bool ok = true;

	      ip =
		m_crypt->decrypted(QByteArray::
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

	QApplication::restoreOverrideCursor();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton");
}

void spoton::slotUnblockNeighbor(void)
{
  if(!m_crypt)
    return;

  QString remoteIp("");
  int row = -1;

  if((row = m_ui.neighbors->currentRow()) >= 0)
    {
      QTableWidgetItem *item = m_ui.neighbors->item
	(row, 9); // Remote IP Address

      if(item)
	remoteIp = item->text();
    }

  if(remoteIp.isEmpty())
    return;

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton");

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
	QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

	if(query.exec("SELECT remote_ip_address, OID "
		      "FROM neighbors WHERE status_control = 'blocked'"))
	  while(query.next())
	    {
	      bool ok = true;

	      QString ip
		(m_crypt->decrypted(QByteArray::
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

	QApplication::restoreOverrideCursor();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton");
}

void spoton::slotDeleteAllListeners(void)
{
  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "listeners.db");

    if(db.open())
      {
	QSqlQuery query(db);

	if(!isKernelActive())
	  query.exec("DELETE FROM listeners");
	else
	  query.exec("UPDATE listeners SET "
		     "status_control = 'deleted'");
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton");

  while(m_ui.listeners->rowCount() > 0)
    m_ui.listeners->removeRow(0);
}

void spoton::slotDeleteAllNeighbors(void)
{
  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "neighbors.db");

    if(db.open())
      {
	QSqlQuery query(db);

	if(!isKernelActive())
	  query.exec("DELETE FROM neighbors");
	else
	  query.exec("UPDATE neighbors SET "
		     "status_control = 'deleted'");
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton");

  while(m_ui.neighbors->rowCount() > 0)
    m_ui.neighbors->removeRow(0);
}

void spoton::slotPopulateParticipants(void)
{
  if(!m_crypt)
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

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton");

    db.setDatabaseName(fileInfo.absoluteFilePath());

    if(db.open())
      {
	updateParticipantsTable(db);

	QList<int> rows;
	QList<int> rowsE;
	QModelIndexList list
	  (m_ui.participants->selectionModel()->selectedRows(3));
	QModelIndexList listE
	  (m_ui.emailParticipants->selectionModel()->selectedRows(2));
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
	    QVariant data(list.takeFirst().data());

	    if(!data.isNull() && data.isValid())
	      hashes.append(data.toString());
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

	QSqlQuery query(db);
	QWidget *focusWidget = QApplication::focusWidget();

	query.setForwardOnly(true);

	/*
	** We only wish to display other public keys.
	*/

	if(query.exec("SELECT name, OID, neighbor_oid, public_key_hash, "
		      "status, gemini FROM friends_public_keys WHERE "
		      "key_type = 'messaging'"))
	  while(query.next())
	    {
	      QString status(query.value(4).toString());
	      bool temporary =
		query.value(2).toInt() == -1 ? false : true;

	      if(!isKernelActive())
		status = "offline";

	      for(int i = 0; i < query.record().count(); i++)
		{
		  QTableWidgetItem *item = 0;

		  if(i == 0)
		    {
		      row += 1;
		      m_ui.participants->setRowCount(row);

		      if(!temporary)
			{
			  rowE += 1;
			  m_ui.emailParticipants->setRowCount(rowE);
			}
		    }

		  if(i == 0)
		    item = new QTableWidgetItem
		      (QString::fromUtf8(query.value(i).toByteArray()));
		  else if(i == 4)
		    {
		      QString status(query.value(i).toString());

		      status[0] = status.toUpper()[0];

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
		  else if(i == 5)
		    {
		      bool ok = true;

		      if(query.value(i).isNull())
			item = new QTableWidgetItem();
		      else
			item = new QTableWidgetItem
			  (m_crypt->decrypted(QByteArray::
					      fromBase64(query.
							 value(i).
							 toByteArray()),
					      &ok).constData());
		    }
		  else
		    item = new QTableWidgetItem(query.value(i).toString());

		  item->setFlags
		    (Qt::ItemIsSelectable | Qt::ItemIsEnabled);

		  if(i == 0)
		    {
		      if(!temporary)
			m_ui.emailParticipants->setItem
			  (rowE - 1, i, item->clone());

		      if(!temporary)
			{
			  if(status == "away")
			    {
			      item->setIcon
				(QIcon(QString(":/%1/away.png").
				       arg(m_settings.value("gui/iconSet",
							    "nouve").
					   toString())));
			      item->setToolTip(tr("Your friend %1 is away.").
					       arg(item->text()));
			    }
			  else if(status == "busy")
			    {
			      item->setIcon
				(QIcon(QString(":/%1/busy.png").
				       arg(m_settings.value("gui/iconSet",
							    "nouve").
					   toString())));
			      item->setToolTip(tr("Your friend %1 is busy.").
					       arg(item->text()));
			    }
			  else if(status == "offline")
			    {
			      item->setIcon
				(QIcon(QString(":/%1/offline.png").
				       arg(m_settings.value("gui/iconSet",
							    "nouve").
					   toString())));
			      item->setToolTip
				(tr("Your friend %1 is offline.").
				 arg(item->text()));
			    }
			  else if(status == "online")
			    {
			      item->setIcon
				(QIcon(QString(":/%1/online.png").
				       arg(m_settings.value("gui/iconSet",
							    "nouve").
					   toString())));
			      item->setToolTip(tr("User %1 is online.").
					       arg(item->text()));
			    }
			  else
			    item->setToolTip(tr("User %1 is a "
						"permanent friend.").
					     arg(item->text()));
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
		  else if(i == 1)
		    {
		      if(!temporary)
			m_ui.emailParticipants->setItem
			  (rowE - 1, i, item->clone());
		    }
		  else if(i == 3)
		    {
		      if(!temporary)
			m_ui.emailParticipants->setItem
			  (rowE - 1, i - 1, item->clone());
		    }
		  else if(i == 5)
		    item->setFlags(item->flags() | Qt::ItemIsEditable);

		  item->setData(Qt::UserRole, temporary);
		  m_ui.participants->blockSignals(true);
		  m_ui.participants->setItem(row - 1, i, item);
		  m_ui.participants->blockSignals(false);
		}

	      if(hashes.contains(query.value(3).toString()))
		rows.append(row - 1);

	      if(hashesE.contains(query.value(3).toString()))
		rowsE.append(rowE - 1);
	    }

	if(focusWidget)
	  focusWidget->setFocus();

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

  QSqlDatabase::removeDatabase("spoton");
}
