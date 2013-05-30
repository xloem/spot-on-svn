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

#include <QApplication>
#include <QCheckBox>
#include <QClipboard>
#include <QDateTime>
#include <QDesktopServices>
#include <QDir>
#include <QFileDialog>
#ifdef Q_OS_MAC
#include <QMacStyle>
#endif
#include <QMessageBox>
#ifdef Q_OS_WIN32
#include <qt_windows.h>
#include <QtNetwork>
#else
#include <QNetworkInterface>
#endif
#include <QProcess>
#include <QScrollBar>
#include <QSettings>
#include <QSqlQuery>
#include <QSqlRecord>
#include <QStyle>
#include <QTranslator>
#include <QUuid>
#include <QtDebug>

#include <limits>

extern "C"
{
#include "LibSpotOn/libspoton.h"
}

#include "Common/spot-on-common.h"
#include "Common/spot-on-gcrypt.h"
#include "Common/spot-on-misc.h"
#include "Common/spot-on-send.h"
#include "spot-on.h"
#include "spot-on-reencode.h"

int main(int argc, char *argv[])
{
#ifdef Q_OS_MAC
  QApplication::setStyle(new QMacStyle());
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
#ifdef Q_OS_MAC
  setAttribute(Qt::WA_MacMetalStyle, true);
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
  connect(m_sb.chat,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotChatStatusClicked(void)));
  connect(m_sb.email,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotEmailStatusClicked(void)));
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
  connect(m_ui.deleteListener,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotDeleteListener(void)));
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
  connect(m_ui.deleteAllListeners,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotDeleteAllListeners(void)));
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
  connect(m_ui.showOnlyConnectedNeighbors,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotOnlyConnectedNeighborsToggled(bool)));
  connect(m_ui.showOnlyOnlineListeners,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotOnlyOnlineListenersToggled(bool)));
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
  m_sb.kernelstatus->setIcon(QIcon(":/deactivate.png"));
  m_sb.kernelstatus->setToolTip
    (tr("Not connected to the kernel. Is the kernel "
	"active?"));

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
  m_ui.participants->setStyleSheet
    ("QTableView {selection-background-color: lightgreen}");

  QSettings settings;

  if(!settings.contains("gui/uuid"))
    {
      QUuid uuid(QUuid::createUuid());

      settings.setValue("gui/uuid", uuid.toString());
    }

  for(int i = 0; i < settings.allKeys().size(); i++)
    m_settings[settings.allKeys().at(i)] = settings.value
      (settings.allKeys().at(i));

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
    m_ui.kernelPath->setText(QCoreApplication::applicationDirPath() +
			   QDir::separator() +
#ifdef Q_OS_MAC
                           "Spot-On-Kernel.app"
#elif defined(Q_OS_WIN32)
                           "Spot-On-Kernel.exe"
#else
                           "Spot-On-Kernel"
#endif
			   );

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
  m_ui.keepOnlyUserDefinedNeighbors->setChecked
    (m_settings.value("gui/keepOnlyUserDefinedNeighbors", false).toBool());
  m_ui.postofficeCheckBox->setChecked
    (m_settings.value("gui/postoffice_enabled", false).toBool());
  m_ui.scrambler->setChecked
    (m_settings.value("gui/scramblerEnabled", false).toBool());
  m_ui.showOnlyConnectedNeighbors->setChecked
    (m_settings.value("gui/showOnlyConnectedNeighbors", false).toBool());
  m_ui.showOnlyOnlineListeners->setChecked
    (m_settings.value("gui/showOnlyOnlineListeners", false).toBool());

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
      m_ui.passphrase->setEnabled(false);
      m_ui.passphraseButton->setEnabled(false);
      m_ui.passphraseLabel->setEnabled(false);
      m_ui.kernelBox->setEnabled(false);
      m_ui.listenersBox->setEnabled(false);
      m_ui.resetSpotOn->setEnabled(false);

      for(int i = 0; i < m_ui.tab->count(); i++)
	if(i == 4) // Settings
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

  if(m_settings.contains("gui/neighborsHorizontalSplitter"))
    m_ui.neighborsHorizontalSplitter->restoreState
      (m_settings.value("gui/neighborsHorizontalSplitter").toByteArray());

  if(m_settings.contains("gui/neighborsVerticalSplitter"))
    m_ui.neighborsVerticalSplitter->restoreState
      (m_settings.value("gui/neighborsVerticalSplitter").toByteArray());

  if(m_settings.contains("gui/readVerticalSplitter"))
    m_ui.readVerticalSplitter->restoreState
      (m_settings.value("gui/readVerticalSplitter").toByteArray());

  m_ui.neighbors->setContextMenuPolicy(Qt::CustomContextMenu);
  m_ui.participants->setContextMenuPolicy(Qt::CustomContextMenu);
  connect(m_ui.neighbors,
	  SIGNAL(customContextMenuRequested(const QPoint &)),
	  this,
	  SLOT(slotShowContextMenu(const QPoint &)));
  connect(m_ui.participants,
	  SIGNAL(customContextMenuRequested(const QPoint &)),
	  this,
	  SLOT(slotShowContextMenu(const QPoint &)));
  m_ui.mail->setColumnHidden(4, true); // message
  m_ui.mail->setColumnHidden(5, true); // OID
  m_ui.listeners->setColumnHidden(m_ui.listeners->columnCount() - 1,
				  true); // OID
  m_ui.neighbors->setColumnHidden
    (m_ui.neighbors->columnCount() - 1, true); // OID
  m_ui.participants->setColumnHidden(1, true); // OID
  m_ui.participants->setColumnHidden(2, true); // neighbor_oid
  m_ui.participants->setColumnHidden(3, true); // public_key_hash
  m_ui.participants->resizeColumnsToContents();
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
  m_ui.neighborsVerticalSplitter->setStretchFactor(0, 1);
  m_ui.neighborsVerticalSplitter->setStretchFactor(1, 0);
  m_ui.readVerticalSplitter->setStretchFactor(0, 1);
  m_ui.readVerticalSplitter->setStretchFactor(1, 0);
  prepareListenerIPCombo();
  spoton_misc::prepareDatabases();

  /*
  ** Not wise! We may find things we're not prepared for.
  */

  foreach(QAbstractButton *button,
	  m_ui.participants->findChildren<QAbstractButton *> ())
    button->setToolTip(tr("Broadcast"));

  show();
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
	    (5, m_crypt->keyedHash((ip + port).toLatin1(), &ok).
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
	QString proxyPort("");
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

	if(ok)
	  query.bindValue
	    (7, m_crypt->keyedHash((ip + port).toLatin1(), &ok).
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

	proxyHostname = m_ui.proxyHostname->text().trimmed();
	proxyPassword = m_ui.proxyPassword->text();
	proxyPort = QString::number(m_ui.proxyPort->value());

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
	    ("HHHH:HHHH:HHHH:HHHH:HHHH:HHHH:HHHH:HHHH; ");
	  m_ui.listenerScopeId->setEnabled(true);
	  m_ui.listenerScopeIdLabel->setEnabled(true);
	}
      else
	{
	  m_ui.neighborIP->clear();
	  m_ui.neighborIP->setInputMask
	    ("HHHH:HHHH:HHHH:HHHH:HHHH:HHHH:HHHH:HHHH; ");
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

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton");

    db.setDatabaseName(fileInfo.absoluteFilePath());

    if(db.open())
      {
	updateListenersTable(db);

	QModelIndexList list;
	QString ip("");
	QString port("");
	int columnIP = 2;
	int columnPORT = 3;
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

	m_ui.listeners->setSortingEnabled(false);
	m_ui.listeners->clearContents();
	m_ui.listeners->setRowCount(0);

	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec(QString("SELECT "
			      "status_control, status, "
			      "ip_address, port, scope_id, protocol, "
			      "external_ip_address, external_port, "
			      "connections, maximum_clients, OID "
			      "FROM listeners "
			      "%1").
		      arg(m_ui.showOnlyOnlineListeners->isChecked() ?
			  "WHERE status = 'online'" : "")))
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
							      toInt())))
			  box->setCurrentIndex
			    (box->findText(QString::number(query.
							   value(i).
							   toInt())));
			else
			  box->setCurrentIndex(0);

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
		QWidget *focusWidget = QApplication::focusWidget();
		bool ok = true;

		bytes1 = m_crypt->decrypted
		  (QByteArray::fromBase64(query.value(2).toByteArray()),
		   &ok);
		bytes2 = m_crypt->decrypted
		  (QByteArray::fromBase64(query.value(3).toByteArray()),
		   &ok);

		if(ip == bytes1 && port == bytes2)
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

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton");

    db.setDatabaseName(fileInfo.absoluteFilePath());

    if(db.open())
      {
	updateNeighborsTable(db);

	QModelIndexList list;
	QString remoteIp("");
	QString remotePort("");
	int columnCOUNTRY = 8;
	int columnREMOTE_IP = 9;
	int columnREMOTE_PORT = 10;
	int hval = m_ui.neighbors->horizontalScrollBar()->value();
	int row = -1;
	int vval = m_ui.neighbors->verticalScrollBar()->value();

	list = m_ui.neighbors->selectionModel()->selectedRows
	  (columnREMOTE_IP);

	if(!list.isEmpty())
	  remoteIp = list.at(0).data().toString();

	list = m_ui.neighbors->selectionModel()->selectedRows
	  (columnREMOTE_PORT);

	if(!list.isEmpty())
	  remotePort = list.at(0).data().toString();

	m_ui.neighbors->setSortingEnabled(false);
	m_ui.neighbors->clearContents();
	m_ui.neighbors->setRowCount(0);

	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec(QString("SELECT sticky, UPPER(uuid), status, "
			      "status_control, "
			      "local_ip_address, local_port, "
			      "external_ip_address, external_port, "
			      "country, "
			      "remote_ip_address, "
			      "remote_port, scope_id, protocol, "
			      "proxy_hostname, proxy_port, OID "
			      "FROM neighbors "
			      "%1").
		      arg(m_ui.showOnlyConnectedNeighbors->isChecked() ?
			  "WHERE status = 'connected'" : "")))
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
		QWidget *focusWidget = QApplication::focusWidget();
		bool ok = true;

		bytes1 = m_crypt->decrypted
		  (QByteArray::fromBase64(query.value(columnREMOTE_IP).
					  toByteArray()), &ok);
		bytes2 = m_crypt->decrypted
		  (QByteArray::fromBase64(query.value(columnREMOTE_PORT).
					  toByteArray()), &ok);

		if(remoteIp == bytes1 && remotePort == bytes2)
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
  dialog.setAttribute(Qt::WA_MacMetalStyle, false);
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
  settings.setValue("gui/keepOnlyUserDefinedNeighbors",
		    m_ui.keepOnlyUserDefinedNeighbors->isChecked());
  settings.setValue("gui/neighborsHorizontalSplitter",
		    m_ui.neighborsHorizontalSplitter->saveState());
  settings.setValue("gui/neighborsVerticalSplitter",
		    m_ui.neighborsVerticalSplitter->saveState());
  settings.setValue("gui/readVerticalSplitter",
		    m_ui.readVerticalSplitter->saveState());
  settings.setValue("gui/showOnlyConnectedNeighbors",
		    m_ui.showOnlyConnectedNeighbors->isChecked());
  settings.setValue("gui/showOnlyOnlineListeners",
		    m_ui.showOnlyOnlineListeners->isChecked());
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
	      query.bindValue(0, "off");

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
		   "status = 'off' WHERE "
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
      m_ui.passphrase1->setFocus();
      return;
    }
  else if(str1 != str2)
    {
      QMessageBox::critical(this, tr("Spot-On: Error"),
			    tr("The passphrases are not equal."));
      m_ui.passphrase1->setFocus();
      return;
    }

  if(spoton_gcrypt::passphraseSet())
    {
      QMessageBox mb(this);

#ifdef Q_OS_MAC
      mb.setAttribute(Qt::WA_MacMetalStyle, true);
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
      if(reencode)
	{
	  slotDeactivateKernel();
	  m_sb.status->setText
	    (tr("Re-encoding RSA key pair 1 of 2. Please be patient."));
	  spoton_gcrypt::reencodeRSAKeys
	    (m_ui.cipherType->currentText(),
	     derivedKey,
	     m_settings.value("gui/cipherType", "aes256").toString().trimmed(),
	     m_crypt->symmetricKey(),
	     "private",
	     error2);
	  m_sb.status->clear();

	  if(error2.isEmpty())
	    {
	      m_sb.status->setText
		(tr("Re-encoding RSA key pair 2 of 2. Please be patient."));
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

	  list << "private"
	       << "url";

	  for(int i = 0; i < list.size(); i++)
	    {
	      m_sb.status->setText
		(tr("Generating RSA key pair %1 of %2. Please be patient.").
		 arg(i + 1).arg(list.size()));

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
		 "private");

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
	     "private");

	  if(!reencode)
	    {
	      m_sb.status->setText
		(tr("Initializing country_inclusion.db."));
	      QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
	      spoton_misc::populateCountryDatabase(m_crypt);
	      QApplication::restoreOverrideCursor();
	      m_sb.status->clear();
	    }

	  if(!m_tableTimer.isActive())
	    m_tableTimer.start();

	  sendKeyToKernel();
	}

      m_sb.kernelstatus->setEnabled(true);
      m_ui.kernelBox->setEnabled(true);
      m_ui.listenersBox->setEnabled(true);
      m_ui.resetSpotOn->setEnabled(true);
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
      mb.setAttribute(Qt::WA_MacMetalStyle, true);
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
    {
      QByteArray key;
      QString error("");

      key = spoton_gcrypt::derivedKey
	(m_ui.cipherType->currentText(),
	 m_ui.hashType->currentText(),
	 static_cast<unsigned long> (m_ui.iterationCount->value()),
	 m_ui.passphrase->text(),
	 salt,
	 error);
      delete m_crypt;
      m_crypt = new spoton_gcrypt
	(m_ui.cipherType->currentText(),
	 m_ui.hashType->currentText(),
	 m_ui.passphrase->text().toUtf8(),
	 key,
	 m_ui.saltLength->value(),
	 m_ui.iterationCount->value(),
	 "private");
      m_sb.status->setText
	(tr("Initializing country_inclusion.db."));
      QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
      spoton_misc::populateCountryDatabase(m_crypt);
      QApplication::restoreOverrideCursor();
      spoton_misc::populateCountryDatabase(m_crypt);
      m_sb.status->clear();

      if(!m_tableTimer.isActive())
	m_tableTimer.start();

      sendKeyToKernel();
      m_sb.kernelstatus->setEnabled(true);
      m_ui.kernelBox->setEnabled(true);
      m_ui.listenersBox->setEnabled(true);
      m_ui.passphrase->clear();
      m_ui.passphrase->setEnabled(false);
      m_ui.passphraseButton->setEnabled(false);
      m_ui.passphraseLabel->setEnabled(false);
      m_ui.rsaKeySize->setEnabled(false);
      m_ui.resetSpotOn->setEnabled(true);

      for(int i = 0; i < m_ui.tab->count(); i++)
	m_ui.tab->setTabEnabled(i, true);

      m_ui.tab->setCurrentIndex
	(m_settings.value("gui/currentTabIndex", m_ui.tab->count() - 1).
	 toInt());
    }
  else
    {
      m_ui.passphrase->clear();
      m_ui.passphrase->setFocus();
    }
}

void spoton::slotTabChanged(int index)
{
  Q_UNUSED(index);
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
	      query.bindValue(0, 5 * (index + 1));
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

  if(m_ui.neighbors == sender())
    {
      menu.addAction(QIcon(":/share.png"),
		     tr("Share &Messaging Public Key"),
		     this, SLOT(slotSharePublicKey(void)));
      menu.addAction(QIcon(":/share.png"),
		     tr("Share &URL Public Key"),
		     this, SLOT(slotShareURLPublicKey(void)));
      menu.addSeparator();
      menu.addAction(tr("&Connect"),
		     this, SLOT(slotConnectNeighbor(void)));
      menu.addAction(tr("&Disconnect"),
		     this, SLOT(slotDisconnectNeighbor(void)));
      menu.addSeparator();
      menu.addAction(QIcon(":/clear.png"),tr("&Delete"),
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
	(QIcon(":/add.png"),
	 tr("&Add participant as friend."),
	 this, SLOT(slotSharePublicKeyWithParticipant(void)));
      QTableWidgetItem *item = m_ui.participants->itemAt(point);

      if(item && item->data(Qt::UserRole).toBool()) // Temporary friend?
	action->setEnabled(true);
      else
	action->setEnabled(false);

      menu.addAction(QIcon(":/copy.png"),
		     tr("&Copy Repleo to the clipboard buffer."),
		     this, SLOT(slotCopyFriendshipBundle(void)));
      menu.addAction(tr("&Generate random Gemini (AES-256)."),
		     this, SLOT(slotGenerateGeminiInChat(void)));
      menu.addAction(QIcon(":/clear.png"),
		     tr("&Remove"),
		     this, SLOT(slotRemoveParticipants(void)));
      menu.exec(m_ui.participants->mapToGlobal(point));
    }
}

void spoton::slotKernelSocketState(void)
{
  if(m_kernelSocket.state() == QAbstractSocket::ConnectedState)
    {
      sendKeyToKernel();
      m_sb.kernelstatus->setIcon(QIcon(":/activate.png"));
      m_sb.kernelstatus->setToolTip
	(tr("Connected to the kernel on port %1 "
	    "from local port %2.").
	 arg(m_kernelSocket.peerPort()).
	 arg(m_kernelSocket.localPort()));
    }
  else
    {
      m_sb.kernelstatus->setIcon(QIcon(":/deactivate.png"));
      m_sb.kernelstatus->setToolTip
	(tr("Not connected to the kernel. Is the kernel "
	    "active?"));
    }
}

void spoton::sendKeyToKernel(void)
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
	    ("spoton::sendKeyToKernel(): write() failure.");
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
	QModelIndexList list
	  (m_ui.participants->selectionModel()->selectedRows(3));
	QString participant(m_ui.participantsCombo->currentText());
	QStringList hashes;
	int hval = m_ui.participants->horizontalScrollBar()->value();
	int row = 0;
	int vval = m_ui.participants->verticalScrollBar()->value();

	while(!list.isEmpty())
	  {
	    QVariant data(list.takeFirst().data());

	    if(!data.isNull() && data.isValid())
	      hashes.append(data.toString());
	  }

	m_ui.participants->setSortingEnabled(false);
	m_ui.participants->clearContents();
	m_ui.participants->setRowCount(0);

	for(int i = m_ui.participantsCombo->count() - 1; i >= 1; i--)
	  m_ui.participantsCombo->removeItem(i);

	QMap<QString, QPair<QByteArray, qint64> > participants;
	QSqlQuery query(db);
	QWidget *focusWidget = QApplication::focusWidget();

	query.setForwardOnly(true);

	/*
	** We only wish to display other public keys.
	*/

	if(query.exec("SELECT name, OID, neighbor_oid, public_key_hash, "
		      "status, gemini FROM friends_public_keys"))
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
		      QPair<QByteArray, qint64> pair;

		      pair.first = query.value(3).toByteArray();
		      pair.second = query.value(1).toLongLong();
		      participants.insert(item->text(), pair);

		      if(!temporary)
			{
			  if(status == "away")
			    {
			      item->setIcon
				(QIcon(":/away.png"));
			      item->setToolTip(tr("Your friend %1 is away.").
					       arg(item->text()));
			    }
			  else if(status == "busy")
			    {
			      item->setIcon
				(QIcon(":/busy.png"));
			      item->setToolTip(tr("Your friend %1 is busy.").
					       arg(item->text()));
			    }
			  else if(status == "offline")
			    {
			      item->setIcon
				(QIcon(":/offline.png"));
			      item->setToolTip
				(tr("Your friend %1 is offline.").
				 arg(item->text()));
			    }
			  else if(status == "online")
			    {
			      item->setIcon
				(QIcon(":/online.png"));
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
			    (QIcon(":/add.png"));
			  item->setToolTip
			    (tr("User %1 requests your friendship.").
			     arg(item->text()));
			}
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
	    }

	if(focusWidget)
	  focusWidget->setFocus();

	if(!participants.isEmpty())
	  {
	    m_ui.participantsCombo->insertSeparator(1);

	    for(int i = 0; i < participants.keys().size(); i++)
	      m_ui.participantsCombo->addItem
		(participants.keys().at(i));

	    for(int i = 0; i < participants.size(); i++)
	      {
		QPair<QByteArray, qint64> pair
		  (participants[participants.keys().at(i)]);

		m_ui.participantsCombo->setItemData
		  (i + 2, pair.second, Qt::UserRole);
		m_ui.participantsCombo->setItemData
		  (i + 2, pair.first, Qt::UserRole + 1);
	      }

	    int index = -1;

	    if((index = m_ui.participantsCombo->findText(participant)) > -1)
	      m_ui.participantsCombo->setCurrentIndex(index);
	  }

	m_ui.participants->setSelectionMode(QAbstractItemView::MultiSelection);

	while(!rows.isEmpty())
	  m_ui.participants->selectRow(rows.takeFirst());

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

void spoton::slotSendMessage(void)
{
  if(m_kernelSocket.state() != QAbstractSocket::ConnectedState)
    return;
  else if(m_ui.message->toPlainText().trimmed().isEmpty())
    return;

  if(!m_ui.participants->selectionModel()->hasSelection())
    /*
    ** We need at least one participant.
    */

    return;

  QModelIndexList list(m_ui.participants->selectionModel()->selectedRows(1));
  QString message("");

  message.append
    (QDateTime::currentDateTime().
     toString("[hh:mm<font color=grey>:ss</font>] "));
  message.append(tr("<b>me:</b> "));
  message.append(m_ui.message->toPlainText().trimmed());
  m_ui.messages->append(message);
  m_ui.messages->verticalScrollBar()->setValue
    (m_ui.messages->verticalScrollBar()->maximum());

  while(!list.isEmpty())
    {
      QModelIndex index(list.takeFirst());
      QVariant data(index.data());

      if(!data.isNull() && data.isValid())
	{
	  QByteArray message("");
	  QByteArray name(m_settings.value("gui/nodeName", "unknown").
			  toByteArray().trimmed());

	  if(name.isEmpty())
	    name = "unknown";

	  /*
	  ** message_participantoid_myname_message
	  */

	  message.append("message_");
	  message.append(QString("%1_").arg(data.toString()));
	  message.append(name.toBase64());
	  message.append("_");
	  message.append(m_ui.message->toPlainText().trimmed().toUtf8().
			 toBase64());
	  message.append('\n');

	  if(m_kernelSocket.write(message.constData(), message.length()) !=
	     message.length())
	    spoton_misc::logError
	      ("spoton::slotSendMessage(): write() failure.");
	  else
	    m_kernelSocket.flush();
	}
    }

  m_ui.message->clear();
}

void spoton::slotReceivedKernelMessage(void)
{
  m_kernelSocketData.append(m_kernelSocket.readAll());

  if(m_kernelSocketData.endsWith('\n'))
    {
      QList<QByteArray> list
	(m_kernelSocketData.mid(0, m_kernelSocketData.lastIndexOf('\n')).
	 split('\n'));

      m_kernelSocketData.remove(0, m_kernelSocketData.lastIndexOf('\n'));

      while(!list.isEmpty())
	{
	  QByteArray data(list.takeFirst());

	  if(data.startsWith("message_"))
	    {
	      data.remove(0, strlen("message_"));

	      if(!data.isEmpty())
		{
		  QList<QByteArray> list(data.split('_'));

		  if(list.size() != 3)
		    continue;

		  for(int i = 0; i < list.size(); i++)
		    list.replace(i, QByteArray::fromBase64(list.at(i)));

		  QByteArray hash;
		  bool duplicate = false;
		  bool ok = true;

		  hash = spoton_gcrypt::sha512Hash(list.at(0), &ok);

		  if(m_messagingCache.contains(hash))
		    duplicate = true;
		  else
		    m_messagingCache.insert(hash, 0);

		  if(duplicate)
		    continue;

		  QByteArray name(list.at(1));
		  QByteArray message(list.at(2));
		  QString msg("");

		  if(name.isEmpty())
		    name = "unknown";

		  if(message.isEmpty())
		    message = "unknown";

		  msg.append
		    (QDateTime::currentDateTime().
		     toString("[hh:mm<font color=grey>:ss</font>] "));
		  msg.append
		    (QString("<font color=blue>%1: </font>").
		     arg(QString::fromUtf8(name.constData(),
					   name.length())));
		  msg.append(QString::fromUtf8(message.constData(),
					       message.length()));
		  m_ui.messages->append(msg);
		  m_ui.messages->verticalScrollBar()->setValue
		    (m_ui.messages->verticalScrollBar()->maximum());

		  if(m_ui.tab->currentIndex() != 0)
		    m_sb.chat->setVisible(true);
		}
	    }
	  else if(data == "newmail")
	    m_sb.email->setVisible(true);
	}
    }
}

void spoton::slotSharePublicKey(void)
{
  if(!m_crypt)
    return;
  else if(m_kernelSocket.state() != QAbstractSocket::ConnectedState)
    return;

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

  QByteArray hash(20, 0); // Sha-1
  QByteArray publicKey;
  QByteArray signature;
  bool ok = true;

  publicKey = m_crypt->publicKey(&ok);

  if(ok)
    signature = m_crypt->digitalSignature(hash, &ok);

  if(ok)
    {
      QByteArray message;
      QByteArray name(m_settings.value("gui/nodeName", "unknown").
		      toByteArray().trimmed());

      if(name.isEmpty())
	name = "unknown";

      message.append("sharepublickey_");
      message.append(oid);
      message.append("_");
      message.append(name.toBase64());
      message.append("_");
      message.append(publicKey.toBase64());
      message.append("_");
      message.append(signature.toBase64());
      message.append('\n');

      if(m_kernelSocket.write(message.constData(), message.length()) !=
	 message.length())
	spoton_misc::logError
	  ("spoton::slotSharePublicKey(): write() failure.");
      else
	m_kernelSocket.flush();
    }
}

void spoton::slotRemoveParticipants(void)
{
  if(!m_ui.participants->selectionModel()->hasSelection())
    return;

  QMessageBox mb(this);

#ifdef Q_OS_MAC
  mb.setAttribute(Qt::WA_MacMetalStyle, true);
#endif
  mb.setIcon(QMessageBox::Question);
  mb.setWindowTitle(tr("Spot-On: Confirmation"));
  mb.setWindowModality(Qt::WindowModal);
  mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
  mb.setText(tr("Are you sure that you wish to remove the selected "
		"participant(s)?"));

  if(mb.exec() != QMessageBox::Yes)
    return;

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "friends_public_keys.db");

    if(db.open())
      {
	QModelIndexList list
	  (m_ui.participants->selectionModel()->selectedRows(1));
	QSqlQuery query(db);

	while(!list.isEmpty())
	  {
	    QVariant data(list.takeFirst().data());

	    if(!data.isNull() && data.isValid())
	      query.exec(QString("DELETE FROM friends_public_keys WHERE "
				 "OID = %1").arg(data.toString()));
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton");
}

void spoton::slotSaveNodeName(void)
{
  m_settings["gui/nodeName"] = m_ui.nodeName->text().trimmed().
    toUtf8();

  QSettings settings;

  settings.setValue("gui/nodeName", m_ui.nodeName->text().trimmed().toUtf8());
  m_ui.nodeName->selectAll();
}

void spoton::highlightKernelPath(void)
{
  QColor color;
  QFileInfo fileInfo(m_ui.kernelPath->text());
  QPalette palette;

#if defined(Q_OS_MAC)
  if((fileInfo.isBundle() || fileInfo.isExecutable()) && fileInfo.size() > 0)
#elif defined(Q_OS_WIN32)
  if(fileInfo.isReadable() && fileInfo.size() > 0)
#else
  if(fileInfo.isExecutable() && fileInfo.size() > 0)
#endif    
    color = QColor(144, 238, 144);
  else
    color = QColor(240, 128, 128); // Light coral!

  palette.setColor(m_ui.kernelPath->backgroundRole(), color);
  m_ui.kernelPath->setPalette(palette);
}

void spoton::slotOnlyConnectedNeighborsToggled(bool state)
{
  m_settings["gui/showOnlyConnectedNeighbors"] = state;

  QSettings settings;

  settings.setValue("gui/showOnlyConnectedNeighbors", state);
  m_neighborsLastModificationTime = QDateTime();
}

void spoton::slotOnlyOnlineListenersToggled(bool state)
{
  m_settings["gui/showOnlyOnlineListeners"] = state;

  QSettings settings;

  settings.setValue("gui/showOnlyOnlineListeners", state);
  m_listenersLastModificationTime = QDateTime();
}

void spoton::slotKeepOnlyUserDefinedNeighbors(bool state)
{
  m_settings["gui/keepOnlyUserDefinedNeighbors"] = state;

  QSettings settings;

  settings.setValue("gui/keepOnlyUserDefinedNeighbors", state);

  if(state)
    m_neighborsLastModificationTime = QDateTime();
}

void spoton::prepareListenerIPCombo(void)
{
  m_ui.listenerIPCombo->clear();

  QList<QNetworkInterface> interfaces(QNetworkInterface::allInterfaces());
  QStringList list;

  while(!interfaces.isEmpty())
    {
      QNetworkInterface interface(interfaces.takeFirst());

      if(!interface.isValid() || !(interface.flags() &
				   QNetworkInterface::IsUp))
	continue;

      QList<QNetworkAddressEntry> addresses(interface.addressEntries());

      while(!addresses.isEmpty())
	{
	  QHostAddress address(addresses.takeFirst().ip());

	  if(m_ui.ipv4Listener->isChecked())
	    {
	      if(address.protocol() == QAbstractSocket::IPv4Protocol)
		list.append(address.toString());
	    }
	  else
	    {
	      if(address.protocol() == QAbstractSocket::IPv6Protocol)
		list.append(QHostAddress(address.toIPv6Address()).toString());
	    }
	}
    }

  if(!list.isEmpty())
    {
      qSort(list);
      m_ui.listenerIPCombo->addItem(tr("Custom"));
      m_ui.listenerIPCombo->insertSeparator(1);
      m_ui.listenerIPCombo->addItems(list);
    }
  else
    m_ui.listenerIPCombo->addItem(tr("Custom"));
}

void spoton::slotListenerIPComboChanged(int index)
{
  /*
  ** Method will be called because of activity in prepareListenerIPCombo().
  */

  if(index == 0)
    {
      m_ui.listenerIP->clear();
      m_ui.listenerScopeId->clear();
      m_ui.listenerIP->setEnabled(true);
    }
  else
    {
      m_ui.listenerIP->setText(m_ui.listenerIPCombo->currentText());
      m_ui.listenerIP->setEnabled(false);
    }
}

void spoton::slotChatSendMethodChanged(int index)
{
  if(index == 0)
    m_settings["gui/chatSendMethod"] = "Normal_POST";
  else
    m_settings["gui/chatSendMethod"] = "Artificial_GET";

  QSettings settings;

  settings.setValue
    ("gui/chatSendMethod", m_settings.value("gui/chatSendMethod").toString());
}

void spoton::slotSharePublicKeyWithParticipant(void)
{
  if(!m_crypt)
    return;
  else if(m_kernelSocket.state() != QAbstractSocket::ConnectedState)
    return;

  QString oid("");
  int row = -1;

  if((row = m_ui.participants->currentRow()) >= 0)
    {
      QTableWidgetItem *item = m_ui.participants->item
	(row, 2); // neighbor_oid

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    return;

  QByteArray hash(20, 0); // Sha-1
  QByteArray publicKey;
  QByteArray signature;
  bool ok = true;

  publicKey = m_crypt->publicKey(&ok);

  if(ok)
    signature = m_crypt->digitalSignature(hash, &ok);

  if(ok)
    {
      QByteArray message;
      QByteArray name(m_settings.value("gui/nodeName", "unknown").
		      toByteArray().trimmed());

      if(name.isEmpty())
	name = "unknown";

      message.append("befriendparticipant_");
      message.append(oid);
      message.append("_");
      message.append(name.toBase64());
      message.append("_");
      message.append(publicKey.toBase64());
      message.append("_");
      message.append(signature.toBase64());
      message.append('\n');

      if(m_kernelSocket.write(message.constData(), message.length()) !=
	 message.length())
	spoton_misc::logError
	  ("spoton::slotSharePublicKeyWithParticipant(): write() failure.");
      else
	m_kernelSocket.flush();
    }
}

void spoton::slotViewDocumentation(void)
{
  m_docViewer.show(this);
}

void spoton::slotViewLog(void)
{
  m_logViewer.show(this);
}

void spoton::slotStatusChanged(int index)
{
  if(index == 0)
    m_settings["gui/my_status"] = "Away";
  else if(index == 1)
    m_settings["gui/my_status"] = "Busy";
  else if(index == 2)
    m_settings["gui/my_status"] = "Offline";
  else
    m_settings["gui/my_status"] = "Online";

  QSettings settings;

  settings.setValue
    ("gui/my_status", m_settings.value("gui/my_status").toString());
}

bool spoton::isKernelActive(void) const
{
  return m_ui.pid->text() != "0";
}

void spoton::slotCopyMyPublicKey(void)
{
  if(!m_crypt)
    return;

  QClipboard *clipboard = QApplication::clipboard();

  if(!clipboard)
    return;

  QByteArray hash(20, 0); // Sha-1
  QByteArray name;
  QByteArray publicKey;
  QByteArray signature;
  bool ok = true;

  name = m_settings.value("gui/nodeName", "unknown").toByteArray().
    trimmed().toBase64();
  publicKey = m_crypt->publicKey(&ok).toBase64();

  if(ok)
    signature = m_crypt->digitalSignature(hash, &ok).toBase64();

  if(ok)
    clipboard->setText("K" + name + "@" + publicKey + "@" + signature);
  else
    clipboard->clear();
}

void spoton::slotPopulateCountries(void)
{
  if(!m_crypt)
    return;

  QFileInfo fileInfo(spoton_misc::homePath() + QDir::separator() +
		     "country_inclusion.db");

  if(fileInfo.exists())
    {
      if(fileInfo.lastModified() <= m_countriesLastModificationTime)
	return;
      else
	m_countriesLastModificationTime = fileInfo.lastModified();
    }
  else
    m_countriesLastModificationTime = QDateTime();

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton");

    db.setDatabaseName(fileInfo.absoluteFilePath());

    if(db.open())
      {
	QSqlQuery query(db);
	QWidget *focusWidget = QApplication::focusWidget();

	query.setForwardOnly(true);

	if(query.exec("SELECT country, accepted FROM country_inclusion"))
	  {
	    QList<QListWidgetItem *> list(m_ui.countries->selectedItems());
	    QString selectedCountry("");
	    int hval = m_ui.countries->horizontalScrollBar()->value();
	    int vval = m_ui.countries->verticalScrollBar()->value();

	    if(!list.isEmpty())
	      selectedCountry = list.at(0)->text();

	    m_ui.countries->clear();

	    QList<QPair<QString, bool> > countries;

	    while(query.next())
	      {
		QString country("");
		bool accepted = true;
		bool ok = true;

		country = m_crypt->decrypted(QByteArray::
					     fromBase64(query.
							value(0).
							toByteArray()),
					     &ok).constData();

		if(ok)
		  accepted = m_crypt->decrypted(QByteArray::
						fromBase64(query.
							   value(1).
							   toByteArray()),
						&ok).toInt();

		if(ok)
		  {
		    QPair<QString, bool> pair(country, accepted);

		    countries.append(pair);
		  }
	      }

	    qSort(countries);
	    disconnect(m_ui.countries,
		       SIGNAL(itemChanged(QListWidgetItem *)),
		       this,
		       SLOT(slotCountryChanged(QListWidgetItem *)));

	    QListWidgetItem *selected = 0;

	    while(!countries.isEmpty())
	      {
		QListWidgetItem *item = 0;
		QPair<QString, bool> pair(countries.takeFirst());

		item = new QListWidgetItem(pair.first);
		item->setFlags
		  (Qt::ItemIsEnabled | Qt::ItemIsSelectable |
		   Qt::ItemIsUserCheckable);

		if(pair.second)
		  item->setCheckState(Qt::Checked);
		else
		  item->setCheckState(Qt::Unchecked);

		QIcon icon(iconForCountry(item->text()));

		if(icon.isNull())
		  icon = QIcon(":/Flags/unknown.png");

		if(!icon.isNull())
		  item->setIcon(icon);

		m_ui.countries->addItem(item);

		if(!selectedCountry.isEmpty())
		  if(item->text() == selectedCountry)
		    selected = item;
	      }

	    if(selected)
	      selected->setSelected(true);

	    m_ui.countries->horizontalScrollBar()->setValue(hval);
	    m_ui.countries->verticalScrollBar()->setValue(vval);
	    connect(m_ui.countries,
		    SIGNAL(itemChanged(QListWidgetItem *)),
		    this,
		    SLOT(slotCountryChanged(QListWidgetItem *)));

	    if(focusWidget)
	      focusWidget->setFocus();
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton");
}

void spoton::slotCountryChanged(QListWidgetItem *item)
{
  if(!item)
    return;
  else if(!m_crypt)
    return;

  bool ok = true;

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "country_inclusion.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.prepare("UPDATE country_inclusion SET accepted = ? "
		      "WHERE country_hash = ?");
	query.bindValue
	  (0, m_crypt->encrypted(QString::number(item->checkState()).
				 toLatin1(), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (1, m_crypt->keyedHash(item->text().toLatin1(), &ok).toBase64());

	if(ok)
	  ok = query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton");

  if(ok)
    {
      {
	QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton");

	db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
			   "neighbors.db");

	if(db.open())
	  {
	    QSqlQuery query(db);

	    query.prepare("UPDATE neighbors SET "
			  "status_control = 'disconnected' "
			  "WHERE qt_country_hash = ?");
	    query.bindValue
	      (0,
	       m_crypt->keyedHash(item->text().toLatin1(), &ok).toBase64());

	    if(ok)
	      query.exec();
	  }

	db.close();
      }

      QSqlDatabase::removeDatabase("spoton");
    }
}

QIcon spoton::iconForCountry(const QString &country)
{
  if(country == "Afghanistan")
      return QIcon(":/Flags/af.png");
  else if(country == "Albania")
    return QIcon(":/Flags/al.png");
  else if(country == "Algeria")
    return QIcon(":/Flags/dz.png");
  else if(country == "AmericanSamoa")
    return QIcon(":/Flags/as.png");
  else if(country == "Angola")
    return QIcon(":/Flags/ao.png");
  else if(country == "Argentina")
    return QIcon(":/Flags/ar.png");
  else if(country == "Armenia")
    return QIcon(":/Flags/am.png");
  else if(country == "Aruba")
    return QIcon(":/Flags/aw.png");
  else if(country == "Algeria")
    return QIcon(":/Flags/dz.png");
  else if(country == "Australia")
    return QIcon(":/Flags/au.png");
  else if(country == "Austria")
    return QIcon(":/Flags/at.png");
  else if(country == "Azerbaijan")
    return QIcon(":/Flags/az.png");
  else if(country == "Bahrain")
    return QIcon(":/Flags/bh.png");
  else if(country == "Bangladesh")
    return QIcon(":/Flags/bd.png");
  else if(country == "Barbados")
    return QIcon(":/Flags/bb.png");
  else if(country == "Belarus")
    return QIcon(":/Flags/by.png");
  else if(country == "Belgium")
    return QIcon(":/Flags/be.png");
  else if(country == "Belize")
    return QIcon(":/Flags/bz.png");
  else if(country == "Benin")
    return QIcon(":/Flags/bj.png");
  else if(country == "Bermuda")
    return QIcon(":/Flags/bm.png");
  else if(country == "Bhutan")
    return QIcon(":/Flags/bt.png");
  else if(country == "Bolivia")
    return QIcon(":/Flags/bo.png");
  else if(country == "BosniaAndHerzegowina")
    return QIcon(":/Flags/ba.png");
  else if(country == "Botswana")
    return QIcon(":/Flags/bw.png");
  else if(country == "Brazil")
    return QIcon(":/Flags/br.png");
  else if(country == "BruneiDarussalam")
    return QIcon(":/Flags/bn.png");
  else if(country == "Bulgaria")
    return QIcon(":/Flags/bg.png");
  else if(country == "BurkinaFaso")
    return QIcon(":/Flags/bf.png");
  else if(country == "Burundi")
    return QIcon(":/Flags/bi.png");
  else if(country == "Cambodia")
    return QIcon(":/Flags/kh.png");
  else if(country == "Cameroon")
    return QIcon(":/Flags/cm.png");
  else if(country == "Canada")
    return QIcon(":/Flags/ca.png");
  else if(country == "CapeVerde")
    return QIcon(":/Flags/cv.png");
  else if(country == "CentralAfricanRepublic")
    return QIcon(":/Flags/cf.png");
  else if(country == "Chad")
    return QIcon(":/Flags/td.png");
  else if(country == "Chile")
    return QIcon(":/Flags/cl.png");
  else if(country == "China")
    return QIcon(":/Flags/cn.png");
  else if(country == "Colombia")
    return QIcon(":/Flags/co.png");
  else if(country == "Comoros")
    return QIcon(":/Flags/km.png");
  else if(country == "CostaRica")
    return QIcon(":/Flags/cr.png");
  else if(country == "Croatia")
    return QIcon(":/Flags/hr.png");
  else if(country == "Cyprus")
    return QIcon(":/Flags/cy.png");
  else if(country == "CzechRepublic")
    return QIcon(":/Flags/cz.png");
  else if(country == "Default")
    return QIcon(":/Flags/us.png");
  else if(country == "DemocraticRepublicOfCongo")
    return QIcon(":/Flags/cd.png");
  else if(country == "Denmark")
    return QIcon(":/Flags/dk.png");
  else if(country == "Djibouti")
    return QIcon(":/Flags/dj.png");
  else if(country == "DominicanRepublic")
    return QIcon(":/Flags/do.png");
  else if(country == "Ecuador")
    return QIcon(":/Flags/ec.png");
  else if(country == "Egypt")
    return QIcon(":/Flags/eg.png");
  else if(country == "ElSalvador")
    return QIcon(":/Flags/sv.png");
  else if(country == "EquatorialGuinea")
    return QIcon(":/Flags/gq.png");
  else if(country == "Eritrea")
    return QIcon(":/Flags/er.png");
  else if(country == "Estonia")
    return QIcon(":/Flags/ee.png");
  else if(country == "Ethiopia")
    return QIcon(":/Flags/et.png");
  else if(country == "FaroeIslands")
    return QIcon(":/Flags/fo.png");
  else if(country == "Finland")
    return QIcon(":/Flags/fi.png");
  else if(country == "France")
    return QIcon(":/Flags/fr.png");
  else if(country == "FrenchGuiana")
    return QIcon(":/Flags/gy.png");
  else if(country == "Gabon")
    return QIcon(":/Flags/ga.png");
  else if(country == "Georgia")
    return QIcon(":/Flags/ge.png");
  else if(country == "Germany")
    return QIcon(":/Flags/de.png");
  else if(country == "Ghana")
    return QIcon(":/Flags/gh.png");
  else if(country == "Greece")
    return QIcon(":/Flags/gr.png");
  else if(country == "Greenland")
    return QIcon(":/Flags/gl.png");
  else if(country == "Guadeloupe")
    return QIcon(":/Flags/fr.png");
  else if(country == "Guam")
    return QIcon(":/Flags/gu.png");
  else if(country == "Guatemala")
    return QIcon(":/Flags/gt.png");
  else if(country == "Guinea")
    return QIcon(":/Flags/gn.png");
  else if(country == "GuineaBissau")
    return QIcon(":/Flags/gw.png");
  else if(country == "Guyana")
    return QIcon(":/Flags/gy.png");
  else if(country == "Honduras")
    return QIcon(":/Flags/hn.png");
  else if(country == "HongKong")
    return QIcon(":/Flags/hk.png");
  else if(country == "Hungary")
    return QIcon(":/Flags/hu.png");
  else if(country == "Iceland")
    return QIcon(":/Flags/is.png");
  else if(country == "India")
    return QIcon(":/Flags/in.png");
  else if(country == "Indonesia")
    return QIcon(":/Flags/id.png");
  else if(country == "Iran")
    return QIcon(":/Flags/ir.png");
  else if(country == "Iraq")
    return QIcon(":/Flags/iq.png");
  else if(country == "Ireland")
    return QIcon(":/Flags/ie.png");
  else if(country == "Israel")
    return QIcon(":/Flags/il.png");
  else if(country == "Italy")
    return QIcon(":/Flags/it.png");
  else if(country == "IvoryCoast")
    return QIcon(":/Flags/ci.png");
  else if(country == "Jamaica")
    return QIcon(":/Flags/jm.png");
  else if(country == "Japan")
    return QIcon(":/Flags/jp.png");
  else if(country == "Jordan")
    return QIcon(":/Flags/jo.png");
  else if(country == "Kazakhstan")
    return QIcon(":/Flags/kz.png");
  else if(country == "Kenya")
    return QIcon(":/Flags/ke.png");
  else if(country == "Kuwait")
    return QIcon(":/Flags/kw.png");
  else if(country == "Kyrgyzstan")
    return QIcon(":/Flags/kg.png");
  else if(country == "Lao")
    return QIcon(":/Flags/la.png");
  else if(country == "LatinAmericaAndTheCaribbean")
    return QIcon(":/Flags/mx.png");
  else if(country == "Latvia")
    return QIcon(":/Flags/lv.png");
  else if(country == "Lebanon")
    return QIcon(":/Flags/lb.png");
  else if(country == "Lesotho")
    return QIcon(":/Flags/ls.png");
  else if(country == "Liberia")
    return QIcon(":/Flags/lr.png");
  else if(country == "LibyanArabJamahiriya")
    return QIcon(":/Flags/ly.png");
  else if(country == "Liechtenstein")
    return QIcon(":/Flags/li.png");
  else if(country == "Lithuania")
    return QIcon(":/Flags/lt.png");
  else if(country == "Luxembourg")
    return QIcon(":/Flags/lu.png");
  else if(country == "Macau")
    return QIcon(":/Flags/mo.png");
  else if(country == "Macedonia")
    return QIcon(":/Flags/mk.png");
  else if(country == "Madagascar")
    return QIcon(":/Flags/mg.png");
  else if(country == "Malaysia")
    return QIcon(":/Flags/my.png");
  else if(country == "Mali")
    return QIcon(":/Flags/ml.png");
  else if(country == "Malta")
    return QIcon(":/Flags/mt.png");
  else if(country == "MarshallIslands")
    return QIcon(":/Flags/mh.png");
  else if(country == "Martinique")
    return QIcon(":/Flags/fr.png");
  else if(country == "Mauritius")
    return QIcon(":/Flags/mu.png");
  else if(country == "Mayotte")
    return QIcon(":/Flags/yt.png");
  else if(country == "Mexico")
    return QIcon(":/Flags/mx.png");
  else if(country == "Moldova")
    return QIcon(":/Flags/md.png");
  else if(country == "Monaco")
    return QIcon(":/Flags/mc.png");
  else if(country == "Mongolia")
    return QIcon(":/Flags/mn.png");
  else if(country == "Montenegro")
    return QIcon(":/Flags/me.png");
  else if(country == "Morocco")
    return QIcon(":/Flags/ma.png");
  else if(country == "Mozambique")
    return QIcon(":/Flags/mz.png");
  else if(country == "Myanmar")
    return QIcon(":/Flags/mm.png");
  else if(country == "Namibia")
    return QIcon(":/Flags/na.png");
  else if(country == "Nepal")
    return QIcon(":/Flags/np.png");
  else if(country == "Netherlands")
    return QIcon(":/Flags/nl.png");
  else if(country == "NewZealand")
    return QIcon(":/Flags/nz.png");
  else if(country == "Nicaragua")
    return QIcon(":/Flags/ni.png");
  else if(country == "Niger")
    return QIcon(":/Flags/ne.png");
  else if(country == "Nigeria")
    return QIcon(":/Flags/ng.png");
  else if(country == "NorthernMarianaIslands")
    return QIcon(":/Flags/mp.png");
  else if(country == "Norway")
    return QIcon(":/Flags/no.png");
  else if(country == "Oman")
    return QIcon(":/Flags/om.png");
  else if(country == "Pakistan")
    return QIcon(":/Flags/pk.png");
  else if(country == "Panama")
    return QIcon(":/Flags/pa.png");
  else if(country == "Paraguay")
    return QIcon(":/Flags/py.png");
  else if(country == "PeoplesRepublicOfCongo")
    return QIcon(":/Flags/cg.png");
  else if(country == "Peru")
    return QIcon(":/Flags/pe.png");
  else if(country == "Philippines")
    return QIcon(":/Flags/ph.png");
  else if(country == "Poland")
    return QIcon(":/Flags/pl.png");
  else if(country == "Portugal")
    return QIcon(":/Flags/pt.png");
  else if(country == "PuertoRico")
    return QIcon(":/Flags/pr.png");
  else if(country == "Qatar")
    return QIcon(":/Flags/qa.png");
  else if(country == "RepublicOfKorea")
    return QIcon(":/Flags/kr.png");
  else if(country == "Reunion")
    return QIcon(":/Flags/fr.png");
  else if(country == "Romania")
    return QIcon(":/Flags/ro.png");
  else if(country == "RussianFederation")
    return QIcon(":/Flags/ru.png");
  else if(country == "Rwanda")
    return QIcon(":/Flags/rw.png");
  else if(country == "Saint Barthelemy")
    return QIcon(":/Flags/bl.png");
  else if(country == "Saint Martin")
    return QIcon(":/Flags/fr.png");
  else if(country == "SaoTomeAndPrincipe")
    return QIcon(":/Flags/st.png");
  else if(country == "SaudiArabia")
    return QIcon(":/Flags/sa.png");
  else if(country == "Senegal")
    return QIcon(":/Flags/sn.png");
  else if(country == "Serbia")
    return QIcon(":/Flags/rs.png");
  else if(country == "SerbiaAndMontenegro")
    return QIcon(":/Flags/rs.png");
  else if(country == "Singapore")
    return QIcon(":/Flags/sg.png");
  else if(country == "Slovakia")
    return QIcon(":/Flags/sk.png");
  else if(country == "Slovenia")
    return QIcon(":/Flags/si.png");
  else if(country == "Somalia")
    return QIcon(":/Flags/so.png");
  else if(country == "SouthAfrica")
    return QIcon(":/Flags/za.png");
  else if(country == "Spain")
    return QIcon(":/Flags/es.png");
  else if(country == "SriLanka")
    return QIcon(":/Flags/lk.png");
  else if(country == "Sudan")
    return QIcon(":/Flags/sd.png");
  else if(country == "Swaziland")
    return QIcon(":/Flags/sz.png");
  else if(country == "Sweden")
    return QIcon(":/Flags/se.png");
  else if(country == "Switzerland")
    return QIcon(":/Flags/ch.png");
  else if(country == "SyrianArabRepublic")
    return QIcon(":/Flags/sy.png");
  else if(country == "Taiwan")
    return QIcon(":/Flags/tw.png");
  else if(country == "Tajikistan")
    return QIcon(":/Flags/tj.png");
  else if(country == "Tanzania")
    return QIcon(":/Flags/tz.png");
  else if(country == "Thailand")
    return QIcon(":/Flags/th.png");
  else if(country == "Togo")
    return QIcon(":/Flags/tg.png");
  else if(country == "Tonga")
    return QIcon(":/Flags/to.png");
  else if(country == "TrinidadAndTobago")
    return QIcon(":/Flags/tt.png");
  else if(country == "Tunisia")
    return QIcon(":/Flags/tn.png");
  else if(country == "Turkey")
    return QIcon(":/Flags/tr.png");
  else if(country == "USVirginIslands")
    return QIcon(":/Flags/vi.png");
  else if(country == "Uganda")
    return QIcon(":/Flags/ug.png");
  else if(country == "Ukraine")
    return QIcon(":/Flags/ua.png");
  else if(country == "UnitedArabEmirates")
    return QIcon(":/Flags/ae.png");
  else if(country == "UnitedKingdom")
    return QIcon(":/Flags/gb.png");
  else if(country == "UnitedStates")
    return QIcon(":/Flags/us.png");
  else if(country == "UnitedStatesMinorOutlyingIslands")
    return QIcon(":/Flags/us.png");
  else if(country == "Uruguay")
    return QIcon(":/Flags/uy.png");
  else if(country == "Uzbekistan")
    return QIcon(":/Flags/uz.png");
  else if(country == "Venezuela")
    return QIcon(":/Flags/ve.png");
  else if(country == "VietNam")
    return QIcon(":/Flags/vn.png");
  else if(country == "Yemen")
    return QIcon(":/Flags/ye.png");
  else if(country == "Yugoslavia")
    return QIcon(":/Flags/yu.png");
  else if(country == "Zambia")
    return QIcon(":/Flags/zm.png");
  else if(country == "Zimbabwe")
    return QIcon(":/Flags/zw.png");
  else
    return QIcon(":/Flags/unknown.png");
}

void spoton::slotAddBootstrapper(void)
{
}

void spoton::slotFetchMoreAlgo(void)
{
}

void spoton::slotFetchMoreButton(void)
{
}

void spoton::slotAddFriendsKey(void)
{
  if(m_ui.addFriendPublicKeyRadio->isChecked())
    {
      if(m_ui.friendInformation->toPlainText().trimmed().isEmpty())
	return;

      QString key(m_ui.friendInformation->toPlainText().trimmed());

      if(!(key.startsWith("K") || key.startsWith("k")))
	{
	  QMessageBox::warning
	    (this, tr("Spot-On: Warning"),
	     tr("Invalid key. The key must start with either the letter "
		"K or the letter k."));
	  return;
	}

      key.remove(0, 1);

      {
	QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton");

	db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
			   "friends_public_keys.db");

	if(db.open())
	  {
	    spoton_misc::prepareDatabases();

	    QList<QByteArray> list(key.toLatin1().split('@'));

	    if(list.size() != 3)
	      return;

	    QByteArray name(list.at(0));
	    QByteArray publicKey(list.at(1));
	    QByteArray signature(list.at(2));

	    name = QByteArray::fromBase64(name);
	    publicKey = QByteArray::fromBase64(publicKey);
	    signature = QByteArray::fromBase64(signature);

	    if(spoton_misc::saveFriendshipBundle(name,
						 publicKey,
						 -1,
						 db))
	      m_ui.friendInformation->selectAll();
	  }

	db.close();
      }

      QSqlDatabase::removeDatabase("spoton");
    }
  else
    {
      /*
      ** Now we have to perform the inverse of slotCopyFriendshipBundle().
      ** Have fun!
      */

      if(!m_crypt)
	return;
      else if(m_ui.friendInformation->toPlainText().trimmed().isEmpty())
	return;

      QByteArray repleo(m_ui.friendInformation->toPlainText().trimmed().
			toLatin1());

      if(!(repleo.startsWith("R") || repleo.startsWith("r")))
	{
	  QMessageBox::warning
	    (this, tr("Spot-On: Warning"),
	     tr("Invalid repleo. The repleo must start with "
		"either the letter R or the letter r."));
	  return;
	}

      repleo.remove(0, 1);

      QList<QByteArray> list(repleo.split('@'));

      if(list.size() != 6)
	{
	  spoton_misc::logError
	    (QString("spoton::slotAddFriendsKey(): "
		     "received irregular data. Expecting 6 entries, "
		     "received %1.").arg(list.size()));
	  return;
	}

      for(int i = 0; i < list.size(); i++)
	list.replace(i, QByteArray::fromBase64(list.at(i)));

      QByteArray hash;
      QByteArray name;
      QByteArray publicKey;
      QByteArray signature;
      QByteArray symmetricKey;
      QByteArray symmetricKeyAlgorithm;
      bool ok = true;

      symmetricKey = list.value(0);
      symmetricKey = m_crypt->publicKeyDecrypt(symmetricKey, &ok);

      if(!ok)
	return;

      symmetricKeyAlgorithm = list.value(1);
      symmetricKeyAlgorithm = m_crypt->publicKeyDecrypt
	(symmetricKeyAlgorithm, &ok);

      if(!ok)
	return;

      spoton_gcrypt crypt(symmetricKeyAlgorithm,
			  QString("sha512"),
			  QByteArray(),
			  symmetricKey,
			  0,
			  0,
			  QString(""));

      name = crypt.decrypted(list.value(2), &ok);

      if(!ok)
	return;

      publicKey = crypt.decrypted(list.value(3), &ok);

      if(!ok)
	return;

      signature = crypt.decrypted(list.value(4), &ok);

      if(!ok)
	return;

      hash = crypt.decrypted(list.value(5), &ok);

      if(!ok)
	return;

      QByteArray computedHash
	(crypt.keyedHash(symmetricKey +
			 symmetricKeyAlgorithm +
			 name +
			 publicKey +
			 signature, &ok));

      if(!ok)
	return;

      if(computedHash == hash)
	{
	  {
	    QSqlDatabase db = QSqlDatabase::addDatabase
	      ("QSQLITE", "spoton");

	    db.setDatabaseName
	      (spoton_misc::homePath() + QDir::separator() +
	       "friends_public_keys.db");

	    if(db.open())
	      {
		spoton_misc::prepareDatabases();

		if(spoton_misc::saveFriendshipBundle(name,
						     publicKey,
						     -1,
						     db))
		  m_ui.friendInformation->selectAll();
	      }

	    db.close();
	  }

	  QSqlDatabase::removeDatabase("spoton");
	}
    }
}

void spoton::slotDoSearch(void)
{
}

void spoton::slotDisplayLocalSearchResults(void)
{
}

void spoton::slotClearOutgoingMessage(void)
{
  if(m_ui.mailTab->currentIndex() == 1)
    {
      m_ui.participantsCombo->setCurrentIndex(0);
      m_ui.outgoingMessage->clear();
      m_ui.outgoingSubject->clear();
      m_ui.goldbug->clear();
    }
}

void spoton::slotResetAll(void)
{
  QMessageBox mb(this);

#ifdef Q_OS_MAC
  mb.setAttribute(Qt::WA_MacMetalStyle, true);
#endif
  mb.setIcon(QMessageBox::Question);
  mb.setWindowTitle(tr("Spot-On: Confirmation"));
  mb.setWindowModality(Qt::WindowModal);
  mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
  mb.setText(tr("Are you sure that you wish to reset Spot-On? All "
		"data will be lost."));

  if(mb.exec() != QMessageBox::Yes)
    return;

  slotDeactivateKernel();

  QStringList list;

  list << "country_inclusion.db"
       << "email.db"
       << "error_log.dat"
       << "friends_public_keys.db"
       << "idiotes.db"
       << "kernel.db"
       << "listeners.db"
       << "neighbors.db"
       << "public_keys.db"
       << "shared.db"
       << "urls.db";

  while(!list.isEmpty())
    QFile::remove
      (spoton_misc::homePath() + QDir::separator() + list.takeFirst());

  QSettings settings;

  for(int i = settings.allKeys().size() - 1; i >= 0; i--)
    settings.remove(settings.allKeys().at(i));

  QApplication::instance()->exit(0);
  QProcess::startDetached(QCoreApplication::applicationDirPath() +
			  QDir::separator() +
			  QCoreApplication::applicationName());
}

void spoton::slotCopyFriendshipBundle(void)
{
  QClipboard *clipboard = QApplication::clipboard();

  if(!clipboard)
    return;

  if(!m_crypt)
    {
      clipboard->clear();
      return;
    }

  QString oid("");
  int row = -1;

  if((row = m_ui.participants->currentRow()) >= 0)
    {
      QTableWidgetItem *item = m_ui.participants->item
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
  ** 3. Encrypt our information (name, public key, signature) with the
  **    symmetric key. Call our plaintext information T.
  ** 4. Compute a keyed hash of S and T using the symmetric key.
  ** 5. Encrypt the keyed hash with the symmetric key.
  */

  QString neighborOid("");
  QByteArray gemini;
  QByteArray publicKey;
  QByteArray symmetricKey;
  QByteArray symmetricKeyAlgorithm;

  spoton_misc::retrieveSymmetricData(gemini,
				     publicKey,
				     symmetricKey,
				     symmetricKeyAlgorithm,
				     neighborOid,
				     oid,
				     m_crypt);

  if(publicKey.isEmpty() ||
     symmetricKey.isEmpty() || symmetricKeyAlgorithm.isEmpty())
    {
      clipboard->clear();
      return;
    }

  QByteArray data;
  bool ok = true;

  data.append
    (spoton_gcrypt::publicKeyEncrypt(symmetricKey, publicKey, &ok).
     toBase64());
  data.append("@");

  if(!ok)
    {
      clipboard->clear();
      return;
    }

  data.append
    (spoton_gcrypt::publicKeyEncrypt(symmetricKeyAlgorithm, publicKey, &ok).
     toBase64());
  data.append("@");

  if(!ok)
    {
      clipboard->clear();
      return;
    }

  QByteArray myName;
  spoton_gcrypt crypt(symmetricKeyAlgorithm,
		      QString("sha512"),
		      QByteArray(),
		      symmetricKey,
		      0,
		      0,
		      QString(""));

  myName = m_settings.value("gui/nodeName", "unknown").toByteArray().
    trimmed();

  if(myName.isEmpty())
    myName = "unknown";

  data.append(crypt.encrypted(myName, &ok).toBase64());
  data.append("@");

  if(!ok)
    {
      clipboard->clear();
      return;
    }

  QByteArray myPublicKey(m_crypt->publicKey(&ok));

  if(!ok)
    {
      clipboard->clear();
      return;
    }

  data.append(crypt.encrypted(myPublicKey, &ok).toBase64());
  data.append("@");

  if(!ok)
    {
      clipboard->clear();
      return;
    }

  QByteArray hash(20, 0); // Sha-1
  QByteArray mySignature(m_crypt->digitalSignature(hash, &ok));

  if(!ok)
    {
      clipboard->clear();
      return;
    }

  data.append(crypt.encrypted(mySignature, &ok).toBase64());
  data.append("@");

  if(!ok)
    {
      clipboard->clear();
      return;
    }

  hash = crypt.keyedHash(symmetricKey +
			 symmetricKeyAlgorithm +
			 myName +
			 myPublicKey +
			 mySignature, &ok);

  if(!ok)
    {
      clipboard->clear();
      return;
    }

  data.append(crypt.encrypted(hash, &ok).toBase64());

  if(!ok)
    {
      clipboard->clear();
      return;
    }

  clipboard->setText("R" + data);
}

Ui_spoton_mainwindow spoton::ui(void) const
{
  return m_ui;
}

void spoton::slotSendMail(void)
{
  if(!m_crypt)
    return;

  QByteArray message
    (m_ui.outgoingMessage->toHtml().trimmed().toUtf8());

  /*
  ** Why would you send an empty message?
  */

  if(message.isEmpty())
    {
      QMessageBox::warning
	(this, tr("Spot-On: Warning"),
	 tr("Please compose an actual letter."));
      m_ui.outgoingMessage->setFocus();
      return;
    }

  /*
  ** Bundle the love letter and send it to the email.db file. The
  ** kernel shall do the rest.
  */

  spoton_misc::prepareDatabases();

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "email.db");

    if(db.open())
      {
	QList<QByteArray> publicKeyHashes;
	QList<qint64> oids;

	if(m_ui.participantsCombo->currentIndex() > 1)
	  {
	    int index = m_ui.participantsCombo->currentIndex();
	    QByteArray publicKeyHash
	      (m_ui.participantsCombo->itemData(index, Qt::UserRole + 1).
	       toByteArray());
	    qint64 oid = m_ui.participantsCombo->
	      itemData(index, Qt::UserRole).toLongLong();

	    oids.append(oid);
	    publicKeyHashes.append(publicKeyHash);
	  }
	else
	  for(int i = 2; i < m_ui.participantsCombo->count(); i++)
	    {
	      QByteArray publicKeyHash
		(m_ui.participantsCombo->itemData(i, Qt::UserRole + 1).
		 toByteArray());
	      qint64 oid = m_ui.participantsCombo->
		itemData(i, Qt::UserRole).toLongLong();

	      oids.append(oid);
	      publicKeyHashes.append(publicKeyHash);
	    }

	while(!oids.isEmpty())
	  {
	    QByteArray goldbug
	      (m_ui.goldbug->text().trimmed().toLatin1());
	    QByteArray publicKeyHash(publicKeyHashes.takeFirst());
	    QByteArray subject
	      (m_ui.outgoingSubject->text().trimmed().toUtf8());
	    QDateTime now(QDateTime::currentDateTime());
	    QSqlQuery query(db);
	    bool ok = true;
	    qint64 oid = oids.takeFirst();

	    query.prepare("INSERT INTO folders "
			  "(date, folder_index, goldbug, hash, "
			  "message, receiver_sender, receiver_sender_hash, "
			  "status, subject, participant_oid) "
			  "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
	    query.bindValue
	      (0, m_crypt->encrypted(now.toString(Qt::ISODate).
				     toUtf8(), &ok).toBase64());
	    query.bindValue(1, 1); // Sent Folder

	    if(ok)
	      query.bindValue
		(2, m_crypt->encrypted(goldbug, &ok).toBase64());

	    if(ok)
	      query.bindValue
		(3, m_crypt->keyedHash(now.toString().toLatin1() +
				       message + subject, &ok).toBase64());

	    if(ok)
	      query.bindValue(4, m_crypt->encrypted(message, &ok).toBase64());

	    if(ok)
	      query.bindValue
		(5, m_crypt->encrypted(m_ui.participantsCombo->currentText().
				       toUtf8(), &ok).
		 toBase64());

	    if(ok)
	      query.bindValue
		(6, publicKeyHash.toBase64());

	    if(ok)
	      query.bindValue
		(7, m_crypt->encrypted(tr("Queued").toUtf8(),
				       &ok).toBase64());

	    if(ok)
	      query.bindValue
		(8, m_crypt->encrypted(subject, &ok).toBase64());

	    if(ok)
	      query.bindValue
		(9, m_crypt->encrypted(QString::number(oid).toLatin1(), &ok).
		 toBase64());

	    if(ok)
	      query.exec();
	  }

	m_ui.outgoingMessage->clear();
	m_ui.outgoingSubject->clear();
	m_ui.goldbug->clear();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton");
}

void spoton::slotDeleteAllBlockedNeighbors(void)
{
  if(!m_crypt)
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  /*
  ** Delete all non-unique blocked neighbors.
  ** Do remember that remote_ip_address contains encrypted data.
  */

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "neighbors.db");

    if(db.open())
      {
	QMultiHash<QByteArray, qint64> hash;
	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec("SELECT remote_ip_address, OID FROM neighbors "
		      "WHERE status_control = 'blocked' ORDER BY OID"))
	  while(query.next())
	    {
	      QByteArray ip;
	      bool ok = true;

	      ip =
		m_crypt->decrypted(QByteArray::fromBase64(query.value(0).
							  toByteArray()),
				   &ok);

	      if(ok)
		hash.insert(ip, query.value(1).toLongLong());
	    }

	query.prepare("DELETE FROM neighbors WHERE OID = ?");

	for(int i = 0; i < hash.keys().size(); i++)
	  {
	    QList<qint64> list(hash.values(hash.keys().at(i)));

	    qSort(list);

	    for(int j = 1; j < list.size(); j++) // Delete all but one.
	      {
		query.bindValue(0, list.at(j));
		query.exec();
	      }
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton");
  QApplication::restoreOverrideCursor();
}

void spoton::slotCopyMyURLPublicKey(void)
{
}

void spoton::slotShareURLPublicKey(void)
{
}

void spoton::slotDeleteAllUuids(void)
{
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  /*
  ** Delete all non-unique uuids.
  */

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "neighbors.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("DELETE FROM neighbors WHERE OID NOT IN ("
		   "SELECT OID FROM neighbors GROUP BY uuid)");
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton");
  QApplication::restoreOverrideCursor();
}

void spoton::slotRefreshMail(void)
{
  if(!m_crypt)
    return;
  else if(m_ui.mailTab->currentIndex() != 0)
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  if(m_ui.folder->currentIndex() == 0)
    m_ui.mail->horizontalHeaderItem(1)->setText(tr("From"));
  else if(m_ui.folder->currentIndex() == 1)
    m_ui.mail->horizontalHeaderItem(1)->setText(tr("To"));
  else
    m_ui.mail->horizontalHeaderItem(1)->setText(tr("From/To"));

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "email.db");

    if(db.open())
      {
	m_ui.mail->clearContents();
	m_ui.mail->setRowCount(0);
	m_ui.mail->setSortingEnabled(false);
	m_ui.mailMessage->clear();

	QSqlQuery query(db);
	int row = 0;

	if(query.exec(QString("SELECT date, receiver_sender, status, "
			      "subject, "
			      "message, OID FROM folders WHERE "
			      "folder_index = %1").
		      arg(m_ui.folder->currentIndex())))
	  while(query.next())
	    for(int i = 0; i < query.record().count(); i++)
	      {
		bool ok = true;
		QTableWidgetItem *item = 0;

		if(i == 0)
		  {
		    row += 1;
		    m_ui.mail->setRowCount(row);
		  }

		if(i >= 0 && i <= 4)
		  {
		    if(i == 2)
		      item = new QTableWidgetItem
			(QString::fromUtf8(m_crypt->
					   decrypted(QByteArray::
						     fromBase64(query.
								value(i).
								toByteArray()),
						     &ok).constData()));
		    else
		      item = new QTableWidgetItem
			(m_crypt->decrypted(QByteArray::
					    fromBase64(query.
						       value(i).
						       toByteArray()),
					    &ok).constData());

		    if(i == 3)
		      item->setIcon(QIcon(":/email.png"));
		  }
		else
		  item = new QTableWidgetItem(query.value(i).toString());

		item->setFlags
		  (Qt::ItemIsSelectable | Qt::ItemIsEnabled);
		m_ui.mail->setItem(row - 1, i, item);
	      }

	m_ui.mail->setSortingEnabled(true);
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton");
  QApplication::restoreOverrideCursor();
}

void spoton::slotRefreshPostOffice(void)
{
  if(!m_crypt)
    return;
  else if(m_ui.mailTab->currentIndex() != 2)
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "email.db");

    if(db.open())
      {
	m_ui.postoffice->clearContents();
	m_ui.postoffice->setRowCount(0);
	m_ui.postoffice->setSortingEnabled(false);

	QSqlQuery query(db);
	int row = 0;

	if(query.exec("SELECT date_received, "
		      "message_bundle, recipient_hash "
		      "FROM post_office"))
	  while(query.next())
	    for(int i = 0; i < query.record().count(); i++)
	      {
		bool ok = true;
		QTableWidgetItem *item = 0;

		if(i == 0)
		  {
		    row += 1;
		    m_ui.postoffice->setRowCount(row);
		  }

		if(i == 0)
		  item = new QTableWidgetItem
		    (m_crypt->decrypted(QByteArray::
					fromBase64(query.
						   value(i).
						   toByteArray()),
					&ok).constData());
		else if(i == 1)
		  {
		    QByteArray bytes
		      (m_crypt->decrypted(QByteArray::
					  fromBase64(query.
						     value(i).
						     toByteArray()),
					  &ok));

		    item = new QTableWidgetItem
		      (QString::number(bytes.size()));
		  }
		else
		  item = new QTableWidgetItem(query.value(i).toString());

		item->setFlags
		  (Qt::ItemIsSelectable | Qt::ItemIsEnabled);
		m_ui.postoffice->setItem(row - 1, i, item);
	      }

	m_ui.postoffice->setSortingEnabled(true);
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton");
  QApplication::restoreOverrideCursor();
}

void spoton::slotMailSelected(QTableWidgetItem *item)
{
  if(!item)
    return;

  int row = item->row();

  if(row < 0)
    {
      m_ui.mailMessage->clear();
      return;
    }

  QString date("");
  QString fromTo("");
  QString message("");
  QString status("");
  QString subject("");
  QString text("");

  {
    QTableWidgetItem *item = m_ui.mail->item(row, 0); // Date

    if(item)
      date = item->text();

    item = m_ui.mail->item(row, 1); // From / To

    if(item)
      fromTo = item->text();

    item = m_ui.mail->item(row, 2); // Status

    if(item)
      status = item->text();

    item = m_ui.mail->item(row, 3); // Subject

    if(item)
      subject = item->text();

    item = m_ui.mail->item(row, 4); // Message

    if(item)
      message = item->text();
  }

  if(m_ui.folder->currentIndex() == 0) // Inbox
    {
      text.append(tr("<b>From:</b> "));
      text.append(fromTo);
      text.append("<br>");
      text.append(tr("<b>To:</b> me"));
      text.append("<br>");
      text.append(tr("<b>Subject:</b> "));
      text.append(subject);
      text.append("<br>");
      text.append(tr("<b>Sent: </b> "));
      text.append(date);
      text.append("<br><br>");
      text.append(message);

      if(status != tr("Read"))
	{
	  QTableWidgetItem *item = 0;

	  if((item = m_ui.mail->item(row, 5))) // OID
	    if(updateMailStatus(item->text(), tr("Read")))
	      if((item = m_ui.mail->item(row, 2))) // Status
		item->setText(tr("Read"));
	}
    }
  else if(m_ui.folder->currentIndex() == 1) // Sent
    {
      text.append(tr("<b>From:</b> me"));
      text.append("<br>");
      text.append(tr("<b>To:</b> "));
      text.append(fromTo);
      text.append("<br>");
      text.append(tr("<b>Subject:</b> "));
      text.append(subject);
      text.append("<br>");
      text.append(tr("<b>Sent: </b> "));
      text.append(date);
      text.append("<br><br>");
      text.append(message);
    }
  else // Trash
    {
      text.append(tr("<b>From/To:</b> "));
      text.append(fromTo);
      text.append("<br>");
      text.append(tr("<b>From/To:</b> "));
      text.append(fromTo);
      text.append("<br>");
      text.append(tr("<b>Subject:</b> "));
      text.append(subject);
      text.append("<br>");
      text.append(tr("<b>Sent: </b> "));
      text.append(date);
      text.append("<br><br>");
      text.append(message);
    }

  m_ui.mailMessage->clear();
  m_ui.mailMessage->append(text);
  m_ui.mailMessage->horizontalScrollBar()->setValue(0);
  m_ui.mailMessage->verticalScrollBar()->setValue(0);
}

void spoton::slotDeleteMail(void)
{
  if(m_ui.mailTab->currentIndex() != 0)
    return;

  QModelIndexList list
    (m_ui.mail->selectionModel()->selectedRows(5)); // OID

  if(list.isEmpty())
    return;

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "email.db");

    if(db.open())
      {
	QSqlQuery query(db);

	while(!list.isEmpty())
	  {
	    QString oid(list.takeFirst().data().toString());
	    bool ok = true;

	    if(m_ui.folder->currentIndex() == 2)
	      {
		query.prepare("DELETE FROM folders WHERE oid = ?");
		query.bindValue(0, oid);
	      }
	    else
	      {
		query.prepare("UPDATE folders SET folder_index = 2, "
			      "status = ? WHERE "
			      "oid = ?");

		if(m_crypt)
		  query.bindValue
		    (0, m_crypt->encrypted(tr("Deleted").toUtf8(), &ok).
		     toBase64());
		else
		  ok = false;

		query.bindValue(1, oid);
	      }

	    if(ok)
	      query.exec();
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton");
  slotRefreshMail();
}

void spoton::slotGeminiChanged(QTableWidgetItem *item)
{
  if(!item)
    return;
  else if(item->column() != 5) // Gemini
    return;
  else if(!m_ui.participants->item(item->row(), 1))
    return;

  saveGemini(item->text().toLatin1(), // Gemini
	     m_ui.participants->item(item->row(), 1)->text()); // OID
}

void spoton::slotGenerateGeminiInChat(void)
{
  if(!m_crypt)
    return;

  QModelIndexList list
    (m_ui.participants->selectionModel()->selectedRows(1));

  while(!list.isEmpty())
    {
      QTableWidgetItem *item1 =
	m_ui.participants->item(list.first().row(), 1); // OID
      QTableWidgetItem *item2 =
	m_ui.participants->item(list.first().row(), 5); // Gemini

      list.takeFirst();

      if(!item1 || !item2)
	continue;

      QByteArray gemini
	(spoton_gcrypt::
	 strongRandomBytes(spoton_gcrypt::cipherKeyLength("aes256")));

      if(saveGemini(gemini.toBase64(), item1->text()))
	{
	  m_ui.participants->blockSignals(true);
	  item2->setText(gemini.toBase64());
	  m_ui.participants->blockSignals(false);
	}
    }
}

bool spoton::saveGemini(const QByteArray &gemini,
			const QString &oid)
{
  bool ok = true;

  {
    QSqlDatabase db = QSqlDatabase::addDatabase
      ("QSQLITE", "spoton_save_gemini"); /*
					 ** We need a special database
					 ** name. Please see itemChanged()
					 ** documentation.
					 */

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.prepare("UPDATE friends_public_keys SET "
		      "gemini = ? WHERE OID = ?");

	if(gemini.isNull())
	  query.bindValue(0, QVariant(QVariant::ByteArray));
	else
	  {
	    if(m_crypt)
	      query.bindValue(0, m_crypt->encrypted(gemini, &ok).toBase64());
	    else
	      query.bindValue(0, QVariant(QVariant::ByteArray));
	  }

	query.bindValue(1, oid);

	if(ok)
	  ok = query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton_save_gemini");
  return ok;
}

void spoton::slotGenerateGoldBug(void)
{
  QByteArray goldbug
    (spoton_gcrypt::
     strongRandomBytes(spoton_gcrypt::cipherKeyLength("aes256")));

  m_ui.goldbug->setText(goldbug.toBase64());
}

void spoton::slotEmptyTrash(void)
{
  QMessageBox mb(this);

#ifdef Q_OS_MAC
  mb.setAttribute(Qt::WA_MacMetalStyle, true);
#endif
  mb.setIcon(QMessageBox::Question);
  mb.setWindowTitle(tr("Spot-On: Confirmation"));
  mb.setWindowModality(Qt::WindowModal);
  mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
  mb.setText(tr("Are you sure that you wish to empty the Trash folder?"));

  if(mb.exec() != QMessageBox::Yes)
    return;

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "email.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("DELETE FROM folders WHERE folder_index = 2");
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton");

  if(m_ui.folder->currentIndex() == 2)
    {
      m_ui.mail->clearContents();
      m_ui.mail->setRowCount(0);
    }
}

void spoton::slotRetrieveMail(void)
{
  if(m_kernelSocket.state() == QAbstractSocket::ConnectedState)
    {
      QByteArray message("retrievemail\n");

      if(m_kernelSocket.write(message.constData(), message.length()) !=
	 message.length())
	spoton_misc::logError
	  ("spoton::slotRetrieveMail(): write() failure.");
      else
	m_kernelSocket.flush();
    }
}

void spoton::slotKernelStatus(void)
{
  if(isKernelActive())
    slotDeactivateKernel();
  else
    slotActivateKernel();
}

void spoton::slotMailTabChanged(int index)
{
  /*
  ** Change states of some widgets.
  */

  m_ui.pushButtonClearMail->setEnabled(index != 2);
}

void spoton::slotEnabledPostOffice(bool state)
{
  m_settings["gui/postoffice_enabled"] = state;

  QSettings settings;

  settings.setValue("gui/postoffice_enabled", state);
}

void spoton::slotEmailStatusClicked(void)
{
  m_sb.email->setVisible(false);
  m_ui.mailTab->setCurrentIndex(0);
  m_ui.tab->setCurrentIndex(1);
  slotRefreshMail();
}

void spoton::slotChatStatusClicked(void)
{
  m_sb.chat->setVisible(false);
  m_ui.tab->setCurrentIndex(0);
}

bool spoton::updateMailStatus(const QString &oid, const QString &status)
{
  if(!m_crypt)
    return false;

  bool ok = true;

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "email.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.prepare("UPDATE folders SET status = ? WHERE "
		      "oid = ?");
	query.bindValue
	  (0, m_crypt->encrypted(status.toUtf8(), &ok).toBase64());
	query.bindValue(1, oid);

	if(ok)
	  ok = query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton");
  return ok;
}
