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
  connect(m_ui.pushButtonMakeFriends,
	  SIGNAL(clicked(bool)),
	  this,
	  SLOT(slotSharePublicKey(void)));
  connect(m_ui.pushButtonLogViewer,
	  SIGNAL(clicked(bool)),
	  this,
	  SLOT(slotViewLog(void)));
  connect(m_ui.pushButtonDocViewer,
	  SIGNAL(clicked(bool)),
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
  connect(m_ui.chatSendMethod,
	  SIGNAL(currentIndexChanged(int)),
	  this,
	  SLOT(slotChatSendMethodChanged(int)));
  connect(m_ui.status,
	  SIGNAL(currentIndexChanged(int)),
	  this,
	  SLOT(slotStatusChanged(int)));
  connect(m_ui.pushButtonCopytoClipboard,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotCopyMyPublicKey(void)));
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
  connect(m_ui.pushButtonClearOutgoingMessage,
	  SIGNAL(clicked(bool)),
	  this,
	  SLOT(slotClearOutgoingMessage(void)));
  statusBar()->showMessage(tr("Not connected to the kernel. Is the kernel "
			      "active?"));
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

      settings.setValue("gui/uuid", uuid.toRfc4122());
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
  else
    m_ui.status->setCurrentIndex(2);

  m_ui.kernelPath->setToolTip(m_ui.kernelPath->text());
  m_ui.nodeName->setMaxLength(NAME_MAXIMUM_LENGTH);
  m_ui.nodeName->setText
    (QString::fromUtf8(m_settings.value("gui/nodeName", "unknown").
		       toByteArray()).trimmed());
  m_ui.cipherType->clear();
  m_ui.cipherType->addItems(spoton_gcrypt::cipherTypes());
#if SPOTON_MINIMUM_GCRYPT_VERSION < 0x010500
  m_ui.iterationCount->setEnabled(false);
  m_ui.iterationCount->setToolTip
    (tr("The Iteration Count is disabled because "
	"gcrypt's gcry_kdf_derive() function "
	"is not available in your version of gcrypt."));
#endif
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

  m_ui.iterationCount->setValue(m_settings.value("gui/iterationCount", 1000).
			      toInt());
  str = m_settings.value("gui/rsaKeySize", "3072").
    toString().toLower().trimmed();

  if(m_ui.rsaKeySize->findText(str) > -1)
    m_ui.rsaKeySize->setCurrentIndex(m_ui.rsaKeySize->findText(str));

  m_ui.saltLength->setValue(m_settings.value("gui/saltLength", 256).toInt());

  for(int i = 0; i < m_ui.tab->count(); i++)
    m_ui.tab->tabBar()->setTabData(i, QString("page_%1").arg(i + 1));

  if(spoton_gcrypt::passphraseSet())
    {
      m_ui.passphrase1->setText("0000000000");
      m_ui.passphrase2->setText("0000000000");
      m_ui.rsaKeySize->setEnabled(false);

      for(int i = 0; i < m_ui.tab->count(); i++)
	if(m_ui.tab->tabBar()->tabData(i).toString() == "page_7")
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
      m_ui.passphrase->setEnabled(false);
      m_ui.passphraseButton->setEnabled(false);
      m_ui.passphraseLabel->setEnabled(false);
      m_ui.kernelBox->setEnabled(false);
      m_ui.listenersBox->setEnabled(false);
      m_ui.pushButtonDocViewer->setEnabled(false);
      m_ui.pushButtonLogViewer->setEnabled(false);
      m_ui.resetSpotOn->setEnabled(false);

      for(int i = 0; i < m_ui.tab->count(); i++)
	if(m_ui.tab->tabBar()->tabData(i).toString() == "page_5")
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
  m_ui.listeners->setColumnHidden(m_ui.listeners->columnCount() - 1,
				true);
  m_ui.neighbors->setColumnHidden(m_ui.neighbors->columnCount() - 1, true);
  m_ui.participants->setColumnHidden(m_ui.participants->columnCount() - 2, true);
  m_ui.participants->setColumnHidden(m_ui.participants->columnCount() - 3, true);
  m_ui.participants->setColumnHidden(m_ui.participants->columnCount() - 4, true);
  m_ui.participants->horizontalHeader()->setSortIndicator
    (0, Qt::AscendingOrder);
  prepareListenerIPCombo();
  spoton_misc::prepareDatabases();

  /*
  ** Not wise! We may find things we're not prepared for.
  */

  foreach(QAbstractButton *button,
	  m_ui.participants->findChildren<QAbstractButton *> ())
    {
      button->setIcon(QIcon(":/broadcasttoall.png"));
      button->setToolTip(tr("Broadcast"));
    }

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

	bool ok = true;

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
	  query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton");
  m_ui.listenerIP->selectAll();
}

void spoton::slotAddNeighbor(void)
{
  if(!m_crypt)
    return;

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
	QString scopeId(m_ui.neighborScopeId->text().trimmed());
	QString status("connected");
	QSqlQuery query(db);

	if(m_ui.ipv4Neighbor->isChecked())
	  protocol = "IPv4";
	else if(m_ui.ipv6Neighbor->isChecked())
	  protocol = "IPv6";
	else
	  protocol = "dns_domain";

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
		      "qt_country_hash) "
		      "VALUES "
		      "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");

	if(protocol == "IPv6")
	  query.bindValue(0, "::1");
	else
	  query.bindValue(0, "127.0.0.1");

	query.bindValue(1, "0");

	bool ok = true;

	query.bindValue(2, protocol);

	if(ip.isEmpty())
	  query.bindValue
	    (3, m_crypt->encrypted(QByteArray(), &ok).toBase64());
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

	if(ok)
	  query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton");
  m_ui.neighborIP->selectAll();
}

void spoton::slotProtocolRadioToggled(bool state)
{
  Q_UNUSED(state);

  QRadioButton *radio = qobject_cast<QRadioButton *> (sender());

  if(!radio)
    return;

  if(radio == m_ui.ipv4Listener || radio == m_ui.ipv4Neighbor)
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

	QString ip("");
	QString port("");
	int hval = m_ui.listeners->horizontalScrollBar()->value();
	int row = -1;
	int vval = m_ui.listeners->verticalScrollBar()->value();

	if((row = m_ui.listeners->currentRow()) >= 0)
	  {
	    QTableWidgetItem *item = m_ui.listeners->item(row, 2);

	    if(item)
	      ip = item->text();

	    if((item = m_ui.listeners->item(row, 3)))
	      port = item->text();
	  }

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
			      "FROM listeners WHERE "
			      "status_control <> 'deleted' %1").
		      arg(m_ui.showOnlyOnlineListeners->isChecked() ?
			  "AND status = 'online'" : "")))
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

			if(i >= 2 && i <= 5)
			  item = new QTableWidgetItem
			    (m_crypt->decrypted(QByteArray::
						fromBase64(query.
							   value(i).
							   toByteArray()),
						&ok).trimmed().constData());
			else
			  item = new QTableWidgetItem(query.
						      value(i).toString().
						      trimmed());

			item->setTextAlignment(Qt::AlignLeft |
					       Qt::AlignVCenter);
			item->setFlags
			  (Qt::ItemIsSelectable | Qt::ItemIsEnabled);
			m_ui.listeners->setItem(row, i, item);

			if(i == 1)
			  {
			    if(query.value(i).toString().trimmed() == "online")
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
	m_ui.listeners->resizeColumnsToContents();
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

	QString remoteIp("");
	QString remotePort("");
	int columnREMOTE_IP = 9;
	int columnREMOTE_PORT = 10;
	int hval = m_ui.neighbors->horizontalScrollBar()->value();
	int row = -1;
	int vval = m_ui.neighbors->verticalScrollBar()->value();

	if((row = m_ui.neighbors->currentRow()) >= 0)
	  {
	    QTableWidgetItem *item = m_ui.neighbors->item
	      (row, columnREMOTE_IP);

	    if(item)
	      remoteIp = item->text();

	    if((item = m_ui.neighbors->item(row, columnREMOTE_PORT)))
	      remotePort = item->text();
	  }

	m_ui.neighbors->setSortingEnabled(false);
	m_ui.neighbors->clearContents();
	m_ui.neighbors->setRowCount(0);

	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec(QString("SELECT sticky, UPPER(uuid), status, "
			      "local_ip_address, local_port, "
			      "external_ip_address, external_port, "
			      "country, "
			      "remote_ip_address, "
			      "remote_port, scope_id, protocol, OID "
			      "FROM neighbors WHERE "
			      "status_control <> 'deleted' %1").
		      arg(m_ui.showOnlyConnectedNeighbors->isChecked() ?
			  "AND status = 'connected'" : "")))
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
				     "indefinite lifetime for a neighbor. "
				     "If "
				     "not checked, the neighbor will be "
				     "terminated after some internal "
				     "timer expires."));

		if(query.value(0).toInt() == 1)
		  {
		    check->setChecked(true);
		    check->setIcon(QIcon(":/sticky.png"));
		  }
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

		    if(i >= 7 && i <= 10)
		      {
			bool ok = true;

			item = new QTableWidgetItem
			  (m_crypt->decrypted(QByteArray::
					      fromBase64(query.
							 value(i).
							 toByteArray()),
					      &ok).trimmed().constData());
		      }
		    else
		      item = new QTableWidgetItem
			(query.value(i).toString().trimmed());

		    item->setTextAlignment(Qt::AlignLeft | Qt::AlignVCenter);
		    item->setFlags(Qt::ItemIsSelectable | Qt::ItemIsEnabled);

		    if(i == 2)
		      {
			if(query.value(i).toString().trimmed() == "connected")
			  item->setBackground(QBrush(QColor("lightgreen")));
			else
			  item->setBackground(QBrush());

			if(query.value(i).toString().trimmed() == "connected")
			  item->setIcon(QIcon(":/connect_established.png"));
			else
			  item->setIcon(QIcon(":/connect_no.png"));
		      }

		    m_ui.neighbors->setItem(row, i, item);
		  }

		QTableWidgetItem *item1 = m_ui.neighbors->item(row, 7);

		if(item1)
		  {
		    QIcon icon;
		    QTableWidgetItem *item2 = m_ui.neighbors->item(row, 8);

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

	for(int i = 0; i < m_ui.neighbors->columnCount(); i++)
	  m_ui.neighbors->horizontalHeaderItem(i)->
	    setTextAlignment(Qt::AlignLeft | Qt::AlignVCenter);

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
		  m_kernelSocket.connectToHost
		    ("127.0.0.1", query.value(0).toInt());
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
  settings.setValue("gui/neighborsHorizontalSplitter",
		    m_ui.neighborsHorizontalSplitter->saveState());
  settings.setValue("gui/neighborsVerticalSplitter",
		    m_ui.neighborsVerticalSplitter->saveState());
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
	(row, m_ui.listeners->columnCount() - 1);

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
	(row, m_ui.neighbors->columnCount() - 1);

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
    {
      QSqlQuery query(db);

      /*
      ** OK, so the kernel is inactive. Discover the
      ** listeners that have not been deleted and update some of their
      ** information.
      */

      query.exec("PRAGMA synchronous = OFF");
      query.exec("UPDATE listeners SET connections = 0, "
		 "status = 'off' WHERE "
		 "(status = 'online' OR connections > 0) AND "
		 "status_control <> 'deleted'");
    }
}

void spoton::updateNeighborsTable(QSqlDatabase &db)
{
  if(!isKernelActive())
    {
      QSqlQuery query(db);

      /*
      ** OK, so the kernel is inactive. Discover the
      ** neighbors that have not been deleted and update some of their
      ** information.
      */

      query.exec("PRAGMA synchronous = OFF");
      query.exec("UPDATE neighbors SET local_ip_address = '127.0.0.1', "
		 "local_port = 0, status = 'disconnected' WHERE "
		 "(local_ip_address <> '127.0.0.1' OR local_port <> 0 OR "
		 "status <> 'disconnected') AND "
		 "status_control <> 'deleted'");
    }
}

void spoton::updateParticipantsTable(QSqlDatabase &db)
{
  if(!isKernelActive())
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

  statusBar()->showMessage
    (tr(
#if SPOTON_MINIMUM_GCRYPT_VERSION >= 0x010500
	"Generating a derived key. Please be patient."
#else
	"Preparing the passphrase. Please be patient."
#endif
	));
#ifdef Q_OS_MAC
  QApplication::processEvents();
#endif

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
  gcry_randomize(static_cast<void *> (salt.data()),
		 static_cast<size_t> (salt.length()),
		 GCRY_STRONG_RANDOM);

  QByteArray derivedKey
    (spoton_gcrypt::derivedKey(m_ui.cipherType->currentText(),
			       m_ui.hashType->currentText(),
			       static_cast<unsigned long> (m_ui.iterationCount->
							   value()),
			       str1,
			       salt,
			       error1));

  if(error1.isEmpty())
    {
      if(reencode)
	{
	  statusBar()->showMessage
	    (tr("Re-encoding RSA key pair 1 of 2. Please be patient."));
	  QApplication::processEvents();
	  spoton_gcrypt::reencodePrivateKey
	    (m_ui.cipherType->currentText(),
	     derivedKey,
	     m_settings.value("gui/cipherType", "aes256").toString().trimmed(),
	     m_crypt->symmetricKey(),
	     "private",
	     error2);

	  if(error2.isEmpty())
	    {
	      statusBar()->showMessage
		(tr("Re-encoding RSA key pair 2 of 2. Please be patient."));
	      QApplication::processEvents();
	      spoton_gcrypt::reencodePrivateKey
		(m_ui.cipherType->currentText(),
		 derivedKey,
		 m_settings.value("gui/cipherType", "aes256").
		 toString().trimmed(),
		 m_crypt->symmetricKey(),
		 "shared",
		 error2);
	    }
	}
      else
	{
	  QStringList list;

	  list << "private"
	       << "shared";

	  for(int i = 0; i < list.size(); i++)
	    {
	      statusBar()->showMessage
		(tr("Generating RSA key pair %1 of %2. Please be patient.").
		 arg(i + 1).arg(list.size()));
	      QApplication::processEvents();

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
			     "reencodePrivateKey().").
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
	      slotDeactivateKernel();

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
	      reencode.reencode(this, crypt, m_crypt);
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
	      statusBar()->showMessage
		(tr("Initializing country_inclusion.db."));
	      QApplication::processEvents();
	      QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
	      spoton_misc::populateCountryDatabase(m_crypt);
	      QApplication::restoreOverrideCursor();
	    }

	  m_tableTimer.start();
	  sendKeyToKernel();
	}

      m_ui.kernelBox->setEnabled(true);
      m_ui.listenersBox->setEnabled(true);
      m_ui.pushButtonDocViewer->setEnabled(true);
      m_ui.pushButtonLogViewer->setEnabled(true);
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

      statusBar()->showMessage
	(tr("Initializing country_inclusion.db."));
      QApplication::processEvents();
      QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
      spoton_misc::populateCountryDatabase(m_crypt);
      QApplication::restoreOverrideCursor();
      spoton_misc::populateCountryDatabase(m_crypt);
      m_tableTimer.start();
      sendKeyToKernel();
      m_ui.kernelBox->setEnabled(true);
      m_ui.listenersBox->setEnabled(true);
      m_ui.passphrase->clear();
      m_ui.passphrase->setEnabled(false);
      m_ui.passphraseButton->setEnabled(false);
      m_ui.passphraseLabel->setEnabled(false);
      m_ui.rsaKeySize->setEnabled(false);
      m_ui.pushButtonDocViewer->setEnabled(true);
      m_ui.pushButtonLogViewer->setEnabled(true);
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
      menu.addAction(QIcon(":/sharekey.png"),
		     tr("&Share my Public Key"),
		     this, SLOT(slotSharePublicKey(void)));
      menu.addSeparator();
      menu.addAction(QIcon(":/connect.png"), tr("&Connect"),
		     this, SLOT(slotConnectNeighbor(void)));
      menu.addAction(tr("&Disconnect"),
		     this, SLOT(slotDisconnectNeighbor(void)));
      menu.addSeparator();
      menu.addAction(QIcon(":/delete.png"),tr("&Delete"),
		     this, SLOT(slotDeleteNeighbor(void)));
      menu.addAction(tr("Delete &All"),
		     this, SLOT(slotDeleteAllNeighbors(void)));
      menu.addSeparator();
      menu.addAction(QIcon(":/block.png"),tr("&Block"),
		     this, SLOT(slotBlockNeighbor(void)));
      menu.addAction(tr("&Unblock"),
		     this, SLOT(slotDisconnectNeighbor(void)));
      menu.exec(m_ui.neighbors->mapToGlobal(point));
    }
  else
    {
      QAction *action = menu.addAction
	(QIcon(":/plist_confirmed_as_permanent_friend.png"),
	 tr("&Add participant as friend."),
	 this, SLOT(slotSharePublicKeyWithParticipant(void)));
      QTableWidgetItem *item = m_ui.participants->itemAt(point);

      if(item && item->data(Qt::UserRole).toBool()) // Temporary friend?
	action->setEnabled(true);
      else
	action->setEnabled(false);

      menu.addAction(QIcon(":/repleo.png"),
		     tr("Copy Repleo to the clipboard buffer."),
		     this, SLOT(slotCopyFriendshipBundle(void)));
      menu.addAction(QIcon(":/delete.png"),
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
      statusBar()->showMessage(tr("Connected to the kernel on port %1 "
				  "from local port %2.").
			       arg(m_kernelSocket.peerPort()).
			       arg(m_kernelSocket.localPort()));
    }
  else
    statusBar()->showMessage(tr("Not connected to the kernel. Is the kernel "
				"active?"));
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
	(row, m_ui.neighbors->columnCount() - 1);

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
	(row, m_ui.neighbors->columnCount() - 1);

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
  QString oid("");
  int row = -1;

  if((row = m_ui.neighbors->currentRow()) >= 0)
    {
      QTableWidgetItem *item = m_ui.neighbors->item
	(row, m_ui.neighbors->columnCount() - 1);

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
	query.bindValue(0, "blocked");
	query.bindValue(1, oid);
	query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton");
}

void spoton::slotUnblockNeighbor(void)
{
  /*
  ** Not used.
  */
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

	for(int i = m_ui.participantsCombo->count() - 1; i >= 1; i--)
	  m_ui.participantsCombo->removeItem(i);

	m_ui.participants->setRowCount(0);

	QSqlQuery query(db);
	QStringList participants;
	QWidget *focusWidget = QApplication::focusWidget();

	query.setForwardOnly(true);

	/*
	** We only wish to display other public keys.
	*/

	if(query.exec("SELECT name, OID, neighbor_oid, public_key_hash, "
		      "status FROM friends_public_keys"))
	  while(query.next())
	    {
	      QString status(query.value(4).toString().trimmed());
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
		      (QString::fromUtf8(query.value(i).toByteArray()).
		       trimmed());
		  else if(i == 4)
		    {
		      QString status(query.value(i).toString().trimmed());

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
		  else
		    item = new QTableWidgetItem(query.value(i).toString().
						trimmed());

		  item->setFlags
		    (Qt::ItemIsSelectable | Qt::ItemIsEnabled);

		  if(i == 0)
		    {
		      participants.append(item->text());

		      if(!temporary)
			{
			  if(status == "away")
			    {
			      item->setIcon
				(QIcon(":/Status/status_blue.png"));
			      item->setToolTip(tr("Your friend %1 is away.").
					       arg(item->text()));
			    }
			  else if(status == "busy")
			    {
			      item->setIcon
				(QIcon(":/Status/status_red.png"));
			      item->setToolTip(tr("Your friend %1 is busy.").
					       arg(item->text()));
			    }
			  else if(status == "offline")
			    {
			      item->setIcon
				(QIcon(":/Status/status_gray.png"));
			      item->setToolTip
				(tr("Your friend %1 is offline.").
				 arg(item->text()));
			    }
			  else if(status == "online")
			    {
			      item->setIcon
				(QIcon(":/Status/status_lightgreen.png"));
			      item->setToolTip(tr("User %1 is online.").
					       arg(item->text()));
			    }
			  else
			    {
			      item->setIcon
				(QIcon(":/plist_confirmed_as_permanent_"
				       "friend.png"));
			      item->setToolTip(tr("User %1 is a "
						  "permanent friend.").
					       arg(item->text()));
			    }
			}
		      else
			{
			  item->setIcon
			    (QIcon(":/plist_connected_neighbour.png"));
			  item->setToolTip
			    (tr("User %1 requests your friendship.").
			     arg(item->text()));
			}
		    }

		  item->setData(Qt::UserRole, temporary);
		  m_ui.participants->setItem(row - 1, i, item);
		}

	      if(hashes.contains(query.value(3).toString().trimmed()))
		rows.append(row - 1);
	    }

	if(focusWidget)
	  focusWidget->setFocus();

	if(!participants.isEmpty())
	  {
	    qSort(participants);
	    m_ui.participantsCombo->insertSeparator(1);
	    m_ui.participantsCombo->addItems(participants);
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
      QVariant data(list.takeFirst().data());

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
	      data = data.trimmed();
	      data.remove(0, strlen("message_"));

	      if(!data.isEmpty())
		{
		  QList<QByteArray> list(data.split('_'));

		  if(list.size() != 2)
		    continue;

		  for(int i = 0; i < list.size(); i++)
		    list.replace(i, QByteArray::fromBase64(list.at(i)));

		  QByteArray name(list.at(0));
		  QByteArray message(list.at(1));
		  QString msg("");

		  if(name.isEmpty())
		    name = "unknown";

		  if(message.isEmpty())
		    message = "unknown";

		  name = name.mid(0, name.indexOf('\n')).trimmed();
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

		}
	    }
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
	(row, m_ui.neighbors->columnCount() - 1);

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    return;

  QByteArray publicKey;
  bool ok = true;

  publicKey = m_crypt->publicKey(&ok);

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
      m_ui.listenerIP->setVisible(true);
    }
  else
    m_ui.listenerIP->setVisible(false);
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
      QTableWidgetItem *item = m_ui.participants->item(row, 2);

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    return;

  QByteArray publicKey;
  bool ok = true;

  publicKey = m_crypt->publicKey(&ok);

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

  QByteArray name;
  QByteArray publicKey;
  bool ok = true;

  name = m_settings.value("gui/nodeName", "unknown").toByteArray().
    trimmed().toBase64();
  publicKey = m_crypt->publicKey(&ok).toBase64();

  if(ok)
    clipboard->setText("K" + name + "@" + publicKey);
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
					     &ok).trimmed().constData();

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
		      "WHERE hash = ?");
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

      {
	QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton");

	db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
			   "friends_public_keys.db");

	if(db.open())
	  {
	    spoton_misc::prepareDatabases();

	    QList<QByteArray> list
	      (m_ui.friendInformation->toPlainText().
	       trimmed().toLatin1().split('@'));

	    if(list.size() != 2)
	      return;

	    QByteArray name(list.at(0));
	    QByteArray publicKey(list.at(1));

	    if(name.startsWith("K") || name.startsWith("k"))
	      name.remove(0, 1);

	    name = QByteArray::fromBase64(name);
	    publicKey = QByteArray::fromBase64(publicKey);

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

      if(repleo.startsWith("R") || repleo.startsWith("r"))
	repleo.remove(0, 1);

      QList<QByteArray> list(repleo.split('@'));

      if(list.size() != 5)
	{
	  spoton_misc::logError
	    (QString("spoton::slotAddFriendsKey(): "
		     "received irregular data. Expecting 5 entries, "
		     "received %1.").arg(list.size()));
	  return;
	}

      for(int i = 0; i < list.size(); i++)
	list.replace(i, QByteArray::fromBase64(list.at(i)));

      QByteArray hash;
      QByteArray name;
      QByteArray publicKey;
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

      hash = crypt.decrypted(list.value(4), &ok);

      if(!ok)
	return;

      QByteArray computedHash
	(crypt.keyedHash(symmetricKey +
			 symmetricKeyAlgorithm +
			 name +
			 publicKey, &ok));

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
  m_ui.outgoingMessage->clear();
  m_ui.outgoingSubject->clear();
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
      QTableWidgetItem *item = m_ui.participants->item(row, 1);

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
  ** 3. Encrypt our information (name, public key) with the
  **    symmetric key. Call our plaintext information T.
  ** 4. Compute a keyed hash of S and T using the symmetric key.
  ** 5. Encrypt the keyed hash with the symmetric key.
  */

  QString neighborOid("");
  QByteArray publicKey;
  QByteArray symmetricKey;
  QByteArray symmetricKeyAlgorithm;

  spoton_misc::retrieveSymmetricData(publicKey,
				     symmetricKey,
				     symmetricKeyAlgorithm,
				     neighborOid,
				     oid);

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

  data.append(crypt.encrypted(myPublicKey, &ok).toBase64());
  data.append("@");

  if(!ok)
    {
      clipboard->clear();
      return;
    }

  data.append
    (crypt.encrypted(crypt.keyedHash(symmetricKey +
				     symmetricKeyAlgorithm +
				     myName +
				     myPublicKey, &ok),
		     &ok).toBase64());

  if(!ok)
    {
      clipboard->clear();
      return;
    }

  data.prepend("R");
  clipboard->setText(data);
}

Ui_spoton_mainwindow spoton::ui(void) const
{
  return m_ui;
}
