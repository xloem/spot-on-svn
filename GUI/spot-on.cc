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
#include <QDir>
#include <QFileDialog>
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
#ifdef Q_OS_MAC
#include <QMacStyle>
#endif
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
  QDir().mkdir(spoton_misc::homePath());
  m_crypt = 0;
  m_countriesLastModificationTime = QDateTime();
  m_listenersLastModificationTime = QDateTime();
  m_neighborsLastModificationTime = QDateTime();
  m_participantsLastModificationTime = QDateTime();
  ui.setupUi(this);
  setWindowIcon(QIcon(":/Logo/spoton-button-64.ico"));
#ifdef Q_OS_MAC
  setAttribute(Qt::WA_MacMetalStyle, true);
#endif
  connect(ui.action_Quit,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotQuit(void)));
  connect(ui.action_Log_Viewer,
	  SIGNAL(triggered(void)),
	  this,
	  SLOT(slotViewLog(void)));
  connect(ui.addListener,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotAddListener(void)));
  connect(ui.addNeighbor,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotAddNeighbor(void)));
  connect(ui.ipv4Listener,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotProtocolRadioToggled(bool)));
  connect(ui.ipv4Neighbor,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotProtocolRadioToggled(bool)));
  connect(ui.ipv6Listener,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotProtocolRadioToggled(bool)));
  connect(ui.ipv6Neighbor,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotProtocolRadioToggled(bool)));
  connect(ui.activateKernel,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotActivateKernel(void)));
  connect(ui.deactivateKernel,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotDeactivateKernel(void)));
  connect(ui.selectKernelPath,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSelectKernelPath(void)));
  connect(ui.deleteListener,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotDeleteListener(void)));
  connect(ui.setPassphrase,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSetPassphrase(void)));
  connect(ui.kernelPath,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotSaveKernelPath(void)));
  connect(ui.passphrase,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotValidatePassphrase(void)));
  connect(ui.passphraseButton,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotValidatePassphrase(void)));
  connect(ui.tab,
	  SIGNAL(currentChanged(int)),
	  this,
	  SLOT(slotTabChanged(int)));
  connect(ui.deleteAllListeners,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotDeleteAllListeners(void)));
  connect(ui.sendMessage,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSendMessage(void)));
  connect(ui.message,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotSendMessage(void)));
  connect(ui.clearMessages,
	  SIGNAL(clicked(void)),
	  ui.messages,
	  SLOT(clear(void)));
  connect(ui.saveNodeName,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSaveNodeName(void)));
  connect(ui.nodeName,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotSaveNodeName(void)));
  connect(ui.showOnlyConnectedNeighbors,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotOnlyConnectedNeighborsToggled(bool)));
  connect(ui.showOnlyOnlineListeners,
	  SIGNAL(toggled(bool)),
	  this,
	  SLOT(slotOnlyOnlineListenersToggled(bool)));
  connect(ui.pushButtonMakeFriends,
	  SIGNAL(clicked(bool)),
	  this,
	  SLOT(slotSharePublicKey(void)));
  connect(ui.pushButtonLogViewer,
	  SIGNAL(clicked(bool)),
	  this,
	  SLOT(slotViewLog(void)));
  connect(ui.listenerIP,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotAddListener(void)));
  connect(ui.neighborIP,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotAddNeighbor(void)));
  connect(ui.listenerIPCombo,
	  SIGNAL(currentIndexChanged(int)),
	  this,
	  SLOT(slotListenerIPComboChanged(int)));
  connect(ui.chatSendMethod,
	  SIGNAL(currentIndexChanged(int)),
	  this,
	  SLOT(slotChatSendMethodChanged(int)));
  connect(ui.status,
	  SIGNAL(currentIndexChanged(int)),
	  this,
	  SLOT(slotStatusChanged(int)));
  connect(ui.pushButtonCopytoClipboard,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotCopyMyPublicKey(void)));
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
  statusBar()->showMessage(tr("Not connected to the kernel. Is the kernel "
			      "active?"));
  m_generalTimer.start(2500);
  ui.friendName->setText("unknown");
  ui.ipv4Listener->setChecked(true);
  ui.listenerIP->setInputMask("000.000.000.000; ");
  ui.listenerScopeId->setEnabled(false);
  ui.listenerScopeIdLabel->setEnabled(false);
  ui.neighborIP->setInputMask("000.000.000.000; ");
  ui.neighborScopeId->setEnabled(false);
  ui.neighborScopeIdLabel->setEnabled(false);
  ui.participants->setStyleSheet
    ("QTableView {selection-background-color: lightgreen}");

  QSettings settings;

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
    ui.kernelPath->setText(m_settings.value("gui/kernelPath").toString().
			   trimmed());
  else
    ui.kernelPath->setText(QCoreApplication::applicationDirPath() +
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
    ui.chatSendMethod->setCurrentIndex(0);
  else
    ui.chatSendMethod->setCurrentIndex(1);

  QByteArray status
    (m_settings.value("gui/my_status", "Online").toByteArray());

  if(status == "Away")
    ui.status->setCurrentIndex(0);
  else if(status == "Busy")
    ui.status->setCurrentIndex(1);
  else
    ui.status->setCurrentIndex(2);

  ui.kernelPath->setToolTip(ui.kernelPath->text());
  ui.nodeName->setMaxLength(spoton_send::NAME_MAXIMUM_LENGTH);
  ui.nodeName->setText
    (QString::fromUtf8(m_settings.value("gui/nodeName", "unknown").
		       toByteArray()).trimmed());
  ui.cipherType->clear();
  ui.cipherType->addItems(spoton_gcrypt::cipherTypes());
#if SPOTON_MINIMUM_GCRYPT_VERSION < 0x010500
  ui.iterationCount->setEnabled(false);
  ui.iterationCount->setToolTip
    (tr("The Iteration Count is disabled because "
	"gcrypt's gcry_kdf_derive() function "
	"is not available in your version of gcrypt."));
#endif
  ui.showOnlyConnectedNeighbors->setChecked
    (m_settings.value("gui/showOnlyConnectedNeighbors", false).toBool());
  ui.showOnlyOnlineListeners->setChecked
    (m_settings.value("gui/showOnlyOnlineListeners", false).toBool());

  /*
  ** Please don't translate n/a.
  */

  if(ui.cipherType->count() == 0)
    ui.cipherType->addItem("n/a");

  ui.hashType->clear();
  ui.hashType->addItems(spoton_gcrypt::hashTypes());

  if(ui.cipherType->count() == 0)
    ui.cipherType->addItem("n/a");

  QString str("");

  str = m_settings.value("gui/cipherType", "aes256").
    toString().toLower().trimmed();

  if(ui.cipherType->findText(str) > -1)
    ui.cipherType->setCurrentIndex(ui.cipherType->findText(str));

  str = m_settings.value("gui/hashType", "sha512").
    toString().toLower().trimmed();

  if(ui.hashType->findText(str) > -1)
    ui.hashType->setCurrentIndex(ui.hashType->findText(str));

  ui.iterationCount->setValue(m_settings.value("gui/iterationCount", 1000).
			      toInt());
  str = m_settings.value("gui/rsaKeySize", "3072").
    toString().toLower().trimmed();

  if(ui.rsaKeySize->findText(str) > -1)
    ui.rsaKeySize->setCurrentIndex(ui.rsaKeySize->findText(str));

  ui.saltLength->setValue(m_settings.value("gui/saltLength", 256).toInt());

  for(int i = 0; i < ui.tab->count(); i++)
    ui.tab->tabBar()->setTabData(i, QString("page_%1").arg(i + 1));

  if(spoton_gcrypt::passphraseSet())
    {
      ui.passphrase1->setText("0000000000");
      ui.passphrase2->setText("0000000000");
      ui.rsaKeySize->setEnabled(false);

      for(int i = 0; i < ui.tab->count(); i++)
	if(ui.tab->tabBar()->tabData(i).toString() == "page_7")
	  {
	    ui.tab->blockSignals(true);
	    ui.tab->setCurrentIndex(i);
	    ui.tab->blockSignals(false);
	    ui.tab->setTabEnabled(i, true);
	  }
	else
	  ui.tab->setTabEnabled(i, false);

      ui.passphrase->setFocus();
    }
  else
    {
      ui.passphrase->setEnabled(false);
      ui.passphraseButton->setEnabled(false);
      ui.passphraseLabel->setEnabled(false);
      ui.kernelBox->setEnabled(false);
      ui.listenersBox->setEnabled(false);
      ui.resetSpotOn->setEnabled(false);

      for(int i = 0; i < ui.tab->count(); i++)
	if(ui.tab->tabBar()->tabData(i).toString() == "page_5")
	  {
	    ui.tab->blockSignals(true);
	    ui.tab->setCurrentIndex(i);
	    ui.tab->blockSignals(false);
	    ui.tab->setTabEnabled(i, true);
	  }
	else
	  ui.tab->setTabEnabled(i, false);

      ui.passphrase1->setFocus();
    }

  if(m_settings.contains("gui/chatHorizontalSplitter"))
    ui.chatHorizontalSplitter->restoreState
      (m_settings.value("gui/chatHorizontalSplitter").toByteArray());

  if(m_settings.contains("gui/neighborsHorizontalSplitter"))
    ui.neighborsHorizontalSplitter->restoreState
      (m_settings.value("gui/neighborsHorizontalSplitter").toByteArray());

  if(m_settings.contains("gui/neighborsVerticalSplitter"))
    ui.neighborsVerticalSplitter->restoreState
      (m_settings.value("gui/neighborsVerticalSplitter").toByteArray());

  ui.neighbors->setContextMenuPolicy(Qt::CustomContextMenu);
  ui.participants->setContextMenuPolicy(Qt::CustomContextMenu);
  connect(ui.neighbors,
	  SIGNAL(customContextMenuRequested(const QPoint &)),
	  this,
	  SLOT(slotShowContextMenu(const QPoint &)));
  connect(ui.participants,
	  SIGNAL(customContextMenuRequested(const QPoint &)),
	  this,
	  SLOT(slotShowContextMenu(const QPoint &)));
  ui.listeners->setColumnHidden(ui.listeners->columnCount() - 1,
				true);
  ui.neighbors->setColumnHidden(ui.neighbors->columnCount() - 1, true);
  ui.participants->setColumnHidden(ui.participants->columnCount() - 2, true);
  ui.participants->setColumnHidden(ui.participants->columnCount() - 3, true);
  ui.participants->setColumnHidden(ui.participants->columnCount() - 4, true);
  ui.participants->horizontalHeader()->setSortIndicator
    (0, Qt::AscendingOrder);
  prepareListenerIPCombo();
  spoton_misc::prepareDatabases();

  /*
  ** Not wise! We may find things we're not prepared for.
  */

  foreach(QAbstractButton *button,
	  ui.participants->findChildren<QAbstractButton *> ())
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

	if(ui.listenerIPCombo->currentIndex() == 0)
	  ip = ui.listenerIP->text().trimmed();
	else
	  ip = ui.listenerIPCombo->currentText();

	QString port(QString::number(ui.listenerPort->value()));
	QString protocol("");
	QString scopeId(ui.listenerScopeId->text().trimmed());
	QString status("online");
	QSqlQuery query(db);

	if(ui.ipv4Listener->isChecked())
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
		if(ui.listenerIPCombo->currentIndex() == 0)
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
	  if(query.exec())
	    db.commit();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton");
  ui.listenerIP->selectAll();
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

	QString ip(ui.neighborIP->text().trimmed());
	QString port(QString::number(ui.neighborPort->value()));
	QString protocol("");
	QString scopeId(ui.neighborScopeId->text().trimmed());
	QString status("connected");
	QSqlQuery query(db);

	if(ui.ipv4Neighbor->isChecked())
	  protocol = "IPv4";
	else if(ui.ipv6Neighbor->isChecked())
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
	  if(query.exec())
	    db.commit();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton");
  ui.neighborIP->selectAll();
}

void spoton::slotProtocolRadioToggled(bool state)
{
  Q_UNUSED(state);

  QRadioButton *radio = qobject_cast<QRadioButton *> (sender());

  if(!radio)
    return;

  if(radio == ui.ipv4Listener || radio == ui.ipv4Neighbor)
    {
      if(radio == ui.ipv4Listener)
	{
	  ui.listenerIP->setInputMask("000.000.000.000; ");
	  ui.listenerScopeId->setEnabled(false);
	  ui.listenerScopeIdLabel->setEnabled(false);
	}
      else
	{
	  ui.neighborIP->clear();
	  ui.neighborIP->setInputMask("000.000.000.000; ");
	  ui.neighborScopeId->setEnabled(false);
	  ui.neighborScopeIdLabel->setEnabled(false);
	}
    }
  else 
    {
      if(radio == ui.ipv6Listener)
	{
	  ui.listenerIP->setInputMask
	    ("HHHH:HHHH:HHHH:HHHH:HHHH:HHHH:HHHH:HHHH; ");
	  ui.listenerScopeId->setEnabled(true);
	  ui.listenerScopeIdLabel->setEnabled(true);
	}
      else
	{
	  ui.neighborIP->clear();
	  ui.neighborIP->setInputMask
	    ("HHHH:HHHH:HHHH:HHHH:HHHH:HHHH:HHHH:HHHH; ");
	  ui.neighborScopeId->setEnabled(true);
	  ui.neighborScopeIdLabel->setEnabled(true);
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
	int hval = ui.listeners->horizontalScrollBar()->value();
	int row = -1;
	int vval = ui.listeners->verticalScrollBar()->value();

	if((row = ui.listeners->currentRow()) >= 0)
	  {
	    QTableWidgetItem *item = ui.listeners->item(row, 2);

	    if(item)
	      ip = item->text();

	    if((item = ui.listeners->item(row, 3)))
	      port = item->text();
	  }

	ui.listeners->setSortingEnabled(false);
	ui.listeners->clearContents();
	ui.listeners->setRowCount(0);

	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec(QString("SELECT "
			      "status_control, status, "
			      "ip_address, port, scope_id, protocol, "
			      "external_ip_address, external_port, "
			      "connections, maximum_clients, OID "
			      "FROM listeners WHERE "
			      "status_control <> 'deleted' %1").
		      arg(ui.showOnlyOnlineListeners->isChecked() ?
			  "AND status = 'online'" : "")))
	  {
	    row = 0;

	    while(query.next())
	      {
		QCheckBox *check = 0;
		QComboBox *box = 0;
		QTableWidgetItem *item = 0;

		ui.listeners->setRowCount(row + 1);

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
			ui.listeners->setCellWidget(row, i, check);
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
			ui.listeners->setCellWidget(row, i, box);

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
			ui.listeners->setItem(row, i, item);

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
		  ui.listeners->selectRow(row);

		if(focusWidget)
		  focusWidget->setFocus();

		row += 1;
	      }
	  }

	ui.listeners->setSortingEnabled(true);
	ui.listeners->resizeColumnsToContents();
	ui.listeners->horizontalHeader()->setStretchLastSection(true);
	ui.listeners->horizontalScrollBar()->setValue(hval);
	ui.listeners->verticalScrollBar()->setValue(vval);
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
	int hval = ui.neighbors->horizontalScrollBar()->value();
	int row = -1;
	int vval = ui.neighbors->verticalScrollBar()->value();

	if((row = ui.neighbors->currentRow()) >= 0)
	  {
	    QTableWidgetItem *item = ui.neighbors->item
	      (row, columnREMOTE_IP);

	    if(item)
	      remoteIp = item->text();

	    if((item = ui.neighbors->item(row, columnREMOTE_PORT)))
	      remotePort = item->text();
	  }

	ui.neighbors->setSortingEnabled(false);
	ui.neighbors->clearContents();
	ui.neighbors->setRowCount(0);

	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec(QString("SELECT sticky, uuid, status, "
			      "local_ip_address, local_port, "
			      "external_ip_address, external_port, "
			      "country, "
			      "remote_ip_address, "
			      "remote_port, scope_id, protocol, OID "
			      "FROM neighbors WHERE "
			      "status_control <> 'deleted' %1").
		      arg(ui.showOnlyConnectedNeighbors->isChecked() ?
			  "AND status = 'connected'" : "")))
	  {
	    QString localIp("");
	    QString localPort("");

	    row = 0;

	    while(query.next())
	      {
		ui.neighbors->setRowCount(row + 1);

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
		ui.neighbors->setCellWidget(row, 0, check);

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

		    ui.neighbors->setItem(row, i, item);
		  }

		QTableWidgetItem *item1 = ui.neighbors->item(row, 7);

		if(item1)
		  {
		    QTableWidgetItem *item2 = ui.neighbors->item(row, 8);

		    if(item2)
		      {
			item1->setIcon
			  (QIcon(QString(":/Flags/%1.png").
				 arg(spoton_misc::
				     countryCodeFromIPAddress(item2->text()).
				     toLower())));
		      }
		    else
		      item1->setIcon(QIcon(":/Flags/unknown.png"));
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
		  ui.neighbors->selectRow(row);

		if(focusWidget)
		  focusWidget->setFocus();

		row += 1;
	      }
	  }

	ui.neighbors->setSortingEnabled(true);

	for(int i = 0; i < ui.neighbors->columnCount(); i++)
	  ui.neighbors->horizontalHeaderItem(i)->
	    setTextAlignment(Qt::AlignLeft | Qt::AlignVCenter);

	ui.neighbors->horizontalHeader()->setStretchLastSection(true);
	ui.neighbors->horizontalScrollBar()->setValue(hval);
	ui.neighbors->verticalScrollBar()->setValue(vval);
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton");
}

void spoton::slotActivateKernel(void)
{
  QString program(ui.kernelPath->text());

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
  QPalette pidPalette(ui.pid->palette());
  QString sharedPath(spoton_misc::homePath() + QDir::separator() +
		     "shared.db");
  QString text(ui.pid->text());
  libspoton_handle_t libspotonHandle;

  pidPalette.setColor(ui.pid->backgroundRole(), color);

  if(libspoton_init(sharedPath.toStdString().c_str(),
		    &libspotonHandle) == LIBSPOTON_ERROR_NONE)
    {
      ui.pid->setText
	(QString::number(libspoton_registered_kernel_pid(&libspotonHandle)));

      if(isKernelActive())
	{
	  QColor color(144, 238, 144); // Light green!
	  QPalette palette(ui.pid->palette());

	  palette.setColor(ui.pid->backgroundRole(), color);
	  ui.pid->setPalette(palette);
	}
      else
	ui.pid->setPalette(pidPalette);
    }
  else
    ui.pid->setPalette(pidPalette);

  libspoton_close(&libspotonHandle);
  highlightKernelPath();

  if(text != ui.pid->text())
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
  saveKernelPath(ui.kernelPath->text().trimmed());
}

void spoton::saveKernelPath(const QString &path)
{
  if(!path.isEmpty())
    {
      m_settings["gui/kernelPath"] = path;

      QSettings settings;
      
      settings.setValue("gui/kernelPath", path);
      ui.kernelPath->setText(path);
      ui.kernelPath->setToolTip(path);
      ui.kernelPath->selectAll();
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
		    ui.chatHorizontalSplitter->saveState());
  settings.setValue("gui/currentTabIndex", ui.tab->currentIndex());
  settings.setValue("gui/neighborsHorizontalSplitter",
		    ui.neighborsHorizontalSplitter->saveState());
  settings.setValue("gui/neighborsVerticalSplitter",
		    ui.neighborsVerticalSplitter->saveState());
  settings.setValue("gui/showOnlyConnectedNeighbors",
		    ui.showOnlyConnectedNeighbors->isChecked());
  settings.setValue("gui/showOnlyOnlineListeners",
		    ui.showOnlyOnlineListeners->isChecked());
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

  if((row = ui.listeners->currentRow()) >= 0)
    {
      QTableWidgetItem *item = ui.listeners->item
	(row, ui.listeners->columnCount() - 1);

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
	db.commit();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton");

  if(row > -1)
    ui.listeners->removeRow(row);
}

void spoton::slotDeleteNeighbor(void)
{
  QString oid("");
  int row = -1;

  if((row = ui.neighbors->currentRow()) >= 0)
    {
      QTableWidgetItem *item = ui.neighbors->item
	(row, ui.neighbors->columnCount() - 1);

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
	db.commit();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton");

  if(row > -1)
    ui.neighbors->removeRow(row);
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
	    db.commit();
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
      db.commit();
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
      db.commit();
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
      db.commit();
    }
}

void spoton::slotSetPassphrase(void)
{
  bool reencode = false;
  QString str1(ui.passphrase1->text());
  QString str2(ui.passphrase2->text());

  if(str1.length() < 16 || str2.length() < 16)
    {
      QMessageBox::critical(this, tr("Spot-On: Error"),
			    tr("The passphrases must contain at least "
			       "sixteen characters each."));
      ui.passphrase1->setFocus();
      return;
    }
  else if(str1 != str2)
    {
      QMessageBox::critical(this, tr("Spot-On: Error"),
			    tr("The passphrases are not equal."));
      ui.passphrase1->setFocus();
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
		    "existing passphrase?"));

      if(mb.exec() != QMessageBox::Yes)
	return;
      else
	reencode = true;
    }

  QString lastStatusBarMessage(statusBar()->currentMessage());

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

  salt.resize(ui.saltLength->value());
  gcry_randomize(static_cast<void *> (salt.data()),
		 static_cast<size_t> (salt.length()),
		 GCRY_STRONG_RANDOM);

  QByteArray derivedKey
    (spoton_gcrypt::derivedKey(ui.cipherType->currentText(),
			       ui.hashType->currentText(),
			       static_cast<unsigned long> (ui.iterationCount->
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
#ifdef Q_OS_MAC
	  QApplication::processEvents();
#endif
	  spoton_gcrypt::reencodePrivateKey
	    (ui.cipherType->currentText(),
	     derivedKey,
	     m_settings.value("gui/cipherType", "aes256").toString().trimmed(),
	     m_crypt->key(),
	     "private",
	     error2);

	  if(error2.isEmpty())
	    {
	      statusBar()->showMessage
		(tr("Re-encoding RSA key pair 2 of 2. Please be patient."));
#ifdef Q_OS_MAC
	      QApplication::processEvents();
#endif
	      spoton_gcrypt::reencodePrivateKey
		(ui.cipherType->currentText(),
		 derivedKey,
		 m_settings.value("gui/cipherType", "aes256").
		 toString().trimmed(),
		 m_crypt->key(),
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
#ifdef Q_OS_MAC
	      QApplication::processEvents();
#endif
	      spoton_gcrypt *g = new spoton_gcrypt
		(ui.cipherType->currentText(),
		 ui.hashType->currentText(),
		 derivedKey,
		 ui.saltLength->value(),
		 ui.iterationCount->value(),
		 list.at(i));

	      g->generatePrivatePublicKeys
		(ui.rsaKeySize->currentText().toInt(), error2);
	      delete g;

	      if(!error2.isEmpty())
		break;
	    }
	}
    }

  if(error1.isEmpty() && error2.isEmpty())
    saltedPassphraseHash = spoton_gcrypt::saltedPassphraseHash
      (ui.hashType->currentText(), str1, salt, error3);

  statusBar()->showMessage(lastStatusBarMessage);

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
	  delete m_crypt;
	  m_crypt = new spoton_gcrypt
	    (ui.cipherType->currentText(),
	     ui.hashType->currentText(),
	     derivedKey,
	     ui.saltLength->value(),
	     ui.iterationCount->value(),
	     "private");

	  QString lastStatusBarMessage(statusBar()->currentMessage());

	  statusBar()->showMessage
	    (tr("Initializing country_inclusion.db."));
#ifdef Q_OS_MAC
	  QApplication::processEvents();
#endif
	  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
	  spoton_misc::populateCountryDatabase(m_crypt);
	  QApplication::restoreOverrideCursor();
	  statusBar()->showMessage(lastStatusBarMessage);
	  m_tableTimer.start(2500);
	  sendKeyToKernel();
	}

      ui.kernelBox->setEnabled(true);
      ui.listenersBox->setEnabled(true);
      ui.passphrase1->setText("0000000000");
      ui.passphrase2->setText("0000000000");
      ui.rsaKeySize->setEnabled(false);

      for(int i = 0; i < ui.tab->count(); i++)
	ui.tab->setTabEnabled(i, true);

      /*
      ** Save the various entities.
      */

      m_settings["gui/cipherType"] = ui.cipherType->currentText();
      m_settings["gui/hashType"] = ui.hashType->currentText();
      m_settings["gui/iterationCount"] = ui.iterationCount->value();
      m_settings["gui/rsaKeySize"] = ui.rsaKeySize->currentText().toInt();
      m_settings["gui/salt"] = salt.toHex();
      m_settings["gui/saltLength"] = ui.saltLength->value();
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
     spoton_gcrypt::saltedPassphraseHash(ui.hashType->currentText(),
					 ui.passphrase->text(),
					 salt, error).toHex())
    {
      QByteArray key;
      QString error("");

      key = spoton_gcrypt::derivedKey
	(ui.cipherType->currentText(),
	 ui.hashType->currentText(),
	 static_cast<unsigned long> (ui.iterationCount->value()),
	 ui.passphrase->text(),
	 salt,
	 error);
      delete m_crypt;
      m_crypt = new spoton_gcrypt
	(ui.cipherType->currentText(),
	 ui.hashType->currentText(),
	 key,
	 ui.saltLength->value(),
	 ui.iterationCount->value(),
	 "private");

      QString lastStatusBarMessage(statusBar()->currentMessage());

      statusBar()->showMessage
	(tr("Initializing country_inclusion.db."));
#ifdef Q_OS_MAC
      QApplication::processEvents();
#endif
      QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
      spoton_misc::populateCountryDatabase(m_crypt);
      QApplication::restoreOverrideCursor();
      statusBar()->showMessage(lastStatusBarMessage);
      spoton_misc::populateCountryDatabase(m_crypt);
      m_tableTimer.start(2500);
      sendKeyToKernel();
      ui.kernelBox->setEnabled(true);
      ui.listenersBox->setEnabled(true);
      ui.passphrase->clear();
      ui.passphrase->setEnabled(false);
      ui.passphraseButton->setEnabled(false);
      ui.passphraseLabel->setEnabled(false);
      ui.rsaKeySize->setEnabled(false);

      for(int i = 0; i < ui.tab->count(); i++)
	ui.tab->setTabEnabled(i, true);

      ui.tab->setCurrentIndex
	(m_settings.value("gui/currentTabIndex", ui.tab->count() - 1).
	 toInt());
    }
  else
    {
      ui.passphrase->clear();
      ui.passphrase->setFocus();
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
	    db.commit();
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
	    db.commit();
	  }

	db.close();
      }

      QSqlDatabase::removeDatabase("spoton");
    }
}

void spoton::slotShowContextMenu(const QPoint &point)
{
  QMenu menu(this);

  if(ui.neighbors == sender())
    {
      menu.addAction(QIcon(":/add-neighbor-to-chat.png"),
		     tr("&Share my Public Key"),
		     this, SLOT(slotSharePublicKey(void)));
      menu.addSeparator();
      menu.addAction(QIcon(":/connect.png"), tr("&Connect"),
		     this, SLOT(slotConnectNeighbor(void)));
      menu.addAction(tr("&Disconnect"),
		     this, SLOT(slotDisconnectNeighbor(void)));
      menu.addSeparator();
      menu.addAction(tr("&Delete"),
		     this, SLOT(slotDeleteNeighbor(void)));
      menu.addAction(tr("Delete &All"),
		     this, SLOT(slotDeleteAllNeighbors(void)));
      menu.addSeparator();
      menu.addAction(tr("&Block"),
		     this, SLOT(slotBlockNeighbor(void)));
      menu.addAction(tr("&Unblock"),
		     this, SLOT(slotDisconnectNeighbor(void)));
      menu.exec(ui.neighbors->mapToGlobal(point));
    }
  else
    {
      QAction *action = menu.addAction
	(QIcon(":/plist_confirmed_as_permanent_friend.png"),
	 tr("&Add participant as friend."),
	 this, SLOT(slotSharePublicKeyWithParticipant(void)));
      QTableWidgetItem *item = ui.participants->itemAt(point);

      if(item && item->data(Qt::UserRole).toBool()) // Temporary friend?
	action->setEnabled(true);
      else
	action->setEnabled(false);

      menu.addAction(QIcon(":/delete.png"), tr("&Remove"), this, 
		     SLOT(slotRemoveParticipants(void)));
      menu.exec(ui.participants->mapToGlobal(point));
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
	QByteArray key(m_crypt->key(), m_crypt->keyLength());

	key = key.toBase64();
	key.prepend("key_");
	key.append('\n');

	if(m_kernelSocket.write(key.constData(), key.length()) != key.length())
	  spoton_misc::logError
	    ("spoton::sendKeyToKernel(): write() failure.");
	else
	  m_kernelSocket.flush();
      }
}

void spoton::slotConnectNeighbor(void)
{
    {
     if(!isKernelActive())
   return slotActivateKernel();
    }

  QString oid("");
  int row = -1;

  if((row = ui.neighbors->currentRow()) >= 0)
    {
      QTableWidgetItem *item = ui.neighbors->item
	(row, ui.neighbors->columnCount() - 1);

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
	db.commit();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton");
}

void spoton::slotDisconnectNeighbor(void)
{
  QString oid("");
  int row = -1;

  if((row = ui.neighbors->currentRow()) >= 0)
    {
      QTableWidgetItem *item = ui.neighbors->item
	(row, ui.neighbors->columnCount() - 1);

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
	db.commit();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton");
}

void spoton::slotBlockNeighbor(void)
{
  QString oid("");
  int row = -1;

  if((row = ui.neighbors->currentRow()) >= 0)
    {
      QTableWidgetItem *item = ui.neighbors->item
	(row, ui.neighbors->columnCount() - 1);

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
	db.commit();
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

	query.exec("PRAGMA synchronous = OFF");

	if(!isKernelActive())
	  query.exec("DELETE FROM listeners");
	else
	  query.exec("UPDATE listeners SET "
		     "status_control = 'deleted'");

	db.commit();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton");

  while(ui.listeners->rowCount() > 0)
    ui.listeners->removeRow(0);
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

	query.exec("PRAGMA synchronous = OFF");

	if(!isKernelActive())
	  query.exec("DELETE FROM neighbors");
	else
	  query.exec("UPDATE neighbors SET "
		     "status_control = 'deleted'");

	db.commit();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton");

  while(ui.neighbors->rowCount() > 0)
    ui.neighbors->removeRow(0);
}

void spoton::slotPopulateParticipants(void)
{
  QFileInfo fileInfo(spoton_misc::homePath() + QDir::separator() +
		     "friends_symmetric_keys.db");

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
	  (ui.participants->selectionModel()->selectedRows(3));
	QStringList hashes;
	int hval = ui.participants->horizontalScrollBar()->value();
	int row = 0;
	int vval = ui.participants->verticalScrollBar()->value();

	while(!list.isEmpty())
	  {
	    QVariant data(list.takeFirst().data());

	    if(!data.isNull() && data.isValid())
	      hashes.append(data.toString());
	  }

	ui.participants->setSortingEnabled(false);
	ui.participants->clearContents();
	ui.participants->setRowCount(0);

	QSqlQuery query(db);
	QWidget *focusWidget = QApplication::focusWidget();

	query.setForwardOnly(true);

	/*
	** We only wish to display other public keys.
	*/

	if(query.exec("SELECT name, OID, neighbor_oid, public_key_hash, "
		      "status FROM symmetric_keys"))
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
		      ui.participants->setRowCount(row);
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
		  ui.participants->setItem(row - 1, i, item);
		}

	      if(hashes.contains(query.value(3).toString().trimmed()))
		rows.append(row - 1);
	    }

	if(focusWidget)
	  focusWidget->setFocus();

	ui.participants->setSelectionMode(QAbstractItemView::MultiSelection);

	while(!rows.isEmpty())
	  ui.participants->selectRow(rows.takeFirst());

	ui.participants->setSelectionMode
	  (QAbstractItemView::ExtendedSelection);
	ui.participants->setSortingEnabled(true);
	ui.participants->resizeColumnsToContents();
	ui.participants->horizontalHeader()->setStretchLastSection(true);
	ui.participants->horizontalScrollBar()->setValue(hval);
	ui.participants->verticalScrollBar()->setValue(vval);
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton");
}

void spoton::slotSendMessage(void)
{
  if(m_kernelSocket.state() != QAbstractSocket::ConnectedState)
    return;
  else if(ui.message->toPlainText().trimmed().isEmpty())
    return;

  if(!ui.participants->selectionModel()->hasSelection())
    /*
    ** We need at least one participant.
    */

    return;

  QModelIndexList list(ui.participants->selectionModel()->selectedRows(1));
  QString message("");

  message.append
    (QDateTime::currentDateTime().
     toString("[hh:mm<font color=grey>:ss</font>] "));
  message.append(tr("<b>me:</b> "));
  message.append(ui.message->toPlainText().trimmed());
  ui.messages->append(message);
  ui.messages->verticalScrollBar()->setValue
    (ui.messages->verticalScrollBar()->maximum());

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
	  message.append(ui.message->toPlainText().trimmed().toUtf8().
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

  ui.message->clear();
}

void spoton::slotReceivedKernelMessage(void)
{
  m_kernelSocketData.append(m_kernelSocket.readAll());

  if(m_kernelSocketData.endsWith('\n'))
    {
      QList<QByteArray> list(m_kernelSocketData.split('\n'));

      m_kernelSocketData.clear();

      while(!list.isEmpty())
	{
	  QByteArray data(list.takeFirst());

	  if(data.startsWith("message_"))
	    {
	      data = data.trimmed();
	      data.remove(0, strlen("message_"));

	      if(!data.isEmpty())
		{
		  data = QByteArray::fromBase64(data);

		  QByteArray name
		    (data.mid(0, spoton_send::NAME_MAXIMUM_LENGTH));
		  QByteArray message
		    (data.mid(spoton_send::NAME_MAXIMUM_LENGTH).trimmed());
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
		  ui.messages->append(msg);
		  ui.messages->verticalScrollBar()->setValue
		    (ui.messages->verticalScrollBar()->maximum());
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

  if((row = ui.neighbors->currentRow()) >= 0)
    {
      QTableWidgetItem *item = ui.neighbors->item
	(row, ui.neighbors->columnCount() - 1);

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
  if(!ui.participants->selectionModel()->hasSelection())
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
		       "friends_symmetric_keys.db");

    if(db.open())
      {
	QModelIndexList list
	  (ui.participants->selectionModel()->selectedRows(1));
	QSqlQuery query(db);

	query.exec("PRAGMA synchronous = OFF");

	while(!list.isEmpty())
	  {
	    QVariant data(list.takeFirst().data());

	    if(!data.isNull() && data.isValid())
	      query.exec(QString("DELETE FROM symmetric_keys WHERE "
				 "OID = %1").arg(data.toString()));
	  }

	db.commit();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton");
}

void spoton::slotSaveNodeName(void)
{
  m_settings["gui/nodeName"] = ui.nodeName->text().trimmed().
    toUtf8();

  QSettings settings;

  settings.setValue("gui/nodeName", ui.nodeName->text().trimmed().toUtf8());
  ui.nodeName->selectAll();
}

void spoton::highlightKernelPath(void)
{
  QColor color;
  QFileInfo fileInfo(ui.kernelPath->text());
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

  palette.setColor(ui.kernelPath->backgroundRole(), color);
  ui.kernelPath->setPalette(palette);
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
  ui.listenerIPCombo->clear();

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

	  if(ui.ipv4Listener->isChecked())
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
      ui.listenerIPCombo->addItem(tr("Custom"));
      ui.listenerIPCombo->insertSeparator(1);
      ui.listenerIPCombo->addItems(list);
    }
  else
    ui.listenerIPCombo->addItem(tr("Custom"));
}

void spoton::slotListenerIPComboChanged(int index)
{
  /*
  ** Method will be called because of activity in prepareListenerIPCombo().
  */

  if(index == 0)
    {
      ui.listenerIP->clear();
      ui.listenerScopeId->clear();
      ui.listenerIP->setVisible(true);
    }
  else
    ui.listenerIP->setVisible(false);
}

void spoton::slotChatSendMethodChanged(int index)
{
  if(index == 0)
    m_settings["gui/chatSendMethod"] = "Artificial_GET";
  else
    m_settings["gui/chatSendMethod"] = "Normal_POST";

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

  if((row = ui.participants->currentRow()) >= 0)
    {
      QTableWidgetItem *item = ui.participants->item(row, 1);

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    return;

  QString neighborOid("");
  QByteArray publicKey;
  QByteArray symmetricKey;
  QByteArray symmetricKeyAlgorithm;

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "friends_symmetric_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec(QString("SELECT neighbor_oid, "
			      "public_key, symmetric_key, "
			      "symmetric_key_algorithm "
			      "FROM symmetric_keys WHERE "
			      "OID = %1").arg(oid)))
	  if(query.next())
	    {
	      bool ok = true;

	      neighborOid = query.value(0).toString();
	      publicKey = query.value(1).toByteArray();
	      symmetricKey = m_crypt->decrypted
		(QByteArray::fromBase64(query.value(2).toByteArray()),
		 &ok);

	      if(ok)
		symmetricKeyAlgorithm = m_crypt->decrypted
		  (QByteArray::fromBase64(query.value(3).toByteArray()),
		   &ok);
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton");

  if(publicKey.isEmpty() ||
     symmetricKey.isEmpty() || symmetricKeyAlgorithm.isEmpty())
    {
      spoton_misc::logError("spoton::slotSharePublicKeyWithParticipant(): "
			    "publicKey, or symmetricKey, or "
			    "symmetricKeyAlgorithm is empty.");
      return;
    }

  QByteArray message;

  message.append("befriendparticipant_");
  message.append(neighborOid);
  message.append("_");
  message.append(publicKey.toBase64());
  message.append("_");
  message.append(symmetricKey.toBase64());
  message.append("_");
  message.append(symmetricKeyAlgorithm.toBase64());
  message.append('\n');

  if(m_kernelSocket.write(message.constData(), message.length()) !=
     message.length())
    spoton_misc::logError
      ("spoton::slotSharePublicKeyWithParticipant(): "
       "write() failure.");
  else
    m_kernelSocket.flush();
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
  return ui.pid->text() != "0";
}

void spoton::slotCopyMyPublicKey(void)
{
  if(!m_crypt)
    return;

  QClipboard *clipboard = QApplication::clipboard();

  if(!clipboard)
    return;

  QByteArray publicKey;
  bool ok = true;

  publicKey = m_crypt->publicKey(&ok);

  if(ok)
    clipboard->setText(publicKey.constData());
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

	if(query.exec("SELECT country, accepted FROM country_inclusion"))
	  {
	    QList<QListWidgetItem *> list(ui.countries->selectedItems());
	    QString selectedCountry("");
	    int hval = ui.countries->horizontalScrollBar()->value();
	    int vval = ui.countries->verticalScrollBar()->value();

	    if(!list.isEmpty())
	      selectedCountry = list.at(0)->text();

	    ui.countries->clear();

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
	    disconnect(ui.countries,
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

		item->setIcon(icon);
		ui.countries->addItem(item);

		if(!selectedCountry.isEmpty())
		  if(item->text() == selectedCountry)
		    selected = item;
	      }

	    if(selected)
	      selected->setSelected(true);

	    ui.countries->horizontalScrollBar()->setValue(hval);
	    ui.countries->verticalScrollBar()->setValue(vval);
	    connect(ui.countries,
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
	  if((ok = query.exec()))
	    db.commit();
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
	      if(query.exec())
		db.commit();
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

void spoton::slotConnectOnlyToStickies(void)
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
}

void spoton::slotDoSearch(void)
{
}

void spoton::slotDisplayLocalSearchResults(void)

{
}

void spoton::slotResetAll(void)

{
}
