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
#include "GeoIP.h"
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

spoton::spoton(void)
{
  QDir().mkdir(spoton_misc::homePath());
  m_crypt = 0;
  m_listenersLastModificationTime = QDateTime();
  m_neighborsLastModificationTime = QDateTime();
  m_participantsLastModificationTime = QDateTime();
  ui.setupUi(this);
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
  connect(&m_generalTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotGeneralTimerTimeout(void)));
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

  str = m_settings.value("gui/cipherType").toString().toLower().trimmed();

  if(ui.cipherType->findText(str) > -1)
    ui.cipherType->setCurrentIndex(ui.cipherType->findText(str));

  str = m_settings.value("gui/hashType").toString().toLower().trimmed();

  if(ui.hashType->findText(str) > -1)
    ui.hashType->setCurrentIndex(ui.hashType->findText(str));

  ui.iterationCount->setValue(m_settings.value("gui/iterationCount", 1000).
			      toInt());
  str = m_settings.value("gui/rsaKeySize").toString().toLower().trimmed();

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
	if(ui.tab->tabBar()->tabData(i).toString() == "page_6")
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
	if(ui.tab->tabBar()->tabData(i).toString() == "page_4")
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
  ui.participants->setColumnHidden(ui.participants->columnCount() - 1, true);
  slotPopulateParticipants();
  prepareListenerIPCombo();
  show();
}

void spoton::slotQuit(void)
{
  close();
}

void spoton::slotAddListener(void)
{
  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton_database");

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
	  {
	    if(m_crypt)
	      query.bindValue
		(0, m_crypt->encrypted(QByteArray(), &ok).toBase64());
	    else
	      query.bindValue(0, QVariant());
	  }
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

	    if(m_crypt)
	      {
		if(ok)
		  query.bindValue
		    (0, m_crypt->encrypted(ip.toLatin1(), &ok).toBase64());
	      }
	    else
	      query.bindValue(0, ip);
	  }

	if(m_crypt)
	  {
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
	  }
	else
	  {
	    query.bindValue(1, port);
	    query.bindValue(2, protocol);
	    query.bindValue(3, scopeId);
	    query.bindValue(4, status);
	    query.bindValue(5, ip + port);
	  }

	if(ok)
	  if(query.exec())
	    db.commit();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton_database");
  ui.listenerIP->selectAll();
}

void spoton::slotAddNeighbor(void)
{
  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton_database");

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
		      "country) "
		      "VALUES "
		      "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");

	if(protocol == "IPv6")
	  query.bindValue(0, "::1");
	else
	  query.bindValue(0, "127.0.0.1");

	query.bindValue(1, "0");

	bool ok = true;

	query.bindValue(2, protocol);

	if(ip.isEmpty())
	  {
	    if(m_crypt)
	      query.bindValue
		(3, m_crypt->encrypted(QByteArray(), &ok).toBase64());
	    else
	      query.bindValue(3, QVariant());
	  }
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

	    if(m_crypt)
	      {
		if(ok)
		  query.bindValue
		    (3, m_crypt->encrypted(ip.toLatin1(), &ok).toBase64());
	      }
	    else
	      query.bindValue(3, ip);
	  }

	query.bindValue(5, 1); // Sticky.

	if(m_crypt)
	  {
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
	  }
	else
	  {
	    query.bindValue(4, port);
	    query.bindValue(6, scopeId);
	    query.bindValue(7, ip + port);
	  }

	query.bindValue(8, status);

	const char *country = "";

#ifdef SPOTON_LINKED_WITH_LIBGEOIP
	GeoIP *gi = 0;

	gi = GeoIP_open(SPOTON_GEOIP_DATA_FILE, GEOIP_MEMORY_CACHE);

	if(gi)
	  country = GeoIP_country_name_by_addr(gi, ip.toLatin1().constData());

	GeoIP_delete(gi);
#endif

	if(m_crypt)
	  {
	    if(ok)
	      query.bindValue
		(9, m_crypt->encrypted(QByteArray(country), &ok).toBase64());
	  }
	else
	  query.bindValue(9, QByteArray(country));

	if(ok)
	  if(query.exec())
	    db.commit();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton_database");
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
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton_database");

    db.setDatabaseName(fileInfo.absoluteFilePath());

    if(db.open())
      {
	updateListenersTable(db);

	QString ip("");
	QString port("");
	int row = -1;

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

			if(i >= 2 && i <= 5 && m_crypt)
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

			item->setTextAlignment(Qt::AlignCenter);
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

		QWidget *focusWidget = QApplication::focusWidget();

		if(m_crypt)
		  {
		    QByteArray bytes1;
		    QByteArray bytes2;
		    bool ok = true;

		    bytes1 = m_crypt->decrypted
		      (QByteArray::fromBase64(query.value(2).toByteArray()),
		       &ok);
		    bytes2 = m_crypt->decrypted
		      (QByteArray::fromBase64(query.value(3).toByteArray()),
		       &ok);

		    if(ip == bytes1 && port == bytes2)
		      ui.listeners->selectRow(row);
		  }
		else
		  {
		    if(ip == query.value(1).toString().trimmed() &&
		       port == query.value(2).toString().trimmed())
		      ui.listeners->selectRow(row);
		  }

		if(focusWidget)
		  focusWidget->setFocus();

		row += 1;
	      }
	  }

	ui.listeners->setSortingEnabled(true);
	ui.listeners->resizeColumnsToContents();
	ui.listeners->horizontalHeader()->setStretchLastSection(true);
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton_database");
}

void spoton::slotPopulateNeighbors(void)
{
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
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton_database");

    db.setDatabaseName(fileInfo.absoluteFilePath());

    if(db.open())
      {
	updateNeighborsTable(db);

	QString remoteIp("");
	QString remotePort("");
	int columnREMOTE_IP = 9;
	int columnREMOTE_PORT = 10;
	int row = -1;

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
		  check->setChecked(true);

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

		    if(i >= 7 && i <= 10 && m_crypt)
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

		    item->setTextAlignment(Qt::AlignCenter);
		    item->setFlags(Qt::ItemIsSelectable | Qt::ItemIsEnabled);

		    if(i == 2)
		      {
			if(query.value(i).toString().trimmed() == "connected")
			  item->setBackground(QBrush(QColor("lightgreen")));
			else
			  item->setBackground(QBrush());

			if(query.value(i).toString().trimmed() == "connected")
			  item->setIcon(QIcon(":/connect_established.png"));
		      }

		    ui.neighbors->setItem(row, i, item);
		  }

		QWidget *focusWidget = QApplication::focusWidget();

		if(m_crypt)
		  {
		    QByteArray bytes1;
		    QByteArray bytes2;
		    bool ok = true;

		    bytes1 = m_crypt->decrypted
		      (QByteArray::fromBase64(query.value(columnREMOTE_IP).
					      toByteArray()), &ok);
		    bytes2 = m_crypt->decrypted
		      (QByteArray::fromBase64(query.value(columnREMOTE_PORT).
					      toByteArray()), &ok);

		    if(remoteIp == bytes1 && remotePort == bytes2)
		      ui.neighbors->selectRow(row);
		  }
		else
		  {
		    if(remoteIp == query.value(columnREMOTE_IP).
		       toString().trimmed() &&
		       remotePort == query.value(columnREMOTE_PORT).
		       toString().trimmed())
		      ui.neighbors->selectRow(row);
		  }

		if(focusWidget)
		  focusWidget->setFocus();

		row += 1;
	      }
	  }

	ui.neighbors->setSortingEnabled(true);
	ui.neighbors->resizeColumnsToContents();
	ui.neighbors->horizontalHeader()->setStretchLastSection(true);
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton_database");
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

      if(ui.pid->text() != "0")
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
      m_listenersLastModificationTime = QDateTime();
      m_neighborsLastModificationTime = QDateTime();
      m_participantsLastModificationTime = QDateTime();
    }

  if(text != "0")
    if(m_kernelSocket.state() == QAbstractSocket::UnconnectedState)
      {
	{
	  QSqlDatabase db = QSqlDatabase::addDatabase
	    ("QSQLITE", "spoton_database");

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

	QSqlDatabase::removeDatabase("spoton_database");
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
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton_database");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "listeners.db");

    if(db.open())
      {
	QSqlQuery query(db);

	if(ui.pid->text() == "0")
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

  QSqlDatabase::removeDatabase("spoton_database");

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
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton_database");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "neighbors.db");

    if(db.open())
      {
	QSqlQuery query(db);

	if(ui.pid->text() == "0")
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

  QSqlDatabase::removeDatabase("spoton_database");

  if(row > -1)
    ui.neighbors->removeRow(row);
}

void spoton::slotListenerCheckChange(int state)
{
  QCheckBox *checkBox = qobject_cast<QCheckBox *> (sender());

  if(checkBox)
    {
      m_tableTimer.stop();

      {
	QSqlDatabase db = QSqlDatabase::addDatabase
	  ("QSQLITE", "spoton_database");

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

      QSqlDatabase::removeDatabase("spoton_database");
      m_tableTimer.start();
    }
}

void spoton::updateListenersTable(QSqlDatabase &db)
{
  if(ui.pid->text() == "0") // Is the kernel active?
    {
      QSqlQuery query(db);

      /*
      ** OK, so the kernel is inactive. Discover the
      ** listeners that have not been deleted and update some of their
      ** information. Only update online listeners.
      */

      query.exec("PRAGMA synchronous = OFF");
      query.exec("UPDATE listeners SET connections = 0, "
		 "status = 'off' WHERE status = 'online' AND "
		 "status_control <> 'deleted'");
      db.commit();
    }
}

void spoton::updateNeighborsTable(QSqlDatabase &db)
{
  if(ui.pid->text() == "0") // Is the kernel active?
    {
      QSqlQuery query(db);

      /*
      ** OK, so the kernel is inactive. Discover the
      ** neighbors that have not been deleted and update some of their
      ** information. Only update connected neighbors.
      */

      query.exec("PRAGMA synchronous = OFF");
      query.exec("UPDATE neighbors SET local_port = 0, "
		 "status = 'disconnected' WHERE "
		 "status = 'connected' AND status_control <> 'deleted'");
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
      return;
    }
  else if(str1 != str2)
    {
      QMessageBox::critical(this, tr("Spot-On: Error"),
			    tr("The passphrases are not equal."));
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
		 static_cast<size_t> (salt.length()), GCRY_STRONG_RANDOM);

  QByteArray derivedKey
    (spoton_gcrypt::derivedKey(ui.cipherType->currentText(),
			       ui.hashType->currentText(),
			       static_cast<unsigned long> (ui.iterationCount->
							   value()),
			       str1,
			       salt,
			       error1));
  libspoton_error_t err = LIBSPOTON_ERROR_NONE;

  if(error1.isEmpty())
    {
      if(reencode)
	{
	  statusBar()->showMessage
	    (tr("Generating RSA key pair 1 of 2. Please be patient."));
#ifdef Q_OS_MAC
	  QApplication::processEvents();
#endif
	  spoton_gcrypt::reencodePrivateKey
	    (ui.cipherType->currentText(),
	     derivedKey,
	     m_settings["gui/cipherType"].toString().trimmed(),
	     m_crypt->key(),
	     spoton_misc::homePath() + QDir::separator() +
	     "private_public_keys.db",
	     error2);

	  if(error2.isEmpty())
	    {
	      statusBar()->showMessage
		(tr("Generating RSA key pair 2 of 2. Please be patient."));
#ifdef Q_OS_MAC
	      QApplication::processEvents();
#endif
	      spoton_gcrypt::reencodePrivateKey
		(ui.cipherType->currentText(),
		 derivedKey,
		 m_settings["gui/cipherType"].toString().trimmed(),
		 m_crypt->key(),
		 spoton_misc::homePath() + QDir::separator() + "shared.db",
		 error2);
	    }
	}
      else
	{
	  QStringList list;

	  list << "private_public_keys.db"
	       << "shared.db";

	  for(int i = 0; i < list.size(); i++)
	    {
	      libspoton_handle_t libspotonHandle;

	      if((err =
		  libspoton_init((spoton_misc::homePath() +
				  QDir::separator() + list.at(i)).
				 toStdString().data(),
				 &libspotonHandle)) !=
		 LIBSPOTON_ERROR_NONE)
		goto error_label;

	      statusBar()->showMessage
		(tr("Generating RSA key pair %1 of %2. Please be patient.").
		 arg(i + 1).arg(list.size()));
#ifdef Q_OS_MAC
	      QApplication::processEvents();
#endif

	      if((err =
		  libspoton_generate_private_public_keys(derivedKey.
							 constData(),
							 ui.cipherType->
							 currentText().
							 toStdString().
							 data(),
							 ui.rsaKeySize->
							 currentText().
							 toInt(),
							 &libspotonHandle))
		 != LIBSPOTON_ERROR_NONE)
		goto error_label;

	    error_label:
	      libspoton_close(&libspotonHandle);

	      if(err != LIBSPOTON_ERROR_NONE)
		break;
	    }
	}
    }

  if(error1.isEmpty() && error2.isEmpty() && err == LIBSPOTON_ERROR_NONE)
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
			  tr("An error (%1) occurred with spoton_gcrypt::"
			     "reencodePrivateKey().").
			  arg(error2.remove(".")));
  else if(!error3.isEmpty())
    QMessageBox::critical(this, tr("Spot-On: Error"),
			  tr("An error (%1) occurred with spoton_gcrypt::"
			     "saltedPassphraseHash().").
			  arg(error3.remove(".")));
  else if(err != LIBSPOTON_ERROR_NONE)
    QMessageBox::critical(this, tr("Spot-On: Error"),
			  tr("An error (%1) occurred with libspoton.").
			  arg(libspoton_strerror(err)));
  else
    {
      if(!m_crypt || reencode)
	{
	  m_tableTimer.stop();
	  delete m_crypt;
	  m_crypt = new spoton_gcrypt
	    (ui.cipherType->currentText(),
	     ui.hashType->currentText(),
	     derivedKey,
	     ui.saltLength->value(),
	     ui.iterationCount->value(),
	     spoton_misc::homePath() + QDir::separator() +
	     "private_public_keys.db");
	  m_tableTimer.start(2500);

	  if(m_crypt)
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
      m_tableTimer.stop();
      delete m_crypt;
      m_crypt = new spoton_gcrypt
	(ui.cipherType->currentText(),
	 ui.hashType->currentText(),
	 key,
	 ui.saltLength->value(),
	 ui.iterationCount->value(),
	 spoton_misc::homePath() + QDir::separator() +
	 "private_public_keys.db");
      m_tableTimer.start(2500);

      if(m_crypt)
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
	(m_settings.value("gui/currentTabIndex", 0).toInt());
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
      m_tableTimer.stop();

      {
	QSqlDatabase db = QSqlDatabase::addDatabase
	  ("QSQLITE", "spoton_database");

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

      QSqlDatabase::removeDatabase("spoton_database");
      m_tableTimer.start();
    }
}

void spoton::slotMaximumClientsChanged(int index)
{
  QComboBox *comboBox = qobject_cast<QComboBox *> (sender());

  if(comboBox)
    {
      m_tableTimer.stop();

      {
	QSqlDatabase db = QSqlDatabase::addDatabase
	  ("QSQLITE", "spoton_database");

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

      QSqlDatabase::removeDatabase("spoton_database");
      m_tableTimer.start();
    }
}

void spoton::slotShowContextMenu(const QPoint &point)
{
  QMenu menu(this);

  if(ui.neighbors == sender())
    {
      menu.addAction(QIcon(":/add-neighbor-to-chat.png"),
		     tr("&Share Public Key"),
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
		     this, SLOT(slotUnblockNeighbor(void)));
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
  if(m_crypt && m_kernelSocket.state() == QAbstractSocket::ConnectedState)
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
  QString oid("");
  int row = -1;

  if((row = ui.neighbors->currentRow()) >= 0)
    {
      QTableWidgetItem *item = ui.neighbors->item
	(row, ui.neighbors->columnCount() - 1);

      if(item)
	oid = item->text();
    }

  m_tableTimer.stop();

  {
    QSqlDatabase db = QSqlDatabase::addDatabase
      ("QSQLITE", "spoton_database");

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

  QSqlDatabase::removeDatabase("spoton_database");
  m_tableTimer.start();
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

  m_tableTimer.stop();

  {
    QSqlDatabase db = QSqlDatabase::addDatabase
      ("QSQLITE", "spoton_database");

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

  QSqlDatabase::removeDatabase("spoton_database");
  m_tableTimer.start();
}

void spoton::slotBlockNeighbor(void)
{
}

void spoton::slotUnblockNeighbor(void)
{
}

void spoton::slotDeleteAllListeners(void)
{
  {
    QSqlDatabase db = QSqlDatabase::addDatabase
      ("QSQLITE", "spoton_database");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "listeners.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("PRAGMA synchronous = OFF");

	if(ui.pid->text() == "0")
	  query.exec("DELETE FROM listeners");
	else
	  query.exec("UPDATE listeners SET "
		     "status_control = 'deleted'");

	db.commit();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton_database");

  while(ui.listeners->rowCount() > 0)
    ui.listeners->removeRow(0);
}

void spoton::slotDeleteAllNeighbors(void)
{
  {
    QSqlDatabase db = QSqlDatabase::addDatabase
      ("QSQLITE", "spoton_database");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "neighbors.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("PRAGMA synchronous = OFF");

	if(ui.pid->text() == "0")
	  query.exec("DELETE FROM neighbors");
	else
	  query.exec("UPDATE neighbors SET "
		     "status_control = 'deleted'");

	db.commit();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton_database");

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
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton_database");

    db.setDatabaseName(fileInfo.absoluteFilePath());

    if(db.open())
      {
	QList<QTableWidgetItem *> list(ui.participants->selectedItems());
	QStringList oids;
	int row = 0;

	for(int i = 0; i < list.size(); i++)
	  {
	    QTableWidgetItem *item = ui.participants->item
	      (list.at(i)->row(), 1);

	    if(item)
	      oids.append(item->text());
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

	if(query.exec("SELECT name, OID, neighbor_oid FROM symmetric_keys"))
	  {
	    while(query.next())
	      {
		bool temporary =
		  query.value(2).toInt() == -1 ? false : true;

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
		    else
		      item = new QTableWidgetItem(query.value(i).toString().
						  trimmed());

		    item->setFlags
		      (Qt::ItemIsSelectable | Qt::ItemIsEnabled);

		    if(!temporary)
		      {
			item->setIcon
			  (QIcon(":/plist_confirmed_as_permanent_friend.png"));
			item->setToolTip(tr("%1 is a permanent friend.").
					 arg(item->text()));
		      }
		    else
		      {
			item->setIcon
			  (QIcon(":/plist_connected_neighbour.png"));
			item->setToolTip
			  (tr("%1 requests your friendship.").
			   arg(item->text()));
		      }

		    item->setData(Qt::UserRole, temporary);
		    ui.participants->setItem(row - 1, i, item);
		  }

		if(oids.contains(query.value(1).toString().trimmed()))
		  ui.participants->selectRow(row - 1);
	      }
	  }

	if(focusWidget)
	  focusWidget->setFocus();

	ui.participants->setSortingEnabled(true);
	ui.participants->resizeColumnsToContents();
	ui.participants->horizontalHeader()->setStretchLastSection(true);
	ui.participants->horizontalHeader()->setSortIndicator
	  (0, Qt::AscendingOrder);
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton_database");
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

  QList<QTableWidgetItem *> list(ui.participants->selectedItems());
  QString message("");

  message.append(tr("<b>me:</b> "));
  message.append(ui.message->toPlainText().trimmed());
  ui.messages->append(message);
  ui.messages->textCursor().movePosition(QTextCursor::End);
  ui.messages->ensureCursorVisible();

  while(!list.isEmpty())
    {
      int row = list.takeFirst()->row();
      QTableWidgetItem *item = ui.participants->item(row, 1);

      if(item)
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
	  message.append(QString("%1_").arg(item->text()));
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
		    (QString("%1: ").arg(QString::fromUtf8(name.constData(),
							   name.length())));
		  msg.append(QString::fromUtf8(message.constData(),
					       message.length()));
		  ui.messages->append(msg);
		  ui.messages->textCursor().movePosition(QTextCursor::End);
		  ui.messages->ensureCursorVisible();
		}
	    }
	}
    }
}

void spoton::slotSharePublicKey(void)
{
  if(m_kernelSocket.state() != QAbstractSocket::ConnectedState)
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
    QSqlDatabase db = QSqlDatabase::addDatabase
      ("QSQLITE", "spoton_database");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "friends_symmetric_keys.db");

    if(db.open())
      {
	m_tableTimer.stop();

	QList<QTableWidgetItem *> list(ui.participants->selectedItems());
	QSqlQuery query(db);

	query.exec("PRAGMA synchronous = OFF");

	for(int i = 0; i < list.size(); i++)
	  {
	    QTableWidgetItem *item = ui.participants->item
	      (list.at(i)->row(), 1);

	    if(item)
	      query.exec(QString("DELETE FROM symmetric_keys WHERE "
				 "OID = %1").arg(item->text()));
	  }

	db.commit();
	m_tableTimer.start();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton_database");
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
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton_database");

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

  QSqlDatabase::removeDatabase("spoton_database");

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
