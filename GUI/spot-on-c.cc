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

#include <QCheckBox>
#if QT_VERSION < 0x050000
#include <QDesktopServices>
#endif
#include <QPlainTextEdit>
#include <QProgressBar>
#if QT_VERSION >= 0x050000
#include <QStandardPaths>
#endif
#include <QTableWidgetItem>

#include "spot-on.h"

void spoton::slotGenerateEtpKeys(int index)
{
  if(m_ui.pairRadio->isChecked())
    {
      if(index == 0)
	{
	  m_ui.etpCipherType->setCurrentIndex(0);
	  m_ui.etpEncryptionKey->clear();
	  m_ui.etpHashType->setCurrentIndex(0);
	  m_ui.etpMacKey->clear();
	}
      else if(index == 1)
	{
	  m_ui.etpEncryptionKey->setText
	    (spoton_crypt::
	     strongRandomBytes(m_ui.etpEncryptionKey->maxLength()).
	     toBase64());
	  m_ui.etpMacKey->setText
	    (spoton_crypt::
	     strongRandomBytes(m_ui.etpMacKey->maxLength()).
	     toBase64());
	}
      else if(index == 2)
	m_ui.etpEncryptionKey->setText
	  (spoton_crypt::
	   strongRandomBytes(m_ui.etpEncryptionKey->maxLength()).
	   toBase64());
      else if(index == 3)
	m_ui.etpMacKey->setText
	  (spoton_crypt::
	   strongRandomBytes(m_ui.etpMacKey->maxLength()).
	   toBase64());

      disconnect(m_ui.generate,
		 SIGNAL(activated(int)),
		 this,
		 SLOT(slotGenerateEtpKeys(int)));
      m_ui.generate->setCurrentIndex(0);
      connect(m_ui.generate,
	      SIGNAL(activated(int)),
	      this,
	      SLOT(slotGenerateEtpKeys(int)));
    }
}

void spoton::slotAddEtpMagnet(void)
{
  QString connectionName("");
  QString error("");
  QString magnet("");
  QStringList list;
  bool ok = true;
  spoton_crypt *s_crypt = m_crypts.value("chat", 0);

  if(!s_crypt)
    {
      error = tr("Invalid spoton_crypt object. This is a fatal flaw.");
      goto done_label;
    }

  if(m_ui.magnetRadio->isChecked())
    magnet = m_ui.etpMagnet->toPlainText().trimmed();
  else
    magnet = QString("magnet:?"
		     "ct=%1&"
		     "ek=%2&"
		     "ht=%3&"
		     "mk=%4&"
		     "xt=urn:starbeam").
      arg(m_ui.etpCipherType->currentText()).
      arg(m_ui.etpEncryptionKey->text().trimmed()).
      arg(m_ui.etpHashType->currentText()).
      arg(m_ui.etpMacKey->text().trimmed());

  /*
  ** Validate the magnet.
  */

  if(!spoton_misc::isValidStarBeamMagnet(magnet.toLatin1()))
    {
      error = tr("Invalid magnet. Are you missing tokens?");
      goto done_label;
    }

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "starbeam.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.prepare("INSERT OR REPLACE INTO "
		      "magnets (magnet, magnet_hash) "
		      "VALUES (?, ?)");
	query.bindValue(0, s_crypt->encrypted(magnet.toLatin1(),
					      &ok).toBase64());

	if(ok)
	  query.bindValue(1, s_crypt->keyedHash(magnet.toLatin1(),
						&ok).toBase64());

	if(ok)
	  ok = query.exec();
      }
    else
      ok = false;

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(!ok)
    error = tr("A database error occurred.");
  else
    {
      m_ui.etpCipherType->setCurrentIndex(0);
      m_ui.etpEncryptionKey->clear();
      m_ui.etpHashType->setCurrentIndex(0);
      m_ui.etpMacKey->clear();
      m_ui.etpMagnet->clear();
    }

 done_label:

  if(!error.isEmpty())
    QMessageBox::critical(this, tr("Spot-On: Error"), error);
  else
    askKernelToReadStarBeamKeys();
}

void spoton::slotPopulateEtpMagnets(void)
{
  spoton_crypt *s_crypt = m_crypts.value("chat", 0);

  if(!s_crypt)
    return;

  QFileInfo fileInfo(spoton_misc::homePath() + QDir::separator() +
		     "starbeam.db");

  if(fileInfo.exists())
    {
      if(fileInfo.lastModified() <= m_magnetsLastModificationTime)
	return;
      else
	m_magnetsLastModificationTime = fileInfo.lastModified();
    }
  else
    m_magnetsLastModificationTime = QDateTime();

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(fileInfo.absoluteFilePath());

    if(db.open())
      {
	QSqlQuery query(db);
	QStringList checked;
	QWidget *focusWidget = QApplication::focusWidget();

	for(int i = 0; i < m_ui.addTransmittedMagnets->rowCount(); i++)
	  {
	    QCheckBox *checkBox = qobject_cast<QCheckBox *>
	      (m_ui.addTransmittedMagnets->cellWidget(i, 0));

	    if(checkBox && checkBox->isChecked())
	      checked.append(checkBox->text());
	  }

	m_ui.etpMagnets->setSortingEnabled(false);
	m_ui.etpMagnets->clearContents();
	m_ui.etpMagnets->setRowCount(0);
	m_ui.addTransmittedMagnets->setSortingEnabled(false);
	m_ui.addTransmittedMagnets->clearContents();
	m_ui.addTransmittedMagnets->setRowCount(0);
	query.setForwardOnly(true);

	if(query.exec("SELECT magnet, one_time_magnet, "
		      "OID FROM magnets"))
	  {
	    int row = 0;

	    while(query.next())
	      {
		QByteArray bytes;
		bool ok = true;

		bytes = s_crypt->decrypted
		  (QByteArray::fromBase64(query.value(0).toByteArray()), &ok);

		QCheckBox *checkBox = new QCheckBox();
		QTableWidgetItem *item = 0;

		if(ok)
		  item = new QTableWidgetItem(bytes.constData());
		else
		  item = new QTableWidgetItem(tr("error"));

		item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
		m_ui.etpMagnets->setRowCount(row + 1);
		m_ui.etpMagnets->setItem(row, 1, item);
		checkBox->setChecked(query.value(1).toInt());
		checkBox->setProperty
		  ("oid", query.value(query.record().count() - 1));
		connect(checkBox,
			SIGNAL(toggled(bool)),
			this,
			SLOT(slotStarOTMCheckChange(bool)));
		m_ui.etpMagnets->setCellWidget(row, 0, checkBox);
		m_ui.addTransmittedMagnets->setRowCount(row + 1);
		checkBox = new QCheckBox();

		if(ok)
		  checkBox->setText(bytes.replace("&", "&&").constData());
		else
		  checkBox->setText(tr("error"));

		if(checked.contains(checkBox->text()))
		  checkBox->setChecked(true);

		m_ui.addTransmittedMagnets->setCellWidget(row, 0, checkBox);
		item = new QTableWidgetItem
		  (query.value(query.record().count() - 1).toString());
		item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
		m_ui.etpMagnets->setItem(row, 2, item);
		m_ui.addTransmittedMagnets->setItem(row, 1, item->clone());
		row += 1;
	      }
	  }

	m_ui.etpMagnets->setSortingEnabled(true);
	m_ui.addTransmittedMagnets->setSortingEnabled(true);

	if(focusWidget)
	  focusWidget->setFocus();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotShowEtpMagnetsMenu(const QPoint &point)
{
  QMenu menu(this);

  if(m_ui.etpMagnets == sender())
    {
      menu.addAction(tr("Copy &Magnet"),
		     this, SLOT(slotCopyEtpMagnet(void)));
      menu.addSeparator();
      menu.addAction(QIcon(QString(":/%1/clear.png").
			   arg(m_settings.value("gui/iconSet", "nouve").
			       toString())),
		     tr("&Delete"),
		     this, SLOT(slotDeleteEtpMagnet(void)));
      menu.addAction(tr("Delete &All"),
		     this, SLOT(slotDeleteEtpAllMagnets(void)));
      menu.exec(m_ui.etpMagnets->mapToGlobal(point));
    }
}

void spoton::slotDeleteEtpAllMagnets(void)
{
  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "starbeam.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("DELETE FROM magnets");
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  askKernelToReadStarBeamKeys();
}

void spoton::slotDeleteEtpMagnet(void)
{
  QString oid("");
  int row = -1;

  if((row = m_ui.etpMagnets->currentRow()) >= 0)
    {
      QTableWidgetItem *item = m_ui.etpMagnets->item
	(row, m_ui.etpMagnets->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "starbeam.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.prepare("DELETE FROM magnets WHERE OID = ?");
	query.bindValue(0, oid);
	query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  askKernelToReadStarBeamKeys();
}

void spoton::slotCopyEtpMagnet(void)
{
  QClipboard *clipboard = QApplication::clipboard();

  if(!clipboard)
    return;
  else
    clipboard->clear();

  int row = -1;

  if((row = m_ui.etpMagnets->currentRow()) >= 0)
    {
      QTableWidgetItem *item = m_ui.etpMagnets->item(row, 1); // Magnet

      if(item)
	clipboard->setText(item->text());
    }
}

void spoton::slotSaveDestination(void)
{
  saveDestination(m_ui.destination->text().trimmed());
}

void spoton::saveDestination(const QString &path)
{
  if(!path.isEmpty())
    {
      m_settings["gui/etpDestinationPath"] = path;

      QSettings settings;

      settings.setValue("gui/etpDestinationPath", path);
      m_ui.destination->setText(path);
      m_ui.destination->setToolTip(path);
      m_ui.destination->selectAll();
    }
}

void spoton::slotSelectDestination(void)
{
  QFileDialog dialog(this);

  dialog.setWindowTitle
    (tr("Spot-On: Select StarBeam Destination Path"));
  dialog.setFileMode(QFileDialog::Directory);
  dialog.setDirectory(QDir::homePath());
  dialog.setLabelText(QFileDialog::Accept, tr("&Select"));
  dialog.setAcceptMode(QFileDialog::AcceptOpen);
#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
  dialog.setAttribute(Qt::WA_MacMetalStyle, false);
#endif
#endif

  if(dialog.exec() == QDialog::Accepted)
    saveDestination(dialog.selectedFiles().value(0).trimmed());
}

void spoton::slotReceiversClicked(bool state)
{
  m_settings["gui/etpReceivers"] = state;

  QSettings settings;

  settings.setValue("gui/etpReceivers", state);
}

void spoton::slotMaxMosaicSize(int value)
{
  m_settings["gui/maxMosaicSize"] = value;

  QSettings settings;

  settings.setValue("gui/maxMosaicSize", value);
}

void spoton::slotBuzzActionsActivated(int index)
{
  if(index == 0)
    {
      m_ui.channel->clear();
      m_ui.iterationCount->setValue(10000);
      m_ui.channelSalt->clear();
      m_ui.channelType->setCurrentIndex(0);
      m_ui.buzzHashKey->clear();
      m_ui.buzzHashType->setCurrentIndex(0);
    }
  else if(index == 1)
    {
      m_ui.channel->setText
	(spoton_crypt::strongRandomBytes(m_ui.channel->maxLength()).
	 toBase64());
      m_ui.channelSalt->setText
	(spoton_crypt::strongRandomBytes(512).toBase64());
      m_ui.buzzHashKey->setText
	(spoton_crypt::strongRandomBytes(512).toBase64());
    }

  disconnect(m_ui.buzzActions,
	     SIGNAL(activated(int)),
	     this,
	     SLOT(slotGenerateEtpKeys(int)));
  m_ui.buzzActions->setCurrentIndex(0);
  connect(m_ui.buzzActions,
	  SIGNAL(activated(int)),
	  this,
	  SLOT(slotGenerateEtpKeys(int)));
}

void spoton::slotAcceptChatKeys(bool state)
{
  m_settings["gui/acceptChatKeys"] = state;

  QSettings settings;

  settings.setValue("gui/acceptChatKeys", state);
}

void spoton::slotAcceptEmailKeys(bool state)
{
  m_settings["gui/acceptEmailKeys"] = state;

  QSettings settings;

  settings.setValue("gui/acceptEmailKeys", state);
}

void spoton::slotAcceptUrlKeys(bool state)
{
  m_settings["gui/acceptUrlKeys"] = state;

  QSettings settings;

  settings.setValue("gui/acceptUrlKeys", state);
}

void spoton::slotAutoRetrieveEmail(bool state)
{
  m_settings["gui/automaticallyRetrieveEmail"] = state;

  QSettings settings;

  settings.setValue("gui/automaticallyRetrieveEmail", state);

  if(state)
    m_emailRetrievalTimer.start();
  else
    m_emailRetrievalTimer.stop();
}

void spoton::slotMailRetrievalIntervalChanged(int value)
{
  m_settings["gui/emailRetrievalInterval"] = value;

  QSettings settings;

  settings.setValue("gui/emailRetrievalInterval", value);
  m_emailRetrievalTimer.setInterval(60 * 1000 * value);
}

void spoton::slotResetCertificate(void)
{
  spoton_crypt *s_crypt = m_crypts.value("chat", 0);

  if(!s_crypt)
    return;

  QModelIndexList list;

  list = m_ui.neighbors->selectionModel()->selectedRows
    (m_ui.neighbors->columnCount() - 1); // OID

  if(list.isEmpty())
    return;

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
		      "certificate = ? "
		      "WHERE OID = ? AND status = 'disconnected' AND "
		      "user_defined = 1");
	query.bindValue
	  (0, s_crypt->encrypted(QByteArray(), &ok).toBase64());
	query.bindValue(1, list.at(0).data());

	if(ok)
	  query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotTransportChanged(int index)
{
  if(m_ui.listenerTransport == sender())
    {
      m_ui.recordIPAddress->setEnabled(index == 0);
      m_ui.permanentCertificate->setEnabled(index == 0);
      m_ui.sslListener->setEnabled(index == 0);
      m_ui.listenerKeySize->setEnabled(index == 0);
      m_ui.listenerShareAddress->setEnabled(index == 1);
    }
  else if(m_ui.neighborTransport == sender())
    {
      m_ui.addException->setEnabled(index == 0);
      m_ui.requireSsl->setEnabled(index == 0);
      m_ui.sslKeySizeLabel->setEnabled(index == 0);
      m_ui.neighborKeySize->setEnabled(index == 0);
    }
}

void spoton::slotStarOTMCheckChange(bool state)
{
  QCheckBox *checkBox = qobject_cast<QCheckBox *> (sender());

  if(checkBox)
    {
      QString connectionName("");

      {
	QSqlDatabase db = spoton_misc::database(connectionName);

	db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
			   "starbeam.db");

	if(db.open())
	  {
	    QSqlQuery query(db);

	    query.prepare("UPDATE magnets SET "
			  "one_time_magnet = ? "
			  "WHERE OID = ?");
	    query.bindValue(0, state ? 1 : 0);
	    query.bindValue(1, checkBox->property("oid"));
	    query.exec();
	  }

	db.close();
      }

      QSqlDatabase::removeDatabase(connectionName);
    }
}

void spoton::slotPopulateKernelStatistics(void)
{
  QFileInfo fileInfo(spoton_misc::homePath() + QDir::separator() +
		     "kernel.db");

  if(fileInfo.exists())
    {
      if(fileInfo.lastModified() <= m_kernelStatisticsLastModificationTime)
	return;
      else
	m_kernelStatisticsLastModificationTime = fileInfo.lastModified();
    }
  else
    m_kernelStatisticsLastModificationTime = QDateTime();

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(fileInfo.absoluteFilePath());

    if(db.open())
      {
	m_ui.kernelStatistics->setSortingEnabled(false);
	m_ui.kernelStatistics->clearContents();
	m_ui.kernelStatistics->setRowCount(0);

	QSqlQuery query(db);
	QWidget *focusWidget = QApplication::focusWidget();

	query.setForwardOnly(true);

	if(query.exec("SELECT statistic, value FROM kernel_statistics "
		      "ORDER BY statistic"))
	  {
	    int row = 0;

	    while(query.next())
	      {
		QTableWidgetItem *item = new QTableWidgetItem
		  (query.value(0).toString());

		item->setFlags
		  (Qt::ItemIsSelectable | Qt::ItemIsEnabled);
		m_ui.kernelStatistics->setRowCount(row + 1);
		m_ui.kernelStatistics->setItem(row, 0, item);
		item = new QTableWidgetItem(query.value(1).toString());
		item->setFlags
		  (Qt::ItemIsSelectable | Qt::ItemIsEnabled);
		m_ui.kernelStatistics->setItem(row, 1, item);

		if(query.value(0).toString().toLower().contains("congestion"))
		  {
		    if(query.value(1).toInt() <= 50)
		      item->setBackground
			(QBrush(QColor("lightgreen")));
		    else
		      item->setBackground
			(QBrush(QColor(240, 128, 128)));
		  }

		row += 1;
	      }
	  }

	m_ui.kernelStatistics->setSortingEnabled(true);
	m_ui.kernelStatistics->horizontalHeader()->
	  setStretchLastSection(true);

	if(focusWidget)
	  focusWidget->setFocus();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotExternalIp(int index)
{
  QComboBox *comboBox = qobject_cast<QComboBox *> (sender());

  if(!comboBox)
    return;

  QString str("");
  int v = 30;

  if(comboBox == m_ui.guiExternalIpFetch)
    str = "gui";
  else
    str = "kernel";

  if(index == 0)
    v = 30;
  else if(index == 1)
    v = 60;
  else
    v = -1;

  m_settings[QString("gui/%1ExternalIpInterval").arg(str)] = v;

  QSettings settings;

  settings.setValue(QString("gui/%1ExternalIpInterval").arg(str), v);

  if(str == "gui")
    {
      if(index == 0)
	m_externalAddressDiscovererTimer.start(30000);
      else if(index == 1)
	m_externalAddressDiscovererTimer.start(60000);
      else
	m_externalAddressDiscovererTimer.stop();
    }
}

void spoton::slotSelectTransmitFile(void)
{
  QFileDialog dialog(this);

  dialog.setWindowTitle
    (tr("Spot-On: Select StarBeam Transmit File"));
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
    {
      m_ui.transmittedFile->setText
	(dialog.selectedFiles().value(0).trimmed());
      m_ui.transmittedFile->setToolTip(m_ui.transmittedFile->text());
    }
}

void spoton::slotTransmit(void)
{
  /*
  ** We must have at least one magnet selected.
  */

  QByteArray encryptedMosaic;
  QFileInfo fileInfo;
  QList<QByteArray> magnets;
  QString connectionName("");
  QString error("");
  bool ok = true;
  bool zero = true;

  spoton_crypt *s_crypt = m_crypts.value("chat", 0);

  if(!s_crypt)
    {
      error = tr("Invalid spoton_crypt object. This is a fatal flaw.");
      goto done_label;
    }

  if(m_ui.transmittedFile->text().trimmed().isEmpty())
    {
      error = tr("Please select a file to transfer.");
      goto done_label;
    }

  fileInfo.setFile(m_ui.transmittedFile->text().trimmed());

  if(!fileInfo.exists() || !fileInfo.isReadable())
    {
      error = tr("The provided file cannot be accessed.");
      goto done_label;
    }

  for(int i = 0; i < m_ui.addTransmittedMagnets->rowCount(); i++)
    {
      QCheckBox *checkBox = qobject_cast<QCheckBox *>
	(m_ui.addTransmittedMagnets->cellWidget(i, 0));

      if(checkBox)
	if(checkBox->isChecked())
	  {
	    zero = false;
	    magnets << checkBox->text().replace("&&", "&").toLatin1();
	  }
    }

  if(zero)
    {
      error = tr("Please select at least one magnet.");
      goto done_label;
    }

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "starbeam.db");

    if(db.open())
      {
	QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

	QByteArray mosaic(spoton_crypt::strongRandomBytes(64).toBase64());
	QSqlQuery query(db);

	query.prepare("INSERT INTO transmitted "
		      "(file, hash, mosaic, nova, position, pulse_size, "
		      "status_control, total_size) "
		      "VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
	query.bindValue
	  (0, s_crypt->encrypted(m_ui.transmittedFile->text().toUtf8(),
				 &ok).toBase64());

	if(ok)
	  query.bindValue
	    (1, s_crypt->
	     encrypted(spoton_crypt::
		       sha1FileHash(m_ui.transmittedFile->text()).toHex(),
		       &ok).toBase64());

	if(ok)
	  {
	    encryptedMosaic = s_crypt->encrypted(mosaic, &ok);

	    if(ok)
	      query.bindValue(2, encryptedMosaic.toBase64());
	  }

	if(ok)
	  query.bindValue
	    (3, s_crypt->encrypted(m_ui.transmitNova->text().trimmed().
				   toLatin1(), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (4, s_crypt->encrypted("0", &ok).toBase64());

	if(ok)
	  query.bindValue
	    (5, s_crypt->
	     encrypted(QByteArray::number(m_ui.pulseSize->
					  value()), &ok).toBase64());

	query.bindValue(6, "paused");

	if(ok)
	  query.bindValue
	    (7, s_crypt->
	     encrypted(QString::
		       number(QFileInfo(m_ui.transmittedFile->
					text()).size()).toLatin1(),
		       &ok).toBase64());

	if(ok)
	  query.exec();

	for(int i = 0; i < magnets.size(); i++)
	  {
	    query.prepare("INSERT INTO transmitted_magnets "
			  "(magnet, magnet_hash, transmitted_oid) "
			  "VALUES (?, ?, (SELECT OID FROM transmitted WHERE "
			  "mosaic = ?))");

	    if(ok)
	      query.bindValue
		(0, s_crypt->encrypted(magnets.at(i), &ok).toBase64());

	    if(ok)
	      query.bindValue
		(1, s_crypt->keyedHash(magnets.at(i), &ok).toBase64());

	    if(ok)
	      query.bindValue(2, encryptedMosaic.toBase64());

	    if(ok)
	      query.exec();
	    else
	      break;

	    if(query.lastError().isValid())
	      {
		error = query.lastError().text();
		break;
	      }

	    query.prepare("DELETE FROM magnets WHERE "
			  "magnet_hash = ? and one_time_magnet = 1");
	    query.bindValue(0, s_crypt->keyedHash(magnets.at(i), &ok).
			    toBase64());

	    if(ok)
	      query.exec();
	  }

	QApplication::restoreOverrideCursor();
      }

    if(db.lastError().isValid())
      error = tr("A database error (%1) occurred.").
	arg(db.lastError().text());
    else if(!error.isEmpty())
      error = tr("A database error (%1) occurred.").
	arg(error);
    else if(!ok)
      error = tr("An error occurred within spoton_crypt.");

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

 done_label:

  if(!error.isEmpty())
    QMessageBox::critical(this, tr("Spot-On: Error"), error);
  else
    {
      m_ui.pulseSize->setValue(15000);
      m_ui.transmitNova->clear();
      m_ui.transmittedFile->clear();
    }
}

void spoton::slotAcceptBuzzMagnets(bool state)
{
  m_settings["gui/acceptBuzzMagnets"] = state;

  QSettings settings;

  settings.setValue("gui/acceptBuzzMagnets", state);
}

void spoton::slotShareBuzzMagnet(void)
{
  if(m_kernelSocket.state() != QAbstractSocket::ConnectedState)
    return;
  else if(!m_kernelSocket.isEncrypted())
    return;

  QAction *action = qobject_cast<QAction *> (sender());

  if(!action)
    return;

  QByteArray data(action->data().toByteArray());
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

  QByteArray message;

  message.append("sharebuzzmagnet_");
  message.append(oid);
  message.append("_");
  message.append(data.toBase64());
  message.append('\n');

  if(m_kernelSocket.write(message.constData(), message.length()) !=
     message.length())
    spoton_misc::logError
      (QString("spoton::slotShareBuzzMagnet(): write() failure "
	       "for %1:%2.").
       arg(m_kernelSocket.peerAddress().toString()).
       arg(m_kernelSocket.peerPort()));
  else
    m_kernelSocket.flush();
}

void spoton::slotPopulateStars(void)
{
  spoton_crypt *s_crypt = m_crypts.value("chat", 0);

  if(!s_crypt)
    return;

  QFileInfo fileInfo(spoton_misc::homePath() + QDir::separator() +
		     "starbeam.db");

  if(fileInfo.exists())
    {
      if(fileInfo.lastModified() <= m_starsLastModificationTime)
	return;
      else
	m_starsLastModificationTime = fileInfo.lastModified();
    }
  else
    m_starsLastModificationTime = QDateTime();

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(fileInfo.absoluteFilePath());

    if(db.open())
      {
	QModelIndexList list;
	QString fileName("");
	QString mosaic("");
	QSqlQuery query(db);
	QWidget *focusWidget = QApplication::focusWidget();
	int hval = 0;
	int row = -1;
	int vval = 0;

	query.setForwardOnly(true);

	/*
	** First, received.
	*/

	list = m_ui.received->selectionModel()->selectedRows
	  (2); // File

	if(!list.isEmpty())
	  fileName = list.at(0).data().toString();

	hval = m_ui.received->horizontalScrollBar()->value();
	vval = m_ui.received->verticalScrollBar()->value();
	m_ui.received->setSortingEnabled(false);
	m_ui.received->clearContents();
	m_ui.received->setRowCount(0);
	row = 0;
	query.prepare("SELECT total_size, file, hash, OID FROM received");

	if(query.exec())
	  while(query.next())
	    {
	      m_ui.received->setRowCount(row + 1);

	      QString fileName("");
	      bool ok = true;

	      for(int i = 0; i < query.record().count(); i++)
		{
		  QTableWidgetItem *item = 0;

		  if(i == 0 || i == 1 || i == 2)
		    {
		      QByteArray bytes;

		      if(!query.isNull(i))
			bytes = s_crypt->
			  decrypted(QByteArray::fromBase64(query.value(i).
							   toByteArray()),
				    &ok);

		      if(ok)
			item = new QTableWidgetItem(bytes.constData());
		      else
			item = new QTableWidgetItem(tr("error"));

		      if(i == 1)
			fileName = item->text();
		    }
		  else if(i == query.record().count() - 1)
		    item = new QTableWidgetItem
		      (query.value(i).toString());

		  if(item)
		    {
		      item->setFlags(Qt::ItemIsEnabled |
				     Qt::ItemIsSelectable);
		      m_ui.received->setItem(row, i + 1, item);
		    }
		}

	      QTableWidgetItem *item1 = m_ui.received->item(row, 1);
	      QTableWidgetItem *item2 = m_ui.received->item(row, 2);

	      if(item1 && item2)
		{
		  int percent = 100 *
		    qAbs(static_cast<double> (QFileInfo(item2->text()).
					      size()) /
			 qMax(1LL, item1->text().toLongLong()));

		  if(percent < 100)
		    {
		      QProgressBar *progressBar = new QProgressBar();

		      progressBar->setValue(percent);
		      progressBar->setTextVisible(true);
		      progressBar->setToolTip
			(QString("%1% - %2").
			 arg(percent).
			 arg(QFileInfo(fileName).fileName()));
		      m_ui.received->setCellWidget(row, 0, progressBar);
		    }
		  else
		    m_ui.received->setItem
		      (row, 0, new QTableWidgetItem("100%"));
		}

	      if(m_ui.received->item(row, 2) &&
		 fileName == m_ui.received->item(row, 2)->text())
		m_ui.received->selectRow(row);

	      row += 1;
	    }

	m_ui.received->setSortingEnabled(true);

	for(int i = 0; i < m_ui.received->columnCount() - 1; i++)
	  /*
	  ** Ignore the OID column.
	  */

	  m_ui.received->resizeColumnToContents(i);

	m_ui.received->horizontalHeader()->setStretchLastSection(true);
	m_ui.received->horizontalScrollBar()->setValue(hval);
	m_ui.received->verticalScrollBar()->setValue(vval);

	/*
	** Second, transmitted.
	*/

	list = m_ui.transmitted->selectionModel()->selectedRows
	  (6); // Mosaic

	if(!list.isEmpty())
	  mosaic = list.at(0).data().toString();

	hval = m_ui.transmitted->horizontalScrollBar()->value();
	vval = m_ui.transmitted->verticalScrollBar()->value();
	m_ui.transmitted->setSortingEnabled(false);
	m_ui.transmitted->clearContents();
	m_ui.transmitted->setRowCount(0);
	row = 0;
	query.prepare("SELECT 0, position, pulse_size, total_size, "
		      "status_control, file, mosaic, hash, OID "
		      "FROM transmitted WHERE status_control <> 'deleted'");

	if(query.exec())
	  while(query.next())
	    {
	      m_ui.transmitted->setRowCount(row + 1);

	      QCheckBox *checkBox = new QCheckBox();
	      QString fileName("");
	      bool ok = true;
	      qint64 position = 0;

	      checkBox->setChecked(true);
	      checkBox->setProperty
		("oid", query.value(query.record().count() - 1));
	      m_ui.transmitted->setCellWidget(row, 0, checkBox);

	      for(int i = 0; i < query.record().count(); i++)
		{
		  QTableWidgetItem *item = 0;

		  if(i == 0)
		    {
		    }
		  else if(i == 1)
		    position = s_crypt->
		      decrypted(QByteArray::fromBase64(query.value(i).
						       toByteArray()),
				&ok).toLongLong();
		  else if(i == 2 || i == 3 || i == 5 || i == 7)
		    {
		      QByteArray bytes
			(s_crypt->
			 decrypted(QByteArray::fromBase64(query.value(i).
							  toByteArray()),
				   &ok));

		      if(ok)
			{
			  if(i == 5)
			    fileName = bytes.constData();

			  item = new QTableWidgetItem(bytes.constData());
			}
		      else
			{
			  if(i == 5)
			    fileName = tr("error");

			  item = new QTableWidgetItem(tr("error"));
			}
		    }
		  else if(i == 6)
		    {
		      QByteArray bytes(query.value(i).toByteArray());

		      bytes = bytes.mid(0, 16) + "..." + bytes.right(16);
		      item = new QTableWidgetItem(bytes.constData());
		    }
		  else if(i == 4)
		    {
		      item = new QTableWidgetItem(query.value(i).toString());

		      if(item->text() != "paused")
			checkBox->setChecked(false);

		      if(item->text() == "transmitting")
			item->setBackground
			  (QBrush(QColor("lightgreen")));
		      else
			item->setBackground(QBrush());
		    }
		  else if(i == query.record().count() - 1)
		    item = new QTableWidgetItem
		      (query.value(i).toString());

		  if(item)
		    {
		      item->setFlags(Qt::ItemIsEnabled |
				     Qt::ItemIsSelectable);
		      m_ui.transmitted->setItem(row, i, item);
		    }
		}

	      QTableWidgetItem *item = m_ui.transmitted->item(row, 3);

	      if(item)
		{
		  int percent = 100 *
		    qAbs(static_cast<double> (position) /
			 qMax(1LL, item->text().toLongLong()));

		  if(percent < 100)
		    {
		      QProgressBar *progressBar = new QProgressBar();

		      progressBar->setValue(percent);
		      progressBar->setToolTip
			(QString("%1% - %2").
			 arg(percent).
			 arg(QFileInfo(fileName).fileName()));
		      progressBar->setTextVisible(true);
		      m_ui.transmitted->setCellWidget
			(row, 1, progressBar);
		    }
		  else
		    m_ui.transmitted->setItem
		      (row, 1, new QTableWidgetItem("100%"));
		}

	      connect(checkBox,
		      SIGNAL(toggled(bool)),
		      this,
		      SLOT(slotTransmittedPaused(bool)));

	      for(int i = 0; i < m_ui.transmitted->columnCount(); i++)
		if(m_ui.transmitted->item(row, i))
		  m_ui.transmitted->item(row, i)->setToolTip(fileName);

	      if(m_ui.transmitted->item(row, 6) &&
		 mosaic == m_ui.transmitted->item(row, 6)->text())
		m_ui.transmitted->selectRow(row);

	      row += 1;
	    }

	m_ui.transmitted->setSortingEnabled(true);

	for(int i = 0; i < m_ui.transmitted->columnCount() - 1; i++)
	  /*
	  ** Ignore the OID column.
	  */

	  m_ui.transmitted->resizeColumnToContents(i);

	m_ui.transmitted->horizontalHeader()->setStretchLastSection(true);
	m_ui.transmitted->horizontalScrollBar()->setValue(hval);
	m_ui.transmitted->verticalScrollBar()->setValue(vval);

	if(focusWidget)
	  focusWidget->setFocus();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotTransmittedPaused(bool state)
{
  QCheckBox *checkBox = qobject_cast<QCheckBox *> (sender());

  if(checkBox)
    {
      QString connectionName("");

      {
	QSqlDatabase db = spoton_misc::database(connectionName);

	db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
			   "starbeam.db");

	if(db.open())
	  {
	    QSqlQuery query(db);

	    query.prepare("UPDATE transmitted SET "
			  "status_control = ? "
			  "WHERE OID = ? AND status_control <> 'deleted'");
	    query.bindValue(0, state ? "paused" : "transmitting");
	    query.bindValue(1, checkBox->property("oid"));
	    query.exec();
	  }

	db.close();
      }

      QSqlDatabase::removeDatabase(connectionName);
    }
}

void spoton::slotDeleteAllTransmitted(void)
{
  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "starbeam.db");

    if(db.open())
      {
	QSqlQuery query(db);

	if(!isKernelActive())
	  {
	    query.exec("DELETE FROM transmitted");
	    query.exec("DELETE FROM transmitted_magnets");
	    query.exec("DELETE FROM transmitted_scheduled_pulses");
	  }
	else
	  query.exec("UPDATE transmitted SET "
		     "status_control = 'deleted' WHERE "
		     "status_control <> 'deleted'");
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotDeleteTransmitted(void)
{
  QString oid("");
  int row = -1;

  if((row = m_ui.transmitted->currentRow()) >= 0)
    {
      QTableWidgetItem *item = m_ui.transmitted->item
	(row, m_ui.transmitted->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "starbeam.db");

    if(db.open())
      {
	QSqlQuery query(db);

	if(!isKernelActive())
	  {
	    query.prepare("DELETE FROM transmitted WHERE "
			  "OID = ?");
	    query.bindValue(0, oid);
	    query.exec();
	    query.exec("DELETE FROM transmitted_magnets WHERE "
		       "transmitted_oid NOT IN "
		       "(SELECT OID FROM transmitted)");
	    query.exec("DELETE FROM transmitted_scheduled_pulses WHERE "
		       "transmitted_oid NOT IN "
		       "(SELECT OID FROM transmitted)");
	  }
	else
	  {
	    query.prepare
	      ("UPDATE transmitted SET status_control = 'deleted' "
	       "WHERE OID = ? AND status_control <> 'deleted'");
	    query.bindValue(0, oid);
	    query.exec();
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotSecureMemoryPoolChanged(int value)
{
  QSettings settings;

  if(m_ui.guiSecureMemoryPool == sender())
    {
      m_settings["gui/gcryctl_init_secmem"] = value;
      settings.setValue("gui/gcryctl_init_secmem", value);
    }
  else
    {
      m_settings["kernel/gcryctl_init_secmem"] = value;
      settings.setValue("kernel/gcryctl_init_secmem", value);
    }
}

void spoton::slotAddReceiveNova(void)
{
  spoton_crypt *s_crypt = m_crypts.value("chat", 0);

  if(!s_crypt)
    {
      QMessageBox::critical(this, tr("Spot-On: Error"),
			    tr("Invalid spoton_crypt object. This is "
			       "a fatal flaw."));
      return;
    }

  QString nova(m_ui.receiveNova->text().trimmed());

  if(nova.isEmpty())
    {
      QMessageBox::critical(this, tr("Spot-On: Error"),
			    tr("Please provide a Nova. Reach for the "
			       "stars!"));
      return;
    }

  QString connectionName("");
  bool ok = true;

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "starbeam.db");

    if((ok = db.open()))
      {
	QSqlQuery query(db);

	query.prepare
	  ("INSERT OR REPLACE INTO received_novas "
	   "(nova, nova_hash) VALUES (?, ?)");
	query.bindValue
	  (0, s_crypt->encrypted(nova.toLatin1(),
				 &ok).toBase64());

	if(ok)
	  query.bindValue
	    (1, s_crypt->keyedHash(nova.toLatin1(), &ok).
	     toBase64());

	if(ok)
	  ok = query.exec();
      }
    else
      ok = false;

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(ok)
    {
      m_ui.receiveNova->clear();
      populateNovas();
      askKernelToReadStarBeamKeys();
    }
  else
    QMessageBox::critical(this, tr("Spot-On: Error"),
			  tr("Unable to store the Nova."));
}

void spoton::populateNovas(void)
{
  spoton_crypt *s_crypt = m_crypts.value("chat", 0);

  if(!s_crypt)
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "starbeam.db");

    if(db.open())
      {
	m_ui.novas->clear();

	QSqlQuery query(db);

	query.setForwardOnly(true);
	query.prepare("SELECT nova FROM received_novas");

	if(query.exec())
	  {
	    QStringList novas;

	    while(query.next())
	      {
		QString nova("");
		bool ok = true;

		nova = s_crypt->
		  decrypted(QByteArray::
			    fromBase64(query.
				       value(0).
				       toByteArray()),
			    &ok).constData();

		if(!nova.isEmpty())
		  novas.append(nova);
	      }

	    qSort(novas);

	    if(!novas.isEmpty())
	      m_ui.novas->addItems(novas);
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotDeleteNova(void)
{
  spoton_crypt *s_crypt = m_crypts.value("chat", 0);

  if(!s_crypt)
    {
      QMessageBox::critical(this, tr("Spot-On: Error"),
			    tr("Invalid spoton_crypt object. This is "
			       "a fatal flaw."));
      return;
    }

  QList<QListWidgetItem *> list(m_ui.novas->selectedItems());

  if(list.isEmpty())
    {
      QMessageBox::critical(this, tr("Spot-On: Error"),
			    tr("Please select a Nova to delete."));
      return;
    }

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "starbeam.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	query.prepare("DELETE FROM received_novas WHERE "
		      "nova_hash = ?");
	query.bindValue
	  (0, s_crypt->keyedHash(list.at(0)->text().toLatin1(), &ok).
	   toBase64());

	if(ok)
	  query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  populateNovas();
  askKernelToReadStarBeamKeys();
}

void spoton::slotGenerateNova(void)
{
  QByteArray nova
    (spoton_crypt::
     strongRandomBytes(spoton_crypt::cipherKeyLength("aes256")));

  m_ui.transmitNova->setText(nova.toBase64());
}

void spoton::slotTransmittedSelected(void)
{
  spoton_crypt *s_crypt = m_crypts.value("chat", 0);

  if(!s_crypt)
    return;

  QString oid("");
  int row = -1;

  if((row = m_ui.transmitted->currentRow()) >= 0)
    {
      QTableWidgetItem *item = m_ui.transmitted->item
	(row, m_ui.transmitted->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "starbeam.db");

    if(db.open())
      {
	m_ui.transmittedMagnets->clear();

	QSqlQuery query(db);

	query.setForwardOnly(true);
	query.prepare("SELECT magnet FROM transmitted_magnets "
		      "WHERE transmitted_oid = ? "
		      "AND transmitted_oid IN (SELECT OID FROM "
		      "transmitted WHERE status_control <> 'deleted' AND "
		      "OID = ?)");
	query.bindValue(0, oid);
	query.bindValue(1, oid);

	if(query.exec())
	  {
	    QStringList magnets;

	    while(query.next())
	      {
		QString magnet("");
		bool ok = true;

		magnet = s_crypt->
		  decrypted(QByteArray::
			    fromBase64(query.
				       value(0).
				       toByteArray()),
			    &ok).constData();

		if(!magnet.isEmpty())
		  magnets.append(magnet);
	      }

	    qSort(magnets);

	    if(!magnets.isEmpty())
	      m_ui.transmittedMagnets->addItems(magnets);
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotCopyTransmittedMagnet(void)
{
  QClipboard *clipboard = QApplication::clipboard();

  if(!clipboard)
    return;
  else
    clipboard->clear();

  QListWidgetItem *item = m_ui.transmittedMagnets->currentItem();

  if(item)
    clipboard->setText(item->text());
}

void spoton::slotDeleteAllReceived(void)
{
  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "starbeam.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("DELETE FROM received");
	query.exec("DELETE FROM received_pulses");
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotDeleteReceived(void)
{
  QString oid("");
  int row = -1;

  if((row = m_ui.received->currentRow()) >= 0)
    {
      QTableWidgetItem *item = m_ui.received->item
	(row, m_ui.received->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "starbeam.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.prepare("DELETE FROM received WHERE "
		      "OID = ?");
	query.bindValue(0, oid);
	query.exec();
	query.exec("DELETE FROM received_pulses WHERE "
		   "received_oid NOT IN "
		   "(SELECT OID FROM received)");
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::askKernelToReadStarBeamKeys(void)
{
  if(m_kernelSocket.state() != QAbstractSocket::ConnectedState)
    return;
  else if(!m_kernelSocket.isEncrypted())
    return;

  QByteArray message;

  message.append("populate_starbeam_keys\n");

  if(m_kernelSocket.write(message.constData(), message.length()) !=
     message.length())
    spoton_misc::logError
      (QString("spoton::askKernelToReadStarBeamKeys(): "
	       "write() failure for %1:%2.").
       arg(m_kernelSocket.peerAddress().toString()).
       arg(m_kernelSocket.peerPort()));
  else
    m_kernelSocket.flush();
}

void spoton::slotRewindFile(void)
{
  spoton_crypt *s_crypt = m_crypts.value("chat", 0);

  if(!s_crypt)
    return;

  QString oid("");
  int row = -1;

  if((row = m_ui.transmitted->currentRow()) >= 0)
    {
      QTableWidgetItem *item = m_ui.transmitted->item
	(row, m_ui.transmitted->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "starbeam.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	query.prepare
	  ("UPDATE transmitted SET position = ?, "
	   "status_control = 'paused' "
	   "WHERE OID = ? AND status_control <> 'deleted'");
	query.bindValue
	  (0, s_crypt->encrypted(QByteArray::number(0), &ok).
	   toBase64());
	query.bindValue(1, oid);

	if(ok)
	  query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotComputeFileHash(void)
{
  spoton_crypt *s_crypt = m_crypts.value("chat", 0);

  if(!s_crypt)
    return;

  QAction *action = qobject_cast<QAction *> (sender());

  if(!action)
    return;

  QTableWidget *table = 0;

  if(action->property("widget_of").toString() == "received")
    table = m_ui.received;
  else if(action->property("widget_of").toString() == "transmitted")
    table = m_ui.transmitted;

  if(!table)
    return;

  QString oid("");
  int row = -1;

  if((row = table->currentRow()) >= 0)
    {
      QTableWidgetItem *item = table->item
	(row, table->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    return;

  QTableWidgetItem *item = 0;

  if(m_ui.received == table)
    item = table->item(table->currentRow(), 2); // File
  else
    item = table->item(table->currentRow(), 5); // File

  if(!item)
    return;

  QFile file;
  QString fileName(item->text());

  file.setFileName(fileName);

  if(!file.open(QIODevice::ReadOnly))
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QByteArray hash(spoton_crypt::sha1FileHash(fileName));

  QApplication::restoreOverrideCursor();

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "starbeam.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	if(m_ui.received == table)
	  query.prepare
	    ("UPDATE received SET hash = ? WHERE OID = ?");
	else
	  query.prepare
	    ("UPDATE transmitted SET hash = ? WHERE OID = ?");

	query.bindValue
	  (0, s_crypt->encrypted(hash.toHex(), &ok).
	   toBase64());
	query.bindValue(1, oid);

	if(ok)
	  query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotCopyFileHash(void)
{
  QClipboard *clipboard = QApplication::clipboard();

  if(!clipboard)
    return;

  QAction *action = qobject_cast<QAction *> (sender());

  if(!action)
    {
      clipboard->clear();
      return;
    }

  QTableWidget *table = 0;

  if(action->property("widget_of").toString() == "received")
    table = m_ui.received;
  else if(action->property("widget_of").toString() == "transmitted")
    table = m_ui.transmitted;

  if(!table)
    {
      clipboard->clear();
      return;
    }

  QString oid("");
  int row = -1;

  if((row = table->currentRow()) >= 0)
    {
      QTableWidgetItem *item = table->item
	(row, table->columnCount() - 1); // OID

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    {
      clipboard->clear();
      return;
    }

  QTableWidgetItem *item = 0;

  if(m_ui.received == table)
    item = table->item(table->currentRow(), 3); // Hash
  else
    item = table->item(table->currentRow(), 7); // Hash

  if(!item)
    {
      clipboard->clear();
      return;
    }

  clipboard->setText(item->text());
}

void spoton::slotViewRosetta(void)
{
  m_rosetta.show(this);
}

void spoton::sharePublicKeyWithParticipant(const QString &keyType)
{
  if(!m_crypts.value(keyType, 0) ||
     !m_crypts.value(QString("%1-signature").arg(keyType), 0))
    return;
  else if(m_kernelSocket.state() != QAbstractSocket::ConnectedState)
    return;
  else if(!m_kernelSocket.isEncrypted())
    return;

  QString oid("");
  QTableWidget *table = 0;
  int row = -1;

  if(keyType == "chat")
    table = m_ui.participants;
  else if(keyType == "email")
    table = m_ui.emailParticipants;
  else if(keyType == "url")
    table = m_ui.urlParticipants;

  if(!table)
    return;

  if((row = table->currentRow()) >= 0)
    {
      QTableWidgetItem *item = table->item(row, 2); // neighbor_oid

      if(item)
	oid = item->text();
    }

  if(oid.isEmpty())
    return;

  QByteArray publicKey;
  QByteArray signature;
  bool ok = true;

  publicKey = m_crypts.value(keyType)->publicKey(&ok);

  if(ok)
    signature = m_crypts.value(keyType)->digitalSignature(publicKey, &ok);

  QByteArray sPublicKey;
  QByteArray sSignature;

  if(ok)
    sPublicKey = m_crypts.value(QString("%1-signature").arg(keyType))->
      publicKey(&ok);

  if(ok)
    sSignature = m_crypts.value(QString("%1-signature").arg(keyType))->
      digitalSignature(sPublicKey, &ok);

  if(ok)
    {
      QByteArray message;
      QByteArray name;

      if(keyType == "chat")
	name = m_settings.value("gui/nodeName", "unknown").
	  toByteArray().trimmed();
      else if(keyType == "email")
	name = m_settings.value("gui/emailName", "unknown").
	  toByteArray().trimmed();
      else if(keyType == "url")
	name = name = m_settings.value("gui/urlName", "unknown").
	  toByteArray().trimmed();

      if(name.isEmpty())
	name = "unknown";

      message.append("befriendparticipant_");
      message.append(oid);
      message.append("_");
      message.append(keyType.toLatin1().toBase64());
      message.append("_");
      message.append(name.toBase64());
      message.append("_");
      message.append(publicKey.toBase64());
      message.append("_");
      message.append(signature.toBase64());
      message.append("_");
      message.append(sPublicKey.toBase64());
      message.append("_");
      message.append(sSignature.toBase64());
      message.append('\n');

      if(m_kernelSocket.write(message.constData(), message.length()) !=
	 message.length())
	spoton_misc::logError
	  (QString("spoton::sharePublicKeyWithParticipant(): "
		   "write() failure for %1:%2.").
	   arg(m_kernelSocket.peerAddress().toString()).
	   arg(m_kernelSocket.peerPort()));
      else
	m_kernelSocket.flush();
    }
}

void spoton::slotRegenerateKey(void)
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
  mb.setText(tr("Are you sure that you wish to generate the selected "
		"key pair?"));

  if(mb.exec() != QMessageBox::Yes)
    return;

  QString keyType("chat");

  if(m_ui.keys->currentText() == tr("Chat"))
    keyType = "chat";
  else if(m_ui.keys->currentText() == tr("E-Mail"))
    keyType = "email";
  else if(m_ui.keys->currentText() == tr("Rosetta"))
    keyType = "rosetta";
  else if(m_ui.keys->currentText() == tr("URL"))
    keyType = "url";

  QString encryptionKeyType("");
  QString signatureKeyType("");

  if(m_ui.encryptionKeyType->currentIndex() == 0)
    encryptionKeyType = "elg";
  else
    encryptionKeyType = "rsa";

  if(m_ui.signatureKeyType->currentIndex() == 0)
    signatureKeyType = "dsa";
  else if(m_ui.signatureKeyType->currentIndex() == 1)
    signatureKeyType = "elg";
  else
    signatureKeyType = "rsa";

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  m_sb.status->setText(tr("Generating public key pairs."));
  m_sb.status->repaint();

  QString error("");
  spoton_crypt *crypt = m_crypts.value(keyType, 0);

  if(crypt)
    crypt->generatePrivatePublicKeys
      (m_ui.keySize->currentText().toInt(),
       encryptionKeyType,
       error);

  if(error.isEmpty())
    {
      crypt = m_crypts.value(QString("%1-signature").arg(keyType), 0);

      if(crypt)
	crypt->generatePrivatePublicKeys
	  (m_ui.keySize->currentText().toInt(),
	   signatureKeyType,
	   error);
    }

  m_sb.status->clear();
  QApplication::restoreOverrideCursor();
  updatePublicKeysLabel();

  if(error.isEmpty())
    {
      if(m_ui.encryptionKeyType->currentIndex() == 0)
	m_settings["gui/encryptionKey"] = "elg";
      else
	m_settings["gui/encryptionKey"] = "rsa";

      m_settings["gui/keySize"] = m_ui.keySize->currentText().toInt();

      if(m_ui.signatureKeyType->currentIndex() == 0)
	m_settings["gui/signatureKey"] = "dsa";
      else if(m_ui.signatureKeyType->currentIndex() == 1)
	m_settings["gui/signatureKey"] = "elg";
      else
	m_settings["gui/signatureKey"] = "rsa";

      QSettings settings;

      settings.setValue("gui/encryptionKey", m_settings["gui/encryptionKey"]);
      settings.setValue("gui/keySize", m_settings["gui/keySize"]);
      settings.setValue
	("gui/signatureKey", m_settings["gui/signatureKey"]);

      if(m_ui.keys->currentText() == tr("Rosetta"))
	m_rosetta.setCryptObjects(m_crypts.value("rosetta", 0),
				  m_crypts.value("rosetta-signature", 0));
      else
	sendKeysToKernel();
    }
  else
    QMessageBox::critical(this, tr("Spot-On: Error"),
			  tr("An error (%1) occurred with "
			     "spoton_crypt::"
			     "generatePrivatePublicKeys().").
			  arg(error.remove(".").trimmed()));
}

void spoton::prepareContextMenuMirrors(void)
{
  if(!m_ui.chatActionMenu->menu())
    {
      QAction *action = 0;
      QMenu *menu = new QMenu(this);

      menu->addAction
	(QIcon(QString(":/%1/add.png").
	       arg(m_settings.value("gui/iconSet", "nouve").toString())),
	 tr("&Add participant as friend."),
	 this, SLOT(slotShareChatPublicKeyWithParticipant(void)));
      menu->addAction(QIcon(QString(":/%1/copy.png").
			    arg(m_settings.value("gui/iconSet", "nouve").
				toString())),
		      tr("&Copy Repleo to the clipboard buffer."),
		      this, SLOT(slotCopyFriendshipBundle(void)));
      menu->addSeparator();
      action = menu->addAction(tr("&Call participant."),
			       this, SLOT(slotCallParticipant(void)));
      action->setProperty("type", "calling");
      action = menu->addAction(tr("&Terminate call."),
			       this, SLOT(slotCallParticipant(void)));
      action->setProperty("type", "terminating");
      menu->addSeparator();
      action = menu->addAction(tr("&Generate random Gemini pair "
				  "(AES-256 Key, SHA-512 Key)."),
			       this, SLOT(slotGenerateGeminiInChat(void)));
      menu->addSeparator();
      menu->addAction(QIcon(QString(":/%1/clear.png").
			    arg(m_settings.value("gui/iconSet", "nouve").
				toString())),
		      tr("&Remove participant(s)."),
		      this, SLOT(slotRemoveParticipants(void)));
      m_ui.chatActionMenu->setMenu(menu);
    }

  if(!m_ui.emailWriteActionMenu->menu())
    {
      QMenu *menu = new QMenu(this);

      menu->addAction
	(QIcon(QString(":/%1/add.png").
	       arg(m_settings.value("gui/iconSet", "nouve").toString())),
	 tr("&Add participant as friend."),
	 this, SLOT(slotShareEmailPublicKeyWithParticipant(void)));
      menu->addSeparator();
      menu->addAction(QIcon(QString(":/%1/copy.png").
			    arg(m_settings.value("gui/iconSet", "nouve").
				toString())),
		      tr("&Copy keys to the clipboard buffer."),
		      this, SLOT(slotCopyEmailKeys(void)));
      menu->addAction(QIcon(QString(":/%1/copy.png").
			    arg(m_settings.value("gui/iconSet", "nouve").
				toString())),
		      tr("&Copy Repleo to the clipboard buffer."),
		      this, SLOT(slotCopyEmailFriendshipBundle(void)));
      menu->addSeparator();
      menu->addAction(QIcon(QString(":/%1/clear.png").
			    arg(m_settings.value("gui/iconSet", "nouve").
				toString())),
		      tr("&Remove participant(s)."),
		      this, SLOT(slotRemoveEmailParticipants(void)));
      m_ui.emailWriteActionMenu->setMenu(menu);
    }

  if(!m_ui.listenersActionMenu->menu())
    {
      QMenu *menu = new QMenu(this);

      menu->addAction(QIcon(QString(":/%1/clear.png").
			    arg(m_settings.value("gui/iconSet", "nouve").
				toString())),
		      tr("&Delete"),
		      this, SLOT(slotDeleteListener(void)));
      menu->addAction(tr("Delete &All"),
		      this, SLOT(slotDeleteAllListeners(void)));
      menu->addSeparator();
      menu->addAction(tr("Detach &Neighbors"),
		      this, SLOT(slotDetachListenerNeighbors(void)));
      menu->addAction(tr("Disconnect &Neighbors"),
		      this, SLOT(slotDisconnectListenerNeighbors(void)));
      menu->addSeparator();
      menu->addAction(tr("&Publish Information (Plaintext)"),
		      this, SLOT(slotPublicizeListenerPlaintext(void)));
      menu->addAction(tr("Publish &All (Plaintext)"),
		      this, SLOT(slotPublicizeAllListenersPlaintext(void)));
      menu->addSeparator();
      menu->addAction(tr("&Full Echo"),
		      this, SLOT(slotListenerFullEcho(void)));
      menu->addAction(tr("&Half Echo"),
		      this, SLOT(slotListenerHalfEcho(void)));
      m_ui.listenersActionMenu->setMenu(menu);
    }

  if(!m_ui.magnetsActionMenu->menu())
    {
      QMenu *menu = new QMenu(this);

      menu->addAction(tr("Copy &Magnet"),
		      this, SLOT(slotCopyEtpMagnet(void)));
      menu->addSeparator();
      menu->addAction(QIcon(QString(":/%1/clear.png").
			    arg(m_settings.value("gui/iconSet", "nouve").
				toString())),
		      tr("&Delete"),
		      this, SLOT(slotDeleteEtpMagnet(void)));
      menu->addAction(tr("Delete &All"),
		      this, SLOT(slotDeleteEtpAllMagnets(void)));
      m_ui.magnetsActionMenu->setMenu(menu);
    }

  if(!m_ui.neighborsActionMenu->menu())
    {
      QMenu *menu = new QMenu(this);

      menu->addAction(QIcon(QString(":/%1/share.png").
			    arg(m_settings.value("gui/iconSet", "nouve").
				toString())),
		      tr("Share &Chat Public Key"),
		      this, SLOT(slotShareChatPublicKey(void)));
      menu->addAction(QIcon(QString(":/%1/share.png").
			    arg(m_settings.value("gui/iconSet", "nouve").
				toString())),
		      tr("Share &E-Mail Public Key"),
		      this, SLOT(slotShareEmailPublicKey(void)));
      menu->addAction(QIcon(QString(":%1//share.png").
			    arg(m_settings.value("gui/iconSet", "nouve").
				toString())),
		      tr("Share &URL Public Key"),
		      this, SLOT(slotShareURLPublicKey(void)));
      menu->addSeparator();
      menu->addAction(tr("&Connect"),
		      this, SLOT(slotConnectNeighbor(void)));
      menu->addAction(tr("&Disconnect"),
		      this, SLOT(slotDisconnectNeighbor(void)));
      menu->addSeparator();
      menu->addAction
	(tr("&Authenticate"),
	 this,
	 SLOT(slotAuthenticate(void)));
      menu->addAction(tr("&Reset Account Information"),
		      this,
		      SLOT(slotResetAccountInformation(void)));
      menu->addSeparator();
      menu->addAction(tr("&Reset Certificate"),
		      this,
		      SLOT(slotResetCertificate(void)));
      menu->addSeparator();
      menu->addAction(QIcon(QString(":/%1/clear.png").
			    arg(m_settings.value("gui/iconSet", "nouve").
				toString())),
		      tr("&Delete"),
		      this, SLOT(slotDeleteNeighbor(void)));
      menu->addAction(tr("Delete &All"),
		      this, SLOT(slotDeleteAllNeighbors(void)));
      menu->addAction(tr("Delete All Non-Unique &Blocked Neighbors"),
		      this, SLOT(slotDeleteAllBlockedNeighbors(void)));
      menu->addAction(tr("Delete All Non-Unique &UUIDs"),
		      this, SLOT(slotDeleteAllUuids(void)));
      menu->addSeparator();
      menu->addAction(tr("B&lock"),
		      this, SLOT(slotBlockNeighbor(void)));
      menu->addAction(tr("U&nblock"),
		      this, SLOT(slotUnblockNeighbor(void)));
      menu->addSeparator();
      menu->addAction(tr("&Full Echo"),
		      this, SLOT(slotNeighborFullEcho(void)));
      menu->addAction(tr("&Half Echo"),
		      this, SLOT(slotNeighborHalfEcho(void)));
      m_ui.neighborsActionMenu->setMenu(menu);
    }

  if(!m_ui.receivedActionMenu->menu())
    {
      QMenu *menu = new QMenu(this);

      menu->addAction(QIcon(QString(":/%1/clear.png").
			    arg(m_settings.value("gui/iconSet", "nouve").
				toString())),
		      tr("&Delete"), this,
		      SLOT(slotDeleteReceived(void)));
      menu->addAction(tr("Delete &All"), this,
		      SLOT(slotDeleteAllReceived(void)));
      menu->addSeparator();

      QAction *action = menu->addAction(tr("&Compute SHA-1 Hash"), this,
					SLOT(slotComputeFileHash(void)));

      action->setProperty("widget_of", "received");
      menu->addSeparator();
      action = menu->addAction(tr("&Copy File Hash"), this,
			       SLOT(slotCopyFileHash(void)));
      action->setProperty("widget_of", "received");
      m_ui.receivedActionMenu->setMenu(menu);
    }

  if(!m_ui.transmittedActionMenu->menu())
    {
      QAction *action = 0;
      QMenu *menu = new QMenu(this);

      menu->addAction(QIcon(QString(":/%1/clear.png").
			    arg(m_settings.value("gui/iconSet", "nouve").
				toString())),
		      tr("&Delete"), this,
		      SLOT(slotDeleteTransmitted(void)));
      menu->addAction(tr("Delete &All"), this,
		      SLOT(slotDeleteAllTransmitted(void)));
      menu->addSeparator();
      action = menu->addAction(tr("&Compute SHA-1 Hash"), this,
			       SLOT(slotComputeFileHash(void)));
      action->setProperty("widget_of", "transmitted");
      menu->addSeparator();
      action = menu->addAction(tr("&Copy File Hash"), this,
			       SLOT(slotCopyFileHash(void)));
      action->setProperty("widget_of", "transmitted");
      menu->addSeparator();
      menu->addAction(tr("Copy &Magnet"),
		      this, SLOT(slotCopyTransmittedMagnet(void)));
      m_ui.transmittedActionMenu->setMenu(menu);
    }
}

void spoton::slotCopyEmailKeys(void)
{
  QClipboard *clipboard = QApplication::clipboard();

  if(!clipboard)
    return;

  QByteArray name;
  QByteArray publicKeyHash;
  QString oid("");
  int row = -1;

  if((row = m_ui.emailParticipants->currentRow()) >= 0)
    {
      QTableWidgetItem *item = m_ui.emailParticipants->
	item(row, 0); // Name

      if(item)
	name.append(item->text());

      item = m_ui.emailParticipants->item(row, 1); // OID

      if(item)
	oid = item->text();

      item = m_ui.emailParticipants->item(row, 3); // public_key_hash

      if(item)
	publicKeyHash.append(item->text());
    }

  if(oid.isEmpty() || publicKeyHash.isEmpty())
    {
      clipboard->clear();
      return;
    }

  if(name.isEmpty())
    name = "unknown";

  QByteArray publicKey;
  QByteArray signatureKey;
  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);
	query.prepare("SELECT public_key "
		      "FROM friends_public_keys WHERE "
		      "OID = ?");
	query.bindValue(0, oid);

	if(query.exec())
	  if(query.next())
	    publicKey = query.value(0).toByteArray();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  signatureKey = spoton_misc::signaturePublicKeyFromPublicKeyHash
    (QByteArray::fromBase64(publicKeyHash));

  if(!publicKey.isEmpty() && !signatureKey.isEmpty())
    clipboard->setText
      ("K" + QByteArray("email").toBase64() + "@" +
       name.toBase64() + "@" +
       publicKey.toBase64() + "@" + QByteArray().toBase64() + "@" +
       signatureKey.toBase64() + "@" + QByteArray().toBase64());
  else
    clipboard->clear();
}

void spoton::slotImpersonate(bool state)
{
  m_settings["gui/impersonate"] = state;

  QSettings settings;

  settings.setValue("gui/impersonate", state);
}

void spoton::slotCopyOrPaste(void)
{
  QAction *action = qobject_cast<QAction *> (sender());

  if(!action)
    return;

  QWidget *widget = QApplication::focusWidget();

  if(!widget)
    return;

  QString a("");

  if(action == m_ui.action_Copy)
    a = "copy";
  else
    a = "paste";

  if(qobject_cast<QLineEdit *> (widget))
    {
      if(a == "copy")
	qobject_cast<QLineEdit *> (widget)->copy();
      else
	qobject_cast<QLineEdit *> (widget)->paste();
    }
  else if(qobject_cast<QPlainTextEdit *> (widget))
    {
      if(a == "copy")
	qobject_cast<QPlainTextEdit *> (widget)->copy();
      else
	qobject_cast<QPlainTextEdit *> (widget)->paste();
    }
  else if(qobject_cast<QTextEdit *> (widget))
    {
      if(a == "copy")
	qobject_cast<QTextEdit *> (widget)->copy();
      else
	qobject_cast<QTextEdit *> (widget)->paste();
    }
}

void spoton::updatePublicKeysLabel(void)
{
  QString str
    (tr("<b>Chat Key Pair:</b> %1, <b>Chat Signature Key Pair:</b> %2, "
	"<b>E-Mail Key Pair:</b> %3, "
	"<b>E-Mail Signature Key Pair:</b> %4, "
	"<b>Rosetta Key Pair:</b> %5, "
	"<b>Rosetta Signature Key Pair:</b> %6, "
	"<b>URL Key Pair:</b> %7, <b>URL Signature Key Pair:</b> %8."));
  QStringList list;

  list << "chat"
       << "chat-signature"
       << "email"
       << "email-signature"
       << "rosetta"
       << "rosetta-signature"
       << "url"
       << "url-signature";

  for(int i = 0; i < list.size(); i++)
    if(m_crypts.value(list.at(i), 0))
      str.replace
	(QString("%%1").arg(i + 1),
	 QString::number(m_crypts.value(list.at(i))->publicKeyCount()));
    else
      str.replace(QString("%%1").arg(i + 1), "0");

  m_ui.publicKeysInformation->setText(str);
}

void spoton::slotExportPublicKeys(void)
{
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

  QByteArray keys(copyMyChatPublicKey() + "@" +
		  copyMyEmailPublicKey() + "@" +
		  copyMyRosettaPublicKey() + "@" +
		  copyMyUrlPublicKey());

  QApplication::restoreOverrideCursor();

  if(keys.count("@") == 3)
    /*
    ** Problem!
    */

    QMessageBox::critical
      (this, tr("Spot-On: Error"),
       tr("A deep failure occurred while gathering your public key pairs. "
	  "Do you have public keys? Please inspect the Settings tab."));
  else
    {
      if(keys.length() >= 30000)
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
	  mb.setText
	    (tr("The gathered public keys contain a lot (%1) of data. "
		"Are you sure that you wish to export the data?").
	     arg(keys.length()));

	  if(mb.exec() != QMessageBox::Yes)
	    return;
	}

      QFileDialog dialog(this);

      dialog.setConfirmOverwrite(true);
      dialog.setWindowTitle
	(tr("Spot-On: Select Public Keys Export File"));
      dialog.setFileMode(QFileDialog::AnyFile);
#if QT_VERSION < 0x050000
      dialog.setDirectory
	(QDesktopServices::storageLocation(QDesktopServices::
					   DesktopLocation));
#else
      dialog.setDirectory
	(QStandardPaths::standardLocations(QStandardPaths::DesktopLocation).
	 value(0));
#endif
      dialog.setLabelText(QFileDialog::Accept, tr("&Save"));
      dialog.setAcceptMode(QFileDialog::AcceptSave);
#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
      dialog.setAttribute(Qt::WA_MacMetalStyle, false);
#endif
#endif
      dialog.selectFile
	(QString("spot-on-public-keys-export-%1.txt").
	 arg(QDateTime::currentDateTime().toString("MM-dd-yyyy-hh-mm-ss")));

      if(dialog.exec() == QDialog::Accepted)
	{
	  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

	  QFile file;

	  file.setFileName(dialog.selectedFiles().value(0).trimmed());

	  if(file.open(QIODevice::Truncate | QIODevice::WriteOnly))
	    {
	      file.write(keys);
	      file.flush();
	    }

	  file.close();
	  QApplication::restoreOverrideCursor();
	}
    }
}

void spoton::slotImportPublicKeys(void)
{
  QFileDialog dialog(this);

  dialog.setWindowTitle
    (tr("Spot-On: Select Public Keys Import File"));
  dialog.setFileMode(QFileDialog::ExistingFile);
#if QT_VERSION < 0x050000
  dialog.setDirectory
    (QDesktopServices::storageLocation(QDesktopServices::
				       DesktopLocation));
#else
  dialog.setDirectory
    (QStandardPaths::standardLocations(QStandardPaths::DesktopLocation).
     value(0));
#endif
  dialog.setLabelText(QFileDialog::Accept, tr("&Select"));
  dialog.setAcceptMode(QFileDialog::AcceptOpen);
#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
  dialog.setAttribute(Qt::WA_MacMetalStyle, false);
#endif
#endif

  if(dialog.exec() == QDialog::Accepted)
    {
      QFileInfo fileInfo;

      fileInfo.setFile(dialog.directory(),
		       dialog.selectedFiles().value(0).trimmed());

      if(fileInfo.size() >= 30000)
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
	  mb.setText
	    (tr("The import file contains a lot (%1) of data. Are you "
		"sure that you wish to process it?").
	     arg(fileInfo.size()));

	  if(mb.exec() != QMessageBox::Yes)
	    return;
	}

      QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

      QByteArray bytes;
      QFile file;

      file.setFileName(fileInfo.filePath());

      if(file.open(QIODevice::ReadOnly))
	bytes = file.readAll();

      file.close();
      QApplication::restoreOverrideCursor();

      QList<QByteArray> list(bytes.split('@'));

      while(!list.isEmpty())
	if(list.size() >= 6)
	  {
	    QByteArray bytes("K");

	    bytes.append(list.takeFirst().remove(0, 1));
	    bytes.append("@");
	    bytes.append(list.takeFirst());
	    bytes.append("@");
	    bytes.append(list.takeFirst());
	    bytes.append("@");
	    bytes.append(list.takeFirst());
	    bytes.append("@");
	    bytes.append(list.takeFirst());
	    bytes.append("@");
	    bytes.append(list.takeFirst());
	    addFriendsKey(bytes);
	  }
	else
	  break;
    }
}

void spoton::slotExportListeners(void)
{
  if(m_ui.listeners->rowCount() == 0)
    {
      QMessageBox::critical
	(this, tr("Spot-On: Error"),
	 tr("Unable to export an empty listeners table."));
      return;
    }

  QFileDialog dialog(this);

  dialog.setConfirmOverwrite(true);
  dialog.setWindowTitle
    (tr("Spot-On: Select Listeners Export File"));
  dialog.setFileMode(QFileDialog::AnyFile);
#if QT_VERSION < 0x050000
  dialog.setDirectory(QDesktopServices::storageLocation(QDesktopServices::
							DesktopLocation));
#else
  dialog.setDirectory(QStandardPaths::
		      standardLocations(QStandardPaths::DesktopLocation).
		      value(0));
#endif
  dialog.setLabelText(QFileDialog::Accept, tr("&Save"));
  dialog.setAcceptMode(QFileDialog::AcceptSave);
#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
  dialog.setAttribute(Qt::WA_MacMetalStyle, false);
#endif
#endif
  dialog.selectFile(QString("spot-on-listeners-export-%1.txt").
		    arg(QDateTime::currentDateTime().
			toString("MM-dd-yyyy-hh-mm-ss")));

  if(dialog.exec() == QDialog::Accepted)
    {
      QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

      QFile file;

      file.setFileName(dialog.selectedFiles().value(0).trimmed());

      if(file.open(QIODevice::Text | QIODevice::Truncate |
		   QIODevice::WriteOnly))
	for(int i = 0; i < m_ui.listeners->rowCount(); i++)
	  {
	    QByteArray bytes;

	    bytes.append("echo_mode=");
	    bytes.append(m_ui.listeners->item(i, 11)->text());
	    bytes.append("&");
	    bytes.append("ip_address=");
	    bytes.append(m_ui.listeners->item(i, 7)->text());
	    bytes.append("&");
	    bytes.append("orientation=");
	    bytes.append(m_ui.listeners->item(i, 18)->text());
	    bytes.append("&");
	    bytes.append("port=");
	    bytes.append(m_ui.listeners->item(i, 4)->text());
	    bytes.append("&");
	    bytes.append("protocol=");
	    bytes.append(m_ui.listeners->item(i, 6)->text());
	    bytes.append("&");
	    bytes.append("scope_id=");
	    bytes.append(m_ui.listeners->item(i, 5)->text().remove("&"));
	    bytes.append("&");
	    bytes.append("ssl_key_size=");
	    bytes.append(m_ui.listeners->item(i, 2)->text());
	    bytes.append("&");
	    bytes.append("transport=");
	    bytes.append(m_ui.listeners->item(i, 15)->text());
	    bytes.append("\n");
	    file.write(bytes);
	    file.flush();
	  }

      file.close();
      QApplication::restoreOverrideCursor();
    }
}

void spoton::slotForceKernelRegistration(bool state)
{
  m_settings["gui/forceKernelRegistration"] = state;

  QSettings settings;

  settings.setValue("gui/forceKernelRegistration", state);
}

void spoton::slotImportNeighbors(void)
{
  spoton_crypt *s_crypt = m_crypts.value("chat", 0);

  if(!s_crypt)
    {
      QMessageBox::critical(this, tr("Spot-On: Error"),
			    tr("Invalid spoton_crypt object. "
			       "This is a fatal flaw."));
      return;
    }

  QFileDialog dialog(this);

  dialog.setWindowTitle
    (tr("Spot-On: Select Neighbors Import File"));
  dialog.setFileMode(QFileDialog::ExistingFile);
#if QT_VERSION < 0x050000
  dialog.setDirectory
    (QDesktopServices::storageLocation(QDesktopServices::
				       DesktopLocation));
#else
  dialog.setDirectory
    (QStandardPaths::standardLocations(QStandardPaths::DesktopLocation).
     value(0));
#endif
  dialog.setLabelText(QFileDialog::Accept, tr("&Select"));
  dialog.setAcceptMode(QFileDialog::AcceptOpen);
#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
  dialog.setAttribute(Qt::WA_MacMetalStyle, false);
#endif
#endif

  if(dialog.exec() == QDialog::Accepted)
    {
      QFileInfo fileInfo;

      fileInfo.setFile(dialog.directory(),
		       dialog.selectedFiles().value(0).trimmed());

      if(fileInfo.size() >= 30000)
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
	  mb.setText
	    (tr("The import file contains a lot (%1) of data. Are you "
		"sure that you wish to process it?").
	     arg(fileInfo.size()));

	  if(mb.exec() != QMessageBox::Yes)
	    return;
	}

      QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));

      QString connectionName("");

      {
	QSqlDatabase db = spoton_misc::database(connectionName);

	db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
			   "neighbors.db");

	if(db.open())
	  {
	    QFile file;

	    file.setFileName(fileInfo.filePath());

	    if(file.open(QIODevice::ReadOnly))
	      {
		QByteArray bytes(1024, 0);
		qint64 rc = 0;

		while((rc = file.readLine(bytes.data(),
					  bytes.length())) > -1)
		  {
		    QHash<QString, QByteArray> hash;
		    QList<QByteArray> list(bytes.mid(0, rc).
					   trimmed().split('&'));
		    bool fine = true;

		    while(!list.isEmpty())
		      {
			QByteArray token(list.takeFirst().trimmed());

			if(token.startsWith("echo_mode="))
			  {
			    token.remove(0, qstrlen("echo_mode="));

			    if(!(token == "full" || token == "half"))
			      fine = false;
			    else
			      hash["echo_mode"] = token;
			  }
			else if(token.startsWith("ip_address="))
			  {
			    token.remove(0, qstrlen("ip_address="));

			    if(QHostAddress(token.constData()).isNull())
			      fine = false;
			    else
			      hash["ip_address"] = token;
			  }
			else if(token.startsWith("orientation="))
			  {
			    token.remove(0, qstrlen("orientation="));
			    token = token.toLower();

			    if(!(token == "packet" || token == "stream"))
			      fine = false;
			    else
			      hash["orientation"] = token;
			  }
			else if(token.startsWith("port="))
			  {
			    token.remove(0, qstrlen("port="));

			    if(!(token.toInt() > 0 &&
				 token.toInt() <= 65535))
			      fine = false;
			    else
			      hash["port"] = token;
			  }
			else if(token.startsWith("protocol="))
			  {
			    token.remove(0, qstrlen("protocol="));
			    token = token.toLower();

			    if(token == "ipv4")
			      hash["protocol"] = "IPv4";
			    else if(token == "ipv6")
			      hash["protocol"] = "IPv6";
			    else
			      fine = false;
			  }
			else if(token.startsWith("scope_id="))
			  {
			    token.remove(0, qstrlen("scope_id="));
			    hash["scope_id"] = token;
			  }
			else if(token.startsWith("ssl_key_size="))
			  {
			    token.remove(0, qstrlen("ssl_key_size="));

			    if(!(token == "0" ||
				 token == "2048" || token == "3072" ||
				 token == "4096" || token == "8192"))
			      fine = false;
			    else
			      hash["ssl_key_size"] = token;
			  }
			else if(token.startsWith("transport="))
			  {
			    token.remove(0, qstrlen("transport="));
			    token = token.toLower();

			    if(!(token == "tcp" || token == "udp"))
			      fine = false;
			    else
			      hash["transport"] = token;
			  }

			if(!fine)
			  break;
		      }

		    if(hash.count() != 8)
		      fine = false;

		    if(fine)
		      {
			QSqlQuery query(db);
			bool ok = true;

			query.prepare
			  ("INSERT INTO neighbors "
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
			   "certificate, "
			   "ssl_required, "
			   "account_name, "
			   "account_password, "
			   "transport, "
			   "orientation) "
			   "VALUES "
			   "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
			   "?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");

			query.bindValue(0, QVariant(QVariant::String));
			query.bindValue(1, QVariant(QVariant::String));
			query.bindValue
			  (2, s_crypt->
			   encrypted(hash["protocol"], &ok).toBase64());

			if(ok)
			  query.bindValue
			    (3, s_crypt->
			     encrypted(hash["ip_address"], &ok).toBase64());

			if(ok)
			  query.bindValue
			    (4, s_crypt->
			     encrypted(hash["port"], &ok).toBase64());

			query.bindValue(5, 1); // Sticky.

			if(ok)
			  query.bindValue
			    (6, s_crypt->
			     encrypted(hash["scope_id"], &ok).toBase64());

			if(ok)
			  query.bindValue
			    (7, s_crypt->
			     keyedHash(QByteArray() + // Proxy Hostname
				       QByteArray() + // Proxy Port
				       hash["ip_address"] +
				       hash["port"] +
				       hash["scope_id"] +
				       hash["transport"], &ok).
			     toBase64());

			query.bindValue(8, "disconnected");

			QString country
			  (spoton_misc::
			   countryNameFromIPAddress(hash["ip_address"].
						    constData()));

			if(ok)
			  query.bindValue
			    (9, s_crypt->
			     encrypted(country.toLatin1(), &ok).toBase64());

			if(ok)
			  query.bindValue
			    (10, s_crypt->
			     keyedHash(hash["ip_address"], &ok).
			     toBase64());

			if(ok)
			  query.bindValue
			    (11, s_crypt->
			     keyedHash(country.remove(" ").toLatin1(), &ok).
			     toBase64());

			if(ok)
			  query.bindValue
			    (12, s_crypt->
			     encrypted(QByteArray(), &ok).
			     toBase64());

			if(ok)
			  query.bindValue
			    (13, s_crypt->
			     encrypted(QByteArray(), &ok).
			     toBase64());

			if(ok)
			  query.bindValue
			    (14, s_crypt->encrypted(QByteArray(),
						    &ok).toBase64());

			if(ok)
			  query.bindValue
			    (15, s_crypt->encrypted(QByteArray("NoProxy"),
						    &ok).toBase64());

			if(ok)
			  query.bindValue
			    (16, s_crypt->encrypted(QByteArray(), &ok).
			     toBase64());

			if(ok)
			  query.bindValue
			    (17, s_crypt->
			     encrypted("{00000000-0000-0000-0000-"
				       "000000000000}", &ok).
			     toBase64());

			if(ok)
			  query.bindValue
			    (18, s_crypt->
			     encrypted(hash["echo_mode"], &ok).toBase64());

			if(hash["transport"] == "tcp")
			  query.bindValue
			    (19, hash["ssl_key_size"].toInt());
			else
			  query.bindValue(19, 0);

			query.bindValue(20, 0);

			if(ok)
			  query.bindValue
			    (21, s_crypt->encrypted(QByteArray(),
						    &ok).toBase64());

			if(hash["transport"] == "tcp")
			  query.bindValue(22, 1);
			else
			  query.bindValue(22, 0);

			if(ok)
			  query.bindValue
			    (23, s_crypt->encrypted(QByteArray(),
						    &ok).toBase64());

			if(ok)
			  query.bindValue
			    (24, s_crypt->encrypted(QByteArray(),
						    &ok).toBase64());

			if(ok)
			  query.bindValue
			    (25,
			     s_crypt->encrypted(hash["transport"],
						&ok).toBase64());

			if(ok)
			  query.bindValue
			    (26, s_crypt->encrypted(hash["orientation"],
						    &ok).toBase64());

			if(ok)
			  query.exec();
		      }
		  }
	      }

	    file.close();
	  }

	db.close();
      }

      QSqlDatabase::removeDatabase(connectionName);
      QApplication::restoreOverrideCursor();
    }
}
