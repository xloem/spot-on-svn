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
  spoton_misc::prepareDatabases();

  QString connectionName("");
  QString error("");
  QString magnet("");
  QStringList list;
  bool ok = true;
  int tokens = 0;
  spoton_crypt *s_crypt = m_crypts.value("chat", 0);

  if(!s_crypt)
    {
      error = tr("Invalid spoton_crypt object.");
      goto done_label;
    }

  if(m_ui.magnetRadio->isChecked())
    magnet = m_ui.etpMagnet->text().trimmed();
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

  list = QString(magnet).remove("magnet:?").split('&');

  while(!list.isEmpty())
    {
      QString str(list.takeFirst());

      if(str.startsWith("ct="))
	{
	  str.remove(0, 3);
	  tokens += str.trimmed().isEmpty() ? 0 : 1;
	}
      else if(str.startsWith("ek="))
	{
	  str.remove(0, 3);
	  tokens += str.trimmed().isEmpty() ? 0 : 1;
	}
      else if(str.startsWith("ht="))
	{
	  str.remove(0, 3);
	  tokens += str.trimmed().isEmpty() ? 0 : 1;
	}
      else if(str.startsWith("mk="))
	{
	  str.remove(0, 3);
	  tokens += str.trimmed().isEmpty() ? 0 : 1;
	}
      else if(str.startsWith("xt="))
	{
	  str.remove(0, 3);
	  tokens += str.trimmed().isEmpty() ? 0 : 1;
	}
    }

  if(tokens != 5)
    {
      error = tr("Invalid magnet.");
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
	QWidget *focusWidget = QApplication::focusWidget();
	int row = 0;

	m_ui.etpMagnets->setSortingEnabled(false);
	m_ui.etpMagnets->clearContents();
	m_ui.etpMagnets->setRowCount(0);
	m_ui.transmittersMagnets->setSortingEnabled(false);
	m_ui.transmittersMagnets->clearContents();
	m_ui.transmittersMagnets->setRowCount(0);
	query.setForwardOnly(true);

	if(query.exec("SELECT magnet, one_time_magnet, "
		      "OID FROM magnets"))
	  while(query.next())
	    {
	      QByteArray bytes;
	      bool ok = true;

	      bytes = s_crypt->decrypted
		(QByteArray::fromBase64(query.value(0).toByteArray()), &ok);

	      QCheckBox *checkBox = new QCheckBox();
	      QTableWidgetItem *item = new QTableWidgetItem
		(bytes.constData());

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
	      m_ui.transmittersMagnets->setRowCount(row + 1);
	      checkBox = new QCheckBox();
	      checkBox->setText(bytes.replace("&", "&&").constData());
	      m_ui.transmittersMagnets->setCellWidget(row, 0, checkBox);
	      item = new QTableWidgetItem(query.value(2).toString());
	      item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
	      m_ui.etpMagnets->setItem(row, 2, item);
	      m_ui.transmittersMagnets->setItem(row, 1, item->clone());
	      row += 1;
	    }

	m_ui.etpMagnets->setSortingEnabled(true);
	m_ui.transmittersMagnets->resizeColumnsToContents();
	m_ui.transmittersMagnets->setSortingEnabled(true);

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
    (tr("Spot-On: Select Destination Path"));
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

void spoton::slotMaxMosaics(int value)
{
  m_settings["gui/maxMosaics"] = value;

  QSettings settings;

  settings.setValue("gui/maxMosaics", value);
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
	int row = 0;

	query.setForwardOnly(true);

	if(query.exec("SELECT statistic, value FROM kernel_statistics "
		      "ORDER BY statistic"))
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
	      row += 1;
	    }

	m_ui.kernelStatistics->setSortingEnabled(true);
	m_ui.kernelStatistics->resizeColumnsToContents();
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
    (tr("Spot-On: Select Transmit File"));
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
      error = tr("Invalid spoton_crypt object.");
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
      error = tr("The provided file does not exist.");
      goto done_label;
    }

  for(int i = 0; i < m_ui.transmittersMagnets->rowCount(); i++)
    {
      QCheckBox *checkBox = qobject_cast<QCheckBox *>
	(m_ui.transmittersMagnets->cellWidget(i, 0));

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
	QByteArray mosaic(spoton_crypt::strongRandomBytes(256).toBase64());
	QSqlQuery query(db);

	query.prepare("INSERT INTO transmitted "
		      "(file, mosaic, muted, pulse_size, "
		      "status, total_size) "
		      "VALUES (?, ?, ?, ?, ?, ?)");
	query.bindValue
	  (0, s_crypt->encrypted(m_ui.transmittedFile->text().toUtf8(),
				 &ok).toBase64());

	if(ok)
	  {
	    encryptedMosaic = s_crypt->encrypted(mosaic, &ok);

	    if(ok)
	      query.bindValue(1, encryptedMosaic.toBase64());
	  }

	query.bindValue(2, 1);

	if(ok)
	  query.bindValue
	    (3, s_crypt->
	     encrypted(QString::number(m_ui.pulseSize->
				       value()).toLatin1(), &ok).toBase64());

	query.bindValue(4, "transmitted");

	if(ok)
	  query.bindValue
	    (5, s_crypt->
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
	      break;

	    query.prepare("DELETE FROM magnets WHERE "
			  "magnet_hash = ? AND one_time_magnet = 1");
	    query.bindValue
	      (0, s_crypt->keyedHash(magnets.at(i), &ok).toBase64());

	    if(ok)
	      query.exec();
	    else
	      break;

	    if(query.lastError().isValid())
	      break;
	  }
      }

    if(db.lastError().isValid())
      error = tr("A database error (%1) occurred.").
	arg(db.lastError().text());
    else if(!ok)
      error = tr("An error occurred within spoton_crypt.");

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

 done_label:

  if(!error.isEmpty())
    QMessageBox::critical(this, tr("Spot-On: Error"), error);
  else
    m_ui.transmittedFile->clear();
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
	QString mosaic("");
	QSqlQuery query(db);
	QWidget *focusWidget = QApplication::focusWidget();
	int hval = 0;
	int row = -1;
	int vval = 0;

	query.setForwardOnly(true);

	/*
	** First, retrieved.
	*/

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
	query.prepare("SELECT muted, 0, pulse_size, total_size, "
		      "status, file, mosaic, OID "
		      "FROM transmitted");

	if(query.exec())
	  while(query.next())
	    {
	      m_ui.transmitted->setRowCount(row + 1);

	      QCheckBox *checkBox = new QCheckBox();
	      bool ok = true;

	      checkBox->setChecked(query.value(0).toInt());
	      checkBox->setProperty
		("oid", query.value(query.record().count() - 1));
	      connect(checkBox,
		      SIGNAL(toggled(bool)),
		      this,
		      SLOT(slotTransmittedMuted(bool)));
	      m_ui.transmitted->setCellWidget(row, 0, checkBox);

	      for(int i = 0; i < query.record().count(); i++)
		{
		  QTableWidgetItem *item = 0;

		  if(i == 0)
		    {
		      // Ignore.
		    }
		  else if(i == 2 || i == 3 || i == 5 || i == 6)
		    item = new QTableWidgetItem
		      (s_crypt->
		       decrypted(QByteArray::fromBase64(query.value(i).
							toByteArray()),
				 &ok).constData());
		  else if(i == 1)
		    item = new QTableWidgetItem("0");
		  else if(i == 4)
		    item = new QTableWidgetItem
		      (QString::
		       fromUtf8(s_crypt->
				decrypted(QByteArray::
					  fromBase64(query.value(i).
						     toByteArray()),
					  &ok).constData()));
		  else if(i == 6)
		    item = new QTableWidgetItem("0");
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

void spoton::slotTransmittedMuted(bool state)
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
			  "muted = ? "
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
	    query.exec("DELETE FROM transmitted_pulses");
	  }
	else
	  query.exec("UPDATE transmitted SET "
		     "status = 'deleted' WHERE "
		     "status <> 'deleted'");
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotDeleteTransmitted(void)
{
}
