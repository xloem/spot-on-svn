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
	  m_ui.etpEncryptionKey->setText
	    (spoton_crypt::
	     strongRandomBytes(m_ui.etpEncryptionKey->maxLength()).
	     toBase64());
	  m_ui.etpMacKey->setText
	    (spoton_crypt::
	     strongRandomBytes(m_ui.etpMacKey->maxLength()).
	     toBase64());
	}
      else if(index == 1)
	m_ui.etpEncryptionKey->setText
	  (spoton_crypt::
	   strongRandomBytes(m_ui.etpEncryptionKey->maxLength()).
	   toBase64());
      else if(index == 2)
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
		     "mk=%4").
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
    }

  if(tokens != 4)
    {
      error = tr("Invalid magnet.");
      goto done_label;
    }

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "etp_magnets.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.prepare("INSERT OR REPLACE INTO "
		      "etp_magnets "
		      "(magnet, magnet_hash) "
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
		     "etp_magnets.db");

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
	int row = 0;

	m_ui.etpMagnets->setSortingEnabled(false);
	m_ui.etpMagnets->clearContents();
	m_ui.etpMagnets->setRowCount(0);
	m_ui.etpTransmittersMagnets->setSortingEnabled(false);
	m_ui.etpTransmittersMagnets->clearContents();
	m_ui.etpTransmittersMagnets->setRowCount(0);
	query.setForwardOnly(true);

	if(query.exec("SELECT magnet, OID FROM etp_magnets"))
	  while(query.next())
	    {
	      QByteArray bytes;
	      bool ok = true;

	      bytes = s_crypt->decrypted
		(QByteArray::fromBase64(query.value(0).toByteArray()), &ok);

	      QCheckBox *box = new QCheckBox();
	      QTableWidgetItem *item = new QTableWidgetItem
		(bytes.constData());

	      item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
	      m_ui.etpMagnets->setRowCount(row + 1);
	      m_ui.etpMagnets->setItem(row, 0, item);
	      box->setText(bytes.replace("&", "&&").constData());
	      m_ui.etpTransmittersMagnets->setRowCount(row + 1);
	      m_ui.etpTransmittersMagnets->setCellWidget(row, 0, box);
	      item = new QTableWidgetItem(query.value(1).toString());
	      item->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
	      m_ui.etpMagnets->setItem(row, 1, item);
	      m_ui.etpTransmittersMagnets->setItem(row, 1, item->clone());
	      row += 1;
	    }

	m_ui.etpMagnets->resizeColumnsToContents();
	m_ui.etpMagnets->setSortingEnabled(true);
	m_ui.etpTransmittersMagnets->resizeColumnsToContents();
	m_ui.etpTransmittersMagnets->setSortingEnabled(true);
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
		       "etp_magnets.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.exec("DELETE FROM etp_magnets");
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
      (spoton_misc::homePath() + QDir::separator() + "etp_magnets.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.prepare("DELETE FROM etp_magnets WHERE OID = ?");
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
      QTableWidgetItem *item = m_ui.etpMagnets->item(row, 0); // Magnet

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

  dialog.setFilter(
#if defined Q_OS_LINUX || defined Q_OS_MAC || defined Q_OS_UNIX
		   QDir::Dirs | QDir::Readable
#else
		   QDir::AllDirs
#endif
		   );
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
