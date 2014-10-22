/*
** Copyright (c) 2011 - 10^10^10, Alexis Megas.
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

#include <QDir>
#include <QFileInfo>
#include <QMessageBox>
#include <QProgressDialog>
#if QT_VERSION >= 0x050000
#include <QtConcurrent>
#endif
#include <QtCore>

#include "spot-on.h"
#include "spot-on-defines.h"
#include "ui_postgresqlconnect.h"

void spoton::slotPrepareUrlDatabases(void)
{
  QProgressDialog progress(this);
  bool created = true;

#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
  progress.setAttribute(Qt::WA_MacMetalStyle, true);
#endif
#endif
  progress.setLabelText(tr("Creating URL databases..."));
  progress.setMaximum(26 * 26);
  progress.setMinimum(0);
  progress.setWindowTitle(tr("%1: Creating URL Databases").
    arg(SPOTON_APPLICATION_NAME));
  progress.show();
  progress.update();
  QDir().mkdir(spoton_misc::homePath() + QDir::separator() + "spot-on_URLs");

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "spot-on_URLs" +
       QDir::separator() + "spot-on_key_information.db");

    if(db.open())
      {
	QSqlQuery query(db);

	if(!query.exec("CREATE TABLE IF NOT EXISTS key_information ("
		       "cipher_type TEXT NOT NULL, "
		       "symmetric_key TEXT PRIMARY KEY NOT NULL)"))
	  created = false;

	if(!query.exec("CREATE TRIGGER IF NOT EXISTS key_information_trigger "
		       "BEFORE INSERT ON key_information "
		       "BEGIN "
		       "DELETE FROM key_information; "
		       "END"))
	  created = false;
      }
    else
      created = false;

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  for(int i = 0, processed = 0; i < 26 && !progress.wasCanceled(); i++)
    for(int j = 0; j < 26 && !progress.wasCanceled(); j++)
      {
	if(processed <= progress.maximum())
	  progress.setValue(processed);

	  if(m_urlDatabase.open())
	    {
	      QSqlQuery query(m_urlDatabase);

	      if(!query.exec(QString("CREATE TABLE IF NOT EXISTS "
				     "keywords_%1%2 ("
				     "keyword_hash TEXT NOT NULL, "
				     "url_hash TEXT NOT NULL, "
				     "PRIMARY KEY (keyword_hash, url_hash))").
			     arg(QChar(i + 97)).arg(QChar(j + 97))))
		created = false;

	      if(!query.exec(QString("CREATE TABLE IF NOT EXISTS urls_%1%2 ("
				     "date_time_inserted TEXT NOT NULL, "
				     "description BLOB, "
				     "title BLOB NOT NULL, "
				     "url BLOB NOT NULL, "
				     "url_hash TEXT PRIMARY KEY NOT NULL)").
			     arg(QChar(i + 97)).arg(QChar(j + 97))))
		created = false;
	    }
	  else
	    created = false;

	  processed += 1;
	  progress.update();
#ifndef Q_OS_MAC
	  QApplication::processEvents();
#endif
      }

  if(!created)
    QMessageBox::critical(this, tr("%1: Error").
			  arg(SPOTON_APPLICATION_NAME),
			  tr("One or more errors occurred while attempting "
			     "to create the URL databases."));
}

void spoton::slotDeleteAllUrls(void)
{
  QMessageBox mb(this);

#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
  mb.setAttribute(Qt::WA_MacMetalStyle, true);
#endif
#endif
  mb.setIcon(QMessageBox::Question);
  mb.setWindowTitle(tr("%1: Confirmation").
		    arg(SPOTON_APPLICATION_NAME));
  mb.setWindowModality(Qt::WindowModal);
  mb.setStandardButtons(QMessageBox::No | QMessageBox::Yes);
  mb.setText(tr("Are you sure that you wish to remove all of the "
		"URL databases?"));

  if(mb.exec() != QMessageBox::Yes)
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  bool deleted = deleteAllUrls();
  QApplication::restoreOverrideCursor();

  if(!deleted)
    QMessageBox::critical(this, tr("%1: Error").
			  arg(SPOTON_APPLICATION_NAME),
			  tr("One or more errors occurred while "
			     "attempting to remove the URL databases."));
}

bool spoton::deleteAllUrls(void) const
{
  QDir dir(spoton_misc::homePath());

  if(!dir.exists("spot-on_URLs"))
    return true;

  bool deleted = true;

  if(dir.cd("spot-on_URLs"))
    {
      for(int i = 0; i < 26; i++)
	for(int j = 0; j < 26; j++)
	  {
	    QString fileName(QString("spot-on_urls_%1%2.db").
			     arg(static_cast<char> (i + 97)).
			     arg(static_cast<char> (j + 97)));

	    if(dir.exists(fileName))
	      if(!dir.remove(fileName))
		deleted = false;
	  }

      if(dir.exists("spot-on_key_information.db"))
	if(!dir.remove("spot-on_key_information.db"))
	  deleted = false;
    }
  else
    deleted = false;

  if(!QDir(spoton_misc::homePath()).rmdir("spot-on_URLs"))
    deleted = false;

  return deleted;
}

void spoton::slotGatherUrlStatistics(void)
{
  if(!m_gatherUrlStatisticsFuture.isFinished())
    return;
  else if(!m_urlDatabase.isOpen())
    {
      emit urlStatisticsGathered(0, 0);
      return;
    }

  m_ui.gatherStatistics->setEnabled(false);
  m_gatherUrlStatisticsFuture = QtConcurrent::run
    (this, &spoton::gatherUrlStatistics);
}

void spoton::gatherUrlStatistics(void)
{
  qint64 count = 0;
  quint64 size = 0;

  for(int i = 0; i < 26; i++)
    for(int j = 0; j < 26; j++)
      {
	if(m_gatherUrlStatisticsFuture.isCanceled())
	  goto done_label;

	QSqlQuery query(m_urlDatabase);

	if(query.exec(QString("SELECT COUNT(*) FROM urls_%1%2").
		      arg(QChar(i + 97)).arg(QChar(i + 97))))
	  if(query.next())
	    count += query.value(0).toLongLong();
      }

 done_label:

  if(!m_gatherUrlStatisticsFuture.isCanceled())
    emit urlStatisticsGathered(count, size);
}

void spoton::slotUrlStatisticsGathered(const qint64 count,
				       const quint64 size)
{
  m_ui.gatherStatistics->setEnabled(true);
  m_ui.urlCount->setValue(static_cast<int> (count));
  m_ui.urlDatabasesSize->setValue(static_cast<int> (size / (1024 * 1024)));
}

void spoton::slotImportUrls(void)
{
  spoton_crypt *l_crypt = m_crypts.value("url", 0);

  if(!l_crypt)
    {
      QMessageBox::critical
	(this,
	 tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	 tr("Invalid spoton_crypt object. This is a fatal flaw."));
      return;
    }

  /*
  ** We need to determine the encryption key that was
  ** used to encrypt the URLs shared by another application.
  */

  QByteArray symmetricKey;
  QString cipherType("");
  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "spot-on_URLs" +
       QDir::separator() + "spot-on_key_information.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	query.setForwardOnly(true);

	if(query.exec("SELECT cipher_type, symmetric_key "
			 "FROM key_information") &&
	   query.next())
	  {
	    cipherType = l_crypt->decryptedAfterAuthenticated
	      (QByteArray::fromBase64(query.value(0).
				      toByteArray()),
	       &ok).constData();

	    if(ok)
	      symmetricKey = l_crypt->decryptedAfterAuthenticated
		(QByteArray::fromBase64(query.value(1).
					toByteArray()),
		 &ok);
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(cipherType.isEmpty() || symmetricKey.isEmpty())
    {
      QMessageBox::critical
	(this,
	 tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
	 tr("Unable to retrieve the cipher type and symmetric key."));
      return;
    }

  QProgressDialog progress(this);

#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
  progress.setAttribute(Qt::WA_MacMetalStyle, true);
#endif
#endif
  progress.setLabelText(tr("Importing URLs..."));
  progress.setMinimum(0);
  progress.setWindowTitle(tr("%1: Importing URLs").
			  arg(SPOTON_APPLICATION_NAME));
  progress.show();
  progress.update();

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "shared.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec("SELECT COUNT(*) from urls"))
	  if(query.next())
	    progress.setMaximum(query.value(0).toInt());

	if(query.exec("SELECT description, encrypted, title, url "
		      "FROM urls"))
	  {
	    int processed = 0;

	    while(query.next())
	      {
		if(progress.wasCanceled())
		  break;

		if(processed <= progress.maximum())
		  progress.setValue(processed);

		QByteArray description;
		QByteArray title;
		QByteArray url;
		bool encrypted = query.value(1).toBool();
		bool ok = true;

		if(encrypted)
		  {
		    spoton_crypt crypt
		      (cipherType,
		       QString(""),
		       QByteArray(),
		       symmetricKey,
		       0,
		       0,
		       QString(""));

		    description = crypt.decrypted
		      (query.value(0).toByteArray(), &ok);

		    if(ok)
		      title = crypt.decrypted
			(query.value(2).toByteArray(), &ok);

		    if(ok)
		      url = crypt.decrypted
			(query.value(3).toByteArray(), &ok);
		  }
		else
		  {
		    description = query.value(0).toByteArray();
		    title = query.value(2).toByteArray();
		    url = query.value(3).toByteArray();
		  }

		if(ok)
		  importUrl(description, title, url);

		QSqlQuery deleteQuery(db);

		deleteQuery.prepare("DELETE FROM urls WHERE url = ?");
		deleteQuery.bindValue(0, query.value(3));
		processed += 1;
		progress.update();
#ifndef Q_OS_MAC
		QApplication::processEvents();
#endif
	      }
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton::slotShowUrlSettings(void)
{
  m_ui.urlSettings->setVisible(!m_ui.urlSettings->isVisible());
}

void spoton::slotSelectUrlIniPath(void)
{
  QFileDialog dialog(this);

  dialog.setWindowTitle
    (tr("%1: Select INI Path").
     arg(SPOTON_APPLICATION_NAME));
  dialog.setFileMode(QFileDialog::ExistingFile);
  dialog.setFilter(QDir::AllEntries | QDir::Hidden);
  dialog.setDirectory(QDir::homePath());
  dialog.setLabelText(QFileDialog::Accept, tr("&Select"));
  dialog.setAcceptMode(QFileDialog::AcceptOpen);
#ifdef Q_OS_MAC
#if QT_VERSION < 0x050000
  dialog.setAttribute(Qt::WA_MacMetalStyle, false);
#endif
#endif

  if(dialog.exec() == QDialog::Accepted)
    saveUrlIniPath(dialog.selectedFiles().value(0));
}

void spoton::saveUrlIniPath(const QString &path)
{
  if(path.isEmpty())
    return;

  m_settings["gui/urlIniPath"] = path;

  QSettings settings;

  settings.setValue("gui/urlIniPath", path);
  m_ui.urlIniPath->setText(path);
  m_ui.urlIniPath->setToolTip(path);
  m_ui.urlIniPath->selectAll();

  {
    QSettings settings(path, QSettings::IniFormat);

    for(int i = 0; i < settings.allKeys().size(); i++)
      {
	QString key(settings.allKeys().at(i));
	QVariant value(settings.value(key));

	if(key.toLower().contains("ciphertype"))
	  {
	    if(m_ui.urlCipher->findText(value.toString()) >= 0)
	      m_ui.urlCipher->setCurrentIndex
		(m_ui.urlCipher->findText(value.toString()));
	  }
	else if(key.toLower().contains("hash") &&
		value.toByteArray().length() >= 64)
	  m_ui.urlIniHash->setText(value.toByteArray().toHex());
	else if(key.toLower().contains("hashtype"))
	  {
	    if(m_ui.urlHash->findText(value.toString()) >= 0)
	      m_ui.urlHash->setCurrentIndex
		(m_ui.urlHash->findText(value.toString()));
	  }
	else if(key.toLower().contains("iteration"))
	  m_ui.urlIteration->setValue(value.toInt());
	else if(key.toLower().contains("salt") &&
		value.toByteArray().length() >= 100)
	  m_ui.urlSalt->setText(value.toByteArray().toHex());
      }
  }
}

void spoton::slotSetUrlIniPath(void)
{
  saveUrlIniPath(m_ui.urlIniPath->text());
}

void spoton::slotVerify(void)
{
  QByteArray computedHash;
  QByteArray salt
    (QByteArray::fromHex(m_ui.urlSalt->text().toLatin1()));
  QByteArray saltedPassphraseHash
    (QByteArray::fromHex(m_ui.urlIniHash->text().toLatin1()));
  QString error("");
  bool ok = false;

  computedHash = spoton_crypt::saltedPassphraseHash
    (m_ui.urlHash->currentText(), m_ui.urlPassphrase->text(), salt, error);

  if(!computedHash.isEmpty() && !saltedPassphraseHash.isEmpty() &&
     spoton_crypt::memcmp(computedHash, saltedPassphraseHash))
    if(error.isEmpty())
      ok = true;

  if(ok)
    QMessageBox::information
      (this, tr("%1: Information").
       arg(SPOTON_APPLICATION_NAME),
       tr("The provided credentials appear correct. Please save the "
	  "information."));
  else
    QMessageBox::information
      (this, tr("%1: Information").
       arg(SPOTON_APPLICATION_NAME),
       tr("The provided credentials are incorrect."));
}

void spoton::slotSaveUrlCredentials(void)
{
  QByteArray salt
    (QByteArray::fromHex(m_ui.urlSalt->text().toLatin1()));
  QPair<QByteArray, QByteArray> keys;
  QString error("");
  spoton_crypt *crypt = m_crypts.value("url", 0);

  if(!crypt)
    {
      error = tr("Invalid spoton_crypt object. This is a fatal flaw.");
      goto done_label;
    }

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  keys = spoton_crypt::derivedKeys(m_ui.urlCipher->currentText(),
				   m_ui.urlHash->currentText(),
				   m_ui.urlIteration->value(),
				   m_ui.urlPassphrase->text(),
				   salt,
				   64, // Dooble.
				   error);
  QApplication::restoreOverrideCursor();

  if(error.isEmpty())
    {
      QString connectionName("");

      {
	QSqlDatabase db = spoton_misc::database(connectionName);

	db.setDatabaseName
	  (spoton_misc::homePath() + QDir::separator() + "spot-on_URLs" +
	   QDir::separator() + "spot-on_key_information.db");

	if(db.open())
	  {
	    QSqlQuery query(db);
	    bool ok = true;

	    query.prepare
	      ("INSERT OR REPLACE INTO key_information "
	       "(cipher_type, symmetric_key) "
	       "VALUES (?, ?)");
	    query.bindValue
	      (0, crypt->encryptedThenHashed(m_ui.urlCipher->currentText().
					     toLatin1(),
					     &ok).toBase64());

	    if(ok)
	      query.bindValue
		(1, crypt->
		 encryptedThenHashed(keys.first, &ok).toBase64());

	    if(ok)
	      {
		if(!query.exec())
		  error = tr("Database write error.");
	      }
	    else
	      error = tr("An error occurred with "
			 "spoton_crypt::encryptedThenHashed().");
	  }
	else
	  error = tr("Unable to access spot-on_key_information.db.");

	db.close();
      }

      QSqlDatabase::removeDatabase(connectionName);
    }
  else
    error = tr("Key generation failure.");

 done_label:

  if(!error.isEmpty())
    QMessageBox::critical(this,
			  tr("%1: Error").arg(SPOTON_APPLICATION_NAME),
			  error);
  else
    m_ui.urlPassphrase->clear();
}

void spoton::importUrl(const QByteArray &description,
		       const QByteArray &title,
		       const QByteArray &url)
{
  Q_UNUSED(description);
  Q_UNUSED(title);
  Q_UNUSED(url);
}

void spoton::slotPostgreSQLConnect(void)
{
  QDialog dialog(this);
  Ui_postgresqlconnect ui;

  dialog.setWindowTitle
    (tr("%1: PostgreSQL Connect").
     arg(SPOTON_APPLICATION_NAME));
  ui.setupUi(&dialog);
#ifdef Q_OS_MAC
  dialog.setAttribute(Qt::WA_MacMetalStyle, false);
#endif

  if(dialog.exec() == QDialog::Accepted)
    {
      m_urlDatabase.close();
      m_urlDatabase = QSqlDatabase();

      if(QSqlDatabase::contains("PostgreSQL"))
	QSqlDatabase::removeDatabase("PostgreSQL");

      m_urlDatabase = QSqlDatabase::addDatabase("PostgreSQL");
      m_urlDatabase.setHostName(ui.host->text());
      m_urlDatabase.setDatabaseName(ui.database->text());
      m_urlDatabase.open(ui.name->text(), ui.password->text());

      if(!m_urlDatabase.isOpen())
	{
	  m_urlDatabase = QSqlDatabase();
	  QSqlDatabase::removeDatabase("PostgreSQL");
	}
    }
}
