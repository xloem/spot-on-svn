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

void spoton::slotPrepareUrlDatabases(void)
{
  QProgressDialog progress(this);

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
  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  spoton_misc::prepareUrlDatabases(&progress);
  QApplication::restoreOverrideCursor();
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
  deleteAllUrls();
  QApplication::restoreOverrideCursor();
}

void spoton::deleteAllUrls(void)
{
  QDir dir(spoton_misc::homePath());

  if(dir.cd("spot-on_URLs"))
    {
      for(int i = 0; i < 26; i++)
	for(int j = 0; j < 26; j++)
	  dir.remove(QString("spot-on_urls_%1%2.db").
		     arg(static_cast<char> (i + 97)).
		     arg(static_cast<char> (j + 97)));

      dir.remove("spot-on_keyword_indices");
    }

  QDir(spoton_misc::homePath()).rmdir("spot-on_URLs");
}

void spoton::slotGatherUrlStatistics(void)
{
  if(!m_gatherUrlStatisticsFuture.isFinished())
    return;

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

	QFileInfo fileInfo
	  (QString("%1%2%3%2spot-on_urls_%4%5.db").
	   arg(spoton_misc::homePath()).
	   arg(QDir::separator()).
	   arg("spot-on_URLs").
	   arg(static_cast<char> (i + 97)).
	   arg(static_cast<char> (j + 97)));

	size += fileInfo.size();

	QString connectionName("");

	{
	  QSqlDatabase db = spoton_misc::database(connectionName);

	  db.setDatabaseName(fileInfo.absolutePath());

	  if(db.open())
	    {
	      QSqlQuery query(db);

	      if(query.exec("SELECT COUNT(*) FROM urls"))
		if(query.next())
		  count += query.value(0).toLongLong();
	    }

	  db.close();
	}

	QSqlDatabase::removeDatabase(connectionName);
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
  QList<QList<QVariant> > list;
  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "shared.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec("SELECT description, encrypted, title, url "
		      "FROM urls"))
	  {
	    int processed = 0;

	    while(query.next())
	      {
		processed += 1;

		if(processed > 100)
		  break;

		QByteArray description;
		QByteArray title;
		QByteArray url;
		bool encrypted = query.value(1).toBool();
		bool ok = true;

		if(encrypted)
		  {
		    spoton_crypt *s_crypt = m_crypts.value("url", 0);

		    if(!s_crypt)
		      continue;

		    /*
		    ** We need to determine the encryption key that was
		    ** used to encrypt the URLs shared by another application.
		    */

		    spoton_crypt crypt
		      ("aes256",
		       QString(""),
		       QByteArray(),
		       QByteArray(),
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
		  {
		    QList<QVariant> variants;

		    variants << description << title << url;
		    list.append(variants);
		  }

		QSqlQuery deleteQuery(db);

		deleteQuery.prepare("DELETE FROM urls WHERE url = ?");
		deleteQuery.bindValue(0, query.value(3));
		deleteQuery.exec();
	      }
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  spoton_crypt *s_crypt = m_crypts.value("url", 0);

  spoton_misc::populateUrlsDatabase(list, s_crypt);
}
