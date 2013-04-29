/*
** Copyright (c) 2013 Alexis Megas
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
#include <QDir>
#include <QFile>
#include <QSqlDatabase>
#include <QSqlQuery>

#include <limits>

#include "Common/spot-on-gcrypt.h"
#include "Common/spot-on-misc.h"
#include "spot-on-reencode.h"

spoton_reencode::spoton_reencode(void)
{
}

spoton_reencode::~spoton_reencode()
{
}

void spoton_reencode::reencode(spoton *ui,
			       spoton_gcrypt *newCrypt,
			       spoton_gcrypt *oldCrypt)
{
  if(!newCrypt || !oldCrypt || !ui)
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  ui->statusBar()->showMessage
    (QObject::tr("Re-encoding country_inclusion.db."));
  QApplication::processEvents();
  QFile::remove(spoton_misc::homePath() + QDir::separator() +
		"country_inclusion.db");
  spoton_misc::prepareDatabases();

  {
    QSqlDatabase db = QSqlDatabase::addDatabase
      ("QSQLITE", "spoton_reencode");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "country_inclusion.db");

    if(db.open())
      {
	for(int i = 0; i < ui->ui().countries->count(); i++)
	  {
	    QListWidgetItem *item = ui->ui().countries->item(i);

	    if(!item)
	      continue;

	    QSqlQuery query(db);
	    bool ok = true;

	    query.prepare("INSERT INTO country_inclusion "
			  "(country, accepted, hash) "
			  "VALUES (?, ?, ?)");
	    query.bindValue
	      (0, newCrypt->encrypted(item->text().toLatin1(),
				      &ok).toBase64());

	    if(ok)
	      query.bindValue
		(1, newCrypt->encrypted(QString::number(item->
							checkState() ==
							Qt::Checked).
					toLatin1(), &ok).
		 toBase64());

	    if(ok)
	      query.bindValue
		(2,
		 newCrypt->keyedHash(item->text().toLatin1(),
				     &ok).toBase64());

	    if(ok)
	      query.exec();
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton_reencode");
  ui->statusBar()->showMessage
    (QObject::tr("Re-encoding listeners.db."));
  QApplication::processEvents();
  QFile::remove(spoton_misc::homePath() + QDir::separator() +
		"listeners.db");
  spoton_misc::prepareDatabases();

  {
    QSqlDatabase db = QSqlDatabase::addDatabase
      ("QSQLITE", "spoton_reencode");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "listeners.db");

    if(db.open())
      {
	for(int i = 0; i < ui->ui().listeners->rowCount(); i++)
	  {
	    QSqlQuery query(db);
	    bool ok = true;

	    query.prepare("INSERT INTO listeners "
			  "(status_control, "
			  "status, "
			  "ip_address, "
			  "port, "
			  "scope_id, "
			  "protocol, "
			  "external_ip_address, "
			  "external_port, "
			  "connections, "
			  "maximum_clients, "
			  "hash) "
			  "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");

	    for(int j = 0; j < ui->ui().listeners->columnCount(); j++)
	      if(j == 0)
		{
		  QCheckBox *checkBox =
		    qobject_cast<QCheckBox *> (ui->ui().
					       listeners->
					       cellWidget(i, j));

		  if(checkBox && checkBox->isChecked())
		    query.bindValue(j, "online");
		  else
		    query.bindValue(j, "off");
		}
	      else if(j == 1)
		query.bindValue(j, "off");
	      else if(j >= 2 && j <= 5)
		{
		  if(ok)
		    {
		      QTableWidgetItem *item = ui->ui().listeners->item(i, j);

		      if(item)
			query.bindValue
			  (j, newCrypt->encrypted(item->text().
						  toLatin1(), &ok).
			   toBase64());
		    }
		}
	      else if(j >= 6 && j <= 7)
		{
		  QTableWidgetItem *item = ui->ui().listeners->
		    item(i, j);

		  if(item)
		    query.bindValue(j, item->text());
		}
	      else if(j == 8)
		query.bindValue(j, 0);
	      else if(j == 9)
		{
		  QComboBox *comboBox = qobject_cast<QComboBox *>
		    (ui->ui().listeners->cellWidget(i, j));

		  if(comboBox)
		    {
		      if(comboBox->currentIndex() != comboBox->count() - 1)
			query.bindValue
			  (j, 5 * (comboBox->currentIndex() + 1));
		      else
			query.bindValue(j, std::numeric_limits<int>::max());
		    }
		  else
		    query.bindValue(j, 5);
		}
 
	    if(ok)
	      {
		QTableWidgetItem *item1 = ui->ui().listeners->
		  item(i, 2);
		QTableWidgetItem *item2 = ui->ui().listeners->
		  item(i, 3);

		if(item1 && item2)
		  query.bindValue
		    (10, newCrypt->keyedHash((item1->text() +
					      item2->text()).toLatin1(),
					     &ok).
		     toBase64());
	      }

	    if(ok)
	      query.exec();
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton_reencode");
  ui->statusBar()->showMessage
    (QObject::tr("Re-encoding neighbors.db."));
  QApplication::processEvents();
  QFile::remove(spoton_misc::homePath() + QDir::separator() +
		"neighbors.db");
  spoton_misc::prepareDatabases();

  {
    QSqlDatabase db = QSqlDatabase::addDatabase
      ("QSQLITE", "spoton_reencode");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "neighbors.db");

    if(db.open())
      {
	for(int i = 0; i < ui->ui().neighbors->rowCount(); i++)
	  {
	    QSqlQuery query(db);
	    bool ok = true;

	    query.prepare("INSERT INTO neighbors "
			  "(sticky, "
			  "uuid, "
			  "status, "
			  "local_ip_address, "
			  "local_port, "
			  "external_ip_address, "
			  "external_port, "
			  "country, "
			  "remote_ip_address, "
			  "remote_port, "
			  "scope_id, "
			  "protocol, "
			  "hash, "
			  "remote_ip_address_hash, "
			  "qt_country_hash) "
			  "VALUES (?, ?, ?, ?, ?, ?, ?, "
			  "?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");

	    for(int j = 0; j < ui->ui().neighbors->columnCount(); j++)
	      if(j == 0)
		{
		  QCheckBox *checkBox =
		    qobject_cast<QCheckBox *> (ui->ui().
					       neighbors->
					       cellWidget(i, j));

		  if(checkBox && checkBox->isChecked())
		    query.bindValue(j, 1);
		  else
		    query.bindValue(j, 0);
		}
	      else if(j >= 1 && j <= 6)
		{
		  QTableWidgetItem *item = ui->ui().neighbors->
		    item(i, j);

		  if(item)
		    query.bindValue(j, item->text());
		}
	      else if(j >= 7 && j <= 10)
		{
		  if(ok)
		    {
		      QTableWidgetItem *item =
			ui->ui().neighbors->item(i, j);

		      if(item)
			query.bindValue
			  (j, newCrypt->encrypted(item->text().
						  toLatin1(), &ok).
			   toBase64());
		    }
		}

	    if(ok)
	      query.exec();
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton_reencode");
  QApplication::restoreOverrideCursor();
}
