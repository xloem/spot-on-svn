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
  spoton_misc::prepareDatabases();

  {
    QSqlDatabase db = QSqlDatabase::addDatabase
      ("QSQLITE", "spoton_reencode");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "country_inclusion.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec("SELECT country, accepted, country_hash FROM "
		      "country_inclusion"))
	  while(query.next())
	    {
	      QSqlQuery updateQuery(db);
	      QString country("");
	      bool accepted = true;
	      bool ok = true;

	      updateQuery.prepare("UPDATE country_inclusion "
				  "SET country = ?, "
				  "accepted = ?, "
				  "country_hash = ? WHERE "
				  "country_hash = ?");
	      country = oldCrypt->decrypted(QByteArray::
					    fromBase64(query.
						       value(0).
						       toByteArray()),
					    &ok).constData();

	      if(ok)
		accepted = oldCrypt->decrypted(QByteArray::
					       fromBase64(query.
							  value(1).
							  toByteArray()),
					       &ok).toInt();

	      if(ok)
		updateQuery.bindValue
		  (0, newCrypt->encrypted(country.toLatin1(),
					  &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (1, newCrypt->encrypted(QString::number(accepted).
					  toLatin1(), &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (2,
		   newCrypt->keyedHash(country.toLatin1(),
				       &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (3, query.value(2));

	      if(ok)
		updateQuery.exec();
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton_reencode");
  ui->statusBar()->showMessage
    (QObject::tr("Re-encoding listeners.db."));
  QApplication::processEvents();
  spoton_misc::prepareDatabases();

  {
    QSqlDatabase db = QSqlDatabase::addDatabase
      ("QSQLITE", "spoton_reencode");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "listeners.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec("SELECT ip_address, port, scope_id, "
		      "protocol, hash FROM listeners"))
	  while(query.next())
	    {
	      QSqlQuery updateQuery(db);
	      QString ipAddress("");
	      QString port("");
	      QString protocol("");
	      QString scopeId("");
	      bool ok = true;

	      updateQuery.prepare("UPDATE listeners "
				  "SET ip_address = ?, "
				  "port = ?, "
				  "scope_id = ?, "
				  "protocol = ?, "
				  "hash = ? "
				  "WHERE hash = ?");
	      ipAddress = oldCrypt->decrypted(QByteArray::
					      fromBase64(query.
							 value(0).
							 toByteArray()),
					      &ok).constData();

	      if(ok)
		port = oldCrypt->decrypted(QByteArray::
					   fromBase64(query.
						      value(1).
						      toByteArray()),
					   &ok).constData();

	      if(ok)
		scopeId = oldCrypt->decrypted(QByteArray::
					      fromBase64(query.
							 value(2).
							 toByteArray()),
					      &ok).constData();

	      if(ok)
		protocol = oldCrypt->decrypted(QByteArray::
					       fromBase64(query.
							  value(3).
							  toByteArray()),
					       &ok).constData();

	      if(ok)
		updateQuery.bindValue
		  (0, newCrypt->encrypted(ipAddress.
					  toLatin1(), &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (1, newCrypt->encrypted(port.toLatin1(), &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (2, newCrypt->encrypted(scopeId.toLatin1(), &ok).
		   toBase64());

	      if(ok)
		updateQuery.bindValue
		  (3, newCrypt->encrypted(protocol.toLatin1(), &ok).
		   toBase64());

	      if(ok)
		updateQuery.bindValue
		  (4, newCrypt->keyedHash((ipAddress + port).toLatin1(),
					  &ok).
		   toBase64());

	      if(ok)
		updateQuery.bindValue
		  (5, query.value(4));

	      if(ok)
		updateQuery.exec();
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton_reencode");
  ui->statusBar()->showMessage
    (QObject::tr("Re-encoding neighbors.db."));
  QApplication::processEvents();
  spoton_misc::prepareDatabases();

  {
    QSqlDatabase db = QSqlDatabase::addDatabase
      ("QSQLITE", "spoton_reencode");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "neighbors.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec("SELECT remote_ip_address, remote_port, "
		      "scope_id, country, hash FROM neighbors"))
	  while(query.next())
	    {
	      QSqlQuery updateQuery(db);
	      QString country("");
	      QString ipAddress("");
	      QString port("");
	      QString scopeId("");
	      bool ok = true;

	      updateQuery.prepare("UPDATE neighbors "
				  "SET remote_ip_address = ?, "
				  "remote_port = ?, "
				  "scope_id = ?, "
				  "country = ?, "
				  "hash = ?, "
				  "remote_ip_address_hash = ?, "
				  "qt_country_hash = ? "
				  "WHERE hash = ?");
	      ipAddress = oldCrypt->decrypted(QByteArray::
					      fromBase64(query.
							 value(0).
							 toByteArray()),
					      &ok).constData();

	      if(ok)
		port = oldCrypt->decrypted(QByteArray::
					   fromBase64(query.
						      value(1).
						      toByteArray()),
					   &ok).constData();

	      if(ok)
		scopeId = oldCrypt->decrypted(QByteArray::
					      fromBase64(query.
							 value(2).
							 toByteArray()),
					      &ok).constData();

	      if(ok)
		country = oldCrypt->decrypted(QByteArray::
					      fromBase64(query.
							 value(3).
							 toByteArray()),
					      &ok).constData();

	      if(ok)
		updateQuery.bindValue
		  (0, newCrypt->encrypted(ipAddress.
					  toLatin1(), &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (1, newCrypt->encrypted(port.toLatin1(), &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (2, newCrypt->encrypted(scopeId.toLatin1(), &ok).
		   toBase64());

	      if(ok)
		updateQuery.bindValue
		  (3, newCrypt->encrypted(country.toLatin1(), &ok).
		   toBase64());

	      if(ok)
		updateQuery.bindValue
		  (4, newCrypt->keyedHash((ipAddress + port).toLatin1(),
					  &ok).
		   toBase64());

	      if(ok)
		updateQuery.bindValue
		  (5, newCrypt->keyedHash(ipAddress.toLatin1(), &ok).
		   toBase64());

	      if(ok)
		updateQuery.bindValue
		  (6, newCrypt->keyedHash(country.toLatin1(), &ok).
		   toBase64());

	      if(ok)
		updateQuery.bindValue
		  (7, query.value(4));

	      if(ok)
		updateQuery.exec();
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton_reencode");
  QApplication::restoreOverrideCursor();
}
