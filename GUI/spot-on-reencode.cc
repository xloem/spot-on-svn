/*
** Copyright (c) 2011, 2012, 2013 Alexis Megas
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
#include <QSqlRecord>

#include <limits>

#include "Common/spot-on-crypt.h"
#include "Common/spot-on-misc.h"
#include "spot-on-reencode.h"

spoton_reencode::spoton_reencode(void)
{
}

spoton_reencode::~spoton_reencode()
{
}

void spoton_reencode::reencode(Ui_statusbar sb,
			       spoton_crypt *newCrypt,
			       spoton_crypt *oldCrypt)
{
  if(!newCrypt || !oldCrypt)
    return;

  QApplication::setOverrideCursor(QCursor(Qt::WaitCursor));
  sb.status->setText
    (QObject::tr("Re-encoding email.db."));
  QApplication::processEvents();
  spoton_misc::prepareDatabases();

  {
    QSqlDatabase db = QSqlDatabase::addDatabase
      ("QSQLITE", "spoton_reencode");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "email.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec("SELECT date, goldbug, message, message_digest, "
		      "participant_oid, "
		      "receiver_sender, status, subject, OID FROM folders"))
	  while(query.next())
	    {
	      QList<QByteArray> list;
	      bool ok = true;

	      for(int i = 0; i < query.record().count(); i++)
		if(i >= 0 && i <= 7)
		  {
		    QByteArray bytes
		      (oldCrypt->decrypted(QByteArray::
					   fromBase64(query.value(i).
						      toByteArray()), &ok));

		    if(ok)
		      list.append(bytes);
		    else
		      break;
		  }

	      if(ok)
		if(!list.isEmpty())
		  {
		    QSqlQuery updateQuery(db);

		    updateQuery.prepare("UPDATE folders SET "
					"date = ?, goldbug = ?, "
					"message = ?, message_digest = ?, "
					"participant_oid = ?, "
					"receiver_sender = ?, "
					"status = ?, "
					"subject = ?, hash = ? "
					"WHERE OID = ?");

		    for(int i = 0; i < list.size(); i++)
		      if(ok)
			updateQuery.bindValue
			  (i, newCrypt->encrypted(list.at(i), &ok).
			   toBase64());
		      else
			break;

		    if(ok)
		      updateQuery.bindValue
			(8, newCrypt->keyedHash(list.value(2) +
						list.value(7), &ok).
			 toBase64());

		    if(ok)
		      {
			updateQuery.bindValue(9, query.value(8));
			updateQuery.exec();
		      }
		  }
	    }

	if(query.exec("SELECT date_received, message_bundle, "
		      "participant_hash, OID "
		      "FROM post_office"))
	  while(query.next())
	    {
	      QByteArray dateReceived;
	      QByteArray messageBundle;
	      QByteArray participantHash;
	      QSqlQuery updateQuery(db);
	      bool ok = true;

	      updateQuery.prepare("UPDATE post_office "
				  "SET date_received = ?, "
				  "message_bundle = ?, "
				  "message_bundle_hash = ?, "
				  "participant_hash = ? "
				  "WHERE "
				  "OID = ?");

	      dateReceived = oldCrypt->decrypted
		(QByteArray::
		 fromBase64(query.value(0).toByteArray()),
		 &ok);

	      if(ok)
		messageBundle = oldCrypt->decrypted
		  (QByteArray::
		   fromBase64(query.value(1).toByteArray()),
		   &ok);

	      if(ok)
		participantHash = oldCrypt->decrypted
		  (QByteArray::
		   fromBase64(query.value(2).toByteArray()),
		   &ok);

	      if(ok)
		updateQuery.bindValue
		  (0, newCrypt->encrypted(dateReceived,
					  &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (1, newCrypt->encrypted(messageBundle,
					  &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (2, newCrypt->keyedHash(messageBundle,
					  &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (3, newCrypt->encrypted(participantHash,
					  &ok).toBase64());

	      updateQuery.bindValue(4, query.value(3));

	      if(ok)
		updateQuery.exec();
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton_reencode");
  sb.status->setText
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
  sb.status->setText
    (QObject::tr("Re-encoding portions of idiotes.db."));

  {
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE", "spoton_reencode");

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "idiotes.db");

    if(db.open())
      {
	QSqlQuery query(db);
	bool ok = true;

	query.setForwardOnly(true);

	if(query.exec("SELECT certificate FROM certificates "
		      "WHERE id = 'neighbor'"))
	  if(query.next())
	    {
	      QByteArray certificate;
	      QSqlQuery updateQuery(db);

	      certificate = QByteArray::fromBase64(query.value(0).
						   toByteArray());

	      if(ok)
		certificate = oldCrypt->decrypted(certificate, &ok);

	      updateQuery.prepare("UPDATE certificates SET "
				  "certificate = ? "
				  "WHERE id = 'neighbor'");

	      if(ok)
		updateQuery.bindValue
		  (0, newCrypt->encrypted(certificate, &ok).toBase64());

	      if(ok)
		updateQuery.exec();
	    }

	if(query.exec("SELECT id, private_key, public_key "
		      "FROM idiotes WHERE id IN ('kernel', 'neighbor')"))
	  while(query.next())
	    {
	      QByteArray privateKey;
	      QByteArray publicKey;
	      QSqlQuery updateQuery(db);

	      privateKey = QByteArray::fromBase64(query.value(1).
						  toByteArray());
	      publicKey = QByteArray::fromBase64(query.value(2).
						 toByteArray());

	      if(ok)
		privateKey = oldCrypt->decrypted(privateKey, &ok);

	      if(ok)
		publicKey = oldCrypt->decrypted(publicKey, &ok);

	      updateQuery.prepare("UPDATE idiotes SET "
				  "private_key = ?, "
				  "public_key = ? "
				  "WHERE id = ?");

	      if(ok)
		updateQuery.bindValue
		  (0, newCrypt->encrypted(privateKey, &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (1, newCrypt->encrypted(publicKey, &ok).toBase64());

	      updateQuery.bindValue(2, query.value(0));

	      if(ok)
		updateQuery.exec();
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton_reencode");
  sb.status->setText
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
		      "protocol, certificate, "
		      "private_key, public_key, hash FROM listeners"))
	  while(query.next())
	    {
	      QByteArray certificate;
	      QByteArray privateKey;
	      QByteArray publicKey;
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
				  "hash = ?, "
				  "certificate = ?, "
				  "private_key = ?, "
				  "public_key = ? "
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
		certificate = oldCrypt->decrypted
		  (QByteArray::fromBase64(query.value(4).toByteArray()),
		   &ok);

	      if(ok)
		privateKey = oldCrypt->decrypted
		  (QByteArray::fromBase64(query.value(5).toByteArray()),
		   &ok);

	      if(ok)
		publicKey = oldCrypt->decrypted
		  (QByteArray::fromBase64(query.value(6).toByteArray()),
		   &ok);

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
		  (5, newCrypt->encrypted(certificate, &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (6, newCrypt->encrypted(privateKey, &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (7, newCrypt->encrypted(publicKey, &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (8, query.value(7));

	      if(ok)
		updateQuery.exec();
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton_reencode");
  sb.status->setText
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
		      "scope_id, country, hash, proxy_hostname, "
		      "proxy_password, proxy_port, proxy_type, "
		      "proxy_username FROM neighbors"))
	  while(query.next())
	    {
	      QSqlQuery updateQuery(db);
	      QString country("");
	      QString ipAddress("");
	      QString port("");
	      QString proxyHostname("");
	      QString proxyPassword("");
	      QString proxyPort("1");
	      QString proxyType("");
	      QString proxyUsername("");
	      QString scopeId("");
	      bool ok = true;

	      updateQuery.prepare("UPDATE neighbors "
				  "SET remote_ip_address = ?, "
				  "remote_port = ?, "
				  "scope_id = ?, "
				  "country = ?, "
				  "hash = ?, "
				  "remote_ip_address_hash = ?, "
				  "qt_country_hash = ?, "
				  "proxy_hostname = ?, "
				  "proxy_password = ?, "
				  "proxy_port = ?, "
				  "proxy_type = ?, "
				  "proxy_username = ? "
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
		proxyHostname = oldCrypt->decrypted(QByteArray::
						    fromBase64(query.
							       value(5).
							       toByteArray()),
						    &ok).constData();

	      if(ok)
		proxyPassword = oldCrypt->decrypted(QByteArray::
						    fromBase64(query.
							       value(6).
							       toByteArray()),
						    &ok).constData();

	      if(ok)
		proxyPort = oldCrypt->decrypted(QByteArray::
						fromBase64(query.
							   value(7).
							   toByteArray()),
						&ok).constData();

	      if(ok)
		proxyType = oldCrypt->decrypted(QByteArray::
						fromBase64(query.
							   value(8).
							   toByteArray()),
						&ok).constData();

	      if(ok)
		proxyUsername = oldCrypt->decrypted(QByteArray::
						    fromBase64(query.
							       value(9).
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
		  (7, newCrypt->encrypted(proxyHostname.toLatin1(), &ok).
		   toBase64());

	      if(ok)
		updateQuery.bindValue
		  (8, newCrypt->encrypted(proxyPassword.toUtf8(), &ok).
		   toBase64());

	      if(ok)
		updateQuery.bindValue
		  (9, newCrypt->encrypted(proxyPort.toLatin1(), &ok).
		   toBase64());

	      if(ok)
		updateQuery.bindValue
		  (10, newCrypt->encrypted(proxyType.toLatin1(), &ok).
		   toBase64());

	      if(ok)
		updateQuery.bindValue
		  (11, newCrypt->encrypted(proxyUsername.toUtf8(), &ok).
		   toBase64());

	      if(ok)
		updateQuery.bindValue
		  (12, query.value(4));

	      if(ok)
		updateQuery.exec();
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton_reencode");
  QApplication::restoreOverrideCursor();
  sb.status->clear();
}
