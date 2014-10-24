/*
** Copyright (c) 2011 - 10^10^10, Alexis Megas.
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

  QString connectionName("");

  sb.status->setText
    (QObject::tr("Re-encoding buzz_channels.db."));
  sb.status->repaint();

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "buzz_channels.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec("SELECT data, data_hash FROM buzz_channels"))
	  while(query.next())
	    {
	      QByteArray data;
	      QSqlQuery updateQuery(db);
	      bool ok = true;

	      updateQuery.prepare("UPDATE buzz_channels "
				  "SET data = ?, "
				  "data_hash = ? WHERE "
				  "data_hash = ?");
	      data = oldCrypt->decryptedAfterAuthenticated
		(QByteArray::fromBase64(query.value(0).toByteArray()),
		 &ok);

	      if(ok)
		updateQuery.bindValue
		  (0, newCrypt->encryptedThenHashed(data, &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (1,
		   newCrypt->keyedHash(data,
				       &ok).toBase64());

	      updateQuery.bindValue
		(2, query.value(1));

	      if(ok)
		updateQuery.exec();
	      else
		{
		  QSqlQuery deleteQuery(db);

		  deleteQuery.prepare("DELETE FROM buzz_channels WHERE "
				      "data_hash = ?");
		  deleteQuery.bindValue(0, query.value(1));
		  deleteQuery.exec();
		}
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  sb.status->setText
    (QObject::tr("Re-encoding email.db."));
  sb.status->repaint();

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "email.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec("SELECT date, goldbug, message, message_code, "
		      "participant_oid, "
		      "receiver_sender, status, subject, "
		      "OID FROM folders"))
	  while(query.next())
	    {
	      QList<QByteArray> list;
	      bool ok = true;

	      for(int i = 0; i < query.record().count() - 1; i++)
		{
		  QByteArray bytes;

		  bytes = oldCrypt->decryptedAfterAuthenticated
		    (QByteArray::
		     fromBase64(query.value(i).
				toByteArray()), &ok);

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
					"date = ?, "
					"goldbug = ?, "
					"message = ?, "
					"message_code = ?, "
					"participant_oid = ?, "
					"receiver_sender = ?, "
					"status = ?, "
					"subject = ?, "
					"hash = ? "
					"WHERE OID = ?");

		    for(int i = 0; i < list.size(); i++)
		      if(ok)
			updateQuery.bindValue
			  (i, newCrypt->encryptedThenHashed(list.at(i),
							    &ok).
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
			updateQuery.bindValue
			  (9, query.value(query.record().count() - 1));
			updateQuery.exec();
		      }
		    else
		      {
			QSqlQuery deleteQuery(db);

			deleteQuery.prepare("DELETE FROM folders WHERE "
					    "OID = ?");
			deleteQuery.bindValue
			  (0, query.value(query.record().count() - 1));
			deleteQuery.exec();
			deleteQuery.prepare
			  ("DELETE FROM folders_attachment WHERE "
			   "folders_oid = ?");
			deleteQuery.bindValue
			  (0, query.value(query.record().count() - 1));
			deleteQuery.exec();
		      }
		  }
	    }

	if(query.exec("SELECT data, name, OID FROM folders_attachment"))
	  while(query.next())
	    {
	      QList<QByteArray> list;
	      bool ok = true;

	      for(int i = 0; i < query.record().count() - 1; i++)
		{
		  QByteArray bytes;

		  bytes = oldCrypt->decryptedAfterAuthenticated
		    (QByteArray::
		     fromBase64(query.value(i).
				toByteArray()), &ok);

		  if(ok)
		    list.append(bytes);
		  else
		    break;
		}

	      if(ok)
		if(!list.isEmpty())
		  {
		    QSqlQuery updateQuery(db);

		    updateQuery.prepare("UPDATE folders_attachment SET "
					"data = ?, "
					"name = ? "
					"WHERE OID = ?");

		    for(int i = 0; i < list.size(); i++)
		      if(ok)
			updateQuery.bindValue
			  (i, newCrypt->encryptedThenHashed(list.at(i),
							    &ok).
			   toBase64());
		      else
			break;

		    updateQuery.bindValue
		      (2, query.value(2));

		    if(ok)
		      updateQuery.exec();
		    else
		      {
			QSqlQuery deleteQuery(db);

			deleteQuery.prepare
			  ("DELETE FROM folders_attachment WHERE "
			   "OID = ?");
			deleteQuery.bindValue
			  (0, query.value(query.record().count() - 1));
			deleteQuery.exec();
		      }
		  }
	    }

	if(query.exec("SELECT cipher_type, hash_type, name, postal_address, "
		      "OID FROM institutions"))
	  while(query.next())
	    {
	      QByteArray cipherType;
	      QByteArray hashType;
	      QByteArray name;
	      QByteArray postalAddress;
	      QSqlQuery updateQuery(db);
	      bool ok = true;

	      updateQuery.prepare("UPDATE institutions "
				  "SET "
				  "cipher_type = ?, "
				  "hash_type = ?, "
				  "name = ?, "
				  "postal_address = ?, "
				  "hash = ? "
				  "WHERE "
				  "OID = ?");

	      cipherType = oldCrypt->decryptedAfterAuthenticated
		(QByteArray::
		 fromBase64(query.value(0).toByteArray()),
		 &ok);

	      if(ok)
		hashType = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::
		   fromBase64(query.value(1).toByteArray()),
		   &ok);

	      if(ok)
		name = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::
		   fromBase64(query.value(2).toByteArray()),
		   &ok);

	      if(ok)
		postalAddress = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::
		   fromBase64(query.value(3).toByteArray()),
		   &ok);

	      if(ok)
		updateQuery.bindValue
		  (0, newCrypt->encryptedThenHashed(cipherType,
						    &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (1, newCrypt->encryptedThenHashed(hashType,
						    &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (2, newCrypt->encryptedThenHashed(name,
						    &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (3, newCrypt->encryptedThenHashed(postalAddress,
						    &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (4, newCrypt->keyedHash(name,
					  &ok).toBase64());

	      updateQuery.bindValue(5, query.value(4));

	      if(ok)
		updateQuery.exec();
	      else
		{
		  QSqlQuery deleteQuery(db);

		  deleteQuery.prepare("DELETE FROM institutions WHERE "
				      "OID = ?");
		  deleteQuery.bindValue(0, query.value(4));
		  deleteQuery.exec();
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

	      dateReceived = oldCrypt->decryptedAfterAuthenticated
		(QByteArray::
		 fromBase64(query.value(0).toByteArray()),
		 &ok);

	      if(ok)
		messageBundle = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::
		   fromBase64(query.value(1).toByteArray()),
		   &ok);

	      if(ok)
		participantHash = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::
		   fromBase64(query.value(2).toByteArray()),
		   &ok);

	      if(ok)
		updateQuery.bindValue
		  (0, newCrypt->encryptedThenHashed(dateReceived,
						    &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (1, newCrypt->encryptedThenHashed(messageBundle,
						    &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (2, newCrypt->keyedHash(messageBundle,
					  &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (3, newCrypt->encryptedThenHashed(participantHash,
						    &ok).toBase64());

	      updateQuery.bindValue(4, query.value(3));

	      if(ok)
		updateQuery.exec();
	      else
		{
		  QSqlQuery deleteQuery(db);

		  deleteQuery.prepare("DELETE FROM post_office WHERE "
				      "OID = ?");
		  deleteQuery.bindValue(0, query.value(3));
		  deleteQuery.exec();
		}
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  sb.status->setText
    (QObject::tr("Re-encoding friends_public_keys.db."));
  sb.status->repaint();

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "friends_public_keys.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec("SELECT gemini, gemini_hash_key, public_key_hash, "
		      "public_key, key_type FROM "
		      "friends_public_keys"))
	  while(query.next())
	    {
	      QByteArray gemini;
	      QByteArray geminiHashKey;
	      QByteArray keyType;
	      QByteArray publicKey;
	      QSqlQuery updateQuery(db);
	      bool ok = true;

	      updateQuery.prepare("UPDATE friends_public_keys "
				  "SET gemini = ?, "
				  "gemini_hash_key = ?, "
				  "public_key = ?, "
				  "key_type = ?, "
				  "key_type_hash = ? "
				  "WHERE public_key_hash = ?");

	      if(!query.isNull(0))
		gemini = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(0).toByteArray()),
		   &ok);

	      if(ok)
		if(!query.isNull(1))
		  geminiHashKey = oldCrypt->decryptedAfterAuthenticated
		    (QByteArray::fromBase64(query.value(1).toByteArray()),
		     &ok);

	      if(ok)
		publicKey = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(3).toByteArray()),
		   &ok);

	      if(ok)
		keyType = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(4).toByteArray()),
		   &ok);

	      if(ok)
		{
		  if(query.isNull(0))
		    updateQuery.bindValue(0, QVariant::String);
		  else
		    updateQuery.bindValue
		      (0, newCrypt->encryptedThenHashed(gemini,
							&ok).toBase64());
		}

	      if(ok)
		{
		  if(query.isNull(1))
		    updateQuery.bindValue(1, QVariant::String);
		  else
		    updateQuery.bindValue
		      (1,
		       newCrypt->encryptedThenHashed(geminiHashKey,
						     &ok).toBase64());
		}

	      if(ok)
		updateQuery.bindValue
		  (2,
		   newCrypt->encryptedThenHashed(publicKey,
						 &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (3,
		   newCrypt->encryptedThenHashed(keyType,
						 &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (4,
		   newCrypt->keyedHash(keyType, &ok).toBase64());

	      updateQuery.bindValue
		(5, query.value(2));

	      if(ok)
		updateQuery.exec();
	      else
		{
		  QSqlQuery deleteQuery(db);

		  deleteQuery.prepare("DELETE FROM friends_public_keys "
				      "WHERE public_key_hash = ?");
		  deleteQuery.bindValue(0, query.value(2));
		  deleteQuery.exec();
		}
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  sb.status->setText
    (QObject::tr("Re-encoding listeners.db."));
  sb.status->repaint();

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "listeners.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec("SELECT ip_address, port, scope_id, "
		      "protocol, echo_mode, certificate, private_key, "
		      "public_key, transport, orientation, "
		      "hash FROM listeners"))
	  while(query.next())
	    {
	      QByteArray certificate;
	      QByteArray privateKey;
	      QByteArray publicKey;
	      QSqlQuery updateQuery(db);
	      QString echoMode("");
	      QString ipAddress("");
	      QString orientation("");
	      QString port("");
	      QString protocol("");
	      QString scopeId("");
	      QString transport("");
	      bool ok = true;

	      updateQuery.prepare("UPDATE listeners "
				  "SET ip_address = ?, "
				  "port = ?, "
				  "scope_id = ?, "
				  "protocol = ?, "
				  "hash = ?, "
				  "echo_mode = ?, "
				  "certificate = ?, "
				  "private_key = ?, "
				  "public_key = ?, "
				  "transport = ?, "
				  "orientation = ? "
				  "WHERE hash = ?");
	      ipAddress = oldCrypt->decryptedAfterAuthenticated
		(QByteArray::
		 fromBase64(query.
			    value(0).
			    toByteArray()),
		 &ok).constData();

	      if(ok)
		port = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::
		   fromBase64(query.
			      value(1).
			      toByteArray()),
		   &ok).constData();

	      if(ok)
		scopeId = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::
		   fromBase64(query.
			      value(2).
			      toByteArray()),
		   &ok).constData();

	      if(ok)
		protocol = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::
		   fromBase64(query.
			      value(3).
			      toByteArray()),
		   &ok).constData();

	      if(ok)
		echoMode = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::
		   fromBase64(query.
			      value(4).
			      toByteArray()),
		   &ok).constData();

	      if(ok)
		certificate = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::
		   fromBase64(query.
			      value(5).
			      toByteArray()),
		   &ok);

	      if(ok)
		privateKey = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::
		   fromBase64(query.
			      value(6).
			      toByteArray()),
		   &ok);

	      if(ok)
		publicKey = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::
		   fromBase64(query.
			      value(7).
			      toByteArray()),
		   &ok);

	      if(ok)
		transport = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::
		   fromBase64(query.
			      value(8).
			      toByteArray()),
		   &ok).constData();

	      if(ok)
		orientation = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::
		   fromBase64(query.
			      value(9).
			      toByteArray()),
		   &ok).constData();

	      if(ok)
		updateQuery.bindValue
		  (0, newCrypt->encryptedThenHashed
		   (ipAddress.
		    toLatin1(), &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (1, newCrypt->encryptedThenHashed(port.toLatin1(),
						    &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (2, newCrypt->encryptedThenHashed(scopeId.toLatin1(), &ok).
		   toBase64());

	      if(ok)
		updateQuery.bindValue
		  (3, newCrypt->encryptedThenHashed(protocol.toLatin1(), &ok).
		   toBase64());

	      if(ok)
		updateQuery.bindValue
		  (4, newCrypt->keyedHash((ipAddress + port + scopeId +
					   transport).
					  toLatin1(), &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (5, newCrypt->
		   encryptedThenHashed(echoMode.toLatin1(), &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (6, newCrypt->encryptedThenHashed(certificate,
						    &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (7, newCrypt->encryptedThenHashed(privateKey,
						    &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (8, newCrypt->encryptedThenHashed(publicKey,
						    &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (9, newCrypt->encryptedThenHashed(transport.toLatin1(),
						    &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (10, newCrypt->encryptedThenHashed(orientation.toLatin1(),
						     &ok).toBase64());

	      updateQuery.bindValue
		(11, query.value(10));

	      if(ok)
		updateQuery.exec();
	      else
		{
		  QSqlQuery deleteQuery(db);

		  deleteQuery.prepare("DELETE FROM listeners WHERE "
				      "hash = ?");
		  deleteQuery.bindValue(0, query.value(10));
		  deleteQuery.exec();
		  deleteQuery.exec("DELETE FROM listeners_accounts "
				   "WHERE listener_oid NOT IN "
				   "(SELECT OID FROM listeners)");
		  deleteQuery.exec("DELETE FROM listeners_allowed_ips "
				   "WHERE listener_oid NOT IN "
				   "(SELECT OID FROM listeners)");
		}
	    }

	if(query.exec("SELECT account_name, account_name_hash, "
		      "account_password FROM listeners_accounts"))
	  while(query.next())
	    {
	      QByteArray name;
	      QByteArray password;
	      QSqlQuery updateQuery(db);
	      bool ok = true;

	      updateQuery.prepare("UPDATE listeners_accounts "
				  "SET account_name = ?, "
				  "account_name_hash = ?, "
				  "account_password = ? "
				  "WHERE account_name_hash = ?");
	      name = oldCrypt->decryptedAfterAuthenticated
		(QByteArray::
		 fromBase64(query.
			    value(0).
			    toByteArray()),
		 &ok);

	      if(ok)
		password = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::
		   fromBase64(query.
			      value(2).
			      toByteArray()),
		   &ok);

	      if(ok)
		updateQuery.bindValue
		  (0, newCrypt->encryptedThenHashed(name, &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (1, newCrypt->keyedHash(name, &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (2, newCrypt->encryptedThenHashed(password,
						    &ok).toBase64());

	      updateQuery.bindValue(3, query.value(1));

	      if(ok)
		updateQuery.exec();
	      else
		{
		  QSqlQuery deleteQuery(db);

		  deleteQuery.prepare("DELETE FROM listeners_accounts WHERE "
				      "account_name_hash = ?");
		  deleteQuery.bindValue(0, query.value(1));
		  deleteQuery.exec();
		}
	    }

	if(query.exec("SELECT token, token_hash, token_type "
		      "FROM listeners_adaptive_echo_tokens"))
	  while(query.next())
	    {
	      QByteArray token;
	      QByteArray tokenType;
	      QSqlQuery updateQuery(db);
	      bool ok = true;

	      updateQuery.prepare("UPDATE listeners_adaptive_echo_tokens "
				  "SET token = ?, "
				  "token_hash = ?, "
				  "token_type = ? "
				  "WHERE token_hash = ?");
	      token = oldCrypt->decryptedAfterAuthenticated
		(QByteArray::
		 fromBase64(query.
			    value(0).
			    toByteArray()),
		 &ok);

	      if(ok)
		tokenType = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::
		   fromBase64(query.
			      value(2).
			      toByteArray()),
		   &ok);

	      if(ok)
		updateQuery.bindValue
		  (0, newCrypt->encryptedThenHashed(token, &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (1, newCrypt->keyedHash(token + tokenType,
					  &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (2, newCrypt->encryptedThenHashed(tokenType,
						    &ok).toBase64());

	      updateQuery.bindValue(3, query.value(1));

	      if(ok)
		updateQuery.exec();
	      else
		{
		  QSqlQuery deleteQuery(db);

		  deleteQuery.prepare
		    ("DELETE FROM listeners_adaptive_echo_tokens WHERE "
		     "token_hash = ?");
		  deleteQuery.bindValue(0, query.value(1));
		  deleteQuery.exec();
		}
	    }

	if(query.exec("SELECT ip_address, ip_address_hash "
		      "FROM listeners_allowed_ips"))
	  while(query.next())
	    {
	      QByteArray ip;
	      QSqlQuery updateQuery(db);
	      bool ok = true;

	      updateQuery.prepare("UPDATE listeners_allowed_ips "
				  "SET ip_address = ?, "
				  "ip_address_hash = ? "
				  "WHERE ip_address_hash = ?");
	      ip = oldCrypt->decryptedAfterAuthenticated
		(QByteArray::
		 fromBase64(query.
			    value(0).
			    toByteArray()),
		 &ok);

	      if(ok)
		updateQuery.bindValue
		  (0, newCrypt->encryptedThenHashed(ip, &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (1, newCrypt->keyedHash(ip, &ok).toBase64());

	      updateQuery.bindValue(2, query.value(1));

	      if(ok)
		updateQuery.exec();
	      else
		{
		  QSqlQuery deleteQuery(db);

		  deleteQuery.prepare("DELETE FROM listeners_allowed_ips "
				      "WHERE "
				      "ip_address_hash = ?");
		  deleteQuery.bindValue(0, query.value(1));
		  deleteQuery.exec();
		}
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  sb.status->setText
    (QObject::tr("Re-encoding neighbors.db."));
  sb.status->repaint();

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "neighbors.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec("SELECT remote_ip_address, remote_port, "
		      "scope_id, country, hash, proxy_hostname, "
		      "proxy_password, proxy_port, proxy_type, "
		      "proxy_username, uuid, "
		      "echo_mode, certificate, protocol, "
		      "account_name, account_password, transport, "
		      "orientation, ae_token, ae_token_type "
		      "FROM neighbors"))
	  while(query.next())
	    {
	      QByteArray peerCertificate;
	      QByteArray uuid;
	      QSqlQuery updateQuery(db);
	      QString accountName("");
	      QString accountPassword("");
	      QString aeToken("");
	      QString aeTokenType("");
	      QString country("");
	      QString echoMode("");
	      QString ipAddress("");
	      QString orientation("");
	      QString port("");
	      QString protocol("");
	      QString proxyHostname("");
	      QString proxyPassword("");
	      QString proxyPort("1");
	      QString proxyType("");
	      QString proxyUsername("");
	      QString scopeId("");
	      QString transport("");
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
				  "proxy_username = ?, "
				  "uuid = ?, "
				  "echo_mode = ?, "
				  "certificate = ?, "
				  "protocol = ?, "
				  "ssl_session_cipher = NULL, "
				  "account_name = ?, "
				  "account_password = ?, "
				  "account_authenticated = NULL, "
				  "transport = ?, "
				  "orientation = ?, "
				  "ae_token = ?, "
				  "ae_token_type = ? "
				  "WHERE hash = ?");
	      ipAddress = oldCrypt->decryptedAfterAuthenticated
		(QByteArray::
		 fromBase64(query.
			    value(0).
			    toByteArray()),
		 &ok).constData();

	      if(ok)
		port = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::
		   fromBase64(query.
			      value(1).
			      toByteArray()),
		   &ok).constData();

	      if(ok)
		scopeId = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::
		   fromBase64(query.
			      value(2).
			      toByteArray()),
		   &ok).constData();

	      if(ok)
		country = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::
		   fromBase64(query.
			      value(3).
			      toByteArray()),
		   &ok).constData();

	      if(ok)
		proxyHostname = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::
		   fromBase64(query.
			      value(5).
			      toByteArray()),
		   &ok).constData();

	      if(ok)
		proxyPassword = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::
		   fromBase64(query.
			      value(6).
			      toByteArray()),
		   &ok).constData();

	      if(ok)
		proxyPort = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::
		   fromBase64(query.
			      value(7).
			      toByteArray()),
		   &ok).constData();

	      if(ok)
		proxyType = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::
		   fromBase64(query.
			      value(8).
			      toByteArray()),
		   &ok).constData();

	      if(ok)
		proxyUsername = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::
		   fromBase64(query.
			      value(9).
			      toByteArray()),
		   &ok).constData();

	      if(ok)
		uuid = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::
		   fromBase64(query.
			      value(10).
			      toByteArray()),
		   &ok);

	      if(ok)
		echoMode = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::fromBase64(query.value(11).toByteArray()),
		   &ok).constData();

	      if(ok)
		peerCertificate = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::
		   fromBase64(query.
			      value(12).
			      toByteArray()),
		   &ok);

	      if(ok)
		protocol = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::
		   fromBase64(query.
			      value(13).
			      toByteArray()),
		   &ok).constData();

	      if(ok)
		accountName = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::
		   fromBase64(query.
			      value(14).
			      toByteArray()),
		   &ok).constData();

	      if(ok)
		accountPassword = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::
		   fromBase64(query.
			      value(15).
			      toByteArray()),
		   &ok).constData();

	      if(ok)
		transport = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::
		   fromBase64(query.
			      value(16).
			      toByteArray()),
		   &ok).constData();

	      if(ok)
		orientation = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::
		   fromBase64(query.
			      value(17).
			      toByteArray()),
		   &ok).constData();

	      if(ok)
		if(!query.isNull(18))
		  aeToken = oldCrypt->decryptedAfterAuthenticated
		    (QByteArray::
		     fromBase64(query.
				value(18).
				toByteArray()),
		     &ok).constData();

	      if(ok)
		if(!query.isNull(19))
		  aeTokenType = oldCrypt->decryptedAfterAuthenticated
		    (QByteArray::
		     fromBase64(query.
				value(19).
				toByteArray()),
		     &ok).constData();

	      if(ok)
		updateQuery.bindValue
		  (0, newCrypt->encryptedThenHashed(ipAddress.
						    toLatin1(),
						    &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (1, newCrypt->encryptedThenHashed(port.toLatin1(),
						    &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (2, newCrypt->encryptedThenHashed(scopeId.toLatin1(), &ok).
		   toBase64());

	      if(ok)
		updateQuery.bindValue
		  (3, newCrypt->encryptedThenHashed(country.toLatin1(), &ok).
		   toBase64());

	      if(ok)
		updateQuery.bindValue
		  (4, newCrypt->keyedHash((ipAddress + port + scopeId +
					   transport).toLatin1(), &ok).
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
		  (7, newCrypt->
		   encryptedThenHashed(proxyHostname.toLatin1(), &ok).
		   toBase64());

	      if(ok)
		updateQuery.bindValue
		  (8, newCrypt->encryptedThenHashed(proxyPassword.toUtf8(),
						    &ok).
		   toBase64());

	      if(ok)
		updateQuery.bindValue
		  (9, newCrypt->
		   encryptedThenHashed(proxyPort.toLatin1(), &ok).
		   toBase64());

	      if(ok)
		updateQuery.bindValue
		  (10, newCrypt->
		   encryptedThenHashed(proxyType.toLatin1(), &ok).
		   toBase64());

	      if(ok)
		updateQuery.bindValue
		  (11, newCrypt->
		   encryptedThenHashed(proxyUsername.toUtf8(), &ok).
		   toBase64());

	      if(ok)
		updateQuery.bindValue
		  (12, newCrypt->encryptedThenHashed(uuid, &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (13, newCrypt->encryptedThenHashed(echoMode.toLatin1(),
						     &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (14, newCrypt->encryptedThenHashed(peerCertificate, &ok).
		   toBase64());

	      if(ok)
		updateQuery.bindValue
		  (15, newCrypt->
		   encryptedThenHashed(protocol.toLatin1(), &ok).
		   toBase64());

	      if(ok)
		updateQuery.bindValue
		  (16, newCrypt->encryptedThenHashed
		   (accountName.toLatin1(), &ok).
		   toBase64());

	      if(ok)
		updateQuery.bindValue
		  (17, newCrypt->
		   encryptedThenHashed(accountPassword.toLatin1(),
				       &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (18, newCrypt->encryptedThenHashed(transport.toLatin1(),
						     &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (19, newCrypt->
		   encryptedThenHashed(orientation.toLatin1(), &ok).
		   toBase64());

	      if(ok)
		{
		  if(aeToken.isEmpty())
		    updateQuery.bindValue(20, QVariant::String);
		  else
		    updateQuery.bindValue
		      (20, newCrypt->
		       encryptedThenHashed(aeToken.toLatin1(), &ok).
		       toBase64());
		}

	      if(ok)
		{
		  if(aeTokenType.isEmpty())
		    updateQuery.bindValue(21, QVariant::String);
		  else
		    updateQuery.bindValue
		      (21, newCrypt->
		       encryptedThenHashed(aeTokenType.toLatin1(), &ok).
		       toBase64());
		}

	      updateQuery.bindValue
		(22, query.value(4));

	      if(ok)
		updateQuery.exec();
	      else
		{
		  QSqlQuery deleteQuery(db);

		  deleteQuery.prepare("DELETE FROM neighbors WHERE "
				      "hash = ?");
		  deleteQuery.bindValue(0, query.value(4));
		  deleteQuery.exec();
		}
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  sb.status->setText
    (QObject::tr("Re-encoding starbeam.db."));
  sb.status->repaint();

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "starbeam.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.setForwardOnly(true);

	if(query.exec("SELECT magnet, magnet_hash FROM magnets"))
	  while(query.next())
	    {
	      QByteArray magnet;
	      QSqlQuery updateQuery(db);
	      bool ok = true;

	      updateQuery.prepare("UPDATE magnets "
				  "SET magnet = ?, "
				  "magnet_hash = ? "
				  "WHERE magnet_hash = ?");
	      magnet = oldCrypt->decryptedAfterAuthenticated
		(QByteArray::
		 fromBase64(query.
			    value(0).
			    toByteArray()),
		 &ok);

	      if(ok)
		updateQuery.bindValue
		  (0, newCrypt->encryptedThenHashed(magnet,
						    &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (1,
		   newCrypt->keyedHash(magnet,
				       &ok).toBase64());

	      updateQuery.bindValue
		(2, query.value(1));

	      if(ok)
		updateQuery.exec();
	      else
		{
		  QSqlQuery deleteQuery(db);

		  deleteQuery.prepare("DELETE FROM magnets WHERE "
				      "magnet_hash = ?");
		  deleteQuery.bindValue(0, query.value(1));
		  deleteQuery.exec();
		}
	    }

	if(query.exec("SELECT file, file_hash, hash, pulse_size, total_size "
		      "FROM received"))
	  while(query.next())
	    {
	      QByteArray bytes;
	      QSqlQuery updateQuery(db);
	      bool ok = true;

	      updateQuery.prepare("UPDATE received "
				  "SET file = ?, "
				  "file_hash = ?, "
				  "hash = ?, "
				  "pulse_size = ?, "
				  "total_size = ? "
				  "WHERE file_hash = ?");
	      bytes = oldCrypt->decryptedAfterAuthenticated
		(QByteArray::
		 fromBase64(query.
			    value(0).
			    toByteArray()),
		 &ok);

	      if(ok)
		updateQuery.bindValue
		  (0, newCrypt->encryptedThenHashed(bytes, &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (1, newCrypt->keyedHash(bytes, &ok).toBase64());

	      if(ok)
		if(!query.isNull(2))
		  bytes = oldCrypt->decryptedAfterAuthenticated
		    (QByteArray::
		     fromBase64(query.
				value(2).
				toByteArray()),
		     &ok);

	      if(ok)
		{
		  if(query.isNull(2))
		    updateQuery.bindValue(2, QVariant::String);
		  else
		    updateQuery.bindValue
		      (2, newCrypt->
		       encryptedThenHashed(bytes, &ok).toBase64());
		}

	      if(ok)
		bytes = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::
		   fromBase64(query.
			      value(3).
			      toByteArray()),
		   &ok);

	      if(ok)
		updateQuery.bindValue
		  (3, newCrypt->encryptedThenHashed(bytes, &ok).toBase64());

	      if(ok)
		bytes = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::
		   fromBase64(query.
			      value(4).
			      toByteArray()),
		   &ok);

	      if(ok)
		updateQuery.bindValue
		  (4, newCrypt->encryptedThenHashed(bytes, &ok).toBase64());

	      updateQuery.bindValue(5, query.value(1));

	      if(ok)
		updateQuery.exec();
	      else
		{
		  QSqlQuery deleteQuery(db);

		  deleteQuery.prepare("DELETE FROM received WHERE "
				      "file_hash = ?");
		  deleteQuery.bindValue(0, query.value(1));
		  deleteQuery.exec();
		}
	    }

	if(query.exec("SELECT nova, nova_hash FROM received_novas"))
	  while(query.next())
	    {
	      QByteArray bytes;
	      QSqlQuery updateQuery(db);
	      bool ok = true;

	      updateQuery.prepare("UPDATE received_novas "
				  "SET nova = ?, "
				  "nova_hash = ? "
				  "WHERE nova_hash = ?");
	      bytes = oldCrypt->decryptedAfterAuthenticated
		(QByteArray::
		 fromBase64(query.
			    value(0).
			    toByteArray()),
		 &ok);

	      if(ok)
		updateQuery.bindValue
		  (0, newCrypt->encryptedThenHashed(bytes, &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (1, newCrypt->keyedHash(bytes, &ok).toBase64());

	      updateQuery.bindValue(2, query.value(1));

	      if(ok)
		updateQuery.exec();
	      else
		{
		  QSqlQuery deleteQuery(db);

		  deleteQuery.prepare("DELETE FROM received_novas WHERE "
				      "nova_hash = ?");
		  deleteQuery.bindValue(0, query.value(1));
		  deleteQuery.exec();
		}
	    }

	if(query.exec("SELECT file, hash, mosaic, nova, position, "
		      "pulse_size, total_size FROM transmitted"))
	  while(query.next())
	    {
	      QByteArray bytes;
	      QSqlQuery updateQuery(db);
	      bool ok = true;

	      updateQuery.prepare("UPDATE transmitted "
				  "SET file = ?, "
				  "hash = ?, "
				  "mosaic = ?, "
				  "nova = ?, "
				  "position = ?, "
				  "pulse_size = ?, "
				  "total_size = ? "
				  "WHERE mosaic = ?");
	      bytes = oldCrypt->decryptedAfterAuthenticated
		(QByteArray::
		 fromBase64(query.
			    value(0).
			    toByteArray()),
		 &ok);

	      if(ok)
		updateQuery.bindValue
		  (0, newCrypt->encryptedThenHashed(bytes, &ok).toBase64());

	      if(ok)
		bytes = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::
		   fromBase64(query.
			      value(1).
			      toByteArray()),
		   &ok);

	      if(ok)
		updateQuery.bindValue
		  (1, newCrypt->encryptedThenHashed(bytes, &ok).toBase64());

	      updateQuery.bindValue(2, query.value(2));

	      if(ok)
		bytes = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::
		   fromBase64(query.
			      value(3).
			      toByteArray()),
		   &ok);

	      if(ok)
		updateQuery.bindValue
		  (3, newCrypt->encryptedThenHashed(bytes, &ok).toBase64());

	      if(ok)
		bytes = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::
		   fromBase64(query.
			      value(4).
			      toByteArray()),
		   &ok);

	      if(ok)
		updateQuery.bindValue
		  (4, newCrypt->encryptedThenHashed(bytes, &ok).toBase64());

	      if(ok)
		bytes = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::
		   fromBase64(query.
			      value(5).
			      toByteArray()),
		   &ok);

	      if(ok)
		updateQuery.bindValue
		  (5, newCrypt->encryptedThenHashed(bytes, &ok).toBase64());

	      if(ok)
		bytes = oldCrypt->decryptedAfterAuthenticated
		  (QByteArray::
		   fromBase64(query.
			      value(6).
			      toByteArray()),
		   &ok);

	      if(ok)
		updateQuery.bindValue
		  (6, newCrypt->encryptedThenHashed(bytes, &ok).toBase64());

	      updateQuery.bindValue(7, query.value(2));

	      if(ok)
		updateQuery.exec();
	      else
		{
		  QSqlQuery deleteQuery(db);

		  deleteQuery.prepare("DELETE FROM transmitted WHERE "
				      "mosaic = ?");
		  deleteQuery.bindValue(0, query.value(2));
		  deleteQuery.exec();
		  deleteQuery.exec
		    ("DELETE FROM transmitted_magnets WHERE "
		     "transmitted_oid NOT IN "
		     "(SELECT OID FROM transmitted)");
		  deleteQuery.exec
		    ("DELETE FROM transmitted_scheduled_pulses WHERE "
		     "transmitted_oid NOT IN "
		     "(SELECT OID FROM transmitted)");
		}
	    }

	if(query.exec("SELECT magnet, magnet_hash FROM transmitted_magnets"))
	  while(query.next())
	    {
	      QByteArray magnet;
	      QSqlQuery updateQuery(db);
	      bool ok = true;

	      updateQuery.prepare("UPDATE transmitted_magnets "
				  "SET magnet = ?, "
				  "magnet_hash = ? "
				  "WHERE magnet_hash = ?");
	      magnet = oldCrypt->decryptedAfterAuthenticated
		(QByteArray::
		 fromBase64(query.
			    value(0).
			    toByteArray()),
		 &ok);

	      if(ok)
		updateQuery.bindValue
		  (0, newCrypt->encryptedThenHashed(magnet,
						    &ok).toBase64());

	      if(ok)
		updateQuery.bindValue
		  (1,
		   newCrypt->keyedHash(magnet,
				       &ok).toBase64());

	      updateQuery.bindValue
		(2, query.value(1));

	      if(ok)
		updateQuery.exec();
	      else
		{
		  QSqlQuery deleteQuery(db);

		  deleteQuery.prepare
		    ("DELETE FROM transmitted_magnets WHERE "
		     "magnet_hash = ?");
		  deleteQuery.bindValue(0, query.value(1));
		  deleteQuery.exec();
		}
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  sb.status->clear();
}
