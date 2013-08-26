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

#include <QDateTime>
#include <QDir>
#include <QSqlDatabase>
#include <QSqlQuery>

#include "Common/spot-on-crypt.h"
#include "Common/spot-on-misc.h"
#include "spot-on-kernel.h"
#include "spot-on-mailer.h"

spoton_mailer::spoton_mailer(QObject *parent):QObject(parent)
{
  connect(&m_reaperTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotReap(void)));
  connect(&m_retrieveMailTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotRetrieveMailTimeout(void)));
  connect(&m_timer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotTimeout(void)));
  m_reaperTimer.start(60000); /*
			      ** Reap old letters from our post office
			      ** once per minute.
			      */
  m_retrieveMailTimer.setInterval(5000); /*
					 ** Harvest a letter from our post
					 ** office every five seconds.
					 */
  m_timer.start(15000); // Send queued mail every fifteen seconds.
}

spoton_mailer::~spoton_mailer()
{
}

void spoton_mailer::slotTimeout(void)
{
  spoton_crypt *s_crypt = spoton_kernel::s_crypts.value("email", 0);

  if(!s_crypt)
    return;

  QList<QVector<QVariant> > list;
  QString connectionName1("");
  QString connectionName2("");

  {
    QSqlDatabase db1 = spoton_misc::database(connectionName1);
    QSqlDatabase db2 = spoton_misc::database(connectionName2);

    db1.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "email.db");
    db2.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() +
       "friends_public_keys.db");

    if(db1.open() && db2.open())
      {
	QByteArray name
	  (spoton_kernel::s_settings.value("gui/emailName", "unknown").
	   toByteArray().trimmed());
	QSqlQuery query(db1);

	/*
	** Send all messages from the sent folder.
	*/

	query.setForwardOnly(true);

	if(query.exec("SELECT goldbug, message, participant_oid, status, "
		      "subject, OID FROM folders WHERE folder_index = 1"))
	  while(query.next())
	    {
	      QString status;
	      bool ok = true;

	      status = QString::fromUtf8
		(s_crypt->
		 decrypted(QByteArray::fromBase64(query.
						  value(3).
						  toByteArray()),
			   &ok).constData());

	      if(status != tr("Queued"))
		continue;

	      QByteArray goldbug;
	      QByteArray message;
	      QByteArray publicKey;
	      QByteArray subject;
	      qint64 mailOid = query.value(5).toLongLong();
	      qint64 participantOid = -1;

	      goldbug = s_crypt->
		decrypted(QByteArray::fromBase64(query.
						 value(0).
						 toByteArray()),
			  &ok);

	      if(ok)
		message = s_crypt->
		  decrypted(QByteArray::fromBase64(query.
						   value(1).
						   toByteArray()),
			    &ok);

	      if(ok)
		participantOid = s_crypt->
		  decrypted(QByteArray::fromBase64(query.
						   value(2).
						   toByteArray()),
			    &ok).toLongLong();

	      if(ok)
		{
		  QByteArray publicKeyHash;
		  QSqlQuery query(db2);

		  query.setForwardOnly(true);
		  query.prepare("SELECT public_key FROM "
				"friends_public_keys "
				"WHERE OID = ? AND neighbor_oid = -1");
		  query.bindValue(0, participantOid);

		  if((ok = query.exec()))
		    if((ok = query.next()))
		      publicKey = query.value(0).toByteArray();
		}

	      if(ok)
		subject = s_crypt->
		  decrypted(QByteArray::fromBase64(query.
						   value(4).
						   toByteArray()),
			    &ok);

	      if(ok)
		{
		  QVector<QVariant> vector;

		  vector << goldbug
			 << message
			 << name
			 << publicKey
			 << subject
			 << mailOid;
		  list.append(vector);
		}
	    }
      }

    db1.close();
    db2.close();
  }

  QSqlDatabase::removeDatabase(connectionName1);
  QSqlDatabase::removeDatabase(connectionName2);

  for(int i = 0; i < list.size(); i++)
    {
      QVector<QVariant> vector(list.at(i));

      emit sendMail(vector.value(0).toByteArray(),
		    vector.value(1).toByteArray(),
		    vector.value(2).toByteArray(),
		    vector.value(3).toByteArray(),
		    vector.value(4).toByteArray(),
		    vector.value(5).toLongLong());
    }
}

void spoton_mailer::slotRetrieveMail(const QByteArray &data,
				     const QByteArray &publicKeyHash,
				     const QByteArray &signature)
{
  /*
  ** We must locate the public key that's associated with the provided
  ** public key hash. Remember publicKeyHash is the hash of the signature
  ** public key.
  */

  QByteArray publicKey(spoton_misc::publicKeyFromHash(publicKeyHash));

  if(publicKey.isEmpty())
    return;

  if(!spoton_crypt::isValidSignature(data,
				     publicKey,
				     signature))
    return;

  publicKey = spoton_misc::publicKeyFromSignaturePublicKeyHash
    (publicKeyHash);

  if(publicKey.isEmpty())
    return;

  QByteArray hash;
  bool ok = true;

  hash = spoton_crypt::sha512Hash(publicKey, &ok);

  if(!ok)
    return;

  if(!m_publicKeyHashes.contains(hash))
    m_publicKeyHashes.append(hash);

  if(!m_retrieveMailTimer.isActive())
    m_retrieveMailTimer.start();
}

void spoton_mailer::slotRetrieveMailTimeout(void)
{
  /*
  ** We're assuming that only authenticated participants
  ** can request their e-mail. Let's hope our implementation
  ** of digital signatures is correct.
  */

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "email.db");

    if(db.open())
      {
	QByteArray publicKeyHash(m_publicKeyHashes.first());
	QSqlQuery query(db);

	query.setForwardOnly(true);
	query.prepare("SELECT message_bundle, OID FROM post_office "
		      "WHERE recipient_hash = ?");
	query.bindValue(0, publicKeyHash.toBase64());

	if(query.exec())
	  {
	    if(query.next())
	      {
		spoton_crypt *s_crypt =
		  spoton_kernel::s_crypts.value("email", 0);

		if(s_crypt)
		  {
		    /*
		    ** Is this a letter?
		    */

		    QByteArray message;
		    bool ok = true;

		    message = s_crypt->
		      decrypted(QByteArray::fromBase64(query.
						       value(0).
						       toByteArray()),
				&ok);

		    if(ok)
		      {
			emit sendMailFromPostOffice(message);
			
			QSqlQuery deleteQuery(db);

			deleteQuery.prepare("DELETE FROM post_office "
					    "WHERE recipient_hash = ? AND "
					    "OID = ?");
			deleteQuery.bindValue(0, publicKeyHash.toBase64());
			deleteQuery.bindValue(1, query.value(1));
			deleteQuery.exec();
		      }
		  }
	      }
	    else
	      m_publicKeyHashes.takeFirst();
	  }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(m_publicKeyHashes.isEmpty())
    m_retrieveMailTimer.stop();
}

void spoton_mailer::slotReap(void)
{
  spoton_crypt *s_crypt = spoton_kernel::s_crypts.value("email", 0);

  if(!s_crypt)
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "email.db");

    if(db.open())
      {
	QDateTime now(QDateTime::currentDateTime());
	QSqlQuery query(db);
	int days = spoton_kernel::s_settings.value
	  ("gui/postofficeDays", 1).toInt();

	query.setForwardOnly(true);

	if(query.exec("SELECT date_received, OID FROM post_office"))
	  while(query.next())
	    {
	      QDateTime dateTime;
	      bool ok = true;

	      dateTime = QDateTime::fromString
		(s_crypt->decrypted(QByteArray::
				    fromBase64(query.
					       value(0).
					       toByteArray()),
				    &ok).constData(),
		 Qt::ISODate);

	      if(dateTime.daysTo(now) > days)
		{
		  QSqlQuery deleteQuery(db);

		  deleteQuery.prepare("DELETE FROM post_office "
				      "WHERE OID = ?");
		  deleteQuery.bindValue(0, query.value(1));
		  deleteQuery.exec();
		}
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}
