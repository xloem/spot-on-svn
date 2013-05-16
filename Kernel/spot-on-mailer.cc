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

#include <QDir>
#include <QSqlDatabase>
#include <QSqlQuery>

#include "Common/spot-on-gcrypt.h"
#include "Common/spot-on-misc.h"
#include "spot-on-kernel.h"
#include "spot-on-mailer.h"

spoton_mailer::spoton_mailer(QObject *parent):QObject(parent)
{
  connect(&m_timer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotTimeout(void)));
  m_timer.start(15000);
}

spoton_mailer::~spoton_mailer()
{
}

void spoton_mailer::slotTimeout(void)
{
  if(!spoton_kernel::s_crypt1)
    return;

  QList<QVector<QVariant> > list;

  {
    QSqlDatabase db1 = QSqlDatabase::addDatabase
      ("QSQLITE", "spoton_mailer1");
    QSqlDatabase db2 = QSqlDatabase::addDatabase
      ("QSQLITE", "spoton_mailer2");

    db1.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "email.db");
    db2.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() +
       "friends_public_keys.db");

    if(db1.open() && db2.open())
      {
	QByteArray name
	  (spoton_kernel::s_settings.value("gui/nodeName", "unknown").
	   toByteArray().trimmed());
	QSqlQuery query(db1);

	/*
	** Send all messages from the sent folder.
	*/

	if(query.exec("SELECT gemini, message, participant_oid, status, "
		      "subject, OID FROM folders WHERE folder_index = 1"))
	  while(query.next())
	    {
	      QByteArray status;
	      bool ok = true;

	      status = spoton_kernel::s_crypt1->
		decrypted(QByteArray::fromBase64(query.
						 value(3).
						 toByteArray()),
			  &ok);

	      if(status != "Queued")
		continue;

	      QByteArray gemini;
	      QByteArray message;
	      QByteArray publicKey;
	      QByteArray subject;
	      qint64 mailOid = query.value(5).toLongLong();
	      qint64 participantOid = -1;

	      if(!query.value(0).isNull())
		gemini = spoton_kernel::s_crypt1->
		  decrypted(QByteArray::fromBase64(query.
						   value(0).
						   toByteArray()),
			    &ok);

	      if(ok)
		message = spoton_kernel::s_crypt1->
		  decrypted(QByteArray::fromBase64(query.
						   value(1).
						   toByteArray()),
			    &ok);

	      if(ok)
		participantOid = spoton_kernel::s_crypt1->
		  decrypted(QByteArray::fromBase64(query.
						   value(2).
						   toByteArray()),
			    &ok).toLongLong();

	      if(ok)
		{
		  QSqlQuery query(db2);

		  query.prepare("SELECT public_key FROM "
				"friends_public_keys "
				"WHERE OID = ?");
		  query.bindValue(0, participantOid);

		  if((ok = query.exec()))
		    if((ok = query.next()))
		      publicKey = query.value(0).toByteArray();
		}

	      if(ok)
		subject = spoton_kernel::s_crypt1->
		  decrypted(QByteArray::fromBase64(query.
						   value(4).
						   toByteArray()),
			    &ok);

	      if(ok)
		{
		  QVector<QVariant> vector;

		  vector << gemini
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

  QSqlDatabase::removeDatabase("spoton_mailer1");
  QSqlDatabase::removeDatabase("spoton_mailer2");

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
