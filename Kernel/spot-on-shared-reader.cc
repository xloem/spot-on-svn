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
#include <QVariant>
#include <QtDebug>

#include "Common/spot-on-gcrypt.h"
#include "Common/spot-on-misc.h"
#include "spot-on-kernel.h"
#include "spot-on-shared-reader.h"

spoton_shared_reader::spoton_shared_reader(QObject *parent):QObject(parent)
{
  connect(&m_timer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotTimeout(void)));
  m_timer.start(5000);
}

spoton_shared_reader::~spoton_shared_reader()
{
}

void spoton_shared_reader::slotTimeout(void)
{
  QList<QList<QVariant> > list;

  {
    QSqlDatabase db = QSqlDatabase::addDatabase
      ("QSQLITE", "spoton_shared_reader");

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "shared.db");

    if(db.open())
      {
	QSqlQuery query(db);
	int processed = 0;

	query.setForwardOnly(true);

	if(query.exec("SELECT description, encrypted, title, url "
		      "FROM urls"))
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
		  if(!spoton_kernel::s_crypt1)
		    continue;

		  spoton_gcrypt crypt
		    (QByteArray("aes256"),
		     QString(""),
		     QByteArray(),
		     QByteArray(spoton_kernel::s_crypt1->passphrase(),
				spoton_kernel::s_crypt1->passphraseLength()),
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

    db.close();
  }

  QSqlDatabase::removeDatabase("spoton_shared_reader");
  spoton_misc::populateUrlsDatabase(list, spoton_kernel::s_crypt1);
}
