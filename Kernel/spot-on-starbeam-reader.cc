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

#include <QDir>
#include <QSqlQuery>

#include "Common/spot-on-crypt.h"
#include "Common/spot-on-misc.h"
#include "spot-on-kernel.h"
#include "spot-on-starbeam-reader.h"

spoton_starbeam_reader::spoton_starbeam_reader
(const qint64 id, QObject *parent):QObject(parent)
{
  m_id = id;
  m_missingLinksIterator = 0;
  m_position = 0;
  connect(&m_timer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotTimeout(void)));
  m_timer.start(1500);
}

spoton_starbeam_reader::~spoton_starbeam_reader()
{
  m_timer.stop();

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "starbeam.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.prepare("DELETE FROM transmitted WHERE OID = ? AND "
		      "status_control = 'deleted'");
	query.bindValue(0, m_id);
	query.exec();
	query.exec("DELETE FROM transmitted_magnets WHERE "
		   "transmitted_oid NOT IN "
		   "(SELECT OID FROM transmitted)");
	query.exec("DELETE FROM transmitted_scheduled_pulses WHERE "
		   "transmitted_oid NOT IN "
		   "(SELECT OID FROM transmitted)");
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
  delete m_missingLinksIterator;
  m_missingLinksIterator = 0;
}

void spoton_starbeam_reader::slotTimeout(void)
{
  spoton_crypt *s_crypt = spoton_kernel::s_crypts.value("chat", 0);

  if(!s_crypt)
    return;

  QString connectionName("");
  bool shouldDelete = false;

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "starbeam.db");

    if(db.open())
      {
	populateMagnets(db);

	if(!m_magnets.isEmpty())
	  {
	    QSqlQuery query(db);

	    query.setForwardOnly(true);
	    query.prepare("SELECT file, missing_links, nova, position, "
			  "pulse_size, status_control, total_size "
			  "FROM transmitted WHERE OID = ?");
	    query.bindValue(0, m_id);

	    if(query.exec())
	      if(query.next())
		{
		  QString status(query.value(5).toString());

		  if(status == "deleted")
		    shouldDelete = true;
		  else if(m_position >= 0 && status == "transmitting")
		    {
		      QByteArray nova;
		      QString fileName("");
		      QString fileSize("");
		      QString pulseSize("");
		      bool ok = true;

		      fileName = s_crypt->
			decryptedAfterAuthenticated
			(QByteArray::
			 fromBase64(query.
				    value(0).
				    toByteArray()),
			 &ok).
			constData();

		      if(ok)
			if(!m_missingLinksIterator)
			  {
			    QByteArray bytes
			      (s_crypt->
			       decryptedAfterAuthenticated
			       (QByteArray::
				fromBase64(query.
					   value(1).
					   toByteArray()),
				&ok));

			    if(ok)
			      {
				if(!bytes.isEmpty())
				  m_missingLinks = bytes.split(',');

				if(!m_missingLinks.isEmpty())
				  {
				    try
				      {
					m_missingLinksIterator =
					  new (std::nothrow)
					  QListIterator<QByteArray> 
					  (m_missingLinks);

					if(m_missingLinksIterator)
					  m_missingLinksIterator->toFront();
					else
					  spoton_misc::logError
					    ("spoton_starbeam_reader::"
					     "slotTimeout(): memory "
					     "failure.");
				      }
				    catch(...)
				      {
					if(m_missingLinksIterator)
					  delete m_missingLinksIterator;

					m_missingLinksIterator = 0;
					spoton_misc::logError
					  ("spoton_starbeam_reader::"
					   "slotTimeout(): critical "
					   "failure.");
				      }
				  }
			      }
			  }

		      if(ok)
			nova = s_crypt->
			  decryptedAfterAuthenticated
			  (QByteArray::
			   fromBase64(query.
				      value(2).
				      toByteArray()),
			   &ok);

		      if(ok)
			{
			  if(!m_missingLinksIterator)
			    m_position = s_crypt->
			      decryptedAfterAuthenticated
			      (QByteArray::
			       fromBase64(query.
					  value(3).
					  toByteArray()),
			       &ok).toLongLong();
			  else if(m_missingLinksIterator->hasNext())
			    {
			      QByteArray bytes
				(m_missingLinksIterator->next().trimmed());

			      if(!bytes.isEmpty())
				m_position = qAbs(bytes.toLongLong());
			    }
			}

		      if(ok)
			pulseSize = s_crypt->
			  decryptedAfterAuthenticated
			  (QByteArray::
			   fromBase64(query.
				      value(4).
				      toByteArray()),
			   &ok).
			  constData();

		      if(ok)
			fileSize = s_crypt->
			  decryptedAfterAuthenticated
			  (QByteArray::
			   fromBase64(query.
				      value(6).
				      toByteArray()),
			   &ok).
			  constData();

		      if(ok)
			pulsate
			  (fileName, pulseSize, fileSize,
			   m_magnets.value(qrand() % m_magnets.count()),
			   nova, db, s_crypt);
		    }
		}
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(shouldDelete)
    {
      spoton_misc::logError
	(QString("spoton_starbeam_reader:slotTimeout(): instructed "
		 "to delete starbeam reader %1.").
	 arg(m_id));
      deleteLater();
      return;
    }

  m_timer.start(qrand() % 500 + 1000);
}

void spoton_starbeam_reader::populateMagnets(const QSqlDatabase &db)
{
  if(!db.isOpen())
    return;
  else if(!m_magnets.isEmpty())
    return;

  QSqlQuery query(db);

  query.setForwardOnly(true);
  query.prepare("SELECT magnet FROM transmitted_magnets WHERE "
		"transmitted_oid = ?");
  query.bindValue(0, m_id);

  if(query.exec())
    while(query.next())
      m_magnets.append(QByteArray::fromBase64(query.value(0).toByteArray()));
}

QHash<QString, QByteArray> spoton_starbeam_reader::elementsFromMagnet
(const QByteArray &magnet, spoton_crypt *s_crypt)
{
  QByteArray data;
  QHash<QString, QByteArray> elements;
  QList<QByteArray> list;
  bool ok = true;

  if(!s_crypt)
    goto done_label;

  data = s_crypt->decryptedAfterAuthenticated(magnet, &ok);

  if(!ok)
    goto done_label;

  list = data.remove(0, qstrlen("magnet:?")).split('&');

  while(!list.isEmpty())
    {
      QByteArray bytes(list.takeFirst());

      if(bytes.startsWith("ct=")) // Cipher Type
	{
	  bytes.remove(0, 3);
	  elements.insert("ct", bytes);
	}
      else if(bytes.startsWith("ek=")) // Encryption Key
	{
	  bytes.remove(0, 3);
	  elements.insert("ek", bytes);
	}
      else if(bytes.startsWith("ht=")) // Hash Type
	{
	  bytes.remove(0, 3);
	  elements.insert("ht", bytes);
	}
      else if(bytes.startsWith("mk=")) // MAC Key
	{
	  bytes.remove(0, 3);
	  elements.insert("mk", bytes);
	}
      else if(bytes.startsWith("xt="))
	{
	  bytes.remove(0, 3);

	  if(bytes == "urn:starbeam")
	    elements.insert("xt", bytes);
	}
    }

  if(!elements.contains("xt"))
    {
      elements.clear();
      goto done_label;
    }

 done_label:
  return elements;
}

void spoton_starbeam_reader::pulsate(const QString &fileName,
				     const QString &pulseSize,
				     const QString &fileSize,
				     const QByteArray &magnet,
				     const QByteArray &nova,
				     const QSqlDatabase &db,
				     spoton_crypt *s_crypt)
{
  if(m_position < 0)
    return;

  QHash<QString, QByteArray> elements(elementsFromMagnet(magnet, s_crypt));

  if(elements.isEmpty())
    return;

  QFile file(fileName);
  QString status("completed");
  bool ok = false;

  if(file.open(QIODevice::ReadOnly))
    {
      if(file.seek(m_position))
	{
	  if(!file.atEnd())
	    {
	      QByteArray buffer(qAbs(pulseSize.toInt()), 0);
	      qint64 rc = 0;

	      if((rc = file.read(buffer.data(), buffer.length())) > 0)
		{
		  QByteArray data(buffer.mid(0, static_cast<int> (rc)));
		  QByteArray messageCode;
		  int size = data.length();
		  spoton_crypt crypt(elements.value("ct").constData(),
				     QString(""),
				     QByteArray(),
				     elements.value("ek"),
				     0,
				     0,
				     QString(""));

		  if(nova.isEmpty())
		    data = crypt.encrypted
		      (QByteArray("0060").toBase64() + "\n" +
		       QFileInfo(fileName).fileName().toUtf8().
		       toBase64() + "\n" +
		       QByteArray::number(m_position).toBase64() + "\n" +
		       QByteArray::number(size).toBase64() + "\n" +
		       fileSize.toLatin1().toBase64() + "\n" +
		       data.toBase64() + "\n" +
		       pulseSize.toLatin1().toBase64(), &ok);
		  else
		    {
		      {
			spoton_crypt crypt("aes256",
					   QString(""),
					   QByteArray(),
					   nova,
					   0,
					   0,
					   QString(""));

			data = crypt.encrypted
			  (QByteArray("0060").toBase64() + "\n" +
			   QFileInfo(fileName).fileName().toUtf8().
			   toBase64() + "\n" +
			   QByteArray::number(m_position).toBase64() + "\n" +
			   QByteArray::number(size).toBase64() + "\n" +
			   fileSize.toLatin1().toBase64() + "\n" +
			   data.toBase64() + "\n" +
			   pulseSize.toLatin1().toBase64(), &ok);
		      }

		      if(ok)
			data = crypt.encrypted(data, &ok);
		    }

		  if(ok)
		    messageCode = spoton_crypt::keyedHash
		      (data,
		       elements.value("mk"),
		       elements.value("ht"),
		       &ok);

		  if(ok)
		    data = data.toBase64() + "\n" + messageCode.toBase64();

		  if(ok)
		    spoton_kernel::s_kernel->writeMessage0060(data, &ok);

		  if(ok)
		    {
		      if(m_missingLinksIterator)
			{
			  if(!m_missingLinksIterator->hasNext())
			    m_position = file.size();
			}
		      else
			m_position = qAbs(m_position + rc); // +=
		    }
		}
	      else if(rc < 0)
		spoton_misc::logError("spoton_starbeam_reader::pulsate(): "
				      "read() failure.");
	    }
	}
      else
	spoton_misc::logError("spoton_starbeam_reader::pulsate(): "
			      "seek() failure.");
    }
  else
    spoton_misc::logError("spoton_starbeam_reader::pulsate(): "
			  "open() failure.");

  if(m_position < file.size())
    status = "transmitting";

  file.close();

  if(ok)
    savePositionAndStatus(status, db);
}

void spoton_starbeam_reader::savePositionAndStatus(const QString &status,
						   const QSqlDatabase &db)
{
  if(!db.isOpen())
    return;

  spoton_crypt *s_crypt = spoton_kernel::s_crypts.value("chat", 0);

  if(!s_crypt)
    return;

  QSqlQuery query(db);
  bool ok = true;

  query.prepare("UPDATE transmitted "
		"SET position = ?, "
		"status_control = CASE WHEN status_control = 'deleted' "
		"THEN 'deleted' ELSE ? END "
		"WHERE OID = ?");
  query.bindValue
    (0, s_crypt->encryptedThenHashed(QByteArray::number(m_position),
				     &ok).toBase64());
  query.bindValue(1, status);
  query.bindValue(2, m_id);

  if(ok)
    query.exec();
}
