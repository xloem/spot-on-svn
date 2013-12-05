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

#include <QDir>
#include <QSqlQuery>

#include "Common/spot-on-crypt.h"
#include "Common/spot-on-misc.h"
#include "spot-on-kernel.h"
#include "spot-on-starbeam-writer.h"

spoton_starbeam_writer::spoton_starbeam_writer
(const qint64 id, QObject *parent):QObject(parent)
{
  m_id = id;
  m_offset = 0;
  connect(&m_timer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotTimeout(void)));
  m_timer.start(5000);
}

spoton_starbeam_writer::~spoton_starbeam_writer()
{
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
	query.exec("DELETE FROM transmitted_pulses WHERE "
		   "transmitted_oid NOT IN "
		   "(SELECT OID FROM transmitted)");
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_starbeam_writer::slotTimeout(void)
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
	    query.prepare("SELECT compress, file, mosaic, "
			  "pulse_size, status, total_size FROM transmitted "
			  "WHERE OID = ?");
	    query.bindValue(0, m_id);

	    if(query.exec())
	      if(query.next())
		{
		  QString status(query.value(4).toString());

		  if(status == "deleted")
		    shouldDelete = true;
		  else if(status == "transmitted")
		    {
		      QByteArray mosaic;
		      QString fileName("");
		      QString fileSize("");
		      QString pulseSize("");
		      bool compress = false;
		      bool ok = true;

		      compress = QVariant
			(s_crypt->
			 decrypted(QByteArray::
				   fromBase64(query.
					      value(0).
					      toByteArray()),
				   &ok).
			 constData()).toBool();

		      if(ok)
			fileName = s_crypt->
			  decrypted(QByteArray::
				    fromBase64(query.
					       value(1).
					       toByteArray()),
				    &ok).
			  constData();

		      if(ok)
			mosaic = s_crypt->
			  decrypted(QByteArray::
				    fromBase64(query.
					       value(2).
					       toByteArray()),
				    &ok);

		      if(ok)
			pulseSize = s_crypt->
			  decrypted(QByteArray::
				    fromBase64(query.
					       value(3).
					       toByteArray()),
				    &ok).
			  constData();

		      if(ok)
			fileSize = s_crypt->
			  decrypted(QByteArray::
				    fromBase64(query.
					       value(5).
					       toByteArray()),
				    &ok).
			  constData();

		      if(ok)
			pulsate
			  (compress, fileName, mosaic, pulseSize, fileSize,
			   m_magnets.value(qrand() % m_magnets.count()),
			   s_crypt);
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
	(QString("spoton_starbeam_writer:slotTimeout(): instructed "
		 "to delete starbeam writer %1.").
	 arg(m_id));
      deleteLater();
    }
}

void spoton_starbeam_writer::populateMagnets(const QSqlDatabase &db)
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

QHash<QString, QByteArray> spoton_starbeam_writer::elementsFromMagnet
(const QByteArray &magnet, spoton_crypt *s_crypt)
{
  QByteArray data;
  QHash<QString, QByteArray> elements;
  QList<QByteArray> list;
  bool ok = true;

  if(!s_crypt)
    goto done_label;

  data = s_crypt->decrypted(magnet, &ok);

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
	  elements.insert("xt", bytes);
	}
    }

  if(!elements.contains("url:starbeam"))
    {
      elements.clear();
      goto done_label;
    }

 done_label:
  return elements;
}

void spoton_starbeam_writer::pulsate(const bool compress,
				     const QString &fileName,
				     const QByteArray &mosaic,
				     const QString &pulseSize,
				     const QString &fileSize,
				     const QByteArray &magnet,
				     spoton_crypt *s_crypt)
{
  QHash<QString, QByteArray> elements(elementsFromMagnet(magnet, s_crypt));

  if(elements.isEmpty())
    return;

  QFile file(fileName);

  if(file.open(QIODevice::ReadOnly))
    if(file.seek(m_offset))
      {
	QByteArray buffer(qAbs(pulseSize.toInt()), 0);
	qint64 rc = 0;

	if((rc = file.read(buffer.data(), buffer.length())) > 0)
	  {
	    QByteArray data(buffer.mid(0, rc));
	    bool ok = true;
	    spoton_crypt crypt(elements.value("ct").constData(),
			       QString(""),
			       QByteArray(),
			       elements.value("ek"),
			       0,
			       0,
			       QString(""));

	    if(compress)
	      data = qCompress(data, 9);

	    if(ok)
	      m_offset += rc;
	  }
      }

  file.close();
  Q_UNUSED(mosaic);
  Q_UNUSED(fileSize);
}
