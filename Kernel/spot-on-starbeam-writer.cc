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
#include <QSqlDatabase>
#include <QSqlQuery>

#include "Common/spot-on-crypt.h"
#include "Common/spot-on-misc.h"
#include "spot-on-kernel.h"
#include "spot-on-starbeam-writer.h"

spoton_starbeam_writer::spoton_starbeam_writer(QObject *parent):
QThread(parent)
{
  m_keyTimer.setInterval(30000);
  m_timer.setInterval(100);
  QThread::start();
}

spoton_starbeam_writer::~spoton_starbeam_writer()
{
  m_keyTimer.stop();
  m_timer.stop();
  quit();
  wait(30000);
}

void spoton_starbeam_writer::run(void)
{
  connect(&m_keyTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotReadKeys(void)));
  connect(&m_timer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotProcessData(void)));
  exec();
}

void spoton_starbeam_writer::slotProcessData(void)
{
  QMutexLocker locker(&m_mutex);

  if(m_queue.isEmpty())
    return;

  QByteArray data(QByteArray::fromBase64(m_queue.dequeue()));

  locker.unlock();

  QList<QByteArray> list(data.split('\n'));

  if(list.size() != 2)
    return;

  QByteArray originalData(data);

  for(int i = 0; i < list.size(); i++)
    list.replace(i, QByteArray::fromBase64(list.at(i)));

  if(m_magnets.isEmpty())
    slotReadKeys();

  QHash<QString, QByteArray> magnet;

  for(int i = 0; i < m_magnets.size(); i++)
    {
      QByteArray messageCode;
      bool ok = true;

      messageCode = spoton_crypt::keyedHash
	(list.value(0),
	 m_magnets.at(i).value("mk"),
	 m_magnets.at(i).value("ht"),
	 &ok);

      if(ok)
	if(list.value(1) == messageCode)
	  {
	    magnet = m_magnets.at(i);
	    break;
	  }
    }

  if(magnet.isEmpty())
    return;

  bool ok = true;
  spoton_crypt crypt(magnet.value("ct").constData(),
		     QString(""),
		     QByteArray(),
		     magnet.value("ek"),
		     0,
		     0,
		     QString(""));

  data = crypt.decrypted(list.value(0), &ok);

  if(!ok)
    return;

  if(data.split('\n').size() != 6)
    {
      for(int i = 0; i < m_novas.size(); i++)
	{
	  QByteArray bytes;
	  bool ok = true;
	  spoton_crypt crypt("aes256",
			     QString(""),
			     QByteArray(),
			     m_novas.at(i),
			     0,
			     0,
			     QString(""));

	  bytes = crypt.decrypted(data, &ok);

	  if(ok)
	    {
	      list = bytes.split('\n');

	      for(int i = 0; i < list.size(); i++)
		list.replace(i, QByteArray::fromBase64(list.at(i)));

	      break;
	    }
	}
    }
  else
    {
      list = data.split('\n');

      for(int i = 0; i < list.size(); i++)
	list.replace(i, QByteArray::fromBase64(list.at(i)));
    }

  if(list.value(0) != "0060")
    return;
  else
    emit receivedPulse(originalData);

  qint64 totalSize = qAbs(list.value(4).toLongLong());
  qint64 position = qAbs(list.value(2).toLongLong());

  if(position > totalSize)
    return;
  else if(totalSize > 1048576 * spoton_kernel::setting("gui/maxMosaicSize",
						       512).toLongLong())
    return;

  QFile file;
  QString fileName
    (spoton_kernel::setting("gui/etpDestinationPath", QDir::homePath()).
     toString() + QDir::separator() + QString::fromUtf8(list.value(1)));
  qint64 size = qAbs(list.value(3).toLongLong());

  file.setFileName(fileName);

  if(file.open(QIODevice::ReadWrite | QIODevice::Unbuffered))
    if(file.seek(position))
      file.write(list.value(5).mid(0, size).constData(), size);

  file.close();

  spoton_crypt *s_crypt = spoton_kernel::s_crypts.value("chat", 0);

  if(!s_crypt)
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "starbeam.db");

    if(db.open())
      {
	QSqlQuery query(db);

	query.prepare
	  ("INSERT OR REPLACE INTO received "
	   "(file, file_hash, total_size) VALUES (?, ?, ?)");
	query.bindValue
	  (0, s_crypt->encrypted(fileName.toUtf8(),
				 &ok).toBase64());

	if(ok)
	  query.bindValue
	    (1, s_crypt->keyedHash(fileName.toUtf8(), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (2, s_crypt->encrypted(QByteArray::number(totalSize), &ok).
	     toBase64());

	if(ok)
	  query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_starbeam_writer::start(void)
{
  m_keyTimer.start();
  m_timer.start();
}

void spoton_starbeam_writer::stop(void)
{
  m_keyTimer.stop();
  m_timer.stop();
}

void spoton_starbeam_writer::slotReadKeys(void)
{
  spoton_crypt *s_crypt = spoton_kernel::s_crypts.value("chat", 0);

  if(!s_crypt)
    return;

  QString connectionName("");

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName
      (spoton_misc::homePath() + QDir::separator() + "starbeam.db");

    if(db.open())
      {
	m_magnets.clear();
	m_novas.clear();

	QSqlQuery query(db);

	query.setForwardOnly(true);
	query.prepare("SELECT magnet FROM magnets");

	if(query.exec())
	  while(query.next())
	    {
	      QByteArray data
		(QByteArray::fromBase64(query.value(0).toByteArray()));
	      bool ok = true;

	      data = s_crypt->decrypted(data, &ok);

	      if(!ok)
		continue;

	      QHash<QString, QByteArray> elements;
	      QList<QByteArray> list
		(data.remove(0, qstrlen("magnet:?")).split('&'));

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

	      if(elements.contains("xt"))
		m_magnets.append(elements);
	    }

	query.prepare("SELECT nova FROM received_novas");

	if(query.exec())
	  while(query.next())
	    {
	      QByteArray data
		(QByteArray::fromBase64(query.value(0).toByteArray()));
	      bool ok = true;

	      data = s_crypt->decrypted(data, &ok);

	      if(!ok)
		continue;

	      m_novas.append(data);
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_starbeam_writer::enqueue(const QByteArray &data)
{
  if(!data.isEmpty())
    if(spoton_kernel::setting("gui/etpReceivers", false).toBool())
      {
	m_mutex.lock();
	m_queue.enqueue(data);
	m_mutex.unlock();
      }
}
