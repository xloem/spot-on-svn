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
#include <QSqlDatabase>
#include <QSqlQuery>

#include "Common/spot-on-crypt.h"
#include "Common/spot-on-misc.h"
#include "spot-on-kernel.h"
#include "spot-on-starbeam-writer.h"

spoton_starbeam_writer::spoton_starbeam_writer(QObject *parent):
  QThread(parent)
{
}

spoton_starbeam_writer::~spoton_starbeam_writer()
{
  quit();
  wait(30000);
}

void spoton_starbeam_writer::run(void)
{
  spoton_starbeam_writer_worker worker(this);

  connect(this,
	  SIGNAL(newData(void)),
	  &worker,
	  SLOT(slotNewData(void)));
  exec();
}

void spoton_starbeam_writer::processData(void)
{
  QWriteLocker locker1(&m_mutex);

  if(m_data.isEmpty())
    return;

  QByteArray data(m_data.take(m_data.keys().value(0)));

  locker1.unlock();

  QList<QByteArray> list(data.split('\n'));

  if(list.size() != 3)
    return;

  QByteArray originalData(data);

  for(int i = 0; i < list.size(); i++)
    list.replace(i, QByteArray::fromBase64(list.at(i)));

  QHash<QString, QByteArray> magnet;
  QList<QHash<QString, QByteArray> > magnets;
  QReadLocker locker2(&m_keyMutex);

  magnets = m_magnets;
  locker2.unlock();

  for(int i = 0; i < magnets.size(); i++)
    {
      QByteArray messageCode;
      bool ok = true;

      messageCode = spoton_crypt::keyedHash
	(list.value(0),
	 magnets.at(i).value("mk"),
	 magnets.at(i).value("ht"),
	 &ok);

      if(ok)
	if(!list.value(1).isEmpty() && !messageCode.isEmpty() &&
	   spoton_crypt::memcmp(list.value(1), messageCode))
	  {
	    magnet = magnets.at(i);
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

  QList<QByteArray> novas;
  QReadLocker locker3(&m_keyMutex);

  novas = m_novas;
  locker3.unlock();

  if(data.split('\n').size() != 7)
    {
      for(int i = 0; i < novas.size(); i++)
	{
	  QByteArray bytes;
	  bool ok = true;
	  spoton_crypt crypt("aes256",
			     QString(""),
			     QByteArray(),
			     novas.at(i),
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

  int dataSize = qAbs(static_cast<int> (list.value(3).toLongLong()));
  int pulseSize = qAbs(static_cast<int> (list.value(6).toLongLong()));
  qint64 maximumSize = 1048576 * spoton_kernel::setting
    ("gui/maxMosaicSize", 512).toLongLong();
  qint64 position = qAbs(list.value(2).toLongLong());
  qint64 totalSize = qAbs(list.value(4).toLongLong());

  if(dataSize != list.value(5).length()) // Data
    return;
  else if(dataSize > pulseSize)
    return;
  else if(dataSize > maximumSize || totalSize > maximumSize)
    return;
  else if(dataSize > totalSize || position >= totalSize)
    return;
  else if(pulseSize > maximumSize)
    return;

  QFile file;
  QString fileName
    (spoton_kernel::setting("gui/etpDestinationPath", QDir::homePath()).
     toString() + QDir::separator() + QString::fromUtf8(list.value(1)));

  file.setFileName(fileName);

  if(file.open(QIODevice::ReadWrite))
    {
      if(file.seek(position))
	{
	  if(static_cast<int> (file.write(list.value(5).mid(0, dataSize).
					  constData(), dataSize)) != dataSize)
	    spoton_misc::logError
	      ("spoton_starbeam_writer::processData(): "
	       "write() failure.");

	  file.flush();
	}
      else
	spoton_misc::logError("spoton_starbeam_writer::processData(): "
			      "seek() failure.");
    }

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
	bool ok = true;

	query.prepare
	  ("INSERT OR REPLACE INTO received "
	   "(file, file_hash, hash, pulse_size, total_size) "
	   "VALUES (?, ?, (SELECT hash FROM received WHERE file_hash = ?), "
	   "?, ?)");

	if(ok)
	  query.bindValue
	    (0, s_crypt->
	     encryptedThenHashed(fileName.toUtf8(), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (1, s_crypt->keyedHash(fileName.toUtf8(), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (2, s_crypt->keyedHash(fileName.toUtf8(), &ok).toBase64());

	if(ok)
	  query.bindValue
	    (3, s_crypt->
	     encryptedThenHashed(QByteArray::number(pulseSize), &ok).
	     toBase64());

	if(ok)
	  query.bindValue
	    (4, s_crypt->
	     encryptedThenHashed(QByteArray::number(totalSize), &ok).
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
  slotReadKeys();
  QThread::start();
}

void spoton_starbeam_writer::stop(void)
{
  quit();
  wait(30000);

  QWriteLocker locker1(&m_keyMutex);

  m_magnets.clear();
  m_novas.clear();
  locker1.unlock();

  QWriteLocker locker2(&m_mutex);

  m_data.clear();
  locker2.unlock();
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
	QWriteLocker locker(&m_keyMutex);

	m_magnets.clear();
	m_novas.clear();
	locker.unlock();

	QSqlQuery query(db);

	query.setForwardOnly(true);
	query.prepare("SELECT magnet FROM magnets");

	if(query.exec())
	  while(query.next())
	    {
	      QByteArray data
		(QByteArray::fromBase64(query.value(0).toByteArray()));
	      bool ok = true;

	      data = s_crypt->decryptedAfterAuthenticated(data, &ok);

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
		{
		  QWriteLocker locker(&m_keyMutex);

		  m_magnets.append(elements);
		}
	    }

	query.prepare("SELECT nova FROM received_novas");

	if(query.exec())
	  while(query.next())
	    {
	      QByteArray data
		(QByteArray::fromBase64(query.value(0).toByteArray()));
	      bool ok = true;

	      data = s_crypt->decryptedAfterAuthenticated(data, &ok);

	      if(!ok)
		continue;

	      QWriteLocker locker(&m_keyMutex);

	      m_novas.append(data);
	    }
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);
}

void spoton_starbeam_writer::append(const QByteArray &data)
{
  if(data.isEmpty())
    return;

  spoton_crypt *s_crypt = spoton_kernel::s_crypts.value("chat", 0);

  if(!s_crypt)
    return;

  QReadLocker locker(&m_keyMutex);

  if(m_magnets.isEmpty())
    return;

  locker.unlock();

  if(spoton_kernel::setting("gui/etpReceivers", false).toBool())
    {
      QByteArray bytes(data.trimmed());
      QByteArray hash;
      bool new_data = false;
      bool ok = true;

      hash = s_crypt->keyedHash(bytes, &ok);

      if(!ok)
	hash = QCryptographicHash::hash(bytes, QCryptographicHash::Sha1);

      QWriteLocker locker(&m_mutex);

      if(!m_data.contains(hash))
	{
	  m_data.insert(hash, bytes);
	  new_data = true;
	}

      locker.unlock();

      /*
      ** If the thread is not active, it should be!
      */

      if(!isRunning())
	start();

      if(new_data)
	emit newData();
    }
}

bool spoton_starbeam_writer::isActive(void) const
{
  return isRunning();
}
