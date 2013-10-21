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
#include <QMessageBox>
#include <QScrollBar>
#include <QSettings>
#include <QSqlDatabase>
#include <QSqlQuery>
#if QT_VERSION >= 0x050000
#include <QtConcurrent>
#endif
#include <QtCore>
#include <QtCore/qmath.h>

#include "Common/spot-on-common.h"
#include "Common/spot-on-crypt.h"
#include "Common/spot-on-misc.h"
#include "spot-on-buzzpage.h"

spoton_buzzpage::spoton_buzzpage(QSslSocket *kernelSocket,
				 const QByteArray &channel,
				 const QByteArray &channelSalt,
				 const QByteArray &channelType,
				 const QByteArray &id,
				 const unsigned long iterationCount,
				 spoton_crypt *crypt,
				 QWidget *parent):QWidget(parent)
{
  ui.setupUi(this);
  m_channel = channel.trimmed();

  if(m_channel.isEmpty())
    m_channel = "unknown";

  m_channelSalt = channelSalt.trimmed();
  m_channelType = channelType.trimmed();

  if(m_channelType.isEmpty())
    m_channelType = "aes256";

  m_crypt = crypt;
  m_id = id.trimmed();
  m_iterationCount = qMax(static_cast<unsigned long> (10000),
			  iterationCount);

  if(m_id.isEmpty())
    m_id = spoton_crypt::strongRandomBytes
      (spoton_common::BUZZ_MAXIMUM_ID_LENGTH / 2).toHex();

  /*
  ** Generate some awful key.
  */

  size_t keyLength = spoton_crypt::cipherKeyLength(channelType);

  if(keyLength > 0)
    {
      m_key.resize(keyLength);

      if(m_channelSalt.isEmpty())
	{
	  QByteArray salt;
	  bool ok = true;

	  salt = spoton_crypt::keyedHash(m_channel + m_channelType,
					 m_channel, "sha512", &ok);

	  if(!ok)
	    /*
	    ** We're doomed!
	    */

	    salt = m_channel + m_channelType;

	  m_channelSalt = salt;
	}
      else
	ui.salt->setText(m_channelSalt);

      if(gcry_kdf_derive(static_cast<const void *> (m_channel.constData()),
			 static_cast<size_t> (m_channel.length()),
			 GCRY_KDF_PBKDF2,
			 GCRY_MD_SHA512,
			 static_cast<const void *> (m_channelSalt.constData()),
			 static_cast<size_t> (m_channelSalt.length()),
			 m_iterationCount,
			 keyLength,
			 static_cast<void *> (m_key.data())) != 0)
	m_key = m_channel;
    }
  else
    m_key = m_channel;

  m_kernelSocket = kernelSocket;
  m_statusTimer.start(30000);
  connect(&m_statusTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotStatusTimeout(void)));
  connect(ui.clearMessages,
	  SIGNAL(clicked(void)),
	  ui.messages,
	  SLOT(clear(void)));
  connect(ui.favorite,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSave(void)));
  connect(ui.remove,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotRemove(void)));
  connect(ui.sendMessage,
	  SIGNAL(clicked(void)),
	  this,
	  SLOT(slotSendMessage(void)));
  connect(ui.message,
	  SIGNAL(returnPressed(void)),
	  this,
	  SLOT(slotSendMessage(void)));
  connect(&m_messagingCachePurgeTimer,
	  SIGNAL(timeout(void)),
	  this,
	  SLOT(slotMessagingCachePurge(void)));
  ui.clients->setColumnHidden(1, true); // ID
  ui.clients->setColumnHidden(2, true); // Time
  ui.clients->horizontalHeader()->setSortIndicator(0, Qt::AscendingOrder);
  ui.iterationCount->setText(QString::number(m_iterationCount));
  ui.splitter->setStretchFactor(0, 1);
  ui.splitter->setStretchFactor(1, 0);
  ui.type->setText(m_channelType);
  slotSetIcons();
  m_messagingCachePurgeTimer.start(60000);

  QByteArray name;
  QSettings settings;

  name = settings.value("gui/buzzName", "unknown").toByteArray().trimmed();

  if(name.isEmpty())
    name = "unknown";

  QList<QByteArray> list;

  list << name
       << m_id;
  userStatus(list);
}

spoton_buzzpage::~spoton_buzzpage()
{
  m_messagingCacheMutex.lock();
  m_messagingCache.clear();
  m_messagingCacheMutex.unlock();
  m_future.waitForFinished();
  spoton_misc::logError(QString("spoton_buzzpage::~spoton_buzzpage(): "
				"channel %1:%2 closed.").
			arg(m_channel.constData()).
			arg(m_channelType.constData()));
}

void spoton_buzzpage::slotSetIcons(void)
{
  QSettings settings;
  QString iconSet(settings.value("gui/iconSet", "nouve").toString());

  ui.clearMessages->setIcon(QIcon(QString(":/%1/clear.png").arg(iconSet)));
  ui.sendMessage->setIcon(QIcon(QString(":/%1/ok.png").arg(iconSet)));
}

void spoton_buzzpage::slotSendMessage(void)
{
  QByteArray name;
  QByteArray sendMethod;
  QSettings settings;
  QString error("");
  QString message("");

  if(!m_kernelSocket)
    {
      error = tr("Empty kernel socket.");
      goto done_label;
    }
  else if(m_kernelSocket->state() != QAbstractSocket::ConnectedState)
    {
      error = tr("Not connected to the kernel.");
      goto done_label;
    }
  else if(!m_kernelSocket->isEncrypted())
    {
      error = tr("Connection to the kernel is not encrypted.");
      goto done_label;
    }
  else if(ui.message->toPlainText().trimmed().isEmpty())
    {
      error = tr("Please provide a message.");
      goto done_label;
    }

  message.append
    (QDateTime::currentDateTime().
     toString("[hh:mm<font color=grey>:ss</font>] "));
  message.append(tr("<b>me:</b> "));
  message.append(ui.message->toPlainText().trimmed());
  ui.messages->append(message);
  ui.messages->verticalScrollBar()->setValue
    (ui.messages->verticalScrollBar()->maximum());

  if(ui.sendMethod->currentIndex() == 0)
    sendMethod = "Normal_POST";
  else
    sendMethod = "Artificial_GET";

  name = settings.value("gui/buzzName", "unknown").toByteArray().trimmed();

  if(name.isEmpty())
    name = "unknown";

  {
    QByteArray message;

    message.append("buzz_");
    message.append(m_key.toBase64());
    message.append("_");
    message.append(m_channelType.toBase64());
    message.append("_");
    message.append(name.toBase64());
    message.append("_");
    message.append(m_id.toBase64());
    message.append("_");
    message.append(ui.message->toPlainText().trimmed().toUtf8().
		   toBase64());
    message.append("_");
    message.append(sendMethod.toBase64());
    message.append('\n');

    if(m_kernelSocket->write(message.constData(),
			     message.length()) != message.length())
      spoton_misc::logError
	(QString("spoton_buzzpage::slotSendMessage(): "
		 "write() failure for %1:%2.").
	 arg(m_kernelSocket->peerAddress().toString()).
	 arg(m_kernelSocket->peerPort()));
    else
      m_kernelSocket->flush();
  }

  ui.message->clear();

 done_label:
  
  if(!error.isEmpty())
    QMessageBox::critical(this, tr("Spot-On: Error"), error);
}

void spoton_buzzpage::appendMessage(const QByteArray &hash,
				    const QList<QByteArray> &list)
{
  if(list.size() != 3)
    return;

  QByteArray id
    (list.value(1).mid(0, spoton_common::BUZZ_MAXIMUM_ID_LENGTH).trimmed());

  if(id == m_id)
    /*
    ** Ignore myself.
    */

    return;

  m_purgeMutex.lock();
  m_purge = false;
  m_purgeMutex.unlock();
  m_messagingCacheMutex.lock();

  if(m_messagingCache.contains(hash))
    {
      m_messagingCacheMutex.unlock();
      m_purgeMutex.lock();
      m_purge = true;
      m_purgeMutex.unlock();
      return;
    }
  else
    m_messagingCache[hash] = QDateTime::currentDateTime();

  m_messagingCacheMutex.unlock();
  m_purgeMutex.lock();
  m_purge = true;
  m_purgeMutex.unlock();

  QByteArray name
    (list.value(0).mid(0, spoton_common::NAME_MAXIMUM_LENGTH).trimmed());
  QByteArray message(list.value(2));
  QString msg("");

  if(name.isEmpty() || name == "unknown")
    name = id.mid(0, 16) + "-unknown";

  if(message.isEmpty())
    message = "unknown";

  msg.append
    (QDateTime::currentDateTime().
     toString("[hh:mm<font color=grey>:ss</font>] "));
  msg.append
    (QString("<font color=blue>%1: </font>").
     arg(QString::fromUtf8(name.constData(),
			   name.length())));
  msg.append(QString::fromUtf8(message.constData(),
			       message.length()));
  ui.messages->append(msg);
  ui.messages->verticalScrollBar()->setValue
    (ui.messages->verticalScrollBar()->maximum());
  emit changed();
}

void spoton_buzzpage::slotSendStatus(void)
{
  if(!m_kernelSocket)
    return;
  else if(m_kernelSocket->state() != QAbstractSocket::ConnectedState)
    return;
  else if(!m_kernelSocket->isEncrypted())
    return;

  QByteArray name;
  QByteArray message;
  QSettings settings;

  name = settings.value("gui/buzzName", "unknown").toByteArray().trimmed();

  if(name.isEmpty())
    name = "unknown";

  message.clear();
  message.append("buzz_");
  message.append(m_key.toBase64());
  message.append("_");
  message.append(m_channelType.toBase64());
  message.append("_");
  message.append(name.toBase64());
  message.append("_");
  message.append(m_id.toBase64());
  message.append('\n');

  if(m_kernelSocket->write(message.constData(),
			   message.length()) != message.length())
    spoton_misc::logError
      (QString("spoton_buzzpage::slotSendStatus(): write() failure "
	       "for %1:%2.").
       arg(m_kernelSocket->peerAddress().toString()).
       arg(m_kernelSocket->peerPort()));
  else
    m_kernelSocket->flush();
}

void spoton_buzzpage::userStatus(const QList<QByteArray> &list)
{
  if(list.size() != 2)
    return;

  QByteArray id
    (list.value(1).mid(0, spoton_common::BUZZ_MAXIMUM_ID_LENGTH).trimmed());

  if(id.isEmpty())
    id = spoton_crypt::
      strongRandomBytes(spoton_common::BUZZ_MAXIMUM_ID_LENGTH / 2).toHex();

  QByteArray name
    (list.value(0).mid(0, spoton_common::NAME_MAXIMUM_LENGTH).trimmed());
  QList<QTableWidgetItem *> items
    (ui.clients->findItems(id, Qt::MatchExactly));

  if(name.isEmpty() || name == "unknown")
    name = id.mid(0, 16) + "-unknown";

  ui.clients->setSortingEnabled(false);

  if(items.isEmpty())
    {
      ui.clients->setRowCount(ui.clients->rowCount() + 1);

      QTableWidgetItem *item = 0;

      item = new QTableWidgetItem(QString::fromUtf8(name.constData(),
						    name.length()));
      item->setFlags(Qt::ItemIsSelectable | Qt::ItemIsEnabled);

      if(id == m_id)
	item->setBackground(QBrush(QColor(254, 229, 172)));

      item->setToolTip(id.mid(0, 16) + "..." + id.right(16));
      ui.clients->setItem(ui.clients->rowCount() - 1, 0, item);
      item = new QTableWidgetItem(id.constData());
      item->setFlags
	(Qt::ItemIsSelectable | Qt::ItemIsEnabled);
      ui.clients->setItem(ui.clients->rowCount() - 1, 1, item);
      item = new QTableWidgetItem
	(QDateTime::currentDateTime().toString(Qt::ISODate));
      item->setFlags
	(Qt::ItemIsSelectable | Qt::ItemIsEnabled);
      ui.clients->setItem(ui.clients->rowCount() - 1, 2, item);

      QString msg("");

      msg.append
	(QDateTime::currentDateTime().
	 toString("[hh:mm<font color=grey>:ss</font>] "));
      msg.append(tr("<i>%1 has joined %2.</i>").
		 arg(QString::fromUtf8(name.constData(),
				       name.length())).
		 arg(QString::fromUtf8(m_channel.constData(),
				       m_channel.length())));
      ui.messages->append(msg);
      ui.messages->verticalScrollBar()->setValue
	(ui.messages->verticalScrollBar()->maximum());
      emit changed();
    }
  else
    {
      QTableWidgetItem *item = ui.clients->item(items.value(0)->row(), 0);

      if(item)
	{
	  if(item->text().toUtf8() != name)
	    {
	      QString msg("");

	      msg.append
		(QDateTime::currentDateTime().
		 toString("[hh:mm<font color=grey>:ss</font>] "));
	      msg.append(tr("<i>%1 is now known as %2.</i>").
			 arg(item->text()).
			 arg(QString::fromUtf8(name.constData(),
					       name.length())));
	      ui.messages->append(msg);
	      ui.messages->verticalScrollBar()->setValue
		(ui.messages->verticalScrollBar()->maximum());
	      item->setText(QString::fromUtf8(name.constData(),
					      name.length()));
	      emit changed();
	    }

	  /*
	  ** Update the client's time.
	  */

	  item = ui.clients->item(items.value(0)->row(), 2);

	  if(item) // Not a critical change. Do not notify the UI.
	    item->setText
	      (QDateTime::currentDateTime().toString(Qt::ISODate));
	}
    }

  ui.clients->setSortingEnabled(true);
  ui.clients->resizeColumnToContents(0);
  ui.clients->horizontalHeader()->setStretchLastSection(true);
}

void spoton_buzzpage::slotStatusTimeout(void)
{
  QDateTime now(QDateTime::currentDateTime());

  for(int i = ui.clients->rowCount() - 1; i >= 0; i--)
    {
      QTableWidgetItem *item = ui.clients->item(i, 1);

      if(item && item->text() == m_id)
	continue;

      item = ui.clients->item(i, 2);

      if(item)
	{
	  QDateTime dateTime
	    (QDateTime::fromString(item->text(), Qt::ISODate));

	  if(dateTime.secsTo(now) >= 60)
	    {
	      QTableWidgetItem *item = ui.clients->item(i, 0);

	      if(item)
		{
		  QString msg("");

		  msg.append
		    (QDateTime::currentDateTime().
		     toString("[hh:mm<font color=grey>:ss</font>] "));
		  msg.append(tr("<i>%1 has left %2.</i>").
			     arg(item->text()).
			     arg(QString::fromUtf8(m_channel.constData(),
						   m_channel.length())));
		  ui.messages->append(msg);
		  ui.messages->verticalScrollBar()->setValue
		    (ui.messages->verticalScrollBar()->maximum());
		  emit changed();
		}

	      ui.clients->removeRow(i);
	    }
	}
    }
}

void spoton_buzzpage::slotMessagingCachePurge(void)
{
  if(m_future.isFinished())
    if(!m_messagingCache.isEmpty())
      m_future = QtConcurrent::run
	(this, &spoton_buzzpage::purgeMessagingCache);
}

void spoton_buzzpage::purgeMessagingCache(void)
{
  if(!m_messagingCacheMutex.tryLock())
    return;

  QDateTime now(QDateTime::currentDateTime());
  QMutableHashIterator<QByteArray, QDateTime> i(m_messagingCache);

  while(i.hasNext())
    {
      m_purgeMutex.lock();

      if(!m_purge)
	{
	  m_purgeMutex.unlock();
	  break;
	}

      m_purgeMutex.unlock();
      i.next();

      if(i.value().secsTo(now) >= 120)
	i.remove();
    }

  m_messagingCacheMutex.unlock();
}

QByteArray spoton_buzzpage::channel(void) const
{
  return m_channel;
}

QByteArray spoton_buzzpage::channelType(void) const
{
  return m_channelType;
}

QByteArray spoton_buzzpage::key(void) const
{
  return m_key;
}

void spoton_buzzpage::slotBuzzNameChanged(const QByteArray &name)
{
  QList<QByteArray> list;

  list << name
       << m_id;
  userStatus(list);
}

void spoton_buzzpage::slotSave(void)
{
  if(!m_crypt)
    {
      QMessageBox::critical(this, tr("Spot-On: Error"),
			    tr("Invalid spoton_crypt object."));
      return;
    }

  QString connectionName("");
  bool ok = true;

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "buzz_channels.db");

    if(db.open())
      {
	QByteArray data;
	QSqlQuery query(db);

	data.append(m_channel.toBase64());
	data.append("\n");
	data.append(QString::number(m_iterationCount).toLatin1().toBase64());
	data.append("\n");

	if(!ui.salt->text().isEmpty())
	  data.append(m_channelSalt.toBase64());
	else
	  data.append(QByteArray().toBase64());

	data.append("\n");
	data.append(m_channelType.toBase64());
	query.prepare("INSERT OR REPLACE INTO buzz_channels "
		      "(data, data_hash) "
		      "VALUES (?, ?)");
	query.bindValue(0, m_crypt->encrypted(data, &ok).toBase64());

	if(ok)
	  query.bindValue(1, m_crypt->keyedHash(data, &ok).toBase64());

	if(ok)
	  ok = query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(!ok)
    QMessageBox::critical(this, tr("Spot-On: Error"),
			  tr("An error occurred while attempting to "
			     "save the channel data. Please enable "
			     "logging and try again."));
  else
    emit channelSaved();
}

void spoton_buzzpage::slotRemove(void)
{
  if(!m_crypt)
    {
      QMessageBox::critical(this, tr("Spot-On: Error"),
			    tr("Invalid spoton_crypt object."));
      return;
    }

  QString connectionName("");
  bool ok = true;

  {
    QSqlDatabase db = spoton_misc::database(connectionName);

    db.setDatabaseName(spoton_misc::homePath() + QDir::separator() +
		       "buzz_channels.db");

    if(db.open())
      {
	QByteArray data;
	QSqlQuery query(db);

	data.append(m_channel.toBase64());
	data.append("\n");
	data.append(QString::number(m_iterationCount).toLatin1().toBase64());
	data.append("\n");

	if(!ui.salt->text().isEmpty())
	  data.append(m_channelSalt.toBase64());
	else
	  data.append(QByteArray().toBase64());

	data.append("\n");
	data.append(m_channelType.toBase64());
	query.prepare("DELETE FROM buzz_channels WHERE "
		      "data_hash = ?");
	query.bindValue(0, m_crypt->keyedHash(data, &ok).toBase64());

	if(ok)
	  ok = query.exec();
      }

    db.close();
  }

  QSqlDatabase::removeDatabase(connectionName);

  if(!ok)
    QMessageBox::critical(this, tr("Spot-On: Error"),
			  tr("An error occurred while attempting to "
			     "remove the channel data. Please enable "
			     "logging and try again."));
  else
    emit channelSaved();
}
