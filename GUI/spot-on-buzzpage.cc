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
#include <QScrollBar>
#include <QSettings>
#if QT_VERSION >= 0x050000
#include <QtConcurrent>
#endif
#include <QtCore>

#include "Common/spot-on-common.h"
#include "Common/spot-on-crypt.h"
#include "Common/spot-on-misc.h"
#include "spot-on-buzzpage.h"

spoton_buzzpage::spoton_buzzpage(QSslSocket *kernelSocket,
				 const QByteArray &channel,
				 const QByteArray &channelSalt,
				 const QByteArray &channelType,
				 const QByteArray &id,
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

  m_id = id.trimmed();

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

	  m_channelSalt = salt.toBase64();
	}
      else
	ui.salt->setText(m_channelSalt);

      if(gcry_kdf_derive(static_cast<const void *> (m_channel.constData()),
			 static_cast<size_t> (m_channel.length()),
			 GCRY_KDF_PBKDF2,
			 GCRY_MD_SHA512,
			 static_cast<const void *> (m_channelSalt.constData()),
			 static_cast<size_t> (m_channelSalt.length()),
			 5000,
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
  ui.splitter->setStretchFactor(0, 1);
  ui.splitter->setStretchFactor(1, 0);
  ui.type->setText(m_channelType);
  slotSetIcons();
  m_messagingCachePurgeTimer.start(60000);
}

spoton_buzzpage::~spoton_buzzpage()
{
  m_messagingCacheMutex.lock();
  m_messagingCache.clear();
  m_messagingCacheMutex.unlock();
  m_future.waitForFinished();
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
  if(!m_kernelSocket)
    return;
  else if(m_kernelSocket->state() != QAbstractSocket::ConnectedState)
    return;
  else if(!m_kernelSocket->isEncrypted())
    return;
  else if(ui.message->toPlainText().trimmed().isEmpty())
    return;

  QByteArray name;
  QByteArray sendMethod;
  QString message;
  QSettings settings;

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
	("spoton_buzzpage::slotSendMessage(): write() failure.");
    else
      m_kernelSocket->flush();
  }

  ui.message->clear();
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

  if(name.isEmpty())
    name = "unknown";

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
      ("spoton_buzzpage::slotSendStatus(): write() failure.");
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

  if(id == m_id)
    return;

  QByteArray name
    (list.value(0).mid(0, spoton_common::NAME_MAXIMUM_LENGTH).trimmed());
  QList<QTableWidgetItem *> items
    (ui.clients->findItems(id, Qt::MatchExactly));

  if(name.isEmpty())
    name = "unknown";

  ui.clients->setSortingEnabled(false);

  if(items.isEmpty())
    {
      ui.clients->setRowCount(ui.clients->rowCount() + 1);

      QTableWidgetItem *item = 0;

      item = new QTableWidgetItem(QString::fromUtf8(name.constData(),
						    name.length()));
      item->setToolTip(id.constData());
      ui.clients->setItem(ui.clients->rowCount() - 1, 0, item);
      item = new QTableWidgetItem(id.constData());
      ui.clients->setItem(ui.clients->rowCount() - 1, 1, item);
      item = new QTableWidgetItem
	(QDateTime::currentDateTime().toString(Qt::ISODate));
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
      QTableWidgetItem *item = ui.clients->item(i, 2);

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
